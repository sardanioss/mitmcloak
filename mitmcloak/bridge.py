"""The mitmproxy addon.

Setting `flow.response` inside the `request` hook makes mitmproxy skip
`make_server_connection()` entirely, so there is no upstream Python TLS connection to
fingerprint. httpcloak makes the whole upstream leg instead.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import platform
import time
from pathlib import Path
from collections.abc import Sequence
from typing import Any, Callable

from mitmproxy import command, ctx, exceptions, http
from mitmproxy import types as mtypes

from . import capture, headers as hdrs, options as opts_mod
from .catalogue import Catalogue
from .identify import BaseIdentifier
from .mirror import (
    ClientProfile, MirrorRegistry, base_for_user_agent, refine_platform,
)
from .resolve import Resolver, session_key
from .sessions import SessionPool, build_session, enforce_required_flags

logger = logging.getLogger(__name__)

SWEEP_INTERVAL = 60.0


def _check_platform() -> None:
    """Fail with a useful message on musl rather than an opaque loader error.

    Go's c-shared archive uses initial-exec TLS, which musl will not dlopen
    (golang/go#54805). Alpine images are common for mitmproxy, so this is worth
    catching at import rather than at the first request.
    """
    if platform.system() != "Linux":
        return
    if Path("/etc/alpine-release").exists():
        raise RuntimeError(
            "mitmcloak: httpcloak cannot load on Alpine/musl (golang/go#54805). "
            "Use a glibc image such as python:3.12-slim."
        )


class Bridge:
    """Replaces mitmproxy's upstream leg with httpcloak.

    Every keyword argument other than `session`, `preset`, `headers` and `mode` is
    forwarded to `httpcloak.Session` untouched, so a new httpcloak release is usable
    without a mitmcloak release.
    """

    def __init__(
        self,
        preset: str | None = None,
        *,
        mode: str | None = None,
        headers: str | None = None,
        session: Callable[[Any], Any] | None = None,
        **session_kwargs: Any,
    ) -> None:
        _check_platform()
        self._preset_override = preset
        self._mode_override = mode
        self._headers_override = headers
        self._session_kwargs = session_kwargs

        self.pool = SessionPool()
        self.mirror = MirrorRegistry()
        self.identifier = BaseIdentifier()
        self.catalogue = Catalogue()
        self.resolver = Resolver()
        self.resolver.session_factory = session

        self._profiles: dict[str, ClientProfile] = {}
        self._presets_for_conn: dict[str, str] = {}
        self._sweeper: asyncio.Task | None = None
        self._inflight: set[asyncio.Task] = set()
        self._logged_passthrough: set[str] = set()
        self._preset_names: set | None = None

        self.stats = {
            "bridged": 0, "mirrored": 0, "static": 0, "rule": 0, "supplied": 0,
            "errors": 0, "timeouts": 0, "server_connects": 0,
            "passthrough_websocket": 0, "passthrough_body": 0,
            "passthrough_bypass": 0, "passthrough_other": 0,
            "captured_hellos": 0, "captured_h2": 0,
            "base_from_tls": 0, "base_from_user_agent": 0,
            "observed_only": 0, "tls_refused": 0,
        }
        self._requested: set[str] = set()
        """Client connections that produced at least one request we could act on."""
        self._refused_hosts: set[str] = set()

    # ------------------------------------------------------------------ options

    def load(self, loader) -> None:
        opts_mod.register(loader)

    def configure(self, updated) -> None:
        if "mitmcloak_rule" in updated or "mitmcloak_bypass" in updated:
            try:
                self.resolver.configure(ctx.options.mitmcloak_rule, ctx.options.mitmcloak_bypass)
            except ValueError as exc:
                raise exceptions.OptionsError(f"mitmcloak: {exc}") from exc
        if "mitmcloak_preset_file" in updated:
            self._load_preset_files(ctx.options.mitmcloak_preset_file)
        if "mitmcloak_max_sessions" in updated:
            self.pool.max_sessions = ctx.options.mitmcloak_max_sessions
        if "mitmcloak_max_idle" in updated:
            self.pool.max_idle = ctx.options.mitmcloak_max_idle
        if "mitmcloak_export_dir" in updated and ctx.options.mitmcloak_export_dir:
            Path(ctx.options.mitmcloak_export_dir).mkdir(parents=True, exist_ok=True)
        if "mitmcloak_catalogue_dir" in updated:
            self.catalogue.directory = (
                Path(ctx.options.mitmcloak_catalogue_dir).expanduser()
                if ctx.options.mitmcloak_catalogue_dir else None
            )

    def _load_preset_files(self, paths) -> None:
        import httpcloak

        for path in paths:
            try:
                name = httpcloak.load_preset(str(Path(path).expanduser()))
                logger.info("mitmcloak: loaded preset %s from %s", name, path)
            except Exception as exc:                   # noqa: BLE001
                if "already registered" in str(exc):
                    continue
                raise exceptions.OptionsError(
                    f"mitmcloak: could not load preset file {path}: {exc}"
                ) from exc

    # ---------------------------------------------------------------- lifecycle

    def running(self) -> None:
        # connection_strategy defaults to eager, which opens the upstream TLS
        # connection before the request hook fires. That leaks a Python ClientHello to
        # the origin even though the request itself goes out through httpcloak, which
        # is a louder signal than not bridging at all. Correct it rather than warn.
        if ctx.options.connection_strategy != "lazy":
            ctx.options.update(connection_strategy="lazy")
            logger.warning(
                "mitmcloak: forced connection_strategy=lazy; eager opens an upstream "
                "TLS connection before the request hook and leaks a Python ClientHello"
            )
        self._apply_overrides()
        upstream = opts_mod.upstream_from_mode(ctx.options)
        if upstream and not ctx.options.mitmcloak_proxy:
            logger.info(
                "mitmcloak: chaining the httpcloak leg through the upstream proxy %s, "
                "since the short circuit means mitmproxy never reaches it itself",
                upstream,
            )
        self._sweeper = asyncio.ensure_future(self._sweep_loop())
        import httpcloak

        logger.info(
            "mitmcloak: ready (httpcloak %s, preset=%s, mode=%s, headers=%s)",
            httpcloak.version(), self._preset(), self._mode(), self._header_mode(),
        )

    def _apply_overrides(self) -> None:
        """Constructor arguments win over option defaults, but not over --set."""
        pairs = (
            ("mitmcloak_preset", self._preset_override),
            ("mitmcloak_mode", self._mode_override),
            ("mitmcloak_headers", self._headers_override),
        )
        for name, value in pairs:
            if value is None:
                continue
            option = ctx.options._options.get(name)
            if option is not None and not option.has_changed():
                ctx.options.update(**{name: value})

    async def _sweep_loop(self) -> None:
        try:
            while True:
                await asyncio.sleep(SWEEP_INTERVAL)
                self.pool.sweep()
        except asyncio.CancelledError:
            pass

    def done(self) -> None:
        written = self.catalogue.flush(self._base_for_identity)
        if written:
            logger.info(
                "mitmcloak: catalogued %d fingerprint(s) to %s",
                written, self.catalogue.directory,
            )
        if self._sweeper is not None:
            self._sweeper.cancel()
        for task in list(self._inflight):
            task.cancel()
        self.pool.close()
        self.mirror.close()
        logger.info("mitmcloak: %s", self.summary())

    def summary(self) -> str:
        parts = [f"{k}={v}" for k, v in self.stats.items() if v]
        parts.append(f"sessions={len(self.pool)}")
        parts.append(f"presets={len(self.mirror.names())}")
        return "stats " + " ".join(parts)

    # ------------------------------------------------------- the no-upstream proof

    def server_connect(self, data) -> None:
        """Should stay at zero for every bridged flow.

        This is a stronger check than reading a JA4 back: if it moves, mitmproxy opened
        its own connection and something bypassed the bridge.
        """
        self.stats["server_connects"] += 1

    # ------------------------------------------------------------------- capture

    def tls_clienthello(self, data) -> None:
        client_hello = data.client_hello
        # A bypassed connection is still worth fingerprinting. The hook fires before
        # the ignore decision takes effect, so a cert-pinned app that we can never
        # decrypt still yields its exact TLS fingerprint.
        try:
            info = capture.parse_client_hello(
                client_hello.raw_bytes(wrap_in_record=True), client_hello.sni
            )
        except Exception as exc:                       # noqa: BLE001
            logger.debug("mitmcloak: could not parse ClientHello: %s", exc)
            return
        self.stats["captured_hellos"] += 1
        self.catalogue.note_hello(info)
        conn_id = data.context.client.id
        profile = self._profiles.get(conn_id)
        if profile is None:
            profile = ClientProfile(hello=info)
            self._profiles[conn_id] = profile
        if info.has_psk:
            # A resuming hello is a different shape and belongs in its own slot; using
            # it as the fresh hello would send a PSK extension with nothing to resume.
            profile.psk_hello = info
        else:
            profile.hello = info
        profile.orders_seen.add(info.extension_order)

    def next_layer(self, data) -> None:
        """Capture the client's H2 preface once TLS is up.

        `data_client()` holds the decrypted bytes at this point, which is preface plus
        SETTINGS plus WINDOW_UPDATE and often the first HEADERS frame.
        """
        try:
            preface = capture.parse_h2_preface(data.data_client())
        except Exception:                              # noqa: BLE001
            return
        if preface is None:
            return
        profile = self._profiles.get(data.context.client.id)
        if profile is None or profile.h2 is not None:
            return
        profile.h2 = preface
        self.catalogue.note_h2(profile.hello.stable_id, preface)
        self.stats["captured_h2"] += 1

    def tls_failed_client(self, data) -> None:
        """The client rejected our certificate. Its fingerprint is still ours.

        Pinning stops us reading an app's traffic. It does not stop us reading its
        ClientHello, which arrived in plaintext before the trust decision was made.
        """
        self.stats["tls_refused"] += 1
        seen = self._profiles.get(data.context.client.id)
        if seen is not None:
            self.catalogue.note_refused(seen.hello.stable_id)
        host = getattr(data.context.server, "address", None)
        host = host[0] if host else None
        if host and host not in self._refused_hosts:
            self._refused_hosts.add(host)
            logger.info(
                "mitmcloak: %s refused our certificate, so its traffic stays opaque. "
                "Its TLS fingerprint was captured anyway.", host,
            )

    def client_disconnected(self, client) -> None:
        profile = self._profiles.pop(client.id, None)
        self._presets_for_conn.pop(client.id, None)
        made_request = client.id in self._requested
        self._requested.discard(client.id)
        if profile is None or made_request:
            return
        # A connection that produced a hello but never a request we could act on: a
        # pinned app, a failed handshake, or a client that hung up. The fingerprint is
        # the whole point of capturing it, so keep it rather than letting it die with
        # the connection. Only reachable because the base now comes from the TLS stack;
        # there is no User-Agent to fall back on here.
        self._record_observed(profile)

    def _record_observed(self, profile: ClientProfile) -> None:
        self.stats["observed_only"] += 1
        self.catalogue.note_no_request(profile.hello.stable_id)
        self.catalogue.flush(self._base_for_identity)

    def _base_for_identity(self, stable_id: str) -> str:
        entry = self.catalogue.entries.get(stable_id)
        if entry is not None and ctx.options.mitmcloak_identify_by_tls:
            match = self.identifier.match(entry.hello.family_id)
            if match is not None:
                return match
        return self._preset()

    # -------------------------------------------------------------- the bridge

    async def request(self, flow: http.HTTPFlow) -> None:
        if flow.response is not None:
            return                                     # another addon already answered
        if not flow.live:
            return

        if self._is_websocket(flow):
            # Returning a 101 with no server connection breaks the flow outright, so
            # hand WebSockets back to mitmproxy until httpcloak speaks them.
            self._passthrough(flow, "websocket")
            return
        if self.resolver.should_bypass(flow):
            self._passthrough(flow, "bypass")
            return

        if self._targets_self(flow):
            # A browser pointed straight at the proxy port with no proxy configured
            # sends an origin-form request, which mitmproxy reconstructs as a URL
            # aimed back at us. Fetching it would loop until the deadline and report
            # a timeout, which reads like a network fault rather than a misconfigured
            # client.
            self._fail(
                flow, 421,
                "this request targets the proxy's own listen address. Configure "
                "the proxy in your client's network settings rather than browsing "
                "to the proxy port directly.",
            )
            return

        body = flow.request.raw_content or b""
        if len(body) > ctx.options.mitmcloak_max_body:
            self._passthrough(flow, "body")
            return

        decision = self.resolver.decide(
            flow, self._mode(), lambda: self._mirror_preset(flow), self._preset()
        )
        if decision.reason == "mirror" and self._mode() == "mirror" and not decision.preset:
            self._passthrough(flow, "other")
            return
        self.stats[{"callable": "supplied", "rule": "rule",
                    "mirror": "mirrored", "static": "static"}[decision.reason]] += 1

        try:
            session = self._session_for(flow, decision)
        except Exception as exc:                       # noqa: BLE001
            self._fail(flow, 502, f"could not create an upstream session: {exc}")
            return

        task = asyncio.current_task()
        if task is not None:
            self._inflight.add(task)
        started = time.perf_counter()
        try:
            response = await session.request_async(
                flow.request.method,
                flow.request.url,
                headers=hdrs.request_headers(flow.request.headers.fields, self._header_mode()) or None,
                data=body or None,
                timeout=ctx.options.mitmcloak_timeout,
            )
        except asyncio.CancelledError:
            raise                                      # client went away; Go side cancels too
        except Exception as exc:                       # noqa: BLE001
            text = str(exc)
            if "deadline" in text or "timeout" in text.lower():
                self.stats["timeouts"] += 1
                self._fail(flow, 504, text)
            else:
                self._fail(flow, 502, text)
            return
        finally:
            if task is not None:
                self._inflight.discard(task)

        resp = http.Response.make(response.status_code, bytes(response.content or b""))
        resp.headers = http.Headers(hdrs.response_pairs(response.headers))
        if getattr(response, "protocol", None):
            resp.http_version = _wire_version(response.protocol)
        flow.response = resp
        self._requested.add(flow.client_conn.id)
        seen = self._profiles.get(flow.client_conn.id)
        if seen is not None:
            self.catalogue.note_request(seen.hello.stable_id)
        flow.metadata["mitmcloak"] = {
            "preset": decision.preset,
            "via": decision.reason,
            "upstream": getattr(response, "protocol", None),
            "ms": round((time.perf_counter() - started) * 1000, 1),
        }
        self.stats["bridged"] += 1

    # ------------------------------------------------------------------ helpers

    def _session_for(self, flow, decision):
        scope = ctx.options.mitmcloak_session_scope
        key = session_key(flow, decision, scope, ctx.options.mitmcloak_http_version)
        if decision.session is not None:
            enforce_required_flags(decision.session)
            return self.pool.adopt(key, decision.session)
        kwargs = opts_mod.session_options(ctx.options)
        kwargs.update(self._session_kwargs)
        return self.pool.get(key, lambda: build_session(decision.preset, kwargs))

    def _mirror_preset(self, flow) -> str | None:
        conn_id = flow.client_conn.id
        cached = self._presets_for_conn.get(conn_id)
        if cached is not None:
            return cached
        profile = self._profiles.get(conn_id)
        if profile is None:
            return None
        # Built here rather than in tls_clienthello because the User-Agent, which is
        # the fallback signal for the base, does not exist until a request arrives.
        #
        # The TLS stack is asked first. A system agent or an app rarely puts a platform
        # token in its User-Agent, and an iOS client falling through to a Chrome desktop
        # base gets the wrong header block. The ClientHello does not lie about which
        # stack produced it, and matching it against the built-in presets is exact.
        base = None
        if ctx.options.mitmcloak_identify_by_tls:
            base = self.identifier.match(profile.hello.family_id)
        base_from_tls = base is not None
        user_agent = flow.request.headers.get("user-agent", "")
        if base is None:
            base = base_for_user_agent(user_agent, self._preset())
            self.identifier.by_user_agent += 1
        else:
            base = refine_platform(base, user_agent, self._known_presets())
        self.stats["base_from_tls" if base_from_tls else "base_from_user_agent"] += 1
        name = self.mirror.ensure(profile, base)
        if name is not None:
            self._presets_for_conn[conn_id] = name
            self._export(name)
        return name

    def _known_presets(self) -> set:
        if self._preset_names is None:
            import httpcloak

            self._preset_names = set(httpcloak.available_presets())
        return self._preset_names

    def _export(self, name: str) -> None:
        directory = ctx.options.mitmcloak_export_dir
        if not directory:
            return
        doc = self.mirror.document(name)
        if doc is None:
            return
        path = Path(directory) / f"{name}.json"
        if path.exists():
            return
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(doc, indent=2))
        except OSError as exc:
            logger.warning("mitmcloak: could not export %s: %s", path, exc)

    @staticmethod
    def _targets_self(flow) -> bool:
        try:
            listen_port = int(ctx.options.listen_port or 0)
        except (TypeError, ValueError):
            return False
        if flow.request.port != listen_port:
            return False
        sock = flow.client_conn.sockname
        return bool(sock) and flow.request.pretty_host == sock[0]

    @staticmethod
    def _is_websocket(flow) -> bool:
        # Matches mitmproxy's own test in send_response().
        return bool(
            flow.request.headers.get("Sec-WebSocket-Version") and ctx.options.websocket
        )

    def _passthrough(self, flow, reason: str) -> None:
        self.stats[f"passthrough_{reason}"] += 1
        host = flow.request.pretty_host
        marker = f"{reason}:{host}"
        if marker not in self._logged_passthrough:
            self._logged_passthrough.add(marker)
            logger.info(
                "mitmcloak: %s not bridged (%s); it reaches the origin with mitmproxy's "
                "own fingerprint", host, reason,
            )

    def _fail(self, flow, status: int, message: str) -> None:
        self.stats["errors"] += 1
        flow.response = http.Response.make(
            status, f"mitmcloak: {message}".encode(),
            {"Content-Type": "text/plain; charset=utf-8"},
        )

    def _preset(self) -> str:
        return ctx.options.mitmcloak_preset

    def _mode(self) -> str:
        return ctx.options.mitmcloak_mode

    def _header_mode(self) -> str:
        return ctx.options.mitmcloak_headers

    # ----------------------------------------------------------------- commands

    @command.command("mitmcloak.presets")
    def cmd_presets(self) -> Sequence[str]:
        """List every preset available, built in and mirrored."""
        import httpcloak

        return sorted(set(httpcloak.available_presets()) | set(self.mirror.names()))

    @command.command("mitmcloak.preset")
    @command.argument("name", type=mtypes.Choice("mitmcloak.presets"))
    def cmd_preset(self, name: str) -> None:
        """Switch the static preset."""
        ctx.options.update(mitmcloak_preset=name)
        logger.info("mitmcloak: preset is now %s", name)

    @command.command("mitmcloak.preset.load")
    def cmd_preset_load(self, path: mtypes.Path) -> str:
        """Load a JSON preset file and register it."""
        import httpcloak

        return httpcloak.load_preset(str(path))

    @command.command("mitmcloak.preset.describe")
    @command.argument("name", type=mtypes.Choice("mitmcloak.presets"))
    def cmd_preset_describe(self, name: str) -> str:
        """Show the fully resolved JSON for a preset."""
        import httpcloak

        return httpcloak.describe_preset(name)

    @command.command("mitmcloak.mirror.list")
    def cmd_mirror_list(self) -> Sequence[str]:
        """Every fingerprint mirrored in this session."""
        return self.mirror.names()

    @command.command("mitmcloak.mirror.export")
    def cmd_mirror_export(self, directory: mtypes.Path) -> str:
        """Write every mirrored preset out, for reuse without the device present."""
        target = Path(str(directory))
        target.mkdir(parents=True, exist_ok=True)
        written = 0
        for name in self.mirror.names():
            doc = self.mirror.document(name)
            if doc is None:
                continue
            (target / f"{name}.json").write_text(json.dumps(doc, indent=2))
            written += 1
        return f"wrote {written} preset(s) to {target}"

    @command.command("mitmcloak.catalogue")
    def cmd_catalogue(self) -> Sequence[str]:
        """Every distinct TLS fingerprint seen, used or not."""
        return self.catalogue.summary()

    @command.command("mitmcloak.catalogue.save")
    def cmd_catalogue_save(self, directory: mtypes.Path) -> str:
        """Write every observed fingerprint out as a loadable preset file."""
        previous = self.catalogue.directory
        self.catalogue.directory = Path(str(directory))
        self.catalogue._written.clear()
        try:
            written = self.catalogue.flush(self._base_for_identity)
        finally:
            self.catalogue.directory = previous
        return f"wrote {written} fingerprint(s) to {directory}"

    @command.command("mitmcloak.stats")
    def cmd_stats(self) -> str:
        """Counters, including how many flows were not bridged and why."""
        return self.summary()


def _wire_version(protocol: str) -> str:
    return {"h2": "HTTP/2.0", "h3": "HTTP/3.0"}.get(protocol, "HTTP/1.1")
