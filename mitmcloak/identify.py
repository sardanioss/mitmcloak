"""Recognise a captured fingerprint as one of the built-in presets.

The User-Agent is a poor signal for choosing a base preset: system agents and most
apps do not put a platform token in it, and an iOS client that falls through to a
Chrome desktop base gets the wrong header block and the wrong H2 settings.

The ClientHello is a much better signal, and it is one we already hold. This module
learns what each candidate base preset actually puts on the wire by making it connect
to a local socket that reads the handshake and hangs up, then matches captured clients
against that map. No network, no certificates: we only ever need the first record.
"""
from __future__ import annotations

import json
import logging
import socket
import threading

from .capture import parse_client_hello

logger = logging.getLogger(__name__)

# Only presets worth using as a base. Probing all ~94 registered names would be mostly
# wasted work, since they collapse to far fewer distinct TLS identities.
BASE_CANDIDATES = (
    "chrome-151-windows", "chrome-151-macos", "chrome-151-linux",
    "chrome-151-ios", "chrome-151-android",
    "chrome-150-windows", "chrome-146-windows",
    "firefox-148-windows", "firefox-148-linux", "firefox-148-macos",
    "firefox-133-windows", "safari-18-ios",
)


class _HelloSink:
    """A TCP socket that reads one TLS record and closes.

    Enough to learn a preset's ClientHello without terminating TLS or owning a
    certificate. The client's handshake fails, which is fine: the bytes we want are
    the ones it already sent.
    """

    def __init__(self) -> None:
        self._sock = socket.socket()
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(8)
        self._sock.settimeout(5.0)
        self.port = self._sock.getsockname()[1]
        self.captured: list[bytes] = []
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self) -> None:
        while not self._stop.is_set():
            try:
                conn, _ = self._sock.accept()
            except (TimeoutError, OSError):
                continue
            try:
                conn.settimeout(3.0)
                data = b""
                while len(data) < 5:
                    chunk = conn.recv(65535)
                    if not chunk:
                        break
                    data += chunk
                if len(data) >= 5:
                    want = 5 + int.from_bytes(data[3:5], "big")
                    while len(data) < want:
                        chunk = conn.recv(65535)
                        if not chunk:
                            break
                        data += chunk
                    self.captured.append(data[:want])
            except OSError:
                pass
            finally:
                conn.close()

    def close(self) -> None:
        self._stop.set()
        try:
            self._sock.close()
        except OSError:
            pass


def build_identity_map(
    candidates=BASE_CANDIDATES,
) -> tuple[dict[str, str], dict[str, bool]]:
    """Learn what each candidate preset puts on the wire.

    Returns ({stable_id: preset_name}, {preset_name: permutes}). Presets that share a
    ClientHello collapse onto one identity entry; first name wins, and the candidate
    order above decides which that is. The permutation map is keyed by preset name, so
    every candidate keeps its own answer even when its identity collapsed.

    Each candidate is asked for two connections rather than one, because that is what
    it takes to see whether it reorders its extensions. Chromium does on every
    connection and Apple's stack, NSS and Go do not, but hardcoding that would be a
    table to maintain; asking the preset costs one extra local socket and cannot go
    stale when httpcloak adds a client.
    """
    import httpcloak

    sink = _HelloSink()
    identities: dict[str, str] = {}
    permutes: dict[str, bool] = {}
    try:
        for name in candidates:
            before = len(sink.captured)
            session = None
            try:
                session = httpcloak.Session(
                    preset=name, verify=False, timeout=3, http_version="h2",
                    without_cookie_jar=True, without_conditional_cache=True,
                    allow_redirects=False,
                )
                for _ in range(2):
                    try:
                        session.get(f"https://127.0.0.1:{sink.port}/", timeout=3)
                    except Exception:                  # noqa: BLE001 - expected
                        pass
            except Exception as exc:                   # noqa: BLE001
                logger.debug("mitmcloak: could not probe %s: %s", name, exc)
                continue
            finally:
                if session is not None:
                    try:
                        session.close()
                    except Exception:                  # noqa: BLE001
                        pass
            orders = set()
            for raw in sink.captured[before:]:
                try:
                    info = parse_client_hello(raw)
                except ValueError:
                    continue
                identities.setdefault(info.family_id, name)
                orders.add(info.extension_order)
            if len(sink.captured[before:]) > 1:
                permutes[name] = len(orders) > 1
    finally:
        sink.close()
    logger.info(
        "mitmcloak: learned %d distinct TLS identities from %d base presets, "
        "%d of which reorder their extensions per connection",
        len(identities), len(candidates), sum(permutes.values()),
    )
    return identities, permutes


# A ClientHello unlike any browser preset, used to ask httpcloak whether it really
# honours raw_client_hello. curl's, because its 30 ciphers and absent GREASE make an
# accidental match impossible.
_PROBE_FIXTURE = "curl-8.21-openssl"


def probe_fixture() -> tuple[str, str] | None:
    """The bundled probe hello and the family it must reproduce."""
    import base64
    from pathlib import Path

    path = Path(__file__).parent / "data" / "client_hellos.json"
    try:
        blob = json.loads(path.read_text())[_PROBE_FIXTURE]["client_hello_b64"]
    except (OSError, KeyError, ValueError):
        return None
    try:
        family = parse_client_hello(base64.b64decode(blob)).family_id
    except ValueError:
        return None
    return blob, family


def supports_raw_client_hello(fixture_b64: str, expected_family: str) -> bool:
    """Ask httpcloak to replay a known hello and check that it actually did.

    Go's JSON decoder ignores unknown fields, so an httpcloak without C1 accepts a
    preset carrying raw_client_hello, drops the key, and quietly serves the base
    preset instead. The registration succeeds, the logs say "mirrored", and the wire
    carries the wrong fingerprint. Nothing short of looking at the bytes catches it.
    """
    import httpcloak

    name = "mitmcloak-capability-probe"
    spec = {
        "name": name, "based_on": "chrome-151-windows",
        "tls": {"raw_client_hello": fixture_b64, "allow_blunt_mimicry": True},
    }
    try:
        httpcloak.load_preset_from_json(json.dumps({"version": 1, "preset": spec}))
    except Exception as exc:                           # noqa: BLE001
        if "already registered" not in str(exc):
            logger.debug("mitmcloak: capability probe could not register: %s", exc)
            return False

    sink = _HelloSink()
    session = None
    try:
        session = httpcloak.Session(
            preset=name, verify=False, timeout=3, http_version="h2",
            without_cookie_jar=True, without_conditional_cache=True,
            allow_redirects=False,
        )
        try:
            session.get(f"https://127.0.0.1:{sink.port}/", timeout=3)
        except Exception:                              # noqa: BLE001 - expected
            pass
        for raw in sink.captured:
            try:
                if parse_client_hello(raw).family_id == expected_family:
                    return True
            except ValueError:
                continue
        return False
    except Exception as exc:                           # noqa: BLE001
        logger.debug("mitmcloak: capability probe failed: %s", exc)
        return False
    finally:
        if session is not None:
            try:
                session.close()
            except Exception:                          # noqa: BLE001
                pass
        sink.close()
        try:
            httpcloak.unregister_preset(name)
        except Exception:                              # noqa: BLE001
            pass


class BaseIdentifier:
    """Picks a base preset for a captured client, TLS first and User-Agent second."""

    def __init__(self) -> None:
        self._identities: dict[str, str] | None = None
        self._permutes: dict[str, bool] = {}
        self.matched = 0
        self.by_user_agent = 0

    def ensure_loaded(self) -> None:
        if self._identities is None:
            try:
                self._identities, self._permutes = build_identity_map()
            except Exception as exc:                   # noqa: BLE001
                logger.warning("mitmcloak: TLS identity probing failed: %s", exc)
                self._identities = {}
                self._permutes = {}

    def match(self, family_id: str) -> str | None:
        self.ensure_loaded()
        name = (self._identities or {}).get(family_id)
        if name is not None:
            self.matched += 1
        return name

    def permutes(self, base: str) -> bool:
        """Whether the chosen base was measured reordering its extensions.

        The User-Agent can move a match onto a sibling variant that was never probed
        (chrome-150-windows -> chrome-150-android), so an unprobed name falls back to
        its family: the platform suffix does not change the TLS stack. An unknown
        family answers False and the client's own repeat connections settle it.
        """
        self.ensure_loaded()
        if base in self._permutes:
            return self._permutes[base]
        head = base.rpartition("-")[0]
        if head:
            for name, value in self._permutes.items():
                if name.rpartition("-")[0] == head:
                    return value
        return False

    def known(self) -> dict[str, str]:
        self.ensure_loaded()
        return dict(self._identities or {})
