"""mitmproxy option registration and validation.

Everything reachable from Python is reachable from `--set` and from mitmweb's option
editor, where a `choices` list renders as a dropdown.
"""
from __future__ import annotations

from collections.abc import Sequence

from . import headers as _headers

MODES = ("auto", "static", "mirror")

# Passed straight through to httpcloak.Session. Deliberately not an allowlist of
# everything Session accepts: these are the ones worth a CLI flag. Anything else goes
# through the Python API, where kwargs are forwarded untouched.
PASSTHROUGH_STR = (
    ("mitmcloak_proxy", "proxy", "", "Upstream proxy for the httpcloak leg"),
    ("mitmcloak_ja3", "ja3", "", "JA3 override for the static preset"),
    ("mitmcloak_akamai", "akamai", "", "Akamai H2 override for the static preset"),
)
PASSTHROUGH_INT = (
    ("mitmcloak_tcp_ttl", "tcp_ttl", "TCP TTL override"),
    ("mitmcloak_tcp_mss", "tcp_mss", "TCP MSS override"),
    ("mitmcloak_tcp_window_size", "tcp_window_size", "TCP window size override"),
)


def register(loader) -> None:
    loader.add_option(
        "mitmcloak_preset", str, "chrome-151-windows",
        "Preset for the upstream leg when not mirroring.",
    )
    loader.add_option(
        "mitmcloak_mode", str, "auto",
        "auto mirrors the real client when its fingerprint was captured and falls "
        "back to the static preset otherwise; static always uses the preset; mirror "
        "refuses to fall back.",
        choices=list(MODES),
    )
    loader.add_option(
        "mitmcloak_headers", str, "merge",
        "merge keeps the client's header values inside the preset's block; replace "
        "keeps only semantic headers and lets the preset supply the rest.",
        choices=list(_headers.MODES),
    )
    loader.add_option(
        "mitmcloak_preset_file", Sequence[str], [],
        "Path to a JSON preset file to load at startup. Repeatable.",
    )
    loader.add_option(
        "mitmcloak_rule", Sequence[str], [],
        'Per-flow preset selection: "/<flow filter>/<preset>", any separator. '
        'Example: "/~d .*\\.example\\.com/chrome-151-ios". Repeatable, first match wins.',
    )
    loader.add_option(
        "mitmcloak_bypass", str, "",
        "Flow filter for requests that should not be bridged at all.",
    )
    loader.add_option(
        "mitmcloak_http_version", str, "auto",
        "Upstream protocol for the httpcloak leg.",
        choices=["auto", "h1", "h2", "h3"],
    )
    loader.add_option(
        "mitmcloak_session_scope", str, "origin",
        "origin gives one upstream connection per origin, which is what a browser "
        "does; client and connection trade that coherence for identity separation.",
        choices=["origin", "client", "connection"],
    )
    loader.add_option(
        "mitmcloak_catalogue_dir", str, "",
        "Write every distinct TLS fingerprint seen into this directory, whether or "
        "not it was ever used. Entries are loadable preset files, so anything the "
        "proxy watched go past can be turned into a preset later.",
    )
    loader.add_option(
        "mitmcloak_identify_by_tls", bool, True,
        "Choose a mirrored client's base preset by matching its TLS stack against the "
        "built-in presets, falling back to the User-Agent. Apps and system agents "
        "rarely carry a platform token in their User-Agent.",
    )
    loader.add_option(
        "mitmcloak_max_sessions", int, 96,
        "Session pool cap. This is a memory dial as much as a reuse dial: an httpcloak "
        "session costs roughly 190 kB and closing one does not return that memory to "
        "the OS, so peak usage tracks the high-water mark of live sessions rather than "
        "the request count.",
    )
    loader.add_option(
        "mitmcloak_max_idle", int, 120,
        "Seconds before an idle session is closed. Frees sockets and file descriptors; "
        "it does not reduce memory, since closing a session returns nothing to the OS.",
    )
    loader.add_option(
        "mitmcloak_max_body", int, 50 * 1024 * 1024,
        "Requests with a body over this are handed back to mitmproxy unbridged.",
    )
    loader.add_option("mitmcloak_timeout", int, 30, "Upstream request timeout in seconds.")
    loader.add_option("mitmcloak_verify", bool, True, "Verify upstream certificates.")
    loader.add_option("mitmcloak_disable_ech", bool, False, "Disable Encrypted Client Hello.")
    loader.add_option("mitmcloak_tls_only", bool, False, "TLS-only mode on the upstream leg.")
    loader.add_option(
        "mitmcloak_export_dir", str, "",
        "Directory to write every mirrored preset into, for reuse without the device.",
    )
    for name, _dest, default, help_text in PASSTHROUGH_STR:
        loader.add_option(name, str, default, help_text)
    for name, _dest, help_text in PASSTHROUGH_INT:
        loader.add_option(name, int, 0, help_text)


def upstream_from_mode(opts) -> str | None:
    """The proxy mitmproxy was told to chain through, if any.

    In upstream mode mitmproxy would normally forward everything to another proxy. We
    short-circuit before it ever gets the chance, so without this the configured proxy
    is silently bypassed and requests leave from the real address while the operator
    believes otherwise. Honour it by handing it to httpcloak instead.
    """
    for entry in (getattr(opts, "mode", None) or []):
        if entry.startswith("upstream:"):
            target = entry.split(":", 1)[1].strip()
            if target and "://" not in target:
                target = "http://" + target
            return target or None
    return None


def session_options(opts) -> dict:
    """Collect the option values that become httpcloak.Session kwargs."""
    out: dict = {
        "timeout": opts.mitmcloak_timeout,
        "verify": opts.mitmcloak_verify,
        "http_version": opts.mitmcloak_http_version,
    }
    if opts.mitmcloak_disable_ech:
        out["disable_ech"] = True
    if opts.mitmcloak_tls_only:
        out["tls_only"] = True
    # An explicit mitmcloak_proxy wins; otherwise inherit mitmproxy's upstream mode.
    upstream = upstream_from_mode(opts)
    if upstream:
        out["proxy"] = upstream
    for name, dest, _default, _help in PASSTHROUGH_STR:
        value = getattr(opts, name, "")
        if value:
            out[dest] = value
    for name, dest, _help in PASSTHROUGH_INT:
        value = getattr(opts, name, 0)
        if value:
            out[dest] = value
    return out
