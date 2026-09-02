"""Header handling in both directions.

httpcloak's ordinary pipeline always injects the preset's header block and merges caller
headers into it, so `merge` is named for what actually happens rather than for what a
passthrough would do.
"""
from __future__ import annotations

from typing import Any, Iterable

# Stripped in both directions. These describe a single hop and must not be forwarded.
HOP_BY_HOP = frozenset({
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailer", "transfer-encoding", "upgrade", "proxy-connection",
    "host", "content-length",
})

# Dropped from the response: httpcloak already decoded the body, so re-advertising the
# original encoding makes the client decode a second time and fail.
RESPONSE_DROP = frozenset({"content-encoding", "content-length", "transfer-encoding"})

# Kept in `replace` mode. Everything else comes from the preset.
SEMANTIC = frozenset({
    "cookie", "authorization", "content-type", "referer", "origin",
    "accept", "content-encoding",
})

MODES = ("merge", "replace", "exact")


def request_headers(fields: Iterable[tuple[bytes, bytes]], mode: str) -> dict[str, str]:
    """Build the header dict for httpcloak from the client's raw ordered fields.

    Duplicates collapse here, which is a real fidelity limit: a dict cannot express two
    Cookie headers. It is what the current httpcloak request API accepts.
    """
    out: dict[str, str] = {}
    for raw_name, raw_value in fields:
        name = raw_name.decode("latin-1")
        lowered = name.lower()
        if lowered in HOP_BY_HOP:
            continue
        if mode == "replace" and not (
            lowered in SEMANTIC or lowered.startswith("x-")
        ):
            continue
        value = raw_value.decode("latin-1")
        if lowered in out or name in out:
            # Repeated header. Cookie crumbs rejoin with "; " per RFC 9113 8.1.2.5;
            # anything else follows the comma rule.
            existing = out.get(name, out.get(lowered, ""))
            joiner = "; " if lowered == "cookie" else ", "
            out[name] = f"{existing}{joiner}{value}"
        else:
            out[name] = value
    return out


def exact_headers(fields: Iterable[tuple[bytes, bytes]]) -> list[tuple[str, str]]:
    """The client's header block verbatim: order, casing and duplicates all kept.

    This is the one form that loses nothing. `request_headers` returns a dict, and a
    dict cannot hold two Cookie headers or remember that the client wrote `X-FOO`
    rather than `X-Foo`, so both are gone before httpcloak sees them.

    Hop-by-hop headers are still dropped, because they describe the client-to-proxy
    connection and forwarding them is a proxy bug rather than a fidelity gain. Host and
    the pseudo-header block are dropped for a different reason: httpcloak writes those
    itself as protocol framing, so listing them again would put two of each on the wire.
    """
    out: list[tuple[str, str]] = []
    for raw_name, raw_value in fields:
        name = raw_name.decode("latin-1")
        if name.lower() in HOP_BY_HOP:
            continue
        out.append((name, raw_value.decode("latin-1")))
    return out


def header_order(fields: Iterable[tuple[bytes, bytes]]) -> list[str]:
    """The client's header order, lowercased, duplicates removed, hop-by-hop stripped."""
    seen: list[str] = []
    for raw_name, _ in fields:
        name = raw_name.decode("latin-1").lower()
        if name in HOP_BY_HOP or name in seen:
            continue
        seen.append(name)
    return seen


def response_pairs(headers: Any) -> list[tuple[bytes, bytes]]:
    """Flatten httpcloak's response headers into ordered byte pairs.

    Values arrive as lists, and several Set-Cookie headers must survive as several
    headers rather than one joined string.
    """
    pairs: list[tuple[bytes, bytes]] = []
    for name, value in (headers or {}).items():
        if name.lower() in RESPONSE_DROP:
            continue
        values = value if isinstance(value, (list, tuple)) else [value]
        for item in values:
            pairs.append((name.encode("latin-1"), str(item).encode("latin-1")))
    return pairs


def trailer_pairs(trailer: Any) -> list[tuple[bytes, bytes]]:
    """Flatten httpcloak's response trailer block into ordered byte pairs.

    Empty when the response carried none. Worth forwarding because gRPC puts the call's
    real status in the trailers and answers 200 in the header block either way, so a
    proxy that drops them turns every failed call into a success.
    """
    pairs: list[tuple[bytes, bytes]] = []
    for name, value in (trailer or {}).items():
        values = value if isinstance(value, (list, tuple)) else [value]
        for item in values:
            pairs.append((name.encode("latin-1"), str(item).encode("latin-1")))
    return pairs
