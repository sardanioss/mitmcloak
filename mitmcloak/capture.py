"""Raw wire parsing for client fingerprints.

Deliberately free of any httpcloak import. Everything here is byte manipulation on
material mitmproxy hands us, so it unit-tests without the cgo library present and can
be reused as a standalone extractor.
"""
from __future__ import annotations

import base64
import hashlib
import struct
from dataclasses import dataclass, field
from typing import Any

H2_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

# RFC 8879 codepoints, for turning the compress_certificate extension into the names
# httpcloak's preset schema expects.
_CERT_COMP = {1: "zlib", 2: "brotli", 3: "zstd"}

# HPACK representation prefixes (RFC 7541 section 6).
_REPR_INDEXED = "indexed"
_REPR_INCREMENTAL = "incremental"
_REPR_WITHOUT = "without"
_REPR_NEVER = "never"


def is_grease(value: int) -> bool:
    """RFC 8701 GREASE values are 0x?a?a with both nibbles equal."""
    return (value & 0x0F0F) == 0x0A0A


def _u16_list(buf: bytes) -> list[int]:
    return [struct.unpack("!H", buf[i:i + 2])[0] for i in range(0, len(buf) - 1, 2)]


@dataclass
class ClientHelloInfo:
    """What a single observed ClientHello tells us."""

    raw: bytes
    """The full TLS record, exactly as it went past. This is what httpcloak replays."""

    ja3: str
    """Human-readable form. Not used for replay, only for display and hashing."""

    extension_order: tuple[int, ...]
    """Extension types in wire order, GREASE stripped. Used to detect permutation."""

    signature_algorithms: list[int] = field(default_factory=list)
    alpn: list[str] = field(default_factory=list)
    cert_compression: list[str] = field(default_factory=list)
    supported_versions: list[int] = field(default_factory=list)
    key_share_curves: int = 0
    record_size_limit: int | None = None
    has_grease: bool = False
    has_psk: bool = False
    """Extension 41. A hello carrying it is a resumption, not a fresh connection."""
    sni: str | None = None

    @property
    def raw_b64(self) -> str:
        return base64.b64encode(self.raw).decode("ascii")

    def _identity_parts(self, include_alpn: bool) -> list[str]:
        # Extension 0 is server_name, which a client omits when the target is a bare
        # IP and sends when it is a hostname. That is a property of the request, not
        # of the client, so including it would give one client two identities.
        identifying = sorted(e for e in self.extension_order if e != 0)
        parts = [
            self.ja3.split(",")[0],                       # version
            self.ja3.split(",")[1],                       # ciphers, in order
            "-".join(str(x) for x in identifying),
            self.ja3.split(",")[3],                       # curves
            self.ja3.split(",")[4],                       # point formats
            "-".join(str(x) for x in self.signature_algorithms),
            ",".join(self.cert_compression),
            str(self.key_share_curves),
            str(self.record_size_limit),
        ]
        if include_alpn:
            parts.append(",".join(self.alpn))
        return parts

    @property
    def family_id(self) -> str:
        """Identity of the underlying TLS stack, for matching against known presets.

        Excludes ALPN as well as SNI. Two clients on the same stack that differ only
        in whether they offer h2 still want the same base preset, because the base
        supplies the header block and the H2 defaults rather than the protocol choice.
        On iOS this is the difference between Safari and a system agent, and both are
        Apple's stack.
        """
        return hashlib.sha256("|".join(self._identity_parts(False)).encode()).hexdigest()[:12]

    @property
    def stable_id(self) -> str:
        """Content address for this fingerprint.

        Deliberately NOT a hash of `raw`: the 32-byte random, the session id and the
        key-share public keys differ on every single connection, so hashing the bytes
        would mint a new preset per request. This hashes only the parts that identify
        the client, and pointedly excludes extension ORDER, so a permuting client
        still lands on one identity.
        """
        return hashlib.sha256(
            "|".join(self._identity_parts(True)).encode()
        ).hexdigest()[:12]


def parse_client_hello(raw: bytes, sni: str | None = None) -> ClientHelloInfo:
    """Parse a full TLS record (starting 0x16) into the parts a preset needs.

    Raises ValueError on anything that is not a ClientHello record.
    """
    if len(raw) < 6 or raw[0] != 0x16:
        raise ValueError("not a TLS handshake record")

    # Skip record header (5) + handshake header (4) + client_version (2) + random (32).
    body = raw[5:]
    if len(body) < 38 or body[0] != 0x01:
        raise ValueError("not a ClientHello")
    version = struct.unpack("!H", body[4:6])[0]
    pos = 6 + 32
    session_len = body[pos]
    pos += 1 + session_len
    cipher_len = struct.unpack("!H", body[pos:pos + 2])[0]
    pos += 2
    ciphers = _u16_list(body[pos:pos + cipher_len])
    pos += cipher_len
    comp_len = body[pos]
    pos += 1 + comp_len

    info_kwargs: dict[str, Any] = {}
    ext_order: list[int] = []
    curves: list[int] = []
    point_formats: list[int] = []
    grease_seen = any(is_grease(c) for c in ciphers)

    if pos + 2 <= len(body):
        ext_total = struct.unpack("!H", body[pos:pos + 2])[0]
        pos += 2
        end = min(pos + ext_total, len(body))
        while pos + 4 <= end:
            etype = struct.unpack("!H", body[pos:pos + 2])[0]
            elen = struct.unpack("!H", body[pos + 2:pos + 4])[0]
            edata = body[pos + 4:pos + 4 + elen]
            pos += 4 + elen
            if is_grease(etype):
                grease_seen = True
                continue
            ext_order.append(etype)
            _read_extension(etype, edata, curves, point_formats, info_kwargs)

    ja3 = "{},{},{},{},{}".format(
        version,
        "-".join(str(c) for c in ciphers if not is_grease(c)),
        "-".join(str(e) for e in ext_order),
        "-".join(str(c) for c in curves),
        "-".join(str(p) for p in point_formats),
    )
    return ClientHelloInfo(
        raw=raw,
        ja3=ja3,
        extension_order=tuple(ext_order),
        has_grease=grease_seen,
        has_psk=41 in ext_order,
        sni=sni,
        **info_kwargs,
    )


def _read_extension(etype, data, curves, point_formats, out) -> None:
    """Pull the fields the preset schema can carry out of one extension body."""
    if etype == 10 and len(data) >= 2:                       # supported_groups
        n = struct.unpack("!H", data[0:2])[0]
        curves.extend(g for g in _u16_list(data[2:2 + n]) if not is_grease(g))
    elif etype == 11 and len(data) >= 1:                     # ec_point_formats
        point_formats.extend(data[1:1 + data[0]])
    elif etype == 13 and len(data) >= 2:                     # signature_algorithms
        n = struct.unpack("!H", data[0:2])[0]
        out["signature_algorithms"] = _u16_list(data[2:2 + n])
    elif etype == 16 and len(data) >= 2:                     # ALPN
        n = struct.unpack("!H", data[0:2])[0]
        blob, p, names = data[2:2 + n], 0, []
        while p < len(blob):
            ln = blob[p]
            names.append(blob[p + 1:p + 1 + ln].decode("ascii", "replace"))
            p += 1 + ln
        out["alpn"] = names
    elif etype == 27 and len(data) >= 1:                     # compress_certificate
        out["cert_compression"] = [
            _CERT_COMP.get(a, str(a)) for a in _u16_list(data[1:1 + data[0]])
        ]
    elif etype == 28 and len(data) >= 2:                     # record_size_limit
        out["record_size_limit"] = struct.unpack("!H", data[0:2])[0]
    elif etype == 43 and len(data) >= 1:                     # supported_versions
        out["supported_versions"] = [
            v for v in _u16_list(data[1:1 + data[0]]) if not is_grease(v)
        ]
    elif etype == 51 and len(data) >= 2:                     # key_share
        n = struct.unpack("!H", data[0:2])[0]
        blob, p, groups = data[2:2 + n], 0, 0
        while p + 4 <= len(blob):
            group = struct.unpack("!H", blob[p:p + 2])[0]
            ln = struct.unpack("!H", blob[p + 2:p + 4])[0]
            if not is_grease(group):
                groups += 1
            p += 4 + ln
        out["key_share_curves"] = groups


@dataclass
class H2Preface:
    """The client's HTTP/2 opening, which is three quarters of the Akamai fingerprint."""

    settings: list[tuple[int, int]] = field(default_factory=list)
    window_update: int | None = None
    pseudo_order: list[str] | None = None
    priority_frames: int = 0

    @property
    def akamai(self) -> str:
        """Display form. The preset is built from the discrete fields, not this."""
        s = ";".join(f"{k}:{v}" for k, v in self.settings)
        pseudo = ",".join(p[1] for p in (self.pseudo_order or []))
        return f"{s}|{self.window_update or 0}|{self.priority_frames}|{pseudo}"


def parse_h2_preface(buf: bytes) -> H2Preface | None:
    """Parse the client's H2 preface out of a raw buffer.

    Returns None when the buffer does not start with the connection preface, which is
    the normal case for HTTP/1.1 clients and for the pre-TLS next_layer calls.
    """
    if not buf.startswith(H2_PREFACE):
        return None
    out = H2Preface()
    pos = len(H2_PREFACE)
    header_block = b""
    while pos + 9 <= len(buf):
        length = int.from_bytes(buf[pos:pos + 3], "big")
        ftype = buf[pos + 3]
        flags = buf[pos + 4]
        stream_id = struct.unpack("!I", buf[pos + 5:pos + 9])[0] & 0x7FFFFFFF
        body = buf[pos + 9:pos + 9 + length]
        if len(body) < length:
            break                                    # frame truncated, stop cleanly
        if ftype == 0x04:                            # SETTINGS
            for i in range(0, length - 5, 6):
                out.settings.append((
                    struct.unpack("!H", body[i:i + 2])[0],
                    struct.unpack("!I", body[i + 2:i + 6])[0],
                ))
        elif ftype == 0x08 and length == 4 and stream_id == 0:
            # Connection-level only. A stream-level WINDOW_UPDATE read as the
            # connection one silently produces the wrong Akamai string.
            out.window_update = struct.unpack("!I", body)[0] & 0x7FFFFFFF
        elif ftype == 0x02:                          # PRIORITY
            out.priority_frames += 1
        elif ftype == 0x01 and not header_block:     # first HEADERS
            block = body
            if flags & 0x08 and block:               # PADDED
                block = block[1 + block[0]:]
            if flags & 0x20:                         # PRIORITY
                block = block[5:]
            header_block = block
        pos += 9 + length

    if header_block:
        out.pseudo_order = _pseudo_order(header_block)
    return out


def _pseudo_order(block: bytes) -> list[str] | None:
    """Decode just far enough to recover pseudo-header order.

    mitmproxy already depends on `hpack`, so this costs nothing. Best effort: whether
    the HEADERS frame has arrived by the time we look depends on how the client packs
    its writes, and the caller must cope with None.
    """
    try:
        import hpack

        decoded = hpack.Decoder().decode(block, raw=True)
    except Exception:
        return None
    order = [k.decode() for k, _ in decoded if k.startswith(b":")]
    return order or None


def parse_hpack_representations(block: bytes) -> list[tuple[str, str | None]]:
    """Map a raw HPACK block to (representation, header_name_if_known) pairs.

    Used to derive the per-name representation overrides a mirrored preset needs when
    the client diverges from its base policy. Returns [] if the block will not parse.
    """
    try:
        import hpack

        names = [k.decode() for k, _ in hpack.Decoder().decode(block, raw=True)]
    except Exception:
        names = []

    out: list[tuple[str, str | None]] = []
    pos = 0
    idx = 0
    try:
        while pos < len(block):
            first = block[pos]
            if first & 0x80:
                _, pos = _hpack_varint(block, pos, 7)
                kind = _REPR_INDEXED
            elif first & 0xE0 == 0x20:               # dynamic table size update
                _, pos = _hpack_varint(block, pos, 5)
                continue
            else:
                if first & 0xC0 == 0x40:
                    kind, bits = _REPR_INCREMENTAL, 6
                elif first & 0xF0 == 0x10:
                    kind, bits = _REPR_NEVER, 4
                else:
                    kind, bits = _REPR_WITHOUT, 4
                name_idx, pos = _hpack_varint(block, pos, bits)
                if name_idx == 0:
                    pos = _hpack_skip_string(block, pos)
                pos = _hpack_skip_string(block, pos)
            out.append((kind, names[idx] if idx < len(names) else None))
            idx += 1
    except (IndexError, ValueError):
        return out
    return out


def _hpack_varint(buf: bytes, pos: int, prefix_bits: int) -> tuple[int, int]:
    mask = (1 << prefix_bits) - 1
    value = buf[pos] & mask
    pos += 1
    if value < mask:
        return value, pos
    shift = 0
    while True:
        byte = buf[pos]
        pos += 1
        value += (byte & 0x7F) << shift
        shift += 7
        if not byte & 0x80:
            return value, pos


def _hpack_skip_string(buf: bytes, pos: int) -> int:
    length, pos = _hpack_varint(buf, pos, 7)
    return pos + length
