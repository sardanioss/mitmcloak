"""Unit tests for the wire parsing. No network, no cgo library, no mitmproxy runtime."""
import base64
import json
from pathlib import Path

import pytest

from mitmcloak import capture

def _fixture_dir() -> Path:
    """Prefer the copy shipped inside the package, so these run against an installed
    wheel as well as a checkout."""
    import mitmcloak

    return Path(mitmcloak.__file__).parent / "data"


def _hellos():
    data = json.loads((_fixture_dir() / "client_hellos.json").read_text())
    return {k: base64.b64decode(v["client_hello_b64"])
            for k, v in data.items() if not k.startswith("_")}


@pytest.fixture(scope="module")
def hellos():
    return _hellos()


def test_grease_detection():
    assert capture.is_grease(0x0A0A)
    assert capture.is_grease(0xBABA)
    assert not capture.is_grease(0x0403)


def test_chrome_hello_has_grease(hellos):
    info = capture.parse_client_hello(hellos["chrome-151-windows"])
    assert info.has_grease
    assert not info.has_psk
    # ML-DSA codepoints; JA3 cannot carry these, which is why the raw bytes are replayed.
    assert 2308 in info.signature_algorithms
    assert info.alpn == ["h2", "http/1.1"]
    assert info.cert_compression == ["brotli"]


def test_curl_hello_has_no_grease(hellos):
    info = capture.parse_client_hello(hellos["curl-8.21-openssl"])
    assert not info.has_grease
    assert len(info.signature_algorithms) == 26


def test_firefox_hello(hellos):
    info = capture.parse_client_hello(hellos["firefox-148-linux"])
    assert not info.has_grease
    assert info.key_share_curves >= 1


# Fixtures that are the same client seen twice, or a preset and the browser it
# models. They must collapse onto one identity, so they are excluded from the
# all-different check below and asserted on directly instead.
SAME_CLIENT = {
    "chrome-151-windows",
    "chromium-150-boringssl",
    "chromium-150-boringssl-second-connection",
}


def test_stable_id_differs_per_client(hellos):
    ids = {name: capture.parse_client_hello(raw).stable_id
           for name, raw in hellos.items() if name not in SAME_CLIENT}
    assert len(set(ids.values())) == len(ids)


def test_one_client_keeps_one_identity_across_stacks_that_permute(hellos):
    """Two consecutive real Chromium connections send different extension orders. If
    that produced two identities it would mint a preset per connection, and the
    httpcloak preset modelling that browser has to land on the same one."""
    ids = {capture.parse_client_hello(hellos[n]).stable_id for n in SAME_CLIENT}
    assert len(ids) == 1


def test_stable_id_ignores_extension_order(hellos):
    """A permuting client must land on one identity, not a new preset per connection."""
    info = capture.parse_client_hello(hellos["chrome-151-windows"])
    shuffled = capture.ClientHelloInfo(
        raw=info.raw,
        ja3=info.ja3,
        extension_order=tuple(reversed(info.extension_order)),
        signature_algorithms=info.signature_algorithms,
        alpn=info.alpn,
        cert_compression=info.cert_compression,
        key_share_curves=info.key_share_curves,
        record_size_limit=info.record_size_limit,
    )
    assert shuffled.stable_id == info.stable_id


def test_rejects_non_handshake():
    with pytest.raises(ValueError):
        capture.parse_client_hello(b"\x17\x03\x03\x00\x05hello")


def test_h2_preface_none_for_non_h2():
    assert capture.parse_h2_preface(b"GET / HTTP/1.1\r\n\r\n") is None


def _frame(ftype, flags, stream, payload):
    return (len(payload).to_bytes(3, "big") + bytes([ftype, flags])
            + stream.to_bytes(4, "big") + payload)


def test_h2_preface_parses_settings_and_connection_window_update():
    settings = b"".join(
        sid.to_bytes(2, "big") + val.to_bytes(4, "big")
        for sid, val in ((3, 100), (4, 65536), (2, 0))
    )
    buf = (capture.H2_PREFACE
           + _frame(0x04, 0, 0, settings)
           + _frame(0x08, 0, 5, (999).to_bytes(4, "big"))       # STREAM-level, ignore
           + _frame(0x08, 0, 0, (1048510465).to_bytes(4, "big")))  # connection-level
    out = capture.parse_h2_preface(buf)
    assert out.settings == [(3, 100), (4, 65536), (2, 0)]
    # A stream-level WINDOW_UPDATE read as the connection one silently produces the
    # wrong Akamai string, which is exactly the bug this locks.
    assert out.window_update == 1048510465


def test_h2_preface_ignores_truncated_trailing_frame():
    buf = capture.H2_PREFACE + _frame(0x04, 0, 0, b"") + b"\x00\x00\x40\x01\x00\x00"
    out = capture.parse_h2_preface(buf)
    assert out is not None and out.settings == []


def test_hpack_representations():
    import hpack

    enc = hpack.Encoder()
    block = enc.encode([(":method", "GET"), ("x-thing", "value")])
    reps = capture.parse_hpack_representations(block)
    assert reps
    assert all(kind in ("indexed", "incremental", "without", "never")
               for kind, _ in reps)


def test_quic_hello_is_recognised(hellos):
    """A QUIC hello replayed over TCP is a shape no real client produces."""
    tcp = capture.parse_client_hello(hellos["chrome-151-windows"])
    assert not tcp.is_quic

    quic = capture.ClientHelloInfo(
        raw=tcp.raw, ja3=tcp.ja3,
        extension_order=tuple(list(tcp.extension_order) + [57]),
        alpn=["h3", "h3-29"],
    )
    assert quic.is_quic


def test_h3_only_alpn_alone_marks_a_quic_hello(hellos):
    tcp = capture.parse_client_hello(hellos["chrome-151-windows"])
    quic = capture.ClientHelloInfo(
        raw=tcp.raw, ja3=tcp.ja3, extension_order=tcp.extension_order, alpn=["h3"],
    )
    assert quic.is_quic
