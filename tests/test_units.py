"""Header handling, rule parsing and the mirror preset builder."""
import base64
import json
from pathlib import Path

import pytest

from mitmcloak import capture, headers as hdrs, mirror
from mitmcloak.resolve import parse_rule
from mitmcloak.sessions import SessionPool

FIXTURES = Path(__file__).resolve().parent.parent / "research" / "fixtures"


def _chrome():
    data = json.loads((FIXTURES / "client_hellos.json").read_text())
    return base64.b64decode(data["chrome-151-windows"]["client_hello_b64"])


FIELDS = [
    (b"Host", b"example.com"), (b"Cookie", b"a=1"), (b"Cookie", b"b=2"),
    (b"User-Agent", b"UA"), (b"X-Odd", b"1"), (b"Connection", b"keep-alive"),
    (b"Accept", b"text/html"),
]


def test_hop_by_hop_stripped():
    out = hdrs.request_headers(FIELDS, "merge")
    assert "Host" not in out and "Connection" not in out


def test_cookie_crumbs_rejoin_with_semicolon():
    assert hdrs.request_headers(FIELDS, "merge")["Cookie"] == "a=1; b=2"


def test_replace_mode_keeps_semantic_and_x_headers():
    out = hdrs.request_headers(FIELDS, "replace")
    assert "Cookie" in out and "X-Odd" in out and "User-Agent" not in out


def test_header_order_is_deduped_and_lowercased():
    assert hdrs.header_order(FIELDS) == ["cookie", "user-agent", "x-odd", "accept"]


def test_response_keeps_every_set_cookie():
    pairs = hdrs.response_pairs({"set-cookie": ["a=1", "b=2", "c=3"], "x": "y"})
    assert sum(1 for k, _ in pairs if k == b"set-cookie") == 3


def test_response_drops_content_length_and_encoding():
    """httpcloak already decoded the body; re-advertising makes the client decode twice."""
    pairs = hdrs.response_pairs(
        {"content-length": ["5"], "content-encoding": ["gzip"], "x": "y"}
    )
    assert [k for k, _ in pairs] == [b"x"]


def test_rule_parsing_accepts_any_separator():
    assert parse_rule("/~d example\\.com/chrome-151-ios").preset == "chrome-151-ios"
    assert parse_rule("|~m POST|firefox-148-linux").preset == "firefox-148-linux"


def test_rule_without_a_preset_is_rejected():
    with pytest.raises(Exception):
        parse_rule("/~d example\\.com/")


def test_base_selection_prefers_firefox_over_platform():
    ua = "Mozilla/5.0 (Windows NT 10.0; rv:148.0) Gecko/20100101 Firefox/148.0"
    assert mirror.base_for_user_agent(ua, "x") == "firefox-148-windows"


def test_base_selection_falls_back():
    assert mirror.base_for_user_agent("", "chrome-151-linux") == "chrome-151-linux"


def test_built_preset_always_carries_based_on():
    """A preset with only a tls block builds from an empty Preset and every request fails."""
    info = capture.parse_client_hello(_chrome())
    doc = mirror.build_preset(mirror.ClientProfile(hello=info), "chrome-151-windows", "mc-x")
    assert doc["preset"]["based_on"] == "chrome-151-windows"
    assert doc["preset"]["tls"]["raw_client_hello"]


def test_built_preset_uses_discrete_h2_form():
    """The akamai shorthand overlays on the base and lets base settings leak through."""
    info = capture.parse_client_hello(_chrome())
    profile = mirror.ClientProfile(hello=info)
    profile.h2 = capture.H2Preface(
        settings=[(3, 100), (4, 65536)], window_update=1048510465,
        pseudo_order=[":method", ":scheme", ":authority", ":path"],
    )
    block = mirror.build_preset(profile, "chrome-151-windows", "mc-x")["preset"]["http2"]
    assert "akamai" not in block
    assert block["settings"] == [{"id": 3, "value": 100}, {"id": 4, "value": 65536}]
    assert block["settings_order"] == [3, 4]
    assert block["connection_window_update"] == 1048510465


def test_pseudo_order_is_omitted_when_not_decoded():
    """Desktop Chrome is m,a,s,p but iOS Chrome is m,s,a,p; a hardcoded default is wrong."""
    info = capture.parse_client_hello(_chrome())
    profile = mirror.ClientProfile(hello=info)
    profile.h2 = capture.H2Preface(settings=[(1, 65536)])
    assert "pseudo_order" not in mirror.build_preset(
        profile, "chrome-151-windows", "mc-x")["preset"]["http2"]


def test_permutation_needs_two_distinct_orders():
    info = capture.parse_client_hello(_chrome())
    profile = mirror.ClientProfile(hello=info)
    profile.orders_seen.add(info.extension_order)
    assert not profile.permutes
    profile.orders_seen.add(tuple(reversed(info.extension_order)))
    assert profile.permutes


class _FakeSession:
    def __init__(self):
        self.closed = False
        self._idle = 0.0

    def idle_time(self):
        return self._idle

    def close(self):
        self.closed = True


def test_pool_evicts_and_closes():
    pool = SessionPool(max_sessions=2)
    made = [pool.get((i,), _FakeSession) for i in range(3)]
    assert len(pool) == 2
    assert made[0].closed


def test_pool_sweeps_idle_sessions():
    pool = SessionPool(max_sessions=10, max_idle=5.0)
    session = pool.get(("a",), _FakeSession)
    session._idle = 99.0
    assert pool.sweep() == 1
    assert session.closed


def test_pool_never_closes_a_supplied_session():
    """A session the user handed us stays theirs; we use it and let go."""
    pool = SessionPool(max_sessions=1)
    supplied = _FakeSession()
    pool.adopt(("a",), supplied)
    pool.get(("b",), _FakeSession)          # forces eviction of the supplied one
    assert not supplied.closed


def test_family_id_ignores_alpn_but_stable_id_does_not():
    """Safari and an HTTP/1.1-only system agent share a stack and want the same base."""
    info = capture.parse_client_hello(_chrome())
    h1_only = capture.ClientHelloInfo(
        raw=info.raw, ja3=info.ja3, extension_order=info.extension_order,
        signature_algorithms=info.signature_algorithms, alpn=["http/1.1"],
        cert_compression=info.cert_compression, key_share_curves=info.key_share_curves,
        record_size_limit=info.record_size_limit,
    )
    assert h1_only.family_id == info.family_id
    assert h1_only.stable_id != info.stable_id


def test_identity_ignores_sni_presence():
    """A client omits SNI for a bare IP target; that is the request, not the client."""
    info = capture.parse_client_hello(_chrome())
    assert 0 in info.extension_order
    without_sni = capture.ClientHelloInfo(
        raw=info.raw, ja3=info.ja3,
        extension_order=tuple(e for e in info.extension_order if e != 0),
        signature_algorithms=info.signature_algorithms, alpn=info.alpn,
        cert_compression=info.cert_compression, key_share_curves=info.key_share_curves,
        record_size_limit=info.record_size_limit,
    )
    assert without_sni.family_id == info.family_id


def test_real_iphone_capture_identifies_as_ios():
    """Locks the device result: a physical iPhone's stack must resolve to the iOS preset."""
    device = Path(__file__).resolve().parent.parent / "research" / "fixtures" / "device"
    captures = sorted(device.glob("*.json"))
    if not captures:
        pytest.skip("no device capture fixture")
    for path in captures:
        doc = json.loads(path.read_text())["preset"]
        info = capture.parse_client_hello(
            base64.b64decode(doc["tls"]["raw_client_hello"])
        )
        # Every hello the iPhone produced, Safari and system agents alike, is Apple's
        # stack and must land on one family.
        assert info.family_id == capture.parse_client_hello(
            base64.b64decode(json.loads(captures[0].read_text())
                             ["preset"]["tls"]["raw_client_hello"])
        ).family_id


def test_pinned_client_profile_is_still_a_usable_preset():
    """A client that refuses our CA never sends a request, so it never gets a
    User-Agent. Its preset must still build, which only works because the base now
    comes from the TLS stack."""
    info = capture.parse_client_hello(_chrome())
    profile = mirror.ClientProfile(hello=info)      # no h2, no request, no UA
    doc = mirror.build_preset(profile, "chrome-151-windows", "mc-pinned")["preset"]
    assert doc["based_on"] == "chrome-151-windows"
    assert doc["tls"]["raw_client_hello"]
    assert "http2" not in doc                        # never got past the handshake
