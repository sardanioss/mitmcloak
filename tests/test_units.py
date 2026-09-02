"""Header handling, rule parsing and the mirror preset builder."""
import base64
import json
from pathlib import Path

import pytest

from mitmcloak import capture, headers as hdrs, mirror
from mitmcloak.resolve import parse_rule
from mitmcloak.sessions import SessionPool

def _fixture_dir() -> Path:
    """Prefer the copy shipped inside the package, so these run against an installed
    wheel as well as a checkout."""
    import mitmcloak

    packaged = Path(mitmcloak.__file__).parent / "data"
    if (packaged / "client_hellos.json").exists():
        return packaged
    return Path(__file__).resolve().parent.parent / "research" / "fixtures"


def _chrome():
    data = json.loads((_fixture_dir() / "client_hellos.json").read_text())
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


def test_catalogue_records_a_client_that_never_sent_a_request():
    from mitmcloak.catalogue import Catalogue

    info = capture.parse_client_hello(_chrome())
    cat = Catalogue()
    cat.note_hello(info)
    cat.note_no_request(info.stable_id)
    doc = cat.document(info.stable_id, "chrome-151-windows")
    assert doc["_observed"]["connections_without_a_request"] == 1
    assert doc["_observed"]["tls_only"] is True      # no H2 preface was ever seen
    assert doc["preset"]["tls"]["raw_client_hello"]


def test_catalogue_entry_is_a_loadable_preset_document():
    """The _observed block rides alongside; Go ignores unknown top-level fields."""
    from mitmcloak.catalogue import Catalogue

    info = capture.parse_client_hello(_chrome())
    cat = Catalogue()
    cat.note_hello(info)
    doc = cat.document(info.stable_id, "chrome-151-windows")
    assert doc["version"] == 1
    assert set(doc) == {"version", "preset", "_observed"}


def test_catalogue_upgrades_an_entry_when_the_h2_half_arrives():
    from mitmcloak.catalogue import Catalogue

    info = capture.parse_client_hello(_chrome())
    cat = Catalogue()
    cat.note_hello(info)
    assert not cat.entries[info.stable_id].complete
    cat.note_h2(info.stable_id, capture.H2Preface(settings=[(1, 65536)]))
    assert cat.entries[info.stable_id].complete


def test_upstream_mode_is_handed_to_httpcloak():
    """Otherwise the operator's proxy is silently bypassed and requests leave from
    the real address while they believe they are chained."""
    from mitmcloak.options import upstream_from_mode

    class O:
        mode = ["upstream:http://127.0.0.1:8080"]
    assert upstream_from_mode(O) == "http://127.0.0.1:8080"


def test_upstream_mode_gains_a_scheme_when_bare():
    from mitmcloak.options import upstream_from_mode

    class O:
        mode = ["upstream:127.0.0.1:8080"]
    assert upstream_from_mode(O) == "http://127.0.0.1:8080"


def test_regular_mode_has_no_upstream():
    from mitmcloak.options import upstream_from_mode

    class O:
        mode = ["regular"]
    assert upstream_from_mode(O) is None


def test_explicit_proxy_option_wins_over_upstream_mode():
    from mitmcloak.options import session_options

    class O:
        mode = ["upstream:http://from-mode:8080"]
        mitmcloak_timeout = 30; mitmcloak_verify = True
        mitmcloak_http_version = "auto"; mitmcloak_disable_ech = False
        mitmcloak_tls_only = False; mitmcloak_proxy = "http://explicit:9090"
        mitmcloak_ja3 = ""; mitmcloak_akamai = ""
        mitmcloak_tcp_ttl = 0; mitmcloak_tcp_mss = 0; mitmcloak_tcp_window_size = 0
    assert session_options(O)["proxy"] == "http://explicit:9090"


def test_pool_identifies_supplied_sessions_by_identity_not_id():
    """CPython reuses object ids, so keying on id() could make the pool refuse to
    close a session it actually owns."""
    import weakref

    from mitmcloak.sessions import SessionPool

    pool = SessionPool(max_sessions=4)
    assert isinstance(pool._external, weakref.WeakSet)
    supplied = _FakeSession()
    pool.adopt(("a",), supplied)
    owned = _FakeSession()
    pool.get(("b",), lambda: owned)
    pool.close()
    assert not supplied.closed          # theirs, left alone
    assert owned.closed                 # ours, closed


def test_pool_defaults_bound_memory():
    """The cap is a memory ceiling: ~190 kB per live session, and closing returns
    nothing to the OS, so the default must be a deliberate number."""
    from mitmcloak.sessions import SessionPool

    pool = SessionPool()
    assert pool.max_sessions == 96
    assert pool.max_idle == 120.0


def test_zero_hit_rate_is_detectable():
    """A pool whose origins exceed its cap and rotate never hits, which makes it an
    allocation treadmill rather than a cache. `reused == 0` while `created` climbs is
    the signal the addon warns on."""
    from mitmcloak.sessions import SessionPool

    pool = SessionPool(max_sessions=4)
    for i in range(40):                       # 10 origins rotating, cap 4
        pool.get((f"h{i % 10}",), _FakeSession)
    assert pool.reused == 0
    assert pool.created == 40
    assert pool.evicted == 36


# --------------------------------------------------------------- exact headers

RAW_FIELDS = [
    (b"Host", b"example.com"), (b"Cookie", b"a=1"), (b"X-ODD-CASE", b"1"),
    (b"Cookie", b"b=2"), (b"User-Agent", b"probe/1"),
    (b"Connection", b"keep-alive"), (b"Content-Length", b"0"),
]


def test_exact_headers_keep_order_casing_and_duplicates():
    """The three things a dict destroys. Measured through the proxy: an origin sees
    Cookie, X-ODD-CASE, Cookie in that order, where merge mode sends one Cookie and
    X-Odd-Case."""
    got = hdrs.exact_headers(RAW_FIELDS)
    assert got == [
        ("Cookie", "a=1"), ("X-ODD-CASE", "1"), ("Cookie", "b=2"),
        ("User-Agent", "probe/1"),
    ]


def test_exact_headers_still_drop_hop_by_hop_and_framing():
    """Forwarding a hop-by-hop header is a proxy bug, not fidelity, and httpcloak
    writes Host itself, so listing it again puts two on the wire."""
    names = [n.lower() for n, _ in hdrs.exact_headers(RAW_FIELDS)]
    assert "host" not in names
    assert "connection" not in names
    assert "content-length" not in names


def test_merge_mode_still_collapses_what_exact_mode_keeps():
    """Not a regression: it is the reason exact mode exists."""
    merged = hdrs.request_headers(RAW_FIELDS, "merge")
    assert merged["Cookie"] == "a=1; b=2"       # two headers became one
    assert len(hdrs.exact_headers(RAW_FIELDS)) == 4


def test_exact_is_a_selectable_mode():
    assert "exact" in hdrs.MODES


# ------------------------------------------------------------------- trailers

def test_trailer_pairs_flattens_repeated_names():
    assert hdrs.trailer_pairs({"grpc-status": ["14"], "x-multi": ["a", "b"]}) == [
        (b"grpc-status", b"14"), (b"x-multi", b"a"), (b"x-multi", b"b"),
    ]


def test_trailer_pairs_is_empty_when_there_were_none():
    assert hdrs.trailer_pairs(None) == []
    assert hdrs.trailer_pairs({}) == []


# --------------------------------------------------------- how headers are sent

class _Req:
    def __init__(self, fields, version="HTTP/2.0"):
        self.headers = type("H", (), {"fields": fields})()
        self.http_version = version


class _Flow:
    def __init__(self, fields, version="HTTP/2.0"):
        self.request = _Req(fields, version)


class _Decision:
    def __init__(self, reason):
        self.reason = reason


def _bridge(mode):
    from mitmcloak.bridge import Bridge

    b = Bridge()
    b._header_mode = lambda: mode
    return b


def test_exact_mode_sends_pairs_and_nothing_else():
    kwargs = _bridge("exact")._header_kwargs(_Flow(RAW_FIELDS), _Decision("mirror"))
    assert list(kwargs) == ["exact_headers"]
    assert kwargs["exact_headers"][0] == ("Cookie", "a=1")


def test_header_order_is_sent_only_when_the_preset_mirrors_this_client():
    """Under a static preset the client is some other program, and forcing its header
    order onto a browser's header block describes a client that does not exist."""
    mirrored = _bridge("merge")._header_kwargs(_Flow(RAW_FIELDS), _Decision("mirror"))
    static = _bridge("merge")._header_kwargs(_Flow(RAW_FIELDS), _Decision("static"))
    assert mirrored["header_order"] == ["cookie", "x-odd-case", "user-agent"]
    assert "header_order" not in static
