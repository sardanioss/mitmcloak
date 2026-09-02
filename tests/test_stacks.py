"""What mitmcloak does with a ClientHello from each real TLS stack.

Every fixture here is a capture from the named client running against a socket that
reads one record and hangs up, so these are the bytes those clients actually send
rather than a model of them. The point of the file is coverage of stacks, not of
code paths: a mirror that only works for Chromium is not a mirror.
"""
import base64
import json
import sys
import types
from pathlib import Path

import pytest

from mitmcloak import capture, mirror


def _fixtures() -> dict:
    import mitmcloak

    packaged = Path(mitmcloak.__file__).parent / "data" / "client_hellos.json"
    if not packaged.exists():
        packaged = (Path(__file__).resolve().parent.parent
                    / "research" / "fixtures" / "client_hellos.json")
    data = json.loads(packaged.read_text())
    data.pop("_note", None)
    return data


def _hello(name: str):
    return capture.parse_client_hello(
        base64.b64decode(_fixtures()[name]["client_hello_b64"]))


ALL = sorted(_fixtures())


@pytest.mark.parametrize("name", ALL)
def test_every_stack_parses_and_builds_a_preset(name):
    info = _hello(name)
    doc = mirror.build_preset(mirror.ClientProfile(hello=info), "chrome-151-windows", "mc-x")
    assert doc["preset"]["tls"]["raw_client_hello"]
    assert info.ciphers, "a ClientHello with no cipher suites is not one"


# Recorded from the Go stack httpcloak links, per stack. These are the suites that
# would fail *if the origin selected one*; the offer itself always goes out verbatim,
# so none of this changes the fingerprint. A change here means either a new fixture
# or that the Go stack's cipher table moved, and both deserve a look.
UNNEGOTIABLE = {
    "chrome-151-windows": 0,
    "chromium-150-boringssl": 0,
    "chromium-150-boringssl-second-connection": 0,
    "firefox-148-linux": 0,
    "firefox-152-nss": 0,
    "go-crypto-tls": 0,
    "curl-8.21-openssl": 10,
    "python-3.14-openssl": 6,
    "node-22-openssl": 32,
    "wget-1.25-gnutls": 12,
    "java-26-jsse": 15,
}


@pytest.mark.parametrize("name", ALL)
def test_unnegotiable_cipher_count_is_pinned(name):
    assert len(mirror.unnegotiable_ciphers(_hello(name))) == UNNEGOTIABLE[name]


def test_browsers_offer_nothing_the_stack_cannot_finish():
    """The stacks people actually browse with are fully covered, which is why a
    mirrored browser never fails on cipher selection. The gap is entirely in
    OpenSSL-family and JSSE clients, and entirely in suites no modern origin picks."""
    for name in ("chromium-150-boringssl", "firefox-152-nss", "chrome-151-windows"):
        assert mirror.unnegotiable_ciphers(_hello(name)) == []


def test_chromium_reorders_its_extensions_and_firefox_does_not():
    """Measured from two consecutive real connections, and the reason permute_raw_hello
    has to be declared: one capture cannot tell you whether the client would have
    ordered them differently next time."""
    a = _hello("chromium-150-boringssl")
    b = _hello("chromium-150-boringssl-second-connection")
    assert set(a.extension_order) == set(b.extension_order)
    assert a.extension_order != b.extension_order
    assert a.family_id == b.family_id, "a permuting client must keep one identity"


# ------------------------------------------------------------------ registration

class _FakeHttpcloak(types.ModuleType):
    """Stands in for httpcloak so registration can be driven without the cgo library."""

    def __init__(self, reject_extensions=()):
        super().__init__("httpcloak")
        self.reject = set(reject_extensions)
        self.loaded: list[dict] = []

    def load_preset_from_json(self, blob):
        doc = json.loads(blob)
        self.loaded.append(doc)
        if self.reject and not doc["preset"]["tls"].get("allow_blunt_mimicry"):
            raise RuntimeError("unsupported extension %d" % sorted(self.reject)[0])

    def unregister_preset(self, name):
        pass


@pytest.fixture
def fake_httpcloak(monkeypatch):
    def install(reject_extensions=()):
        fake = _FakeHttpcloak(reject_extensions)
        monkeypatch.setitem(sys.modules, "httpcloak", fake)
        return fake
    return install


def test_blunt_mimicry_is_asked_for_not_guessed(fake_httpcloak):
    """A table of the extensions httpcloak models would drift on its next release, and
    silently: one entry too many and the client falls back to a generic preset."""
    fake = fake_httpcloak(reject_extensions={22})
    profile = mirror.ClientProfile(hello=_hello("curl-8.21-openssl"))
    name = mirror.MirrorRegistry().ensure(profile, "chrome-151-windows")
    assert name is not None
    assert len(fake.loaded) == 2, "it must try without blunt mimicry first"
    assert "allow_blunt_mimicry" not in fake.loaded[0]["preset"]["tls"]
    assert fake.loaded[1]["preset"]["tls"]["allow_blunt_mimicry"] is True


def test_a_hello_the_stack_models_never_gets_blunt_mimicry(fake_httpcloak):
    fake = fake_httpcloak()
    profile = mirror.ClientProfile(hello=_hello("chromium-150-boringssl"))
    assert mirror.MirrorRegistry().ensure(profile, "chrome-151-windows") is not None
    assert len(fake.loaded) == 1
    assert "allow_blunt_mimicry" not in fake.loaded[0]["preset"]["tls"]


def test_permutation_is_declared_when_the_base_was_measured_permuting(fake_httpcloak):
    fake = fake_httpcloak()
    profile = mirror.ClientProfile(hello=_hello("chromium-150-boringssl"))
    mirror.MirrorRegistry().ensure(profile, "chrome-151-windows", base_permutes=True)
    assert fake.loaded[0]["preset"]["tls"]["permute_raw_hello"] is True


def test_permutation_is_not_declared_for_a_stack_that_does_not(fake_httpcloak):
    fake = fake_httpcloak()
    profile = mirror.ClientProfile(hello=_hello("firefox-152-nss"))
    mirror.MirrorRegistry().ensure(profile, "firefox-148-linux", base_permutes=False)
    assert "permute_raw_hello" not in fake.loaded[0]["preset"]["tls"]


def test_blunt_mimicry_drops_the_shuffle(fake_httpcloak):
    """httpcloak ignores permute_raw_hello under blunt mimicry, so sending both would
    describe a preset that does not exist. A real frozen order beats a shuffled one
    built from extensions we could not model."""
    fake = fake_httpcloak(reject_extensions={22})
    profile = mirror.ClientProfile(hello=_hello("node-22-openssl"))
    mirror.MirrorRegistry().ensure(profile, "chrome-151-windows", base_permutes=True)
    tls = fake.loaded[-1]["preset"]["tls"]
    assert tls["allow_blunt_mimicry"] is True
    assert "permute_raw_hello" not in tls


def test_a_client_that_starts_permuting_gets_a_new_preset(fake_httpcloak):
    """stable_id sorts extensions, so every order of one client hashes the same. If
    permute were left out of the cache key, the preset minted from the first
    connection would pin permute=False for the rest of the run."""
    fake = fake_httpcloak()
    registry = mirror.MirrorRegistry()
    a = _hello("chromium-150-boringssl")
    b = _hello("chromium-150-boringssl-second-connection")
    profile = mirror.ClientProfile(hello=a)
    profile.orders_seen.add(a.extension_order)
    first = registry.ensure(profile, "chrome-151-windows")
    assert "permute_raw_hello" not in fake.loaded[0]["preset"]["tls"]

    profile.orders_seen.add(b.extension_order)      # a second order, from the client
    second = registry.ensure(profile, "chrome-151-windows")
    assert second != first
    assert fake.loaded[1]["preset"]["tls"]["permute_raw_hello"] is True
