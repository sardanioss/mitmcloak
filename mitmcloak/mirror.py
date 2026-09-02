"""Turn observed client fingerprints into registered httpcloak presets.

The registry is process-global and name-keyed, and re-registering a name raises rather
than replacing, so names are content-addressed and every registration goes through the
cache here. All of it runs on the event loop; nothing in this module is thread-safe by
design, because it is never called from a thread.
"""
from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import dataclass, field

from .capture import ClientHelloInfo, H2Preface, is_grease

logger = logging.getLogger(__name__)

PRESET_PREFIX = "mc-"

# User-Agent substring -> base preset. `based_on` is mandatory: a preset carrying only a
# tls block builds from an empty Preset and every request through it fails. The base
# supplies the H2 settings, the header set and the protocol list.
_UA_BASES = (
    ("firefox", "firefox-148-windows"),
    ("iphone", "chrome-151-ios"),
    ("ipad", "chrome-151-ios"),
    ("android", "chrome-151-android"),
    ("macintosh", "chrome-151-macos"),
    ("mac os", "chrome-151-macos"),
    ("linux", "chrome-151-linux"),
    ("windows", "chrome-151-windows"),
)


_PLATFORM_TOKENS = (
    ("iphone", "ios"), ("ipad", "ios"), ("android", "android"),
    ("macintosh", "macos"), ("mac os", "macos"),
    ("cros", "linux"), ("linux", "linux"), ("x11", "linux"),
    ("windows", "windows"),
)


def platform_for_user_agent(ua: str) -> str | None:
    ua = (ua or "").lower()
    for needle, platform in _PLATFORM_TOKENS:
        if needle in ua:
            return platform
    return None


def refine_platform(base: str, ua: str, known: set) -> str:
    """Let the User-Agent choose the platform within a TLS-matched family.

    A stack's ClientHello identifies the browser but usually not the operating system:
    Firefox on Linux and on Windows send the same one. So TLS decides the family and
    the User-Agent decides the variant, which is the opposite way round from how each
    signal fails. When the UA says nothing useful, the TLS match stands.
    """
    platform = platform_for_user_agent(ua)
    if platform is None:
        return base
    head, _, current = base.rpartition("-")
    if not head or current == platform:
        return base
    candidate = f"{head}-{platform}"
    return candidate if candidate in known else base


def base_for_user_agent(ua: str, fallback: str) -> str:
    ua = (ua or "").lower()
    # Firefox first: its UA also contains the platform tokens.
    for needle, preset in _UA_BASES:
        if needle in ua:
            return preset
    return fallback


@dataclass
class ClientProfile:
    """Everything observed about one client connection, before it becomes a preset."""

    hello: ClientHelloInfo
    psk_hello: ClientHelloInfo | None = None
    h2: H2Preface | None = None
    orders_seen: set[tuple[int, ...]] = field(default_factory=set)

    @property
    def permutes(self) -> bool:
        """True once the same client has been seen sending more than one order.

        Real Chrome reorders extensions on every connection, curl and OkHttp do not.
        Browsers open several connections during one page load, so the samples arrive
        on their own.
        """
        return len(self.orders_seen) > 1


def build_preset(
    profile: ClientProfile,
    base: str,
    name: str,
    *,
    blunt: bool = False,
    permute: bool = False,
) -> dict:
    """Assemble the preset document for one observed client.

    The TLS block replays the captured bytes rather than a JA3 string, because JA3
    cannot express GREASE and drops extension payloads. The H2 block uses the discrete
    settings form rather than the akamai shorthand, because the shorthand is treated as
    an overlay on the base and lets the base's settings leak through.

    blunt passes extensions httpcloak has no model for through verbatim. It is not
    guessed here: the caller sets it after a registration has actually been refused,
    so the list of modelled extensions never has to be mirrored and can never drift.

    blunt and permute compose. They did not always: httpcloak ignored the shuffle under
    blunt mimicry until it learned to move extensions it has no model for, so a capture
    needing blunt mimicry was frozen. Emitting both is now correct, and it matters most
    exactly where it used to be dropped, since every QUIC hello carries an extension the
    library may not model.

    permute reshuffles the extension order, which Chromium does on every connection.
    Measured against httpcloak 1.7.0, a captured hello reseeds per session and not per
    connection: six connections through one session send one order, six sessions send
    six. Since sessions are pooled per origin, that gives a client one stable order per
    origin rather than a fresh one per connection. Still worth setting, because without
    it every origin sees the same order and correlating them is trivial, but it is not
    yet what the browser does.

    """
    tls: dict = {"raw_client_hello": profile.hello.raw_b64}
    if profile.psk_hello is not None:
        tls["raw_psk_client_hello"] = profile.psk_hello.raw_b64
    if blunt:
        tls["allow_blunt_mimicry"] = True
    if permute:
        tls["permute_raw_hello"] = True

    spec: dict = {"name": name, "based_on": base, "tls": tls}

    h2 = profile.h2
    if h2 is not None and h2.settings:
        block: dict = {
            "settings": [{"id": k, "value": v} for k, v in h2.settings],
            "settings_order": [k for k, _ in h2.settings],
        }
        if h2.window_update:
            block["connection_window_update"] = h2.window_update
        # Only override pseudo order when it was genuinely decoded. Desktop Chrome is
        # m,a,s,p but iOS Chrome is m,s,a,p, so a hardcoded fallback is wrong half the
        # time; leaving it out inherits the base's, which the UA already selected.
        if h2.pseudo_order:
            block["pseudo_order"] = h2.pseudo_order
        spec["http2"] = block

    return {"version": 1, "preset": spec}


# Cipher suites httpcloak's TLS stack can complete a handshake with. A captured
# hello's cipher list goes on the wire verbatim whatever it contains, so this does
# not change what we offer and never blocks a mirror; it only decides whether we
# warn. It matters when the far end *selects* one of these, which is the single way
# a faithfully mirrored hello can still fail to connect.
#
# Measured, not assumed: this is tls.CipherSuites() plus tls.InsecureCipherSuites()
# in the Go stack httpcloak links, and tests/test_units.py pins the list. Everything
# missing from it is either a DHE suite (removed from Go outright), a CBC-SHA384
# suite, or one of the CCM/ARIA/Camellia families.
_NEGOTIABLE_CIPHERS = frozenset({
    0x1301, 0x1302, 0x1303,
    0xc009, 0xc00a, 0xc013, 0xc014, 0xc02b, 0xc02c, 0xc02f, 0xc030, 0xcca8, 0xcca9,
    0x0005, 0x000a, 0x002f, 0x0035, 0x003c, 0x009c, 0x009d,
    0xc007, 0xc011, 0xc012, 0xc023, 0xc027,
})

# 0x00ff and 0x5600 are signalling values, never selectable, so a client offering
# them is not offering a cipher we cannot honour.
_SIGNALLING_CIPHERS = frozenset({0x00ff, 0x5600})


def unnegotiable_ciphers(hello: ClientHelloInfo) -> list[int]:
    """Ciphers this client offers that httpcloak could not complete if chosen."""
    return [
        c for c in hello.ciphers
        if not is_grease(c)
        and c not in _NEGOTIABLE_CIPHERS
        and c not in _SIGNALLING_CIPHERS
    ]


_UNSUPPORTED_EXTENSION = object()


class MirrorRegistry:
    """Caches registered mirror presets so identical clients share one registration."""

    def __init__(self) -> None:
        self._by_id: dict[str, str] = {}
        self._docs: dict[str, dict] = {}
        self.registered = 0
        self.reused = 0
        self.failed = 0

    def names(self) -> list[str]:
        return sorted(self._by_id.values())

    def document(self, name: str) -> dict | None:
        return self._docs.get(name)

    def ensure(
        self, profile: ClientProfile, base: str, *, base_permutes: bool = False
    ) -> str | None:
        """Register the preset for this profile, or return the cached name.

        Returns None when the preset cannot be registered, so the caller falls back to
        the static preset rather than failing the request.
        """
        import httpcloak

        # A capture is one connection, so its extension order is one sample and nothing
        # in the bytes says whether the client would have ordered them differently next
        # time. Two sources answer that. base_permutes is what the matched base preset
        # was measured doing at startup, which covers the first request; orders_seen is
        # this client's own evidence, which arrives later but is about the real client.
        permute = base_permutes or profile.permutes

        # The name has to cover everything that shapes the preset, not just the TLS
        # fingerprint. Several presets share one ClientHello while differing in H2
        # settings and headers, so chrome-151-windows and chrome-151-android would
        # otherwise collide on one name and the second client would silently get the
        # first one's base. permute is in the key too: stable_id sorts extensions, so
        # every order of one client hashes the same, and without it the preset minted
        # from the first connection would pin permute=False for the rest of the run.
        key = f"{profile.hello.stable_id}|{base}|{profile.psk_hello is not None}|{permute}"
        cached = self._by_id.get(key)
        if cached is not None:
            self.reused += 1
            return cached
        digest = hashlib.sha256(key.encode()).hexdigest()[:12]
        name = f"{PRESET_PREFIX}{digest}"

        # Asked, not guessed. Mirroring a table of the extensions httpcloak models
        # would drift silently on its next release in both directions: an extension
        # wrongly listed makes registration fail and the client falls back to a
        # generic preset, and one wrongly missing turns on blunt mimicry that costs
        # the per-connection extension shuffle. Trying it and reading the refusal
        # cannot drift, and it costs one extra call per distinct fingerprint.
        doc = build_preset(profile, base, name, permute=permute)
        registered = self._register(doc, name)
        if registered is _UNSUPPORTED_EXTENSION:
            doc = build_preset(profile, base, name, blunt=True, permute=permute)
            registered = self._register(doc, name)
            if registered is True:
                logger.info(
                    "mitmcloak: %s carries an extension httpcloak does not model, "
                    "replaying it verbatim (extension order frozen)", name,
                )
        if registered is not True:
            self.failed += 1
            return None

        self._by_id[key] = name
        self._docs[name] = doc
        self.registered += 1
        logger.info(
            "mitmcloak: mirrored %s -> %s (base=%s, psk=%s, grease=%s, permute=%s)",
            profile.hello.sni or "?", name, base,
            profile.psk_hello is not None, profile.hello.has_grease,
            doc["preset"]["tls"].get("permute_raw_hello", False),
        )
        unusable = unnegotiable_ciphers(profile.hello)
        if unusable:
            # The offer still goes out verbatim, so the fingerprint is unaffected.
            # Only a server that selects one of these fails, and it would have to
            # prefer it over the AES-GCM and TLS 1.3 suites offered alongside.
            logger.warning(
                "mitmcloak: %s offers %d cipher(s) httpcloak cannot complete if the "
                "server selects one: %s. They are still offered, so the fingerprint "
                "matches; only an origin that prefers one of them will fail.",
                name, len(unusable), " ".join("0x%04x" % c for c in unusable),
            )
        return name

    def _register(self, doc: dict, name: str):
        """True on success, _UNSUPPORTED_EXTENSION when only blunt mimicry can help."""
        import httpcloak

        try:
            httpcloak.load_preset_from_json(json.dumps(doc))
        except Exception as exc:                       # noqa: BLE001 - reported, not raised
            text = str(exc)
            if "already registered" in text:
                # Same name already present. With content-addressed names that means an
                # identical document, so reusing it is correct.
                logger.debug("mitmcloak: reusing already-registered preset %s", name)
                return True
            if "unsupported extension" in text:
                return _UNSUPPORTED_EXTENSION
            logger.warning("mitmcloak: could not register mirror preset: %s", exc)
            return False
        return True

    def close(self) -> None:
        """Unregister everything we minted. Called from the addon's done() hook."""
        try:
            import httpcloak
        except Exception:                              # noqa: BLE001
            return
        for name in list(self._docs):
            try:
                httpcloak.unregister_preset(name)
            except Exception:                          # noqa: BLE001
                pass
        self._by_id.clear()
        self._docs.clear()
