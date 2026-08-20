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

from .capture import ClientHelloInfo, H2Preface

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


def build_preset(profile: ClientProfile, base: str, name: str) -> dict:
    """Assemble the preset document for one observed client.

    The TLS block replays the captured bytes rather than a JA3 string, because JA3
    cannot express GREASE and drops extension payloads. The H2 block uses the discrete
    settings form rather than the akamai shorthand, because the shorthand is treated as
    an overlay on the base and lets the base's settings leak through.
    """
    tls: dict = {"raw_client_hello": profile.hello.raw_b64}
    if profile.psk_hello is not None:
        tls["raw_psk_client_hello"] = profile.psk_hello.raw_b64
    if not _uses_only_known_extensions(profile.hello):
        tls["allow_blunt_mimicry"] = True

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


# Extensions uTLS models natively. Anything outside this needs blunt mimicry, which
# passes unknown extensions through verbatim.
_KNOWN_EXTENSIONS = frozenset({
    0, 5, 10, 11, 13, 16, 17, 18, 21, 23, 27, 28, 34, 35, 41, 43, 44, 45, 50, 51,
    17513, 17613, 30032, 65037, 65281,
})


def _uses_only_known_extensions(hello: ClientHelloInfo) -> bool:
    return all(e in _KNOWN_EXTENSIONS for e in hello.extension_order)


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

    def ensure(self, profile: ClientProfile, base: str) -> str | None:
        """Register the preset for this profile, or return the cached name.

        Returns None when the preset cannot be registered, so the caller falls back to
        the static preset rather than failing the request.
        """
        import httpcloak

        # The name has to cover everything that shapes the preset, not just the TLS
        # fingerprint. Several presets share one ClientHello while differing in H2
        # settings and headers, so chrome-151-windows and chrome-151-android would
        # otherwise collide on one name and the second client would silently get the
        # first one's base.
        key = f"{profile.hello.stable_id}|{base}|{profile.psk_hello is not None}"
        cached = self._by_id.get(key)
        if cached is not None:
            self.reused += 1
            return cached
        digest = hashlib.sha256(key.encode()).hexdigest()[:12]
        name = f"{PRESET_PREFIX}{digest}"
        doc = build_preset(profile, base, name)
        try:
            httpcloak.load_preset_from_json(json.dumps(doc))
        except Exception as exc:                       # noqa: BLE001 - reported, not raised
            if "already registered" not in str(exc):
                self.failed += 1
                logger.warning("mitmcloak: could not register mirror preset: %s", exc)
                return None
            # Same name already present. With content-addressed names that means an
            # identical document, so reusing it is correct.
            logger.debug("mitmcloak: reusing already-registered preset %s", name)
        self._by_id[key] = name
        self._docs[name] = doc
        self.registered += 1
        logger.info(
            "mitmcloak: mirrored %s -> %s (base=%s, psk=%s, grease=%s)",
            profile.hello.sni or "?", name, base,
            profile.psk_hello is not None, profile.hello.has_grease,
        )
        return name

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
