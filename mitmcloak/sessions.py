"""Pooled httpcloak sessions.

Sessions are cgo handles, so an unbounded map leaks native memory that Python profiling
will not show. Eviction is not optional here.
"""
from __future__ import annotations

import logging
import time
import weakref
from collections import OrderedDict
from typing import Any, Callable

logger = logging.getLogger(__name__)

# Not preferences. Without the cache flag a reused session answers 304 to a client that
# never sent a validator; the other two hand ownership of cookies and redirects back to
# the real client, which is the only party that can decide them correctly.
REQUIRED_FLAGS = {
    "without_cookie_jar": True,
    "without_conditional_cache": True,
    "allow_redirects": False,
}


class SessionPool:
    """LRU pool with an idle sweep, keyed by whatever the resolver decides.

    The cap is a memory ceiling. MEASURED: an httpcloak session costs about 190 kB, and
    closing one returns nothing to the OS, so peak usage follows the high-water mark of
    concurrently live sessions rather than the number of requests served. Sizing this is
    the main lever an operator has.

    A workload whose distinct origins exceed the cap and cycles through them in order is
    the pathological case for LRU and will show a 0% hit rate. `reused` staying at zero
    while `created` climbs is the signal for that.
    """

    def __init__(self, max_sessions: int = 96, max_idle: float = 120.0) -> None:
        self.max_sessions = max_sessions
        self.max_idle = max_idle
        self._pool: OrderedDict[tuple, Any] = OrderedDict()
        self._external: weakref.WeakSet = weakref.WeakSet()
        """Sessions handed to us by a user callable. We use them, we never close them.

        A WeakSet rather than a set of id(): CPython reuses object ids once an object
        is collected, so a freed supplied session could hand its id to a session we
        own, and we would then decline to close it forever.
        """
        self.created = 0
        self.reused = 0
        self.evicted = 0
        self.swept = 0

    def __len__(self) -> int:
        return len(self._pool)

    def adopt(self, key: tuple, session: Any) -> Any:
        """Take a caller-supplied session into the pool without owning its lifetime."""
        existing = self._pool.get(key)
        if existing is session:
            self._pool.move_to_end(key)
            return session
        self._external.add(session)
        self._pool[key] = session
        self._trim()
        return session

    def get(self, key: tuple, factory: Callable[[], Any]) -> Any:
        session = self._pool.get(key)
        if session is not None:
            self._pool.move_to_end(key)
            self.reused += 1
            return session
        session = factory()
        self.created += 1
        self._pool[key] = session
        self._trim()
        return session

    def _trim(self) -> None:
        while len(self._pool) > self.max_sessions:
            _, old = self._pool.popitem(last=False)
            self.evicted += 1
            self._close(old)

    def sweep(self) -> int:
        """Drop sessions idle past the threshold. Returns how many went."""
        stale = []
        for key, session in self._pool.items():
            try:
                idle = session.idle_time()
            except Exception:                          # noqa: BLE001
                continue
            if idle is not None and idle > self.max_idle:
                stale.append(key)
        for key in stale:
            self._close(self._pool.pop(key))
            self.swept += 1
        return len(stale)

    def close(self) -> None:
        for session in self._pool.values():
            self._close(session)
        self._pool.clear()
        self._external.clear()

    def _close(self, session: Any) -> None:
        # Never close a session the user handed us; they may still be using it.
        if session in self._external:
            self._external.discard(session)
            return
        try:
            session.close()
        except Exception:                              # noqa: BLE001
            pass


def build_session(preset: str, opts: dict) -> Any:
    """Create a session with the three required flags forced on top of user options."""
    import httpcloak

    kwargs = dict(opts)
    kwargs.update(REQUIRED_FLAGS)
    kwargs["preset"] = preset
    return httpcloak.Session(**kwargs)


def enforce_required_flags(session: Any) -> None:
    """Apply the three correctness flags to a session we did not build.

    A user-supplied session is theirs in every other respect, but these three decide
    whether the real client still owns its own cookies, cache and redirects.
    """
    for setter, value in (
        ("set_conditional_cache", False),
        ("set_follow_redirects", False),
    ):
        fn = getattr(session, setter, None)
        if fn is None:
            continue
        try:
            fn(value)
        except Exception:                              # noqa: BLE001
            logger.debug("mitmcloak: could not apply %s on a supplied session", setter)
