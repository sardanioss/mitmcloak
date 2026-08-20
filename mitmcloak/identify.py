"""Recognise a captured fingerprint as one of the built-in presets.

The User-Agent is a poor signal for choosing a base preset: system agents and most
apps do not put a platform token in it, and an iOS client that falls through to a
Chrome desktop base gets the wrong header block and the wrong H2 settings.

The ClientHello is a much better signal, and it is one we already hold. This module
learns what each candidate base preset actually puts on the wire by making it connect
to a local socket that reads the handshake and hangs up, then matches captured clients
against that map. No network, no certificates: we only ever need the first record.
"""
from __future__ import annotations

import logging
import socket
import threading

from .capture import parse_client_hello

logger = logging.getLogger(__name__)

# Only presets worth using as a base. Probing all ~94 registered names would be mostly
# wasted work, since they collapse to far fewer distinct TLS identities.
BASE_CANDIDATES = (
    "chrome-151-windows", "chrome-151-macos", "chrome-151-linux",
    "chrome-151-ios", "chrome-151-android",
    "chrome-150-windows", "chrome-146-windows",
    "firefox-148-windows", "firefox-148-linux", "firefox-148-macos",
    "firefox-133-windows", "safari-18-ios",
)


class _HelloSink:
    """A TCP socket that reads one TLS record and closes.

    Enough to learn a preset's ClientHello without terminating TLS or owning a
    certificate. The client's handshake fails, which is fine: the bytes we want are
    the ones it already sent.
    """

    def __init__(self) -> None:
        self._sock = socket.socket()
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(8)
        self._sock.settimeout(5.0)
        self.port = self._sock.getsockname()[1]
        self.captured: list[bytes] = []
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self) -> None:
        while not self._stop.is_set():
            try:
                conn, _ = self._sock.accept()
            except (TimeoutError, OSError):
                continue
            try:
                conn.settimeout(3.0)
                data = b""
                while len(data) < 5:
                    chunk = conn.recv(65535)
                    if not chunk:
                        break
                    data += chunk
                if len(data) >= 5:
                    want = 5 + int.from_bytes(data[3:5], "big")
                    while len(data) < want:
                        chunk = conn.recv(65535)
                        if not chunk:
                            break
                        data += chunk
                    self.captured.append(data[:want])
            except OSError:
                pass
            finally:
                conn.close()

    def close(self) -> None:
        self._stop.set()
        try:
            self._sock.close()
        except OSError:
            pass


def build_identity_map(candidates=BASE_CANDIDATES) -> dict[str, str]:
    """Map each candidate preset's TLS identity to its name.

    Returns {stable_id: preset_name}. Presets that share a ClientHello collapse onto
    one entry; first name wins, and the candidate order above decides which that is.
    """
    import httpcloak

    sink = _HelloSink()
    identities: dict[str, str] = {}
    try:
        for name in candidates:
            before = len(sink.captured)
            session = None
            try:
                session = httpcloak.Session(
                    preset=name, verify=False, timeout=3, http_version="h2",
                    without_cookie_jar=True, without_conditional_cache=True,
                    allow_redirects=False,
                )
                try:
                    session.get(f"https://127.0.0.1:{sink.port}/", timeout=3)
                except Exception:                      # noqa: BLE001 - expected
                    pass
            except Exception as exc:                   # noqa: BLE001
                logger.debug("mitmcloak: could not probe %s: %s", name, exc)
                continue
            finally:
                if session is not None:
                    try:
                        session.close()
                    except Exception:                  # noqa: BLE001
                        pass
            for raw in sink.captured[before:]:
                try:
                    identities.setdefault(parse_client_hello(raw).family_id, name)
                except ValueError:
                    continue
    finally:
        sink.close()
    logger.info(
        "mitmcloak: learned %d distinct TLS identities from %d base presets",
        len(identities), len(candidates),
    )
    return identities


class BaseIdentifier:
    """Picks a base preset for a captured client, TLS first and User-Agent second."""

    def __init__(self) -> None:
        self._identities: dict[str, str] | None = None
        self.matched = 0
        self.by_user_agent = 0

    def ensure_loaded(self) -> None:
        if self._identities is None:
            try:
                self._identities = build_identity_map()
            except Exception as exc:                   # noqa: BLE001
                logger.warning("mitmcloak: TLS identity probing failed: %s", exc)
                self._identities = {}

    def match(self, family_id: str) -> str | None:
        self.ensure_loaded()
        name = (self._identities or {}).get(family_id)
        if name is not None:
            self.matched += 1
        return name

    def known(self) -> dict[str, str]:
        self.ensure_loaded()
        return dict(self._identities or {})
