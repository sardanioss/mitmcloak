"""A record of every distinct TLS fingerprint seen, whether or not we ever used it.

The mirror registry holds presets we actually serve requests through, and registering
one costs a slot in httpcloak's process-global namespace. That is the wrong home for a
fingerprint we merely watched go past, and most of what a proxy sees is exactly that: a
pinned app that refused our certificate, a client that hung up, a background agent that
made one request and left.

Catalogue entries are written as valid preset documents with an extra `_observed` block.
Go's JSON decoder ignores unknown fields, so a catalogue file loads with
`httpcloak.load_preset(path)` unchanged, with no conversion step.
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path

from .capture import ClientHelloInfo, H2Preface
from .mirror import build_preset

logger = logging.getLogger(__name__)


@dataclass
class Observation:
    hello: ClientHelloInfo
    h2: H2Preface | None = None
    hosts: set[str] = field(default_factory=set)
    connections: int = 0
    requests: int = 0
    refused: int = 0
    """Times this client sent a TLS alert rejecting our certificate."""

    no_request: int = 0
    """Connections that produced a hello but never a request we could act on.

    Refusal is only one reason. A client may also abort cleanly without an alert, or
    simply hang up, and from the outside those look the same. Counted separately from
    `refused` rather than guessing which it was.
    """

    @property
    def complete(self) -> bool:
        """Whether the H2 half was captured too, or only the TLS half."""
        return self.h2 is not None


class Catalogue:
    """Everything observed, keyed by the full fingerprint identity."""

    def __init__(self, directory: str | None = None) -> None:
        self.directory = Path(directory).expanduser() if directory else None
        self.entries: dict[str, Observation] = {}
        self._written: set[str] = set()

    def note_hello(self, hello: ClientHelloInfo) -> Observation:
        entry = self.entries.get(hello.stable_id)
        if entry is None:
            entry = Observation(hello=hello)
            self.entries[hello.stable_id] = entry
        entry.connections += 1
        if hello.sni:
            entry.hosts.add(hello.sni)
        return entry

    def note_h2(self, stable_id: str, preface: H2Preface) -> None:
        entry = self.entries.get(stable_id)
        if entry is not None and entry.h2 is None:
            entry.h2 = preface
            self._written.discard(stable_id)   # richer now, so rewrite it

    def note_request(self, stable_id: str) -> None:
        entry = self.entries.get(stable_id)
        if entry is not None:
            entry.requests += 1

    def note_refused(self, stable_id: str) -> None:
        entry = self.entries.get(stable_id)
        if entry is not None:
            entry.refused += 1

    def note_no_request(self, stable_id: str) -> None:
        entry = self.entries.get(stable_id)
        if entry is not None:
            entry.no_request += 1

    def document(self, stable_id: str, base: str) -> dict | None:
        """A loadable preset document for one observed fingerprint."""
        entry = self.entries.get(stable_id)
        if entry is None:
            return None
        from .mirror import ClientProfile

        profile = ClientProfile(hello=entry.hello, h2=entry.h2)
        doc = build_preset(profile, base, f"observed-{stable_id}")
        doc["_observed"] = {
            "hosts": sorted(entry.hosts)[:20],
            "connections": entry.connections,
            "requests": entry.requests,
            "rejected_our_certificate": entry.refused,
            "connections_without_a_request": entry.no_request,
            "tls_only": not entry.complete,
            "ja3": entry.hello.ja3,
            "alpn": entry.hello.alpn,
            "grease": entry.hello.has_grease,
            "resumption_hello": entry.hello.has_psk,
        }
        return doc

    def flush(self, base_for: callable) -> int:
        """Write every entry not already on disk. Returns how many were written."""
        if self.directory is None:
            return 0
        try:
            self.directory.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            logger.warning("mitmcloak: cannot write the catalogue: %s", exc)
            return 0
        written = 0
        for stable_id in list(self.entries):
            if stable_id in self._written:
                continue
            doc = self.document(stable_id, base_for(stable_id))
            if doc is None:
                continue
            try:
                (self.directory / f"observed-{stable_id}.json").write_text(
                    json.dumps(doc, indent=2)
                )
            except OSError as exc:
                logger.warning("mitmcloak: cannot write catalogue entry: %s", exc)
                continue
            self._written.add(stable_id)
            written += 1
        return written

    def summary(self) -> list[str]:
        rows = []
        for stable_id, entry in sorted(
            self.entries.items(), key=lambda kv: -kv[1].connections
        ):
            hosts = ", ".join(sorted(entry.hosts)[:2]) or "?"
            rows.append(
                f"{stable_id}  conns={entry.connections:<4} reqs={entry.requests:<5} "
                f"refused={entry.refused:<3} noreq={entry.no_request:<3} "
                f"{'tls+h2' if entry.complete else 'tls-only'}  {hosts}"
            )
        return rows
