"""Decide which preset and which session a flow goes out on.

One chain, first match wins:
  1. a user-supplied session callable
  2. per-flow rules, in the order they were given
  3. the mirror, when the client's fingerprint was captured
  4. the static preset
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Callable

from mitmproxy import flowfilter
from mitmproxy.utils import spec as spec_utils

logger = logging.getLogger(__name__)


@dataclass
class Rule:
    matcher: Any
    preset: str
    source: str

    def matches(self, flow) -> bool:
        try:
            return bool(self.matcher(flow))
        except Exception:                              # noqa: BLE001
            return False


def parse_rule(option: str) -> Rule:
    """Parse "/<flow filter>/<preset>" using mitmproxy's own spec parser.

    Deliberately mitmproxy's filter language rather than a syntax of our own, so `~d`,
    `~u`, `~m` and `~src` all work and the separator can be any character.
    """
    flow_filter, subject, replacement = spec_utils.parse_spec(option)
    # For the two-part form "/<filter>/<preset>" mitmproxy hands back the filter text
    # as `subject` and the preset as `replacement`. Falling back to `subject` when the
    # preset is empty would silently accept "/~d example\.com/" and treat the filter
    # text itself as a preset name.
    preset = (replacement or "").strip()
    if not preset:
        raise ValueError(f"no preset named in {option!r}; expected /<flow filter>/<preset>")
    if flow_filter is None:
        raise ValueError("no flow filter given")
    return Rule(matcher=flow_filter, preset=preset, source=option)


def parse_filter(expression: str):
    if not expression:
        return None
    return flowfilter.parse(expression)


@dataclass
class Decision:
    preset: str
    reason: str
    """One of: callable, rule, mirror, static."""
    session: Any = None
    """Set only when a user callable supplied one outright."""


class Resolver:
    def __init__(self) -> None:
        self.rules: list[Rule] = []
        self.bypass = None
        self.session_factory: Callable[[Any], Any] | None = None

    def configure(self, rule_specs, bypass_expr: str) -> None:
        self.rules = [parse_rule(spec) for spec in rule_specs]
        self.bypass = parse_filter(bypass_expr)

    def should_bypass(self, flow) -> bool:
        if self.bypass is None:
            return False
        try:
            return bool(self.bypass(flow))
        except Exception:                              # noqa: BLE001
            return False

    def decide(self, flow, mode: str, mirror_preset, static: str) -> Decision:
        """`mirror_preset` is a callable, so a client whose flows always match a rule
        never pays to have a mirror preset built and registered for it."""
        if self.session_factory is not None:
            try:
                session = self.session_factory(flow)
            except Exception:                          # noqa: BLE001
                logger.exception("mitmcloak: session factory raised, falling through")
                session = None
            if session is not None:
                return Decision(preset="<supplied>", reason="callable", session=session)

        for rule in self.rules:
            if rule.matches(flow):
                return Decision(preset=rule.preset, reason="rule")

        if mode in ("auto", "mirror"):
            name = mirror_preset()
            if name:
                return Decision(preset=name, reason="mirror")

        return Decision(preset=static, reason="static")


def session_key(flow, decision: Decision, scope: str, http_version: str) -> tuple:
    """Build the pool key.

    Default scope is `origin`, which gives one upstream connection per origin. That is
    what a browser does over HTTP/2, and keying on the client connection instead would
    open several upstream connections where one is expected.
    """
    key: list = [flow.request.pretty_host, flow.request.port, decision.preset, http_version]
    if scope == "client":
        peer = flow.client_conn.peername
        key.append(peer[0] if peer else "?")
    elif scope == "connection":
        key.append(flow.client_conn.id)
    return tuple(key)
