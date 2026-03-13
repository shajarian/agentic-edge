"""
Policy Engine — stores and evaluates network security policies.

Policies are simple rule objects that the Incident Manager agent can
query via its ``check_policy`` tool to understand whether observed
behaviour violates the site's security posture.
"""

import logging
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class PolicyRule:
    """A single declarative policy rule."""
    rule_id: str
    description: str
    # Conditions  (all optional — only set fields are checked)
    max_flow_rate: Optional[float] = None          # packets/s
    max_byte_rate: Optional[float] = None           # bytes/s
    blocked_ports: list[int] = field(default_factory=list)
    allowed_protocols: list[int] = field(default_factory=list)  # IANA proto numbers
    max_connections_per_minute: Optional[int] = None
    # Action to suggest when violated
    suggested_action: str = "alert_only"


class PolicyEngine:
    """
    Manages a set of PolicyRules and evaluates them against flow metadata.
    """

    def __init__(self):
        self._rules: dict[str, PolicyRule] = {}
        self._load_defaults()

    # ── Public API ────────────────────────────────────────────────────

    def add_rule(self, rule: PolicyRule):
        self._rules[rule.rule_id] = rule

    def get_rule(self, rule_id: str) -> Optional[PolicyRule]:
        return self._rules.get(rule_id)

    def all_rules(self) -> list[PolicyRule]:
        return list(self._rules.values())

    def evaluate(self, flow: dict) -> list[dict]:
        """
        Evaluate all rules against a single flow record.

        Args:
            flow: dict with keys like 'Dst Port', 'Protocol',
                  'Flow Packets/s', 'Flow Bytes/s', etc.

        Returns:
            List of violation dicts: {rule_id, description, suggested_action}
        """
        violations = []
        for rule in self._rules.values():
            v = self._check_rule(rule, flow)
            if v:
                violations.append(v)
        return violations

    def summary(self) -> str:
        """Compact policy summary for the LLM context window."""
        lines = [f"Active policies ({len(self._rules)} rules):"]
        for r in self._rules.values():
            lines.append(f"  - [{r.rule_id}] {r.description}")
        return "\n".join(lines)

    # ── Internal ──────────────────────────────────────────────────────

    def _check_rule(self, rule: PolicyRule, flow: dict) -> Optional[dict]:
        """Return a violation dict if the rule is violated, else None."""

        # Port check
        dst_port = flow.get("Dst Port")
        if rule.blocked_ports and dst_port is not None:
            if int(dst_port) in rule.blocked_ports:
                return {
                    "rule_id": rule.rule_id,
                    "description": f"Port {dst_port} is blocked by policy",
                    "suggested_action": rule.suggested_action,
                }

        # Protocol check
        protocol = flow.get("Protocol")
        if rule.allowed_protocols and protocol is not None:
            if int(protocol) not in rule.allowed_protocols:
                return {
                    "rule_id": rule.rule_id,
                    "description": f"Protocol {protocol} is not in allowed list",
                    "suggested_action": rule.suggested_action,
                }

        # Flow rate check
        flow_pps = flow.get("Flow Packets/s")
        if rule.max_flow_rate and flow_pps is not None:
            if float(flow_pps) > rule.max_flow_rate:
                return {
                    "rule_id": rule.rule_id,
                    "description": f"Flow rate {flow_pps:.0f} pps exceeds limit {rule.max_flow_rate}",
                    "suggested_action": rule.suggested_action,
                }

        # Byte rate check
        flow_bps = flow.get("Flow Bytes/s")
        if rule.max_byte_rate and flow_bps is not None:
            if float(flow_bps) > rule.max_byte_rate:
                return {
                    "rule_id": rule.rule_id,
                    "description": f"Byte rate {flow_bps:.0f} B/s exceeds limit {rule.max_byte_rate}",
                    "suggested_action": rule.suggested_action,
                }

        return None

    def _load_defaults(self):
        """Load a sensible set of default policies for IoT networks."""
        self.add_rule(PolicyRule(
            rule_id="BLOCK_TELNET",
            description="Block Telnet and common Mirai ports (23, 2323, 5555)",
            blocked_ports=[23, 2323, 5555],
            suggested_action="block_port",
        ))
        self.add_rule(PolicyRule(
            rule_id="RATE_LIMIT_HIGH_PPS",
            description="Flag flows exceeding 10 000 packets/s",
            max_flow_rate=10_000,
            suggested_action="rate_limit",
        ))
        self.add_rule(PolicyRule(
            rule_id="RATE_LIMIT_HIGH_BPS",
            description="Flag flows exceeding 100 MB/s",
            max_byte_rate=100_000_000,
            suggested_action="rate_limit",
        ))
