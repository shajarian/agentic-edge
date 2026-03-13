"""
Event Store — circular buffer of recent telemetry events and alerts.

Provides the agent with a short-term memory of what has happened
recently, supporting queries such as "show me the last 5 alerts
involving this IP".
"""

import logging
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class Event:
    """A single event record (alert or observation)."""
    timestamp: float                     # Unix epoch
    event_type: str                      # "alert" | "observation" | "mitigation"
    source_ip: str = ""
    destination_ip: str = ""
    destination_port: int = 0
    protocol: int = 0
    severity: str = "info"               # info | low | medium | high | critical
    description: str = ""
    metadata: dict = field(default_factory=dict)


class EventStore:
    """
    Fixed-size, in-memory circular buffer of Events.
    Designed for edge gateways with limited RAM.
    """

    def __init__(self, max_events: int = 1000):
        self._buffer: deque[Event] = deque(maxlen=max_events)
        self._alert_count = 0

    # ── Write ─────────────────────────────────────────────────────────

    def record(self, event: Event):
        """Append an event to the store."""
        self._buffer.append(event)
        if event.event_type == "alert":
            self._alert_count += 1

    def record_alert(
        self,
        source_ip: str,
        destination_ip: str,
        description: str,
        severity: str = "high",
        **metadata,
    ) -> Event:
        """Convenience method to record an alert."""
        evt = Event(
            timestamp=time.time(),
            event_type="alert",
            source_ip=source_ip,
            destination_ip=destination_ip,
            severity=severity,
            description=description,
            metadata=metadata,
        )
        self.record(evt)
        return evt

    def record_mitigation(
        self,
        source_ip: str,
        action: str,
        description: str,
    ) -> Event:
        """Record a mitigation action taken by the agent."""
        evt = Event(
            timestamp=time.time(),
            event_type="mitigation",
            source_ip=source_ip,
            description=description,
            metadata={"action": action},
        )
        self.record(evt)
        return evt

    # ── Read ──────────────────────────────────────────────────────────

    def recent(self, n: int = 10) -> list[Event]:
        """Return the *n* most recent events (newest first)."""
        items = list(self._buffer)
        return list(reversed(items[-n:]))

    def recent_alerts(self, n: int = 10) -> list[Event]:
        """Return the *n* most recent alerts."""
        alerts = [e for e in self._buffer if e.event_type == "alert"]
        return list(reversed(alerts[-n:]))

    def events_for_ip(self, ip: str, n: int = 10) -> list[Event]:
        """Return recent events involving a specific IP."""
        matches = [
            e for e in self._buffer
            if e.source_ip == ip or e.destination_ip == ip
        ]
        return list(reversed(matches[-n:]))

    # ── Summary ───────────────────────────────────────────────────────

    def summary(self) -> dict:
        """Compact summary for the LLM context window."""
        total = len(self._buffer)
        alerts = sum(1 for e in self._buffer if e.event_type == "alert")
        mitigations = sum(1 for e in self._buffer if e.event_type == "mitigation")
        return {
            "total_events": total,
            "alerts": alerts,
            "mitigations": mitigations,
            "buffer_capacity": self._buffer.maxlen,
        }

    def format_recent_for_prompt(self, n: int = 5) -> str:
        """Format recent events as a compact string for the LLM prompt."""
        events = self.recent(n)
        if not events:
            return "No recent events."
        lines = []
        for e in events:
            ts = time.strftime("%H:%M:%S", time.localtime(e.timestamp))
            lines.append(
                f"[{ts}] {e.event_type.upper()} | {e.source_ip} → {e.destination_ip} | "
                f"severity={e.severity} | {e.description}"
            )
        return "\n".join(lines)
