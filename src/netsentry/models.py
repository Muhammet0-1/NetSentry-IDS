"""Payload-free domain models shared by the detection pipeline."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import TypeAlias

SignalValue: TypeAlias = str | int | float | bool


@dataclass(frozen=True, slots=True)
class PacketMetadata:
    """Packet header data with separate presentation and elapsed-time clocks."""

    observed_at: float
    monotonic_at: float
    source_ip: str
    destination_ip: str
    source_port: int
    destination_port: int
    tcp_flags: int

    @property
    def is_initial_syn(self) -> bool:
        """True only for a SYN without ACK, RST, or other TCP flags."""
        return self.tcp_flags == 0x02


@dataclass(frozen=True, slots=True)
class Alert:
    observed_at: float
    rule_id: str
    severity: str
    reason: str
    source_ip: str
    destination_ip: str
    signals: dict[str, SignalValue]

    def as_dict(self) -> dict[str, object]:
        timestamp = datetime.fromtimestamp(self.observed_at, timezone.utc)
        return {
            "timestamp": timestamp.isoformat().replace("+00:00", "Z"),
            "rule_id": self.rule_id,
            "severity": self.severity,
            "reason": self.reason,
            "source_ip": self.source_ip,
            "destination_ip": self.destination_ip,
            "signals": self.signals,
        }
