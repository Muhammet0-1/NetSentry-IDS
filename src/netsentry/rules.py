"""Explainable SYN-based detection rules."""

from __future__ import annotations

from collections.abc import Iterable

from netsentry.models import Alert, PacketMetadata
from netsentry.state import SourceState, SynObservation


def _recent(
    observations: Iterable[SynObservation], now: float, window: float
) -> list[SynObservation]:
    cutoff = now - window
    return [observation for observation in observations if observation.monotonic_at >= cutoff]


class PortScanRule:
    rule_id = "tcp_syn_port_scan"

    def __init__(self, threshold: int, window: float, cooldown: float) -> None:
        self.threshold = threshold
        self.window = window
        self.cooldown = cooldown

    def evaluate(self, packet: PacketMetadata, state: SourceState) -> Alert | None:
        destination_port_count = len(state.port_last_seen_monotonic)
        if destination_port_count < self.threshold or not self._cooldown_elapsed(
            state, packet.monotonic_at
        ):
            return None
        state.last_alerts_monotonic[self.rule_id] = packet.monotonic_at
        return Alert(
            observed_at=packet.observed_at,
            rule_id=self.rule_id,
            severity="medium",
            reason="source contacted many distinct TCP destination ports with initial SYN packets",
            source_ip=packet.source_ip,
            destination_ip=packet.destination_ip,
            signals={
                "unique_destination_ports": destination_port_count,
                "threshold": self.threshold,
                "window_seconds": self.window,
            },
        )

    def _cooldown_elapsed(self, state: SourceState, now: float) -> bool:
        previous = state.last_alerts_monotonic.get(self.rule_id)
        return previous is None or now - previous >= self.cooldown


class SynRateRule:
    rule_id = "tcp_syn_rate"

    def __init__(self, threshold: int, window: float, cooldown: float) -> None:
        self.threshold = threshold
        self.window = window
        self.cooldown = cooldown

    def evaluate(self, packet: PacketMetadata, state: SourceState) -> Alert | None:
        observations = _recent(state.observations, packet.monotonic_at, self.window)
        if len(observations) < self.threshold or not self._cooldown_elapsed(
            state, packet.monotonic_at
        ):
            return None
        state.last_alerts_monotonic[self.rule_id] = packet.monotonic_at
        targets = {item.destination_ip for item in observations}
        return Alert(
            observed_at=packet.observed_at,
            rule_id=self.rule_id,
            severity="medium",
            reason="source exceeded the configured initial TCP SYN rate",
            source_ip=packet.source_ip,
            destination_ip=packet.destination_ip,
            signals={
                "syn_count": len(observations),
                "unique_destination_ips": len(targets),
                "threshold": self.threshold,
                "window_seconds": self.window,
            },
        )

    def _cooldown_elapsed(self, state: SourceState, now: float) -> bool:
        previous = state.last_alerts_monotonic.get(self.rule_id)
        return previous is None or now - previous >= self.cooldown
