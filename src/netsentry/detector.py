"""Rule orchestration independent from packet capture."""

from __future__ import annotations

from netsentry.config import DetectionConfig
from netsentry.models import Alert, PacketMetadata
from netsentry.rules import PortScanRule, SynRateRule
from netsentry.state import BoundedStateStore


class SynDetector:
    def __init__(self, config: DetectionConfig) -> None:
        self.config = config
        self.state = BoundedStateStore(
            max_sources=config.max_sources,
            max_events_per_source=config.max_events_per_source,
            max_ports_per_source=config.max_ports_per_source,
            state_ttl=config.state_ttl,
        )
        self._rate_retention = config.syn_rate_window
        self._port_retention = config.port_scan_window
        self._rules = (
            PortScanRule(
                config.port_scan_threshold, config.port_scan_window, config.alert_cooldown
            ),
            SynRateRule(config.syn_rate_threshold, config.syn_rate_window, config.alert_cooldown),
        )

    def inspect(self, packet: PacketMetadata) -> list[Alert]:
        if not packet.is_initial_syn:
            return []
        state = self.state.record(packet, self._rate_retention, self._port_retention)
        alerts: list[Alert] = []
        for rule in self._rules:
            alert = rule.evaluate(packet, state)
            if alert is not None:
                alerts.append(alert)
        return alerts
