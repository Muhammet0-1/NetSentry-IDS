"""Pipeline connecting parsing, target selection, detection, and reporting."""

from __future__ import annotations

from dataclasses import dataclass

from netsentry.detector import SynDetector
from netsentry.parser import PacketParser
from netsentry.reporting import Reporter, ReportingError


@dataclass(slots=True)
class EngineStats:
    received: int = 0
    ignored: int = 0
    alerts: int = 0


class MonitoringEngine:
    def __init__(
        self,
        parser: PacketParser,
        detector: SynDetector,
        reporter: Reporter,
        target_ips: frozenset[str] | None = None,
        target_ports: frozenset[int] | None = None,
    ) -> None:
        self._parser = parser
        self._detector = detector
        self._reporter = reporter
        self._target_ips = target_ips or frozenset()
        self._target_ports = target_ports or frozenset()
        self.stats = EngineStats()

    def handle_packet(self, raw_packet: object) -> None:
        self.stats.received += 1
        packet = self._parser.parse(raw_packet)
        if packet is None or not self._target_matches(
            packet.destination_ip, packet.destination_port
        ):
            self.stats.ignored += 1
            return
        alerts = self._detector.inspect(packet)
        for alert in alerts:
            try:
                self._reporter.report(alert)
            except OSError as exc:
                raise ReportingError(f"could not write alert output: {exc}") from exc
            self.stats.alerts += 1

    def _target_matches(self, destination_ip: str, destination_port: int) -> bool:
        return (not self._target_ips or destination_ip in self._target_ips) and (
            not self._target_ports or destination_port in self._target_ports
        )
