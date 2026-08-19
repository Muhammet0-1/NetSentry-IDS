from __future__ import annotations

import unittest

from netsentry.config import DetectionConfig, RuntimeConfig
from netsentry.detector import SynDetector
from netsentry.engine import MonitoringEngine
from netsentry.models import Alert, PacketMetadata
from netsentry.parser import ScapyPacketParser


class FakeParser:
    def __init__(self, result: PacketMetadata | None) -> None:
        self.result = result

    def parse(self, _packet: object) -> PacketMetadata | None:
        return self.result


class CollectingReporter:
    def __init__(self) -> None:
        self.alerts: list[Alert] = []

    def report(self, alert: Alert) -> None:
        self.alerts.append(alert)


def detection_config() -> DetectionConfig:
    return DetectionConfig(
        port_scan_threshold=2,
        port_scan_window=10,
        syn_rate_threshold=10,
        syn_rate_window=10,
        alert_cooldown=10,
        state_ttl=10,
        max_sources=10,
        max_events_per_source=10,
    )


class EngineAndParserTests(unittest.TestCase):
    def test_malformed_object_is_ignored(self) -> None:
        self.assertIsNone(ScapyPacketParser().parse(object()))

    def test_engine_ignores_parser_failure(self) -> None:
        reporter = CollectingReporter()
        engine = MonitoringEngine(FakeParser(None), SynDetector(detection_config()), reporter)
        engine.handle_packet(object())
        self.assertEqual(engine.stats.received, 1)
        self.assertEqual(engine.stats.ignored, 1)
        self.assertEqual(reporter.alerts, [])

    def test_target_filters_apply_before_detection(self) -> None:
        metadata = PacketMetadata(1, 1, "198.51.100.1", "192.0.2.1", 50000, 80, 0x02)
        reporter = CollectingReporter()
        detector = SynDetector(detection_config())
        engine = MonitoringEngine(
            FakeParser(metadata),
            detector,
            reporter,
            target_ips=frozenset({"192.0.2.99"}),
        )
        engine.handle_packet(object())
        self.assertEqual(detector.state.source_count, 0)
        self.assertEqual(engine.stats.ignored, 1)

    def test_canonical_ipv6_target_matches_packet_metadata(self) -> None:
        runtime = RuntimeConfig(
            output_path=None, target_ips=frozenset({"2001:0db8:0:0::2"})
        )
        metadata = PacketMetadata(
            1,
            1,
            "2001:db8::1",
            "2001:db8::2",
            50000,
            443,
            0x02,
        )
        reporter = CollectingReporter()
        detector = SynDetector(detection_config())
        engine = MonitoringEngine(
            FakeParser(metadata), detector, reporter, target_ips=runtime.target_ips
        )
        engine.handle_packet(object())
        self.assertEqual(engine.stats.ignored, 0)
        self.assertEqual(detector.state.source_count, 1)


if __name__ == "__main__":
    unittest.main()
