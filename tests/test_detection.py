from __future__ import annotations

import unittest

from netsentry.config import DetectionConfig
from netsentry.detector import SynDetector
from netsentry.models import Alert, PacketMetadata


def packet(
    timestamp: float,
    destination_port: int,
    *,
    wall_time: float | None = None,
    source_ip: str = "198.51.100.10",
    destination_ip: str = "192.0.2.10",
    flags: int = 0x02,
) -> PacketMetadata:
    return PacketMetadata(
        observed_at=timestamp if wall_time is None else wall_time,
        monotonic_at=timestamp,
        source_ip=source_ip,
        destination_ip=destination_ip,
        source_port=50_000,
        destination_port=destination_port,
        tcp_flags=flags,
    )


def config(**overrides: object) -> DetectionConfig:
    values: dict[str, object] = {
        "port_scan_threshold": 3,
        "port_scan_window": 10.0,
        "syn_rate_threshold": 5,
        "syn_rate_window": 5.0,
        "alert_cooldown": 20.0,
        "state_ttl": 20.0,
        "max_sources": 10,
        "max_events_per_source": 10,
        "max_ports_per_source": 10,
    }
    values.update(overrides)
    return DetectionConfig(**values)  # type: ignore[arg-type]


class SynDetectorTests(unittest.TestCase):
    def test_port_scan_fires_at_distinct_port_threshold(self) -> None:
        detector = SynDetector(config())
        self.assertEqual(detector.inspect(packet(0, 20)), [])
        self.assertEqual(detector.inspect(packet(1, 21)), [])
        alerts = detector.inspect(packet(2, 22))
        self.assertEqual([alert.rule_id for alert in alerts], ["tcp_syn_port_scan"])
        self.assertEqual(alerts[0].signals["unique_destination_ports"], 3)
        self.assertIn("threshold", alerts[0].signals)

    def test_repeated_port_does_not_look_like_port_scan(self) -> None:
        detector = SynDetector(config(syn_rate_threshold=10, max_events_per_source=10))
        for timestamp in range(5):
            self.assertEqual(detector.inspect(packet(float(timestamp), 443)), [])
        self.assertEqual(detector.state.port_count("198.51.100.10"), 1)

    def test_repeat_flood_cannot_evict_distinct_port_evidence(self) -> None:
        detector = SynDetector(
            DetectionConfig(
                port_scan_threshold=16,
                port_scan_window=60.0,
                syn_rate_threshold=100,
                syn_rate_window=10.0,
                alert_cooldown=120.0,
                state_ttl=120.0,
                max_sources=10,
                max_events_per_source=256,
                max_ports_per_source=16,
            )
        )
        ports = [20] + ([21] * 242) + list(range(22, 36))
        self.assertEqual(len(ports), 257)

        alerts: list[Alert] = []
        for index, destination_port in enumerate(ports):
            timestamp = 59.0 * index / (len(ports) - 1)
            alerts.extend(detector.inspect(packet(timestamp, destination_port)))

        scan_alerts = [alert for alert in alerts if alert.rule_id == "tcp_syn_port_scan"]
        rate_alerts = [alert for alert in alerts if alert.rule_id == "tcp_syn_rate"]
        self.assertEqual(len(scan_alerts), 1)
        self.assertEqual(scan_alerts[0].signals["unique_destination_ports"], 16)
        self.assertEqual(rate_alerts, [])

    def test_old_observations_fall_outside_window(self) -> None:
        detector = SynDetector(config())
        detector.inspect(packet(0, 20))
        detector.inspect(packet(1, 21))
        self.assertEqual(detector.inspect(packet(12, 22)), [])

    def test_syn_rate_has_reason_and_counts(self) -> None:
        detector = SynDetector(
            config(port_scan_threshold=10, syn_rate_threshold=3, max_events_per_source=10)
        )
        detector.inspect(packet(0, 443))
        detector.inspect(packet(1, 443))
        alerts = detector.inspect(packet(2, 443))
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].rule_id, "tcp_syn_rate")
        self.assertEqual(alerts[0].signals["syn_count"], 3)
        self.assertTrue(alerts[0].reason)

    def test_non_initial_syn_is_ignored(self) -> None:
        detector = SynDetector(config())
        for flags in (0x00, 0x12, 0x04, 0x10):
            self.assertEqual(detector.inspect(packet(1, 443, flags=flags)), [])
        self.assertEqual(detector.state.source_count, 0)

    def test_alert_cooldown_prevents_spam_then_expires(self) -> None:
        detector = SynDetector(
            config(
                port_scan_threshold=10,
                syn_rate_threshold=2,
                syn_rate_window=30.0,
                alert_cooldown=10.0,
                state_ttl=30.0,
            )
        )
        detector.inspect(packet(0, 443))
        self.assertEqual(len(detector.inspect(packet(1, 443))), 1)
        self.assertEqual(detector.inspect(packet(2, 443)), [])
        self.assertEqual(len(detector.inspect(packet(11, 443))), 1)

    def test_source_pause_cannot_bypass_cooldown(self) -> None:
        detector = SynDetector(
            config(
                port_scan_threshold=10,
                port_scan_window=30.0,
                syn_rate_threshold=2,
                syn_rate_window=30.0,
                alert_cooldown=30.0,
                state_ttl=30.0,
            )
        )
        detector.inspect(packet(0, 443))
        self.assertEqual(len(detector.inspect(packet(1, 443))), 1)
        self.assertEqual(detector.inspect(packet(29, 443)), [])
        self.assertEqual(detector.inspect(packet(30, 443)), [])
        self.assertEqual(len(detector.inspect(packet(31, 443))), 1)

    def test_wall_clock_rollback_does_not_affect_windows_or_cooldown(self) -> None:
        detector = SynDetector(
            config(
                port_scan_threshold=10,
                port_scan_window=5.0,
                syn_rate_threshold=2,
                syn_rate_window=5.0,
                alert_cooldown=10.0,
                state_ttl=10.0,
            )
        )
        detector.inspect(packet(0, 443, wall_time=100))
        first_alerts = detector.inspect(packet(1, 443, wall_time=90))
        self.assertEqual(len(first_alerts), 1)
        self.assertEqual(detector.inspect(packet(2, 443, wall_time=80)), [])

        # The wall clock keeps moving backward. Monotonic time expires the old
        # detection window and retains the cooldown independently.
        self.assertEqual(detector.inspect(packet(10, 443, wall_time=70)), [])
        second_alerts = detector.inspect(packet(11, 443, wall_time=60))
        self.assertEqual(len(second_alerts), 1)
        self.assertEqual(second_alerts[0].as_dict()["timestamp"], "1970-01-01T00:01:00Z")
        self.assertNotIn("monotonic_at", second_alerts[0].as_dict())


if __name__ == "__main__":
    unittest.main()
