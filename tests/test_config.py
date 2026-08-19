from __future__ import annotations

import math
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from netsentry.config import (
    ConfigurationError,
    DetectionConfig,
    RuntimeConfig,
    validate_bpf_filter,
    validate_interface_name,
    validate_ip,
    validate_port,
)


class DetectionConfigTests(unittest.TestCase):
    def test_defaults_are_consistent(self) -> None:
        config = DetectionConfig()
        self.assertGreaterEqual(config.max_events_per_source, config.syn_rate_threshold)
        self.assertGreaterEqual(config.max_ports_per_source, config.port_scan_threshold)
        self.assertGreaterEqual(config.state_ttl, config.port_scan_window)
        self.assertGreaterEqual(config.state_ttl, config.alert_cooldown)

    def test_invalid_threshold_and_windows_are_rejected(self) -> None:
        for kwargs in (
            {"port_scan_threshold": 1},
            {"syn_rate_window": 0},
            {"syn_rate_window": math.inf},
            {"alert_cooldown": -1},
            {"max_sources": 0},
            {"max_events_per_source": 99},
            {"max_ports_per_source": 15},
            {"state_ttl": 1},
        ):
            with self.subTest(kwargs=kwargs), self.assertRaises(ConfigurationError):
                DetectionConfig(**kwargs)

    def test_rate_event_capacity_must_cover_rate_threshold(self) -> None:
        with self.assertRaisesRegex(
            ConfigurationError,
            "max_events_per_source must be at least syn_rate_threshold",
        ):
            DetectionConfig(syn_rate_threshold=257, max_events_per_source=256)

    def test_port_recency_capacity_must_cover_scan_threshold(self) -> None:
        with self.assertRaisesRegex(
            ConfigurationError,
            "max_ports_per_source must be at least port_scan_threshold",
        ):
            DetectionConfig(port_scan_threshold=257, max_ports_per_source=256)

    def test_capacities_may_equal_their_thresholds(self) -> None:
        config = DetectionConfig(
            port_scan_threshold=16,
            syn_rate_threshold=100,
            max_events_per_source=100,
            max_ports_per_source=16,
        )
        self.assertEqual(config.max_events_per_source, config.syn_rate_threshold)
        self.assertEqual(config.max_ports_per_source, config.port_scan_threshold)

    def test_state_ttl_cannot_be_shorter_than_alert_cooldown(self) -> None:
        with self.assertRaisesRegex(
            ConfigurationError, "state_ttl must be at least as long as alert_cooldown"
        ):
            DetectionConfig(
                port_scan_window=5,
                syn_rate_window=5,
                alert_cooldown=11,
                state_ttl=10,
            )

    def test_state_ttl_may_equal_alert_cooldown(self) -> None:
        config = DetectionConfig(
            port_scan_window=10,
            syn_rate_window=10,
            alert_cooldown=10,
            state_ttl=10,
        )
        self.assertEqual(config.state_ttl, config.alert_cooldown)


class RuntimeConfigTests(unittest.TestCase):
    def test_ip_port_interface_and_filter_validation(self) -> None:
        self.assertEqual(validate_ip("2001:0db8::1"), "2001:db8::1")
        self.assertEqual(validate_port(443), 443)
        self.assertEqual(validate_interface_name("eth0"), "eth0")
        self.assertEqual(validate_bpf_filter("tcp port 443"), "tcp port 443")
        for operation in (
            lambda: validate_ip("not-an-ip"),
            lambda: validate_port(0),
            lambda: validate_port(65536),
            lambda: validate_interface_name("bad interface"),
            lambda: validate_bpf_filter("tcp\nport 80"),
        ):
            with self.assertRaises(ConfigurationError):
                operation()

    def test_output_directory_must_exist(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            missing = Path(directory) / "missing" / "alerts.jsonl"
            with self.assertRaises(ConfigurationError):
                RuntimeConfig(output_path=missing)

    def test_symbolic_link_output_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "target.jsonl"
            target.touch()
            link = Path(directory) / "alerts.jsonl"
            link.symlink_to(target)
            with self.assertRaises(ConfigurationError):
                RuntimeConfig(output_path=link)

    def test_unknown_user_output_path_is_a_configuration_error(self) -> None:
        path = Path("~netsentry_user_that_cannot_exist_7f9c/alerts.jsonl")
        with self.assertRaisesRegex(ConfigurationError, "output path could not be expanded"):
            RuntimeConfig(output_path=path)

    def test_unexpected_path_expansion_errors_are_not_hidden(self) -> None:
        with (
            patch.object(Path, "expanduser", side_effect=ValueError("synthetic bug")),
            self.assertRaisesRegex(ValueError, "synthetic bug"),
        ):
            RuntimeConfig(output_path=Path("alerts.jsonl"))

    def test_current_user_home_output_path_is_expanded(self) -> None:
        with tempfile.TemporaryDirectory() as directory, patch.dict(
            os.environ, {"HOME": directory}
        ):
            config = RuntimeConfig(output_path=Path("~/alerts.jsonl"))
            self.assertEqual(config.output_path, Path(directory) / "alerts.jsonl")

    def test_absolute_and_relative_output_paths_are_preserved(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            absolute = Path(directory) / "absolute-alerts.jsonl"
            self.assertEqual(RuntimeConfig(output_path=absolute).output_path, absolute)

        relative = Path("relative-alerts.jsonl")
        self.assertEqual(RuntimeConfig(output_path=relative).output_path, relative)

    def test_targets_are_canonicalized(self) -> None:
        config = RuntimeConfig(
            output_path=None,
            target_ips=frozenset({"2001:0db8::1"}),
            target_ports=frozenset({443}),
        )
        self.assertEqual(config.target_ips, frozenset({"2001:db8::1"}))

    def test_scoped_ipv6_target_is_rejected_with_interface_guidance(self) -> None:
        with self.assertRaisesRegex(ConfigurationError, "--interface"):
            RuntimeConfig(output_path=None, target_ips=frozenset({"fe80::1%eth0"}))

    def test_ipv4_target_behavior_is_preserved(self) -> None:
        config = RuntimeConfig(output_path=None, target_ips=frozenset({"192.0.2.10"}))
        self.assertEqual(config.target_ips, frozenset({"192.0.2.10"}))


if __name__ == "__main__":
    unittest.main()
