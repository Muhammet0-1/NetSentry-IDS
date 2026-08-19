from __future__ import annotations

import unittest

from netsentry.models import PacketMetadata
from netsentry.state import BoundedStateStore


def event(timestamp: float, source: str, destination_port: int = 443) -> PacketMetadata:
    return PacketMetadata(
        timestamp,
        timestamp,
        source,
        "192.0.2.1",
        12345,
        destination_port,
        0x02,
    )


def store(*, max_events: int = 3, max_ports: int = 3, ttl: float = 100) -> BoundedStateStore:
    return BoundedStateStore(
        max_sources=2,
        max_events_per_source=max_events,
        max_ports_per_source=max_ports,
        state_ttl=ttl,
    )


class BoundedStateStoreTests(unittest.TestCase):
    def test_source_limit_evicts_least_recent_source(self) -> None:
        state_store = store()
        state_store.record(event(0, "198.51.100.1"), 10, 10)
        state_store.record(event(1, "198.51.100.2"), 10, 10)
        state_store.record(event(2, "198.51.100.3"), 10, 10)
        self.assertEqual(state_store.source_count, 2)
        self.assertEqual(state_store.event_count("198.51.100.1"), 0)

    def test_event_limit_and_retention_are_enforced(self) -> None:
        state_store = store(max_events=2)
        for timestamp in (0.0, 1.0, 2.0):
            state_store.record(event(timestamp, "198.51.100.1"), 10, 10)
        self.assertEqual(state_store.event_count("198.51.100.1"), 2)
        state_store.record(event(20, "198.51.100.1"), 5, 10)
        self.assertEqual(state_store.event_count("198.51.100.1"), 1)

    def test_repeated_port_updates_recency_without_growing_or_evicting(self) -> None:
        state_store = store(max_events=2, max_ports=3)
        source = "198.51.100.1"
        state_store.record(event(0, source, 80), 10, 10)
        state_store.record(event(1, source, 81), 10, 10)
        state = state_store.record(event(2, source, 81), 10, 100)
        for timestamp in range(3, 20):
            state = state_store.record(event(float(timestamp), source, 81), 10, 100)
        self.assertEqual(list(state.port_last_seen_monotonic), [80, 81])
        self.assertEqual(state.port_last_seen_monotonic[81], 19)
        self.assertEqual(state_store.port_count(source), 2)

    def test_port_recency_order_controls_bounded_lru_eviction(self) -> None:
        state_store = store(max_ports=2)
        source = "198.51.100.1"
        state_store.record(event(0, source, 80), 10, 10)
        state_store.record(event(1, source, 81), 10, 10)
        state_store.record(event(2, source, 80), 10, 10)
        state = state_store.record(event(3, source, 82), 10, 10)
        self.assertEqual(list(state.port_last_seen_monotonic), [80, 82])
        self.assertEqual(state_store.port_count(source), 2)

    def test_scan_window_expires_port_recency_by_monotonic_time(self) -> None:
        state_store = store(max_ports=3)
        source = "198.51.100.1"
        state_store.record(event(0, source, 80), 100, 10)
        state_store.record(event(1, source, 81), 100, 10)
        state = state_store.record(event(12, source, 82), 100, 10)
        self.assertEqual(list(state.port_last_seen_monotonic), [82])

    def test_event_and_port_structures_have_independent_memory_bounds(self) -> None:
        state_store = store(max_events=2, max_ports=3)
        source = "198.51.100.1"
        for index, destination_port in enumerate((80, 81, 82, 83)):
            state_store.record(event(float(index), source, destination_port), 100, 100)
        self.assertEqual(state_store.event_count(source), 2)
        self.assertEqual(state_store.port_count(source), 3)

    def test_inactive_state_expires(self) -> None:
        state_store = store(max_events=2, ttl=10)
        state_store.record(event(0, "198.51.100.1"), 10, 10)
        self.assertEqual(state_store.cleanup(11), 1)
        self.assertEqual(state_store.source_count, 0)


if __name__ == "__main__":
    unittest.main()
