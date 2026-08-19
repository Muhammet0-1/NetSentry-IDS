"""Bounded, expiring per-source SYN rate and port-recency state."""

from __future__ import annotations

from collections import OrderedDict, deque
from dataclasses import dataclass, field

from netsentry.models import PacketMetadata


@dataclass(frozen=True, slots=True)
class SynObservation:
    monotonic_at: float
    destination_ip: str


@dataclass(slots=True)
class SourceState:
    observations: deque[SynObservation]
    port_last_seen_monotonic: OrderedDict[int, float]
    last_seen_monotonic: float
    last_alerts_monotonic: dict[str, float] = field(default_factory=dict)


class BoundedStateStore:
    def __init__(
        self,
        max_sources: int,
        max_events_per_source: int,
        max_ports_per_source: int,
        state_ttl: float,
    ) -> None:
        self._max_sources = max_sources
        self._max_events = max_events_per_source
        self._max_ports = max_ports_per_source
        self._state_ttl = state_ttl
        self._sources: OrderedDict[str, SourceState] = OrderedDict()

    def record(
        self,
        packet: PacketMetadata,
        rate_retention: float,
        port_retention: float,
    ) -> SourceState:
        self.cleanup(packet.monotonic_at)
        state = self._sources.get(packet.source_ip)
        if state is None:
            state = SourceState(
                observations=deque(maxlen=self._max_events),
                port_last_seen_monotonic=OrderedDict(),
                last_seen_monotonic=packet.monotonic_at,
            )
            self._sources[packet.source_ip] = state
        else:
            self._sources.move_to_end(packet.source_ip)
            state.last_seen_monotonic = packet.monotonic_at
        state.observations.append(
            SynObservation(
                monotonic_at=packet.monotonic_at,
                destination_ip=packet.destination_ip,
            )
        )
        cutoff = packet.monotonic_at - rate_retention
        while state.observations and state.observations[0].monotonic_at < cutoff:
            state.observations.popleft()

        port_cutoff = packet.monotonic_at - port_retention
        while state.port_last_seen_monotonic:
            _port, last_seen = next(iter(state.port_last_seen_monotonic.items()))
            if last_seen >= port_cutoff:
                break
            state.port_last_seen_monotonic.popitem(last=False)

        destination_port = packet.destination_port
        if destination_port in state.port_last_seen_monotonic:
            state.port_last_seen_monotonic[destination_port] = packet.monotonic_at
            state.port_last_seen_monotonic.move_to_end(destination_port)
        else:
            state.port_last_seen_monotonic[destination_port] = packet.monotonic_at
            if len(state.port_last_seen_monotonic) > self._max_ports:
                state.port_last_seen_monotonic.popitem(last=False)

        while len(self._sources) > self._max_sources:
            self._sources.popitem(last=False)
        return state

    def cleanup(self, now: float) -> int:
        removed = 0
        cutoff = now - self._state_ttl
        while self._sources:
            _source, oldest = next(iter(self._sources.items()))
            if oldest.last_seen_monotonic >= cutoff:
                break
            self._sources.popitem(last=False)
            removed += 1
        return removed

    @property
    def source_count(self) -> int:
        return len(self._sources)

    def event_count(self, source_ip: str) -> int:
        state = self._sources.get(source_ip)
        return len(state.observations) if state is not None else 0

    def port_count(self, source_ip: str) -> int:
        state = self._sources.get(source_ip)
        return len(state.port_last_seen_monotonic) if state is not None else 0
