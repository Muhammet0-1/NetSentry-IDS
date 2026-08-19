"""Defensive conversion from Scapy objects to payload-free metadata."""

from __future__ import annotations

import ipaddress
import logging
import time
from collections.abc import Callable
from typing import Any, ClassVar, Protocol

from netsentry.models import PacketMetadata

LOGGER = logging.getLogger(__name__)


class PacketParser(Protocol):
    def parse(self, packet: object) -> PacketMetadata | None: ...


class ScapyPacketParser:
    _SUPPORTED_LINK_LAYERS: ClassVar[frozenset[str]] = frozenset(
        {
            "CookedLinux",
            "CookedLinuxV2",
            "Dot1AD",
            "Dot1Q",
            "Ether",
            "HDLC",
            "Loopback",
            "LoopbackOpenBSD",
            "Null",
            "PPP",
            "PPPoE",
            "PPPoED",
        }
    )

    def __init__(
        self,
        wall_clock: Callable[[], float] = time.time,
        monotonic_clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._wall_clock = wall_clock
        self._monotonic_clock = monotonic_clock

    def parse(self, packet: object) -> PacketMetadata | None:
        """Ignore unsupported/malformed packets without exposing their payload."""
        try:
            from scapy.layers.inet import IP, TCP
            from scapy.layers.inet6 import (
                IPv6,
                IPv6ExtHdrDestOpt,
                IPv6ExtHdrFragment,
                IPv6ExtHdrHopByHop,
                IPv6ExtHdrRouting,
            )

            network_layer = self._outer_network_layer(packet, IP, IPv6)
            if network_layer is None:
                return None
            tcp_layer: Any
            if isinstance(network_layer, IP):
                network_payload = network_layer.payload
                if int(network_layer.proto) != 6 or not isinstance(network_payload, TCP):
                    return None
                tcp_layer = network_payload
            else:
                tcp_layer = self._ipv6_tcp_layer(
                    network_layer,
                    TCP,
                    {
                        0: IPv6ExtHdrHopByHop,
                        43: IPv6ExtHdrRouting,
                        44: IPv6ExtHdrFragment,
                        60: IPv6ExtHdrDestOpt,
                    },
                )
                if tcp_layer is None:
                    return None
            source_ip = str(ipaddress.ip_address(str(network_layer.src)))
            destination_ip = str(ipaddress.ip_address(str(network_layer.dst)))
            source_port = int(tcp_layer.sport)
            destination_port = int(tcp_layer.dport)
            tcp_flags = int(tcp_layer.flags)
            if not 0 <= source_port <= 65535 or not 0 <= destination_port <= 65535:
                return None
            return PacketMetadata(
                observed_at=self._wall_clock(),
                monotonic_at=self._monotonic_clock(),
                source_ip=source_ip,
                destination_ip=destination_ip,
                source_port=source_port,
                destination_port=destination_port,
                tcp_flags=tcp_flags,
            )
        except Exception as exc:
            # Packet-like objects and optional Scapy layers can fail in backend-specific ways.
            # A single malformed observation must never terminate monitoring.
            LOGGER.debug("packet ignored during metadata parsing: %s", exc)
            return None

    @classmethod
    def _outer_network_layer(
        cls, packet: object, ipv4_type: type[Any], ipv6_type: type[Any]
    ) -> Any | None:
        current: Any = packet
        for _depth in range(16):
            if isinstance(current, (ipv4_type, ipv6_type)):
                return current
            if type(current).__name__ not in cls._SUPPORTED_LINK_LAYERS:
                return None
            next_layer = current.payload
            if next_layer is None or next_layer is current:
                return None
            current = next_layer
        return None

    @staticmethod
    def _ipv6_tcp_layer(
        network_layer: Any,
        tcp_type: type[Any],
        extension_types: dict[int, type[Any]],
    ) -> Any | None:
        next_header = int(network_layer.nh)
        current = network_layer.payload
        for _depth in range(8):
            extension_type = extension_types.get(next_header)
            if extension_type is None:
                break
            if not isinstance(current, extension_type):
                return None
            if next_header == 44 and (
                int(current.offset) != 0 or int(current.m) != 0
            ):
                return None
            next_header = int(current.nh)
            current = current.payload
        else:
            return None
        if next_header != 6 or not isinstance(current, tcp_type):
            return None
        return current
