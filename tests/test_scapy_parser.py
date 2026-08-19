from __future__ import annotations

import importlib.util
import unittest
from typing import Any, cast
from unittest.mock import patch

from netsentry.parser import ScapyPacketParser

SCAPY_AVAILABLE = importlib.util.find_spec("scapy") is not None


@unittest.skipUnless(SCAPY_AVAILABLE, "Scapy is not installed")
class ScapyPacketParserTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        with patch("scapy.config._set_conf_sockets", return_value=None):
            scapy_arch = importlib.import_module("scapy.arch")
        with (
            patch.object(scapy_arch, "read_routes", return_value=[]),
            patch.object(scapy_arch, "read_routes6", return_value=[]),
            patch.object(scapy_arch, "in6_getifaddr", return_value=[]),
        ):
            for module_name in (
                "scapy.layers.inet",
                "scapy.layers.inet6",
                "scapy.layers.l2",
            ):
                importlib.import_module(module_name)

    def test_synthetic_ipv4_packet_is_reduced_to_metadata(self) -> None:
        from scapy.layers.inet import IP, TCP

        raw_packet = IP(src="198.51.100.1", dst="192.0.2.1") / TCP(
            sport=50000, dport=443, flags="S"
        )
        metadata = ScapyPacketParser(
            wall_clock=lambda: 12.5, monotonic_clock=lambda: 7.0
        ).parse(raw_packet)
        self.assertIsNotNone(metadata)
        assert metadata is not None
        self.assertEqual(metadata.source_ip, "198.51.100.1")
        self.assertEqual(metadata.destination_port, 443)
        self.assertEqual(metadata.observed_at, 12.5)
        self.assertEqual(metadata.monotonic_at, 7.0)
        self.assertTrue(metadata.is_initial_syn)
        self.assertFalse(hasattr(metadata, "payload"))

    def test_synthetic_ipv6_packet_is_supported(self) -> None:
        from scapy.layers.inet import TCP
        from scapy.layers.inet6 import IPv6

        raw_packet = IPv6(src="2001:db8::1", dst="2001:db8::2") / TCP(
            sport=50000, dport=8443, flags="S"
        )
        metadata = ScapyPacketParser(
            wall_clock=lambda: 12.5, monotonic_clock=lambda: 7.0
        ).parse(raw_packet)
        self.assertIsNotNone(metadata)
        assert metadata is not None
        self.assertEqual(metadata.source_ip, "2001:db8::1")
        self.assertEqual(metadata.destination_port, 8443)
        self.assertTrue(metadata.is_initial_syn)

    def test_icmp_quoted_ipv4_tcp_syn_is_ignored(self) -> None:
        from scapy.layers.inet import ICMP, IP, TCP

        quoted_syn = IP(src="198.51.100.8", dst="192.0.2.8") / TCP(
            sport=51000, dport=22, flags="S"
        )
        outer_ip = cast(Any, IP(src="192.0.2.1", dst="198.51.100.1"))
        raw_packet = outer_ip / ICMP(type=3, code=3) / quoted_syn
        self.assertIsNone(ScapyPacketParser().parse(raw_packet))

    def test_icmpv6_embedded_tcp_syn_is_ignored(self) -> None:
        from scapy.layers.inet import TCP
        from scapy.layers.inet6 import ICMPv6DestUnreach, IPv6

        embedded_syn = IPv6(src="2001:db8::8", dst="2001:db8::9") / TCP(
            sport=51000, dport=22, flags="S"
        )
        outer_ip = cast(Any, IPv6(src="2001:db8::1", dst="2001:db8::2"))
        raw_packet = outer_ip / ICMPv6DestUnreach(code=4) / embedded_syn
        self.assertIsNone(ScapyPacketParser().parse(raw_packet))

    def test_udp_and_ip_encapsulation_do_not_expose_inner_tcp(self) -> None:
        from scapy.layers.inet import IP, TCP, UDP

        inner_syn = IP(src="198.51.100.8", dst="192.0.2.8") / TCP(
            sport=51000, dport=22, flags="S"
        )
        outer_ip = cast(Any, IP(src="192.0.2.1", dst="198.51.100.1"))
        packets = (outer_ip / UDP(sport=53, dport=53000) / inner_syn, outer_ip / inner_syn)
        for raw_packet in packets:
            with self.subTest(outer_protocol=raw_packet.payload.__class__.__name__):
                self.assertIsNone(ScapyPacketParser().parse(raw_packet))

    def test_ipv6_hop_by_hop_chain_reaches_its_own_tcp_layer(self) -> None:
        from scapy.layers.inet import TCP
        from scapy.layers.inet6 import IPv6, IPv6ExtHdrHopByHop

        raw_packet = (
            IPv6(src="2001:db8::1", dst="2001:db8::2")
            / IPv6ExtHdrHopByHop()
            / TCP(sport=50000, dport=443, flags="S")
        )
        metadata = ScapyPacketParser().parse(raw_packet)
        self.assertIsNotNone(metadata)
        assert metadata is not None
        self.assertEqual(metadata.destination_port, 443)

    def test_vlan_wrapped_ipv4_tcp_syn_is_supported(self) -> None:
        from scapy.layers.inet import IP, TCP
        from scapy.layers.l2 import Dot1AD, Dot1Q, Ether

        packets = (
            Ether() / Dot1Q(vlan=10) / IP(src="198.51.100.1", dst="192.0.2.1")
            / TCP(sport=50000, dport=443, flags="S"),
            Ether() / Dot1AD(vlan=20) / Dot1Q(vlan=10)
            / IP(src="198.51.100.1", dst="192.0.2.1")
            / TCP(sport=50000, dport=8443, flags="S"),
        )
        for raw_packet in packets:
            metadata = ScapyPacketParser().parse(raw_packet)
            self.assertIsNotNone(metadata)
            assert metadata is not None
            self.assertTrue(metadata.is_initial_syn)


if __name__ == "__main__":
    unittest.main()
