"""Tests for device/OS inference helpers."""

from __future__ import annotations

import unittest
from unittest import mock

from src.config import ScanConfig
from src.discovery import (
    NetworkScanner,
    ScanError,
    _ip_sort_key,
    _merge_nmap_host,
    infer_device_type,
    infer_os,
)
from src.models import HostInfo, ServiceInfo
from src.network import LocalNetwork, SsdpDevice
from src.portscan import NmapHost


class DeviceInferenceTests(unittest.TestCase):
    def test_gateway_has_priority(self) -> None:
        host = HostInfo(ip="192.168.1.1")
        device_type, evidence = infer_device_type(host, gateway_ip="192.168.1.1")
        self.assertEqual(device_type, "Router / gateway")
        self.assertTrue(any("gateway" in item for item in evidence))

    def test_hostname_hint(self) -> None:
        host = HostInfo(ip="192.168.1.20", hostname="printer-1")
        device_type, _ = infer_device_type(host)
        self.assertEqual(device_type, "Printer")

    def test_vendor_hint(self) -> None:
        host = HostInfo(ip="192.168.1.21", vendor="Espressif Inc.")
        device_type, evidence = infer_device_type(host)
        self.assertEqual(device_type, "IoT / embedded device")
        self.assertTrue(any("vendor" in item for item in evidence))

    def test_open_port_hint(self) -> None:
        host = HostInfo(
            ip="192.168.1.22",
            services=[ServiceInfo(port=9100, service="jetdirect")],
        )
        device_type, evidence = infer_device_type(host)
        self.assertEqual(device_type, "Printer (JetDirect)")
        self.assertTrue(any("open ports" in item for item in evidence))

    def test_upnp_hint(self) -> None:
        host = HostInfo(ip="192.168.1.23")
        ssdp = SsdpDevice(ip="192.168.1.23", friendly_name="Sonos Play:1")
        device_type, evidence = infer_device_type(host, ssdp=ssdp)
        self.assertEqual(device_type, "Smart speaker")
        self.assertTrue(any("UPnP" in item for item in evidence))

    def test_unknown(self) -> None:
        device_type, evidence = infer_device_type(HostInfo(ip="192.168.1.24"))
        self.assertIsNone(device_type)
        self.assertEqual(evidence, [])


class OsInferenceTests(unittest.TestCase):
    def test_nmap_has_priority(self) -> None:
        host = HostInfo(ip="192.0.2.1", ttl=64)
        self.assertEqual(infer_os(host, nmap_os="Windows 11 (98%)"), "Windows 11 (98%)")

    def test_ttl_guess(self) -> None:
        self.assertIn("Linux", infer_os(HostInfo(ip="192.0.2.1", ttl=64)) or "")
        self.assertIn("Windows", infer_os(HostInfo(ip="192.0.2.1", ttl=128)) or "")

    def test_service_hint_is_combined(self) -> None:
        host = HostInfo(
            ip="192.0.2.1",
            ttl=64,
            services=[ServiceInfo(port=80, product="Microsoft-IIS")],
        )
        result = infer_os(host) or ""
        self.assertIn("Linux", result)
        self.assertIn("Windows", result)

    def test_service_only_hint(self) -> None:
        host = HostInfo(
            ip="192.0.2.1",
            services=[ServiceInfo(port=80, product="nginx", extra="Ubuntu")],
        )
        self.assertEqual(infer_os(host), "Linux")

    def test_unknown(self) -> None:
        self.assertIsNone(infer_os(HostInfo(ip="192.0.2.1")))


class SortingTests(unittest.TestCase):
    def test_ip_sort_key(self) -> None:
        addresses = ["192.168.1.10", "192.168.1.2", "192.168.1.1"]
        self.assertEqual(
            sorted(addresses, key=_ip_sort_key),
            ["192.168.1.1", "192.168.1.2", "192.168.1.10"],
        )


class NmapMergeTests(unittest.TestCase):
    def test_tcp_and_udp_on_the_same_port_are_kept(self) -> None:
        host = HostInfo(
            ip="192.0.2.1",
            services=[ServiceInfo(port=53, protocol="tcp", service="dns")],
        )
        nmap_host = NmapHost(
            ip="192.0.2.1",
            services=[ServiceInfo(port=53, protocol="udp", service="dns")],
        )
        _merge_nmap_host(host, nmap_host)
        self.assertEqual(
            [(service.port, service.protocol) for service in host.services],
            [(53, "tcp"), (53, "udp")],
        )

    def test_existing_service_wins_over_duplicate(self) -> None:
        host = HostInfo(
            ip="192.0.2.1",
            services=[ServiceInfo(port=80, protocol="tcp", service="http")],
        )
        nmap_host = NmapHost(
            ip="192.0.2.1",
            services=[ServiceInfo(port=80, protocol="tcp", product="nginx")],
        )
        _merge_nmap_host(host, nmap_host)
        self.assertEqual(len(host.services), 1)
        self.assertEqual(host.services[0].service, "http")


class NetworkExclusionTests(unittest.TestCase):
    def _scanner(self) -> NetworkScanner:
        config = ScanConfig(
            ping_sweep=False,
            tcp_sweep=False,
            arp_scan=False,
            ssdp=False,
            resolve_names=False,
            quick_port_scan=False,
            engine="native",
        )
        return NetworkScanner(config)

    def _network(self) -> LocalNetwork:
        return LocalNetwork(
            interface="eth0",
            local_ip="192.168.1.1",
            cidr="192.168.1.0/30",
            gateway=None,
        )

    def test_excluded_targets_are_removed_from_the_scan(self) -> None:
        scanner = self._scanner()
        with mock.patch.object(scanner, "_resolve_network", return_value=self._network()), \
                mock.patch("src.discovery.neighbor_table", return_value={}):
            result = scanner.scan("192.168.1.0/30", exclude="192.168.1.1")
        self.assertEqual(result.targets_scanned, 1)
        self.assertEqual(result.config["exclude"], "192.168.1.1")
        self.assertEqual(result.config["excluded_hosts"], 1)

    def test_excluding_every_target_is_an_error(self) -> None:
        scanner = self._scanner()
        with mock.patch.object(scanner, "_resolve_network", return_value=self._network()), \
                mock.patch("src.discovery.neighbor_table", return_value={}):
            with self.assertRaises(ScanError):
                scanner.scan("192.168.1.0/30", exclude="192.168.1.0/30")

    def test_invalid_exclusion_raises_target_error(self) -> None:
        from src.utils import TargetError

        scanner = self._scanner()
        with mock.patch.object(scanner, "_resolve_network", return_value=self._network()):
            with self.assertRaises(TargetError):
                scanner.scan("192.168.1.0/30", exclude="not-a-target")


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
