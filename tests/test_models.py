"""Tests for the report data models."""

from __future__ import annotations

import json
import unittest

from src.models import (
    HostInfo,
    HostScanResult,
    HttpInfo,
    NetworkScanResult,
    ServiceInfo,
    TlsCertificate,
)


def _service(port: int = 80, **kwargs: object) -> ServiceInfo:
    defaults = {
        "port": port,
        "service": "http",
        "product": "nginx",
        "version": "1.24.0",
        "confidence": 92,
        "response_ms": 1.2345,
    }
    defaults.update(kwargs)
    return ServiceInfo(**defaults)  # type: ignore[arg-type]


class ServiceModelTests(unittest.TestCase):
    def test_label(self) -> None:
        self.assertEqual(_service().label, "http (nginx 1.24.0)")
        self.assertEqual(_service(product=None, version=None).label, "http")

    def test_to_dict_rounds_response_time(self) -> None:
        payload = _service().to_dict()
        self.assertEqual(payload["response_ms"], 1.23)
        self.assertIsNone(payload["tls"])
        self.assertIsNone(payload["http"])

    def test_nested_models(self) -> None:
        service = _service(
            tls=TlsCertificate(subject="CN=router", issuer="CN=router"),
            http=HttpInfo(status_code=200, server="nginx"),
        )
        payload = service.to_dict()
        self.assertEqual(payload["tls"]["subject"], "CN=router")
        self.assertEqual(payload["http"]["status_code"], 200)

    def test_round_trip_preserves_nested_data(self) -> None:
        service = _service(
            extra="detail",
            banner="HTTP/1.1 200 OK",
            tls=TlsCertificate(
                subject="CN=router",
                issuer="CN=router",
                version="TLSv1.3",
                days_remaining=12,
                expired=False,
                self_signed=True,
                san=["router", "router.lan"],
            ),
            http=HttpInfo(
                scheme="https",
                status_code=200,
                server="nginx/1.24.0",
                headers={"server": "nginx/1.24.0"},
            ),
        )
        payload = service.to_dict()
        restored = ServiceInfo.from_dict(payload)
        self.assertEqual(restored.to_dict(), payload)

    def test_from_dict_rejects_invalid_port(self) -> None:
        with self.assertRaises(ValueError):
            ServiceInfo.from_dict({"port": "not-a-port"})
        with self.assertRaises(ValueError):
            ServiceInfo.from_dict({"port": 70000})


class HostModelTests(unittest.TestCase):
    def test_open_ports_and_display_name(self) -> None:
        host = HostInfo(
            ip="192.168.1.2",
            services=[
                _service(443),
                _service(80),
                ServiceInfo(port=8080, state="filtered"),
            ],
        )
        self.assertEqual(host.open_ports, [80, 443])
        self.assertEqual(host.display_name, "192.168.1.2")
        host.hostname = "router.lan"
        self.assertEqual(host.display_name, "router.lan")

    def test_add_source_and_evidence_are_idempotent(self) -> None:
        host = HostInfo(ip="192.168.1.2")
        host.add_source("icmp")
        host.add_source("icmp")
        host.add_evidence("seen")
        host.add_evidence("seen")
        self.assertEqual(host.sources, ["icmp"])
        self.assertEqual(host.evidence, ["seen"])

    def test_merge_fills_gaps_and_combines_services(self) -> None:
        first = HostInfo(ip="192.168.1.2", services=[_service(80)], notes=["a"])
        first.add_source("icmp")
        second = HostInfo(
            ip="192.168.1.2",
            mac="aa:bb:cc:dd:ee:ff",
            vendor="Example",
            hostname="host",
            services=[_service(80, version="1.25.0"), _service(443)],
            notes=["b"],
        )
        second.add_source("arp")
        first.merge(second)
        self.assertEqual(first.mac, "aa:bb:cc:dd:ee:ff")
        self.assertEqual(first.vendor, "Example")
        self.assertEqual(first.hostname, "host")
        self.assertEqual([s.port for s in first.services], [80, 443])
        self.assertEqual(first.services[0].version, "1.24.0")
        self.assertEqual(first.sources, ["icmp", "arp"])
        self.assertEqual(first.notes, ["a", "b"])

    def test_to_dict(self) -> None:
        payload = HostInfo(ip="192.168.1.2", latency_ms=1.234).to_dict()
        self.assertEqual(payload["latency_ms"], 1.23)
        self.assertEqual(payload["open_ports"], [])
        json.dumps(payload)

    def test_round_trip(self) -> None:
        host = HostInfo(
            ip="192.168.1.2",
            mac="aa:bb:cc:dd:ee:ff",
            hostname="host.lan",
            is_gateway=True,
            sources=["icmp"],
            evidence=["evidence"],
            services=[_service(80), _service(443, state="filtered")],
            notes=["note"],
        )
        payload = host.to_dict()
        restored = HostInfo.from_dict(payload)
        self.assertEqual(restored.to_dict(), payload)

    def test_from_dict_skips_malformed_services(self) -> None:
        host = HostInfo.from_dict(
            {
                "ip": "192.168.1.2",
                "services": [
                    {"port": 80, "service": "http"},
                    {"port": "bad"},
                    "not-an-object",
                ],
            }
        )
        self.assertEqual([service.port for service in host.services], [80])

    def test_from_dict_requires_ip(self) -> None:
        with self.assertRaises(ValueError):
            HostInfo.from_dict({"hostname": "missing-ip"})


class ResultModelTests(unittest.TestCase):
    def test_network_result(self) -> None:
        result = NetworkScanResult(
            scan_id="NET-1",
            network="192.168.1.0/24",
            interface="eth0",
            local_ip="192.168.1.10",
            gateway="192.168.1.1",
            started_at="2026-01-01T00:00:00+00:00",
            finished_at="2026-01-01T00:00:10+00:00",
            duration_s=10.0,
            targets_scanned=254,
            hosts=[HostInfo(ip="192.168.1.1", services=[_service(80)])],
            warnings=["note"],
        )
        self.assertEqual(result.hosts_up, 1)
        self.assertEqual(result.summary.services_found, 1)
        payload = result.to_dict()
        self.assertEqual(payload["hosts_up"], 1)
        self.assertEqual(payload["summary"]["hosts_total"], 254)
        json.dumps(payload)
        self.assertEqual(NetworkScanResult.from_dict(payload).to_dict(), payload)

    def test_host_result(self) -> None:
        result = HostScanResult(
            scan_id="HOST-1",
            target="example.com",
            resolved_ip="192.0.2.10",
            started_at="2026-01-01T00:00:00+00:00",
            finished_at="2026-01-01T00:00:02+00:00",
            duration_s=2.0,
            ports_scanned=100,
            services=[_service(80), _service(443)],
        )
        self.assertEqual(result.summary.hosts_up, 1)
        self.assertEqual(result.summary.services_found, 2)
        payload = result.to_dict()
        self.assertEqual(payload["open_ports"], [80, 443])
        json.dumps(payload)
        self.assertEqual(HostScanResult.from_dict(payload).to_dict(), payload)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
