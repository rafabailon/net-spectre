"""Tests for text/JSON report rendering and file output."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from src.diffing import DiffError
from src.models import (
    HostInfo,
    HostScanResult,
    HttpInfo,
    NetworkScanResult,
    ServiceInfo,
    TlsCertificate,
)
from src.reporting import (
    _atomic_write,
    export_report,
    load_result,
    render_console_host,
    render_console_network,
    render_csv,
    render_export,
    render_host_report,
    render_network_report,
    render_report,
    write_reports,
)


def _network_result() -> NetworkScanResult:
    service = ServiceInfo(
        port=443,
        service="https",
        product="nginx",
        version="1.24.0",
        confidence=92,
        response_ms=2.0,
        tls=TlsCertificate(
            version="TLSv1.3",
            cipher="TLS_AES_256_GCM_SHA384",
            subject="CN=router.lan",
            issuer="CN=router.lan",
            not_after="2027-01-01T00:00:00+00:00",
            days_remaining=30,
            expired=False,
            self_signed=True,
            san=["router.lan"],
        ),
        http=HttpInfo(
            scheme="https",
            status_code=200,
            server="nginx/1.24.0",
            title="Router",
            headers={"server": "nginx/1.24.0"},
        ),
        banner="HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\n",
    )
    host = HostInfo(
        ip="192.168.1.1",
        mac="aa:bb:cc:dd:ee:ff",
        vendor="Example Corp",
        hostname="router.lan",
        mdns_name="router.local",
        netbios_name="ROUTER",
        device_type="Router / gateway",
        os_guess="Linux / Unix (TTL 64)",
        latency_ms=1.5,
        ttl=64,
        is_gateway=True,
        sources=["icmp", "arp"],
        evidence=["default gateway is 192.168.1.1"],
        services=[service],
        notes=["example note"],
    )
    return NetworkScanResult(
        scan_id="NET-TEST",
        network="192.168.1.0/24",
        interface="eth0",
        local_ip="192.168.1.10",
        gateway="192.168.1.1",
        started_at="2026-01-01T00:00:00+00:00",
        finished_at="2026-01-01T00:00:10+00:00",
        duration_s=10.0,
        targets_scanned=254,
        hosts=[host],
        warnings=["sample warning"],
        config={"engine": "native", "quick_ports": [22, 80, 443]},
        tool_version="1.0.0",
    )


def _host_result() -> HostScanResult:
    service = ServiceInfo(
        port=22,
        service="ssh",
        product="OpenSSH",
        version="9.6",
        confidence=95,
        method="tcp-probe",
        response_ms=1.1,
        banner="SSH-2.0-OpenSSH_9.6",
    )
    return HostScanResult(
        scan_id="HOST-TEST",
        target="example.com",
        resolved_ip="192.0.2.10",
        started_at="2026-01-01T00:00:00+00:00",
        finished_at="2026-01-01T00:00:02+00:00",
        duration_s=2.0,
        ports_scanned=100,
        hostname="example.com",
        services=[service],
        warnings=[],
        config={"engine": "native"},
        engine="native",
        tool_version="1.0.0",
    )


class RenderTests(unittest.TestCase):
    def test_network_report_contains_all_sections(self) -> None:
        report = render_network_report(_network_result())
        for needle in (
            "NETWORK DISCOVERY REPORT",
            "NET-TEST",
            "DEVICES",
            "HOST DETAILS",
            "192.168.1.1",
            "router.lan",
            "Example Corp",
            "443/tcp",
            "TLS:",
            "HTTP metadata:",
            "WARNINGS",
            "sample warning",
        ):
            self.assertIn(needle, report)

    def test_host_report_contains_all_sections(self) -> None:
        report = render_host_report(_host_result())
        for needle in (
            "HOST PORT & SERVICE REPORT",
            "HOST-TEST",
            "OPEN SERVICES",
            "SERVICE DETAILS",
            "22/tcp",
            "OpenSSH",
            "SSH-2.0-OpenSSH_9.6",
            "CONFIGURATION",
        ):
            self.assertIn(needle, report)

    def test_untrusted_text_is_sanitized(self) -> None:
        result = _network_result()
        result.hosts[0].hostname = "\x1b[31mevil\x1b[0m\r\nsecond"
        report = render_network_report(result)
        self.assertNotIn("\x1b[31m", report)
        self.assertNotIn("\r", report)

    def test_console_summaries(self) -> None:
        network = render_console_network(_network_result())
        host = render_console_host(_host_result())
        self.assertIn("Discovered 1 device", network)
        self.assertIn("192.168.1.1", network)
        self.assertIn("1 open port", host)
        self.assertIn("OpenSSH", host)


class CsvTests(unittest.TestCase):
    def test_network_csv_has_a_row_per_service(self) -> None:
        text = render_csv(_network_result())
        lines = text.splitlines()
        self.assertTrue(lines[0].startswith("report,scan_id,ip,mac,vendor"))
        self.assertEqual(len(lines), 2)
        self.assertIn("192.168.1.1", lines[1])
        self.assertIn("443,tcp,open,https,nginx,1.24.0", lines[1])
        self.assertIn("router.lan", lines[1])

    def test_host_csv_contains_service_details(self) -> None:
        text = render_csv(_host_result())
        lines = text.splitlines()
        self.assertEqual(len(lines), 2)
        self.assertIn("host,HOST-TEST,192.0.2.10", lines[1])
        self.assertIn("22,tcp,open,ssh,OpenSSH,9.6", lines[1])

    def test_html_and_control_characters_are_sanitized(self) -> None:
        result = _host_result()
        result.hostname = "bad\x1b[31mname\x0b"
        text = render_csv(result)
        self.assertNotIn("\x1b", text)
        self.assertNotIn("\x0b", text)


class WriteReportTests(unittest.TestCase):
    def test_writes_text_and_json(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            paths = write_reports(_network_result(), directory)
            self.assertTrue(paths.text.is_file())
            self.assertTrue(paths.json.is_file())
            self.assertTrue(paths.text.name.startswith("network_scan_"))
            self.assertEqual(paths.text.suffix, ".log")
            self.assertEqual(paths.json.suffix, ".json")
            payload = json.loads(paths.json.read_text(encoding="utf-8"))
            self.assertEqual(payload["generator"], "Net Spectre")
            self.assertEqual(payload["scan"]["scan_id"], "NET-TEST")
            self.assertIn("NETWORK DISCOVERY REPORT", paths.text.read_text(encoding="utf-8"))

    def test_host_filename_uses_underscores(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            paths = write_reports(_host_result(), directory)
            self.assertTrue(paths.text.name.startswith("host_scan_192_0_2_10_"))
            self.assertNotIn("..", paths.text.name)

    def test_existing_reports_are_not_overwritten(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            first = write_reports(_network_result(), directory)
            second = write_reports(_network_result(), directory)
            self.assertNotEqual(first.text, second.text)
            self.assertIn("_2", second.text.name)
            self.assertTrue(first.text.is_file())
            self.assertTrue(second.text.is_file())

    def test_csv_is_optional(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            paths = write_reports(_network_result(), directory)
            self.assertIsNone(paths.csv)
            self.assertEqual(list(directory.glob("*.csv")), [])

    def test_csv_export_writes_a_third_file(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            paths = write_reports(_network_result(), directory, csv_export=True)
            self.assertIsNotNone(paths.csv)
            assert paths.csv is not None
            self.assertTrue(paths.csv.is_file())
            self.assertEqual(paths.csv.suffix, ".csv")
            self.assertIn("443,tcp,open,https", paths.csv.read_text(encoding="utf-8"))

    def test_existing_csv_forces_a_new_base_name(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            first = write_reports(_network_result(), directory, csv_export=True)
            second = write_reports(_network_result(), directory, csv_export=True)
            self.assertNotEqual(first.csv, second.csv)
            self.assertIn("_2", second.csv.name)

    def test_invalid_timestamp_is_tolerated(self) -> None:
        result = _network_result()
        result.started_at = "not-a-date"
        with tempfile.TemporaryDirectory() as temporary:
            paths = write_reports(result, temporary)
            self.assertTrue(paths.text.is_file())

    def test_failed_atomic_write_removes_temporary_file(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / "report.json"
            with mock.patch("pathlib.Path.replace", side_effect=OSError("boom")):
                with self.assertRaises(OSError):
                    _atomic_write(target, "content")
            self.assertFalse(target.exists())
            self.assertEqual(list(Path(temporary).glob("*.tmp")), [])


class ExportTests(unittest.TestCase):
    def _network_report(self, directory: Path) -> Path:
        return write_reports(_network_result(), directory).json

    def _host_report(self, directory: Path) -> Path:
        return write_reports(_host_result(), directory).json

    def test_load_network_and_host_results(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            network = load_result(self._network_report(directory))
            host = load_result(self._host_report(directory))
        self.assertIsInstance(network, NetworkScanResult)
        self.assertEqual(network.scan_id, "NET-TEST")
        self.assertEqual(network.hosts[0].services[0].port, 443)
        self.assertIsInstance(host, HostScanResult)
        self.assertEqual(host.scan_id, "HOST-TEST")
        self.assertEqual(host.services[0].service, "ssh")

    def test_render_export_csv_and_text(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            report = self._network_report(Path(temporary))
            csv_text = render_export(report, "csv")
            text = render_export(report, "TEXT")
        self.assertTrue(csv_text.startswith("report,scan_id,ip,mac,vendor"))
        self.assertIn("443,tcp,open,https", csv_text)
        self.assertIn("NETWORK DISCOVERY REPORT", text)
        self.assertIn("router.lan", text)

    def test_export_report_writes_default_suffixes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            report = self._network_report(Path(temporary))
            csv_path = export_report(report, "csv")
            text_path = export_report(report, "text")
            self.assertEqual(csv_path, report.with_suffix(".csv"))
            self.assertEqual(text_path, report.with_suffix(".txt"))
            self.assertIn("192.168.1.1", csv_path.read_text(encoding="utf-8"))
            self.assertIn("NETWORK DISCOVERY REPORT", text_path.read_text(encoding="utf-8"))

    def test_export_does_not_overwrite_without_force(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            report = self._network_report(Path(temporary))
            destination = Path(temporary) / "inventory.csv"
            export_report(report, "csv", destination)
            with self.assertRaises(FileExistsError):
                export_report(report, "csv", destination)
            export_report(report, "csv", destination, force=True)
            self.assertTrue(destination.is_file())

    def test_export_rejects_input_as_output(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            report = self._network_report(Path(temporary))
            with self.assertRaises(ValueError):
                export_report(report, "text", report, force=True)

    def test_unknown_format_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            report = self._network_report(Path(temporary))
            with self.assertRaises(ValueError):
                render_export(report, "yaml")
            self.assertEqual(list(Path(temporary).glob("*.csv")), [])

    def test_load_result_handles_bare_and_host_reports(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            bare = directory / "bare.json"
            bare.write_text(
                json.dumps(_network_result().to_dict()), encoding="utf-8"
            )
            host = directory / "host.json"
            host.write_text(json.dumps(_host_result().to_dict()), encoding="utf-8")
            self.assertIsInstance(load_result(bare), NetworkScanResult)
            self.assertIsInstance(load_result(host), HostScanResult)

    def test_load_result_reports_invalid_json(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            broken = Path(temporary) / "broken.json"
            broken.write_text("{not-json", encoding="utf-8")
            with self.assertRaises(DiffError):
                load_result(broken)

    def test_render_report_rejects_unknown_type(self) -> None:
        with self.assertRaises(TypeError):
            render_report(object())  # type: ignore[arg-type]


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
