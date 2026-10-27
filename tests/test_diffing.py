"""Tests for JSON report comparison (``net-spectre diff``)."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from src.diffing import (
    DiffError,
    diff_scans,
    load_report,
    render_diff,
)


def _network_scan(
    scan_id: str,
    hosts: list[dict],
    *,
    warnings: list[str] | None = None,
) -> dict:
    return {
        "scan_id": scan_id,
        "mode": "network",
        "hosts": hosts,
        "warnings": warnings or [],
    }


def _host(
    ip: str,
    *,
    hostname: str | None = None,
    services: list[dict] | None = None,
    vendor: str | None = None,
) -> dict:
    return {
        "ip": ip,
        "hostname": hostname,
        "mac": None,
        "vendor": vendor,
        "device_type": None,
        "os_guess": None,
        "status": "up",
        "is_gateway": False,
        "services": services or [],
    }


def _service(port: int, service: str, *, product: str | None = None) -> dict:
    return {
        "port": port,
        "protocol": "tcp",
        "state": "open",
        "service": service,
        "product": product,
    }


class LoadReportTests(unittest.TestCase):
    def _write(self, directory: Path, payload: object) -> Path:
        path = directory / "report.json"
        path.write_text(json.dumps(payload), encoding="utf-8")
        return path

    def test_wrapped_payload_is_unwrapped(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = self._write(
                Path(temporary),
                {"generator": "Net Spectre", "scan": _network_scan("NET-1", [])},
            )
            scan = load_report(path)
            self.assertEqual(scan["scan_id"], "NET-1")

    def test_bare_scan_is_accepted(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = self._write(
                Path(temporary),
                {"scan_id": "HOST-1", "mode": "host", "resolved_ip": "192.0.2.1"},
            )
            self.assertEqual(load_report(path)["resolved_ip"], "192.0.2.1")

    def test_missing_file(self) -> None:
        with self.assertRaises(DiffError):
            load_report("/nonexistent/report.json")

    def test_invalid_json(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "bad.json"
            path.write_text("{not json", encoding="utf-8")
            with self.assertRaises(DiffError):
                load_report(path)

    def test_unrelated_json_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = self._write(Path(temporary), {"foo": "bar"})
            with self.assertRaises(DiffError):
                load_report(path)


class DiffTests(unittest.TestCase):
    def test_identical_reports_have_no_changes(self) -> None:
        scan = _network_scan("NET-1", [_host("10.0.0.1", services=[_service(80, "http")])])
        diff = diff_scans(scan, json.loads(json.dumps(scan)))
        self.assertFalse(diff.has_changes)
        self.assertEqual(diff.change_count, 0)

    def test_hosts_added_and_removed(self) -> None:
        old = _network_scan("old", [_host("10.0.0.1"), _host("10.0.0.2")])
        new = _network_scan("new", [_host("10.0.0.2"), _host("10.0.0.3")])
        diff = diff_scans(old, new)
        self.assertEqual([item.ip for item in diff.hosts_added], ["10.0.0.3"])
        self.assertEqual([item.ip for item in diff.hosts_removed], ["10.0.0.1"])
        self.assertEqual(diff.change_count, 2)

    def test_host_metadata_changes(self) -> None:
        old = _network_scan("old", [_host("10.0.0.1", hostname="old.lan")])
        new = _network_scan("new", [_host("10.0.0.1", hostname="new.lan")])
        diff = diff_scans(old, new)
        self.assertEqual(len(diff.hosts_changed), 1)
        self.assertEqual(
            diff.hosts_changed[0].fields["hostname"], ("old.lan", "new.lan")
        )

    def test_none_and_empty_values_are_equivalent(self) -> None:
        old = _network_scan("old", [{"ip": "10.0.0.1", "hostname": None}])
        new = _network_scan("new", [{"ip": "10.0.0.1", "hostname": ""}])
        self.assertEqual(diff_scans(old, new).hosts_changed, [])

    def test_services_opened_closed_and_changed(self) -> None:
        old = _network_scan(
            "old",
            [_host("10.0.0.1", services=[_service(80, "http"), _service(22, "ssh")])],
        )
        new = _network_scan(
            "new",
            [
                _host(
                    "10.0.0.1",
                    services=[_service(443, "https"), _service(80, "nginx")],
                )
            ],
        )
        diff = diff_scans(old, new)
        self.assertEqual([item.key for item in diff.services_opened], ["10.0.0.1:443/tcp"])
        self.assertEqual([item.key for item in diff.services_closed], ["10.0.0.1:22/tcp"])
        self.assertEqual(
            [item.key for item in diff.services_changed], ["10.0.0.1:80/tcp"]
        )

    def test_closed_and_filtered_services_are_ignored(self) -> None:
        old = _network_scan("old", [_host("10.0.0.1")])
        new = _network_scan(
            "new",
            [
                _host(
                    "10.0.0.1",
                    services=[{**_service(80, "http"), "state": "filtered"}],
                )
            ],
        )
        self.assertEqual(diff_scans(old, new).services_opened, [])

    def test_host_reports_are_supported(self) -> None:
        old = {
            "scan_id": "HOST-1",
            "mode": "host",
            "resolved_ip": "192.0.2.5",
            "hostname": "web.lan",
            "services": [_service(80, "http")],
        }
        new = {
            "scan_id": "HOST-2",
            "mode": "host",
            "resolved_ip": "192.0.2.5",
            "hostname": "web.lan",
            "services": [_service(80, "http"), _service(443, "https")],
        }
        diff = diff_scans(old, new)
        self.assertEqual(diff.old_mode, "host")
        self.assertEqual([item.key for item in diff.services_opened], ["192.0.2.5:443/tcp"])

    def test_warnings_are_compared(self) -> None:
        old = _network_scan("old", [], warnings=["a", "b"])
        new = _network_scan("new", [], warnings=["b", "c"])
        diff = diff_scans(old, new)
        self.assertEqual(diff.warnings_added, ["c"])
        self.assertEqual(diff.warnings_removed, ["a"])

    def test_to_dict_is_json_friendly(self) -> None:
        old = _network_scan("old", [_host("10.0.0.1", services=[_service(80, "http")])])
        new = _network_scan("new", [_host("10.0.0.2", services=[_service(80, "http")])])
        payload = diff_scans(old, new).to_dict()
        encoded = json.dumps(payload)  # must not raise
        self.assertIn("10.0.0.2", encoded)
        self.assertTrue(payload["has_changes"])

    def test_render_diff_reports_everything(self) -> None:
        old = _network_scan("old", [_host("10.0.0.1", services=[_service(80, "http")])])
        new = _network_scan("new", [_host("10.0.0.2", services=[_service(443, "https")])])
        text = render_diff(diff_scans(old, new))
        self.assertIn("Net Spectre report diff", text)
        self.assertIn("10.0.0.2", text)
        self.assertIn("10.0.0.1", text)
        self.assertIn("change(s) detected", text)

    def test_render_diff_without_changes(self) -> None:
        scan = _network_scan("same", [_host("10.0.0.1")])
        text = render_diff(diff_scans(scan, scan))
        self.assertIn("No changes detected.", text)
        self.assertIn("no host changes", text)
        self.assertIn("no service changes", text)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
