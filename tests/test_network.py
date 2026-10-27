"""Tests for network helpers that do not require live devices."""

from __future__ import annotations

import unittest

from src.network import (
    SsdpDevice,
    _fetch_upnp_description,
    _merge_ssdp_device,
    _parse_ssdp_headers,
    _ping_command,
    tcp_sweep,
)


class SsdpTests(unittest.TestCase):
    def test_parse_headers(self) -> None:
        payload = (
            b"HTTP/1.1 200 OK\r\n"
            b"LOCATION: http://192.168.1.1:5000/desc.xml\r\n"
            b"Server: Linux/3.14 UPnP/1.0\r\n"
            b"ST: upnp:rootdevice\r\n"
            b"USN: uuid:abc::upnp:rootdevice\r\n\r\n"
        )
        headers = _parse_ssdp_headers(payload)
        self.assertEqual(headers["_status"], "HTTP/1.1 200 OK")
        self.assertEqual(
            headers["location"], "http://192.168.1.1:5000/desc.xml"
        )
        self.assertEqual(headers["st"], "upnp:rootdevice")

    def test_merge_keeps_existing_values(self) -> None:
        base = SsdpDevice(ip="192.168.1.1", friendly_name="Router")
        extra = SsdpDevice(
            ip="192.168.1.1",
            friendly_name="Other",
            manufacturer="Example",
            model_name="X1",
        )
        merged = _merge_ssdp_device(base, extra)
        self.assertIs(merged, base)
        self.assertEqual(merged.friendly_name, "Router")
        self.assertEqual(merged.manufacturer, "Example")
        self.assertEqual(merged.model_name, "X1")

    def test_fetch_without_location(self) -> None:
        self.assertEqual(_fetch_upnp_description(None), {})
        self.assertEqual(_fetch_upnp_description("file:///etc/passwd"), {})

    def test_summary(self) -> None:
        device = SsdpDevice(
            ip="192.168.1.1",
            friendly_name="Router",
            manufacturer="Example",
            model_name="X1",
        )
        summary = device.summary()
        self.assertIn("friendlyName=Router", summary)
        self.assertIn("manufacturer=Example", summary)
        self.assertIn("modelName=X1", summary)


class CommandTests(unittest.TestCase):
    def test_ping_command_shape(self) -> None:
        command = _ping_command("192.168.1.1", 1.0)
        self.assertEqual(command[0], "ping")
        self.assertIn("192.168.1.1", command)

    def test_empty_tcp_sweep(self) -> None:
        self.assertEqual(tcp_sweep([], ports=[80]), {})
        self.assertEqual(tcp_sweep(["192.0.2.1"], ports=[]), {})

    def test_tcp_sweep_skips_hosts(self) -> None:
        self.assertEqual(
            tcp_sweep(["192.0.2.1"], ports=[80], skip={"192.0.2.1"}), {}
        )


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
