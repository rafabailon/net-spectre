"""Tests for service fingerprinting and protocol helpers."""

from __future__ import annotations

import struct
import unittest

from src.fingerprint import (
    _ber_integer,
    _ber_oid,
    _ber_tlv,
    _parse_dns_version,
    _parse_ntp,
    build_snmp_get,
    classify,
    parse_http_response,
    parse_server_header,
    parse_snmp_response,
)
from src.models import HttpInfo, TlsCertificate


class HttpParsingTests(unittest.TestCase):
    def test_parse_basic_response(self) -> None:
        payload = (
            b"HTTP/1.1 200 OK\r\n"
            b"Server: nginx/1.24.0\r\n"
            b"X-Powered-By: PHP/8.2\r\n"
            b"Content-Type: text/html; charset=utf-8\r\n"
            b"Location: /login\r\n\r\n"
            b"<html><head><title>Hello &amp; welcome</title></head></html>"
        )
        info = parse_http_response(payload)
        self.assertIsNotNone(info)
        assert info is not None
        self.assertEqual(info.status_code, 200)
        self.assertEqual(info.reason, "OK")
        self.assertEqual(info.server, "nginx/1.24.0")
        self.assertEqual(info.powered_by, "PHP/8.2")
        self.assertEqual(info.title, "Hello & welcome")
        self.assertEqual(info.location, "/login")

    def test_scheme_is_preserved(self) -> None:
        info = parse_http_response(b"HTTP/1.0 204 No Content\r\n\r\n", scheme="https")
        assert info is not None
        self.assertEqual(info.scheme, "https")
        self.assertEqual(info.status_code, 204)

    def test_non_http_payload(self) -> None:
        self.assertIsNone(parse_http_response(b"SSH-2.0-OpenSSH_9.6\r\n"))
        self.assertIsNone(parse_http_response(b""))

    def test_duplicate_headers_are_joined(self) -> None:
        info = parse_http_response(
            b"HTTP/1.1 200 OK\r\nSet-Cookie: a=1\r\nSet-Cookie: b=2\r\n\r\n"
        )
        assert info is not None
        self.assertEqual(info.headers["set-cookie"], "a=1, b=2")


class ServerHeaderTests(unittest.TestCase):
    def test_known_products(self) -> None:
        self.assertEqual(parse_server_header("nginx/1.24.0"), ("nginx", "1.24.0"))
        self.assertEqual(
            parse_server_header("Apache/2.4.58 (Ubuntu)"),
            ("Apache httpd", "2.4.58"),
        )
        self.assertEqual(
            parse_server_header("Microsoft-IIS/10.0"), ("Microsoft IIS", "10.0")
        )
        self.assertEqual(parse_server_header("cloudflare"), ("Cloudflare", None))

    def test_unknown_and_empty(self) -> None:
        self.assertEqual(parse_server_header(None), (None, None))
        self.assertEqual(parse_server_header("SomeApp"), ("SomeApp", None))


class ClassificationTests(unittest.TestCase):
    def test_ssh_banner(self) -> None:
        service, product, version, confidence, _ = classify(
            22, "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13\r\n"
        )
        self.assertEqual(service, "ssh")
        self.assertEqual(product, "OpenSSH")
        self.assertEqual(version, "9.6p1")
        self.assertGreaterEqual(confidence, 90)

    def test_http_metadata(self) -> None:
        http = HttpInfo(
            status_code=200,
            server="nginx/1.24.0",
            title="Welcome",
            headers={},
        )
        service, product, version, confidence, extra = classify(
            80, "HTTP/1.1 200 OK", http=http
        )
        self.assertEqual(service, "http")
        self.assertEqual(product, "nginx")
        self.assertEqual(version, "1.24.0")
        self.assertEqual(confidence, 92)
        self.assertIn("title=", extra or "")
        self.assertIn("status=200", extra or "")

    def test_https_metadata(self) -> None:
        http = HttpInfo(scheme="https", status_code=200, server="Caddy")
        service, product, _, _, _ = classify(443, "", http=http)
        self.assertEqual(service, "https")
        self.assertEqual(product, "Caddy")

    def test_redis_info(self) -> None:
        banner = (
            "# Server\r\nredis_version:7.2.4\r\n"
            "os:Linux 6.8.0 x86_64\r\n"
        )
        service, product, version, confidence, extra = classify(6379, banner)
        self.assertEqual(service, "redis")
        self.assertEqual(product, "Redis")
        self.assertEqual(version, "7.2.4")
        self.assertEqual(confidence, 95)
        self.assertIn("os=", extra or "")

    def test_memcached_version(self) -> None:
        service, product, version, confidence, _ = classify(
            11211, "VERSION 1.6.21\r\n"
        )
        self.assertEqual(service, "memcached")
        self.assertEqual(product, "memcached")
        self.assertEqual(version, "1.6.21")
        self.assertGreaterEqual(confidence, 90)

    def test_tls_fallback(self) -> None:
        tls = TlsCertificate(subject="CN=router", cipher="TLS_AES_256_GCM_SHA384")
        service, _, _, confidence, extra = classify(8443, "", tls=tls)
        self.assertEqual(service, "tls")
        self.assertGreaterEqual(confidence, 55)
        self.assertIn("cipher=", extra or "")

    def test_unknown_service_keeps_port_hint(self) -> None:
        service, _, _, confidence, _ = classify(9999, "")
        self.assertEqual(service, "http-alt")
        self.assertEqual(confidence, 45)

    def test_vnc_signature(self) -> None:
        service, _, _, confidence, _ = classify(5900, "RFB 003.008\n")
        self.assertEqual(service, "vnc")
        self.assertGreaterEqual(confidence, 90)


class SnmpTests(unittest.TestCase):
    def test_build_request_is_well_formed(self) -> None:
        payload = build_snmp_get("1.3.6.1.2.1.1.1.0", "public")
        self.assertEqual(payload[0], 0x30)
        self.assertIn(b"public", payload)
        self.assertIn(b"\x06", payload)

    def test_parse_response(self) -> None:
        varbind = _ber_tlv(0x30, _ber_oid("1.3.6.1.2.1.1.1.0") + _ber_tlv(0x04, b"Test agent"))
        varbinds = _ber_tlv(0x30, varbind)
        pdu = _ber_tlv(
            0xA0,
            _ber_integer(1) + _ber_integer(0) + _ber_integer(0) + varbinds,
        )
        message = _ber_tlv(
            0x30,
            _ber_integer(1) + _ber_tlv(0x04, b"public") + pdu,
        )
        self.assertEqual(parse_snmp_response(message), "Test agent")

    def test_invalid_response(self) -> None:
        self.assertIsNone(parse_snmp_response(b"garbage"))
        self.assertIsNone(parse_snmp_response(b"\x30\x00"))


class UdpParserTests(unittest.TestCase):
    def test_ntp(self) -> None:
        payload = bytearray(48)
        payload[0] = (4 << 3) | 4  # version 4, server mode
        payload[1] = 2  # stratum
        product, extra = _parse_ntp(bytes(payload))
        self.assertEqual(product, "NTP v4")
        self.assertEqual(extra, "stratum=2")
        self.assertEqual(_parse_ntp(b"short"), (None, None))

    def test_dns_version(self) -> None:
        payload = struct.pack("!HHHHHH", 1, 0x8400, 1, 1, 0, 0) + b"BIND 9.18.1"
        product, version = _parse_dns_version(payload)
        self.assertEqual(product, "BIND")
        self.assertEqual(version, "9.18.1")
        self.assertEqual(_parse_dns_version(b"\x00"), (None, None))


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
