"""Tests for DNS, mDNS, NetBIOS and target-resolution helpers."""

from __future__ import annotations

import struct
import unittest

from src.names import (
    _sanitize_name,
    build_dns_query,
    build_nbstat_query,
    decode_dns_name,
    encode_dns_name,
    parse_nbstat_response,
    resolve_ipv4,
)


class DnsWireTests(unittest.TestCase):
    def test_encode_decode_roundtrip(self) -> None:
        encoded = encode_dns_name("example.com")
        self.assertEqual(encoded, b"\x07example\x03com\x00")
        name, offset = decode_dns_name(encoded, 0)
        self.assertEqual(name, "example.com")
        self.assertEqual(offset, len(encoded))

    def test_compression_pointer(self) -> None:
        base = encode_dns_name("example.com")
        packet = base + b"\xc0\x00"
        name, offset = decode_dns_name(packet, len(base))
        self.assertEqual(name, "example.com")
        self.assertEqual(offset, len(base) + 2)

    def test_query_header_and_trailer(self) -> None:
        query = build_dns_query("version.bind", qtype=16, qclass=3, transaction_id=0x1234)
        identifier, flags, qdcount, ancount, nscount, arcount = struct.unpack(
            "!HHHHHH", query[:12]
        )
        self.assertEqual(identifier, 0x1234)
        self.assertEqual(flags, 0)
        self.assertEqual((qdcount, ancount, nscount, arcount), (1, 0, 0, 0))
        self.assertEqual(query[-4:], struct.pack("!HH", 16, 3))

    def test_zero_label_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            decode_dns_name(b"", 0)
        with self.assertRaises(ValueError):
            encode_dns_name("a" * 64 + ".com")

    def test_sanitize_name(self) -> None:
        self.assertEqual(_sanitize_name(" host.local. "), "host.local")
        self.assertIsNone(_sanitize_name("localhost"))
        self.assertIsNone(_sanitize_name(""))
        self.assertIsNone(_sanitize_name("x" * 300))


class NetbiosTests(unittest.TestCase):
    def test_query_format(self) -> None:
        query = build_nbstat_query(transaction_id=1)
        self.assertEqual(struct.unpack("!H", query[:2])[0], 1)
        self.assertEqual(query[12], 32)  # encoded name length
        self.assertEqual(query[-4:], struct.pack("!HH", 0x0021, 0x0001))

    def test_parse_node_status(self) -> None:
        name = b"WORKSTATION    "[:15]
        entry = name + b"\x00" + struct.pack("!H", 0x0000)
        rdata = b"\x01" + entry
        question = encode_dns_name("*") + struct.pack("!HH", 0x0021, 0x0001)
        header = struct.pack("!HHHHHH", 1, 0x8400, 1, 1, 0, 0)
        answer = (
            b"\xc0\x0c"
            + struct.pack("!HHIH", 0x0021, 0x0001, 0, len(rdata))
            + rdata
        )
        names = parse_nbstat_response(header + question + answer)
        self.assertEqual(len(names), 1)
        self.assertEqual(names[0].name, "WORKSTATION")
        self.assertEqual(names[0].suffix, 0)
        self.assertTrue(names[0].is_workstation)

    def test_invalid_node_status(self) -> None:
        self.assertEqual(parse_nbstat_response(b""), [])
        self.assertEqual(parse_nbstat_response(b"\x00" * 12), [])


class ResolveTests(unittest.TestCase):
    def test_literal_ipv4(self) -> None:
        self.assertEqual(resolve_ipv4(" 127.0.0.1 "), "127.0.0.1")

    def test_ipv6_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            resolve_ipv4("::1")


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
