"""Tests for the generic helper functions."""

from __future__ import annotations

import unittest

from src.utils import (
    TargetError,
    ceil_div,
    chunked,
    clamp,
    colorize,
    configure_color,
    exclude_targets,
    expand_targets,
    guess_os_from_ttl,
    humanize_seconds,
    mac_is_locally_administered,
    mac_is_multicast,
    normalize_mac,
    parse_exclusions,
    parse_ping_output,
    parse_port_spec,
    sanitize_filename,
    strip_ansi,
    table,
    unique,
    validate_target,
)


class TargetExpansionTests(unittest.TestCase):
    def test_single_address(self) -> None:
        self.assertEqual(expand_targets("192.168.1.10"), ["192.168.1.10"])

    def test_last_octet_range(self) -> None:
        self.assertEqual(
            expand_targets("192.168.1.10-12"),
            ["192.168.1.10", "192.168.1.11", "192.168.1.12"],
        )

    def test_full_range(self) -> None:
        self.assertEqual(
            expand_targets("10.0.0.1-10.0.0.2"),
            ["10.0.0.1", "10.0.0.2"],
        )

    def test_cidr_uses_usable_hosts(self) -> None:
        self.assertEqual(
            expand_targets("192.168.1.0/30"),
            ["192.168.1.1", "192.168.1.2"],
        )

    def test_cidr_32_returns_the_address(self) -> None:
        self.assertEqual(expand_targets("192.168.1.7/32"), ["192.168.1.7"])

    def test_combinations_are_deduplicated(self) -> None:
        result = expand_targets("192.168.1.1,192.168.1.1-2")
        self.assertEqual(result, ["192.168.1.1", "192.168.1.2"])

    def test_max_hosts_is_enforced(self) -> None:
        with self.assertRaises(TargetError):
            expand_targets("10.0.0.0/24", max_hosts=10)

    def test_invalid_range(self) -> None:
        with self.assertRaises(TargetError):
            expand_targets("10.0.0.10-5")

    def test_empty_spec(self) -> None:
        with self.assertRaises(TargetError):
            expand_targets("   ")

    def test_validate_target(self) -> None:
        self.assertEqual(validate_target("192.168.1.1"), "192.168.1.1")
        self.assertEqual(validate_target("example.com"), "example.com")
        with self.assertRaises(TargetError):
            validate_target("not a host!")


class ExclusionTests(unittest.TestCase):
    def test_empty_spec_excludes_nothing(self) -> None:
        self.assertEqual(parse_exclusions(None), [])
        self.assertEqual(parse_exclusions("   "), [])
        self.assertEqual(exclude_targets(["10.0.0.1"], None), ["10.0.0.1"])

    def test_cidr_and_range_expansion(self) -> None:
        self.assertEqual(
            parse_exclusions("10.0.0.0/30"),
            ["10.0.0.1", "10.0.0.2"],
        )
        self.assertEqual(
            parse_exclusions("10.0.0.8,10.0.0.10-11"),
            ["10.0.0.8", "10.0.0.10", "10.0.0.11"],
        )

    def test_exclusion_preserves_target_order(self) -> None:
        targets = ["10.0.0.3", "10.0.0.1", "10.0.0.2"]
        self.assertEqual(
            exclude_targets(targets, "10.0.0.1-2"),
            ["10.0.0.3"],
        )

    def test_all_targets_can_be_excluded(self) -> None:
        self.assertEqual(exclude_targets(["10.0.0.1"], "10.0.0.1"), [])
        self.assertEqual(exclude_targets(["10.0.0.1"], "10.0.0.0/30"), [])

    def test_invalid_and_oversized_exclusions(self) -> None:
        with self.assertRaises(TargetError):
            parse_exclusions("not-a-network")
        with self.assertRaises(TargetError):
            parse_exclusions("10.0.0.0/24", max_hosts=10)


class IntegerMathTests(unittest.TestCase):
    def test_ceil_div(self) -> None:
        self.assertEqual(ceil_div(10, 3), 4)
        self.assertEqual(ceil_div(9, 3), 3)
        self.assertEqual(ceil_div(0, 5), 0)
        self.assertEqual(ceil_div(-1, 2), 0)
        self.assertEqual(ceil_div(1, 0), 0)


class PortSpecTests(unittest.TestCase):
    def test_lists_and_ranges(self) -> None:
        self.assertEqual(
            parse_port_spec("22,80-82, 443"),
            [22, 80, 81, 82, 443],
        )

    def test_duplicates_are_removed(self) -> None:
        self.assertEqual(parse_port_spec("80,80,80-80"), [80])

    def test_preset(self) -> None:
        self.assertEqual(parse_port_spec(None, preset="web")[:1], [80])

    def test_invalid_ports(self) -> None:
        for spec in ("0", "65536", "100-50", "abc", "1-"):
            with self.subTest(spec=spec), self.assertRaises(TargetError):
                parse_port_spec(spec)

    def test_empty(self) -> None:
        with self.assertRaises(TargetError):
            parse_port_spec("")
        with self.assertRaises(TargetError):
            parse_port_spec(None, preset="does-not-exist")


class MacTests(unittest.TestCase):
    def test_normalize(self) -> None:
        self.assertEqual(
            normalize_mac("AA-BB-CC-DD-EE-FF"), "aa:bb:cc:dd:ee:ff"
        )
        self.assertEqual(
            normalize_mac("aabb.ccdd.eeff"), "aa:bb:cc:dd:ee:ff"
        )
        self.assertIsNone(normalize_mac("not-a-mac"))
        self.assertIsNone(normalize_mac(""))

    def test_flags(self) -> None:
        self.assertTrue(mac_is_locally_administered("02:00:00:00:00:01"))
        self.assertFalse(mac_is_locally_administered("00:50:56:00:00:01"))
        self.assertTrue(mac_is_multicast("01:00:5e:00:00:01"))
        self.assertFalse(mac_is_multicast("00:50:56:00:00:01"))


class OutputHelperTests(unittest.TestCase):
    def test_parse_ping_output(self) -> None:
        output = (
            "64 bytes from 192.168.1.1: icmp_seq=1 ttl=64 time=1.23 ms"
        )
        self.assertEqual(parse_ping_output(output), (1.23, 64))
        self.assertEqual(parse_ping_output("unrelated"), (None, None))

    def test_guess_os_from_ttl(self) -> None:
        self.assertIn("Linux", guess_os_from_ttl(64) or "")
        self.assertIn("Windows", guess_os_from_ttl(128) or "")
        self.assertIn("Network device", guess_os_from_ttl(255) or "")
        self.assertIsNone(guess_os_from_ttl(None))
        self.assertIsNone(guess_os_from_ttl(0))

    def test_humanize_seconds(self) -> None:
        self.assertEqual(humanize_seconds(None), "n/a")
        self.assertEqual(humanize_seconds(0.5), "500 ms")
        self.assertEqual(humanize_seconds(2.5), "2.50 s")
        self.assertEqual(humanize_seconds(61.0), "1m 01.0s")

    def test_sanitize_filename(self) -> None:
        self.assertEqual(sanitize_filename("../../etc/passwd"), "etc_passwd")
        self.assertEqual(sanitize_filename("   "), "target")
        self.assertLessEqual(len(sanitize_filename("x" * 200)), 60)

    def test_unique_preserves_order(self) -> None:
        self.assertEqual(unique([3, 1, 3, 2, 1]), [3, 1, 2])

    def test_clamp(self) -> None:
        self.assertEqual(clamp(5, 1, 3), 3)
        self.assertEqual(clamp(-1, 1, 3), 1)
        self.assertEqual(clamp(2, 1, 3), 2)

    def test_chunked(self) -> None:
        self.assertEqual(list(chunked([1, 2, 3, 4, 5], 2)), [[1, 2], [3, 4], [5]])
        with self.assertRaises(ValueError):
            list(chunked([1], 0))

    def test_strip_ansi_and_table(self) -> None:
        self.assertEqual(strip_ansi("\x1b[31mred\x1b[0m"), "red")
        rendered = table(("A", "B"), [("one", "two")])
        self.assertIn("A", rendered)
        self.assertIn("one", rendered)
        self.assertIn("---", rendered)

    def test_table_aligns_colored_headers(self) -> None:
        configure_color(True)
        try:
            rendered = table(
                (colorize("A", "bold"), "B"),
                [("long", "value")],
            )
        finally:
            configure_color(True)
        lines = [strip_ansi(line) for line in rendered.splitlines()]
        self.assertEqual(lines[0], "A     B")
        self.assertEqual(lines[2], "long  value")


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
