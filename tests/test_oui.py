"""Tests for the MAC OUI vendor database."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from src.oui import (
    EMBEDDED_OUI,
    OuiDatabase,
    _parse_oui_file,
    get_oui_database,
)


class OuiTests(unittest.TestCase):
    def test_embedded_lookup(self) -> None:
        database = OuiDatabase(sources=[])
        self.assertEqual(database.lookup("52:54:00:12:34:56"), "QEMU / KVM")
        self.assertEqual(database.lookup("00:00:0c:11:22:33"), "Cisco")
        self.assertIsNone(database.lookup("02:00:00:00:00:01"))
        self.assertIsNone(database.lookup("not-a-mac"))

    def test_nine_digit_prefix_wins(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "oui.txt"
            path.write_text(
                "001122\tBase vendor\n"
                "001122334\tLong prefix vendor\n",
                encoding="utf-8",
            )
            database = OuiDatabase(sources=[path])
            self.assertEqual(database.lookup("00:11:22:33:44:55"), "Long prefix vendor")
            self.assertEqual(database.lookup("00:11:22:99:44:55"), "Base vendor")

    def test_parse_arp_scan_format(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "arp-scan.txt"
            path.write_text(
                "# comment\n"
                "0050C27D5\tDEUTA-WERKE GmbH\n"
                "00000C\tCisco Systems, Inc\n",
                encoding="utf-8",
            )
            entries = _parse_oui_file(path)
            self.assertEqual(entries["0050C27D5"], "DEUTA-WERKE GmbH")
            self.assertEqual(entries["00000C"], "Cisco Systems, Inc")

    def test_parse_nmap_format(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "nmap-mac-prefixes"
            path.write_text(
                "00000C Cisco Systems\n001122 Example Networks\n",
                encoding="utf-8",
            )
            entries = _parse_oui_file(path)
            self.assertEqual(entries["00000C"], "Cisco Systems")
            self.assertEqual(entries["001122"], "Example Networks")

    def test_parse_ieee_hex_format(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "oui.txt"
            path.write_text(
                "00-00-0C   (hex)               Cisco Systems, Inc.\n"
                "00-11-22   (hex)               Example Corp\n",
                encoding="utf-8",
            )
            entries = _parse_oui_file(path)
            self.assertEqual(entries["00000C"], "Cisco Systems, Inc.")
            self.assertEqual(entries["001122"], "Example Corp")

    def test_embedded_table_is_consistent(self) -> None:
        for prefix in EMBEDDED_OUI:
            self.assertIn(len(prefix), (6, 9))
            int(prefix, 16)

    def test_process_wide_database_is_cached(self) -> None:
        self.assertIs(get_oui_database(), get_oui_database())


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
