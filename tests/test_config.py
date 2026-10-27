"""Tests for ScanConfig validation and environment handling."""

from __future__ import annotations

import os
import unittest
from unittest import mock

from src.config import ScanConfig
from src.constants import QUICK_SCAN_PORTS, TOP_TCP_PORTS


class ConfigTests(unittest.TestCase):
    def test_defaults(self) -> None:
        config = ScanConfig()
        self.assertEqual(config.engine, "native")
        self.assertEqual(config.quick_ports, tuple(sorted(QUICK_SCAN_PORTS)))
        self.assertEqual(config.default_ports, tuple(sorted(TOP_TCP_PORTS)))
        self.assertTrue(config.quick_port_scan)

    def test_validation_clamps_values(self) -> None:
        config = ScanConfig(
            timeout=0.001,
            port_timeout=1000,
            concurrency=0,
            fingerprint_concurrency=10000,
            max_hosts=0,
        )
        self.assertGreaterEqual(config.timeout, 0.1)
        self.assertLessEqual(config.port_timeout, 30.0)
        self.assertEqual(config.concurrency, 1)
        self.assertEqual(config.fingerprint_concurrency, 128)
        self.assertEqual(config.max_hosts, 1)

    def test_ports_are_cleaned(self) -> None:
        config = ScanConfig(quick_ports=(0, 80, 80, 70000, 443))
        self.assertEqual(config.quick_ports, (80, 443))

    def test_unknown_engine(self) -> None:
        with self.assertRaises(ValueError):
            ScanConfig(engine="bogus")

    def test_with_overrides_returns_copy(self) -> None:
        original = ScanConfig()
        changed = original.with_overrides(timeout=2.5, unknown_option=True)
        self.assertIsNot(original, changed)
        self.assertEqual(changed.timeout, 2.5)
        self.assertEqual(original.timeout, 1.5)

    def test_to_dict(self) -> None:
        payload = ScanConfig(udp=True).to_dict()
        self.assertTrue(payload["udp"])
        self.assertIn(53, payload["udp_ports"])
        self.assertIn("quick_ports", payload)

    def test_environment_overrides(self) -> None:
        environment = {
            "NET_SPECTRE_TIMEOUT": "3.5",
            "NET_SPECTRE_CONCURRENCY": "50",
            "NET_SPECTRE_PING_CONCURRENCY": "17",
            "NET_SPECTRE_ENGINE": "native",
            "NET_SPECTRE_LOG_DIR": "/tmp/net-spectre-env",
            "NO_COLOR": "1",
        }
        with mock.patch.dict(os.environ, environment, clear=False):
            config = ScanConfig.from_environment()
        self.assertEqual(config.timeout, 3.5)
        self.assertEqual(config.concurrency, 50)
        self.assertEqual(config.ping_concurrency, 17)
        self.assertFalse(config.color)
        self.assertEqual(str(config.log_dir), "/tmp/net-spectre-env")

    def test_invalid_environment_values_are_ignored(self) -> None:
        with mock.patch.dict(
            os.environ, {"NET_SPECTRE_CONCURRENCY": "not-a-number"}, clear=False
        ):
            config = ScanConfig.from_environment()
        self.assertGreaterEqual(config.concurrency, 1)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
