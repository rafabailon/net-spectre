"""Tests for argument parsing and CLI helpers."""

from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from src import __version__
from src.cli import (
    EXIT_ERROR,
    EXIT_FINDINGS,
    EXIT_OK,
    EXIT_USAGE,
    _config_from_args,
    _resolve_host_ports,
    build_parser,
    main,
)
from src.config import ScanConfig
from src.models import HostScanResult, NetworkScanResult, ServiceInfo


class ParserTests(unittest.TestCase):
    def setUp(self) -> None:
        self.parser = build_parser()

    def test_network_options(self) -> None:
        args = self.parser.parse_args(
            [
                "network",
                "--target",
                "192.168.1.0/24",
                "--interface",
                "eth0",
                "--no-quick-scan",
                "--no-color",
                "--quick-ports",
                "22,80,443",
            ]
        )
        self.assertEqual(args.command, "network")
        self.assertEqual(args.target, "192.168.1.0/24")
        self.assertEqual(args.interface, "eth0")
        self.assertTrue(args.no_quick_scan)
        self.assertTrue(args.no_color)
        config = _config_from_args(args)
        self.assertFalse(config.quick_port_scan)
        self.assertEqual(config.quick_ports, (22, 80, 443))

    def test_host_options(self) -> None:
        args = self.parser.parse_args(
            [
                "host",
                "example.com",
                "--preset",
                "web",
                "--udp",
                "--udp-ports",
                "53,161",
                "--engine",
                "native",
            ]
        )
        self.assertEqual(args.command, "host")
        self.assertEqual(args.target, "example.com")
        self.assertEqual(args.preset, "web")
        self.assertTrue(args.udp)
        config = _config_from_args(args)
        self.assertEqual(config.udp_ports, (53, 161))
        self.assertEqual(config.engine, "native")

    def test_host_ports_resolution(self) -> None:
        config = ScanConfig()
        cases = (
            (["host", "127.0.0.1"], len(config.default_ports)),
            (["host", "127.0.0.1", "-p", "22,80"], 2),
            (["host", "127.0.0.1", "--preset", "web"], 12),
            (["host", "127.0.0.1", "--full"], 65535),
        )
        for argv, expected in cases:
            with self.subTest(argv=argv):
                args = self.parser.parse_args(argv)
                self.assertEqual(len(_resolve_host_ports(args, config)), expected)

    def test_utility_commands_accept_output_options(self) -> None:
        for command in ("interfaces", "update-oui"):
            with self.subTest(command=command):
                args = self.parser.parse_args([command, "--no-color", "-v"])
                self.assertTrue(args.no_color)
                self.assertTrue(args.verbose)
        args = self.parser.parse_args(
            ["menu", "--no-color", "--log-dir", "/tmp/net-spectre-test"]
        )
        self.assertEqual(args.log_dir, Path("/tmp/net-spectre-test"))

    def test_invalid_engine_is_rejected(self) -> None:
        with self.assertRaises(SystemExit):
            with contextlib.redirect_stderr(io.StringIO()):
                self.parser.parse_args(["host", "127.0.0.1", "--engine", "bogus"])

    def test_new_scan_options(self) -> None:
        args = self.parser.parse_args(
            [
                "network",
                "--exclude",
                "192.168.1.1-10",
                "--ping-concurrency",
                "32",
                "--csv",
                "-q",
            ]
        )
        self.assertEqual(args.exclude, "192.168.1.1-10")
        self.assertTrue(args.csv)
        self.assertTrue(args.quiet)
        config = _config_from_args(args)
        self.assertEqual(config.ping_concurrency, 32)

    def test_host_fail_on_open_flag(self) -> None:
        args = self.parser.parse_args(["host", "127.0.0.1", "--fail-on-open"])
        self.assertTrue(args.fail_on_open)

    def test_diff_options(self) -> None:
        args = self.parser.parse_args(
            ["diff", "old.json", "new.json", "--json", "--fail-on-change"]
        )
        self.assertEqual(args.command, "diff")
        self.assertEqual(args.old, Path("old.json"))
        self.assertEqual(args.new, Path("new.json"))
        self.assertTrue(args.json_output)
        self.assertTrue(args.fail_on_change)

    def test_export_options(self) -> None:
        args = self.parser.parse_args(
            [
                "export",
                "report.json",
                "--format",
                "text",
                "--output",
                "-",
                "--force",
                "--no-color",
            ]
        )
        self.assertEqual(args.command, "export")
        self.assertEqual(args.source, Path("report.json"))
        self.assertEqual(args.format, "text")
        self.assertEqual(str(args.output), "-")
        self.assertTrue(args.force)
        self.assertTrue(args.no_color)

    def test_export_defaults_to_csv(self) -> None:
        args = self.parser.parse_args(["export", "report.json"])
        self.assertEqual(args.format, "csv")
        self.assertIsNone(args.output)
        self.assertFalse(args.force)


class CommandHandlerTests(unittest.TestCase):
    def _host_result(self, *, services: bool = True) -> HostScanResult:
        return HostScanResult(
            scan_id="HOST-TEST",
            target="127.0.0.1",
            resolved_ip="127.0.0.1",
            started_at="2026-01-01T00:00:00+00:00",
            finished_at="2026-01-01T00:00:01+00:00",
            duration_s=1.0,
            ports_scanned=1,
            services=[ServiceInfo(port=80, service="http")] if services else [],
            tool_version=__version__,
        )

    def test_host_fail_on_open_returns_exit_three(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            argv = [
                "host",
                "127.0.0.1",
                "-p",
                "80",
                "--fail-on-open",
                "-q",
                "--log-dir",
                temporary,
                "--no-color",
            ]
            with mock.patch("src.cli.HostScanner") as scanner:
                scanner.return_value.scan.return_value = self._host_result()
                with contextlib.redirect_stdout(io.StringIO()):
                    code = main(argv)
            self.assertEqual(code, EXIT_FINDINGS)

    def test_host_without_open_ports_returns_zero(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            argv = [
                "host",
                "127.0.0.1",
                "-p",
                "80",
                "--fail-on-open",
                "-q",
                "--log-dir",
                temporary,
                "--no-color",
            ]
            with mock.patch("src.cli.HostScanner") as scanner:
                scanner.return_value.scan.return_value = self._host_result(
                    services=False
                )
                with contextlib.redirect_stdout(io.StringIO()):
                    code = main(argv)
            self.assertEqual(code, EXIT_OK)

    def test_quiet_suppresses_console_summary_but_writes_reports(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            argv = [
                "host",
                "127.0.0.1",
                "-p",
                "80",
                "-q",
                "--log-dir",
                temporary,
                "--no-color",
            ]
            stdout = io.StringIO()
            with mock.patch("src.cli.HostScanner") as scanner:
                scanner.return_value.scan.return_value = self._host_result()
                with contextlib.redirect_stdout(stdout):
                    code = main(argv)
            self.assertEqual(code, EXIT_OK)
            self.assertEqual(stdout.getvalue().strip(), "")
            self.assertEqual(len(list(Path(temporary).glob("host_scan_*.json"))), 1)

    def test_report_write_failure_returns_exit_one(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            argv = [
                "host",
                "127.0.0.1",
                "-p",
                "80",
                "-q",
                "--log-dir",
                temporary,
                "--no-color",
            ]
            stderr = io.StringIO()
            with mock.patch("src.cli.HostScanner") as scanner:
                scanner.return_value.scan.return_value = self._host_result()
                with mock.patch(
                    "src.cli.write_reports", side_effect=OSError("disk full")
                ):
                    with contextlib.redirect_stderr(stderr):
                        code = main(argv)
            self.assertEqual(code, EXIT_ERROR)
            self.assertIn("Could not write reports", stderr.getvalue())


class ExportCommandTests(unittest.TestCase):
    def _report(self, directory: Path) -> Path:
        path = directory / "host_scan.json"
        payload = {
            "generator": "Net Spectre",
            "report_version": 1,
            "scan": {
                "scan_id": "HOST-1",
                "mode": "host",
                "target": "127.0.0.1",
                "resolved_ip": "127.0.0.1",
                "started_at": "2026-01-01T00:00:00+00:00",
                "finished_at": "2026-01-01T00:00:01+00:00",
                "duration_s": 1.0,
                "services": [
                    {"port": 80, "protocol": "tcp", "state": "open", "service": "http"}
                ],
            },
        }
        path.write_text(json.dumps(payload), encoding="utf-8")
        return path

    def test_export_writes_csv_file(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            report = self._report(directory)
            output = directory / "inventory.csv"
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                code = main(
                    [
                        "export",
                        str(report),
                        "--format",
                        "csv",
                        "--output",
                        str(output),
                        "--no-color",
                    ]
                )
            self.assertEqual(code, EXIT_OK)
            self.assertTrue(output.is_file())
            self.assertIn("80,tcp,open,http", output.read_text(encoding="utf-8"))
            self.assertIn("Export written", stdout.getvalue())

    def test_export_to_stdout(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            report = self._report(Path(temporary))
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                code = main(
                    [
                        "export",
                        str(report),
                        "--format",
                        "text",
                        "--output",
                        "-",
                        "--no-color",
                    ]
                )
            self.assertEqual(code, EXIT_OK)
            self.assertIn("HOST PORT & SERVICE REPORT", stdout.getvalue())

    def test_export_existing_output_requires_force(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            report = self._report(directory)
            output = directory / "inventory.csv"
            output.write_text("existing", encoding="utf-8")
            with contextlib.redirect_stderr(io.StringIO()):
                code = main(
                    [
                        "export",
                        str(report),
                        "--output",
                        str(output),
                        "--no-color",
                    ]
                )
            self.assertEqual(code, EXIT_ERROR)
            self.assertEqual(output.read_text(encoding="utf-8"), "existing")

    def test_export_missing_report_is_an_error(self) -> None:
        with contextlib.redirect_stderr(io.StringIO()):
            code = main(["export", "/nonexistent/report.json", "--no-color"])
        self.assertEqual(code, EXIT_ERROR)

    def test_export_to_input_path_is_a_usage_error(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            report = self._report(Path(temporary))
            with contextlib.redirect_stderr(io.StringIO()):
                code = main(
                    [
                        "export",
                        str(report),
                        "--format",
                        "text",
                        "--output",
                        str(report),
                        "--force",
                        "--no-color",
                    ]
                )
            self.assertEqual(code, EXIT_USAGE)

    def test_export_write_failure_is_an_error(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            report = self._report(Path(temporary))
            with mock.patch("src.cli.export_report", side_effect=OSError("read-only")):
                with contextlib.redirect_stderr(io.StringIO()):
                    code = main(
                        [
                            "export",
                            str(report),
                            "--output",
                            str(Path(temporary) / "out.csv"),
                            "--no-color",
                        ]
                    )
            self.assertEqual(code, EXIT_ERROR)


class DiffCommandTests(unittest.TestCase):
    def _write(self, directory: Path, name: str, payload: dict) -> Path:
        path = directory / name
        path.write_text(json.dumps(payload), encoding="utf-8")
        return path

    def _payload(self, scan_id: str, hosts: list[dict]) -> dict:
        return {
            "generator": "Net Spectre",
            "report_version": 1,
            "scan": {"scan_id": scan_id, "mode": "network", "hosts": hosts},
        }

    def test_diff_reports_changes_and_exit_code(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            old = self._write(
                directory, "old.json", self._payload("old", [{"ip": "10.0.0.1"}])
            )
            new = self._write(
                directory, "new.json", self._payload("new", [{"ip": "10.0.0.2"}])
            )
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                code = main(["diff", str(old), str(new), "--fail-on-change"])
            self.assertEqual(code, EXIT_FINDINGS)
            self.assertIn("10.0.0.2", stdout.getvalue())

    def test_diff_json_output(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            scan = self._payload("same", [{"ip": "10.0.0.1"}])
            old = self._write(directory, "a.json", scan)
            new = self._write(directory, "b.json", scan)
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                code = main(["diff", str(old), str(new), "--json"])
            self.assertEqual(code, EXIT_OK)
            payload = json.loads(stdout.getvalue())
            self.assertFalse(payload["has_changes"])

    def test_diff_missing_file_is_an_error(self) -> None:
        with contextlib.redirect_stderr(io.StringIO()):
            code = main(["diff", "/nonexistent/a.json", "/nonexistent/b.json"])
        self.assertEqual(code, EXIT_ERROR)


class EntryPointTests(unittest.TestCase):
    def test_version(self) -> None:
        stdout = io.StringIO()
        with self.assertRaises(SystemExit) as context:
            with contextlib.redirect_stdout(stdout):
                main(["--version"])
        self.assertEqual(context.exception.code, 0)
        self.assertIn(__version__, stdout.getvalue())

    def test_no_command_without_terminal_prints_help(self) -> None:
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            code = main([])
        self.assertEqual(code, 2)
        self.assertIn("usage:", stdout.getvalue())


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
