"""Command line interface and interactive menu.

Two modes are available:

* non-interactive subcommands for scripting (``network``, ``host``, ``diff``,
  ``export``, ``interfaces``, ``update-oui``);
* a numbered menu when the program is started without arguments in a
  terminal.

The menu implements the two requested workflows directly: network discovery
and per-host port/service scanning.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any, Sequence

from . import __version__
from .config import ScanConfig
from .constants import PORT_PRESETS
from .diffing import DiffError, diff_scans, load_report, render_diff
from .discovery import HostScanner, NetworkScanner, ScanError
from .logging_setup import get_logger, setup_logging
from .network import default_route, detect_local_networks, list_interfaces
from .oui import cache_path, download_oui_database, get_oui_database
from .reporting import (
    ReportPaths,
    export_report,
    render_console_host,
    render_console_network,
    render_export,
    write_reports,
)
from .utils import (
    TargetError,
    colorize,
    configure_color,
    parse_port_spec,
    print_banner,
    table,
)

__all__ = ["main", "build_parser", "interactive_menu"]

logger = get_logger(__name__)

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_USAGE = 2
#: Returned when ``--fail-on-open`` / ``--fail-on-change`` find something.
EXIT_FINDINGS = 3
EXIT_INTERRUPTED = 130


# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------

def _add_output_options(parser: argparse.ArgumentParser) -> None:
    """Options shared by every subcommand (also used by utility commands)."""
    parser.add_argument(
        "--log-dir",
        type=Path,
        default=None,
        metavar="DIR",
        help="directory for reports and the diagnostic log (default: ./logs)",
    )
    parser.add_argument("--no-color", action="store_true", help="disable ANSI colours")
    parser.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        help="suppress progress messages and the console summary (reports are still written)",
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="enable debug logging on stderr"
    )


def _add_common_options(parser: argparse.ArgumentParser) -> None:
    _add_output_options(parser)
    parser.add_argument(
        "--timeout",
        type=float,
        default=None,
        metavar="SECONDS",
        help="service read/probe timeout (default: 1.5)",
    )
    parser.add_argument(
        "--port-timeout",
        type=float,
        default=None,
        metavar="SECONDS",
        help="TCP connect timeout (default: 1.0)",
    )
    parser.add_argument(
        "--concurrency",
        type=int,
        default=None,
        metavar="N",
        help="maximum concurrent TCP connections (default: 250)",
    )
    parser.add_argument(
        "--ping-concurrency",
        type=int,
        default=None,
        metavar="N",
        help="maximum concurrent ICMP/TCP sweep workers (default: 64)",
    )
    parser.add_argument(
        "--fingerprint-concurrency",
        type=int,
        default=None,
        metavar="N",
        help="maximum concurrent service probes (default: 12)",
    )
    parser.add_argument(
        "--max-hosts",
        type=int,
        default=None,
        metavar="N",
        help="safety limit when expanding a network target (default: 4096)",
    )
    parser.add_argument(
        "-e",
        "--engine",
        choices=("native", "nmap", "auto"),
        default=None,
        help="scan engine; 'auto' uses nmap when installed (default: native)",
    )
    parser.add_argument(
        "--no-names",
        action="store_true",
        help="disable reverse DNS, mDNS and NetBIOS name resolution",
    )
    parser.add_argument(
        "--no-mdns",
        action="store_true",
        help="disable mDNS/avahi hostname resolution",
    )
    parser.add_argument(
        "--no-netbios",
        action="store_true",
        help="disable NetBIOS name queries",
    )


def build_parser() -> argparse.ArgumentParser:
    """Create the argument parser (exposed for tests and documentation)."""
    parser = argparse.ArgumentParser(
        prog="net-spectre",
        description=(
            "Net Spectre - discover devices on a local network and enumerate "
            "TCP/UDP services. Every scan writes a text report and a JSON "
            "document. Use only on networks you are authorized to test."
        ),
        epilog=(
            "examples:\n"
            "  net-spectre network\n"
            "  net-spectre network --target 192.168.1.0/24 --exclude 192.168.1.1-10\n"
            "  net-spectre network -t 192.168.1.0/24 --quick-ports 22,80,443 --csv\n"
            "  net-spectre host 192.168.1.1\n"
            "  net-spectre host scanme.example.com -p 1-1024 --udp\n"
            "  net-spectre host 10.0.0.5 --preset full --engine nmap --os-detection\n"
            "  net-spectre host 10.0.0.5 --fail-on-open -q\n"
            "  net-spectre diff logs/network_scan_20260101_120000.json logs/network_scan_20260102_120000.json\n"
            "  net-spectre export logs/network_scan_20260101_120000.json --format csv\n"
            "  net-spectre export report.json --format text --output -\n"
            "  net-spectre interfaces\n"
            "  net-spectre update-oui\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--version", action="version", version=f"Net Spectre {__version__}"
    )
    subparsers = parser.add_subparsers(dest="command", metavar="COMMAND")

    network = subparsers.add_parser(
        "network",
        help="discover all devices on a network",
        description=(
            "Discover live devices using ICMP, TCP, ARP, optional arp-scan/Nmap "
            "and SSDP. Resolves hostnames and vendors, enriches hosts with a "
            "quick port scan and writes a full report."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    network.add_argument(
        "-t",
        "--target",
        default=None,
        metavar="CIDR|IP|RANGE",
        help="network to scan (default: network of the default interface)",
    )
    network.add_argument(
        "-i",
        "--interface",
        default=None,
        metavar="NAME",
        help="interface whose network should be scanned",
    )
    network.add_argument(
        "--exclude",
        default=None,
        metavar="SPEC",
        help=(
            "addresses to skip: '192.168.1.1', '192.168.1.10-20', "
            "'192.168.1.0/28' or a comma separated combination"
        ),
    )
    network.add_argument("--no-ping", action="store_true", help="skip the ICMP sweep")
    network.add_argument(
        "--no-tcp-sweep", action="store_true", help="skip the TCP reachability sweep"
    )
    network.add_argument(
        "--no-arp-scan", action="store_true", help="do not use arp-scan even when available"
    )
    network.add_argument("--no-ssdp", action="store_true", help="skip SSDP/UPnP discovery")
    network.add_argument(
        "--no-quick-scan", action="store_true", help="do not scan ports on discovered hosts"
    )
    network.add_argument(
        "--quick-ports",
        default=None,
        metavar="SPEC",
        help="ports used to enrich hosts (default: built-in quick set)",
    )
    network.add_argument(
        "--csv",
        action="store_true",
        help="also write a flat CSV export of the discovered hosts and services",
    )
    _add_common_options(network)
    network.set_defaults(handler=_command_network)

    host = subparsers.add_parser(
        "host",
        help="scan ports and services on one host",
        description=(
            "Scan every requested TCP port of a host, fingerprint the services "
            "(banners, HTTP metadata, TLS certificates) and optionally probe UDP "
            "and run Nmap version/OS detection."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    host.add_argument("target", help="IPv4 address or hostname")
    host.add_argument(
        "-p",
        "--ports",
        default=None,
        metavar="SPEC",
        help="ports to scan: '80,443', '1-1024', combinations (default: common ports)",
    )
    host.add_argument(
        "--preset",
        choices=sorted(PORT_PRESETS),
        default=None,
        help="built-in port selection: quick, common, web, database or full",
    )
    host.add_argument(
        "--full", action="store_true", help="scan all 65535 TCP ports"
    )
    host.add_argument(
        "--udp",
        action="store_true",
        help="also probe UDP services (best effort; nmap+root improves results)",
    )
    host.add_argument(
        "--udp-ports",
        default=None,
        metavar="SPEC",
        help="UDP ports to probe (default: 53,123,161,1900,5353)",
    )
    host.add_argument(
        "--os-detection",
        action="store_true",
        help="enable Nmap OS fingerprinting (implies --engine nmap; root required)",
    )
    host.add_argument(
        "--csv",
        action="store_true",
        help="also write a flat CSV export of the open services",
    )
    host.add_argument(
        "--fail-on-open",
        action="store_true",
        help=f"exit with code {EXIT_FINDINGS} when at least one service is open",
    )
    _add_common_options(host)
    host.set_defaults(handler=_command_host)

    diff = subparsers.add_parser(
        "diff",
        help="compare two JSON reports",
        description=(
            "Compare two reports written by a previous scan and list hosts and "
            "services that were added, removed or changed.  Use --json for "
            "machine readable output and --fail-on-change for CI/monitoring."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    diff.add_argument("old", type=Path, metavar="OLD", help="baseline JSON report")
    diff.add_argument("new", type=Path, metavar="NEW", help="new JSON report")
    diff.add_argument(
        "--json",
        action="store_true",
        dest="json_output",
        help="print the diff as JSON instead of a human readable table",
    )
    diff.add_argument(
        "--fail-on-change",
        action="store_true",
        help=f"exit with code {EXIT_FINDINGS} when any difference is found",
    )
    _add_output_options(diff)
    diff.set_defaults(handler=_command_diff)

    export = subparsers.add_parser(
        "export",
        help="convert a saved JSON report to CSV or text",
        description=(
            "Convert a JSON report written by a previous scan into a flat CSV "
            "table or a human readable text report.  This command is fully "
            "offline: it never touches the network.  By default the output is "
            "written next to the source file; use --output - for stdout."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    export.add_argument("source", type=Path, metavar="REPORT", help="JSON report to convert")
    export.add_argument(
        "-f",
        "--format",
        choices=("csv", "text"),
        default="csv",
        help="output format (default: csv)",
    )
    export.add_argument(
        "-o",
        "--output",
        type=Path,
        default=None,
        metavar="PATH",
        help="output file (default: alongside REPORT; '-' writes to stdout)",
    )
    export.add_argument(
        "--force",
        action="store_true",
        help="overwrite the output file when it already exists",
    )
    _add_output_options(export)
    export.set_defaults(handler=_command_export)

    interfaces = subparsers.add_parser(
        "interfaces",
        help="list interfaces, local networks and the default route",
    )
    _add_output_options(interfaces)
    interfaces.set_defaults(handler=_command_interfaces)

    update_oui = subparsers.add_parser(
        "update-oui",
        help="download the IEEE MAC vendor registry",
        description="Download the IEEE OUI CSV registry into the local cache.",
    )
    _add_output_options(update_oui)
    update_oui.set_defaults(handler=_command_update_oui)

    menu = subparsers.add_parser("menu", help="start the interactive menu")
    _add_output_options(menu)
    menu.set_defaults(handler=_command_menu)

    return parser


# ---------------------------------------------------------------------------
# Config / parsing helpers
# ---------------------------------------------------------------------------

def _config_from_args(args: argparse.Namespace) -> ScanConfig:
    overrides: dict[str, Any] = {}
    for attribute in (
        "timeout",
        "port_timeout",
        "concurrency",
        "ping_concurrency",
        "fingerprint_concurrency",
        "max_hosts",
        "engine",
    ):
        value = getattr(args, attribute, None)
        if value is not None:
            overrides[attribute] = value
    if getattr(args, "log_dir", None):
        overrides["log_dir"] = args.log_dir
    if getattr(args, "verbose", False):
        overrides["verbose"] = True
    if getattr(args, "no_names", False):
        overrides["resolve_names"] = False
    if getattr(args, "no_mdns", False):
        overrides["use_mdns"] = False
    if getattr(args, "no_netbios", False):
        overrides["use_netbios"] = False
    if getattr(args, "no_ping", False):
        overrides["ping_sweep"] = False
    if getattr(args, "no_tcp_sweep", False):
        overrides["tcp_sweep"] = False
    if getattr(args, "no_arp_scan", False):
        overrides["arp_scan"] = False
    if getattr(args, "no_ssdp", False):
        overrides["ssdp"] = False
    if getattr(args, "no_quick_scan", False):
        overrides["quick_port_scan"] = False
    if getattr(args, "quick_ports", None):
        overrides["quick_ports"] = tuple(parse_port_spec(args.quick_ports))
    if getattr(args, "udp", False):
        overrides["udp"] = True
    if getattr(args, "udp_ports", None):
        overrides["udp_ports"] = tuple(parse_port_spec(args.udp_ports))
    if getattr(args, "os_detection", False):
        overrides["os_detection"] = True
    return ScanConfig.from_environment().with_overrides(**overrides)


def _resolve_host_ports(args: argparse.Namespace, config: ScanConfig) -> list[int]:
    if getattr(args, "full", False):
        return list(PORT_PRESETS["full"])
    if getattr(args, "preset", None):
        return list(PORT_PRESETS[args.preset])
    if getattr(args, "ports", None):
        return parse_port_spec(args.ports)
    return list(config.default_ports)


def _configure_output(args: argparse.Namespace) -> bool:
    """Configure ANSI colour output and return whether colours are enabled."""
    enabled = (
        not getattr(args, "no_color", False)
        and sys.stdout.isatty()
        and not bool(os.environ.get("NO_COLOR"))
    )
    configure_color(enabled)
    return enabled


def _progress(message: str) -> None:
    """Progress messages go to stderr so stdout can be piped safely."""
    print(colorize(f"  · {message}", "grey"), file=sys.stderr, flush=True)


# ---------------------------------------------------------------------------
# Command handlers
# ---------------------------------------------------------------------------

def _command_interfaces(args: argparse.Namespace) -> int:
    _configure_output(args)
    if getattr(args, "verbose", False):
        setup_logging(
            getattr(args, "log_dir", None) or Path("logs"), verbose=True
        )
    interfaces = list_interfaces()
    networks = detect_local_networks()
    interface_name, local_ip, gateway = default_route()
    rows = []
    for item in interfaces:
        addresses = ", ".join(str(address) for address in item.ipv4) or "-"
        rows.append(
            (
                item.name,
                addresses,
                item.mac or "-",
                "up" if item.is_up else "down",
                item.mtu or "-",
            )
        )
    print(colorize("Network interfaces", "bold"))
    print(table(("NAME", "IPv4", "MAC", "STATE", "MTU"), rows))
    print()
    print(colorize("Local networks", "bold"))
    if networks:
        print(
            table(
                ("INTERFACE", "LOCAL IP", "NETWORK", "GATEWAY", "MAC"),
                [
                    (
                        network.interface,
                        network.local_ip,
                        network.cidr,
                        network.gateway or "-",
                        network.mac or "-",
                    )
                    for network in networks
                ],
            )
        )
    else:
        print("No usable IPv4 network found.")
    print()
    print(f"Default route: interface={interface_name or '-'} local_ip={local_ip or '-'} "
          f"gateway={gateway or '-'}")
    return EXIT_OK


def _command_update_oui(args: argparse.Namespace) -> int:
    _configure_output(args)
    if getattr(args, "verbose", False):
        setup_logging(
            getattr(args, "log_dir", None) or Path("logs"), verbose=True
        )
    print("Downloading the IEEE OUI registry…")
    try:
        path, count = download_oui_database()
    except RuntimeError as exc:
        print(colorize(f"error: {exc}", "red"), file=sys.stderr)
        return EXIT_ERROR
    print(colorize(f"Saved {count} vendor prefixes to {path}", "green"))
    return EXIT_OK


def _command_menu(args: argparse.Namespace) -> int:
    overrides: dict[str, Any] = {}
    if getattr(args, "log_dir", None):
        overrides["log_dir"] = args.log_dir
    if getattr(args, "verbose", False):
        overrides["verbose"] = True
    config = ScanConfig.from_environment()
    if overrides:
        config = config.with_overrides(**overrides)
    return interactive_menu(config, no_color=getattr(args, "no_color", False))


def _finish_scan(
    result: Any,
    config: ScanConfig,
    *,
    interactive: bool,
    quiet: bool = False,
    csv_export: bool = False,
) -> ReportPaths | None:
    if interactive and not quiet:
        if result.mode == "network":
            print(render_console_network(result))
        else:
            print(render_console_host(result))
    try:
        paths = write_reports(result, config.log_dir, csv_export=csv_export)
    except OSError as exc:
        print(colorize(f"Could not write reports: {exc}", "red"), file=sys.stderr)
        return None
    if quiet:
        return paths
    print()
    print(colorize("Reports written:", "bold"))
    print(f"  text: {paths.text}")
    print(f"  json: {paths.json}")
    if paths.csv is not None:
        print(f"  csv : {paths.csv}")
    return paths


def _command_network(args: argparse.Namespace) -> int:
    config = _config_from_args(args)
    _configure_output(args)
    quiet = bool(getattr(args, "quiet", False))
    setup_logging(config.log_dir, verbose=config.verbose)
    scanner = NetworkScanner(config, progress=None if quiet else _progress)
    try:
        result = scanner.scan(
            args.target,
            interface=args.interface,
            exclude=getattr(args, "exclude", None),
        )
    except TargetError as exc:
        print(colorize(f"error: {exc}", "red"), file=sys.stderr)
        return EXIT_USAGE
    except ScanError as exc:
        print(colorize(f"error: {exc}", "red"), file=sys.stderr)
        return EXIT_ERROR
    except KeyboardInterrupt:
        print(colorize("\nInterrupted.", "yellow"), file=sys.stderr)
        return EXIT_INTERRUPTED
    except Exception as exc:  # pragma: no cover - unexpected platform error
        logger.exception("network scan failed")
        print(colorize(f"unexpected error: {exc}", "red"), file=sys.stderr)
        return EXIT_ERROR
    paths = _finish_scan(
        result,
        config,
        interactive=not quiet,
        quiet=quiet,
        csv_export=bool(getattr(args, "csv", False)),
    )
    return EXIT_ERROR if paths is None else EXIT_OK


def _command_host(args: argparse.Namespace) -> int:
    config = _config_from_args(args)
    _configure_output(args)
    quiet = bool(getattr(args, "quiet", False))
    setup_logging(config.log_dir, verbose=config.verbose)
    try:
        ports = _resolve_host_ports(args, config)
    except TargetError as exc:
        print(colorize(f"error: {exc}", "red"), file=sys.stderr)
        return EXIT_USAGE
    scanner = HostScanner(config, progress=None if quiet else _progress)
    try:
        result = scanner.scan(args.target, ports=ports)
    except ScanError as exc:
        print(colorize(f"error: {exc}", "red"), file=sys.stderr)
        return EXIT_ERROR
    except KeyboardInterrupt:
        print(colorize("\nInterrupted.", "yellow"), file=sys.stderr)
        return EXIT_INTERRUPTED
    except Exception as exc:  # pragma: no cover - unexpected platform error
        logger.exception("host scan failed")
        print(colorize(f"unexpected error: {exc}", "red"), file=sys.stderr)
        return EXIT_ERROR
    paths = _finish_scan(
        result,
        config,
        interactive=not quiet,
        quiet=quiet,
        csv_export=bool(getattr(args, "csv", False)),
    )
    if paths is None:
        return EXIT_ERROR
    if getattr(args, "fail_on_open", False) and result.services:
        return EXIT_FINDINGS
    return EXIT_OK


def _command_diff(args: argparse.Namespace) -> int:
    _configure_output(args)
    try:
        old_scan = load_report(args.old)
        new_scan = load_report(args.new)
    except DiffError as exc:
        print(colorize(f"error: {exc}", "red"), file=sys.stderr)
        return EXIT_ERROR
    result = diff_scans(old_scan, new_scan)
    if getattr(args, "json_output", False):
        print(json.dumps(result.to_dict(), indent=2, ensure_ascii=False))
    elif not getattr(args, "quiet", False):
        print(render_diff(result))
    if getattr(args, "fail_on_change", False) and result.has_changes:
        return EXIT_FINDINGS
    return EXIT_OK


def _command_export(args: argparse.Namespace) -> int:
    _configure_output(args)
    if getattr(args, "verbose", False):
        setup_logging(
            getattr(args, "log_dir", None) or Path("logs"), verbose=True
        )
    quiet = bool(getattr(args, "quiet", False))
    output = getattr(args, "output", None)
    try:
        if output is not None and str(output) == "-":
            sys.stdout.write(render_export(args.source, args.format))
            return EXIT_OK
        path = export_report(
            args.source,
            args.format,
            output,
            force=bool(getattr(args, "force", False)),
        )
    except DiffError as exc:
        print(colorize(f"error: {exc}", "red"), file=sys.stderr)
        return EXIT_ERROR
    except FileExistsError as exc:
        print(colorize(f"error: {exc}", "red"), file=sys.stderr)
        return EXIT_ERROR
    except ValueError as exc:
        print(colorize(f"error: {exc}", "red"), file=sys.stderr)
        return EXIT_USAGE
    except OSError as exc:
        print(colorize(f"error: cannot write export: {exc}", "red"), file=sys.stderr)
        return EXIT_ERROR
    if not quiet:
        print(colorize("Export written:", "bold"))
        print(f"  {path}")
    return EXIT_OK


# ---------------------------------------------------------------------------
# Interactive menu helpers
# ---------------------------------------------------------------------------

def _prompt(message: str, default: str | None = None) -> str:
    suffix = f" [{default}]" if default else ""
    try:
        value = input(f"{message}{suffix}: ").strip()
    except EOFError:
        raise KeyboardInterrupt from None
    if not value and default is not None:
        return default
    return value


def _prompt_yes_no(message: str, *, default: bool = True) -> bool:
    marker = "Y/n" if default else "y/N"
    value = _prompt(f"{message} ({marker})", default="").lower()
    if not value:
        return default
    return value in {"y", "yes", "s", "si", "sí"}


def _prompt_int(message: str, default: int, *, minimum: int, maximum: int) -> int:
    raw = _prompt(message, str(default))
    try:
        value = int(raw)
    except ValueError:
        print(colorize("  Invalid number; keeping the previous value.", "yellow"))
        return default
    if not minimum <= value <= maximum:
        print(
            colorize(
                f"  Value must be between {minimum} and {maximum}; keeping {default}.",
                "yellow",
            )
        )
        return default
    return value


def _show_settings(config: ScanConfig) -> None:
    print()
    print(colorize("Current settings", "bold"))
    rows = [
        ("Service timeout", f"{config.timeout:.2f} s"),
        ("TCP connect timeout", f"{config.port_timeout:.2f} s"),
        ("TCP concurrency", config.concurrency),
        ("Ping concurrency", config.ping_concurrency),
        ("Fingerprint concurrency", config.fingerprint_concurrency),
        ("Engine", config.engine),
        ("Name resolution", "enabled" if config.resolve_names else "disabled"),
        ("mDNS", "enabled" if config.use_mdns else "disabled"),
        ("NetBIOS", "enabled" if config.use_netbios else "disabled"),
        ("Quick port scan", "enabled" if config.quick_port_scan else "disabled"),
        ("Quick ports", len(config.quick_ports)),
        ("Log directory", config.log_dir),
    ]
    print(table(("SETTING", "VALUE"), rows))
    print()


def _settings_menu(config: ScanConfig) -> ScanConfig:
    while True:
        _show_settings(config)
        print("[1] Change service timeout")
        print("[2] Change TCP concurrency")
        print("[3] Change fingerprint concurrency")
        print("[4] Toggle name resolution")
        print("[5] Change log directory")
        print("[6] Change scan engine")
        print("[0] Back")
        choice = _prompt("Select an option", "0")
        if choice == "1":
            config.timeout = float(
                _prompt_int(
                    "Service timeout (ms)", int(config.timeout * 1000),
                    minimum=100, maximum=30000,
                )
            ) / 1000
        elif choice == "2":
            config.concurrency = _prompt_int(
                "TCP concurrency", config.concurrency, minimum=1, maximum=2000
            )
        elif choice == "3":
            config.fingerprint_concurrency = _prompt_int(
                "Fingerprint concurrency",
                config.fingerprint_concurrency,
                minimum=1,
                maximum=128,
            )
        elif choice == "4":
            enabled = not config.resolve_names
            config.resolve_names = enabled
            config.use_mdns = enabled
            config.use_netbios = enabled
            print(
                colorize(
                    f"  Name resolution {'enabled' if enabled else 'disabled'}.", "grey"
                )
            )
        elif choice == "5":
            raw = _prompt("Log directory", str(config.log_dir))
            if raw:
                config.log_dir = Path(raw).expanduser()
        elif choice == "6":
            raw = _prompt("Engine (native/nmap/auto)", config.engine).lower()
            if raw in {"native", "nmap", "auto"}:
                config.engine = raw
            else:
                print(colorize("  Unknown engine.", "yellow"))
        elif choice == "0":
            try:
                config.validate()
            except ValueError as exc:
                print(colorize(f"  {exc}", "red"))
                config.engine = "native"
            return config


def _interactive_network(config: ScanConfig) -> None:
    networks = detect_local_networks()
    if networks:
        print()
        print(colorize("Detected local networks", "bold"))
        print(
            table(
                ("#", "INTERFACE", "LOCAL IP", "NETWORK", "GATEWAY"),
                [
                    (
                        index,
                        network.interface,
                        network.local_ip,
                        network.cidr,
                        network.gateway or "-",
                    )
                    for index, network in enumerate(networks, start=1)
                ],
            )
        )
        default_target = networks[0].cidr
        print()
        print("Enter a number to select a network, or type a CIDR/IP/range.")
    else:
        default_target = ""
        print(colorize("No local IPv4 network detected.", "yellow"))
    target = _prompt("Target", default_target or None)
    if not target:
        print(colorize("No target provided.", "yellow"))
        return
    if target.isdigit() and networks and 1 <= int(target) <= len(networks):
        target = networks[int(target) - 1].cidr
    quick = _prompt_yes_no("Scan common ports on every discovered device?", default=True)
    scan_config = config.with_overrides(quick_port_scan=quick)
    print()
    print(colorize(f"Scanning {target}…", "cyan"))
    scanner = NetworkScanner(scan_config, progress=_interactive_progress)
    try:
        result = scanner.scan(target)
    except ScanError as exc:
        print(colorize(f"error: {exc}", "red"))
        return
    _finish_scan(result, scan_config, interactive=True)


def _interactive_host(config: ScanConfig) -> None:
    target = _prompt("Target IP or hostname")
    if not target:
        print(colorize("No target provided.", "yellow"))
        return
    print()
    print(colorize("Port selection", "bold"))
    print("[1] Quick      (~50 common ports)")
    print("[2] Common     (curated well-known ports)")
    print("[3] Web        (HTTP/HTTPS ports)")
    print("[4] Database   (database and cache ports)")
    print("[5] Full       (all 65535 TCP ports, slow)")
    print("[6] Custom     (for example: 1-1024,3306,8080)")
    choice = _prompt("Select a port set", "2")
    preset_map = {"1": "quick", "2": "common", "3": "web", "4": "database", "5": "full"}
    try:
        if choice in preset_map:
            ports = list(PORT_PRESETS[preset_map[choice]])
        elif choice == "6":
            raw = _prompt("Ports", "1-1024")
            ports = parse_port_spec(raw)
        else:
            print(colorize("Unknown selection; using common ports.", "yellow"))
            ports = list(config.default_ports)
    except TargetError as exc:
        print(colorize(f"error: {exc}", "red"))
        return

    udp = _prompt_yes_no("Probe UDP services too?", default=False)
    os_detection = _prompt_yes_no(
        "Attempt OS detection with nmap? (requires nmap and root)", default=False
    )
    scan_config = config.with_overrides(udp=udp, os_detection=os_detection)
    print()
    print(
        colorize(
            f"Scanning {target} ({len(ports)} TCP port(s)"
            + (", UDP enabled" if udp else "")
            + ")…",
            "cyan",
        )
    )
    scanner = HostScanner(scan_config, progress=_interactive_progress)
    try:
        result = scanner.scan(target, ports=ports)
    except ScanError as exc:
        print(colorize(f"error: {exc}", "red"))
        return
    _finish_scan(result, scan_config, interactive=True)


def _interactive_progress(message: str) -> None:
    print(colorize(f"  · {message}", "grey"), flush=True)


def _interactive_update_oui() -> None:
    print()
    print("Downloading the IEEE OUI registry…")
    try:
        path, count = download_oui_database()
    except RuntimeError as exc:
        print(colorize(f"error: {exc}", "red"))
        return
    print(colorize(f"Saved {count} vendor prefixes to {path}", "green"))
    print(f"Database in use: {get_oui_database().source_description}")
    print(f"Cache path: {cache_path()}")


def interactive_menu(
    config: ScanConfig | None = None,
    *,
    no_color: bool = False,
) -> int:
    """Run the numbered interactive menu until the user exits.

    Args:
        config: Initial configuration.  Defaults to environment settings.
        no_color: Force plain output even on a terminal.
    """
    config = config or ScanConfig.from_environment()
    color = (
        not no_color
        and not bool(os.environ.get("NO_COLOR"))
        and sys.stdout.isatty()
    )
    configure_color(color)
    setup_logging(config.log_dir, verbose=config.verbose)
    print_banner(__version__, color=color)

    while True:
        print()
        print(colorize("Main menu", "bold"))
        print("  [1] Scan the local network (discover all devices)")
        print("  [2] Scan a host (ports, services, TLS/HTTP metadata)")
        print("  [3] Show interfaces and local networks")
        print("  [4] Settings")
        print("  [5] Update MAC vendor database (IEEE OUI)")
        print("  [0] Exit")
        try:
            choice = _prompt("Select an option", "1")
        except KeyboardInterrupt:
            print()
            return EXIT_OK
        try:
            if choice == "1":
                _interactive_network(config)
            elif choice == "2":
                _interactive_host(config)
            elif choice == "3":
                _command_interfaces(argparse.Namespace(no_color=no_color))
            elif choice == "4":
                config = _settings_menu(config)
                setup_logging(config.log_dir, verbose=config.verbose)
            elif choice == "5":
                _interactive_update_oui()
            elif choice in {"0", "q", "quit", "exit"}:
                print("Goodbye.")
                return EXIT_OK
            else:
                print(colorize("Unknown option.", "yellow"))
        except KeyboardInterrupt:
            print()
            print(colorize("Interrupted; returning to the menu.", "yellow"))
        except Exception as exc:  # keep the menu alive on unexpected errors
            logger.exception("interactive action failed")
            print(colorize(f"Unexpected error: {exc}", "red"))


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main(argv: Sequence[str] | None = None) -> int:
    """Program entry point. Returns a process exit code."""
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command is None:
        if sys.stdin.isatty() and sys.stdout.isatty():
            return interactive_menu(ScanConfig.from_environment())
        parser.print_help()
        return EXIT_USAGE
    handler = getattr(args, "handler", None)
    if handler is None:  # pragma: no cover - argparse guarantees a handler
        parser.print_help()
        return EXIT_USAGE
    try:
        return int(handler(args))
    except KeyboardInterrupt:
        print(colorize("\nInterrupted.", "yellow"), file=sys.stderr)
        return EXIT_INTERRUPTED
    except (TargetError, ValueError) as exc:
        print(colorize(f"error: {exc}", "red"), file=sys.stderr)
        return EXIT_USAGE
    except Exception as exc:  # pragma: no cover - final safety net
        logger.exception("command failed")
        print(colorize(f"unexpected error: {exc}", "red"), file=sys.stderr)
        return EXIT_ERROR
