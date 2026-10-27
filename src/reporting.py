"""Report generation: human readable ``.log`` and machine readable ``.json``.

Every scan writes both files.  The text report is designed to be readable in
an editor or attached to an audit note; the JSON document preserves the full
data model for automation.
"""

from __future__ import annotations

import csv
import io
import json
import os
import re
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Sequence

from .constants import APP_NAME
from .diffing import DiffError, load_report
from .models import HostInfo, HostScanResult, NetworkScanResult, ServiceInfo
from .utils import (
    colorize,
    format_duration,
    sanitize_filename,
    strip_ansi,
    timestamp_slug,
    unique,
)

__all__ = [
    "ReportPaths",
    "export_report",
    "load_result",
    "render_console_host",
    "render_console_network",
    "render_csv",
    "render_export",
    "render_host_report",
    "render_network_report",
    "render_report",
    "write_reports",
]

_WIDTH = 100
_SEPARATOR = "=" * _WIDTH
_SUBSEPARATOR = "-" * _WIDTH
_CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


@dataclass(slots=True)
class ReportPaths:
    """Paths written for one scan.

    ``csv`` is only set when CSV export was explicitly requested.
    """

    text: Path
    json: Path
    csv: Path | None = None


# ---------------------------------------------------------------------------
# Sanitisation / formatting helpers
# ---------------------------------------------------------------------------

def _safe(value: Any) -> str:
    """Make untrusted device strings safe for text files and terminals."""
    if value is None:
        return ""
    text = _CONTROL_RE.sub("", strip_ansi(str(value)))
    return text.replace("\r\n", "\n").replace("\r", "\n")


def _one_line(value: Any, limit: int = 0) -> str:
    text = re.sub(r"\s+", " ", _safe(value)).strip()
    if limit and len(text) > limit:
        text = text[: limit - 1] + "…"
    return text


def _value(label: str, value: Any, indent: int = 0) -> str:
    text = _one_line(value)
    return f"{' ' * indent}{label:<17}: {text}" if text else ""


def _banner_block(banner: str | None, indent: int = 4, max_lines: int = 12) -> list[str]:
    if not banner:
        return []
    lines = [line.rstrip() for line in _safe(banner).splitlines()]
    lines = [line for line in lines if line.strip()]
    if len(lines) > max_lines:
        lines = lines[:max_lines] + [f"... ({len(lines) - max_lines} more line(s))"]
    return [f"{' ' * indent}{line[:180]}" for line in lines]


def _service_line(service: ServiceInfo) -> str:
    details = " ".join(
        part for part in (service.product or "", service.version or "") if part
    ).strip()
    label = service.service or "unknown"
    if details:
        label = f"{label} ({details})"
    return f"{service.port}/{service.protocol}  {label}"


def _tls_lines(service: ServiceInfo, indent: int = 6) -> list[str]:
    tls = service.tls
    if not tls:
        return []
    lines = [f"{' ' * indent}TLS:".rstrip()]
    for label, value in (
        ("Version", tls.version),
        ("Cipher", tls.cipher),
        ("Subject", tls.subject),
        ("Issuer", tls.issuer),
        ("Valid from", tls.not_before),
        ("Valid until", tls.not_after),
        ("Serial", tls.serial_number),
        ("SHA-256", tls.sha256_fingerprint),
    ):
        text = _one_line(value)
        if text:
            lines.append(f"{' ' * (indent + 2)}{label:<12}: {text}")
    if tls.days_remaining is not None:
        validity = (
            f"EXPIRED {-tls.days_remaining} day(s) ago"
            if tls.days_remaining < 0
            else f"{tls.days_remaining} day(s) remaining"
        )
        lines.append(f"{' ' * (indent + 2)}{'Validity':<12}: {validity}")
    if tls.self_signed is not None:
        lines.append(
            f"{' ' * (indent + 2)}{'Self-signed':<12}: {'yes' if tls.self_signed else 'no'}"
        )
    if tls.san:
        lines.append(f"{' ' * (indent + 2)}{'SAN':<12}: {', '.join(tls.san[:20])}")
    return lines


def _http_lines(service: ServiceInfo, indent: int = 6) -> list[str]:
    http = service.http
    if not http:
        return []
    lines = [f"{' ' * indent}HTTP metadata:"]
    for label, value in (
        ("Status", f"{http.status_code or '?'} {http.reason or ''}".strip()),
        ("Server", http.server),
        ("X-Powered-By", http.powered_by),
        ("Title", http.title),
        ("Location", http.location),
    ):
        text = _one_line(value)
        if text:
            lines.append(f"{' ' * (indent + 2)}{label:<12}: {text}")
    if http.headers:
        lines.append(f"{' ' * (indent + 2)}Headers:")
        for header in sorted(http.headers)[:30]:
            value = _one_line(http.headers[header], 300)
            lines.append(f"{' ' * (indent + 4)}{header}: {value}")
    return lines


def _device_summary(host: HostInfo) -> str:
    parts = [
        host.vendor or "",
        host.device_type or "",
        host.os_guess or "",
    ]
    return " / ".join(part for part in parts if part)


def _host_header(host: HostInfo, index: int) -> str:
    name = _one_line(host.display_name)
    suffix = f" ({name})" if name and name != host.ip else ""
    return f"[{index}] {host.ip}{suffix}"


# ---------------------------------------------------------------------------
# Network report
# ---------------------------------------------------------------------------

def render_network_report(result: NetworkScanResult) -> str:
    """Render a complete network scan report as plain text."""
    lines: list[str] = [
        _SEPARATOR,
        " NET SPECTRE - NETWORK DISCOVERY REPORT",
        _SEPARATOR,
        _value("Scan ID", result.scan_id),
        _value("Tool version", result.tool_version),
        _value("Started (UTC)", result.started_at),
        _value("Finished (UTC)", result.finished_at),
        _value("Duration", format_duration(result.duration_s)),
        _value("Interface", result.interface),
        _value("Local IP", result.local_ip),
        _value("Gateway", result.gateway),
        _value("Network", result.network),
        _value("Targets scanned", result.targets_scanned),
        _value("Hosts up", result.hosts_up),
        _value(
            "Services found",
            sum(len(host.services) for host in result.hosts),
        ),
        "",
    ]
    config = result.config or {}
    if config:
        lines.append("Configuration:")
        for key in sorted(config):
            value = config[key]
            if isinstance(value, list):
                if len(value) > 30:
                    value = f"{len(value)} items"
                else:
                    value = ", ".join(str(item) for item in value)
            lines.append(f"  {key:<24}: {_one_line(value)}")
        lines.append("")
    lines.extend([_SUBSEPARATOR, "DEVICES", _SUBSEPARATOR])
    if not result.hosts:
        lines.append("No devices were discovered.")
    else:
        header = f"{'IP':<16} {'MAC':<18} {'Vendor':<24} {'Hostname':<24} {'Type':<22} P"
        lines.append(header)
        lines.append("-" * len(header))
        for host in result.hosts:
            ports = ",".join(str(port) for port in host.open_ports)
            if len(ports) > 24:
                ports = ports[:23] + "…"
            lines.append(
                f"{host.ip:<16} {(host.mac or '-'):<18} "
                f"{_one_line(host.vendor or '-', 24):<24} "
                f"{_one_line(host.display_name, 24):<24} "
                f"{_one_line(host.device_type or '-', 22):<22} "
                f"{len(host.open_ports) or '-'}"
            )
            if ports:
                lines.append(f"{'':<16} ports: {ports}")
        lines.append("")
        lines.extend([_SUBSEPARATOR, "HOST DETAILS", _SUBSEPARATOR, ""])
        for index, host in enumerate(result.hosts, start=1):
            lines.extend(_render_host_details(host, index, gateway=result.gateway))
            lines.append("")

    lines.extend(_render_warnings(result.warnings))
    lines.extend(
        [
            _SEPARATOR,
            f" Report generated by Net Spectre v{result.tool_version}",
            f" Generated at {datetime.now().astimezone().isoformat(timespec='seconds')}",
            _SEPARATOR,
        ]
    )
    return "\n".join(line for line in lines if line is not None) + "\n"


def _render_host_details(host: HostInfo, index: int, *, gateway: str | None) -> list[str]:
    lines = [_host_header(host, index)]
    for label, value in (
        ("Status", host.status),
        ("MAC", host.mac),
        ("Vendor", host.vendor),
        ("Hostname", host.hostname),
        ("mDNS name", host.mdns_name),
        ("NetBIOS name", host.netbios_name),
        ("Device type", host.device_type),
        ("OS guess", host.os_guess),
        ("Latency", f"{host.latency_ms:.2f} ms" if host.latency_ms is not None else None),
        ("TTL", host.ttl),
        ("Gateway", "yes" if host.is_gateway or host.ip == gateway else None),
        ("Sources", ", ".join(host.sources)),
        ("Open ports", ", ".join(str(port) for port in host.open_ports) or "none"),
    ):
        text = _value(label, value, indent=4)
        if text:
            lines.append(text)
    if host.evidence:
        lines.append("    Evidence:")
        for item in host.evidence:
            lines.append(f"      - {_one_line(item, 300)}")
    if host.services:
        lines.append("    Services:")
        for service in host.services:
            lines.append(f"      {_service_line(service)}")
            if service.extra:
                lines.append(f"          Details    : {_one_line(service.extra, 400)}")
            if service.confidence:
                lines.append(f"          Confidence : {service.confidence}%")
            if service.response_ms is not None:
                lines.append(f"          Response   : {service.response_ms:.2f} ms")
            lines.extend(_tls_lines(service, indent=10))
            lines.extend(_http_lines(service, indent=10))
            banner_lines = _banner_block(service.banner, indent=10, max_lines=8)
            if banner_lines:
                lines.append("          Banner:")
                lines.extend(banner_lines)
    if host.notes:
        lines.append("    Notes:")
        for note in host.notes:
            lines.append(f"      - {_one_line(note, 300)}")
    return lines


def _render_warnings(warnings: Sequence[str]) -> list[str]:
    if not warnings:
        return []
    lines = [_SUBSEPARATOR, "WARNINGS", _SUBSEPARATOR]
    for warning in unique(warnings):
        lines.append(f"  ! {_one_line(warning, 400)}")
    lines.append("")
    return lines


# ---------------------------------------------------------------------------
# Host report
# ---------------------------------------------------------------------------

def render_host_report(result: HostScanResult) -> str:
    """Render a complete single host scan report as plain text."""
    lines: list[str] = [
        _SEPARATOR,
        " NET SPECTRE - HOST PORT & SERVICE REPORT",
        _SEPARATOR,
        _value("Scan ID", result.scan_id),
        _value("Tool version", result.tool_version),
        _value("Engine", result.engine),
        _value("Started (UTC)", result.started_at),
        _value("Finished (UTC)", result.finished_at),
        _value("Duration", format_duration(result.duration_s)),
        _value("Target", result.target),
        _value("Resolved IP", result.resolved_ip),
        _value("Hostname", result.hostname),
        _value("MAC", result.mac),
        _value("Vendor", result.vendor),
        _value("Device type", result.device_type),
        _value("OS guess", result.os_guess),
        _value("Latency", f"{result.latency_ms:.2f} ms" if result.latency_ms is not None else None),
        _value("TTL", result.ttl),
        _value("Gateway", "yes" if result.is_gateway else None),
        _value("Ports scanned", result.ports_scanned),
        _value("Open ports", len(result.services)),
        "",
        _SUBSEPARATOR,
        "OPEN SERVICES",
        _SUBSEPARATOR,
    ]
    if not result.services:
        lines.append("No open services were detected on the scanned ports.")
    else:
        header = (
            f"{'PORT':<11} {'SERVICE':<18} {'PRODUCT / VERSION':<36} "
            f"{'CONF':<5} {'METHOD':<12} RESPONSE"
        )
        lines.append(header)
        lines.append("-" * len(header))
        for service in result.services:
            product = " ".join(
                part for part in (service.product or "", service.version or "") if part
            ).strip()
            response = (
                f"{service.response_ms:.1f} ms" if service.response_ms is not None else "-"
            )
            lines.append(
                f"{str(service.port) + '/' + service.protocol:<11} "
                f"{_one_line(service.service, 18):<18} "
                f"{_one_line(product, 36):<36} "
                f"{str(service.confidence or '-') + '%':<5} "
                f"{_one_line(service.method, 12):<12} {response}"
            )
        lines.append("")
        lines.append(_SUBSEPARATOR)
        lines.append("SERVICE DETAILS")
        lines.append(_SUBSEPARATOR)
        for service in result.services:
            lines.append("")
            lines.append(
                f"[{service.port}/{service.protocol}] {service.service or 'unknown'}"
            )
            for label, value in (
                ("State", service.state),
                ("Product", service.product),
                ("Version", service.version),
                ("Details", service.extra),
                ("Confidence", f"{service.confidence}%" if service.confidence else None),
                ("Method", service.method),
                (
                    "Response",
                    f"{service.response_ms:.2f} ms" if service.response_ms is not None else None,
                ),
            ):
                text = _value(label, value, indent=2)
                if text:
                    lines.append(text)
            lines.extend(_tls_lines(service, indent=2))
            lines.extend(_http_lines(service, indent=2))
            banner_lines = _banner_block(service.banner, indent=4)
            if banner_lines:
                lines.append("  Banner:")
                lines.extend(banner_lines)

    config = result.config or {}
    if config:
        lines.extend(["", _SUBSEPARATOR, "CONFIGURATION", _SUBSEPARATOR])
        for key in sorted(config):
            value = config[key]
            if isinstance(value, list):
                value = f"{len(value)} items" if len(value) > 30 else ", ".join(map(str, value))
            lines.append(f"  {key:<24}: {_one_line(value)}")

    lines.extend(_render_warnings(result.warnings))
    lines.extend(
        [
            _SEPARATOR,
            f" Report generated by Net Spectre v{result.tool_version}",
            f" Generated at {datetime.now().astimezone().isoformat(timespec='seconds')}",
            _SEPARATOR,
        ]
    )
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# Console summaries
# ---------------------------------------------------------------------------

def render_console_network(result: NetworkScanResult) -> str:
    """Short coloured summary for interactive use."""
    lines = [
        "",
        colorize(f"Discovered {result.hosts_up} device(s)", "bold", "green")
        + colorize(
            f" in {format_duration(result.duration_s)} "
            f"({result.targets_scanned} targets scanned)",
            "grey",
        ),
        "",
    ]
    if result.hosts:
        header = f"{'IP':<16} {'HOSTNAME':<26} {'VENDOR':<24} {'TYPE':<24} PORTS"
        lines.append(colorize(header, "bold"))
        lines.append("-" * min(_WIDTH, len(header) + 20))
        for host in result.hosts:
            ports = ",".join(str(port) for port in host.open_ports)
            if len(ports) > 30:
                ports = ports[:29] + "…"
            lines.append(
                f"{host.ip:<16} {_one_line(host.display_name, 26):<26} "
                f"{_one_line(host.vendor or '-', 24):<24} "
                f"{_one_line(host.device_type or '-', 24):<24} {ports or '-'}"
            )
    else:
        lines.append(colorize("No devices responded.", "yellow"))
    if result.warnings:
        lines.append("")
        for warning in unique(result.warnings):
            lines.append(colorize(f"! {_one_line(warning, 160)}", "yellow"))
    return "\n".join(lines)


def render_console_host(result: HostScanResult) -> str:
    """Short coloured summary of a host scan."""
    title = f"{result.resolved_ip}"
    if result.hostname and result.hostname != result.resolved_ip:
        title += f" ({result.hostname})"
    lines = [
        "",
        colorize(title, "bold", "cyan")
        + colorize(
            f"  {len(result.services)} open port(s) in {format_duration(result.duration_s)}",
            "grey",
        ),
    ]
    metadata = _device_summary_from_result(result)
    if metadata:
        lines.append(colorize(metadata, "grey"))
    lines.append("")
    if result.services:
        header = f"{'PORT':<12} {'SERVICE':<20} {'PRODUCT / VERSION':<38} CONF"
        lines.append(colorize(header, "bold"))
        lines.append("-" * len(header))
        for service in result.services:
            product = " ".join(
                part for part in (service.product or "", service.version or "") if part
            ).strip() or "-"
            confidence = f"{service.confidence}%" if service.confidence else "-"
            color = "green" if service.confidence >= 80 else "yellow"
            lines.append(
                f"{str(service.port) + '/' + service.protocol:<12} "
                f"{_one_line(service.service, 20):<20} "
                f"{_one_line(product, 38):<38} "
                + colorize(f"{confidence:<5}", color)
            )
    else:
        lines.append(colorize("No open ports were found.", "yellow"))
    if result.warnings:
        lines.append("")
        for warning in unique(result.warnings):
            lines.append(colorize(f"! {_one_line(warning, 160)}", "yellow"))
    return "\n".join(lines)


def _device_summary_from_result(result: HostScanResult) -> str:
    parts = [result.vendor, result.device_type, result.os_guess]
    text = " / ".join(part for part in parts if part)
    if result.mac:
        text = f"{result.mac} {text}".strip()
    return text


# ---------------------------------------------------------------------------
# CSV export
# ---------------------------------------------------------------------------

_CSV_COLUMNS = (
    "report",
    "scan_id",
    "ip",
    "mac",
    "vendor",
    "hostname",
    "device_type",
    "os_guess",
    "latency_ms",
    "ttl",
    "gateway",
    "port",
    "protocol",
    "state",
    "service",
    "product",
    "version",
    "confidence",
    "method",
    "response_ms",
    "tls_subject",
    "tls_issuer",
    "tls_not_after",
    "http_status",
    "http_title",
    "notes",
)


def _csv_text(value: Any) -> str:
    """Normalize a value for a single-line CSV field."""
    if value is None:
        return ""
    return _one_line(value, 500)


def _csv_service_fields(service: ServiceInfo | None) -> dict[str, Any]:
    if service is None:
        return {}
    tls = service.tls
    http = service.http
    return {
        "port": service.port,
        "protocol": service.protocol,
        "state": service.state,
        "service": service.service,
        "product": service.product,
        "version": service.version,
        "confidence": service.confidence if service.confidence else "",
        "method": service.method,
        "response_ms": (
            f"{service.response_ms:.2f}" if service.response_ms is not None else ""
        ),
        "tls_subject": tls.subject if tls else "",
        "tls_issuer": tls.issuer if tls else "",
        "tls_not_after": tls.not_after if tls else "",
        "http_status": http.status_code if http and http.status_code is not None else "",
        "http_title": http.title if http else "",
    }


def _csv_rows(result: NetworkScanResult | HostScanResult) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    if isinstance(result, NetworkScanResult):
        for host in result.hosts:
            base = {
                "report": "network",
                "scan_id": result.scan_id,
                "ip": host.ip,
                "mac": host.mac,
                "vendor": host.vendor,
                "hostname": host.display_name,
                "device_type": host.device_type,
                "os_guess": host.os_guess,
                "latency_ms": (
                    f"{host.latency_ms:.2f}" if host.latency_ms is not None else ""
                ),
                "ttl": host.ttl,
                "gateway": "yes" if host.is_gateway else "",
                "notes": "; ".join(unique(host.notes + host.evidence)),
            }
            if host.services:
                for service in host.services:
                    rows.append({**base, **_csv_service_fields(service)})
            else:
                rows.append(base)
        return rows

    base = {
        "report": "host",
        "scan_id": result.scan_id,
        "ip": result.resolved_ip,
        "mac": result.mac,
        "vendor": result.vendor,
        "hostname": result.hostname or result.target,
        "device_type": result.device_type,
        "os_guess": result.os_guess,
        "latency_ms": (
            f"{result.latency_ms:.2f}" if result.latency_ms is not None else ""
        ),
        "ttl": result.ttl,
        "gateway": "yes" if result.is_gateway else "",
        "notes": "; ".join(result.warnings),
    }
    if result.services:
        for service in result.services:
            rows.append({**base, **_csv_service_fields(service)})
    else:
        rows.append(base)
    return rows


def render_csv(result: NetworkScanResult | HostScanResult) -> str:
    """Render a scan result as a single flat CSV table.

    One row is emitted per open service (or per host when no service was
    found), which makes the export easy to load into a spreadsheet or a
    database without a second normalization step.
    """
    buffer = io.StringIO()
    writer = csv.DictWriter(
        buffer,
        fieldnames=list(_CSV_COLUMNS),
        extrasaction="ignore",
        lineterminator="\n",
    )
    writer.writeheader()
    for row in _csv_rows(result):
        writer.writerow({column: _csv_text(row.get(column)) for column in _CSV_COLUMNS})
    return buffer.getvalue()


# ---------------------------------------------------------------------------
# File writing
# ---------------------------------------------------------------------------

def _unique_base(log_dir: Path, base: str) -> Path:
    candidate = base
    counter = 2
    while any(
        (log_dir / f"{candidate}{suffix}").exists()
        for suffix in (".log", ".json", ".csv")
    ):
        candidate = f"{base}_{counter}"
        counter += 1
    return log_dir / candidate


def _atomic_write(path: Path, content: str) -> None:
    """Write ``content`` atomically, removing the temporary file on failure."""
    temporary = path.with_suffix(path.suffix + ".tmp")
    try:
        with temporary.open("w", encoding="utf-8", newline="\n") as handle:
            handle.write(content)
            handle.flush()
            try:
                os.fsync(handle.fileno())
            except OSError:
                pass
        temporary.replace(path)
    finally:
        if temporary.exists():
            try:
                temporary.unlink()
            except OSError:
                pass


def write_reports(
    result: NetworkScanResult | HostScanResult,
    log_dir: Path | str = Path("logs"),
    *,
    csv_export: bool = False,
) -> ReportPaths:
    """Write the reports for a scan result.

    The human readable ``.log`` and machine readable ``.json`` documents are
    always written.  When ``csv_export`` is true a flat ``.csv`` table is
    written as well.  Existing files are never overwritten; a numeric suffix
    is added when necessary.
    """
    directory = Path(log_dir).expanduser()
    directory.mkdir(parents=True, exist_ok=True)

    if isinstance(result, NetworkScanResult):
        base_name = "network_scan"
        text = render_network_report(result)
    elif isinstance(result, HostScanResult):
        base_name = "host_scan_" + sanitize_filename(result.resolved_ip).replace(".", "_")
        text = render_host_report(result)
    else:  # pragma: no cover - defensive
        raise TypeError(f"unsupported result type: {type(result)!r}")

    try:
        started = datetime.fromisoformat(result.started_at)
        suffix = started.strftime("%Y%m%d_%H%M%S")
    except (TypeError, ValueError):
        suffix = timestamp_slug()

    base = _unique_base(directory, f"{base_name}_{suffix}")
    text_path = base.with_name(f"{base.name}.log")
    json_path = base.with_name(f"{base.name}.json")

    _atomic_write(text_path, text)
    payload = {
        "generator": APP_NAME,
        "report_version": 1,
        "scan": result.to_dict(),
    }
    _atomic_write(
        json_path,
        json.dumps(payload, indent=2, ensure_ascii=False, sort_keys=False) + "\n",
    )
    csv_path = base.with_name(f"{base.name}.csv") if csv_export else None
    if csv_path is not None:
        _atomic_write(csv_path, render_csv(result))
    return ReportPaths(text=text_path, json=json_path, csv=csv_path)


# ---------------------------------------------------------------------------
# Offline export / reloading
# ---------------------------------------------------------------------------

_EXPORT_SUFFIXES = {"csv": ".csv", "text": ".txt"}


def _export_format(fmt: str) -> str:
    normalized = str(fmt).strip().lower()
    if normalized not in _EXPORT_SUFFIXES:
        choices = ", ".join(sorted(_EXPORT_SUFFIXES))
        raise ValueError(f"unknown export format {fmt!r} (choose from {choices})")
    return normalized


def load_result(path: Path | str) -> NetworkScanResult | HostScanResult:
    """Load a saved JSON report back into its typed result object.

    Both the wrapped envelope written by :func:`write_reports` and a bare scan
    object are accepted.  The result type is selected from the ``mode`` field
    (with a structural fallback for older reports).

    Raises:
        DiffError: when the file is missing, is not valid JSON, or does not
            look like a Net Spectre report.
    """
    source = Path(path).expanduser()
    scan = load_report(source)
    mode = str(scan.get("mode") or "").lower()
    is_host = mode == "host" or (
        "resolved_ip" in scan and not isinstance(scan.get("hosts"), list)
    )
    try:
        if is_host:
            return HostScanResult.from_dict(scan)
        return NetworkScanResult.from_dict(scan)
    except (TypeError, ValueError) as exc:  # pragma: no cover - defensive
        raise DiffError(f"cannot parse {source}: {exc}") from exc


def render_report(result: NetworkScanResult | HostScanResult) -> str:
    """Render either scan result as its human readable text report."""
    if isinstance(result, NetworkScanResult):
        return render_network_report(result)
    if isinstance(result, HostScanResult):
        return render_host_report(result)
    raise TypeError(f"unsupported result type: {type(result)!r}")


def render_export(source: Path | str, fmt: str = "csv") -> str:
    """Render a saved JSON report as ``csv`` or ``text`` without scanning."""
    normalized = _export_format(fmt)
    result = load_result(source)
    if normalized == "csv":
        return render_csv(result)
    return render_report(result)


def export_report(
    source: Path | str,
    fmt: str = "csv",
    destination: Path | str | None = None,
    *,
    force: bool = False,
) -> Path:
    """Convert a saved JSON report to ``csv`` or ``text`` on disk.

    Args:
        source: Existing JSON report written by a previous scan.
        fmt: ``csv`` or ``text``.
        destination: Output path.  Defaults to the source path with a
            ``.csv`` or ``.txt`` suffix.
        force: Overwrite ``destination`` when it already exists.

    Returns:
        The path that was written.

    Raises:
        DiffError: when ``source`` cannot be loaded.
        FileExistsError: when the destination exists and ``force`` is false.
        ValueError: for an unknown format or when the input would be
            overwritten by the output.
    """
    normalized = _export_format(fmt)
    source_path = Path(source).expanduser()
    if destination is None:
        target = source_path.with_suffix(_EXPORT_SUFFIXES[normalized])
    else:
        target = Path(destination).expanduser()
    if target.resolve() == source_path.resolve():
        raise ValueError("output path must differ from the input report")
    if target.exists() and not force:
        raise FileExistsError(
            f"{target} already exists (use --force to overwrite it)"
        )
    content = render_export(source_path, normalized)
    target.parent.mkdir(parents=True, exist_ok=True)
    _atomic_write(target, content)
    return target
