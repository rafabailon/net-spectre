"""Compare two Net Spectre JSON reports.

The ``diff`` command is useful to answer the operational question "what
changed on this network since the last audit?".  Reports are read from the
JSON documents written by :func:`src.reporting.write_reports`; the comparison
is purely structural and never touches the network.

Both network and host reports are supported.  Network reports contribute one
entry per discovered host; host reports contribute a single host.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping

from .utils import colorize, table

__all__ = [
    "DiffError",
    "HostDiff",
    "ScanDiff",
    "ServiceDiff",
    "diff_scans",
    "load_report",
    "render_diff",
]

#: Host fields compared when a host exists in both reports.
_HOST_FIELDS = (
    "hostname",
    "mac",
    "vendor",
    "device_type",
    "os_guess",
    "status",
    "is_gateway",
)


class DiffError(ValueError):
    """Raised when a report cannot be loaded or does not have the expected shape."""


@dataclass(slots=True)
class HostDiff:
    """A host that was added, removed or whose metadata changed."""

    ip: str
    change: str
    hostname: str | None = None
    fields: dict[str, tuple[Any, Any]] = field(default_factory=dict)


@dataclass(slots=True)
class ServiceDiff:
    """An open service that appeared, disappeared or changed."""

    ip: str
    port: int
    protocol: str
    change: str
    old: str | None = None
    new: str | None = None

    @property
    def key(self) -> str:
        return f"{self.ip}:{self.port}/{self.protocol}"


@dataclass(slots=True)
class ScanDiff:
    """Difference between two scan reports."""

    old_scan_id: str | None = None
    new_scan_id: str | None = None
    old_mode: str | None = None
    new_mode: str | None = None
    hosts_added: list[HostDiff] = field(default_factory=list)
    hosts_removed: list[HostDiff] = field(default_factory=list)
    hosts_changed: list[HostDiff] = field(default_factory=list)
    services_opened: list[ServiceDiff] = field(default_factory=list)
    services_closed: list[ServiceDiff] = field(default_factory=list)
    services_changed: list[ServiceDiff] = field(default_factory=list)
    warnings_added: list[str] = field(default_factory=list)
    warnings_removed: list[str] = field(default_factory=list)

    @property
    def change_count(self) -> int:
        return (
            len(self.hosts_added)
            + len(self.hosts_removed)
            + len(self.hosts_changed)
            + len(self.services_opened)
            + len(self.services_closed)
            + len(self.services_changed)
            + len(self.warnings_added)
            + len(self.warnings_removed)
        )

    @property
    def has_changes(self) -> bool:
        return self.change_count > 0

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON friendly representation."""
        return {
            "old_scan_id": self.old_scan_id,
            "new_scan_id": self.new_scan_id,
            "old_mode": self.old_mode,
            "new_mode": self.new_mode,
            "has_changes": self.has_changes,
            "change_count": self.change_count,
            "hosts": {
                "added": [
                    {"ip": item.ip, "hostname": item.hostname}
                    for item in self.hosts_added
                ],
                "removed": [
                    {"ip": item.ip, "hostname": item.hostname}
                    for item in self.hosts_removed
                ],
                "changed": [
                    {
                        "ip": item.ip,
                        "hostname": item.hostname,
                        "fields": {
                            key: {"old": old, "new": new}
                            for key, (old, new) in item.fields.items()
                        },
                    }
                    for item in self.hosts_changed
                ],
            },
            "services": {
                "opened": [
                    {
                        "ip": item.ip,
                        "port": item.port,
                        "protocol": item.protocol,
                        "service": item.new,
                    }
                    for item in self.services_opened
                ],
                "closed": [
                    {
                        "ip": item.ip,
                        "port": item.port,
                        "protocol": item.protocol,
                        "service": item.old,
                    }
                    for item in self.services_closed
                ],
                "changed": [
                    {
                        "ip": item.ip,
                        "port": item.port,
                        "protocol": item.protocol,
                        "old": item.old,
                        "new": item.new,
                    }
                    for item in self.services_changed
                ],
            },
            "warnings": {
                "added": list(self.warnings_added),
                "removed": list(self.warnings_removed),
            },
        }


# ---------------------------------------------------------------------------
# Loading / normalization
# ---------------------------------------------------------------------------

def load_report(path: Path | str) -> dict[str, Any]:
    """Load a report JSON document and return its ``scan`` object.

    Both the wrapped format written by Net Spectre (``{"generator": ...,
    "scan": {...}}``) and a bare scan object are accepted.

    Raises:
        DiffError: when the file is missing, invalid JSON or not a scan report.
    """
    report_path = Path(path).expanduser()
    try:
        raw = report_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise DiffError(f"cannot read {report_path}: {exc}") from exc
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise DiffError(f"invalid JSON in {report_path}: {exc}") from exc
    if not isinstance(payload, dict):
        raise DiffError(f"{report_path} does not contain a JSON object")
    scan = payload.get("scan", payload)
    if not isinstance(scan, dict):
        raise DiffError(f"{report_path} does not contain a scan report")
    if "hosts" not in scan and "resolved_ip" not in scan:
        raise DiffError(
            f"{report_path} is not a Net Spectre network or host report"
        )
    return scan


def _host_records(scan: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    records: dict[str, dict[str, Any]] = {}
    hosts = scan.get("hosts")
    if isinstance(hosts, list):
        for host in hosts:
            if not isinstance(host, Mapping):
                continue
            ip = host.get("ip")
            if ip:
                records[str(ip)] = dict(host)
        return records
    ip = scan.get("resolved_ip")
    if ip:
        records[str(ip)] = dict(scan)
    return records


def _host_name(host: Mapping[str, Any]) -> str | None:
    for key in ("hostname", "mdns_name", "netbios_name", "target"):
        value = host.get(key)
        if value:
            return str(value)
    return None


def _service_label(service: Mapping[str, Any] | None) -> str | None:
    if not service:
        return None
    name = str(service.get("service") or "unknown")
    details = " ".join(
        str(part)
        for part in (service.get("product"), service.get("version"))
        if part
    )
    return f"{name} ({details})" if details else name


def _services(host: Mapping[str, Any]) -> dict[tuple[int, str], Mapping[str, Any]]:
    services: dict[tuple[int, str], Mapping[str, Any]] = {}
    raw = host.get("services")
    if not isinstance(raw, list):
        return services
    for service in raw:
        if not isinstance(service, Mapping) or service.get("state", "open") != "open":
            continue
        try:
            port = int(service.get("port", 0))
        except (TypeError, ValueError):
            continue
        if not 1 <= port <= 65535:
            continue
        protocol = str(service.get("protocol") or "tcp")
        services[(port, protocol)] = service
    return services


def _different(old: Any, new: Any) -> bool:
    """Compare values treating ``None`` and empty strings as equivalent."""
    if old in (None, "") and new in (None, ""):
        return False
    return old != new


# ---------------------------------------------------------------------------
# Comparison
# ---------------------------------------------------------------------------

def diff_scans(
    old_scan: Mapping[str, Any],
    new_scan: Mapping[str, Any],
) -> ScanDiff:
    """Compare two normalized scan dictionaries.

    Args:
        old_scan: The baseline scan (``payload["scan"]``).
        new_scan: The newer scan.

    Returns:
        A :class:`ScanDiff` describing hosts, services and warnings that were
        added, removed or changed.
    """
    result = ScanDiff(
        old_scan_id=old_scan.get("scan_id"),
        new_scan_id=new_scan.get("scan_id"),
        old_mode=old_scan.get("mode"),
        new_mode=new_scan.get("mode"),
    )
    old_hosts = _host_records(old_scan)
    new_hosts = _host_records(new_scan)

    for ip in sorted(set(old_hosts) - set(new_hosts)):
        result.hosts_removed.append(
            HostDiff(ip=ip, change="removed", hostname=_host_name(old_hosts[ip]))
        )
    for ip in sorted(set(new_hosts) - set(old_hosts)):
        result.hosts_added.append(
            HostDiff(ip=ip, change="added", hostname=_host_name(new_hosts[ip]))
        )

    for ip in sorted(set(old_hosts) & set(new_hosts)):
        old_host, new_host = old_hosts[ip], new_hosts[ip]
        fields: dict[str, tuple[Any, Any]] = {}
        for name in _HOST_FIELDS:
            old_value, new_value = old_host.get(name), new_host.get(name)
            if _different(old_value, new_value):
                fields[name] = (old_value, new_value)
        if fields:
            result.hosts_changed.append(
                HostDiff(
                    ip=ip,
                    change="changed",
                    hostname=_host_name(new_host) or _host_name(old_host),
                    fields=fields,
                )
            )

        old_services = _services(old_host)
        new_services = _services(new_host)
        for key in sorted(set(old_services) | set(new_services)):
            port, protocol = key
            old_service = old_services.get(key)
            new_service = new_services.get(key)
            if old_service is None:
                result.services_opened.append(
                    ServiceDiff(
                        ip=ip,
                        port=port,
                        protocol=protocol,
                        change="opened",
                        new=_service_label(new_service),
                    )
                )
            elif new_service is None:
                result.services_closed.append(
                    ServiceDiff(
                        ip=ip,
                        port=port,
                        protocol=protocol,
                        change="closed",
                        old=_service_label(old_service),
                    )
                )
            else:
                old_label = _service_label(old_service)
                new_label = _service_label(new_service)
                if old_label != new_label:
                    result.services_changed.append(
                        ServiceDiff(
                            ip=ip,
                            port=port,
                            protocol=protocol,
                            change="changed",
                            old=old_label,
                            new=new_label,
                        )
                    )

    old_warnings = set(str(item) for item in (old_scan.get("warnings") or []))
    new_warnings = set(str(item) for item in (new_scan.get("warnings") or []))
    result.warnings_added = sorted(new_warnings - old_warnings)
    result.warnings_removed = sorted(old_warnings - new_warnings)
    return result


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------

def render_diff(diff: ScanDiff) -> str:
    """Render a diff as readable text for the terminal."""
    lines: list[str] = [
        colorize("Net Spectre report diff", "bold"),
        f"  old: {diff.old_scan_id or '?'} ({diff.old_mode or 'unknown'})",
        f"  new: {diff.new_scan_id or '?'} ({diff.new_mode or 'unknown'})",
        "",
    ]

    if diff.hosts_added or diff.hosts_removed or diff.hosts_changed:
        rows: list[tuple[str, str, str]] = []
        for item in diff.hosts_added:
            rows.append(("+", item.ip, item.hostname or ""))
        for item in diff.hosts_removed:
            rows.append(("-", item.ip, item.hostname or ""))
        for item in diff.hosts_changed:
            details = ", ".join(
                f"{name}: {old or '-'} -> {new or '-'}"
                for name, (old, new) in item.fields.items()
            )
            rows.append(("~", item.ip, details))
        lines.append(colorize("Hosts", "bold"))
        lines.append(table(("", "IP", "DETAIL"), rows))
        lines.append("")
    else:
        lines.extend([colorize("Hosts", "bold"), "  no host changes", ""])

    service_rows: list[tuple[str, str, str]] = []
    for item in diff.services_opened:
        service_rows.append(("+", item.key, item.new or ""))
    for item in diff.services_closed:
        service_rows.append(("-", item.key, item.old or ""))
    for item in diff.services_changed:
        service_rows.append(
            ("~", item.key, f"{item.old or '-'} -> {item.new or '-'}")
        )
    lines.append(colorize("Services", "bold"))
    if service_rows:
        lines.append(table(("", "SERVICE", "DETAIL"), service_rows))
    else:
        lines.append("  no service changes")
    lines.append("")

    if diff.warnings_added or diff.warnings_removed:
        lines.append(colorize("Warnings", "bold"))
        for warning in diff.warnings_added:
            lines.append(f"  + {warning}")
        for warning in diff.warnings_removed:
            lines.append(f"  - {warning}")
        lines.append("")

    if diff.has_changes:
        lines.append(
            colorize(f"{diff.change_count} change(s) detected.", "yellow", "bold")
        )
    else:
        lines.append(colorize("No changes detected.", "green", "bold"))
    return "\n".join(lines)
