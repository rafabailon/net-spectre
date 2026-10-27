"""Typed data structures shared by scanners and report writers.

All models expose ``to_dict()`` so they can be serialized to JSON without a
custom encoder.  The structures are intentionally flat and string based for
long term compatibility of the JSON reports.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

__all__ = [
    "HttpInfo",
    "HostInfo",
    "HostScanResult",
    "NetworkScanResult",
    "ScanSummary",
    "ServiceInfo",
    "TlsCertificate",
]


def _clean(value: Any) -> Any:
    """Recursively convert dataclasses / containers to JSON friendly values."""
    if hasattr(value, "to_dict"):
        return value.to_dict()
    if isinstance(value, dict):
        return {str(key): _clean(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set, frozenset)):
        return [_clean(item) for item in value]
    return value


# ---------------------------------------------------------------------------
# Tolerant deserialization helpers
# ---------------------------------------------------------------------------

def _mapping(value: Any) -> dict[str, Any]:
    return dict(value) if isinstance(value, Mapping) else {}


def _text(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value)
    return text if text else None


def _integer(value: Any, default: int | None = None) -> int | None:
    if value is None or value == "":
        return default
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _number(value: Any, default: float | None = None) -> float | None:
    if value is None or value == "":
        return default
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _optional_bool(value: Any) -> bool | None:
    return value if isinstance(value, bool) else None


def _strings(value: Any) -> list[str]:
    if not isinstance(value, (list, tuple, set, frozenset)):
        return []
    return [str(item) for item in value if item is not None]


def _mappings(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, (list, tuple)):
        return []
    return [dict(item) for item in value if isinstance(item, Mapping)]


# ---------------------------------------------------------------------------
# Service level models
# ---------------------------------------------------------------------------

@dataclass(slots=True)
class TlsCertificate:
    """Details extracted from a X.509 certificate presented by a service."""

    subject: str | None = None
    issuer: str | None = None
    version: str | None = None
    cipher: str | None = None
    not_before: str | None = None
    not_after: str | None = None
    days_remaining: int | None = None
    expired: bool | None = None
    self_signed: bool | None = None
    serial_number: str | None = None
    sha256_fingerprint: str | None = None
    san: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "subject": self.subject,
            "issuer": self.issuer,
            "version": self.version,
            "cipher": self.cipher,
            "not_before": self.not_before,
            "not_after": self.not_after,
            "days_remaining": self.days_remaining,
            "expired": self.expired,
            "self_signed": self.self_signed,
            "serial_number": self.serial_number,
            "sha256_fingerprint": self.sha256_fingerprint,
            "san": list(self.san),
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "TlsCertificate":
        """Reconstruct a certificate from a JSON report entry."""
        return cls(
            subject=_text(data.get("subject")),
            issuer=_text(data.get("issuer")),
            version=_text(data.get("version")),
            cipher=_text(data.get("cipher")),
            not_before=_text(data.get("not_before")),
            not_after=_text(data.get("not_after")),
            days_remaining=_integer(data.get("days_remaining")),
            expired=_optional_bool(data.get("expired")),
            self_signed=_optional_bool(data.get("self_signed")),
            serial_number=_text(data.get("serial_number")),
            sha256_fingerprint=_text(data.get("sha256_fingerprint")),
            san=_strings(data.get("san")),
        )


@dataclass(slots=True)
class HttpInfo:
    """Metadata obtained from an HTTP response."""

    scheme: str = "http"
    status_code: int | None = None
    reason: str | None = None
    server: str | None = None
    powered_by: str | None = None
    title: str | None = None
    location: str | None = None
    headers: dict[str, str] = field(default_factory=dict)
    body_preview: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "scheme": self.scheme,
            "status_code": self.status_code,
            "reason": self.reason,
            "server": self.server,
            "powered_by": self.powered_by,
            "title": self.title,
            "location": self.location,
            "headers": dict(self.headers),
            "body_preview": self.body_preview,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "HttpInfo":
        """Reconstruct HTTP metadata from a JSON report entry."""
        headers = {
            str(key): str(value)
            for key, value in _mapping(data.get("headers")).items()
            if value is not None
        }
        return cls(
            scheme=_text(data.get("scheme")) or "http",
            status_code=_integer(data.get("status_code")),
            reason=_text(data.get("reason")),
            server=_text(data.get("server")),
            powered_by=_text(data.get("powered_by")),
            title=_text(data.get("title")),
            location=_text(data.get("location")),
            headers=headers,
            body_preview=_text(data.get("body_preview")),
        )


@dataclass(slots=True)
class ServiceInfo:
    """A port that responded, enriched with fingerprint information."""

    port: int
    protocol: str = "tcp"
    state: str = "open"
    service: str = "unknown"
    product: str | None = None
    version: str | None = None
    extra: str | None = None
    banner: str | None = None
    confidence: int = 0
    method: str = "tcp-connect"
    response_ms: float | None = None
    tls: TlsCertificate | None = None
    http: HttpInfo | None = None

    @property
    def label(self) -> str:
        """Short human readable label such as ``http (nginx 1.24.0)``."""
        label = self.service or "unknown"
        details = " ".join(part for part in (self.product, self.version) if part)
        return f"{label} ({details})" if details else label

    def to_dict(self) -> dict[str, Any]:
        return {
            "port": self.port,
            "protocol": self.protocol,
            "state": self.state,
            "service": self.service,
            "product": self.product,
            "version": self.version,
            "extra": self.extra,
            "banner": self.banner,
            "confidence": self.confidence,
            "method": self.method,
            "response_ms": round(self.response_ms, 2) if self.response_ms is not None else None,
            "tls": self.tls.to_dict() if self.tls else None,
            "http": self.http.to_dict() if self.http else None,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "ServiceInfo":
        """Reconstruct a service entry from a JSON report object.

        Raises:
            ValueError: when the entry has no usable port number.
        """
        port = _integer(data.get("port"))
        if port is None or not 1 <= port <= 65535:
            raise ValueError(f"invalid service port: {data.get('port')!r}")
        tls_data = data.get("tls")
        http_data = data.get("http")
        return cls(
            port=port,
            protocol=_text(data.get("protocol")) or "tcp",
            state=_text(data.get("state")) or "open",
            service=_text(data.get("service")) or "unknown",
            product=_text(data.get("product")),
            version=_text(data.get("version")),
            extra=_text(data.get("extra")),
            banner=_text(data.get("banner")),
            confidence=_integer(data.get("confidence"), 0) or 0,
            method=_text(data.get("method")) or "tcp-connect",
            response_ms=_number(data.get("response_ms")),
            tls=TlsCertificate.from_dict(_mapping(tls_data)) if isinstance(tls_data, Mapping) else None,
            http=HttpInfo.from_dict(_mapping(http_data)) if isinstance(http_data, Mapping) else None,
        )


# ---------------------------------------------------------------------------
# Host level models
# ---------------------------------------------------------------------------

@dataclass(slots=True)
class HostInfo:
    """Everything learned about one discovered device."""

    ip: str
    mac: str | None = None
    vendor: str | None = None
    hostname: str | None = None
    mdns_name: str | None = None
    netbios_name: str | None = None
    status: str = "up"
    latency_ms: float | None = None
    ttl: int | None = None
    os_guess: str | None = None
    device_type: str | None = None
    is_gateway: bool = False
    sources: list[str] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)
    services: list[ServiceInfo] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    @property
    def open_ports(self) -> list[int]:
        return sorted({service.port for service in self.services if service.state == "open"})

    @property
    def display_name(self) -> str:
        """Best available human name for the host."""
        return self.hostname or self.mdns_name or self.netbios_name or self.ip

    def add_source(self, source: str) -> None:
        if source and source not in self.sources:
            self.sources.append(source)

    def add_evidence(self, text: str) -> None:
        if text and text not in self.evidence:
            self.evidence.append(text)

    def merge(self, other: "HostInfo") -> "HostInfo":
        """Merge another observation of the same host into this one.

        Non-empty fields on ``other`` fill gaps in ``self``; list fields are
        combined without duplicates.  Services are merged by port/protocol.
        """
        for attribute in (
            "mac", "vendor", "hostname", "mdns_name", "netbios_name",
            "latency_ms", "ttl", "os_guess", "device_type",
        ):
            if not getattr(self, attribute) and getattr(other, attribute):
                setattr(self, attribute, getattr(other, attribute))
        if other.is_gateway:
            self.is_gateway = True
        if other.status == "up":
            self.status = "up"
        for source in other.sources:
            self.add_source(source)
        for item in other.evidence:
            self.add_evidence(item)
        for note in other.notes:
            if note not in self.notes:
                self.notes.append(note)
        merged: dict[tuple[int, str], ServiceInfo] = {
            (service.port, service.protocol): service for service in self.services
        }
        for service in other.services:
            key = (service.port, service.protocol)
            existing = merged.get(key)
            if existing is None:
                merged[key] = service
            else:
                if not existing.product and service.product:
                    existing.product = service.product
                if not existing.version and service.version:
                    existing.version = service.version
                if not existing.banner and service.banner:
                    existing.banner = service.banner
                if not existing.tls and service.tls:
                    existing.tls = service.tls
                if not existing.http and service.http:
                    existing.http = service.http
                existing.confidence = max(existing.confidence, service.confidence)
        self.services = sorted(merged.values(), key=lambda item: (item.port, item.protocol))
        return self

    def to_dict(self) -> dict[str, Any]:
        return {
            "ip": self.ip,
            "mac": self.mac,
            "vendor": self.vendor,
            "hostname": self.hostname,
            "mdns_name": self.mdns_name,
            "netbios_name": self.netbios_name,
            "status": self.status,
            "latency_ms": round(self.latency_ms, 2) if self.latency_ms is not None else None,
            "ttl": self.ttl,
            "os_guess": self.os_guess,
            "device_type": self.device_type,
            "is_gateway": self.is_gateway,
            "sources": list(self.sources),
            "evidence": list(self.evidence),
            "open_ports": self.open_ports,
            "services": [service.to_dict() for service in self.services],
            "notes": list(self.notes),
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "HostInfo":
        """Reconstruct a host entry from a JSON report object.

        Malformed service entries are skipped so one bad row cannot make an
        otherwise valid report unusable.

        Raises:
            ValueError: when the host has no IP address.
        """
        ip = _text(data.get("ip"))
        if not ip:
            raise ValueError("host entry has no IP address")
        services: list[ServiceInfo] = []
        for item in _mappings(data.get("services")):
            try:
                services.append(ServiceInfo.from_dict(item))
            except ValueError:
                continue
        return cls(
            ip=ip,
            mac=_text(data.get("mac")),
            vendor=_text(data.get("vendor")),
            hostname=_text(data.get("hostname")),
            mdns_name=_text(data.get("mdns_name")),
            netbios_name=_text(data.get("netbios_name")),
            status=_text(data.get("status")) or "up",
            latency_ms=_number(data.get("latency_ms")),
            ttl=_integer(data.get("ttl")),
            os_guess=_text(data.get("os_guess")),
            device_type=_text(data.get("device_type")),
            is_gateway=bool(data.get("is_gateway")),
            sources=_strings(data.get("sources")),
            evidence=_strings(data.get("evidence")),
            services=services,
            notes=_strings(data.get("notes")),
        )


# ---------------------------------------------------------------------------
# Scan result models
# ---------------------------------------------------------------------------

@dataclass(slots=True)
class ScanSummary:
    """Small summary shared by both scan types, used by console output."""

    hosts_up: int = 0
    hosts_total: int = 0
    services_found: int = 0
    ports_scanned: int = 0
    duration_s: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "hosts_up": self.hosts_up,
            "hosts_total": self.hosts_total,
            "services_found": self.services_found,
            "ports_scanned": self.ports_scanned,
            "duration_s": round(self.duration_s, 3),
        }


@dataclass(slots=True)
class NetworkScanResult:
    """Result of a full network discovery scan."""

    scan_id: str
    network: str
    interface: str | None
    local_ip: str | None
    gateway: str | None
    started_at: str
    finished_at: str
    duration_s: float
    targets_scanned: int
    hosts: list[HostInfo] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    config: dict[str, Any] = field(default_factory=dict)
    tool_version: str = ""
    mode: str = "network"

    @property
    def hosts_up(self) -> int:
        return sum(1 for host in self.hosts if host.status == "up")

    @property
    def summary(self) -> ScanSummary:
        return ScanSummary(
            hosts_up=self.hosts_up,
            hosts_total=self.targets_scanned,
            services_found=sum(len(host.services) for host in self.hosts),
            ports_scanned=0,
            duration_s=self.duration_s,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "scan_id": self.scan_id,
            "mode": self.mode,
            "tool_version": self.tool_version,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "duration_s": round(self.duration_s, 3),
            "interface": self.interface,
            "local_ip": self.local_ip,
            "gateway": self.gateway,
            "network": self.network,
            "targets_scanned": self.targets_scanned,
            "hosts_up": self.hosts_up,
            "warnings": list(self.warnings),
            "config": dict(self.config),
            "summary": self.summary.to_dict(),
            "hosts": [host.to_dict() for host in self.hosts],
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "NetworkScanResult":
        """Reconstruct a network scan result from its JSON representation."""
        hosts: list[HostInfo] = []
        for item in _mappings(data.get("hosts")):
            try:
                hosts.append(HostInfo.from_dict(item))
            except ValueError:
                continue
        return cls(
            scan_id=str(data.get("scan_id") or ""),
            network=str(data.get("network") or ""),
            interface=_text(data.get("interface")),
            local_ip=_text(data.get("local_ip")),
            gateway=_text(data.get("gateway")),
            started_at=str(data.get("started_at") or ""),
            finished_at=str(data.get("finished_at") or ""),
            duration_s=_number(data.get("duration_s"), 0.0) or 0.0,
            targets_scanned=_integer(data.get("targets_scanned"), 0) or 0,
            hosts=hosts,
            warnings=_strings(data.get("warnings")),
            config=_mapping(data.get("config")),
            tool_version=str(data.get("tool_version") or ""),
            mode=str(data.get("mode") or "network"),
        )


@dataclass(slots=True)
class HostScanResult:
    """Result of scanning one target's ports and services."""

    scan_id: str
    target: str
    resolved_ip: str
    started_at: str
    finished_at: str
    duration_s: float
    ports_scanned: int = 0
    hostname: str | None = None
    mac: str | None = None
    vendor: str | None = None
    latency_ms: float | None = None
    ttl: int | None = None
    os_guess: str | None = None
    device_type: str | None = None
    is_gateway: bool = False
    services: list[ServiceInfo] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    config: dict[str, Any] = field(default_factory=dict)
    engine: str = "native"
    tool_version: str = ""
    mode: str = "host"

    @property
    def summary(self) -> ScanSummary:
        return ScanSummary(
            hosts_up=1 if self.services or self.latency_ms is not None else 0,
            hosts_total=1,
            services_found=len(self.services),
            ports_scanned=self.ports_scanned,
            duration_s=self.duration_s,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "scan_id": self.scan_id,
            "mode": self.mode,
            "tool_version": self.tool_version,
            "engine": self.engine,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "duration_s": round(self.duration_s, 3),
            "target": self.target,
            "resolved_ip": self.resolved_ip,
            "hostname": self.hostname,
            "mac": self.mac,
            "vendor": self.vendor,
            "latency_ms": round(self.latency_ms, 2) if self.latency_ms is not None else None,
            "ttl": self.ttl,
            "os_guess": self.os_guess,
            "device_type": self.device_type,
            "is_gateway": self.is_gateway,
            "ports_scanned": self.ports_scanned,
            "open_ports": sorted({service.port for service in self.services}),
            "warnings": list(self.warnings),
            "config": dict(self.config),
            "summary": self.summary.to_dict(),
            "services": [service.to_dict() for service in self.services],
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "HostScanResult":
        """Reconstruct a single host scan result from its JSON representation."""
        services: list[ServiceInfo] = []
        for item in _mappings(data.get("services")):
            try:
                services.append(ServiceInfo.from_dict(item))
            except ValueError:
                continue
        return cls(
            scan_id=str(data.get("scan_id") or ""),
            target=str(data.get("target") or ""),
            resolved_ip=str(data.get("resolved_ip") or ""),
            started_at=str(data.get("started_at") or ""),
            finished_at=str(data.get("finished_at") or ""),
            duration_s=_number(data.get("duration_s"), 0.0) or 0.0,
            ports_scanned=_integer(data.get("ports_scanned"), 0) or 0,
            hostname=_text(data.get("hostname")),
            mac=_text(data.get("mac")),
            vendor=_text(data.get("vendor")),
            latency_ms=_number(data.get("latency_ms")),
            ttl=_integer(data.get("ttl")),
            os_guess=_text(data.get("os_guess")),
            device_type=_text(data.get("device_type")),
            is_gateway=bool(data.get("is_gateway")),
            services=services,
            warnings=_strings(data.get("warnings")),
            config=_mapping(data.get("config")),
            engine=_text(data.get("engine")) or "native",
            tool_version=str(data.get("tool_version") or ""),
            mode=str(data.get("mode") or "host"),
        )
