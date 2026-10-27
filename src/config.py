"""Configuration model for scans."""

from __future__ import annotations

import os
from dataclasses import dataclass, field, fields
from pathlib import Path
from typing import Any

from .constants import QUICK_SCAN_PORTS, TOP_TCP_PORTS, UDP_PROBE_PORTS
from .utils import clamp

__all__ = ["ScanConfig"]


@dataclass(slots=True)
class ScanConfig:
    """Runtime configuration shared by the scanners and the CLI.

    Values are deliberately conservative to avoid disrupting production
    networks.  They can be changed through CLI options or environment
    variables (see :meth:`from_environment`).
    """

    # Timing / concurrency
    timeout: float = 1.5
    port_timeout: float = 1.0
    concurrency: int = 250
    ping_concurrency: int = 64
    fingerprint_concurrency: int = 12
    max_hosts: int = 4096

    # Discovery features
    ping_sweep: bool = True
    tcp_sweep: bool = True
    arp_scan: bool = True
    ssdp: bool = True
    resolve_names: bool = True
    use_mdns: bool = True
    use_netbios: bool = True
    quick_port_scan: bool = True
    quick_ports: tuple[int, ...] = field(default_factory=lambda: QUICK_SCAN_PORTS)

    # Port scanning
    engine: str = "native"  # native | nmap | auto
    udp: bool = False
    udp_ports: tuple[int, ...] = field(default_factory=lambda: UDP_PROBE_PORTS)
    os_detection: bool = False
    default_ports: tuple[int, ...] = field(default_factory=lambda: TOP_TCP_PORTS)

    # Output
    log_dir: Path = field(default_factory=lambda: Path("logs"))
    color: bool = True
    verbose: bool = False

    def __post_init__(self) -> None:
        self.validate()

    def validate(self) -> None:
        """Clamp values to sane ranges and validate the engine name."""
        self.timeout = clamp(float(self.timeout), 0.1, 30.0)
        self.port_timeout = clamp(float(self.port_timeout), 0.05, 30.0)
        self.concurrency = int(clamp(int(self.concurrency), 1, 2000))
        self.ping_concurrency = int(clamp(int(self.ping_concurrency), 1, 512))
        self.fingerprint_concurrency = int(clamp(int(self.fingerprint_concurrency), 1, 128))
        self.max_hosts = int(clamp(int(self.max_hosts), 1, 65536))
        self.quick_ports = tuple(sorted(set(int(port) for port in self.quick_ports if 1 <= int(port) <= 65535)))
        self.udp_ports = tuple(sorted(set(int(port) for port in self.udp_ports if 1 <= int(port) <= 65535)))
        self.default_ports = tuple(sorted(set(int(port) for port in self.default_ports if 1 <= int(port) <= 65535)))
        engine = (self.engine or "native").lower()
        if engine == "auto":
            from .network import nmap_available

            engine = "nmap" if nmap_available() else "native"
        if engine not in {"native", "nmap"}:
            raise ValueError(f"unknown scan engine: {self.engine!r}")
        self.engine = engine
        self.log_dir = Path(self.log_dir).expanduser()

    def with_overrides(self, **overrides: Any) -> "ScanConfig":
        """Return a copy with the provided overrides applied."""
        data = {item.name: getattr(self, item.name) for item in fields(self)}
        data.update({key: value for key, value in overrides.items() if key in data})
        return ScanConfig(**data)

    def to_dict(self) -> dict[str, Any]:
        """Serializable summary embedded in reports."""
        return {
            "timeout_s": self.timeout,
            "port_timeout_s": self.port_timeout,
            "concurrency": self.concurrency,
            "ping_concurrency": self.ping_concurrency,
            "fingerprint_concurrency": self.fingerprint_concurrency,
            "engine": self.engine,
            "udp": self.udp,
            "udp_ports": list(self.udp_ports) if self.udp else [],
            "os_detection": self.os_detection,
            "ping_sweep": self.ping_sweep,
            "tcp_sweep": self.tcp_sweep,
            "arp_scan": self.arp_scan,
            "ssdp": self.ssdp,
            "resolve_names": self.resolve_names,
            "use_mdns": self.use_mdns,
            "use_netbios": self.use_netbios,
            "quick_port_scan": self.quick_port_scan,
            "quick_ports": list(self.quick_ports) if self.quick_port_scan else [],
            "max_hosts": self.max_hosts,
        }

    @classmethod
    def from_environment(cls) -> "ScanConfig":
        """Build a configuration from ``NET_SPECTRE_*`` environment variables."""
        config = cls()
        mapping: dict[str, tuple[str, Any]] = {
            "NET_SPECTRE_TIMEOUT": ("timeout", float),
            "NET_SPECTRE_PORT_TIMEOUT": ("port_timeout", float),
            "NET_SPECTRE_CONCURRENCY": ("concurrency", int),
            "NET_SPECTRE_PING_CONCURRENCY": ("ping_concurrency", int),
            "NET_SPECTRE_FINGERPRINT_CONCURRENCY": ("fingerprint_concurrency", int),
            "NET_SPECTRE_MAX_HOSTS": ("max_hosts", int),
            "NET_SPECTRE_ENGINE": ("engine", str),
            "NET_SPECTRE_LOG_DIR": ("log_dir", Path),
        }
        for variable, (attribute, converter) in mapping.items():
            raw = os.environ.get(variable)
            if raw is None or raw == "":
                continue
            try:
                setattr(config, attribute, converter(raw))
            except (TypeError, ValueError):
                continue
        if os.environ.get("NO_COLOR"):
            config.color = False
        config.validate()
        return config
