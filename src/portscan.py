"""TCP/UDP port scanning engines (native and optional Nmap backend).

The native engine uses asyncio TCP connect scans.  It does not require root,
works on any platform supported by Python and is fast on local networks.

An optional Nmap backend adds version detection, NSE banner scripts, OS
fingerprinting and reliable UDP scanning when the binary is installed.
"""

from __future__ import annotations

import asyncio
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Callable, Sequence

from .constants import PORT_SERVICES
from .fingerprint import probe_udp_service
from .models import ServiceInfo
from .network import nmap_available
from .utils import is_root, run_command, unique

__all__ = [
    "NmapHost",
    "NmapResult",
    "TcpScanOutcome",
    "compress_ports",
    "nmap_discover",
    "nmap_scan",
    "nmap_udp_scan",
    "parse_nmap_xml",
    "scan_tcp_ports",
    "scan_udp_ports",
]

ProgressCallback = Callable[[str], None]


@dataclass(slots=True)
class TcpScanOutcome:
    """Result of a native TCP connect scan."""

    open_ports: dict[int, float] = field(default_factory=dict)
    scanned: int = 0
    closed: int = 0
    filtered: int = 0
    duration_s: float = 0.0
    errors: list[str] = field(default_factory=list)


async def scan_tcp_ports(
    ip: str,
    ports: Sequence[int],
    *,
    timeout: float = 1.0,
    concurrency: int = 250,
    progress: ProgressCallback | None = None,
) -> TcpScanOutcome:
    """Scan TCP ports concurrently with a connect() scan.

    A refused connection proves the port is closed; a timeout is reported as
    ``filtered`` because the host or a firewall silently dropped the packet.
    """
    started = time.perf_counter()
    outcome = TcpScanOutcome(scanned=len(ports))
    semaphore = asyncio.Semaphore(max(1, concurrency))
    completed = 0

    async def probe(port: int) -> None:
        nonlocal completed
        async with semaphore:
            begin = time.perf_counter()
            writer: asyncio.StreamWriter | None = None
            try:
                _, writer = await asyncio.wait_for(
                    asyncio.open_connection(ip, port), timeout=timeout
                )
                outcome.open_ports[port] = (time.perf_counter() - begin) * 1000
            except (asyncio.TimeoutError, TimeoutError):
                outcome.filtered += 1
            except ConnectionRefusedError:
                outcome.closed += 1
            except OSError:
                outcome.filtered += 1
            finally:
                completed += 1
                if writer is not None:
                    writer.close()
                    try:
                        await writer.wait_closed()
                    except (OSError, asyncio.TimeoutError):
                        pass
                if progress and (completed % 500 == 0 or completed == len(ports)):
                    progress(
                        f"TCP scan: {completed}/{len(ports)} ports, "
                        f"{len(outcome.open_ports)} open"
                    )

    await asyncio.gather(*(probe(port) for port in sorted(set(ports))))
    outcome.duration_s = time.perf_counter() - started
    return outcome


async def scan_udp_ports(
    ip: str,
    ports: Sequence[int],
    *,
    timeout: float = 1.5,
    concurrency: int = 32,
    progress: ProgressCallback | None = None,
) -> list[ServiceInfo]:
    """Probe a curated set of UDP services concurrently.

    UDP has no handshake, so only positive responses are reported.  A missing
    response is inconclusive and is not treated as a closed port.
    """
    semaphore = asyncio.Semaphore(max(1, concurrency))
    completed = 0
    found: list[ServiceInfo] = []

    async def probe(port: int) -> None:
        nonlocal completed
        async with semaphore:
            try:
                info = await asyncio.to_thread(probe_udp_service, ip, port, timeout)
            except Exception:
                info = None
            if info is not None:
                found.append(info)
            completed += 1
            if progress and (completed % 10 == 0 or completed == len(ports)):
                progress(f"UDP scan: {completed}/{len(ports)} probed, {len(found)} responses")

    await asyncio.gather(*(probe(port) for port in sorted(set(ports))))
    return sorted(found, key=lambda item: item.port)


# ---------------------------------------------------------------------------
# Nmap backend
# ---------------------------------------------------------------------------

@dataclass(slots=True)
class NmapHost:
    """Structured representation of one Nmap host element."""

    ip: str
    status: str = "unknown"
    mac: str | None = None
    vendor: str | None = None
    hostnames: list[str] = field(default_factory=list)
    os_matches: list[tuple[str, int]] = field(default_factory=list)
    device_types: list[str] = field(default_factory=list)
    services: list[ServiceInfo] = field(default_factory=list)
    scripts: dict[str, str] = field(default_factory=dict)


@dataclass(slots=True)
class NmapResult:
    """Result of an Nmap run."""

    hosts: list[NmapHost] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    command: list[str] = field(default_factory=list)
    duration_s: float = 0.0

    @property
    def first_host(self) -> NmapHost | None:
        return self.hosts[0] if self.hosts else None


def compress_ports(ports: Sequence[int]) -> str:
    """Compress a sorted port list into an Nmap compatible range string."""
    values = sorted(set(port for port in ports if 1 <= port <= 65535))
    if not values:
        return ""
    ranges: list[str] = []
    start = previous = values[0]
    for port in values[1:]:
        if port == previous + 1:
            previous = port
            continue
        ranges.append(str(start) if start == previous else f"{start}-{previous}")
        start = previous = port
    ranges.append(str(start) if start == previous else f"{start}-{previous}")
    return ",".join(ranges)


def _nmap_base_args() -> list[str]:
    return ["nmap", "-oX", "-", "-Pn", "--reason", "-T3"]


def nmap_scan(
    ip: str,
    ports: Sequence[int],
    *,
    service_detection: bool = True,
    scripts: bool = True,
    os_detection: bool = False,
    timeout: float | None = None,
) -> NmapResult:
    """Run Nmap against one host and parse its XML output.

    ``-sS`` is used when running as root (faster, stealthier), otherwise the
    portable ``-sT`` connect scan is selected.  OS detection also needs root.
    """
    if not nmap_available():
        raise RuntimeError("nmap is not installed")
    port_spec = compress_ports(ports)
    if not port_spec:
        raise ValueError("no ports to scan")
    privileged = is_root()
    args = _nmap_base_args()
    args.append("-sS" if privileged else "-sT")
    args.extend(["-p", port_spec])
    if service_detection:
        args.append("--version-light")
    if scripts:
        args.extend(["--script", "banner,http-title,ssl-cert"])
    if os_detection:
        if not privileged:
            raise RuntimeError("OS detection requires root privileges")
        args.extend(["-O", "--osscan-limit"])
    args.append(ip)
    scan_timeout = timeout or min(1800.0, max(90.0, 30.0 + len(ports) * 0.05))
    started = time.perf_counter()
    result = run_command(args, timeout=scan_timeout)
    elapsed = time.perf_counter() - started
    warnings: list[str] = []
    if result.timed_out:
        warnings.append(f"nmap timed out after {scan_timeout:.0f}s")
    if result.returncode != 0 and not result.stdout.strip():
        warnings.append(f"nmap failed: {(result.stderr or 'unknown error').strip()[:300]}")
    parsed = parse_nmap_xml(result.stdout)
    parsed.warnings.extend(warnings)
    parsed.command = args
    parsed.duration_s = elapsed
    return parsed


def nmap_discover(target: str, *, timeout: float = 300.0) -> NmapResult:
    """Discover live hosts with ``nmap -sn`` (ARP on the local segment)."""
    if not nmap_available():
        raise RuntimeError("nmap is not installed")
    args = ["nmap", "-sn", "-oX", "-", "--reason", target]
    started = time.perf_counter()
    result = run_command(args, timeout=timeout)
    parsed = parse_nmap_xml(result.stdout)
    parsed.command = args
    parsed.duration_s = time.perf_counter() - started
    if result.timed_out:
        parsed.warnings.append(f"nmap discovery timed out after {timeout:.0f}s")
    elif result.returncode != 0 and not result.stdout.strip():
        parsed.warnings.append(
            f"nmap discovery failed: {(result.stderr or 'unknown error').strip()[:300]}"
        )
    return parsed


def nmap_udp_scan(
    ip: str,
    ports: Sequence[int],
    *,
    timeout: float | None = None,
) -> NmapResult:
    """Run a version-aware Nmap UDP scan.

    UDP scanning requires raw sockets, therefore root privileges.  Results are
    only reported for ports that answered; Nmap's ``open|filtered`` states are
    ignored to avoid false positives.
    """
    if not nmap_available():
        raise RuntimeError("nmap is not installed")
    if not is_root():
        raise RuntimeError("UDP scanning with nmap requires root privileges")
    port_spec = compress_ports(ports)
    if not port_spec:
        raise ValueError("no UDP ports to scan")
    args = _nmap_base_args() + [
        "-sU", "--version-light", "-p", port_spec, ip,
    ]
    scan_timeout = timeout or min(900.0, max(90.0, 30.0 + len(ports) * 2.0))
    started = time.perf_counter()
    result = run_command(args, timeout=scan_timeout)
    parsed = parse_nmap_xml(result.stdout)
    parsed.command = args
    parsed.duration_s = time.perf_counter() - started
    if result.timed_out:
        parsed.warnings.append(f"nmap UDP scan timed out after {scan_timeout:.0f}s")
    elif result.returncode != 0 and not result.stdout.strip():
        parsed.warnings.append(
            f"nmap UDP scan failed: {(result.stderr or 'unknown error').strip()[:300]}"
        )
    for host in parsed.hosts:
        host.services = [service for service in host.services if service.state == "open"]
    return parsed


def parse_nmap_xml(xml_text: str) -> NmapResult:
    """Parse Nmap XML into :class:`NmapResult` (also used by unit tests)."""
    result = NmapResult()
    if not xml_text or not xml_text.strip():
        return result
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as exc:
        result.warnings.append(f"could not parse nmap XML: {exc}")
        return result
    for host_element in root.findall("host"):
        status_element = host_element.find("status")
        status = status_element.get("state", "unknown") if status_element is not None else "unknown"
        ip: str | None = None
        mac: str | None = None
        vendor: str | None = None
        for address in host_element.findall("address"):
            address_type = address.get("addrtype", "")
            if address_type == "ipv4" and ip is None:
                ip = address.get("addr")
            elif address_type == "mac":
                mac = address.get("addr")
                vendor = address.get("vendor")
        if ip is None:
            continue
        host = NmapHost(
            ip=ip,
            status=status,
            mac=mac,
            vendor=vendor,
        )
        for hostname in host_element.findall("hostnames/hostname"):
            name = hostname.get("name")
            if name and name not in host.hostnames:
                host.hostnames.append(name)
        for osmatch in host_element.findall("os/osmatch"):
            try:
                accuracy = int(osmatch.get("accuracy", "0"))
            except ValueError:
                accuracy = 0
            name = osmatch.get("name")
            if name:
                host.os_matches.append((name, accuracy))
            for osclass in osmatch.findall("osclass"):
                device_type = osclass.get("type")
                if device_type and device_type not in host.device_types:
                    host.device_types.append(device_type)
        host.os_matches.sort(key=lambda item: item[1], reverse=True)
        for port_element in host_element.findall("ports/port"):
            try:
                port_number = int(port_element.get("portid", "0"))
            except ValueError:
                continue
            protocol = port_element.get("protocol", "tcp")
            state_element = port_element.find("state")
            state = state_element.get("state", "unknown") if state_element is not None else "unknown"
            if state != "open":
                continue
            service_element = port_element.find("service")
            service_name = PORT_SERVICES.get(port_number, "unknown") if protocol == "tcp" else "unknown"
            product = version = extra = tunnel = None
            if service_element is not None:
                service_name = service_element.get("name") or service_name
                product = service_element.get("product")
                version = service_element.get("version")
                extra = service_element.get("extrainfo")
                tunnel = service_element.get("tunnel")
                cpes = [element.text for element in service_element.findall("cpe") if element.text]
                if cpes:
                    extra = "; ".join(unique(([extra] if extra else []) + cpes))
            scripts: list[str] = []
            for script in port_element.findall("script"):
                script_id = script.get("id", "script")
                output = (script.get("output") or "").strip()
                if output:
                    scripts.append(f"{script_id}: {output[:500]}")
                    host.scripts[script_id] = output[:2000]
            if scripts and not extra:
                extra = " | ".join(scripts)[:1000]
            service = ServiceInfo(
                port=port_number,
                protocol=protocol,
                state=state,
                service=service_name,
                product=product,
                version=version,
                extra=extra,
                banner=(" | ".join(scripts)[:2000] or None),
                confidence=95 if (product or version) else 85,
                method="nmap",
            )
            if tunnel == "ssl":
                service.service = service.service if "https" in service.service else f"{service.service}/ssl"
            host.services.append(service)
        for hostscript in host_element.findall("hostscript/script"):
            host.scripts[hostscript.get("id", "hostscript")] = (
                hostscript.get("output") or ""
            )[:2000]
        result.hosts.append(host)
    return result
