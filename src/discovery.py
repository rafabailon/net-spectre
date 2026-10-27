"""High level scan orchestration.

Two workflows are exposed:

``NetworkScanner``
    Discovers live devices on a local IPv4 network using several independent
    techniques (ICMP, TCP, ARP cache, optional arp-scan/Nmap, SSDP), resolves
    names and vendors, optionally enriches each host with a quick port scan,
    and infers the device type/OS.

``HostScanner``
    Scans every requested TCP port of one target, fingerprints the open
    services (banners, HTTP, TLS certificates), optionally probes UDP and
    enriches the result with Nmap when requested.

Both return typed result objects ready for :mod:`src.reporting`.
"""

from __future__ import annotations

import asyncio
import re
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable, Sequence

from . import __version__
from .config import ScanConfig
from .constants import (
    HOSTNAME_DEVICE_HINTS,
    PORT_DEVICE_HINTS,
    VENDOR_DEVICE_HINTS,
)
from .fingerprint import fingerprint_services, probe_service
from .logging_setup import get_logger
from .models import HostInfo, HostScanResult, NetworkScanResult, ServiceInfo
from .names import resolve_ipv4, resolve_names
from .network import (
    LocalNetwork,
    NeighborEntry,
    SsdpDevice,
    arp_scan,
    default_route,
    detect_local_networks,
    neighbor_table,
    nmap_available,
    ping_host,
    ping_sweep,
    ssdp_discover,
    tcp_sweep,
)
from .oui import get_oui_database
from .portscan import (
    NmapHost,
    TcpScanOutcome,
    nmap_discover,
    nmap_scan,
    nmap_udp_scan,
    scan_tcp_ports,
    scan_udp_ports,
)
from .utils import (
    chunked,
    exclude_targets,
    expand_targets,
    guess_os_from_ttl,
    normalize_mac,
    parse_exclusions,
    timestamp_slug,
    utc_now,
)

__all__ = [
    "HostScanner",
    "NetworkScanner",
    "ScanError",
    "infer_device_type",
    "infer_os",
    "scan_host",
    "scan_network",
]

ProgressCallback = Callable[[str], None]
logger = get_logger(__name__)


class ScanError(RuntimeError):
    """Raised when a scan cannot be started or completed."""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _new_scan_id(prefix: str) -> str:
    return f"{prefix}-{timestamp_slug()}-{uuid.uuid4().hex[:6].upper()}"


def _ip_sort_key(ip: str) -> tuple[int, ...]:
    try:
        return tuple(int(part) for part in ip.split("."))
    except ValueError:
        return (999, 999, 999, 999)


def _add_warning(warnings: list[str], message: str) -> None:
    if message and message not in warnings:
        warnings.append(message)


def _notify(progress: ProgressCallback | None, message: str, *, debug: bool = False) -> None:
    if debug:
        logger.debug(message)
    else:
        logger.info(message)
    if progress:
        try:
            progress(message)
        except Exception:  # a UI callback must never break a scan
            logger.debug("progress callback raised", exc_info=True)


def _hostname_matches(text: str, keyword: str) -> bool:
    """Match short keywords on token boundaries and longer ones as substrings."""
    if len(keyword) <= 4:
        return re.search(
            rf"(?<![a-z0-9]){re.escape(keyword)}(?![a-z0-9])", text, re.IGNORECASE
        ) is not None
    return keyword in text.lower()


def infer_device_type(
    host: HostInfo,
    *,
    gateway_ip: str | None = None,
    ssdp: SsdpDevice | None = None,
) -> tuple[str | None, list[str]]:
    """Infer a human readable device type from all available evidence.

    Returns ``(device_type, evidence_list)``.  The checks are ordered by
    reliability: gateway role, UPnP description, hostname, vendor, open ports.
    """
    evidence: list[str] = []
    candidates: list[tuple[int, str]] = []

    if gateway_ip and host.ip == gateway_ip:
        candidates.append((100, "Router / gateway"))
        evidence.append(f"default gateway is {gateway_ip}")

    if ssdp:
        description = " ".join(
            value for value in (ssdp.friendly_name, ssdp.manufacturer, ssdp.model_name) if value
        )
        for keyword, label in (*HOSTNAME_DEVICE_HINTS, *VENDOR_DEVICE_HINTS):
            if _hostname_matches(description, keyword):
                candidates.append((90, label))
                evidence.append(f"UPnP description mentions {keyword!r}")
                break
        if ssdp.friendly_name:
            evidence.append(f"UPnP friendlyName={ssdp.friendly_name!r}")
        if ssdp.model_name:
            evidence.append(f"UPnP modelName={ssdp.model_name!r}")

    names = [value for value in (host.hostname, host.mdns_name, host.netbios_name) if value]
    for name in names:
        for keyword, label in HOSTNAME_DEVICE_HINTS:
            if _hostname_matches(name, keyword):
                candidates.append((80, label))
                evidence.append(f"hostname mentions {keyword!r}")
                break
        if candidates and candidates[-1][0] == 80:
            break

    if host.vendor:
        for keyword, label in VENDOR_DEVICE_HINTS:
            if keyword in host.vendor.lower():
                candidates.append((75, label))
                evidence.append(f"vendor matches {keyword!r}")
                break

    open_ports = set(host.open_ports)
    if open_ports:
        for port_set, label in PORT_DEVICE_HINTS:
            matches = port_set & open_ports
            if matches:
                candidates.append((70, label))
                evidence.append(f"open ports {sorted(matches)} suggest {label}")
                break

    if not candidates:
        return None, evidence
    candidates.sort(key=lambda item: item[0], reverse=True)
    return candidates[0][1], evidence


def infer_os(host: HostInfo, *, nmap_os: str | None = None) -> str | None:
    """Combine the TTL heuristic with Nmap and service evidence."""
    if nmap_os:
        return nmap_os
    ttl_guess = guess_os_from_ttl(host.ttl)
    hints: list[str] = []
    for service in host.services:
        text = " ".join(
            part for part in (service.product, service.extra, service.banner) if part
        ).lower()
        if "windows" in text or "microsoft-iis" in text:
            hints.append("Windows")
            break
        if any(token in text for token in ("ubuntu", "debian", "linux", "centos", "alpine")):
            hints.append("Linux")
            break
        if "freebsd" in text:
            hints.append("FreeBSD")
            break
    if ttl_guess:
        return f"{ttl_guess}; service hints: {hints[0]}" if hints else ttl_guess
    return hints[0] if hints else None


def _vendor_for_mac(mac: str | None) -> str | None:
    if not mac:
        return None
    vendor = get_oui_database().lookup(mac)
    if vendor:
        return vendor
    return None


def _apply_mac(host: HostInfo, entry: NeighborEntry | None) -> None:
    if not entry or not entry.mac:
        return
    existing = normalize_mac(host.mac)
    new_mac = normalize_mac(entry.mac)
    if not new_mac or (existing and existing != new_mac):
        return
    host.mac = new_mac
    if not host.vendor:
        vendor = _vendor_for_mac(new_mac)
        if vendor:
            host.vendor = vendor
        elif int(new_mac.split(":")[0], 16) & 0b10:
            host.vendor = "Locally administered (randomized MAC)"


def _merge_nmap_host(host: HostInfo, nmap_host: NmapHost) -> None:
    if not host.mac and nmap_host.mac:
        host.mac = normalize_mac(nmap_host.mac)
    if not host.vendor and nmap_host.vendor:
        host.vendor = nmap_host.vendor
    if not host.hostname and nmap_host.hostnames:
        host.hostname = nmap_host.hostnames[0]
    merged = {(service.port, service.protocol): service for service in host.services}
    for service in nmap_host.services:
        merged.setdefault((service.port, service.protocol), service)
    host.services = sorted(merged.values(), key=lambda item: (item.port, item.protocol))
    if nmap_host.os_matches:
        name, accuracy = nmap_host.os_matches[0]
        host.os_guess = f"{name} ({accuracy}%)"
        host.add_evidence(f"nmap OS match: {name} ({accuracy}%)")
    if nmap_host.device_types:
        host.add_evidence(f"nmap device types: {', '.join(nmap_host.device_types)}")
    host.add_source("nmap")


async def _scan_quick_ports(
    hosts: Sequence[HostInfo],
    config: ScanConfig,
    *,
    progress: ProgressCallback | None = None,
    warnings: list[str] | None = None,
) -> None:
    """Enrich hosts with a quick TCP port scan and service fingerprints.

    Hosts are processed in small batches so the configured concurrency is a
    global ceiling rather than a per-host value.
    """
    batch_size = 32
    total_batches = max(1, (len(hosts) + batch_size - 1) // batch_size)
    for batch_index, batch in enumerate(chunked(list(hosts), batch_size), start=1):
        per_host = max(8, min(250, config.concurrency // max(1, len(batch))))
        open_by_host: dict[str, dict[int, float]] = {}

        async def scan_one(host: HostInfo) -> None:
            try:
                outcome: TcpScanOutcome = await scan_tcp_ports(
                    host.ip,
                    config.quick_ports,
                    timeout=config.port_timeout,
                    concurrency=per_host,
                )
                open_by_host[host.ip] = outcome.open_ports
            except Exception as exc:
                if warnings is not None:
                    _add_warning(warnings, f"quick port scan failed for {host.ip}: {exc}")

        await asyncio.gather(*(scan_one(host) for host in batch))

        pairs: list[tuple[str, int, float]] = [
            (ip, port, latency)
            for ip, ports in open_by_host.items()
            for port, latency in ports.items()
        ]
        fingerprints: dict[str, list[ServiceInfo]] = {}
        if pairs:
            semaphore = asyncio.Semaphore(max(1, config.fingerprint_concurrency))

            async def fingerprint(ip: str, port: int, latency: float) -> tuple[str, ServiceInfo | None]:
                async with semaphore:
                    try:
                        info = await asyncio.to_thread(
                            probe_service,
                            ip,
                            port,
                            timeout=config.timeout,
                            response_ms=latency,
                        )
                    except Exception:
                        return ip, None
                    return ip, info if info.state == "open" else None

            results = await asyncio.gather(
                *(fingerprint(ip, port, latency) for ip, port, latency in pairs)
            )
            for ip, info in results:
                if info is not None:
                    fingerprints.setdefault(ip, []).append(info)

        for host in batch:
            host.services = sorted(
                fingerprints.get(host.ip, []), key=lambda item: (item.port, item.protocol)
            )
            if host.services:
                host.add_evidence(
                    "open TCP ports: " + ", ".join(str(service.port) for service in host.services)
                )
        if progress:
            progress(
                f"Quick port scan: batch {batch_index}/{total_batches} "
                f"({sum(len(item) for item in fingerprints.values())} services)"
            )


# ---------------------------------------------------------------------------
# Network scanner
# ---------------------------------------------------------------------------

class NetworkScanner:
    """Discover devices on a local IPv4 network and gather all metadata."""

    def __init__(
        self,
        config: ScanConfig | None = None,
        *,
        progress: ProgressCallback | None = None,
    ) -> None:
        self.config = config or ScanConfig()
        self.progress = progress
        self.warnings: list[str] = []

    def scan(
        self,
        target: str | None = None,
        *,
        interface: str | None = None,
        exclude: str | None = None,
    ) -> NetworkScanResult:
        """Run a network discovery scan.

        Args:
            target: CIDR, IP range, single IP or comma separated combination.
                When omitted, the network of the default interface is used.
            interface: Optional interface name used to select the default
                network and to label the report.
            exclude: CIDR, IP range, single IP or comma separated combination
                removed from the expanded target list.

        Raises:
            TargetError: if the target or exclusion specification is invalid
                or too large.
            ScanError: when no usable local network is available or every
                target was excluded.
        """
        started_at = utc_now()
        start_monotonic = time.perf_counter()
        self.warnings = []
        network = self._resolve_network(target, interface)
        all_addresses = expand_targets(network.cidr, max_hosts=self.config.max_hosts)
        excluded = parse_exclusions(exclude, max_hosts=self.config.max_hosts)
        addresses = exclude_targets(
            all_addresses, exclude, max_hosts=self.config.max_hosts
        )
        if not addresses:
            raise ScanError(
                "every target was excluded; widen the target range or remove "
                "some exclusions"
            )
        target_set = set(addresses)

        exclusion_note = (
            f", {len(all_addresses) - len(addresses)} excluded" if excluded else ""
        )
        _notify(
            self.progress,
            f"Network discovery on {network.cidr} "
            f"({len(addresses)} targets{exclusion_note}) via {network.interface}",
        )
        logger.info("Starting network scan on %s (%d targets)", network.cidr, len(addresses))

        hosts: dict[str, HostInfo] = {}
        neighbour_entries: dict[str, NeighborEntry] = {}

        # 1. Passive snapshot before probing.
        try:
            neighbour_entries = neighbor_table()
        except Exception as exc:
            _add_warning(self.warnings, f"could not read ARP table: {exc}")

        # 2. ICMP sweep.
        ping_replies: dict[str, object] = {}
        if self.config.ping_sweep:
            try:
                ping_replies = ping_sweep(
                    addresses,
                    timeout=min(2.0, max(0.3, self.config.timeout)),
                    workers=self.config.ping_concurrency,
                    progress=self.progress,
                )
                for ip, reply in ping_replies.items():
                    if getattr(reply, "alive", False):
                        host = HostInfo(
                            ip=ip,
                            latency_ms=getattr(reply, "latency_ms", None),
                            ttl=getattr(reply, "ttl", None),
                        )
                        host.add_source("icmp")
                        hosts[ip] = host
            except Exception as exc:
                _add_warning(self.warnings, f"ICMP sweep failed: {exc}")
        else:
            _add_warning(self.warnings, "ICMP sweep disabled")

        # 3. TCP sweep for hosts that ignore ICMP.
        if self.config.tcp_sweep:
            try:
                sweep = tcp_sweep(
                    addresses,
                    ports=(80, 443, 22, 445, 3389, 8080, 53, 8000, 631, 9100, 5000, 62078),
                    timeout=min(1.0, max(0.2, self.config.port_timeout)),
                    workers=self.config.ping_concurrency,
                    skip=set(hosts),
                    progress=self.progress,
                )
                for ip, (latency, port) in sweep.items():
                    host = hosts.setdefault(ip, HostInfo(ip=ip))
                    if host.latency_ms is None:
                        host.latency_ms = latency
                    host.add_source(f"tcp-sweep:{port}" if port else "tcp-sweep")
            except Exception as exc:
                _add_warning(self.warnings, f"TCP sweep failed: {exc}")

        # 4. Optional arp-scan (root only, adds silent devices and MACs).
        if self.config.arp_scan:
            try:
                entries, warning = arp_scan(interface=network.interface)
                if warning and "root" in warning.lower():
                    logger.debug("arp-scan skipped: %s", warning)
                for entry in entries:
                    if entry.ip not in target_set:
                        continue
                    neighbour_entries[entry.ip] = entry
                    host = hosts.setdefault(entry.ip, HostInfo(ip=entry.ip))
                    _apply_mac(host, entry)
                    host.add_source("arp-scan")
                if entries:
                    _notify(self.progress, f"arp-scan: {len(entries)} device(s)")
            except Exception as exc:
                _add_warning(self.warnings, f"arp-scan failed: {exc}")

        # 5. Optional Nmap host discovery.
        if self.config.engine == "nmap":
            if nmap_available():
                try:
                    _notify(self.progress, "Running nmap host discovery")
                    discovery = nmap_discover(network.cidr)
                    self.warnings.extend(discovery.warnings)
                    for nmap_host in discovery.hosts:
                        if nmap_host.status != "up" or nmap_host.ip not in target_set:
                            continue
                        host = hosts.setdefault(nmap_host.ip, HostInfo(ip=nmap_host.ip))
                        _merge_nmap_host(host, nmap_host)
                except Exception as exc:
                    _add_warning(self.warnings, f"nmap discovery failed: {exc}")
            else:
                _add_warning(self.warnings, "nmap is not installed; using native discovery")

        # 6. SSDP / UPnP.  ``ssdp_discover`` already merges multiple service
        # responses into one device per IP.
        ssdp_by_ip: dict[str, SsdpDevice] = {}
        if self.config.ssdp:
            try:
                for device in ssdp_discover(progress=self.progress):
                    if device.ip not in target_set:
                        continue
                    ssdp_by_ip[device.ip] = device
                    host = hosts.setdefault(device.ip, HostInfo(ip=device.ip))
                    host.add_source("ssdp")
                    host.add_evidence(device.summary())
            except Exception as exc:
                _add_warning(self.warnings, f"SSDP discovery failed: {exc}")

        # 7. Refresh the ARP table: the sweeps populate it.
        try:
            for ip, entry in neighbor_table().items():
                if ip not in target_set:
                    continue
                neighbour_entries.setdefault(ip, entry)
                if entry.mac and entry.state not in {"FAILED", "INCOMPLETE"}:
                    host = hosts.setdefault(ip, HostInfo(ip=ip))
                    _apply_mac(host, entry)
                    host.add_source("arp-cache")
                    if "icmp" not in host.sources and "arp-scan" not in host.sources:
                        host.notes.append("Only confirmed by the ARP cache (may be stale)")
        except Exception as exc:
            _add_warning(self.warnings, f"could not refresh ARP table: {exc}")

        # 8. Ensure the local scanner and gateway appear if they are in scope.
        gateway = network.gateway
        if gateway in target_set:
            gateway_host = hosts.setdefault(gateway, HostInfo(ip=gateway))
            gateway_host.is_gateway = True
            gateway_host.add_source("gateway")
        if network.local_ip in target_set:
            self_host = hosts.setdefault(network.local_ip, HostInfo(ip=network.local_ip))
            self_host.add_source("local")
            self_host.notes.append("This is the host running Net Spectre")

        # Everyone seen through the above sources is considered up.
        for host in hosts.values():
            host.status = "up"
            if host.is_gateway:
                host.add_evidence(f"default gateway is {host.ip}")
            if network.local_ip == host.ip:
                host.add_evidence("local scanner address")

        _notify(self.progress, f"Discovered {len(hosts)} device(s); resolving names")

        # 9. Names and MAC information.
        if self.config.resolve_names and hosts:
            try:
                self._resolve_host_details(hosts, neighbour_entries)
            except Exception as exc:
                _add_warning(self.warnings, f"hostname resolution failed: {exc}")
        else:
            for ip, entry in neighbour_entries.items():
                if ip in hosts:
                    _apply_mac(hosts[ip], entry)

        # 10. Quick port scan and service enrichment.
        if self.config.quick_port_scan and hosts:
            try:
                _notify(
                    self.progress,
                    f"Quick port scan of {len(hosts)} host(s) "
                    f"({len(self.config.quick_ports)} ports each)",
                )
                asyncio.run(
                    _scan_quick_ports(
                        list(hosts.values()),
                        self.config,
                        progress=self.progress,
                        warnings=self.warnings,
                    )
                )
            except Exception as exc:
                _add_warning(self.warnings, f"quick port scan failed: {exc}")

        # 11. Inference and ordering.
        for host in hosts.values():
            device_type, evidence = infer_device_type(
                host, gateway_ip=gateway, ssdp=ssdp_by_ip.get(host.ip)
            )
            host.device_type = device_type
            for item in evidence:
                host.add_evidence(item)
            host.os_guess = infer_os(host)
            if ssdp_by_ip.get(host.ip):
                host.add_source("ssdp")

        ordered_hosts = sorted(hosts.values(), key=lambda host: _ip_sort_key(host.ip))
        finished_at = utc_now()
        duration = time.perf_counter() - start_monotonic
        scan_id = _new_scan_id("NET")
        report_config = self.config.to_dict()
        if excluded:
            report_config["exclude"] = exclude
            report_config["excluded_hosts"] = len(
                set(all_addresses) - set(addresses)
            )
        logger.info(
            "Network scan %s finished: %d/%d hosts, %d services in %.1fs",
            scan_id, sum(1 for host in ordered_hosts if host.status == "up"),
            len(addresses), sum(len(host.services) for host in ordered_hosts), duration,
        )
        return NetworkScanResult(
            scan_id=scan_id,
            network=network.cidr,
            interface=network.interface,
            local_ip=network.local_ip,
            gateway=network.gateway,
            started_at=started_at.isoformat(timespec="seconds"),
            finished_at=finished_at.isoformat(timespec="seconds"),
            duration_s=duration,
            targets_scanned=len(addresses),
            hosts=ordered_hosts,
            warnings=list(self.warnings),
            config=report_config,
            tool_version=__version__,
        )

    def _resolve_network(self, target: str | None, interface: str | None) -> LocalNetwork:
        interfaces = detect_local_networks()
        chosen: LocalNetwork | None = None
        if interface:
            candidates = [item for item in interfaces if item.interface == interface]
            if not candidates:
                raise ScanError(
                    f"interface {interface!r} has no usable IPv4 address "
                    f"(available: {', '.join(item.interface for item in interfaces) or 'none'})"
                )
            chosen = candidates[0]
        elif interfaces:
            chosen = interfaces[0]
        if target:
            cidr = target.strip()
            if not cidr:
                raise ScanError("target must not be empty")
            _, local_ip, gateway = default_route()
            return LocalNetwork(
                interface=interface or (chosen.interface if chosen else "unknown"),
                local_ip=(chosen.local_ip if chosen else local_ip) or "unknown",
                cidr=cidr,
                gateway=(chosen.gateway if chosen else gateway),
                mac=chosen.mac if chosen else None,
            )
        if chosen is None:
            raise ScanError(
                "no usable local IPv4 network found; specify a target explicitly "
                "(for example 192.168.1.0/24)"
            )
        return chosen

    def _resolve_host_details(
        self,
        hosts: dict[str, HostInfo],
        neighbour_entries: dict[str, NeighborEntry],
    ) -> None:
        """Resolve hostnames and MAC vendors concurrently."""
        timeout = min(2.5, max(0.5, self.config.timeout))
        workers = min(16, max(1, len(hosts)))
        with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="names") as pool:
            futures = {
                pool.submit(
                    resolve_names,
                    host.ip,
                    timeout=timeout,
                    use_mdns=self.config.use_mdns,
                    use_netbios=self.config.use_netbios,
                ): host.ip
                for host in hosts.values()
            }
            for future in as_completed(futures):
                ip = futures[future]
                host = hosts[ip]
                entry = neighbour_entries.get(ip)
                if entry:
                    _apply_mac(host, entry)
                try:
                    hostname, mdns_name, netbios_name = future.result()
                except Exception:
                    continue
                host.hostname = host.hostname or hostname
                host.mdns_name = host.mdns_name or mdns_name
                host.netbios_name = host.netbios_name or netbios_name
                if hostname or mdns_name or netbios_name:
                    host.add_source("name-resolution")
        # Vendors for hosts that only had a MAC in the ARP cache.
        for host in hosts.values():
            if host.mac and not host.vendor:
                host.vendor = _vendor_for_mac(host.mac)


# ---------------------------------------------------------------------------
# Host scanner
# ---------------------------------------------------------------------------

class HostScanner:
    """Scan all requested ports of one host and fingerprint its services."""

    def __init__(
        self,
        config: ScanConfig | None = None,
        *,
        progress: ProgressCallback | None = None,
    ) -> None:
        self.config = config or ScanConfig()
        self.progress = progress
        self.warnings: list[str] = []

    def scan(
        self,
        target: str,
        ports: Sequence[int] | None = None,
    ) -> HostScanResult:
        """Scan a single host.

        Args:
            target: IPv4 address or hostname.
            ports: Ports to scan.  Defaults to ``config.default_ports``.

        Raises:
            ScanError: if the target cannot be resolved or no ports are given.
        """
        started_at = utc_now()
        start_monotonic = time.perf_counter()
        self.warnings = []
        try:
            resolved_ip = resolve_ipv4(target)
        except ValueError as exc:
            raise ScanError(str(exc)) from exc
        port_list = tuple(sorted(set(int(port) for port in (ports or self.config.default_ports))))
        if not port_list:
            raise ScanError("no ports to scan")
        if any(not 1 <= port <= 65535 for port in port_list):
            raise ScanError("ports must be between 1 and 65535")

        _notify(
            self.progress,
            f"Host scan on {target} ({resolved_ip}): {len(port_list)} TCP port(s)",
        )
        host = HostInfo(ip=resolved_ip)
        host.hostname = target if target != resolved_ip else None
        host.add_source("target")

        # ICMP first: it also populates the ARP cache for MAC resolution.
        ping_reply = ping_host(resolved_ip, timeout=min(2.0, max(0.3, self.config.timeout)))
        if ping_reply.alive:
            host.latency_ms = ping_reply.latency_ms
            host.ttl = ping_reply.ttl
            host.add_source("icmp")
        else:
            host.notes.append("No ICMP echo reply (host may filter ICMP)")

        # Basic layer-2 metadata.
        try:
            entry = neighbor_table().get(resolved_ip)
            if entry:
                _apply_mac(host, entry)
                host.add_source(entry.source)
        except Exception as exc:
            _add_warning(self.warnings, f"could not read ARP table: {exc}")

        # Hostnames (skip when the target already was a hostname? No: reverse
        # DNS still yields useful canonical names for the report).
        if self.config.resolve_names:
            try:
                hostname, mdns_name, netbios_name = resolve_names(
                    resolved_ip,
                    timeout=min(2.5, max(0.5, self.config.timeout)),
                    use_mdns=self.config.use_mdns,
                    use_netbios=self.config.use_netbios,
                )
                host.hostname = hostname or host.hostname
                host.mdns_name = mdns_name
                host.netbios_name = netbios_name
                if hostname or mdns_name or netbios_name:
                    host.add_source("name-resolution")
            except Exception as exc:
                _add_warning(self.warnings, f"hostname resolution failed: {exc}")
        if host.mac and not host.vendor:
            host.vendor = _vendor_for_mac(host.mac)

        _, local_ip, gateway = default_route()
        host.is_gateway = bool(gateway and resolved_ip == gateway)
        if local_ip and resolved_ip == local_ip:
            host.notes.append("This is the host running Net Spectre")

        # Decide the engine: OS detection requires Nmap and root.
        engine = self.config.engine
        if self.config.os_detection:
            if nmap_available():
                engine = "nmap"
            else:
                _add_warning(self.warnings, "OS detection requires nmap; skipping it")
        if engine == "nmap" and not nmap_available():
            _add_warning(self.warnings, "nmap is not installed; falling back to the native engine")
            engine = "native"

        nmap_os: str | None = None
        if engine == "nmap":
            services, nmap_os = self._scan_with_nmap(
                resolved_ip, port_list, host, os_detection=self.config.os_detection
            )
        else:
            services = self._scan_native(resolved_ip, port_list, host)

        if self.config.udp:
            services.extend(self._scan_udp(resolved_ip))

        host.services = sorted(
            {(service.port, service.protocol): service for service in services}.values(),
            key=lambda item: (item.protocol, item.port),
        )
        if host.services and host.latency_ms is None:
            host.latency_ms = min(
                (service.response_ms for service in host.services if service.response_ms is not None),
                default=None,
            )

        device_type, evidence = infer_device_type(host, gateway_ip=gateway)
        host.device_type = device_type
        for item in evidence:
            host.add_evidence(item)
        host.os_guess = infer_os(host, nmap_os=nmap_os)

        finished_at = utc_now()
        duration = time.perf_counter() - start_monotonic
        scan_id = _new_scan_id("HOST")
        logger.info(
            "Host scan %s finished: %s, %d open service(s) in %.1fs",
            scan_id, resolved_ip, len(host.services), duration,
        )
        return HostScanResult(
            scan_id=scan_id,
            target=target,
            resolved_ip=resolved_ip,
            started_at=started_at.isoformat(timespec="seconds"),
            finished_at=finished_at.isoformat(timespec="seconds"),
            duration_s=duration,
            ports_scanned=len(port_list),
            hostname=host.hostname,
            mac=host.mac,
            vendor=host.vendor,
            latency_ms=host.latency_ms,
            ttl=host.ttl,
            os_guess=host.os_guess,
            device_type=host.device_type,
            is_gateway=host.is_gateway,
            services=host.services,
            warnings=list(self.warnings),
            config=self.config.to_dict(),
            engine=engine,
            tool_version=__version__,
        )

    def _scan_native(
        self, ip: str, ports: Sequence[int], host: HostInfo
    ) -> list[ServiceInfo]:
        async def run() -> list[ServiceInfo]:
            outcome = await scan_tcp_ports(
                ip,
                ports,
                timeout=self.config.port_timeout,
                concurrency=self.config.concurrency,
                progress=self.progress,
            )
            if not outcome.open_ports:
                return []
            _notify(
                self.progress,
                f"{len(outcome.open_ports)} open TCP port(s); fingerprinting services",
            )
            services = await fingerprint_services(
                ip,
                sorted(outcome.open_ports),
                timeout=self.config.timeout,
                concurrency=self.config.fingerprint_concurrency,
                response_times=outcome.open_ports,
                progress=self.progress,
            )
            host.add_evidence(
                f"TCP scan: {outcome.scanned} scanned, {len(outcome.open_ports)} open, "
                f"{outcome.closed} closed, {outcome.filtered} filtered"
            )
            return services

        results = asyncio.run(run())
        return results

    def _scan_with_nmap(
        self,
        ip: str,
        ports: Sequence[int],
        host: HostInfo,
        *,
        os_detection: bool,
    ) -> tuple[list[ServiceInfo], str | None]:
        try:
            result = nmap_scan(
                ip,
                ports,
                service_detection=True,
                scripts=True,
                os_detection=os_detection,
            )
        except (RuntimeError, ValueError) as exc:
            _add_warning(self.warnings, f"{exc}; falling back to native scan")
            return self._scan_native(ip, ports, host), None
        self.warnings.extend(result.warnings)
        nmap_host = result.first_host
        if nmap_host is None:
            _add_warning(self.warnings, "nmap returned no host information")
            return [], None
        _merge_nmap_host(host, nmap_host)
        if nmap_host.hostnames:
            host.add_evidence(f"nmap hostnames: {', '.join(nmap_host.hostnames)}")
        nmap_os = None
        if nmap_host.os_matches:
            nmap_os = f"{nmap_host.os_matches[0][0]} ({nmap_host.os_matches[0][1]}%)"
        return list(nmap_host.services), nmap_os

    def _scan_udp(self, ip: str) -> list[ServiceInfo]:
        if nmap_available():
            from .utils import is_root

            if is_root():
                try:
                    _notify(self.progress, f"UDP scan with nmap ({len(self.config.udp_ports)} ports)")
                    result = nmap_udp_scan(ip, self.config.udp_ports)
                    self.warnings.extend(result.warnings)
                    if result.first_host and result.first_host.services:
                        return list(result.first_host.services)
                    _add_warning(
                        self.warnings,
                        "nmap UDP scan returned no responses; trying native probes",
                    )
                except (RuntimeError, ValueError) as exc:
                    _add_warning(self.warnings, f"nmap UDP scan failed: {exc}")
        try:
            _notify(
                self.progress,
                f"UDP probes ({len(self.config.udp_ports)} ports, best effort)",
            )
            return asyncio.run(
                scan_udp_ports(
                    ip,
                    self.config.udp_ports,
                    timeout=self.config.timeout,
                    concurrency=min(32, self.config.fingerprint_concurrency * 2),
                    progress=self.progress,
                )
            )
        except Exception as exc:
            _add_warning(self.warnings, f"UDP probing failed: {exc}")
            return []


# ---------------------------------------------------------------------------
# Functional facade
# ---------------------------------------------------------------------------

def scan_network(
    config: ScanConfig | None = None,
    target: str | None = None,
    *,
    interface: str | None = None,
    exclude: str | None = None,
    progress: ProgressCallback | None = None,
) -> NetworkScanResult:
    """Convenience wrapper around :class:`NetworkScanner`."""
    return NetworkScanner(config, progress=progress).scan(
        target, interface=interface, exclude=exclude
    )


def scan_host(
    target: str,
    config: ScanConfig | None = None,
    *,
    ports: Sequence[int] | None = None,
    progress: ProgressCallback | None = None,
) -> HostScanResult:
    """Convenience wrapper around :class:`HostScanner`."""
    return HostScanner(config, progress=progress).scan(target, ports=ports)
