"""Network primitives: interfaces, routes, ARP/neighbour tables, ping/SSDP.

The module prefers the standard library and ``ip``/``ping`` utilities.  When
``psutil`` is installed it is used to enumerate interfaces, which is both
faster and more portable.  Every helper degrades gracefully when a tool is
missing or privileges are insufficient.
"""

from __future__ import annotations

import asyncio
import ipaddress
import re
import socket
import threading
import time
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterable, Sequence

from .constants import USER_AGENT_SHORT
from .utils import (
    detect_platform,
    is_root,
    normalize_mac,
    parse_ping_output,
    run_command,
    safe_decode,
    which,
)

__all__ = [
    "InterfaceInfo",
    "LocalNetwork",
    "NeighborEntry",
    "PingReply",
    "SsdpDevice",
    "arp_scan",
    "default_route",
    "detect_local_networks",
    "list_interfaces",
    "neighbor_table",
    "nmap_available",
    "ping_host",
    "ping_sweep",
    "ssdp_discover",
    "tcp_probe_host",
]

ProgressCallback = Callable[[str], None]


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass(slots=True)
class InterfaceInfo:
    """A network interface and its IPv4 configuration."""

    name: str
    mac: str | None = None
    ipv4: list[ipaddress.IPv4Interface] = field(default_factory=list)
    is_up: bool = True
    is_loopback: bool = False
    mtu: int | None = None

    @property
    def primary_ipv4(self) -> ipaddress.IPv4Interface | None:
        return self.ipv4[0] if self.ipv4 else None


@dataclass(slots=True)
class LocalNetwork:
    """The local network selected for a discovery scan."""

    interface: str
    local_ip: str
    cidr: str
    gateway: str | None = None
    mac: str | None = None


@dataclass(slots=True)
class NeighborEntry:
    """An entry from the kernel ARP / neighbour table."""

    ip: str
    mac: str | None
    interface: str | None = None
    state: str | None = None
    source: str = "neighbor-table"


@dataclass(slots=True)
class PingReply:
    """Result of an ICMP echo probe."""

    ip: str
    alive: bool
    latency_ms: float | None = None
    ttl: int | None = None
    error: str | None = None


@dataclass(slots=True)
class SsdpDevice:
    """A device that answered an SSDP (UPnP) M-SEARCH."""

    ip: str
    server: str | None = None
    location: str | None = None
    st: str | None = None
    usn: str | None = None
    friendly_name: str | None = None
    manufacturer: str | None = None
    model_name: str | None = None
    model_description: str | None = None
    serial_number: str | None = None

    def summary(self) -> str:
        parts = [
            f"{key}={value}"
            for key, value in (
                ("friendlyName", self.friendly_name),
                ("manufacturer", self.manufacturer),
                ("modelName", self.model_name),
                ("server", self.server),
            )
            if value
        ]
        return "UPnP/SSDP " + (", ".join(parts) if parts else "device")


# ---------------------------------------------------------------------------
# Interface and route discovery
# ---------------------------------------------------------------------------

def _psutil_interfaces() -> list[InterfaceInfo] | None:
    """Enumerate interfaces with psutil, returning ``None`` if unavailable."""
    try:
        import psutil  # type: ignore[import-not-found]
    except ImportError:
        return None

    result: list[InterfaceInfo] = []
    stats = psutil.net_if_stats()
    macs: dict[str, str] = {}
    for name, addresses in psutil.net_if_addrs().items():
        for address in addresses:
            if getattr(address, "family", None) == psutil.AF_LINK:
                mac = normalize_mac(getattr(address, "address", None))
                if mac:
                    macs[name] = mac
    for name, addresses in psutil.net_if_addrs().items():
        ipv4: list[ipaddress.IPv4Interface] = []
        for address in addresses:
            if address.family != socket.AF_INET:
                continue
            try:
                ipv4.append(ipaddress.IPv4Interface(f"{address.address}/{address.netmask}"))
            except ValueError:
                try:
                    ipv4.append(ipaddress.IPv4Interface(f"{address.address}/{address.prefixlen}"))
                except (ValueError, AttributeError):
                    continue
        stat = stats.get(name)
        result.append(
            InterfaceInfo(
                name=name,
                mac=macs.get(name),
                ipv4=ipv4,
                is_up=bool(stat.isup) if stat else True,
                is_loopback=name == "lo" or name.startswith("lo"),
                mtu=stat.mtu if stat else None,
            )
        )
    return sorted(result, key=lambda item: (item.is_loopback, item.name))


def _ip_command_interfaces() -> list[InterfaceInfo]:
    """Enumerate interfaces by parsing ``ip`` output (Linux fallback)."""
    result: list[InterfaceInfo] = []
    output = run_command(["ip", "-o", "-4", "addr", "show"], timeout=5.0)
    links = run_command(["ip", "-o", "link", "show"], timeout=5.0)
    macs: dict[str, str] = {}
    mtu_by_name: dict[str, int] = {}
    if links.ok:
        for line in links.stdout.splitlines():
            match = re.match(r"\d+:\s+([^:@]+)(?:@\S+)?:\s+<([^>]*)>.*?(?:mtu\s+(\d+))?", line)
            if not match:
                continue
            name = match.group(1).strip()
            mac_match = re.search(r"link/ether\s+([0-9a-fA-F:]{17})", line)
            if mac_match:
                macs[name] = normalize_mac(mac_match.group(1)) or ""
            mtu_match = re.search(r"mtu\s+(\d+)", line)
            if mtu_match:
                mtu_by_name[name] = int(mtu_match.group(1))
    if output.ok:
        for line in output.stdout.splitlines():
            match = re.match(
                r"\d+:\s+([^:@\s]+)(?:@\S+)?\s+inet\s+(\d+\.\d+\.\d+\.\d+/\d+)", line
            )
            if not match:
                continue
            name, cidr = match.group(1), match.group(2)
            try:
                interface = ipaddress.IPv4Interface(cidr)
            except ValueError:
                continue
            existing = next((item for item in result if item.name == name), None)
            if existing is None:
                result.append(
                    InterfaceInfo(
                        name=name,
                        mac=macs.get(name) or None,
                        ipv4=[interface],
                        is_up=name != "lo",
                        is_loopback=name == "lo",
                        mtu=mtu_by_name.get(name),
                    )
                )
            else:
                existing.ipv4.append(interface)
    return result


def list_interfaces() -> list[InterfaceInfo]:
    """Return all network interfaces with their IPv4 addresses."""
    interfaces = _psutil_interfaces()
    if interfaces is None:
        interfaces = _ip_command_interfaces()
    return interfaces


def default_route() -> tuple[str | None, str | None, str | None]:
    """Return ``(interface, local_ip, gateway)`` for the default route."""
    platform = detect_platform()
    if platform == "linux":
        route = run_command(["ip", "route", "show", "default"], timeout=5.0)
        interface = gateway = None
        if route.ok and route.stdout.strip():
            line = route.stdout.splitlines()[0]
            via = re.search(r"\bvia\s+(\d+\.\d+\.\d+\.\d+)", line)
            dev = re.search(r"\bdev\s+(\S+)", line)
            gateway = via.group(1) if via else None
            interface = dev.group(1) if dev else None
        get_route = run_command(["ip", "route", "get", "1.1.1.1"], timeout=5.0)
        local_ip = None
        if get_route.ok:
            src = re.search(r"\bsrc\s+(\d+\.\d+\.\d+\.\d+)", get_route.stdout)
            dev = re.search(r"\bdev\s+(\S+)", get_route.stdout)
            local_ip = src.group(1) if src else None
            interface = interface or (dev.group(1) if dev else None)
        if local_ip is None:
            local_ip, _, _ = _socket_route()
        return interface, local_ip, gateway
    if platform == "darwin":
        route = run_command(["route", "-n", "get", "default"], timeout=5.0)
        interface = gateway = None
        if route.ok:
            dev = re.search(r"interface:\s*(\S+)", route.stdout)
            gw = re.search(r"gateway:\s*(\d+\.\d+\.\d+\.\d+)", route.stdout)
            interface = dev.group(1) if dev else None
            gateway = gw.group(1) if gw else None
        local_ip, _, _ = _socket_route()
        return interface, local_ip, gateway
    # Windows / other: only the local address is easy to obtain portably.
    local_ip, _, _ = _socket_route()
    return None, local_ip, None


def _socket_route() -> tuple[str | None, None, None]:
    """Discover the local address used for outbound traffic without sending."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(("1.1.1.1", 53))
        return sock.getsockname()[0], None, None
    except OSError:
        return None, None, None
    finally:
        sock.close()


def detect_local_networks() -> list[LocalNetwork]:
    """Return usable local IPv4 networks with gateway information."""
    interfaces = list_interfaces()
    route_interface, route_ip, gateway = default_route()
    networks: list[LocalNetwork] = []
    seen: set[str] = set()
    for interface in interfaces:
        if interface.is_loopback or not interface.is_up:
            continue
        for address in interface.ipv4:
            if address.ip.is_loopback or address.ip.is_link_local:
                continue
            network = address.network
            cidr = str(network)
            if cidr in seen:
                continue
            seen.add(cidr)
            networks.append(
                LocalNetwork(
                    interface=interface.name,
                    local_ip=str(address.ip),
                    cidr=cidr,
                    gateway=gateway if interface.name == route_interface or str(address.ip) == route_ip else None,
                    mac=interface.mac,
                )
            )
    # Put the interface used by the default route first.
    networks.sort(key=lambda item: (item.interface != route_interface, item.cidr))
    return networks


# ---------------------------------------------------------------------------
# Neighbour / ARP table
# ---------------------------------------------------------------------------

def neighbor_table() -> dict[str, NeighborEntry]:
    """Read the kernel ARP/neighbour table.

    Linux ``ip neigh`` is preferred; ``arp -an`` and ``/proc/net/arp`` are
    used as fallbacks.  IPv6 entries are ignored.
    """
    entries: dict[str, NeighborEntry] = {}
    platform = detect_platform()

    if platform == "linux":
        result = run_command(["ip", "-4", "neigh", "show"], timeout=5.0)
        if result.ok:
            for line in result.stdout.splitlines():
                parts = line.split()
                if not parts:
                    continue
                try:
                    ip = str(ipaddress.IPv4Address(parts[0]))
                except ValueError:
                    continue
                mac: str | None = None
                interface: str | None = None
                state: str | None = None
                if "lladdr" in parts:
                    index = parts.index("lladdr")
                    if index + 1 < len(parts):
                        mac = normalize_mac(parts[index + 1])
                if "dev" in parts:
                    index = parts.index("dev")
                    if index + 1 < len(parts):
                        interface = parts[index + 1]
                for token in reversed(parts):
                    if token.isupper() and token not in {"LLADDR"}:
                        state = token
                        break
                if mac or state in {"FAILED", "INCOMPLETE"}:
                    entries[ip] = NeighborEntry(ip, mac, interface, state)
            if entries:
                return entries

    # ``arp -an`` works on Linux and macOS.
    if platform in {"linux", "darwin"}:
        result = run_command(["arp", "-an"], timeout=5.0)
        if result.ok:
            for line in result.stdout.splitlines():
                ip_match = re.search(r"\((\d+\.\d+\.\d+\.\d+)\)", line)
                mac_match = re.search(r"\bat\s+([0-9a-fA-F:]{17})", line)
                iface_match = re.search(r"\bon\s+(\S+)", line)
                if not ip_match:
                    continue
                mac = normalize_mac(mac_match.group(1)) if mac_match else None
                entries[ip_match.group(1)] = NeighborEntry(
                    ip_match.group(1),
                    mac,
                    iface_match.group(1) if iface_match else None,
                    "REACHABLE" if mac else "INCOMPLETE",
                    source="arp",
                )
            if entries:
                return entries

    arp_file = Path("/proc/net/arp")
    if arp_file.is_file():
        try:
            with arp_file.open("r", encoding="utf-8", errors="replace") as handle:
                next(handle, None)
                for line in handle:
                    parts = line.split()
                    if len(parts) < 6 or parts[3] == "00:00:00:00:00:00":
                        continue
                    try:
                        ip = str(ipaddress.IPv4Address(parts[0]))
                    except ValueError:
                        continue
                    entries[ip] = NeighborEntry(
                        ip, normalize_mac(parts[3]), parts[5], "REACHABLE", source="proc-arp"
                    )
        except OSError:
            pass
    return entries


# ---------------------------------------------------------------------------
# Ping / TCP reachability
# ---------------------------------------------------------------------------

def _ping_command(ip: str, timeout: float) -> list[str]:
    platform = detect_platform()
    if platform == "windows":
        return ["ping", "-n", "1", "-w", str(int(timeout * 1000)), ip]
    if platform == "darwin":
        return ["ping", "-n", "-c", "1", "-W", str(int(timeout * 1000)), ip]
    # Linux: -W is in seconds, -w is the overall deadline.
    return ["ping", "-n", "-c", "1", "-W", str(max(1, int(round(timeout)))), ip]


def ping_host(ip: str, timeout: float = 1.0) -> PingReply:
    """Send a single ICMP echo request using the system ``ping``.

    Returns ``alive=False`` for command failures and timeouts; the error field
    explains why.
    """
    result = run_command(_ping_command(ip, timeout), timeout=timeout + 2.0)
    if result.timed_out:
        return PingReply(ip, False, error="ping timed out")
    if result.returncode != 0:
        message = result.stderr.strip() or "no reply"
        return PingReply(ip, False, error=message[:200])
    latency, ttl = parse_ping_output(result.stdout)
    return PingReply(ip, True, latency, ttl)


def tcp_probe_host(
    ip: str,
    ports: Sequence[int] = (80, 443, 22),
    timeout: float = 0.5,
) -> tuple[bool, float | None, int | None]:
    """Return ``(alive, latency_ms, port)`` after trying a few TCP ports.

    Useful for hosts that silently drop ICMP echo requests.  Ports are tried
    in order and probing stops at the first success.
    """
    for port in ports:
        started = time.perf_counter()
        try:
            with socket.create_connection((ip, port), timeout=timeout):
                elapsed = (time.perf_counter() - started) * 1000
                return True, elapsed, port
        except ConnectionRefusedError:
            # A RST proves that the host is up even though the port is closed.
            elapsed = (time.perf_counter() - started) * 1000
            return True, elapsed, None
        except (TimeoutError, socket.timeout):
            continue
        except OSError:
            continue
    return False, None, None


def ping_sweep(
    targets: Iterable[str],
    *,
    timeout: float = 1.0,
    workers: int = 64,
    progress: ProgressCallback | None = None,
) -> dict[str, PingReply]:
    """Ping every target concurrently and return the replies by IP."""
    addresses = list(targets)
    results: dict[str, PingReply] = {}
    if not addresses:
        return results
    workers = max(1, min(workers, len(addresses)))
    done = 0
    lock = threading.Lock()
    with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="ping") as pool:
        futures = {pool.submit(ping_host, ip, timeout): ip for ip in addresses}
        for future in as_completed(futures):
            ip = futures[future]
            try:
                reply = future.result()
            except Exception as exc:  # defensive: a single host must not abort the sweep
                reply = PingReply(ip, False, error=f"{type(exc).__name__}: {exc}")
            results[ip] = reply
            with lock:
                done += 1
                if progress and (done == len(addresses) or done % 25 == 0):
                    alive = sum(1 for item in results.values() if item.alive)
                    progress(f"ICMP sweep: {done}/{len(addresses)} probed, {alive} alive")
    return results


async def _tcp_sweep_async(
    addresses: Sequence[str],
    ports: Sequence[int],
    *,
    timeout: float,
    concurrency: int,
    progress: ProgressCallback | None,
) -> dict[str, tuple[float | None, int | None]]:
    """Probe every host/port pair concurrently and aggregate per host."""
    semaphore = asyncio.Semaphore(max(1, concurrency))
    total = len(addresses) * len(ports)
    completed = 0
    results: dict[str, tuple[float | None, int | None]] = {}

    async def probe(ip: str, port: int) -> tuple[str, int, bool, float | None]:
        nonlocal completed
        async with semaphore:
            started = time.perf_counter()
            writer: asyncio.StreamWriter | None = None
            alive = False
            try:
                _, writer = await asyncio.wait_for(
                    asyncio.open_connection(ip, port), timeout=timeout
                )
                alive = True
            except ConnectionRefusedError:
                # A RST proves that the host is reachable even when closed.
                alive = True
            except (asyncio.TimeoutError, TimeoutError, OSError):
                alive = False
            finally:
                if writer is not None:
                    writer.close()
                    try:
                        await writer.wait_closed()
                    except (OSError, asyncio.TimeoutError):
                        pass
                completed += 1
                if progress and (completed % 500 == 0 or completed == total):
                    progress(
                        f"TCP sweep: {completed}/{total} probes, "
                        f"{len(results)} host(s) alive"
                    )
            latency = (time.perf_counter() - started) * 1000 if alive else None
            return ip, port, alive, latency

    outcomes = await asyncio.gather(
        *(probe(ip, port) for ip in addresses for port in ports)
    )
    for ip, port, alive, latency in outcomes:
        if alive and ip not in results:
            results[ip] = (latency, port)
    return results


def tcp_sweep(
    targets: Iterable[str],
    *,
    ports: Sequence[int] = (80, 443, 22),
    timeout: float = 0.5,
    workers: int = 64,
    skip: Iterable[str] = (),
    progress: ProgressCallback | None = None,
) -> dict[str, tuple[float | None, int | None]]:
    """TCP probe hosts, typically those that do not answer ICMP.

    All host/port pairs are probed concurrently (bounded by a semaphore) so a
    large range of silent hosts costs roughly one timeout instead of one
    timeout per host.  An open port or a TCP reset both prove reachability.
    """
    skipped = set(skip)
    addresses = [ip for ip in targets if ip not in skipped]
    port_list = sorted({int(port) for port in ports})
    if not addresses or not port_list:
        return {}
    total = len(addresses) * len(port_list)
    concurrency = min(total, max(32, workers * 8))
    return asyncio.run(
        _tcp_sweep_async(
            addresses,
            port_list,
            timeout=timeout,
            concurrency=concurrency,
            progress=progress,
        )
    )


# ---------------------------------------------------------------------------
# Optional external scanners
# ---------------------------------------------------------------------------

def nmap_available() -> bool:
    """Return ``True`` when the ``nmap`` binary is installed."""
    return which("nmap") is not None


def arp_scan_available() -> bool:
    """Return ``True`` when the ``arp-scan`` binary is installed.

    Root privileges are checked separately by :func:`arp_scan`, because
    installation and privilege requirements can change independently.
    """
    return which("arp-scan") is not None


def arp_scan(
    *,
    interface: str | None = None,
    target: str | None = None,
    timeout: float = 20.0,
) -> tuple[list[NeighborEntry], str | None]:
    """Run ``arp-scan`` for fast, reliable MAC discovery.

    ``arp-scan`` needs raw sockets and therefore root.  Returns a list of
    entries plus an optional warning; on failure the list is empty.
    """
    if not arp_scan_available():
        return [], "arp-scan is not installed"
    if not is_root():
        return [], "arp-scan requires root privileges (skipped)"
    args = ["arp-scan", "--ignoredups", "--retry=2", "--timeout=500"]
    if interface:
        args.extend(["--interface", interface])
    if target:
        args.append(target)
    else:
        args.append("--localnet")
    result = run_command(args, timeout=timeout)
    if result.timed_out:
        return [], "arp-scan timed out"
    if result.returncode != 0 and not result.stdout.strip():
        return [], f"arp-scan failed: {(result.stderr or 'unknown error').strip()[:200]}"
    entries: list[NeighborEntry] = []
    for line in result.stdout.splitlines():
        parts = line.split("\t")
        if len(parts) < 2:
            parts = line.split()
        if len(parts) < 2:
            continue
        try:
            ip = str(ipaddress.IPv4Address(parts[0].strip()))
        except ValueError:
            continue
        mac = normalize_mac(parts[1].strip())
        if mac:
            entries.append(
                NeighborEntry(ip, mac, interface, "REACHABLE", source="arp-scan")
            )
    return entries, None


# ---------------------------------------------------------------------------
# SSDP / UPnP discovery
# ---------------------------------------------------------------------------

_SSDP_ADDRESS = ("239.255.255.250", 1900)
_SSDP_MESSAGE = (
    "M-SEARCH * HTTP/1.1\r\n"
    "HOST: 239.255.255.250:1900\r\n"
    'MAN: "ssdp:discover"\r\n'
    "MX: 2\r\n"
    "ST: ssdp:all\r\n"
    f"USER-AGENT: {USER_AGENT_SHORT} UPnP/1.1\r\n\r\n"
).encode("ascii")

_XML_FIELD_NAMES = {
    "friendlyName": "friendly_name",
    "manufacturer": "manufacturer",
    "modelName": "model_name",
    "modelDescription": "model_description",
    "serialNumber": "serial_number",
}


def _parse_ssdp_headers(payload: bytes) -> dict[str, str]:
    text = safe_decode(payload)
    lines = text.splitlines()
    status = lines[0].strip() if lines else ""
    headers: dict[str, str] = {"_status": status}
    for line in lines[1:]:
        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        headers[key.strip().lower()] = value.strip()
    return headers


def _fetch_upnp_description(location: str | None, timeout: float = 2.0) -> dict[str, str]:
    """Fetch and parse a UPnP device description, if reachable."""
    if not location or not location.lower().startswith(("http://", "https://")):
        return {}
    request = urllib.request.Request(
        location, headers={"User-Agent": f"{USER_AGENT_SHORT} UPnP/1.1"}
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            payload = response.read(65536)
    except (urllib.error.URLError, TimeoutError, OSError, ValueError):
        return {}
    try:
        root = ET.fromstring(payload)
    except ET.ParseError:
        return {}
    found: dict[str, str] = {}
    for element in root.iter():
        tag = element.tag.rsplit("}", 1)[-1]
        attribute = _XML_FIELD_NAMES.get(tag)
        if attribute and element.text and attribute not in found:
            found[attribute] = element.text.strip()[:200]
    return found


def _merge_ssdp_device(base: SsdpDevice, extra: SsdpDevice) -> SsdpDevice:
    """Fill gaps in ``base`` with information from another response.

    A single UPnP device normally answers with several M-SEARCH responses
    (one per service).  Keeping one merged record per IP keeps reports small
    and avoids repeating identical evidence.
    """
    for attribute in (
        "server",
        "location",
        "st",
        "usn",
        "friendly_name",
        "manufacturer",
        "model_name",
        "model_description",
        "serial_number",
    ):
        if not getattr(base, attribute) and getattr(extra, attribute):
            setattr(base, attribute, getattr(extra, attribute))
    return base


def ssdp_discover(
    *,
    timeout: float = 2.0,
    description_timeout: float = 1.5,
    progress: ProgressCallback | None = None,
) -> list[SsdpDevice]:
    """Send an SSDP M-SEARCH and collect UPnP device descriptions.

    The probe is passive with respect to the devices: it only reads the UPnP
    description they advertise.  Responses are collected first, then every
    unique description URL is fetched concurrently.  Finally the responses are
    merged per IP address so a device that advertises many UPnP services is
    reported once.

    Args:
        timeout: How long to listen for M-SEARCH responses.
        description_timeout: Timeout for each UPnP description download.
        progress: Optional progress callback.

    Returns:
        One :class:`SsdpDevice` per responding IP address.
    """
    responses: dict[tuple[str, str | None], SsdpDevice] = {}
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.settimeout(0.5)
    try:
        sock.sendto(_SSDP_MESSAGE, _SSDP_ADDRESS)
    except OSError as exc:
        sock.close()
        if progress:
            progress(f"SSDP discovery unavailable: {exc}")
        return []
    deadline = time.monotonic() + max(0.5, timeout)
    try:
        while time.monotonic() < deadline:
            try:
                payload, address = sock.recvfrom(65535)
            except (TimeoutError, socket.timeout):
                continue
            except OSError:
                break
            headers = _parse_ssdp_headers(payload)
            ip = address[0]
            usn = headers.get("usn")
            location = headers.get("location")
            key = (ip, usn or location)
            if key in responses:
                continue
            responses[key] = SsdpDevice(
                ip=ip,
                server=headers.get("server"),
                location=location,
                st=headers.get("st"),
                usn=usn,
            )
    finally:
        sock.close()

    # Fetch every unique description URL in parallel instead of blocking the
    # receive loop one URL at a time.
    locations = sorted(
        {device.location for device in responses.values() if device.location}
    )
    descriptions: dict[str, dict[str, str]] = {}
    if locations:
        workers = min(8, len(locations))
        with ThreadPoolExecutor(
            max_workers=workers, thread_name_prefix="ssdp-desc"
        ) as pool:
            futures = {
                pool.submit(_fetch_upnp_description, location, description_timeout): location
                for location in locations
            }
            for future in as_completed(futures):
                location = futures[future]
                try:
                    descriptions[location] = future.result()
                except Exception:
                    descriptions[location] = {}

    merged: dict[str, SsdpDevice] = {}
    for device in responses.values():
        details = descriptions.get(device.location or "", {})
        for attribute, value in details.items():
            setattr(device, attribute, value)
        existing = merged.get(device.ip)
        if existing is None:
            merged[device.ip] = device
        else:
            _merge_ssdp_device(existing, device)

    if progress:
        progress(
            f"SSDP: {len(responses)} UPnP response(s) from "
            f"{len(merged)} device(s)"
        )
    return list(merged.values())
