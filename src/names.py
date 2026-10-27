"""Hostname resolution: reverse DNS, mDNS, NetBIOS and target resolution.

None of the lookups are required for a scan to succeed.  Each one is bounded
by a timeout and failures are cached so a silent device does not slow down a
large network sweep.
"""

from __future__ import annotations

import ipaddress
import random
import re
import socket
import struct
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Callable

from .utils import detect_platform, run_command, safe_decode, which

__all__ = [
    "NetbiosName",
    "build_dns_query",
    "netbios_names",
    "resolve_ipv4",
    "resolve_names",
    "reverse_dns",
    "mdns_reverse",
]

NameCallback = Callable[[str], None]

_CACHE_LOCK = threading.Lock()
_PTR_CACHE: dict[str, str | None] = {}
_MDNS_CACHE: dict[str, str | None] = {}
_NETBIOS_CACHE: dict[str, str | None] = {}
_IP_CACHE: dict[str, str | None] = {}


def _sanitize_name(value: str | None) -> str | None:
    """Trim and validate a hostname returned by an untrusted device."""
    if not value:
        return None
    cleaned = value.strip().strip(".").replace("\x00", "")
    cleaned = "".join(char for char in cleaned if char.isprintable())
    if not cleaned or len(cleaned) > 253:
        return None
    if cleaned.lower() in {"localhost", "local", "unknown"}:
        return None
    return cleaned


# ---------------------------------------------------------------------------
# DNS wire format helpers
# ---------------------------------------------------------------------------

def encode_dns_name(name: str) -> bytes:
    """Encode a domain name into DNS label format."""
    encoded = bytearray()
    for label in name.rstrip(".").split("."):
        if not label:
            continue
        raw = label.encode("idna")
        if len(raw) > 63:
            raise ValueError(f"DNS label too long: {label!r}")
        encoded.append(len(raw))
        encoded.extend(raw)
    encoded.append(0)
    return bytes(encoded)


def build_dns_query(
    name: str,
    qtype: int = 1,
    *,
    qclass: int = 1,
    transaction_id: int | None = None,
) -> bytes:
    """Build a standard DNS query packet.

    ``qtype`` 1 = A, 12 = PTR, 16 = TXT, 255 = ANY.  ``qclass`` 1 = IN,
    3 = CHAOS (useful for ``version.bind``).
    """
    identifier = transaction_id if transaction_id is not None else random.randint(0, 0xFFFF)
    header = struct.pack("!HHHHHH", identifier, 0x0000, 1, 0, 0, 0)
    return header + encode_dns_name(name) + struct.pack("!HH", qtype, qclass)


def decode_dns_name(data: bytes, offset: int, *, max_jumps: int = 20) -> tuple[str, int]:
    """Decode a (possibly compressed) DNS name.

    Returns the decoded name and the offset of the first byte after the name
    at its original location.
    """
    labels: list[str] = []
    cursor = offset
    return_offset = offset
    jumped = False
    jumps = 0
    while True:
        if cursor >= len(data):
            raise ValueError("DNS name runs past the packet")
        length = data[cursor]
        if length & 0xC0 == 0xC0:
            if cursor + 1 >= len(data):
                raise ValueError("truncated DNS compression pointer")
            pointer = ((length & 0x3F) << 8) | data[cursor + 1]
            if not jumped:
                return_offset = cursor + 2
                jumped = True
            cursor = pointer
            jumps += 1
            if jumps > max_jumps:
                raise ValueError("DNS compression loop")
            continue
        if length == 0:
            if not jumped:
                return_offset = cursor + 1
            break
        if length > 63 or cursor + 1 + length > len(data):
            raise ValueError("invalid DNS label length")
        cursor += 1
        labels.append(safe_decode(data[cursor : cursor + length]))
        cursor += length
    return ".".join(labels), return_offset


def _parse_dns_records(
    data: bytes,
) -> list[tuple[str, int, bytes, int]]:
    """Parse a DNS response into ``(owner, type, rdata, rdata_offset)``."""
    if len(data) < 12:
        return []
    _, _, qdcount, ancount, nscount, arcount = struct.unpack("!HHHHHH", data[:12])
    offset = 12
    for _ in range(qdcount):
        _, offset = decode_dns_name(data, offset)
        offset += 4  # QTYPE + QCLASS
    records: list[tuple[str, int, bytes, int]] = []
    for _ in range(ancount + nscount + arcount):
        if offset >= len(data):
            break
        owner, offset = decode_dns_name(data, offset)
        if offset + 10 > len(data):
            break
        record_type, _, _, rdlength = struct.unpack("!HHIH", data[offset : offset + 10])
        offset += 10
        rdata = data[offset : offset + rdlength]
        records.append((owner, record_type, rdata, offset))
        offset += rdlength
    return records


def mdns_reverse(ip: str, *, timeout: float = 1.2) -> str | None:
    """Resolve a local IPv4 address using multicast DNS (PTR query)."""
    with _CACHE_LOCK:
        if ip in _MDNS_CACHE:
            return _MDNS_CACHE[ip]
    name = _mdns_reverse_uncached(ip, timeout)
    with _CACHE_LOCK:
        _MDNS_CACHE[ip] = name
    return name


def _mdns_reverse_uncached(ip: str, timeout: float) -> str | None:
    try:
        address = ipaddress.IPv4Address(ip)
    except ValueError:
        return None
    reverse_name = ".".join(reversed(str(address).split("."))) + ".in-addr.arpa"
    query = build_dns_query(reverse_name, qtype=12)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.settimeout(0.4)
    try:
        sock.sendto(query, ("224.0.0.251", 5353))
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                payload, source = sock.recvfrom(9000)
            except (TimeoutError, socket.timeout):
                continue
            except OSError:
                break
            if source[0] != ip:
                continue
            try:
                for _, record_type, rdata, rdata_offset in _parse_dns_records(payload):
                    if record_type != 12 or not rdata:
                        continue
                    name, _ = decode_dns_name(payload, rdata_offset)
                    candidate = _sanitize_name(name)
                    if candidate:
                        return candidate
            except (ValueError, struct.error):
                continue
    except OSError:
        return None
    finally:
        sock.close()
    return None


# ---------------------------------------------------------------------------
# NetBIOS (NBNS) name query
# ---------------------------------------------------------------------------

@dataclass(slots=True)
class NetbiosName:
    """One entry from a NetBIOS node status response."""

    name: str
    suffix: int
    group: bool

    @property
    def is_workstation(self) -> bool:
        return self.suffix == 0x00 and not self.group


def _encode_netbios_name(name: str = "*") -> bytes:
    """Encode a NetBIOS name for an NBSTAT query."""
    padded = name.upper().ljust(15, " ")[:15].encode("ascii", errors="replace") + b"\x00"
    encoded = bytearray([32])
    for byte in padded:
        encoded.append(ord("A") + (byte >> 4))
        encoded.append(ord("A") + (byte & 0x0F))
    encoded.append(0)
    return bytes(encoded)


def build_nbstat_query(transaction_id: int | None = None) -> bytes:
    """Build a NetBIOS node status request for the wildcard name."""
    identifier = transaction_id if transaction_id is not None else random.randint(0, 0xFFFF)
    header = struct.pack("!HHHHHH", identifier, 0x0000, 1, 0, 0, 0)
    return header + _encode_netbios_name("*") + struct.pack("!HH", 0x0021, 0x0001)


def parse_nbstat_response(data: bytes) -> list[NetbiosName]:
    """Parse a NetBIOS node status response, returning all advertised names."""
    if len(data) < 12:
        return []
    _, flags, qdcount, ancount, _, _ = struct.unpack("!HHHHHH", data[:12])
    if flags & 0x000F:  # RCODE != 0
        return []
    offset = 12
    try:
        for _ in range(qdcount):
            _, offset = decode_dns_name(data, offset)
            offset += 4
        names: list[NetbiosName] = []
        for _ in range(ancount):
            _, offset = decode_dns_name(data, offset)
            if offset + 10 > len(data):
                break
            record_type, _, _, rdlength = struct.unpack("!HHIH", data[offset : offset + 10])
            offset += 10
            rdata_start = offset
            rdata = data[offset : offset + rdlength]
            offset += rdlength
            if record_type != 0x0021 or not rdata:
                continue
            count = rdata[0]
            for index in range(count):
                start = 1 + index * 18
                entry = rdata[start : start + 18]
                if len(entry) < 18:
                    break
                raw_name = safe_decode(entry[:15]).rstrip(" \x00")
                if not raw_name:
                    continue
                suffix = entry[15]
                group_flags = struct.unpack("!H", entry[16:18])[0]
                names.append(NetbiosName(raw_name, suffix, bool(group_flags & 0x8000)))
        return names
    except (ValueError, struct.error):
        return []


def netbios_names(ip: str, *, timeout: float = 1.0) -> list[NetbiosName]:
    """Query a host for its NetBIOS names (UDP 137, NBSTAT)."""
    query = build_nbstat_query()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(query, (ip, 137))
        payload, source = sock.recvfrom(9000)
    except (OSError, TimeoutError):
        return []
    finally:
        sock.close()
    if source[0] != ip:
        return []
    return parse_nbstat_response(payload)


# ---------------------------------------------------------------------------
# Reverse DNS
# ---------------------------------------------------------------------------

def reverse_dns(ip: str, *, timeout: float = 2.0) -> str | None:
    """Resolve a PTR record for ``ip`` using the system resolver."""
    with _CACHE_LOCK:
        if ip in _PTR_CACHE:
            return _PTR_CACHE[ip]
    name = _reverse_dns_uncached(ip, timeout)
    with _CACHE_LOCK:
        _PTR_CACHE[ip] = name
    return name


def _reverse_dns_uncached(ip: str, timeout: float) -> str | None:
    platform = detect_platform()
    if platform in {"linux", "darwin"} and which("getent"):
        result = run_command(["getent", "hosts", ip], timeout=timeout)
        if result.ok:
            for line in result.stdout.splitlines():
                parts = line.split()
                if len(parts) >= 2 and parts[0] == ip:
                    for candidate in parts[1:]:
                        name = _sanitize_name(candidate)
                        if name and not re.fullmatch(r"\d+\.\d+\.\d+\.\d+", name):
                            return name
    try:
        name, _, _ = socket.gethostbyaddr(ip)
        return _sanitize_name(name)
    except OSError:
        return None


def _avahi_resolve(ip: str, timeout: float) -> str | None:
    if not which("avahi-resolve-address"):
        return None
    result = run_command(["avahi-resolve-address", ip], timeout=timeout)
    if not result.ok:
        return None
    for line in result.stdout.splitlines():
        parts = line.split("\t")
        if len(parts) >= 2 and parts[0].strip() == ip:
            return _sanitize_name(parts[1])
    return None


def resolve_names(
    ip: str,
    *,
    timeout: float = 2.0,
    use_mdns: bool = True,
    use_netbios: bool = True,
    progress: NameCallback | None = None,
) -> tuple[str | None, str | None, str | None]:
    """Resolve hostname, mDNS name and NetBIOS name for a host.

    The three lookups run concurrently, each bounded by ``timeout``, so a
    silent device costs at most one timeout rather than three.

    Returns:
        ``(hostname, mdns_name, netbios_name)``.  Any value may be ``None``.
    """
    hostname: str | None = None
    mdns_name: str | None = None
    netbios_name: str | None = None

    with _CACHE_LOCK:
        cached_ptr = _PTR_CACHE.get(ip, "missing")
        cached_mdns = _MDNS_CACHE.get(ip, "missing")
        cached_netbios = _NETBIOS_CACHE.get(ip, "missing")

    if cached_ptr != "missing":
        hostname = cached_ptr
    if cached_mdns != "missing":
        mdns_name = cached_mdns
    if cached_netbios != "missing":
        netbios_name = cached_netbios

    tasks: dict[str, object] = {}
    if cached_ptr == "missing":
        tasks["ptr"] = lambda: reverse_dns(ip, timeout=timeout)
    if use_mdns and cached_mdns == "missing":
        tasks["mdns"] = lambda: _avahi_resolve(ip, timeout) or mdns_reverse(
            ip, timeout=timeout
        )
    if use_netbios and cached_netbios == "missing":
        tasks["netbios"] = lambda: _preferred_netbios_name(ip, timeout)

    if tasks:
        with ThreadPoolExecutor(
            max_workers=len(tasks), thread_name_prefix="resolve"
        ) as pool:
            futures = {
                pool.submit(function): name  # type: ignore[arg-type]
                for name, function in tasks.items()
            }
            for future in as_completed(futures):
                name = futures[future]
                try:
                    value = future.result()
                except Exception:
                    value = None
                if name == "ptr":
                    hostname = value
                    with _CACHE_LOCK:
                        _PTR_CACHE[ip] = value
                elif name == "mdns":
                    mdns_name = value
                    with _CACHE_LOCK:
                        _MDNS_CACHE[ip] = value
                elif name == "netbios":
                    netbios_name = value
                    with _CACHE_LOCK:
                        _NETBIOS_CACHE[ip] = value

    if mdns_name and not hostname:
        hostname = mdns_name
    if netbios_name and not hostname:
        hostname = netbios_name
    if progress and hostname:
        progress(f"Resolved {ip} -> {hostname}")
    return hostname, mdns_name, netbios_name


def _preferred_netbios_name(ip: str, timeout: float) -> str | None:
    """Query NBSTAT and pick the workstation name."""
    names = netbios_names(ip, timeout=timeout)
    preferred = next((item for item in names if item.is_workstation), None)
    if preferred is None:
        preferred = next((item for item in names if not item.group), None)
    return preferred.name if preferred else None


# ---------------------------------------------------------------------------
# Target resolution
# ---------------------------------------------------------------------------

def resolve_ipv4(target: str, *, timeout: float = 3.0) -> str:
    """Resolve a hostname or IP literal to a single IPv4 address.

    Raises:
        ValueError: when the name cannot be resolved to IPv4.
    """
    target = target.strip()
    try:
        address = ipaddress.ip_address(target)
    except ValueError:
        pass
    else:
        if address.version != 4:
            raise ValueError("only IPv4 targets are supported")
        return str(address)

    with _CACHE_LOCK:
        cached = _IP_CACHE.get(target.lower(), "missing")
    if cached not in ("missing", None):
        return str(cached)

    resolved: str | None = None
    platform = detect_platform()
    if platform in {"linux", "darwin"} and which("getent"):
        result = run_command(["getent", "ahostsv4", target], timeout=timeout)
        if result.ok:
            for line in result.stdout.splitlines():
                parts = line.split()
                if parts:
                    try:
                        candidate = ipaddress.ip_address(parts[0])
                    except ValueError:
                        continue
                    if candidate.version == 4:
                        resolved = str(candidate)
                        break
    if resolved is None:
        try:
            resolved = socket.gethostbyname(target)
        except OSError as exc:
            with _CACHE_LOCK:
                _IP_CACHE[target.lower()] = None
            raise ValueError(f"could not resolve {target!r}: {exc}") from exc
    with _CACHE_LOCK:
        _IP_CACHE[target.lower()] = resolved
    return resolved
