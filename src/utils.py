"""Generic helpers: validation, target expansion, subprocess handling, output."""

from __future__ import annotations

import ipaddress
import os
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Iterable, Iterator, Sequence, TypeVar

T = TypeVar("T")

__all__ = [
    "CommandError",
    "CommandResult",
    "TargetError",
    "ceil_div",
    "center",
    "chunked",
    "clamp",
    "colorize",
    "configure_color",
    "detect_platform",
    "exclude_targets",
    "expand_targets",
    "format_duration",
    "guess_os_from_ttl",
    "humanize_seconds",
    "is_root",
    "mac_is_locally_administered",
    "mac_is_multicast",
    "normalize_mac",
    "parse_exclusions",
    "parse_ping_output",
    "parse_port_spec",
    "percentage",
    "print_banner",
    "run_command",
    "safe_decode",
    "sanitize_filename",
    "strip_ansi",
    "table",
    "timestamp_slug",
    "unique",
    "utc_now",
    "utc_now_iso",
    "validate_target",
    "which",
]


# ---------------------------------------------------------------------------
# Time helpers
# ---------------------------------------------------------------------------

def utc_now() -> datetime:
    """Return the current timezone aware UTC time."""
    return datetime.now(timezone.utc)


def utc_now_iso() -> str:
    """Return the current UTC time as an ISO-8601 string."""
    return utc_now().isoformat(timespec="seconds")


def timestamp_slug(moment: datetime | None = None) -> str:
    """Return a filesystem friendly timestamp, e.g. ``20260101_120000``."""
    moment = moment or utc_now()
    return moment.strftime("%Y%m%d_%H%M%S")


def humanize_seconds(seconds: float | None) -> str:
    """Format a duration in a compact human readable form."""
    if seconds is None:
        return "n/a"
    if seconds < 1:
        return f"{seconds * 1000:.0f} ms"
    if seconds < 60:
        return f"{seconds:.2f} s"
    minutes, secs = divmod(seconds, 60)
    return f"{int(minutes)}m {secs:04.1f}s"


def format_duration(seconds: float | None) -> str:
    """Alias for :func:`humanize_seconds` used by report renderers."""
    return humanize_seconds(seconds)


# ---------------------------------------------------------------------------
# Platform / privilege helpers
# ---------------------------------------------------------------------------

def detect_platform() -> str:
    """Return ``linux``, ``darwin`` or ``windows`` (best effort)."""
    if sys.platform.startswith("linux"):
        return "linux"
    if sys.platform == "darwin":
        return "darwin"
    if os.name == "nt":
        return "windows"
    return sys.platform


def is_root() -> bool:
    """Return ``True`` when the process has administrative privileges."""
    try:
        return os.geteuid() == 0  # type: ignore[attr-defined]
    except AttributeError:  # pragma: no cover - Windows
        import ctypes

        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore[attr-defined]
        except Exception:
            return False


def which(binary: str) -> str | None:
    """Locate an executable, returning ``None`` when it is unavailable."""
    return shutil.which(binary)


# ---------------------------------------------------------------------------
# Command execution
# ---------------------------------------------------------------------------

class CommandError(RuntimeError):
    """Raised when a subprocess cannot be executed."""


@dataclass(slots=True)
class CommandResult:
    """Result of :func:`run_command`."""

    args: list[str]
    returncode: int
    stdout: str
    stderr: str
    duration_s: float
    timed_out: bool = False

    @property
    def ok(self) -> bool:
        return self.returncode == 0 and not self.timed_out


def safe_decode(data: bytes | bytearray | None, errors: str = "replace") -> str:
    """Decode bytes tolerantly, preferring UTF-8."""
    if data is None:
        return ""
    if isinstance(data, str):
        return data
    return bytes(data).decode("utf-8", errors=errors)


def run_command(
    args: Sequence[str],
    *,
    timeout: float = 10.0,
    input_data: bytes | None = None,
    env: dict[str, str] | None = None,
) -> CommandResult:
    """Run a command without a shell and capture its output.

    The helper never raises because a tool is missing or times out; failures
    are reported through :class:`CommandResult` so callers can degrade
    gracefully.  ``OSError`` for a missing binary is converted into a result
    with ``returncode`` 127.

    Args:
        args: Command and arguments.  ``shell=True`` is intentionally never
            used to avoid command injection through scan targets.
        timeout: Hard timeout in seconds.
        input_data: Optional bytes written to stdin.
        env: Optional environment override.
    """
    started = utc_now()
    command = list(args)
    try:
        completed = subprocess.run(
            command,
            input=input_data,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            env=env,
            check=False,
        )
    except FileNotFoundError:
        return CommandResult(command, 127, "", f"command not found: {command[0]}", 0.0)
    except subprocess.TimeoutExpired as exc:
        return CommandResult(
            command,
            124,
            safe_decode(exc.stdout),
            safe_decode(exc.stderr) or f"timed out after {timeout:.1f}s",
            (utc_now() - started).total_seconds(),
            timed_out=True,
        )
    except OSError as exc:
        raise CommandError(f"failed to execute {command[0]!r}: {exc}") from exc
    return CommandResult(
        command,
        completed.returncode,
        safe_decode(completed.stdout),
        safe_decode(completed.stderr),
        (utc_now() - started).total_seconds(),
    )


# ---------------------------------------------------------------------------
# Target validation / expansion
# ---------------------------------------------------------------------------

class TargetError(ValueError):
    """Raised for invalid network targets or port specifications."""


def _expand_octet_range(text: str) -> Iterator[str]:
    """Expand ``192.168.1.10-20`` or ``192.168.1.10-192.168.1.20``."""
    if "-" not in text:
        yield text
        return
    start_text, end_text = text.split("-", 1)
    try:
        start = ipaddress.IPv4Address(start_text.strip())
    except ValueError as exc:
        raise TargetError(f"invalid IP range start: {start_text!r}") from exc
    end_text = end_text.strip()
    if "." in end_text:  # full IP end
        try:
            end = ipaddress.IPv4Address(end_text)
        except ValueError as exc:
            raise TargetError(f"invalid IP range end: {end_text!r}") from exc
    else:  # last octet shorthand
        try:
            last_octet = int(end_text)
        except ValueError as exc:
            raise TargetError(f"invalid IP range end: {end_text!r}") from exc
        if not 0 <= last_octet <= 255:
            raise TargetError(f"range end out of bounds: {last_octet}")
        octets = str(start).split(".")
        octets[-1] = str(last_octet)
        end = ipaddress.IPv4Address(".".join(octets))
    if int(end) < int(start):
        raise TargetError(f"range end {end} is lower than start {start}")
    for value in range(int(start), int(end) + 1):
        yield str(ipaddress.IPv4Address(value))


def expand_targets(spec: str, *, max_hosts: int = 4096) -> list[str]:
    """Expand a target specification into a list of IPv4 addresses.

    Accepted forms:

    * single address: ``192.168.1.10``
    * CIDR network: ``192.168.1.0/24``
    * last-octet range: ``192.168.1.10-20``
    * full range: ``192.168.1.10-192.168.1.20``
    * comma separated combinations of the above

    Host bits in a CIDR are ignored (the network's usable hosts are returned);
    ``/31`` and ``/32`` are handled explicitly.

    Raises:
        TargetError: if the specification is invalid or too large.
    """
    spec = (spec or "").strip()
    if not spec:
        raise TargetError("empty target specification")

    addresses: list[str] = []
    seen: set[str] = set()
    for chunk in spec.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        if "/" in chunk:
            try:
                network = ipaddress.ip_network(chunk, strict=False)
            except ValueError as exc:
                raise TargetError(f"invalid CIDR network: {chunk!r}") from exc
            if network.version != 4:
                raise TargetError("only IPv4 networks are supported")
            hosts = network.hosts() if network.prefixlen < 31 else iter(network)
            for host in hosts:
                text = str(host)
                if text not in seen:
                    seen.add(text)
                    addresses.append(text)
                    if len(addresses) > max_hosts:
                        raise TargetError(
                            f"target expands to more than {max_hosts} hosts; "
                            "narrow the range or raise max_hosts"
                        )
        else:
            for text in _expand_octet_range(chunk):
                try:
                    address = ipaddress.ip_address(text)
                except ValueError as exc:
                    raise TargetError(f"invalid IP address: {text!r}") from exc
                if address.version != 4:
                    raise TargetError("only IPv4 targets are supported")
                if text not in seen:
                    seen.add(text)
                    addresses.append(text)
                    if len(addresses) > max_hosts:
                        raise TargetError(
                            f"target expands to more than {max_hosts} hosts; "
                            "narrow the range or raise max_hosts"
                        )
    if not addresses:
        raise TargetError(f"no addresses found in target {spec!r}")
    return addresses


def parse_exclusions(spec: str | None, *, max_hosts: int = 4096) -> list[str]:
    """Expand an exclusion specification into IPv4 addresses.

    The accepted syntax is identical to :func:`expand_targets`: single
    addresses, CIDR networks, last-octet ranges, full ranges and comma
    separated combinations.  An empty specification means "exclude nothing"
    and returns an empty list.

    Raises:
        TargetError: if the specification is invalid or expands to more than
            ``max_hosts`` addresses.
    """
    if spec is None or not spec.strip():
        return []
    return expand_targets(spec, max_hosts=max_hosts)


def exclude_targets(
    targets: Sequence[str],
    spec: str | None,
    *,
    max_hosts: int = 4096,
) -> list[str]:
    """Return ``targets`` without the addresses selected by ``spec``.

    Target order is preserved.  Addresses in the exclusion list that are not
    present in ``targets`` are ignored; an exclusion matching every target
    yields an empty list (callers decide whether that is an error).
    """
    excluded = set(parse_exclusions(spec, max_hosts=max_hosts))
    if not excluded:
        return list(targets)
    return [target for target in targets if target not in excluded]


def validate_target(target: str) -> str:
    """Validate a single IPv4 address or resolvable hostname."""
    target = (target or "").strip()
    if not target:
        raise TargetError("target must not be empty")
    try:
        address = ipaddress.ip_address(target)
    except ValueError:
        # Hostnames: conservative RFC 1123 check; resolution happens later.
        if len(target) > 253 or not re.fullmatch(
            r"(?i)(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*"
            r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?",
            target,
        ):
            raise TargetError(f"invalid IP address or hostname: {target!r}") from None
        return target
    if address.version != 4:
        raise TargetError("only IPv4 targets are supported")
    return str(address)


# ---------------------------------------------------------------------------
# Port specification parsing
# ---------------------------------------------------------------------------

def parse_port_spec(spec: str | None, *, preset: str | None = None) -> list[int]:
    """Parse a port specification into a sorted, de-duplicated list.

    Supported syntax: ``80``, ``80,443``, ``1-1024``, ``22,8000-8100`` and
    combinations separated by commas or whitespace.  A preset name from
    :data:`src.constants.PORT_PRESETS` may be supplied instead.
    """
    from .constants import PORT_PRESETS

    if preset:
        try:
            return sorted(set(PORT_PRESETS[preset.lower()]))
        except KeyError as exc:
            raise TargetError(f"unknown port preset: {preset!r}") from exc

    if not spec:
        raise TargetError("no ports specified")

    ports: set[int] = set()
    for raw in re.split(r"[,\s]+", spec.strip()):
        if not raw:
            continue
        if "-" in raw:
            start_text, _, end_text = raw.partition("-")
            try:
                start, end = int(start_text), int(end_text)
            except ValueError as exc:
                raise TargetError(f"invalid port range: {raw!r}") from exc
            if not (1 <= start <= 65535 and 1 <= end <= 65535):
                raise TargetError(f"port range out of bounds: {raw!r}")
            if start > end:
                raise TargetError(f"port range start greater than end: {raw!r}")
            ports.update(range(start, end + 1))
        else:
            try:
                port = int(raw)
            except ValueError as exc:
                raise TargetError(f"invalid port: {raw!r}") from exc
            if not 1 <= port <= 65535:
                raise TargetError(f"port out of bounds: {port}")
            ports.add(port)
    if not ports:
        raise TargetError(f"no valid ports in {spec!r}")
    return sorted(ports)


# ---------------------------------------------------------------------------
# MAC / network helpers
# ---------------------------------------------------------------------------

_MAC_RE = re.compile(r"[^0-9a-fA-F]")


def normalize_mac(mac: str | None) -> str | None:
    """Normalize a MAC address to lowercase colon notation.

    Returns ``None`` for empty or malformed input.
    """
    if not mac:
        return None
    cleaned = _MAC_RE.sub("", mac)
    if len(cleaned) != 12 or not all(c in "0123456789abcdefABCDEF" for c in cleaned):
        return None
    cleaned = cleaned.lower()
    return ":".join(cleaned[i : i + 2] for i in range(0, 12, 2))


def mac_is_locally_administered(mac: str | None) -> bool:
    """Return ``True`` for randomized / locally administered MAC addresses."""
    normalized = normalize_mac(mac)
    if not normalized:
        return False
    first_octet = int(normalized.split(":")[0], 16)
    return bool(first_octet & 0b10)


def mac_is_multicast(mac: str | None) -> bool:
    """Return ``True`` when the multicast bit is set."""
    normalized = normalize_mac(mac)
    if not normalized:
        return False
    first_octet = int(normalized.split(":")[0], 16)
    return bool(first_octet & 0b1)


_PING_TIME_RE = re.compile(r"time[=<]\s*([0-9.]+)\s*ms", re.IGNORECASE)
_PING_TTL_RE = re.compile(r"ttl[=:]\s*(\d+)", re.IGNORECASE)


def parse_ping_output(output: str) -> tuple[float | None, int | None]:
    """Extract round-trip time (ms) and TTL from ``ping`` output."""
    latency: float | None = None
    ttl: int | None = None
    match = _PING_TIME_RE.search(output)
    if match:
        try:
            latency = float(match.group(1))
        except ValueError:
            latency = None
    match = _PING_TTL_RE.search(output)
    if match:
        try:
            ttl = int(match.group(1))
        except ValueError:
            ttl = None
    return latency, ttl


def guess_os_from_ttl(ttl: int | None) -> str | None:
    """Very rough OS family guess from the initial TTL of a reply.

    The initial TTL is rounded up to the closest common default (32, 64, 128,
    255).  This is a heuristic, not an OS fingerprint.
    """
    if not ttl or not 0 < ttl <= 255:
        return None
    for default, label in (
        (255, "Network device / embedded OS"),
        (128, "Windows"),
        (64, "Linux / Unix / macOS / Android"),
        (32, "Embedded / legacy system"),
    ):
        if ttl <= default and default - ttl <= default * 0.25:
            return f"{label} (TTL {ttl})"
    return f"Unknown (TTL {ttl})"


# ---------------------------------------------------------------------------
# Text / output helpers
# ---------------------------------------------------------------------------

def unique(items: Iterable[T]) -> list[T]:
    """Return items with duplicates removed while preserving order."""
    seen: set[T] = set()
    result: list[T] = []
    for item in items:
        if item not in seen:
            seen.add(item)
            result.append(item)
    return result


def sanitize_filename(value: str, *, max_length: int = 60) -> str:
    """Make a value safe for use as a single filename component."""
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "_", value.strip())
    cleaned = cleaned.strip("._-") or "target"
    return cleaned[:max_length]


_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")

_COLORS = {
    "red": "\x1b[31m",
    "green": "\x1b[32m",
    "yellow": "\x1b[33m",
    "blue": "\x1b[34m",
    "magenta": "\x1b[35m",
    "cyan": "\x1b[36m",
    "white": "\x1b[37m",
    "grey": "\x1b[90m",
    "bold": "\x1b[1m",
    "reset": "\x1b[0m",
}

_COLOR_ENABLED = True


def configure_color(enabled: bool) -> None:
    """Globally enable or disable ANSI colors."""
    global _COLOR_ENABLED
    _COLOR_ENABLED = enabled


def colorize(text: str, *styles: str) -> str:
    """Wrap ``text`` in ANSI styles when colors are enabled."""
    if not _COLOR_ENABLED or not styles:
        return text
    prefix = "".join(_COLORS.get(style, "") for style in styles)
    if not prefix:
        return text
    return f"{prefix}{text}{_COLORS['reset']}"


def strip_ansi(text: str) -> str:
    """Remove ANSI escape sequences from ``text``."""
    return _ANSI_RE.sub("", text)


def print_banner(version: str, *, color: bool = True) -> None:
    """Print the application banner."""
    if color:
        configure_color(True)
    art = r"""
   ______      __              _____ __    _      __
  / ____/_  __/ /_  ___  _____/ ___// /_  (_)__  / /__
 / /   / / / / __ \/ _ \/ ___/\__ \/ __ \/ / _ \/ //_/
/ /___/ /_/ / /_/ /  __/ /  ___/ / / / / /  __/ ,<
\____/\__, /_.___/\___/_/  /____/_/ /_/_/\___/_/|_|
     /____/
"""
    print(colorize(art, "cyan") if color else art)
    print(colorize(f"  Net Spectre v{version} - authorized network inventory", "bold"))
    print(colorize("  Use only on networks you own or are explicitly authorized to test.\n", "grey"))


def center(text: str, width: int = 78) -> str:
    """Center text, ignoring ANSI sequences."""
    plain = strip_ansi(text)
    padding = max(0, (width - len(plain)) // 2)
    return " " * padding + text


def _pad_visible(text: str, width: int) -> str:
    """Left-align ``text`` to ``width`` visible characters, preserving ANSI."""
    return text + " " * max(0, width - len(strip_ansi(text)))


def table(headers: Sequence[str], rows: Sequence[Sequence[object]], *, padding: int = 2) -> str:
    """Render a simple aligned text table, ignoring ANSI escapes in widths."""
    text_rows = [[str(cell) for cell in row] for row in rows]
    widths = [len(strip_ansi(header)) for header in headers]
    for row in text_rows:
        for index, cell in enumerate(row):
            if index < len(widths):
                widths[index] = max(widths[index], len(strip_ansi(cell)))
    gap = " " * padding
    lines = [
        gap.join(_pad_visible(h, widths[i]) for i, h in enumerate(headers)).rstrip()
    ]
    lines.append(gap.join("-" * width for width in widths))
    for row in text_rows:
        lines.append(
            gap.join(
                _pad_visible(cell, widths[i]) if i < len(widths) else cell
                for i, cell in enumerate(row)
            ).rstrip()
        )
    return "\n".join(lines)


def chunked(items: Sequence[T], size: int) -> Iterator[Sequence[T]]:
    """Yield consecutive chunks of at most ``size`` items."""
    if size <= 0:
        raise ValueError("chunk size must be positive")
    for start in range(0, len(items), size):
        yield items[start : start + size]


def clamp(value: float, minimum: float, maximum: float) -> float:
    """Clamp ``value`` to the inclusive range."""
    return max(minimum, min(maximum, value))


def percentage(part: int, total: int) -> float:
    """Return ``part / total`` as a percentage, guarding division by zero."""
    if total <= 0:
        return 0.0
    return 100.0 * part / total


def ceil_div(a: int, b: int) -> int:
    """Return ``ceil(a / b)`` using integer arithmetic only.

    Returns ``0`` when ``b`` is zero, matching the historical behaviour.
    """
    if not b:
        return 0
    return -(-a // b)
