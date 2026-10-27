"""Service fingerprinting and banner grabbing.

The native fingerprinter only performs read-only or benign protocol
handshakes (HTTP GET, EHLO, Redis INFO, NTP client request, SNMP GET on the
public community, ...).  It never attempts authentication or exploitation.

Design notes:

* All network operations have hard timeouts and size limits.
* TSL certificates are parsed without verification: the goal is inventory,
  including self-signed appliances, not trust validation.
* Fingerprinting runs in worker threads so blocking ``ssl``/``socket`` calls do
  not stall the asyncio port scanner.
"""

from __future__ import annotations

import asyncio
import hashlib
import html
import re
import socket
import ssl
import struct
import tempfile
import time
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import Callable, Sequence

from .constants import (
    HTTP_PORTS,
    HTTPS_PORTS,
    PORT_SERVICES,
    PROBES,
    SERVER_PRODUCTS,
    TLS_PORTS,
)
from .models import HttpInfo, ServiceInfo, TlsCertificate
from .names import build_dns_query
from .utils import safe_decode

__all__ = [
    "build_snmp_get",
    "classify",
    "fingerprint_services",
    "parse_http_response",
    "parse_server_header",
    "probe_service",
    "probe_udp_service",
]

ProgressCallback = Callable[[str], None]

_MAX_BANNER = 2000
_MAX_RESPONSE = 65536
_MAX_BODY = 32768

# A permissive TLS context: inventory tools must be able to inspect devices
# with self-signed or legacy certificates.
def _build_ssl_context() -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        context.minimum_version = ssl.TLSVersion.TLSv1
    except (ValueError, AttributeError):  # pragma: no cover - older Python
        pass
    try:
        context.set_ciphers("DEFAULT:@SECLEVEL=1")
    except ssl.SSLError:
        pass
    try:  # allow connections to unpatched appliances
        context.options |= ssl.OP_LEGACY_SERVER_CONNECT  # type: ignore[attr-defined]
    except AttributeError:
        pass
    return context


_SSL_CONTEXT = _build_ssl_context()


# ---------------------------------------------------------------------------
# Low level socket I/O
# ---------------------------------------------------------------------------

def _recv_payload(
    sock: socket.socket,
    *,
    max_bytes: int = _MAX_RESPONSE,
    total_timeout: float = 2.0,
    idle_timeout: float = 0.35,
) -> bytes:
    """Read a bounded amount of data, stopping when the peer goes idle."""
    deadline = time.monotonic() + total_timeout
    chunks: list[bytes] = []
    received = 0
    first = True
    while received < max_bytes:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        sock.settimeout(min(remaining, total_timeout if first else idle_timeout))
        try:
            chunk = sock.recv(min(8192, max_bytes - received))
        except (socket.timeout, TimeoutError):
            break
        except (ConnectionResetError, ssl.SSLError, OSError):
            break
        if not chunk:
            break
        chunks.append(chunk)
        received += len(chunk)
        first = False
    return b"".join(chunks)


def _clean_text(payload: bytes, *, limit: int = _MAX_BANNER) -> str | None:
    """Decode a payload and strip control characters for safe storage."""
    if not payload:
        return None
    text = safe_decode(payload)
    text = text.replace("\x00", "")
    text = "".join(
        char for char in text if char in "\r\n\t" or (char.isprintable() and char not in "\r")
    )
    text = text.strip()
    if not text:
        return None
    if len(text) > limit:
        text = text[:limit] + "…"
    return text


def _connect(ip: str, port: int, timeout: float) -> socket.socket:
    sock = socket.create_connection((ip, port), timeout=timeout)
    try:
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    except OSError:
        pass
    return sock


def _send(sock: socket.socket, payload: bytes) -> None:
    try:
        sock.sendall(payload)
    except (BrokenPipeError, ConnectionResetError, ssl.SSLError, OSError):
        pass


def _http_request(host: str, port: int) -> bytes:
    template = PROBES["http"].replace(b"{host}", host.encode("ascii", "ignore"))
    return template


# ---------------------------------------------------------------------------
# HTTP parsing
# ---------------------------------------------------------------------------

_STATUS_RE = re.compile(r"^HTTP/(\d\.\d)\s+(\d{3})(?:\s+(.*))?$", re.IGNORECASE)
_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
_CHARSET_RE = re.compile(r"charset=([\w-]+)", re.IGNORECASE)


def _decode_body(body: bytes, headers: dict[str, str]) -> str:
    charset = "utf-8"
    content_type = headers.get("content-type", "")
    match = _CHARSET_RE.search(content_type)
    if match:
        charset = match.group(1)
    try:
        return body.decode(charset, errors="replace")
    except LookupError:
        return body.decode("utf-8", errors="replace")


def parse_http_response(payload: bytes, scheme: str = "http") -> HttpInfo | None:
    """Parse an HTTP response into :class:`HttpInfo`.

    Returns ``None`` when the payload does not start with an HTTP status line.
    """
    if not payload:
        return None
    head, separator, body = payload.partition(b"\r\n\r\n")
    if not separator:
        head, _, body = payload.partition(b"\n\n")
    lines = head.splitlines()
    if not lines:
        return None
    status_match = _STATUS_RE.match(safe_decode(lines[0]).strip())
    if not status_match:
        return None
    status_code = int(status_match.group(2))
    reason = (status_match.group(3) or "").strip() or None
    headers: dict[str, str] = {}
    for line in lines[1:]:
        decoded = safe_decode(line)
        if ":" not in decoded:
            continue
        key, _, value = decoded.partition(":")
        key = key.strip().lower()
        value = value.strip()
        if not key:
            continue
        if key in headers:
            headers[key] = f"{headers[key]}, {value}"[:1000]
        else:
            headers[key] = value[:1000]
    body_text = _decode_body(body[:_MAX_BODY], headers) if body else ""
    title: str | None = None
    match = _TITLE_RE.search(body_text)
    if match:
        title = html.unescape(re.sub(r"\s+", " ", match.group(1))).strip()[:200] or None
    preview = re.sub(r"\s+", " ", body_text).strip()[:400] or None
    info = HttpInfo(
        scheme=scheme,
        status_code=status_code,
        reason=reason,
        server=headers.get("server"),
        powered_by=headers.get("x-powered-by"),
        title=title,
        location=headers.get("location"),
        headers=headers,
        body_preview=preview,
    )
    return info


def parse_server_header(server: str | None) -> tuple[str | None, str | None]:
    """Extract product and version from an HTTP ``Server`` header."""
    if not server:
        return None, None
    for pattern, product in SERVER_PRODUCTS:
        match = re.search(pattern, server)
        if not match:
            continue
        version = None
        for group in match.groups():
            if group and re.fullmatch(r"\d+(?:\.\d+)*[a-zA-Z0-9._-]*", group):
                version = group
                break
        return product, version
    # Unknown server: use the first token, keep the full value as fallback.
    candidate = server.split()[0].strip()
    return (candidate or None), None


# ---------------------------------------------------------------------------
# TLS certificate extraction
# ---------------------------------------------------------------------------

def _parse_certificate_datetime(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        parsed = parsedate_to_datetime(value)
    except (TypeError, ValueError):
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def _decode_certificate_with_cryptography(der: bytes) -> dict[str, object]:
    from cryptography import x509  # type: ignore[import-not-found]

    certificate = x509.load_der_x509_certificate(der)
    try:
        not_before = certificate.not_valid_before_utc
        not_after = certificate.not_valid_after_utc
    except AttributeError:  # cryptography < 42
        not_before = certificate.not_valid_before.replace(tzinfo=timezone.utc)
        not_after = certificate.not_valid_after.replace(tzinfo=timezone.utc)
    try:
        san = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        san_values = san.value.get_values_for_type(x509.DNSName)
        san_values += [str(item) for item in san.value.get_values_for_type(x509.IPAddress)]
    except Exception:
        san_values = []
    return {
        "subject": certificate.subject.rfc4514_string(),
        "issuer": certificate.issuer.rfc4514_string(),
        "not_before": not_before,
        "not_after": not_after,
        "serial_number": format(certificate.serial_number, "x"),
        "self_signed": certificate.subject == certificate.issuer,
        "san": san_values,
    }


def _decode_certificate_with_ssl(der: bytes) -> dict[str, object]:
    """Decode a DER certificate using CPython's internal helper.

    This private API is present in all supported CPython versions (3.10+).
    It is used only when ``cryptography`` is not installed.
    """
    decoder = getattr(getattr(ssl, "_ssl", None), "_test_decode_cert", None)
    if decoder is None:
        return {}
    pem = ssl.DER_cert_to_PEM_cert(der)
    path = None
    try:
        with tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False) as handle:
            handle.write(pem)
            path = handle.name
        decoded = decoder(path)
    except (OSError, ValueError, ssl.SSLError):
        return {}
    finally:
        if path:
            try:
                Path(path).unlink(missing_ok=True)
            except OSError:
                pass
    subject = decoded.get("subject", ())
    issuer = decoded.get("issuer", ())
    subject_text = ", ".join(
        f"{key}={value}" for group in subject for key, value in group
    ) or None
    issuer_text = ", ".join(
        f"{key}={value}" for group in issuer for key, value in group
    ) or None
    san = [
        value for kind, value in decoded.get("subjectAltName", ()) if kind in {"DNS", "IP Address"}
    ]
    return {
        "subject": subject_text,
        "issuer": issuer_text,
        "not_before": _parse_certificate_datetime(decoded.get("notBefore")),
        "not_after": _parse_certificate_datetime(decoded.get("notAfter")),
        "serial_number": decoded.get("serialNumber"),
        "self_signed": bool(subject and subject == issuer),
        "san": san,
    }


def _certificate_info(sock: ssl.SSLSocket) -> TlsCertificate | None:
    try:
        der = sock.getpeercert(binary_form=True)
    except (ssl.SSLError, OSError):
        return None
    certificate = TlsCertificate(
        version=sock.version(),
        cipher=(sock.cipher()[0] if sock.cipher() else None),
    )
    if der:
        certificate.sha256_fingerprint = hashlib.sha256(der).hexdigest()
        details: dict[str, object] = {}
        try:
            details = _decode_certificate_with_cryptography(der)
        except ImportError:
            try:
                details = _decode_certificate_with_ssl(der)
            except Exception:
                details = {}
        except Exception:
            details = {}
        certificate.subject = details.get("subject")  # type: ignore[assignment]
        certificate.issuer = details.get("issuer")  # type: ignore[assignment]
        not_before = details.get("not_before")
        not_after = details.get("not_after")
        if isinstance(not_before, datetime):
            certificate.not_before = not_before.isoformat()
        if isinstance(not_after, datetime):
            certificate.not_after = not_after.isoformat()
            certificate.days_remaining = (not_after - datetime.now(timezone.utc)).days
            certificate.expired = certificate.days_remaining < 0
        certificate.self_signed = details.get("self_signed")  # type: ignore[assignment]
        certificate.serial_number = details.get("serial_number")  # type: ignore[assignment]
        san = details.get("san")
        if isinstance(san, (list, tuple)):
            certificate.san = [str(item) for item in san][:50]
        # Heuristic fallback for self-signed certificates.
        if certificate.self_signed is None and certificate.subject and certificate.issuer:
            certificate.self_signed = certificate.subject == certificate.issuer
    return certificate


# ---------------------------------------------------------------------------
# Service classification
# ---------------------------------------------------------------------------

_SSH_RE = re.compile(r"^SSH-(\d+\.\d+)-(\S+)", re.MULTILINE)
_SOFTWARE_PATTERNS: tuple[tuple[str, str], ...] = (
    (r"(?i)\b(OpenSSH)[_ /-]?([\d.p]+)?", "OpenSSH"),
    (r"(?i)\b(Dropbear)[_ /-]?([\d.]+)?", "Dropbear"),
    (r"(?i)\b(vsFTPd)[ /]?([\d.]+)?", "vsFTPd"),
    (r"(?i)\b(ProFTPD)[ /]?([\d.]+)?", "ProFTPD"),
    (r"(?i)\b(Pure-FTPd)[ /]?([\d.]+)?", "Pure-FTPd"),
    (r"(?i)\b(FileZilla Server)[ /]?([\d.]+)?", "FileZilla Server"),
    (r"(?i)\b(Postfix)\b", "Postfix"),
    (r"(?i)\b(Exim)[ /]?([\d.]+)?", "Exim"),
    (r"(?i)\b(Sendmail)[ /]?([\d.]+)?", "Sendmail"),
    (r"(?i)\b(Dovecot)\b", "Dovecot"),
    (r"(?i)\b(MariaDB)[- /]?([\d.]+)?", "MariaDB"),
    (r"(?i)\b(MySQL)[- /]?([\d.]+)?", "MySQL"),
    (r"(?i)\b(Redis)\b", "Redis"),
    (r"(?i)\b(memcached)[ /]?([\d.]+)?", "memcached"),
    (r"(?i)\b(Samba)[ /]?([\d.]+)?", "Samba"),
    (r"(?i)\b(nginx)[ /]?([\d.]+)?", "nginx"),
    (r"(?i)\b(Apache)[ /]?([\d.]+)?", "Apache httpd"),
    (r"(?i)\b(IIS)[ /]?([\d.]+)?", "Microsoft IIS"),
)


def _extract_product(banner: str, port: int) -> tuple[str | None, str | None]:
    """Best effort product/version extraction from raw text."""
    ssh = _SSH_RE.search(banner)
    if ssh:
        software = ssh.group(2)
        protocol = ssh.group(1)
        product, _, version = software.partition("_")
        if not version:
            match = re.match(r"([A-Za-z][A-Za-z0-9.-]*?)[-_]?(\d[\w.]*)$", software)
            if match:
                product, version = match.group(1), match.group(2)
        return product or software, version or f"protocol {protocol}"
    for pattern, product in _SOFTWARE_PATTERNS:
        match = re.search(pattern, banner)
        if not match:
            continue
        version = None
        for group in match.groups()[1:]:
            if group:
                version = group
                break
        return product, version
    # Look for "product/version" or "product version" patterns in a banner.
    match = re.search(r"\b([A-Za-z][A-Za-z0-9._-]{2,20})[/ ](\d+(?:\.\d+){1,3})\b", banner)
    if match and not match.group(1).lower() in {"http", "ssh", "rfb", "smtp", "ftp"}:
        return match.group(1), match.group(2)
    return None, None


def classify(
    port: int,
    banner: str | None,
    *,
    http: HttpInfo | None = None,
    tls: TlsCertificate | None = None,
    protocol: str = "tcp",
) -> tuple[str, str | None, str | None, int, str | None]:
    """Classify a service from its port, banner, HTTP metadata and TLS data.

    Returns:
        ``(service, product, version, confidence, extra)``.
    """
    text = banner or ""
    service = PORT_SERVICES.get(port, "unknown") if protocol == "tcp" else "unknown"
    confidence = 45 if service != "unknown" else 0
    extra: str | None = None
    product: str | None = None
    version: str | None = None

    if http is not None:
        service = "https" if http.scheme == "https" else "http"
        confidence = 92
        product, version = parse_server_header(http.server)
        if not product:
            product, version = _extract_product(text, port)
        details: list[str] = []
        if http.title:
            details.append(f"title={http.title!r}")
        if http.powered_by:
            details.append(f"x-powered-by={http.powered_by}")
        if http.location:
            details.append(f"redirect={http.location}")
        if http.status_code is not None:
            details.append(f"status={http.status_code}")
        extra = "; ".join(details) or None
        return service, product, version, confidence, extra

    if text:
        # Signatures from the constants module take precedence.
        from .constants import BANNER_SIGNATURES

        for pattern, signature_service, _level, score in BANNER_SIGNATURES:
            if re.search(pattern, text, re.IGNORECASE | re.MULTILINE):
                if service == "unknown" or signature_service != "http":
                    service = signature_service
                confidence = max(confidence, score)
                break
        product, version = _extract_product(text, port)
        if product:
            confidence = max(confidence, 70)
        if service == "unknown":
            match = re.match(r"^([A-Za-z][A-Za-z0-9 ._-]{2,40})$", text.splitlines()[0].strip())
            if match:
                extra = match.group(1)
        if service == "redis":
            redis_version = re.search(r"redis_version:([\w.-]+)", text)
            if redis_version:
                product, version = "Redis", redis_version.group(1)
                confidence = 95
            os_name = re.search(r"^os:(.+)$", text, re.MULTILINE)
            if os_name:
                extra = f"os={os_name.group(1).strip()}"
        if service == "memcached":
            match = re.search(r"VERSION\s+(\S+)", text)
            if match:
                product, version = "memcached", match.group(1)
                confidence = 95
        if service == "mysql":
            match = re.search(r"(\d+\.\d+\.\d+[-\w.]*)", text)
            if match:
                version = match.group(1)
        if service == "postgresql":
            pass
        if service == "dns":
            match = re.search(r'"([^"]{1,80})"', text)
            if match:
                product, version = "DNS server", match.group(1)
                confidence = 80

    if tls is not None:
        # Without a parsed HTTP response, a TLS-only service is better labelled
        # "tls" than with a port guess such as "https-alt".  Dedicated TLS
        # protocols (imaps, ldaps, ...) keep their port-based label.
        if service in {"unknown", "tls", "https", "https-alt"}:
            service = "tls"
            confidence = max(confidence, 55)
        if tls.subject:
            details = []
            if tls.cipher:
                details.append(f"cipher={tls.cipher}")
            if tls.not_after:
                details.append(f"not_after={tls.not_after}")
            if tls.expired:
                details.append("certificate=expired")
            extra = "; ".join(details) or None
    return service, product, version, confidence, extra


# ---------------------------------------------------------------------------
# TLS probing
# ---------------------------------------------------------------------------

def _probe_tls(
    ip: str,
    port: int,
    timeout: float,
    *,
    http: bool,
    response_ms: float | None,
) -> ServiceInfo:
    raw = _connect(ip, port, timeout)
    try:
        raw.settimeout(timeout)
        tls_sock = _SSL_CONTEXT.wrap_socket(raw, server_hostname=ip)
    except (ssl.SSLError, OSError):
        raw.close()
        # Not TLS (or handshake failed): retry in plain mode so a service on a
        # TLS-looking port is still reported with its banner.
        return _probe_plain(ip, port, timeout, response_ms=response_ms, allow_http=True)
    try:
        tls_sock.settimeout(timeout)
        tls = _certificate_info(tls_sock)
        http_info: HttpInfo | None = None
        payload = b""
        if http:
            _send(tls_sock, _http_request(ip, port))
            payload = _recv_payload(tls_sock, total_timeout=min(timeout + 1.0, 3.0))
            http_info = parse_http_response(payload, scheme="https")
        else:
            payload = _recv_payload(tls_sock, total_timeout=min(timeout, 1.5))
        banner = _clean_text(payload)
        service, product, version, confidence, extra = classify(
            port, banner, http=http_info, tls=tls
        )
        return ServiceInfo(
            port=port,
            service=service,
            product=product,
            version=version,
            extra=extra,
            banner=banner,
            confidence=confidence,
            method="tls",
            response_ms=response_ms,
            tls=tls,
            http=http_info,
        )
    finally:
        try:
            tls_sock.close()
        except OSError:
            pass


# ---------------------------------------------------------------------------
# Plain TCP probing
# ---------------------------------------------------------------------------

def _initial_probe(port: int, host: str) -> tuple[bytes | None, bool]:
    """Return ``(payload, expect_banner_first)`` for the given port."""
    if port in HTTP_PORTS:
        return _http_request(host, port), False
    if port == 6379:
        return PROBES["redis"], False
    if port == 11211:
        return PROBES["memcached"], False
    if port in {554, 8554}:
        return PROBES["rtsp"].replace(b"{host}", host.encode()), False
    if port == 1883:
        return PROBES["mqtt"], False
    if port == 5432:
        # PostgreSQL SSLRequest: harmless and reveals TLS support.
        return struct.pack("!II", 8, 80877103), False
    return None, True


def _probe_plain(
    ip: str,
    port: int,
    timeout: float,
    *,
    response_ms: float | None,
    allow_http: bool = True,
) -> ServiceInfo:
    sock = _connect(ip, port, timeout)
    try:
        sock.settimeout(timeout)
        payload, expect_banner = _initial_probe(port, ip)
        if payload is None and expect_banner:
            payload = b""
            banner_bytes = _recv_payload(sock, total_timeout=min(timeout, 1.2))
            # SMTP: upgrade with EHLO to obtain capabilities.
            if port in {25, 587} and banner_bytes.startswith(b"220"):
                _send(sock, PROBES["smtp"])
                banner_bytes += _recv_payload(sock, total_timeout=min(timeout, 1.5))
            payload_bytes = banner_bytes
        else:
            _send(sock, payload or b"")
            payload_bytes = _recv_payload(sock, total_timeout=min(timeout + 1.0, 3.0))
            if port == 5432 and payload_bytes[:1] in {b"S", b"N"}:
                # PostgreSQL replies with a single byte to SSLRequest.
                extra = "TLS supported" if payload_bytes[:1] == b"S" else "TLS not supported"
                return ServiceInfo(
                    port=port,
                    service="postgresql",
                    product="PostgreSQL",
                    extra=extra,
                    banner=_clean_text(payload_bytes),
                    confidence=88,
                    method="tcp-probe",
                    response_ms=response_ms,
                )
            if port in {25, 587} and payload_bytes.startswith(b"220"):
                _send(sock, PROBES["smtp"])
                payload_bytes += _recv_payload(sock, total_timeout=min(timeout, 1.5))
            if port == 6379 and b"NOAUTH" in payload_bytes:
                # INFO rejected; fall back to PING for basic identification.
                _send(sock, b"PING\r\n")
                payload_bytes += _recv_payload(sock, total_timeout=min(timeout, 1.0))

        payload_bytes = payload_bytes[:_MAX_RESPONSE]
        banner = _clean_text(payload_bytes)
        http_info: HttpInfo | None = None
        if allow_http and (port in HTTP_PORTS or (banner or "").startswith("HTTP/")):
            http_info = parse_http_response(payload_bytes, scheme="http")
        service, product, version, confidence, extra = classify(
            port, banner, http=http_info
        )
        return ServiceInfo(
            port=port,
            service=service,
            product=product,
            version=version,
            extra=extra,
            banner=banner,
            confidence=confidence,
            method="tcp-probe",
            response_ms=response_ms,
            http=http_info,
        )
    finally:
        try:
            sock.close()
        except OSError:
            pass


def probe_service(
    ip: str,
    port: int,
    *,
    timeout: float = 1.5,
    response_ms: float | None = None,
) -> ServiceInfo:
    """Fingerprint a single open TCP port.

    Never raises for network errors: a :class:`ServiceInfo` with a closed or
    filtered state is returned instead.
    """
    started = time.perf_counter()
    try:
        if port in TLS_PORTS:
            info = _probe_tls(
                ip,
                port,
                timeout,
                http=port in HTTPS_PORTS or port in HTTP_PORTS,
                response_ms=response_ms,
            )
        else:
            info = _probe_plain(ip, port, timeout, response_ms=response_ms)
        if info.response_ms is None:
            info.response_ms = (time.perf_counter() - started) * 1000
        return info
    except (ConnectionRefusedError, ConnectionResetError):
        return ServiceInfo(
            port=port,
            state="closed",
            service=PORT_SERVICES.get(port, "unknown"),
            method="tcp-connect",
            response_ms=(time.perf_counter() - started) * 1000,
        )
    except (socket.timeout, TimeoutError):
        return ServiceInfo(
            port=port,
            state="filtered",
            service=PORT_SERVICES.get(port, "unknown"),
            method="tcp-connect",
            response_ms=(time.perf_counter() - started) * 1000,
        )
    except (ssl.SSLError, OSError) as exc:
        return ServiceInfo(
            port=port,
            state="filtered",
            service=PORT_SERVICES.get(port, "unknown"),
            extra=f"{type(exc).__name__}: {exc}"[:200],
            method="tcp-connect",
            response_ms=(time.perf_counter() - started) * 1000,
        )


async def fingerprint_services(
    ip: str,
    ports: Sequence[int],
    *,
    timeout: float = 1.5,
    concurrency: int = 12,
    response_times: dict[int, float] | None = None,
    progress: ProgressCallback | None = None,
) -> list[ServiceInfo]:
    """Fingerprint several open ports concurrently.

    Blocking socket work runs in the default executor; a semaphore bounds the
    number of simultaneous probes.
    """
    semaphore = asyncio.Semaphore(max(1, concurrency))
    completed = 0

    async def run(port: int) -> ServiceInfo:
        nonlocal completed
        async with semaphore:
            try:
                info = await asyncio.to_thread(
                    probe_service,
                    ip,
                    port,
                    timeout=timeout,
                    response_ms=(response_times or {}).get(port),
                )
            except Exception as exc:  # isolate fingerprint failures
                info = ServiceInfo(
                    port=port,
                    state="filtered",
                    service=PORT_SERVICES.get(port, "unknown"),
                    extra=f"fingerprint error: {type(exc).__name__}: {exc}"[:200],
                )
            completed += 1
            if progress and (completed % 10 == 0 or completed == len(ports)):
                progress(f"Fingerprinted {completed}/{len(ports)} open port(s)")
            return info

    results = await asyncio.gather(*(run(port) for port in sorted(set(ports))))
    return [item for item in results if item.state == "open"]


# ---------------------------------------------------------------------------
# UDP probing
# ---------------------------------------------------------------------------

def _parse_ntp(payload: bytes) -> tuple[str | None, str | None]:
    if len(payload) < 48:
        return None, None
    first = payload[0]
    version = (first >> 3) & 0x07
    mode = first & 0x07
    stratum = payload[1]
    if mode not in {4, 5}:
        return None, None
    return f"NTP v{version}", f"stratum={stratum}"


def _parse_dns_version(payload: bytes) -> tuple[str | None, str | None]:
    if len(payload) < 12:
        return None, None
    flags = struct.unpack("!H", payload[2:4])[0]
    if flags & 0x000F:
        return None, None
    text = safe_decode(payload)
    match = re.search(r'"([^"]{2,80})"', text)
    if match:
        return "DNS server", match.group(1)
    match = re.search(r"(?i)(BIND|Unbound|PowerDNS|dnsmasq|Knot|CoreDNS)[ /]?([\d.]*)", text)
    if match:
        return match.group(1), match.group(2) or None
    return "DNS server", None


# --- Minimal BER encoder/decoder used by the SNMP probe -------------------

def _ber_length(length: int) -> bytes:
    if length < 0x80:
        return bytes([length])
    encoded = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(encoded)]) + encoded


def _ber_tlv(tag: int, value: bytes) -> bytes:
    return bytes([tag]) + _ber_length(len(value)) + value


def _ber_integer(value: int) -> bytes:
    if value == 0:
        payload = b"\x00"
    else:
        length = (value.bit_length() + 7) // 8
        payload = value.to_bytes(length, "big", signed=True)
        if payload[0] & 0x80:
            payload = b"\x00" + payload
    return _ber_tlv(0x02, payload)


def _ber_oid(oid: str) -> bytes:
    parts = [int(part) for part in oid.strip(".").split(".")]
    if len(parts) < 2:
        raise ValueError("OID needs at least two components")
    encoded = bytearray([parts[0] * 40 + parts[1]])
    for part in parts[2:]:
        if part == 0:
            encoded.append(0)
            continue
        stack: list[int] = []
        while part:
            stack.append(part & 0x7F)
            part >>= 7
        for index, value in enumerate(reversed(stack)):
            encoded.append(value | (0x80 if index < len(stack) - 1 else 0))
    return _ber_tlv(0x06, bytes(encoded))


def build_snmp_get(oid: str = "1.3.6.1.2.1.1.1.0", community: str = "public") -> bytes:
    """Build a minimal SNMPv2c GET request for one OID."""
    varbind = _ber_tlv(0x30, _ber_oid(oid) + _ber_tlv(0x05, b""))
    varbinds = _ber_tlv(0x30, varbind)
    pdu = _ber_tlv(
        0xA0,
        _ber_integer(1) + _ber_integer(0) + _ber_integer(0) + varbinds,
    )
    message = _ber_tlv(
        0x30,
        _ber_integer(1) + _ber_tlv(0x04, community.encode("ascii")) + pdu,
    )
    return message


def _ber_read_tlv(data: bytes, offset: int = 0) -> tuple[int, bytes, int]:
    if offset + 2 > len(data):
        raise ValueError("truncated BER")
    tag = data[offset]
    length = data[offset + 1]
    offset += 2
    if length & 0x80:
        count = length & 0x7F
        if count == 0 or offset + count > len(data):
            raise ValueError("invalid BER length")
        length = int.from_bytes(data[offset : offset + count], "big")
        offset += count
    value = data[offset : offset + length]
    if len(value) != length:
        raise ValueError("truncated BER value")
    return tag, value, offset + length


def parse_snmp_response(payload: bytes) -> str | None:
    """Extract the first string value (sysDescr) from an SNMP response."""
    try:
        tag, message, _ = _ber_read_tlv(payload)
        if tag != 0x30:
            return None
        offset = 0
        # version
        _, _, offset = _ber_read_tlv(message, offset)
        # community
        _, _, offset = _ber_read_tlv(message, offset)
        # PDU
        _, pdu, _ = _ber_read_tlv(message, offset)
        offset = 0
        _, _, offset = _ber_read_tlv(pdu, offset)  # request id
        _, _, offset = _ber_read_tlv(pdu, offset)  # error status
        _, _, offset = _ber_read_tlv(pdu, offset)  # error index
        _, varbinds, _ = _ber_read_tlv(pdu, offset)
        offset = 0
        _, varbind, _ = _ber_read_tlv(varbinds, offset)
        offset = 0
        _, _oid, offset = _ber_read_tlv(varbind, offset)
        value_tag, value, _ = _ber_read_tlv(varbind, offset)
        if value_tag == 0x04:
            return _clean_text(value, limit=500)
        if value_tag == 0x02:
            return str(int.from_bytes(value, "big", signed=True))
    except (ValueError, IndexError):
        return None
    return None


def probe_udp_service(ip: str, port: int, timeout: float = 1.5) -> ServiceInfo | None:
    """Send a protocol specific UDP probe and return service metadata.

    Returns ``None`` when no response was received.  UDP scanning is inherently
    unreliable; absence of a reply does not prove a port is closed.
    """
    payload: bytes | None = None
    if port == 53:
        payload = build_dns_query("version.bind", qtype=16, qclass=3)
    elif port == 123:
        payload = b"\x1b" + b"\x00" * 47
    elif port == 161:
        payload = build_snmp_get()
    elif port == 1900:
        payload = (
            b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n"
            b'MAN: "ssdp:discover"\r\nMX: 1\r\nST: ssdp:all\r\n\r\n'
        )
    elif port == 5353:
        payload = build_dns_query("_services._dns-sd._udp.local", qtype=12)
    if payload is None:
        return None

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    started = time.perf_counter()
    try:
        sock.sendto(payload, (ip, port))
        response, source = sock.recvfrom(65535)
    except (socket.timeout, TimeoutError):
        return None
    except OSError:
        return None
    finally:
        sock.close()
    if source[0] != ip:
        return None
    elapsed = (time.perf_counter() - started) * 1000
    banner = _clean_text(response)
    service = "unknown"
    product: str | None = None
    version: str | None = None
    extra: str | None = None
    if port == 53:
        service = "dns"
        product, version = _parse_dns_version(response)
    elif port == 123:
        service = "ntp"
        product, version = _parse_ntp(response)
    elif port == 161:
        service = "snmp"
        description = parse_snmp_response(response)
        product, version = "SNMP agent", None
        extra = description
        if description:
            banner = description
    elif port == 1900:
        service = "ssdp"
        product = "UPnP"
        match = re.search(r"Server:\s*(.+)", banner or "", re.IGNORECASE)
        if match:
            extra = match.group(1).strip()
    elif port == 5353:
        service = "mdns"
        product = "mDNS"
    return ServiceInfo(
        port=port,
        protocol="udp",
        state="open",
        service=service,
        product=product,
        version=version,
        extra=extra,
        banner=banner,
        confidence=75 if service != "unknown" else 40,
        method="udp-probe",
        response_ms=elapsed,
    )
