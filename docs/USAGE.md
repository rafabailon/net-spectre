# Net Spectre — Usage Guide

This document is the complete command reference for Net Spectre. It covers installation, the three workflows (network discovery, host scan, report diff), every option, the interactive menu, the report formats, exit codes, privilege requirements and automation examples.

For a short overview see the [README](../README.md); for the internal design see [ARCHITECTURE.md](ARCHITECTURE.md).

> **Authorisation notice**
> Only scan hosts and networks you own or have explicit written permission to test. Port and service scanning can be logged, rate-limited or treated as an attack by intrusion detection systems. See the legal notice in the README.

---

## Contents

1. [Installation](#installation)
2. [Invocation forms](#invocation-forms)
3. [Workflow 1 — network discovery](#workflow-1--network-discovery)
4. [Workflow 2 — host port/service scan](#workflow-2--host-portservice-scan)
5. [Workflow 3 — comparing reports](#workflow-3--comparing-reports)
6. [Target specifications](#target-specifications)
7. [Port specifications and presets](#port-specifications-and-presets)
8. [Interactive menu](#interactive-menu)
9. [Utility commands](#utility-commands)
10. [Reports and log files](#reports-and-log-files)
11. [JSON schema](#json-schema)
12. [Exit codes](#exit-codes)
13. [Privileges and optional tools](#privileges-and-optional-tools)
14. [Environment variables](#environment-variables)
15. [Automation recipes](#automation-recipes)
16. [Troubleshooting](#troubleshooting)

---

## Installation

### Requirements

- Python **3.10 or newer** (3.12 recommended).
- No mandatory third-party Python package.
- Linux, macOS or Windows. Linux/macOS give the richest results (ICMP, ARP, mDNS, NetBIOS, SSDP).

### Run from the source tree

```bash
cd net-spectre
python3 -m src --version
python3 -m src --help
```

No installation step is needed; the package — the `src/` directory — is self-contained. The importable package is named `src`.

### Install as a command

```bash
python3 -m pip install .
net-spectre --version
```

Editable install with optional dependencies:

```bash
python3 -m pip install -e ".[full]"
```

### Optional external tools

| Tool | Enables | Typical install |
| --- | --- | --- |
| `psutil` (Python) | Portable interface enumeration | `pip install psutil` |
| `cryptography` (Python) | Full X.509 parsing | `pip install cryptography` |
| `nmap` | Version/OS detection, NSE, reliable UDP | `sudo apt install nmap` |
| `arp-scan` | Reliable MAC discovery (root) | `sudo apt install arp-scan` |
| `avahi-resolve-address` | mDNS hostname resolution | `sudo apt install avahi-utils` |

Everything is detected at runtime. Missing tools produce a warning in the report and degrade gracefully; they never abort a scan.

---

## Invocation forms

```text
net-spectre [GLOBAL OPTIONS] COMMAND [COMMAND OPTIONS]

Commands:
  network        discover all devices on a network
  host           scan ports and services on one host
  diff           compare two JSON reports
  export         convert a saved JSON report to CSV or text
  interfaces     list interfaces, networks and the default route
  update-oui     download the IEEE MAC vendor registry
  menu           start the interactive menu

Global options:
  -h, --help     show help
  --version      show the version
```

Starting the program **without a command** in a terminal opens the interactive menu. Without a terminal (for example in a pipeline or cron job) it prints help and exits with code `2`.

`python3 -m src` and the installed `net-spectre` command are equivalent.

---

## Workflow 1 — network discovery

```bash
net-spectre network [options]
```

Discovers every device the scanner can observe on an IPv4 network and gathers all information a host can legitimately learn about each device:

- IPv4 address, MAC address and IEEE OUI vendor;
- reverse DNS, mDNS and NetBIOS names;
- latency and TTL (used for a rough OS family guess);
- device type inferred from the gateway role, UPnP metadata, hostname, vendor and open ports;
- open TCP ports with service fingerprints, banners, HTTP metadata and TLS certificate details for each discovered host;
- evidence and data sources for every conclusion, so results are auditable.

### Options

| Option | Description |
| --- | --- |
| `-t`, `--target SPEC` | Network to scan. Defaults to the network of the default interface. Accepts CIDR, range, single IP or a comma-separated combination. |
| `-i`, `--interface NAME` | Interface used to pick the default network and to label the report. |
| `--exclude SPEC` | Addresses to skip, in the same syntax as `--target` (`192.168.1.1`, `192.168.1.10-20`, `192.168.1.0/28`, comma-separated mixtures). |
| `--no-ping` | Skip the ICMP sweep. |
| `--no-tcp-sweep` | Skip the TCP reachability sweep. |
| `--no-arp-scan` | Never call `arp-scan`, even when installed. |
| `--no-ssdp` | Skip SSDP/UPnP discovery. |
| `--no-quick-scan` | Do not scan ports on discovered hosts (much faster). |
| `--quick-ports SPEC` | Ports used to enrich hosts (default: built-in quick set). |
| `--csv` | Also write a flat CSV export of discovered hosts and services. |
| `--timeout SECONDS` | Service probe timeout (default `1.5`). |
| `--port-timeout SECONDS` | TCP connect timeout (default `1.0`). |
| `--concurrency N` | Maximum concurrent TCP connections (default `250`). |
| `--ping-concurrency N` | Maximum concurrent ICMP/TCP sweep workers (default `64`). |
| `--fingerprint-concurrency N` | Maximum concurrent service probes (default `12`). |
| `--max-hosts N` | Safety limit when expanding a target (default `4096`). |
| `-e`, `--engine {native,nmap,auto}` | Scan engine (default `native`). |
| `--no-names` | Disable reverse DNS, mDNS and NetBIOS. |
| `--no-mdns`, `--no-netbios` | Disable individual name lookups. |
| `--log-dir DIR` | Report and diagnostic log directory (default `./logs`). |
| `--no-color` | Disable ANSI colours. |
| `-q`, `--quiet` | Suppress progress messages and the console summary (reports are still written). |
| `-v`, `--verbose` | Debug logging on stderr. |

### Exclusions

`--exclude` removes addresses from the expanded target set before any probing, so excluded hosts are never contacted. It accepts the same forms as `--target`:

```bash
# Skip a handful of infrastructure addresses
net-spectre network -t 192.168.1.0/24 --exclude 192.168.1.1,192.168.1.2

# Skip a printer pool and a management subnet
net-spectre network -t 10.0.0.0/22 --exclude 10.0.0.100-199,10.0.2.0/24
```

The exclusion list is recorded in the report configuration and the skipped addresses are counted so results remain auditable. If every address of the target is excluded, the scan fails with exit code `1` rather than silently doing nothing.

### Discovery pipeline

The scanner combines independent sources; a device found by any source is reported together with the sources that saw it:

1. **ARP/neighbour table** — passive snapshot before probing.
2. **ICMP sweep** — parallel `ping`, records latency and TTL.
3. **TCP reachability sweep** — probes common ports on hosts that ignore ICMP.
4. **`arp-scan`** (optional, root) — finds silent devices and MAC addresses.
5. **Nmap host discovery** (optional, `--engine nmap`) — `nmap -sn`.
6. **SSDP/UPnP** — multicast M-SEARCH, parallel description downloads, merged per-IP device metadata (friendly name, manufacturer, model).
7. **ARP refresh** — the sweeps populate the kernel neighbour table.
8. Local host and default gateway are always included when in scope.
9. **Concurrent name resolution** — PTR, mDNS, NetBIOS.
10. **Quick port scan and fingerprinting** of every discovered host.
11. **Inference** — device type and OS family, with evidence.

### Examples

```bash
# Scan the network of the default interface
net-spectre network

# Scan a /24 and write reports to a custom directory
net-spectre network --target 192.168.1.0/24 --log-dir reports

# Skip the router and the first ten addresses
net-spectre network -t 192.168.1.0/24 --exclude 192.168.1.1-10

# Fast inventory of a range without the per-host port scan
net-spectre network -t 10.0.0.1-254 --no-quick-scan

# Choose the interface explicitly
net-spectre network --interface wlan0

# Use Nmap for discovery when installed
net-spectre network -t 192.168.0.0/24 --engine nmap

# Silence name lookups and lighten the scan
net-spectre network -t 192.168.1.0/24 --no-names --timeout 1

# Only check a handful of ports on every device
net-spectre network -t 192.168.1.0/24 --quick-ports 22,80,443,8080

# Spreadsheet-friendly export, silent progress
net-spectre network -t 192.168.1.0/24 --csv -q
```

### Notes on results

- A device confirmed only by the ARP cache is marked in its notes as potentially stale.
- MAC addresses are only available on the local layer-2 segment. Routed devices cannot be resolved to a MAC.
- SSDP results depend on devices answering multicast; many IoT devices do.
- The "quick" scan set is intentionally small; use `host` for exhaustive per-device enumeration.

---

## Workflow 2 — host port/service scan

```bash
net-spectre host TARGET [options]
```

Scans every requested TCP port of one IPv4 address or hostname, then fingerprints the open services:

- asyncio connect scan with bounded concurrency and timeouts;
- banner grabbing and protocol probes (HTTP, SSH, FTP, SMTP, IMAP, POP3, Telnet, Redis, memcached, RTSP, MQTT, MySQL, VNC, PostgreSQL, …);
- HTTP metadata: status, server header, product/version, `X-Powered-By`, `<title>`, redirect target and selected headers;
- TLS handshake with certificate details: subject, issuer, validity window, days remaining, self-signed/expired flags, serial, SHA-256 fingerprint, SAN list, protocol version and cipher;
- optional best-effort UDP probes (DNS, NTP, SNMP, SSDP, mDNS);
- optional Nmap backend for version detection, NSE banner/title/certificate scripts, OS detection and reliable UDP.

### Options

| Option | Description |
| --- | --- |
| `TARGET` | IPv4 address or hostname (required, positional). |
| `-p`, `--ports SPEC` | Ports: `80`, `80,443`, `1-1024`, `22,8000-8100`. |
| `--preset NAME` | `quick`, `common`, `web`, `database` or `full`. |
| `--full` | Scan all 65,535 TCP ports. |
| `--udp` | Also probe UDP services (best effort). |
| `--udp-ports SPEC` | UDP ports to probe (default `53,123,161,1900,5353`). |
| `--os-detection` | Enable Nmap OS fingerprinting (implies Nmap, needs root). |
| `--csv` | Also write a flat CSV export of the open services. |
| `--fail-on-open` | Exit with code `3` when at least one service is open. |
| `--timeout SECONDS` | Service probe timeout (default `1.5`). |
| `--port-timeout SECONDS` | TCP connect timeout (default `1.0`). |
| `--concurrency N` | Maximum concurrent TCP connections (default `250`). |
| `--ping-concurrency N` | Maximum concurrent ICMP/TCP sweep workers (default `64`). |
| `--fingerprint-concurrency N` | Maximum concurrent service probes (default `12`). |
| `--max-hosts N` | Safety limit when expanding a target (default `4096`). |
| `-e`, `--engine {native,nmap,auto}` | Scan engine (default `native`). |
| `--no-names` | Disable reverse DNS, mDNS and NetBIOS. |
| `--no-mdns`, `--no-netbios` | Disable individual name lookups. |
| `--log-dir DIR` | Report and diagnostic log directory (default `./logs`). |
| `--no-color` | Disable ANSI colours. |
| `-q`, `--quiet` | Suppress progress messages and the console summary. |
| `-v`, `--verbose` | Debug logging on stderr. |

`--full` takes precedence over `--preset`, which takes precedence over `--ports`. If none is given, the curated common port list is used.

`--fail-on-open` is designed for CI and gating: the scan still runs to completion and still writes reports, but the process exits with code `3` when at least one open service was found, letting a caller treat "any open port" as a policy violation.

### Examples

```bash
# Common ports on a LAN device
net-spectre host 192.168.1.1

# Web ports with TLS/HTTP metadata
net-spectre host 192.168.1.1 --preset web

# Explicit port list and ranges
net-spectre host 10.0.0.5 -p 22,80,443,8000-8100

# Full TCP scan with a short connect timeout
net-spectre host 10.0.0.5 --full --port-timeout 0.3

# Add best-effort UDP probes
net-spectre host 10.0.0.5 --udp

# Nmap version detection and OS fingerprinting (root)
sudo net-spectre host 10.0.0.5 --preset common --engine nmap --os-detection

# Scan a hostname and keep reports in a project directory
net-spectre host router.lan -p 1-1024 --log-dir reports/router

# Fail a CI job when anything is listening
net-spectre host 10.0.0.5 -p 1-1024 --fail-on-open -q
```

### Interpreting services

Each service row reports a canonical service name, product/version when it can be determined, a confidence percentage, the detection method (`tcp-connect`, `banner`, `http`, `tls`, `udp`, `nmap`) and the connect/response time.

- `tcp-connect` means the port accepted a connection but no protocol was identified. This is a real open port, not necessarily a known service.
- `tls` means a TLS handshake succeeded on a non-HTTP port.
- `filtered` ports are not listed as open; the report notes the count.
- UDP results are positive-only: a missing reply is inconclusive.

---

## Workflow 3 — comparing reports

```bash
net-spectre diff OLD NEW [options]
```

`diff` loads two JSON reports produced by earlier scans and reports how the second differs from the first. It works with both network and host reports and matches entities by stable keys (host IP, service `(port, protocol)`).

### Options

| Option | Description |
| --- | --- |
| `OLD` | Baseline JSON report (positional). |
| `NEW` | New JSON report (positional). |
| `--json` | Print the diff as JSON instead of a human-readable table. |
| `--fail-on-change` | Exit with code `3` when any difference is found. |
| `--log-dir DIR` | Diagnostic log directory (default `./logs`). |
| `--no-color` | Disable ANSI colours. |
| `-q`, `--quiet` | Suppress progress and the console summary. |
| `-v`, `--verbose` | Debug logging on stderr. |

### What is compared

- **Hosts (network reports):** presence, MAC, vendor, hostnames, device type, OS guess, status and the set of open ports/services.
- **Services (host reports):** the `(port, protocol)` set, service name, product/version, banner and TLS/HTTP metadata.
- Only services in the `open` state participate; closed and filtered rows are ignored so transient results do not create noise.

### Output

The tabular output lists each changed host or service with a `+` (added), `-` (removed) or `~` (changed) marker and the field-level changes. `--json` prints a stable object (one JSON document on stdout) for tooling:

```json
{
  "old_scan_id": "NET-20260101_120000-A1B2C3",
  "new_scan_id": "NET-20260102_120000-D4E5F6",
  "old_mode": "network",
  "new_mode": "network",
  "has_changes": true,
  "change_count": 2,
  "hosts": {
    "added": [{"ip": "192.168.1.50", "hostname": "printer.lan"}],
    "removed": [],
    "changed": [
      {
        "ip": "192.168.1.1",
        "hostname": "router.lan",
        "fields": {
          "vendor": {"old": "Example Networks", "new": "Other Vendor"}
        }
      }
    ]
  },
  "services": {
    "opened": [{"ip": "192.168.1.50", "port": 631, "protocol": "tcp", "service": "ipp"}],
    "closed": [],
    "changed": [
      {"ip": "192.168.1.1", "port": 443, "protocol": "tcp", "old": "https", "new": "https (nginx 1.25.0)"}
    ]
  },
  "warnings": {"added": [], "removed": []}
}
```

`has_changes` is `true` when `change_count` is greater than zero; both are derived from the difference lists.

### Examples

```bash
# Human-readable difference between two network inventories
net-spectre diff logs/network_scan_20260101_120000.json \
                    logs/network_scan_20260102_120000.json

# Machine-readable, exit 3 if anything changed (e.g. in a cron alert)
net-spectre diff old.json new.json --json --fail-on-change -q
```

---

## Workflow 4 — offline report export

```bash
net-spectre export REPORT [options]
```

`export` loads a JSON report written by an earlier `network` or `host` scan and renders it again as CSV or text. It is completely offline: no discovery, probing or name resolution is performed. This is useful when a report was originally written without `--csv`, when an inventory needs to be regenerated in a different format, or when a pipeline wants a text report from an archived JSON file.

### Options

| Option | Description |
| --- | --- |
| `REPORT` | Existing JSON report (positional). Both wrapped reports and bare scan objects are accepted. |
| `-f`, `--format {csv,text}` | Output format (default `csv`). |
| `-o`, `--output PATH` | Output file. Defaults to the report path with a `.csv` or `.txt` suffix. Use `-` to write to stdout. |
| `--force` | Overwrite the output file if it already exists. |
| `--log-dir DIR` | Diagnostic log directory when `-v` is used (default `./logs`). |
| `--no-color` | Disable ANSI colours. |
| `-q`, `--quiet` | Suppress the “Export written” message. |
| `-v`, `--verbose` | Debug logging on stderr. |

### Behaviour

- The JSON is parsed into the same typed model used by the scanners (`NetworkScanResult` or `HostScanResult`), so the output matches a fresh report as closely as the stored data allows.
- `csv` uses the shared flat schema described under [CSV export](#csv-export); `text` produces the normal human-readable report.
- The default output is a sibling of the input: `report.json` becomes `report.csv` or `report.txt`.
- Existing output files are never overwritten unless `--force` is given, and the output path may not be the input report itself.
- Writes are atomic. A missing, unreadable or malformed report exits with code `1`.

### Examples

```bash
# Convert the newest network report to CSV next to the JSON file
net-spectre export logs/network_scan_20260101_120000.json

# Produce a text report with an explicit name
net-spectre export logs/host_scan_192_168_1_1_20260101_120000.json \
    --format text --output reports/router.txt

# Stream CSV to another process
net-spectre export report.json --format csv --output - | column -t -s,

# Regenerate an inventory, replacing yesterday's file
net-spectre export report.json --output /var/lib/inventory/current.csv --force
```

---

## Target specifications

`network --target` accepts:

| Form | Example |
| --- | --- |
| Single address | `192.168.1.10` |
| CIDR network | `192.168.1.0/24` |
| Last-octet range | `192.168.1.10-20` |
| Full range | `192.168.1.10-192.168.1.20` |
| Comma-separated mixture | `10.0.0.1,10.0.0.5,10.0.0.10-20` |

CIDR host bits are ignored, so `192.168.1.7/24` scans the whole /24. `/31` and `/32` are handled as usable addresses. The expansion is capped by `--max-hosts` (default `4096`) to prevent accidental scans of very large ranges.

`network --exclude` accepts the same forms and removes matching addresses from the expanded target list before probing.

`host TARGET` accepts a single IPv4 address or a hostname that resolves to one. IPv6 is not supported.

---

## Port specifications and presets

Port specs accept commas and whitespace:

```text
80
80,443
1-1024
22,8000-8100,3306
```

Presets (for `host --preset`):

| Preset | Contents |
| --- | --- |
| `quick` | About 50 high-value ports; also used by network discovery. |
| `common` | Curated list of well-known and commonly exposed ports. |
| `web` | HTTP/HTTPS and common alternative web ports. |
| `database` | Database, cache and search service ports. |
| `full` | All 65,535 TCP ports. |

The default when no selection is given is the `common` set.

---

## Interactive menu

```bash
net-spectre            # opens the menu when run in a terminal
net-spectre menu       # force the menu
```

```text
Main menu
  [1] Scan the local network (discover all devices)
  [2] Scan a host (ports, services, TLS/HTTP metadata)
  [3] Show interfaces and local networks
  [4] Settings
  [5] Update MAC vendor database (IEEE OUI)
  [0] Exit
```

- **Network scan** lists detected networks; enter the number of a network or type any supported target. You can enable or disable the per-host quick scan.
- **Host scan** asks for the target and a port set: quick, common, web, database, full or a custom specification. It also asks whether to probe UDP and to attempt Nmap OS detection.
- **Settings** changes the service timeout, TCP concurrency, sweep concurrency, fingerprint concurrency, name resolution, log directory and scan engine for the current session.
- **Update OUI** downloads the IEEE registry into the local cache.

The menu stays alive after errors and returns to the main menu. `Ctrl+C` cancels the current action; entering `0` exits.

---

## Utility commands

### `interfaces`

```bash
net-spectre interfaces
```

Prints interfaces (IPv4, MAC, state, MTU), local networks (interface, address, CIDR, gateway, MAC) and the default route.

### `update-oui`

```bash
net-spectre update-oui
```

Downloads the IEEE OUI CSV registry into the local cache and reports the number of vendor prefixes. The cache path is `$XDG_CACHE_HOME/net_spectre/oui.txt` when `XDG_CACHE_HOME` is set, otherwise `~/.cache/net_spectre/oui.txt`. This improves vendor lookup for the network discovery workflow.

Both utilities accept `--log-dir`, `--no-color` and `-v`.

---

## Reports and log files

Every scan writes two files plus a shared diagnostic log, and an optional third when CSV export is enabled:

```text
logs/
├── net_spectre.log                                   # rotating diagnostic log
├── network_scan_20261022_200437.log                  # human-readable report
├── network_scan_20261022_200437.json                 # machine-readable result
├── network_scan_20261022_200437.csv                  # optional flat export
├── host_scan_192_168_1_1_20261022_201000.log
└── host_scan_192_168_1_1_20261022_201000.json
```

- File names use the scan start time in **UTC** (`YYYYmmdd_HHMMSS`). Host report names embed the IP with dots replaced by underscores.
- Existing files are never overwritten. A `_2`, `_3`, … suffix is added if two scans start in the same second (checked across `.log`, `.json` and `.csv`).
- Writes are atomic: content goes to a temporary file which is then renamed.
- `--log-dir` (or `NET_SPECTRE_LOG_DIR`) changes the destination. The directory is created automatically.
- The diagnostic log rotates at 2 MiB with three backups and always records DEBUG-level detail.

### Text report contents

- scan metadata: ID, version, engine, UTC start/finish, duration, interface, local IP, gateway, network, target count;
- effective configuration (including any `--exclude` list and excluded count);
- device table and detailed per-host sections: status, MAC, vendor, hostnames, device type, OS guess, latency, TTL, gateway flag, data sources, evidence, open ports, services, banners, HTTP metadata, TLS details, notes;
- warnings for missing tools or partial failures.

### CSV export

`--csv` writes a single flat table (one file per scan) that loads directly into spreadsheets, `awk` or databases. Both report types share the same columns:

```text
report, scan_id, ip, mac, vendor, hostname, device_type, os_guess,
latency_ms, ttl, gateway, port, protocol, state, service, product, version,
confidence, method, response_ms, tls_subject, tls_issuer, tls_not_after,
http_status, http_title, notes
```

There is **one row per open service**; a host with no detected service still produces a single row with the service columns left empty, so no host is lost. The `report` column holds `network` or `host`, and `notes` joins the host's notes/evidence (network) or the scan warnings (host).

---

## JSON schema

Each JSON report is a stable envelope around the scan result:

```json
{
  "generator": "Net Spectre",
  "report_version": 1,
  "scan": {
    "scan_id": "NET-20261022_200437-A1B2C3",
    "mode": "network",
    "tool_version": "1.2.0",
    "started_at": "2026-10-22T20:04:37+00:00",
    "finished_at": "2026-10-22T20:04:46+00:00",
    "duration_s": 9.043,
    "interface": "wlan0",
    "local_ip": "192.168.1.42",
    "gateway": "192.168.1.1",
    "network": "192.168.1.0/24",
    "targets_scanned": 254,
    "hosts_up": 8,
    "warnings": [],
    "config": { "...": "effective settings" },
    "summary": {
      "hosts_up": 8,
      "hosts_total": 254,
      "services_found": 21,
      "ports_scanned": 0,
      "duration_s": 9.043
    },
    "hosts": [
      {
        "ip": "192.168.1.1",
        "mac": "aa:bb:cc:dd:ee:ff",
        "vendor": "Example Networks",
        "hostname": "router.lan",
        "mdns_name": null,
        "netbios_name": null,
        "status": "up",
        "latency_ms": 1.42,
        "ttl": 64,
        "os_guess": "Linux / Unix / macOS / Android (TTL 64)",
        "device_type": "Router / gateway",
        "is_gateway": true,
        "sources": ["gateway", "icmp", "arp-cache", "name-resolution"],
        "evidence": ["default gateway is 192.168.1.1", "..."],
        "open_ports": [22, 80, 443],
        "services": [
          {
            "port": 443,
            "protocol": "tcp",
            "state": "open",
            "service": "https",
            "product": null,
            "version": null,
            "extra": null,
            "banner": null,
            "confidence": 85,
            "method": "tls",
            "response_ms": 1.73,
            "tls": {
              "subject": "CN=router.lan",
              "issuer": "CN=router.lan",
              "version": "TLSv1.2",
              "cipher": "ECDHE-RSA-AES128-GCM-SHA256",
              "not_before": "2024-01-01T00:00:00+00:00",
              "not_after": "2025-01-01T00:00:00+00:00",
              "days_remaining": -660,
              "expired": true,
              "self_signed": true,
              "serial_number": "01",
              "sha256_fingerprint": "AA:BB:...",
              "san": ["router.lan"]
            },
            "http": null
          }
        ],
        "notes": []
      }
    ]
  }
}
```

Host scans use the same envelope with `"mode": "host"` and these top-level scan fields: `target`, `resolved_ip`, `hostname`, `mac`, `vendor`, `latency_ms`, `ttl`, `os_guess`, `device_type`, `is_gateway`, `ports_scanned`, `open_ports`, `engine`, `warnings`, `config`, `summary` and `services`.

Fields are additive within `report_version: 1`; consumers should ignore unknown keys.

---

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Success (a scan completed, even if no hosts/ports were found). |
| `1` | Scan or runtime error (unresolvable target, no usable network, all targets excluded, tool failure, unreadable report, failed export write). |
| `2` | Usage error (invalid option, invalid target/port specification, export output equals input), or no TTY with no command. |
| `3` | Findings present and requested: `host --fail-on-open` or `diff --fail-on-change`. |
| `130` | Interrupted with `Ctrl+C`. |

Reports are written only after a scan completes. A scan that finds nothing is still a success and still produces reports.

---

## Privileges and optional tools

Net Spectre runs entirely as an unprivileged user with reduced capabilities:

| Feature | Privileges | Fallback |
| --- | --- | --- |
| ICMP ping | Non-root on Linux (unprivileged ICMP sockets) | TCP sweep |
| TCP connect scan | None | — |
| ARP cache read | None | — |
| `arp-scan` | root | ARP cache / Nmap |
| Nmap SYN scan (`-sS`) | root | connect scan (`-sT`) |
| Nmap OS detection (`-O`) | root | TTL heuristic |
| Nmap UDP scan (`-sU`) | root | native UDP probes |
| UDP probes (native) | None | — |

Running as root improves completeness but is not required. When a privileged feature is unavailable, the reason is recorded in the report's warnings.

---

## Environment variables

| Variable | Description |
| --- | --- |
| `NET_SPECTRE_TIMEOUT` | Service probe timeout in seconds. |
| `NET_SPECTRE_PORT_TIMEOUT` | TCP connect timeout in seconds. |
| `NET_SPECTRE_CONCURRENCY` | Maximum concurrent TCP connections. |
| `NET_SPECTRE_PING_CONCURRENCY` | Maximum concurrent ICMP/TCP sweep workers. |
| `NET_SPECTRE_FINGERPRINT_CONCURRENCY` | Maximum concurrent service probes. |
| `NET_SPECTRE_MAX_HOSTS` | Target expansion limit. |
| `NET_SPECTRE_ENGINE` | `native`, `nmap` or `auto`. |
| `NET_SPECTRE_LOG_DIR` | Default report/log directory. |
| `NET_SPECTRE_OUI_FILE` | Path to an additional/custom OUI database. |
| `NO_COLOR` | Disable ANSI colours (standard convention). |

Command-line options override environment variables. Invalid values are ignored and the defaults are used.

---

## Automation recipes

### JSON post-processing

```bash
net-spectre network -t 192.168.1.0/24 --no-color -q
report=$(ls -t logs/network_scan_*.json | head -1)
python3 - "$report" <<'PY'
import json, sys
scan = json.load(open(sys.argv[1]))["scan"]
for host in scan["hosts"]:
    ports = ",".join(str(port) for port in host["open_ports"]) or "-"
    print(f"{host['ip']:16} {host['mac'] or '-':18} {host['device_type'] or '-':28} {ports}")
PY
```

### Inventory a subnet with CSV

```bash
net-spectre network -t 192.168.1.0/24 --no-quick-scan --csv --log-dir /var/lib/inventory -q
latest=$(ls -t /var/lib/inventory/network_scan_*.csv | head -1)
# Columns: 3=ip 4=mac 5=vendor 6=hostname
cut -d, -f3,4,5,6 "$latest" | column -t -s,
```

### Export an archived report

```bash
# Convert the most recent JSON report to CSV without scanning again
latest=$(ls -t logs/network_scan_*.json | head -1)
net-spectre export "$latest" --format csv --output - | column -t -s,
```

### Alert on network changes

```bash
#!/usr/bin/env bash
set -euo pipefail

dir=/var/lib/inventory
net-spectre network -t 192.168.1.0/24 --log-dir "$dir" -q
new=$(ls -t "$dir"/network_scan_*.json | head -1)
old=$(ls -t "$dir"/network_scan_*.json | sed -n 2p)

# Exit 3 means something changed; send an alert without failing the script
if ! net-spectre diff "$old" "$new" --json --fail-on-change -q \
        > "$dir/latest-diff.json"; then
    echo "inventory changed:" >&2
    cat "$dir/latest-diff.json" >&2
fi
```

### Gate a deployment on open ports

```bash
# Fail the build (exit 3) if the service exposes anything beyond 443
net-spectre host api.internal -p 1-10000 --fail-on-open -q --no-color \
    || echo "open ports detected"
```

### Full port scan with a strict timeout

```bash
net-spectre host 10.0.0.5 --full --port-timeout 0.2 --concurrency 500
```

### Cron-friendly (no colours, quiet, explicit directory)

```bash
0 3 * * * cd /opt/net-spectre && \
  /usr/bin/python3 -m src network -t 10.0.0.0/24 \
  --no-color -q --log-dir /var/log/net-spectre >>/var/log/net-spectre/cron.log 2>&1
```

Progress goes to stderr, so redirecting stdout alone keeps machine-readable output separate. Report paths are printed on stdout at the end of every scan (unless `-q/--quiet` is used).

---

## Troubleshooting

| Symptom | Cause / fix |
| --- | --- |
| No devices found | ICMP may be filtered. Keep the TCP sweep enabled, install `arp-scan`, run as root, or use Nmap discovery. |
| Missing MAC addresses | The device is behind a router or on another layer-2 segment. MAC discovery only works locally. |
| Vendor "unknown" | Run `net-spectre update-oui` to fetch the IEEE registry, or set `NET_SPECTRE_OUI_FILE`. |
| Scan is slow | Add `--no-quick-scan`, reduce `--timeout`/`--port-timeout`, narrow the target, or add `--no-names`. |
| Nmap warnings | `nmap` is not installed or is not on `PATH`; install it or use `--engine native`. |
| OS detection fails | Requires `nmap` and root. Otherwise the TTL heuristic is used. |
| UDP results are sparse | UDP has no handshake; only replies are reported. Nmap with root improves coverage. |
| "Permission denied" for arp-scan | Run as root or disable `arp-scan`. The ARP cache is still used. |
| Port 443 shows `tls` but no HTTP data | The service speaks TLS but did not answer an HTTP request. It may not be a web server. |
| `diff` reports no changes | Only `open` services participate; ensure you compare reports of the same mode. |
| Reports not created | Check write permission for `--log-dir`. Errors are printed to stderr and the scan exits with code `1`. |
| `export` refuses to write | The output file exists (`--force` to replace it) or the report is missing/malformed. |
| Open ports seem missing | Some firewalls drop probes, producing `filtered` results. Increase `--port-timeout`. |
