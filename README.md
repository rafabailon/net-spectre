# Net Spectre

Net Spectre is a dependency-light network inventory and service enumeration tool written in Python. It provides four workflows:

1. **Network discovery** – find every device on a local IPv4 network and collect all the information a host can legitimately learn about it.
2. **Host scan** – scan a single IP address or hostname for open TCP (and optionally UDP) ports, then fingerprint the exposed services.
3. **Diff** – compare two saved reports and list what appeared, vanished or changed between them.
4. **Export** – convert an existing JSON report to a flat CSV table or a human-readable text report, completely offline.

Every scan writes a human-readable **`.log`** report and a machine-readable **`.json`** document, with an optional flat **`.csv`** export for spreadsheets and pipelines. A rotating diagnostic log records what the scanner did.

> **Legal notice**
> Net Spectre is intended for authorised security testing, asset inventory and education. Only scan networks and devices that you own or have explicit written permission to test. Unauthorised scanning may be illegal in your jurisdiction. The authors accept no liability for misuse.

---

## Features

### Network discovery

- ICMP sweep, TCP reachability sweep and the kernel ARP/neighbour table.
- Optional `arp-scan` and Nmap host discovery when installed.
- SSDP/UPnP discovery with parallel description downloads and per-device deduplication.
- Reverse DNS, mDNS/avahi and NetBIOS name resolution (all concurrent).
- MAC address normalisation and IEEE OUI vendor lookup with a built-in offline fallback table.
- Optional quick port scan and service fingerprinting of every discovered host.
- Device type inference from gateway role, UPnP metadata, hostname, vendor and open ports; OS family heuristic from TTL and banners.
- Interface, local network and default gateway detection.
- Target exclusions (`--exclude`) so known infrastructure can be skipped.

### Host scanning

- Asyncio TCP connect scanner with configurable concurrency and timeouts.
- Curated, quick, web, database and full (all 65,535 ports) presets, plus arbitrary port specifications such as `22,80,443,8000-8100`.
- Read-only service probes for HTTP/HTTPS, SSH, FTP, SMTP, IMAP, POP3, Telnet, Redis, memcached, RTSP, MQTT, PostgreSQL, VNC, MySQL and more.
- HTTP metadata (status, server, title, `X-Powered-By`, redirect, headers).
- TLS handshake, certificate details (subject, issuer, validity, SAN, SHA-256 fingerprint, self-signed/expired status) and cipher/version.
- Best-effort UDP probes for DNS, NTP, SNMP, SSDP and mDNS.
- Optional Nmap backend for version detection, NSE banner scripts, OS fingerprinting and reliable UDP scans.

### Comparing reports

- `diff` matches hosts and services across two JSON reports by stable keys.
- Reports added, removed and changed hostnames, vendors, ports and services.
- Human-readable table or `--json` output for machine consumers.
- `--fail-on-change` turns any difference into exit code `3` for CI and monitoring.

### Exporting reports

- `export` converts a saved JSON report to **CSV** or **text** without rescanning.
- Output defaults to a sibling file (`.csv` or `.txt`); `--output -` streams to stdout.
- Existing files are protected by default; `--force` opts into overwriting.
- Both network and host reports are supported through the same typed loader used by `diff`.

### Robustness

- No mandatory third-party Python dependencies; the standard library is enough.
- Every external tool and optional library is detected at runtime and every failure degrades gracefully with a recorded warning.
- Bounded timeouts throughout; progress is written to stderr so stdout can be piped safely. `-q/--quiet` silences progress and the console summary while still writing reports.
- Untrusted device strings are sanitised before they reach reports or terminals.
- Atomic report writes; existing reports are never overwritten.
- Reports and diagnostics are written under `logs/` by default.

---

## Requirements

- Python **3.10+** (tested with 3.12).
- Linux, macOS or Windows. Linux and macOS provide the richest results.
- No mandatory Python packages.

Optional enhancements:

| Component | Purpose | Privileges |
| --- | --- | --- |
| `psutil` | Faster, more portable interface enumeration | none |
| `cryptography` | Complete X.509 certificate parsing | none |
| `nmap` | Version/OS detection, NSE scripts, reliable UDP | root for `-sS`, `-sU`, `-O` |
| `arp-scan` | Fast and reliable MAC discovery | root |
| `avahi-resolve-address` | mDNS hostname resolution | none |

Install the optional Python extras with:

```bash
python3 -m pip install -e ".[full]"
```

On Debian/Ubuntu the external tools are available as:

```bash
sudo apt install nmap arp-scan avahi-utils
```

---

## Installation

Net Spectre runs directly from the source tree:

```bash
cd net-spectre
python3 -m src --version
```

Or install it as a package (provides the `net-spectre` command):

```bash
python3 -m pip install .
net-spectre --version
```

For development, install in editable mode:

```bash
python3 -m pip install -e ".[full]"
```

---

## Quick start

### Interactive menu

```bash
python3 -m src
# or explicitly
python3 -m src menu
```

The menu offers network discovery, host scanning, interface information, settings (timeouts, concurrency, engine, log directory) and OUI updates.

### Discover the local network

```bash
python3 -m src network
```

Use a CIDR, an IP range, a single address or a comma-separated combination:

```bash
python3 -m src network --target 192.168.1.0/24
python3 -m src network --target 192.168.1.1-50
python3 -m src network --target 10.0.0.1,10.0.0.5,10.0.0.10-20
```

Skip addresses you must not touch:

```bash
python3 -m src network -t 192.168.1.0/24 --exclude 192.168.1.1-10
```

Disable the per-host quick port scan for a faster inventory:

```bash
python3 -m src network --target 192.168.1.0/24 --no-quick-scan
```

### Scan one host

```bash
python3 -m src host 192.168.1.1
python3 -m src host 192.168.1.1 --preset web
python3 -m src host 192.168.1.1 -p 1-1024
python3 -m src host 192.168.1.1 --full
python3 -m src host 192.168.1.1 --udp
python3 -m src host 192.168.1.1 --preset full --engine nmap --os-detection
```

### Compare two reports

```bash
python3 -m src diff logs/network_scan_20260101_120000.json \
                    logs/network_scan_20260102_120000.json
```

### Export a saved report

```bash
python3 -m src export logs/network_scan_20260101_120000.json            # CSV next to the source
python3 -m src export report.json --format text                          # text report (.txt)
python3 -m src export report.json --format csv --output -                # write CSV to stdout
python3 -m src export report.json --output inventory.csv --force         # explicit path, overwrite
```

### Utilities

```bash
python3 -m src interfaces          # interfaces, networks, default route
python3 -m src update-oui          # download the IEEE OUI registry
```

---

## Reports

Every scan writes two files to `logs/` (configurable with `--log-dir`), and a third when CSV export is enabled:

```text
logs/
├── net_spectre.log                                 # rotating diagnostic log
├── network_scan_20261022_200437.log                # human-readable report
├── network_scan_20261022_200437.json               # machine-readable result
├── network_scan_20261022_200437.csv                # optional flat export
├── host_scan_192_168_1_1_20261022_201000.log
└── host_scan_192_168_1_1_20261022_201000.json
```

Add `--csv` to `network` or `host` to also write a flattened CSV table of hosts and services. A report can be converted later with `export`, which never touches the network. The text report contains:

- scan metadata (ID, timestamps, duration, interface, gateway, target count);
- the effective configuration;
- a device table and detailed per-host sections (MAC, vendor, hostnames, device type, OS guess, latency, TTL, evidence, open ports, services, TLS/HTTP metadata, banners, notes);
- warnings produced by unavailable tools or partial failures.

The JSON document has a stable envelope:

```json
{
  "generator": "Net Spectre",
  "report_version": 1,
  "scan": {
    "scan_id": "NET-...",
    "mode": "network",
    "hosts": [ ... ],
    "summary": { ... }
  }
}
```

See [docs/USAGE.md](docs/USAGE.md) for the full command reference and [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the internal design.

---

## Common options

| Option | Description |
| --- | --- |
| `--log-dir DIR` | Directory for reports and the diagnostic log (default `./logs`). |
| `--timeout SECONDS` | Service probe/read timeout (default `1.5`). |
| `--port-timeout SECONDS` | TCP connect timeout (default `1.0`). |
| `--concurrency N` | Maximum concurrent TCP connections (default `250`). |
| `--ping-concurrency N` | Maximum concurrent ICMP/TCP sweep workers (default `64`). |
| `--fingerprint-concurrency N` | Maximum concurrent service probes (default `12`). |
| `--max-hosts N` | Safety limit when expanding a target (default `4096`). |
| `-e`, `--engine {native,nmap,auto}` | Scan engine (default `native`). |
| `--csv` | Also write a flat CSV export (network and host). |
| `-q`, `--quiet` | Suppress progress and the console summary. |
| `--no-names` | Disable reverse DNS, mDNS and NetBIOS. |
| `--no-mdns`, `--no-netbios` | Disable individual name lookups. |
| `--no-color` | Disable ANSI colours. |
| `-v`, `--verbose` | Enable debug logging on stderr. |

Network-specific options: `--target`, `--interface`, `--exclude`, `--no-ping`, `--no-tcp-sweep`, `--no-arp-scan`, `--no-ssdp`, `--no-quick-scan`, `--quick-ports`.

Host-specific options: `-p/--ports`, `--preset`, `--full`, `--udp`, `--udp-ports`, `--os-detection`, `--fail-on-open`.

Diff-specific options: `--json`, `--fail-on-change`.

Export-specific options: `REPORT` (positional JSON report), `-f/--format {csv,text}`, `-o/--output PATH` (`-` for stdout), `--force`.

---

## Environment variables

| Variable | Description |
| --- | --- |
| `NET_SPECTRE_TIMEOUT` | Service timeout in seconds. |
| `NET_SPECTRE_PORT_TIMEOUT` | TCP connect timeout in seconds. |
| `NET_SPECTRE_CONCURRENCY` | TCP concurrency. |
| `NET_SPECTRE_PING_CONCURRENCY` | ICMP/TCP sweep concurrency. |
| `NET_SPECTRE_FINGERPRINT_CONCURRENCY` | Fingerprint concurrency. |
| `NET_SPECTRE_MAX_HOSTS` | Target expansion limit. |
| `NET_SPECTRE_ENGINE` | `native`, `nmap` or `auto`. |
| `NET_SPECTRE_LOG_DIR` | Default report/log directory. |
| `NET_SPECTRE_OUI_FILE` | Extra OUI database path. |
| `NO_COLOR` | Disable colours (standard convention). |

Command-line options take precedence over environment variables.

---

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Success (a scan completed, even if nothing was found). |
| `1` | Scan or runtime error. |
| `2` | Usage error (invalid option, invalid target/port spec) or no TTY with no command. |
| `3` | Findings requested with `--fail-on-open` (host) or `--fail-on-change` (diff). |
| `130` | Interrupted with `Ctrl+C`. |

---

## Testing

The test suite uses only the standard library:

```bash
python3 -m unittest discover -s tests -v
```

It covers target and port parsing, exclusions, MAC/OUI handling, DNS/mDNS/NetBIOS wire formats, HTTP and banner classification, SNMP/DNS/NTP parsing, Nmap XML parsing, model round-trips, report rendering/writing (including CSV), offline export, report diffing, configuration handling and CLI parsing.

A syntax check of the whole package:

```bash
python3 -m compileall -q src
```

With coverage:

```bash
make coverage        # or: python3 -m coverage run -m unittest discover -s tests
```

---

## Troubleshooting

- **No devices found:** some networks block ICMP; rely on the TCP sweep, ARP cache and `arp-scan`. Run a discovery scan without `--no-tcp-sweep`.
- **Missing MAC addresses:** ARP data is only available for hosts on the same layer-2 segment. Install `arp-scan` and run as root for the best coverage.
- **Vendor shown as unknown:** run `python3 -m src update-oui` to download the full IEEE registry.
- **OS detection fails:** Nmap OS fingerprinting requires `nmap` and root.
- **UDP results are sparse:** UDP has no handshake; only positive replies are reported. Nmap with root gives better coverage.
- **Scan is slow:** use `--no-quick-scan`, reduce `--timeout`, narrow the target range, or disable name resolution with `--no-names`.

---

## Project layout

```text
net-spectre/
├── src/                  # the importable package (import path: src.*)
│   ├── __init__.py       # package metadata (__version__)
│   ├── __main__.py       # enables `python3 -m src`
│   ├── cli.py            # argument parsing, commands and interactive menu
│   ├── config.py         # ScanConfig with validation and env overrides
│   ├── constants.py      # ports, probes, signatures and inference rules
│   ├── diffing.py        # compare two JSON reports
│   ├── discovery.py      # NetworkScanner / HostScanner orchestration
│   ├── fingerprint.py    # TCP/UDP service probes and classification
│   ├── logging_setup.py  # rotating diagnostic log
│   ├── models.py         # typed results with JSON serialisation and loading
│   ├── names.py          # reverse DNS, mDNS, NetBIOS, target resolution
│   ├── network.py        # interfaces, routes, ARP, ping/TCP sweeps, SSDP
│   ├── oui.py            # OUI database loading/download and vendor lookup
│   ├── portscan.py       # asyncio TCP/UDP engines and Nmap XML parsing
│   ├── reporting.py      # text/JSON/CSV reports, offline export, console output
│   ├── utils.py          # parsing, target expansion, subprocess and colours
│   └── py.typed          # PEP 561 typing marker
├── docs/                 # usage and architecture documentation
├── logs/                 # reports and the diagnostic log (gitignored)
├── tests/                # unittest suite
├── Makefile              # common development tasks
├── pyproject.toml        # packaging metadata and entry point
└── requirements.txt      # optional dependency hints
```

---

## License

MIT. See [LICENSE](LICENSE).
