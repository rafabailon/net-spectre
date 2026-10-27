# Net Spectre — Architecture

This document describes how Net Spectre is structured, how data flows through the scanning workflows, how concurrency and failure handling work, and where to extend the tool. It is written for contributors and reviewers.

---

## Contents

1. [Design goals](#design-goals)
2. [Package map](#package-map)
3. [Dependency strategy](#dependency-strategy)
4. [Data model](#data-model)
5. [Workflow 1: network discovery](#workflow-1-network-discovery)
6. [Workflow 2: host scan](#workflow-2-host-scan)
7. [Workflow 3: report diff](#workflow-3-report-diff)
8. [Workflow 4: offline export](#workflow-4-offline-export)
9. [Concurrency model](#concurrency-model)
10. [Error handling and degradation](#error-handling-and-degradation)
11. [Safety and security](#safety-and-security)
12. [Reporting pipeline](#reporting-pipeline)
13. [Extension points](#extension-points)
14. [Testing strategy](#testing-strategy)
15. [Known limitations](#known-limitations)

---

## Design goals

1. **Complete within the rules.** Gather everything a host can learn through benign, read-only techniques, and clearly show the evidence and data source for each conclusion.
2. **Dependency-light.** The standard library is sufficient. Optional tools and libraries improve results but are never required.
3. **Robust.** Every external call is bounded by a timeout. Any component can fail without aborting the scan; failures become warnings in the report.
4. **Never destructive.** Only connect scans and read-only protocol handshakes are used. No authentication attempts, no exploitation, no writes.
5. **Auditable output.** Every scan produces a human-readable report and a machine-readable JSON document with configuration, timestamps and warnings.
6. **Safe by default.** Conservative timeouts and concurrency, bounded target expansion, no shell execution, sanitised untrusted strings.

---

## Package map

The importable package is the `src/` directory itself, so every module is imported as `src.<module>` (for example `from src.config import ScanConfig`).

```text
src/
├── __init__.py        package metadata (__version__)
├── __main__.py        enables `python3 -m src`
├── cli.py             argparse tree, command handlers, interactive menu
├── config.py          ScanConfig dataclass, validation, env overrides
├── constants.py       port knowledge base, probes, signatures, inference rules
├── diffing.py         report loading, structural comparison, diff rendering
├── discovery.py       NetworkScanner and HostScanner orchestration
├── fingerprint.py     TCP/UDP service probes, HTTP/TLS parsing, classification
├── logging_setup.py   rotating diagnostic logger
├── models.py          typed result dataclasses with to_dict()/from_dict()
├── names.py           reverse DNS, mDNS, NetBIOS, target resolution
├── network.py         interfaces, routes, ARP, ping/TCP sweeps, SSDP
├── oui.py             OUI database loading, download and vendor lookup
├── portscan.py        asyncio TCP/UDP engines, Nmap command/XML handling
├── reporting.py       text/JSON/CSV renderers, report loading/export, atomic writers
├── utils.py           parsing, target expansion, subprocess, formatting, colour
└── py.typed           PEP 561 typing marker
```

### Responsibility boundaries

| Layer | Modules | Responsibility |
| --- | --- | --- |
| Interface | `cli.py`, `__main__.py` | Parse arguments, run commands, render progress, choose exit codes. |
| Orchestration | `discovery.py` | Compose discovery/scanning primitives into the two workflows; infer device type and OS. |
| Primitives | `network.py`, `portscan.py`, `fingerprint.py`, `names.py`, `oui.py` | Perform one kind of network operation and return typed data. |
| Comparison | `diffing.py` | Load saved report dictionaries and compute a structural difference; no network access. |
| Cross-cutting | `config.py`, `constants.py`, `utils.py`, `logging_setup.py` | Configuration, static knowledge, helpers, diagnostics. |
| Output | `models.py`, `reporting.py` | Stable data model, text/JSON/CSV/console rendering, typed report reloading and offline export. |

Dependencies point downward: `cli` → `discovery` → primitives → `utils`. `diffing` operates on plain report dictionaries and `utils`, so it can be used independently of a scan; `reporting` reuses its `load_report()` for offline export. Primitives never import `cli` or `discovery`, so they can be used as a library.

---

## Dependency strategy

- **Mandatory:** Python standard library only.
- **Optional Python:** `psutil` (interface enumeration), `cryptography` (full X.509 parsing). Both are imported lazily and guarded; absence falls back to `/proc`, `ifconfig`/`ip` parsing and the standard `ssl` module.
- **Optional executables:** `nmap`, `arp-scan`, `avahi-resolve-address`. Each is located with `shutil.which` only when needed. Commands are executed as argument lists (never through a shell).
- **Optional system data:** OUI databases shipped by `arp-scan`, `nmap` or `ieee-data`, plus a small embedded fallback table.

This keeps installation trivial and makes behavior predictable on minimal systems, containers and non-root accounts.

---

## Data model

`models.py` contains dataclasses with `to_dict()` methods, so serialisation never needs a custom JSON encoder. Every model also has a tolerant `from_dict()` classmethod, which is what allows saved reports to be reloaded into typed objects for offline export.

```text
ServiceInfo ──┬── TlsCertificate
              └── HttpInfo

HostInfo ────────── list[ServiceInfo]

NetworkScanResult ─ list[HostInfo]
HostScanResult ──── list[ServiceInfo]
        │
        └── ScanSummary (derived property)
```

Key behaviors:

- `HostInfo.merge()` combines observations of the same device without overwriting known values; services merge by `(port, protocol)`, and an existing service always wins over a later, less specific one.
- `HostInfo.open_ports`, `HostScanResult.summary` and `NetworkScanResult.summary` are derived properties, not stored state.
- `_clean()` in `models.py` recursively converts containers, though the explicit `to_dict()` methods are what reporting uses.
- `from_dict()` skips malformed service/host rows instead of discarding an entire report; derived fields such as `open_ports` and `summary` are ignored on load and recomputed.
- JSON field names are part of the public contract (`report_version: 1`). Add fields, do not rename or repurpose existing ones.

---

## Workflow 1: network discovery

Entry point: `NetworkScanner.scan(target, interface, exclude)` in `discovery.py`.

```text
CLI / library
     │
     ▼
_resolve_network() ── detect interfaces & default route (network.py)
     │                 or accept an explicit target
     ▼
expand_targets() ───── CIDR / range / list validation (utils.py)
     │
     ▼
exclude_targets() ──── remove --exclude matches (utils.py)
     │                 (ScanError if nothing remains)
     ▼
┌──────────────────────── discovery sources (independent, fail-safe) ─────────┐
│ 1. neighbor_table()      passive ARP snapshot                              │
│ 2. ping_sweep()          parallel ICMP, latency + TTL                      │
│ 3. tcp_sweep()           parallel TCP probes for ICMP-blocking hosts       │
│ 4. arp_scan()            optional root arp-scan, adds silent devices/MACs   │
│ 5. nmap_discover()       optional nmap -sn                                  │
│ 6. ssdp_discover()       M-SEARCH + parallel description fetch, merged/IP   │
│ 7. neighbor_table()      refresh after active probing                      │
└────────────────────────────────────────────────────────────────────────────┘
     │  hosts: dict[ip, HostInfo]
     ▼
gateway/local host injection (if in scope)
     │
     ▼
_resolve_host_details() ── ThreadPoolExecutor:
     │                      reverse DNS + mDNS + NetBIOS per host (concurrent)
     │                      MAC → OUI vendor
     ▼
_scan_quick_ports() ───── batched asyncio TCP connect sweep over quick_ports
     │                      then concurrent probe_service() in threads
     ▼
infer_device_type() ───── gateway > UPnP > hostname > vendor > open ports
infer_os() ────────────── nmap result > TTL heuristic + service hints
     │
     ▼
NetworkScanResult ─────── ordered by IP, warnings, config, timings
     │
     ▼
reporting.write_reports()
```

Important details:

- Every source adds to the same `hosts` dictionary, so a device seen by several techniques appears once with all `sources` and `evidence` recorded.
- SSDP response merging happens inside `ssdp_discover()`; a device exposing multiple UPnP services becomes one `SsdpDevice` per IP.
- Exclusions are applied once, before any probing, so excluded addresses are never contacted; the excluded set is recorded in the effective config.
- Quick-scan batches cap the global connection count: `per_host` is derived from `config.concurrency / batch_size`, with a floor of 8 and a ceiling of 250.
- Service fingerprinting after the port sweep runs under a semaphore so blocking socket calls in threads cannot exhaust the pool.

---

## Workflow 2: host scan

Entry point: `HostScanner.scan(target, ports)` in `discovery.py`.

```text
CLI / library
     │
     ▼
resolve_ipv4() ────────── IPv4 literal or DNS resolution (names.py)
     │
     ▼
ping_host() ───────────── latency, TTL, populates ARP cache
neighbor_table() ──────── MAC + OUI vendor
resolve_names() ───────── PTR + mDNS + NetBIOS
default_route() ───────── gateway/local-host flags
     │
     ▼
engine selection ──────── native (default) or nmap/auto
     │
     ├── native: scan_tcp_ports() (asyncio connect scan)
     │           └─ fingerprint_services() on open ports
     │
     └── nmap:  nmap_scan() -> parse_nmap_xml()
                 fallback to native on any failure
     │
     ▼
optional UDP ──────────── nmap -sU (root) else scan_udp_ports()
     │
     ▼
deduplicate services by (port, protocol), infer type/OS
     │
     ▼
HostScanResult ───────── reporting.write_reports()
```

The native TCP scan uses `asyncio.open_connection` to every port under a semaphore. A refused connection is recorded as closed, a timeout as filtered, and a successful connect as open with the measured latency. Open ports are then fingerprinted concurrently in worker threads because `socket`/`ssl` are blocking.

When Nmap is selected (directly or through `auto`), its TCP and UDP results are merged by `(port, protocol)`; a key already seen (for example from a richer probe) is not overwritten by a later Nmap row.

---

## Workflow 3: report diff

Entry point: `diff_scans(old_scan, new_scan)` in `diffing.py`. The command has no network side and never touches discovery code.

```text
CLI (`diff OLD NEW`)
     │
     ▼
load_report(path) ─────── read JSON, accept wrapped or bare scan, validate
     │                    shape (raises DiffError → exit 1)
     ▼
_host_records() ───────── network reports: one record per host["ip"]
     │                    host reports: the single scan object keyed by
     │                    resolved_ip
     ▼
diff_scans() ──────────── host set difference; per-host field comparison
     │                    (_HOST_FIELDS); open-service comparison keyed by
     │                    (port, protocol); warning set difference
     ▼
ScanDiff ──────────────── hosts/services/warnings added, removed, changed
     │                    + derived has_changes / change_count
     ▼
render_diff() / to_dict() ─ text table or JSON (`--json`)
     │
     ▼
exit 0, or 3 with --fail-on-change when changes exist
```

Comparison rules:

- Only services whose `state` is `open` participate, so transient `filtered` results never create noise.
- `_different()` treats `None` and `""` as equivalent, avoiding spurious changes when a field was absent in one report and empty in the other.
- Hosts are matched by IP and services by `(port, protocol)`; ordering is deterministic (`sorted`), so identical inputs always give identical output.

---

## Workflow 4: offline export

Entry point: `export_report(source, fmt, destination, force=...)` in `reporting.py`, exposed as `net-spectre export`. It performs no network access and reuses the same renderers as a live scan.

```text
CLI (`export REPORT`)
     │
     ▼
load_result(path) ─────── load_report() reads/validates JSON
     │                    then NetworkScanResult.from_dict() or
     │                    HostScanResult.from_dict() based on mode/fields
     ▼
render_export(path, fmt)
     ├── csv  -> render_csv(result)      (shared flat schema)
     └── text -> render_report(result)   (normal human-readable report)
     │
     ▼
export_report() ───────── default sibling .csv/.txt, or explicit -o path
     │                    rejects output == input; requires --force to replace
     ▼
_atomic_write() ───────── write <name>.tmp, fsync, rename, clean up on error
     │
     ▼
stdout message (unless -q) and exit 0, or 1 on load/write failure
```

Design notes:

- `load_result()` deliberately reuses `diffing.load_report()` for envelope/bare-object handling, so `diff` and `export` accept exactly the same inputs.
- The typed loader is tolerant of additive JSON fields and skips individual malformed service/host entries, but a document that is not a Net Spectre report is rejected with `DiffError` (exit `1`).
- `--output -` short-circuits the file writer and streams the rendered content to stdout, which keeps shell pipelines simple.
- The `.tmp` file is removed in a `finally` block if `replace()` or the write fails, so failed exports do not leave debris behind.

---

## Concurrency model

| Stage | Mechanism | Bounded by |
| --- | --- | --- |
| ICMP sweep | thread pool subprocesses | `ping_concurrency` (default 64) |
| TCP reachability sweep | asyncio tasks over host×port | `ping_concurrency` worker threads |
| Name resolution | `ThreadPoolExecutor` + `as_completed` | min(16, hosts) |
| Quick port scan | asyncio TCP, then thread probes | `concurrency`, `fingerprint_concurrency` |
| Host TCP scan | asyncio + semaphore | `concurrency` (default 250) |
| Service fingerprinting | asyncio + semaphore over threads | `fingerprint_concurrency` (default 12) |
| UDP probes | asyncio + semaphore over threads | `fingerprint_concurrency × 2` (max 32) |
| SSDP descriptions | `ThreadPoolExecutor` + `as_completed` | fixed small pool, deduplicated URLs |
| Nmap | one subprocess per scan | internal Nmap parallelism (`-T3`) |

Rules:

- All network operations have explicit timeouts; there is no unbounded wait.
- Threads are used only for APIs that are blocking (`socket`, `ssl`, subprocesses, `getaddrinfo`).
- Bulk fan-outs (name resolution, SSDP descriptions) iterate futures with `as_completed`, so slow entries are handled as soon as they finish instead of waiting for the whole batch.
- Asyncio semaphores are created per scan, never shared globally.
- Progress callbacks are invoked from worker contexts and must be lightweight; exceptions in callbacks are swallowed so the UI cannot break a scan.

---

## Error handling and degradation

The error policy is "record, degrade, continue":

| Failure | Behavior |
| --- | --- |
| Invalid target or ports | `TargetError` → CLI exit code `2`, no report. |
| No usable local network, or every target excluded | `ScanError` → exit code `1`. |
| Optional module missing (`psutil`, `cryptography`) | Fallback path; no warning needed. |
| Optional executable missing | Feature skipped or replaced; warning may be recorded. |
| `arp-scan`/Nmap privileges missing | Skip privileged mode; record the reason. |
| Per-host name lookup failure | Host keeps its other data. |
| Probe timeout/reset | Port stays closed/filtered or service remains unidentified. |
| Quick-scan batch failure | Warning added; other hosts continue. |
| Unreadable/corrupt report (`diff`, `export`) | `DiffError` → exit code `1`, message on stderr. |
| Report write failure | Error printed to stderr; scan result is lost but process exits `1`. |
| Export destination exists | `FileExistsError` → exit code `1` unless `--force` is given. |
| Export output equals input | `ValueError` → exit code `2`, input is never overwritten. |
| Unexpected exception in a command | Logged with `logger.exception`, exit code `1`. |
| `Ctrl+C` | Exit code `130`, no partial report. |

Warnings are collected per scan (`NetworkScanner.warnings`, `HostScanner.warnings`), deduplicated and embedded in both report formats, so a reader can tell whether "no result" means "nothing there" or "tool unavailable".

### Subprocess handling

`utils.run_command()`:

- never uses a shell;
- converts a missing binary into `CommandResult(returncode=127)`;
- converts a timeout into `returncode=124`, `timed_out=True`;
- decodes output tolerantly with `safe_decode()`;
- raises `CommandError` only for unexpected `OSError`s.

This makes external tools safe to call speculatively.

---

## Safety and security

### Network behavior

- Only **connect()** scans and read-only handshakes are performed. The program never sends credentials, never writes to services and never exploits anything.
- Probes are deliberately minimal: `GET /` over HTTP, `EHLO`, Redis `INFO server`, memcached `version`, RTSP `OPTIONS`, MQTT CONNECT with no credentials, PostgreSQL SSLRequest, SNMP GET on the `public` community, DNS `version.bind`, NTP client request, SSDP M-SEARCH and mDNS queries.
- Total requests per port are bounded; response sizes are capped (`_MAX_RESPONSE`, `_MAX_BANNER`, `_MAX_BODY`).
- Target expansion is capped by `max_hosts` to prevent accidentally scanning a large address space, and `--exclude` removes addresses before any packet is sent.

### Input and output safety

- Port and target parsing is strict; invalid input is rejected before any network activity.
- Subprocesses receive argument lists, so scan targets cannot inject shell syntax.
- Device-provided strings (hostnames, banners, HTTP headers, UPnP fields, certificate subjects) are untrusted. `reporting._safe()` strips ANSI escapes and control characters before text output; console renderers use `_one_line()` and column truncation, and `utils.table` pads by *visible* width so ANSI colour never misaligns columns. This prevents terminal escape injection and report structure corruption.
- Reports are written atomically and never overwrite existing files.

### Privilege model

Root is optional. It only enables `arp-scan`, Nmap SYN scans, Nmap OS detection and Nmap UDP. The tool deliberately does not elevate privileges itself.

---

## Reporting pipeline

```text
result object
   ├── render_network_report() / render_host_report()  -> text  -> atomic .log
   ├── result.to_dict() -> envelope -> json.dumps(...)  -> atomic .json
   ├── render_csv()                                     -> flat  -> atomic .csv
   ├── render_console_*()                               -> stdout summary
   │
   └── offline: load_result() -> from_dict()
          ├── render_export(..., "csv")  -> atomic .csv / stdout
          └── render_report(result)      -> atomic .txt / stdout
```

- The JSON envelope is produced in `write_reports()`: `{"generator", "report_version", "scan"}`.
- `render_csv()` emits one row per open service (or per host when none was found) using the shared `_CSV_COLUMNS` schema, so network and host exports are interchangeable.
- File names derive from the scan start time in UTC; `_unique_base()` adds a numeric suffix instead of overwriting and checks the candidate against `.log`, `.json` and `.csv` so the three files of one scan never collide.
- `_atomic_write()` writes to `<name>.tmp`, fsyncs, then renames; a failure removes the temporary file.
- `sanitize_filename()` and an explicit dot-to-underscore replacement keep host report names portable (and avoid the dotted-IP suffix bug).
- Diagnostic logging (`logs/net_spectre.log`) is separate from scan reports and rotates at 2 MiB with three backups. The logger namespace is deliberately kept as `net_spectre` for backwards compatibility even though the package is `src`.

---

## Extension points

### Add a service probe

1. Add probe bytes to `PROBES` in `constants.py`.
2. Dispatch it from `probe_service()` in `fingerprint.py` based on port or existing response.
3. Extend `BANNER_SIGNATURES` or the HTTP/TLS parsing helpers if new output needs classification.
4. Add a unit test in `tests/test_fingerprint.py` using a local socket or a synthetic payload.

### Add a discovery source

1. Implement a primitive that returns `HostInfo`-compatible data (or a small dataclass) in `network.py`.
2. Call it from `NetworkScanner.scan()` in the numbered pipeline, adding to the shared `hosts` dictionary and calling `add_source()` / `add_evidence()`.
3. Wrap it in `try/except` and record a warning on failure.
4. Add tests with mocked primitives.

### Add a device/OS inference rule

- Device keywords: `VENDOR_DEVICE_HINTS`, `HOSTNAME_DEVICE_HINTS`, `PORT_DEVICE_HINTS` in `constants.py`.
- Priority and combination logic: `infer_device_type()` in `discovery.py`.
- OS: `TTL_OS_HINTS` in `constants.py`, `guess_os_from_ttl()` in `utils.py`, `infer_os()` in `discovery.py`.

### Add a preset

Add a key to `PORT_PRESETS` in `constants.py`; it automatically appears in `host --preset` choices (built from `sorted(PORT_PRESETS)`).

### Add compared fields to `diff`

Extend `_HOST_FIELDS` in `diffing.py` for host metadata, or adjust `_service_label()` to include additional service attributes. Keep the `ScanDiff.to_dict()` keys stable.

### Add an output format

Implement a renderer next to the existing ones in `reporting.py`, extend `write_reports()` for live scans and add the suffix/choice to `_EXPORT_SUFFIXES` for offline `export`. Keep the existing text/JSON/CSV behavior and filenames for backwards compatibility.

### Use as a library

```python
from src.config import ScanConfig
from src.discovery import scan_network, scan_host
from src.reporting import export_report, load_result, write_reports
from src.diffing import diff_scans, load_report

config = ScanConfig(timeout=1.0, concurrency=200)
result = scan_network(config, "192.168.1.0/24", exclude="192.168.1.1-10")
write_reports(result, "reports")

host = scan_host("192.168.1.1", config, ports=[22, 80, 443])

changes = diff_scans(load_report("old.json"), load_report("new.json"))
print(changes.change_count)

saved = load_result("reports/network_scan_20260101_120000.json")
export_report("reports/network_scan_20260101_120000.json", "csv", force=True)
```

Primitives such as `scan_tcp_ports`, `probe_service`, `resolve_names`, `ssdp_discover` and `exclude_targets` are also importable directly.

---

## Testing strategy

The suite uses `unittest` only and makes no real network calls except where a local loopback socket is intentional.

| Test module | Focus |
| --- | --- |
| `test_utils.py` | target/port parsing, exclusions, MAC normalisation, ping parsing, `ceil_div`, ANSI-aware tables, colours, file names |
| `test_config.py` | defaults, clamping, env overrides (incl. ping concurrency), `with_overrides` |
| `test_models.py` | merge behavior, derived properties, JSON round-trips and tolerant `from_dict()` loading |
| `test_names.py` | DNS wire format, name sanitisation, cached lookups |
| `test_oui.py` | database loading, prefix matching, fallback table |
| `test_network.py` | interface/route parsing, ARP parsing, sweeps, SSDP |
| `test_portscan.py` | asyncio scan, port compression, Nmap XML parsing |
| `test_fingerprint.py` | HTTP/TLS parsing, banner classification, SNMP/DNS/NTP |
| `test_discovery.py` | inference rules, nmap merge, exclusion orchestration with mocked primitives |
| `test_reporting.py` | text rendering, JSON envelope, CSV export, typed reload, offline export, atomic/unique writes |
| `test_diffing.py` | report loading, host/service comparison, rendering, `to_dict()` |
| `test_cli.py` | parser structure, option mapping, exit codes, diff/export commands, menu helpers |

Run:

```bash
python3 -m unittest discover -s tests -v
python3 -m compileall -q src
make coverage        # python3 -m coverage run -m unittest discover -s tests
```

---

## Known limitations

- **IPv4 only.** IPv6 discovery and scanning are out of scope.
- **Local segment for MACs.** Devices behind routers cannot be resolved to MAC addresses or vendors.
- **UDP is best effort natively.** Without root/Nmap only positive replies are visible; silence is inconclusive.
- **OS detection is heuristic.** TTL and banner hints are approximate; real fingerprinting needs Nmap `-O` and root.
- **Name resolution depends on the network.** Many devices do not answer PTR, mDNS or NetBIOS.
- **Service identification is signature-based.** Encrypted or custom protocols may be reported only as an open port.
- **ARP cache may be stale.** Such hosts are labelled in their notes.
- **SSDP/UPnP may be disabled.** Some networks block multicast.
- **Nmap XML is parsed with a tolerant subset.** Unknown elements are ignored; only `open` ports are reported.
- **No persistence.** Each scan is independent; use the `diff` command or the JSON output to compare scans over time.
