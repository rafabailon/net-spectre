"""MAC address vendor (OUI) resolution.

Resolution order:

1. A database supplied through ``NET_SPECTRE_OUI_FILE``.
2. A database downloaded by ``net-spectre update-oui`` (cached).
3. Well known system databases installed by ``arp-scan``, ``nmap`` or
   ``ieee-data``.
4. A small embedded fallback table so vendors are still reported on minimal
   systems.

Only the first 6 (MA-L) or 9 (MA-S) hexadecimal digits of a MAC address are
significant for vendor resolution; the longest matching prefix wins.
"""

from __future__ import annotations

import csv
import os
import threading
import urllib.error
import urllib.request
from pathlib import Path
from typing import Iterable

from .constants import USER_AGENT
from .utils import normalize_mac, safe_decode

__all__ = ["OuiDatabase", "get_oui_database", "download_oui_database", "cache_path"]

#: Official IEEE registry in CSV form.
IEEE_OUI_URL = "https://standards-oui.ieee.org/oui/oui.csv"

#: Small offline fallback table (prefix -> vendor).  It is deliberately
#: conservative and only lists well established assignments.
EMBEDDED_OUI: dict[str, str] = {
    # Virtualisation / containers
    "000569": "VMware", "000C29": "VMware", "001C14": "VMware", "005056": "VMware",
    "080027": "Oracle VirtualBox", "525400": "QEMU / KVM", "0242AC": "Docker",
    "00155D": "Microsoft Hyper-V", "0A0027": "Virtual network adapter",
    # Apple
    "000393": "Apple", "000A27": "Apple", "0016CB": "Apple", "0017F2": "Apple",
    "001B63": "Apple", "001CB3": "Apple", "001EC2": "Apple", "001E52": "Apple",
    "001FF3": "Apple", "0021E9": "Apple", "002241": "Apple", "002312": "Apple",
    "002500": "Apple", "0025BC": "Apple", "0026BB": "Apple", "28CFE9": "Apple",
    "3408BC": "Apple", "3C22FB": "Apple", "406C8F": "Apple", "4860BC": "Apple",
    "5855CA": "Apple", "600308": "Apple", "68AB1E": "Apple", "70CD60": "Apple",
    "7831C1": "Apple", "7CD1C3": "Apple", "8866A5": "Apple", "8C8590": "Apple",
    "98D6BB": "Apple", "9C04EB": "Apple", "A483E7": "Apple",
    "A82066": "Apple", "ACBC32": "Apple", "B03495": "Apple", "B817C2": "Apple",
    "BC52B7": "Apple", "C0CECD": "Apple", "C8BCC8": "Apple", "D0817A": "Apple",
    "D8004D": "Apple", "DC2B2A": "Apple", "E0B9BA": "Apple", "F01898": "Apple",
    "F45C89": "Apple",
    # Cisco
    "00000C": "Cisco", "000142": "Cisco", "000143": "Cisco", "001B0C": "Cisco",
    "001B8F": "Cisco", "001D45": "Cisco", "001E13": "Cisco", "0021A0": "Cisco",
    "002497": "Cisco", "0026CB": "Cisco", "2C542D": "Cisco", "70695A": "Cisco",
    "F80BCB": "Cisco", "001A1E": "Aruba Networks", "000B86": "Aruba Networks",
    # Intel / Dell / Lenovo / HP / Microsoft
    "001B21": "Intel", "001E64": "Intel", "00215C": "Intel", "0024D7": "Intel",
    "3C970E": "Intel", "8C1645": "Intel", "A0369F": "Intel", "B808CF": "Intel",
    "E4A471": "Intel", "F8633F": "Intel",
    "001A0A": "Dell", "001422": "Dell", "001C23": "Dell", "00219B": "Dell",
    "0024E8": "Dell", "0026B9": "Dell", "14FEB5": "Dell", "180373": "Dell",
    "18A99B": "Dell", "24B6FD": "Dell", "28F076": "Dell", "3417EB": "Dell",
    "44A842": "Dell", "4C7625": "Dell", "509A4C": "Dell", "54BF64": "Dell",
    "5CF9DD": "Dell", "74867A": "Dell", "782BCB": "Dell", "842B2B": "Dell",
    "90B11C": "Dell", "A41F72": "Dell", "A4BB6D": "Dell", "B083FE": "Dell",
    "B82A72": "Dell", "BC305B": "Dell", "C81F66": "Dell", "D067E5": "Dell",
    "D4AE52": "Dell", "E0DB55": "Dell", "ECF4BB": "Dell", "F04DA2": "Dell",
    "F8BC12": "Dell", "F8DB88": "Dell",
    "0012FE": "Lenovo", "001E4F": "Lenovo", "0021CC": "Lenovo", "00247E": "Lenovo",
    "083E5E": "Lenovo", "28D244": "Lenovo", "3C9180": "Lenovo", "484D7E": "Lenovo",
    "54EE75": "Lenovo", "60D819": "Lenovo", "68F728": "Lenovo", "6C0B84": "Lenovo",
    "7824AF": "Lenovo", "80FA5B": "Lenovo", "847BEB": "Lenovo", "A48CDB": "Lenovo",
    "B02A43": "Lenovo", "C85B76": "Lenovo", "D89EF3": "Lenovo", "E86A64": "Lenovo",
    "F0761C": "Lenovo",
    "001F29": "HP", "00215A": "HP", "002264": "HP", "00237D": "HP", "002481": "HP",
    "0025B3": "HP", "002655": "HP", "2C4138": "HP", "3CD92B": "HP", "40A8F0": "HP",
    "6C3BE5": "HP", "98E7F4": "HP", "A0D3C1": "HP", "B499BA": "HP", "C8CBB8": "HP",
    "D48564": "HP", "EC9A74": "HP", "F4CE46": "HP",
    "0017FA": "Microsoft", "001DD8": "Microsoft",
    "281878": "Microsoft", "3C8375": "Microsoft", "7C1E52": "Microsoft",
    "985FD3": "Microsoft", "C83F26": "Microsoft",
    # Mobile / consumer
    "0012FB": "Samsung", "001599": "Samsung", "001A8A": "Samsung", "0023D6": "Samsung",
    "002637": "Samsung", "28395E": "Samsung", "3423BA": "Samsung", "5C0A5B": "Samsung",
    "781FDB": "Samsung", "8C7712": "Samsung", "C0BDD1": "Samsung", "E8508B": "Samsung",
    "001C62": "LG Electronics", "001E75": "LG Electronics", "0022A9": "LG Electronics",
    "0026E2": "LG Electronics", "3CCD5D": "LG Electronics", "58A2B5": "LG Electronics",
    "88366C": "LG Electronics", "A816B2": "LG Electronics", "C4366C": "LG Electronics",
    "E85B5B": "LG Electronics",
    "001315": "Sony", "0019C5": "Sony", "001DBA": "Sony", "00248C": "Sony",
    "30F9ED": "Sony", "544249": "Sony", "78843C": "Sony", "FC0FE6": "Sony",
    "0009BF": "Nintendo", "0017AB": "Nintendo", "00191D": "Nintendo", "001BEA": "Nintendo",
    "001E35": "Nintendo", "00224C": "Nintendo", "0023CC": "Nintendo", "0024F3": "Nintendo",
    "002659": "Nintendo", "40D40E": "Nintendo", "58BDA3": "Nintendo", "78A2A0": "Nintendo",
    "98B6E9": "Nintendo", "B8AE6E": "Nintendo", "E0E751": "Nintendo",
    "009EC8": "Xiaomi", "04CF8C": "Xiaomi", "087664": "Xiaomi", "0C1DAF": "Xiaomi",
    "102AB3": "Xiaomi", "286C07": "Xiaomi", "34CE00": "Xiaomi",
    "38A4ED": "Xiaomi", "3C4711": "Xiaomi", "44237C": "Xiaomi", "4C49E3": "Xiaomi",
    "548C81": "Xiaomi", "5C0214": "Xiaomi", "64B473": "Xiaomi", "68DFDD": "Xiaomi",
    "6C5AB0": "Xiaomi", "708BCD": "Xiaomi", "742344": "Xiaomi", "7802F8": "Xiaomi",
    "7C1DD9": "Xiaomi", "8CBEBE": "Xiaomi", "94F6A3": "Xiaomi", "A45046": "Xiaomi",
    "ACC1EE": "Xiaomi", "B0E235": "Xiaomi", "B40F3B": "Xiaomi", "C40BCB": "Xiaomi",
    "C80E14": "Xiaomi", "CC9EA2": "Xiaomi", "D4970B": "Xiaomi", "D83214": "Xiaomi",
    "E0DCFF": "Xiaomi", "E4AAEC": "Xiaomi", "E8ABFA": "Xiaomi", "F0B429": "Xiaomi",
    "F48B32": "Xiaomi", "F8A45F": "Xiaomi", "FC64BA": "Xiaomi",
    "001A11": "Google", "3C5AB4": "Google", "546009": "Google", "6CADF8": "Google",
    "94EB2C": "Google", "A47733": "Google", "D86C63": "Google", "F4F5D8": "Google",
    "F4F5E8": "Google",
    "00FC8B": "Amazon", "08849D": "Amazon", "0C47C9": "Amazon", "18742E": "Amazon",
    "34D270": "Amazon", "40B4CD": "Amazon", "44650D": "Amazon", "4CEFC0": "Amazon",
    "50DCE7": "Amazon", "6837E9": "Amazon", "6854FD": "Amazon", "74C246": "Amazon",
    "78E103": "Amazon", "84D6D0": "Amazon", "A002DC": "Amazon", "AC63BE": "Amazon",
    "B0FC36": "Amazon", "F0272D": "Amazon", "F08173": "Amazon", "FC65DE": "Amazon",
    "000D4B": "Roku", "B0A737": "Roku", "CC6DA0": "Roku",
    "000E58": "Sonos", "347E5C": "Sonos", "48A6B8": "Sonos", "5CAAFD": "Sonos",
    "7828CA": "Sonos", "949F3E": "Sonos", "B8E937": "Sonos",
    # Network equipment
    "002719": "TP-Link", "10FEED": "TP-Link", "14CC20": "TP-Link", "30B5C2": "TP-Link",
    "50C7BF": "TP-Link", "54C80F": "TP-Link", "60E327": "TP-Link", "64E599": "TP-Link",
    "68FF7B": "TP-Link", "7C8BCA": "TP-Link", "98DAC4": "TP-Link", "A42BB0": "TP-Link",
    "B04E26": "TP-Link", "C025E9": "TP-Link", "C46E1F": "TP-Link", "D807B6": "TP-Link",
    "EC086B": "TP-Link", "F4F26D": "TP-Link",
    "00146C": "Netgear", "001F33": "Netgear", "0024B2": "Netgear", "204E7F": "Netgear",
    "28C68E": "Netgear", "2CB05D": "Netgear", "4494FC": "Netgear", "4C60DE": "Netgear",
    "841B5E": "Netgear", "9C3DCF": "Netgear", "B07FB9": "Netgear", "C03F0E": "Netgear",
    "C40415": "Netgear", "E0469A": "Netgear", "E4F4C6": "Netgear",
    "001B11": "D-Link", "001E58": "D-Link", "0022B0": "D-Link", "002401": "D-Link",
    "14D64D": "D-Link", "1C7EE5": "D-Link", "28107B": "D-Link", "3C1E04": "D-Link",
    "5CD998": "D-Link", "74DA88": "D-Link", "78321B": "D-Link", "84C9B2": "D-Link",
    "9094E4": "D-Link", "B8A386": "D-Link", "C8BE19": "D-Link", "F07D68": "D-Link",
    "00156D": "Ubiquiti", "002722": "Ubiquiti", "0418D6": "Ubiquiti", "24A43C": "Ubiquiti",
    "44D9E7": "Ubiquiti", "68D79A": "Ubiquiti", "74ACB9": "Ubiquiti", "788A20": "Ubiquiti",
    "802AA8": "Ubiquiti", "AC8BA9": "Ubiquiti", "D021F9": "Ubiquiti", "E063DA": "Ubiquiti",
    "F09FC2": "Ubiquiti", "FCECDA": "Ubiquiti",
    "000C42": "MikroTik", "085531": "MikroTik", "18FD74": "MikroTik", "2CC81B": "MikroTik",
    "488F5A": "MikroTik", "4C5E0C": "MikroTik", "64D154": "MikroTik", "6C3B6B": "MikroTik",
    "744D28": "MikroTik", "789A18": "MikroTik", "B869F4": "MikroTik", "CC2DE0": "MikroTik",
    "DC2C6E": "MikroTik", "E48D8C": "MikroTik", "F41E57": "MikroTik",
    "00E0FC": "Huawei", "04BD88": "Huawei", "0819A6": "Huawei", "0C96BF": "Huawei",
    "104780": "Huawei", "18C58A": "Huawei", "20F3A3": "Huawei", "2469A5": "Huawei",
    "286ED4": "Huawei", "2C55D3": "Huawei", "346BD3": "Huawei", "384C4F": "Huawei",
    "404CCA": "Huawei", "48DB50": "Huawei", "4C1FCC": "Huawei", "5425EA": "Huawei",
    "5C4CA9": "Huawei", "60DE44": "Huawei", "643E8C": "Huawei", "68A0F6": "Huawei",
    "6C92BF": "Huawei", "70723C": "Huawei", "74882A": "Huawei", "78D752": "Huawei",
    "7C6097": "Huawei", "80B686": "Huawei", "84A8E4": "Huawei", "8853D4": "Huawei",
    "8C34FD": "Huawei", "9017AC": "Huawei", "9C28EF": "Huawei", "A08CF8": "Huawei",
    "A49947": "Huawei", "A8F5E1": "Huawei", "ACE215": "Huawei", "B05B67": "Huawei",
    "B41513": "Huawei", "B8BC1B": "Huawei", "BC25E0": "Huawei", "C07009": "Huawei",
    "C40528": "Huawei", "C894BB": "Huawei", "CCA223": "Huawei", "D07AB5": "Huawei",
    "D46A6A": "Huawei", "D8490B": "Huawei", "DCD2FC": "Huawei", "E0247F": "Huawei",
    "E468A3": "Huawei", "E8088B": "Huawei", "EC233D": "Huawei", "F04347": "Huawei",
    "F4559C": "Huawei", "F80113": "Huawei", "FC48EF": "Huawei",
    "00090F": "Fortinet", "085B0E": "Fortinet", "704CA5": "Fortinet",
    "000585": "Juniper Networks", "00121E": "Juniper Networks", "2C6BF5": "Juniper Networks",
    "5C5EAB": "Juniper Networks", "7819F7": "Juniper Networks", "841888": "Juniper Networks",
    "AC4BC8": "Juniper Networks",
    # IoT / embedded / printers / storage / cameras
    "240AC4": "Espressif", "246F28": "Espressif", "2462AB": "Espressif", "30AEA4": "Espressif",
    "3C6105": "Espressif", "3C71BF": "Espressif", "483FDA": "Espressif", "4C11AE": "Espressif",
    "545AA6": "Espressif", "5CCF7F": "Espressif", "600194": "Espressif", "68C63A": "Espressif",
    "744DBD": "Espressif", "7C9EBD": "Espressif", "80646F": "Espressif", "840D8E": "Espressif",
    "84F3EB": "Espressif", "8CAAB5": "Espressif", "A020A6": "Espressif", "A4CF12": "Espressif",
    "AC67B2": "Espressif", "B4E62D": "Espressif",
    "B827EB": "Raspberry Pi", "DCA632": "Raspberry Pi", "E45F01": "Raspberry Pi",
    "28CDC1": "Raspberry Pi", "2CCF67": "Raspberry Pi",
    "00E04C": "Realtek",
    "001132": "Synology", "245EBE": "Synology", "9009D0": "Synology", "001C0E": "QNAP", "00089B": "QNAP",
    "000085": "Canon", "001E8F": "Canon", "2C9EFC": "Canon", "888717": "Canon",
    "F48139": "Canon",
    "001BA9": "Brother", "008077": "Brother", "30055C": "Brother", "3C2AF4": "Brother",
    "50642B": "Brother", "8086F2": "Brother", "B42200": "Brother",
    "000048": "Epson", "000400": "Lexmark", "002000": "Lexmark", "0021B7": "Lexmark",
    "9C934E": "Xerox",
    "4419B6": "Hikvision", "4CBD8F": "Hikvision", "54C415": "Hikvision",
    "5803FB": "Hikvision", "BCAD28": "Hikvision",
    "3CEF8C": "Dahua", "4C11BF": "Dahua", "9C1463": "Dahua",
    "00408C": "Axis Communications", "ACCC8E": "Axis Communications", "B8A44F": "Axis Communications",
    "001788": "Philips Lighting", "84CCA8": "Allterco / Shelly",
    "10D561": "Tuya", "1869D8": "Tuya", "500291": "Tuya", "68572D": "Tuya",
}


def cache_path() -> Path:
    """Return the cache path used for the downloaded IEEE database."""
    base = os.environ.get("XDG_CACHE_HOME") or os.path.join(Path.home(), ".cache")
    return Path(base) / "net_spectre" / "oui.txt"


class OuiDatabase:
    """Vendor lookup with longest-prefix matching."""

    def __init__(self, sources: Iterable[Path] | None = None) -> None:
        self._sources = list(sources) if sources is not None else _default_sources()
        self._entries: dict[str, str] = {}
        self._loaded = False
        self._lock = threading.Lock()
        self.source_description = "embedded fallback"

    @property
    def size(self) -> int:
        self._ensure_loaded()
        return len(self._entries)

    def _ensure_loaded(self) -> None:
        if self._loaded:
            return
        with self._lock:
            if self._loaded:
                return
            entries: dict[str, str] = dict(EMBEDDED_OUI)
            description = "embedded fallback"
            for path in self._sources:
                try:
                    if not path.is_file():
                        continue
                    parsed = _parse_oui_file(path)
                except OSError:
                    continue
                if parsed:
                    entries.update(parsed)
                    description = str(path)
            # Normalize embedded keys (defensive against typos).
            normalized: dict[str, str] = {}
            for prefix, vendor in entries.items():
                clean = prefix.replace(":", "").replace("-", "").replace(" ", "").upper()
                if len(clean) in (6, 9) and all(c in "0123456789ABCDEF" for c in clean):
                    normalized[clean] = vendor.strip()
            self._entries = normalized
            self.source_description = description
            self._loaded = True

    def lookup(self, mac: str | None) -> str | None:
        """Return the vendor for ``mac`` or ``None`` when unknown."""
        normalized = normalize_mac(mac)
        if not normalized:
            return None
        self._ensure_loaded()
        prefix = normalized.replace(":", "").upper()
        # Longest prefix first: MA-S (9 hex digits), then MA-L (6).
        for length in (9, 6):
            vendor = self._entries.get(prefix[:length])
            if vendor:
                return vendor
        return None


def _default_sources() -> list[Path]:
    """Return candidate OUI files in priority order."""
    sources: list[Path] = []
    override = os.environ.get("NET_SPECTRE_OUI_FILE")
    if override:
        sources.append(Path(override).expanduser())
    sources.append(cache_path())
    sources.extend(
        [
            Path("/usr/share/arp-scan/ieee-oui.txt"),
            Path("/usr/share/nmap/nmap-mac-prefixes"),
            Path("/usr/share/ieee-data/oui.txt"),
            Path("/var/lib/ieee-data/oui.txt"),
            Path("/usr/local/share/arp-scan/ieee-oui.txt"),
            Path("/opt/homebrew/share/arp-scan/ieee-oui.txt"),
        ]
    )
    return sources


def _parse_oui_file(path: Path) -> dict[str, str]:
    """Parse arp-scan, nmap or IEEE style OUI files."""
    entries: dict[str, str] = {}
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for raw_line in handle:
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            # arp-scan ieee-oui.txt: "0050C27D5\tDEUTA-WERKE GmbH"
            if "\t" in line:
                prefix, _, vendor = line.partition("\t")
                prefix = prefix.strip().replace(":", "").replace("-", "").upper()
                if len(prefix) in (6, 9) and vendor.strip():
                    entries[prefix] = vendor.strip()
                continue
            # IEEE oui.txt: "00-00-0C   (hex)               Cisco Systems, Inc."
            if "(hex)" in line and line.count("-") >= 2:
                prefix = line.split("(hex)", 1)[0].strip().replace("-", "").upper()
                vendor = line.split("(hex)", 1)[1].strip()
                if len(prefix) == 6 and vendor:
                    entries[prefix] = vendor
                continue
            # nmap-mac-prefixes: "00000C Cisco Systems"
            parts = line.split(None, 1)
            if len(parts) == 2 and len(parts[0]) in (6, 9):
                prefix = parts[0].upper()
                if all(c in "0123456789ABCDEF" for c in prefix):
                    entries[prefix] = parts[1].strip()
    return entries


_DATABASE: OuiDatabase | None = None


def get_oui_database() -> OuiDatabase:
    """Return the process wide OUI database (lazily created)."""
    global _DATABASE
    if _DATABASE is None:
        _DATABASE = OuiDatabase()
    return _DATABASE


def download_oui_database(
    destination: Path | None = None,
    *,
    timeout: float = 30.0,
) -> tuple[Path, int]:
    """Download and cache the IEEE OUI registry.

    Returns:
        ``(path, entry_count)``.

    Raises:
        RuntimeError: when the download or parsing fails.
    """
    target = destination or cache_path()
    target.parent.mkdir(parents=True, exist_ok=True)
    request = urllib.request.Request(
        IEEE_OUI_URL,
        headers={"User-Agent": USER_AGENT},
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            payload = response.read()
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise RuntimeError(f"could not download OUI registry: {exc}") from exc

    entries: dict[str, str] = {}
    try:
        text = safe_decode(payload)
        for row in csv.reader(text.splitlines()):
            if len(row) < 3 or row[0].lower() == "registry":
                continue
            prefix = row[1].strip().upper()
            vendor = row[2].strip()
            if len(prefix) in (6, 9) and vendor:
                entries[prefix] = vendor
    except (csv.Error, UnicodeError) as exc:
        raise RuntimeError(f"could not parse OUI registry: {exc}") from exc

    if not entries:
        raise RuntimeError("downloaded OUI registry was empty")

    temporary = target.with_suffix(target.suffix + ".tmp")
    with temporary.open("w", encoding="utf-8") as handle:
        for prefix in sorted(entries):
            handle.write(f"{prefix}\t{entries[prefix]}\n")
    temporary.replace(target)
    return target, len(entries)
