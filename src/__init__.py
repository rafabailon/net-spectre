"""Net Spectre - network discovery and service enumeration toolkit.

Net Spectre is a small, dependency-light security tool that can:

* discover every device reachable on a local network and gather all the
  information the host can legitimately obtain about it (IP, MAC, vendor,
  hostnames, latency, TTL, inferred OS/device type, open ports and services);
* scan every TCP (and optionally UDP) port of a target, fingerprint the
  exposed services and extract banners, HTTP metadata and TLS certificates;
* persist each scan as a human readable ``.log`` report and a machine friendly
  ``.json`` document.

The package has no mandatory third party dependencies.  ``psutil``,
``nmap``, ``arp-scan`` and ``avahi`` are detected at runtime and used to
improve results when available.
"""

from __future__ import annotations

__version__ = "1.2.0"
__author__ = "Net Spectre contributors"
__license__ = "MIT"

__all__ = ["__version__"]
