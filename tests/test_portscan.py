"""Tests for the port scanner helpers and the Nmap XML parser."""

from __future__ import annotations

import unittest

from src.portscan import compress_ports, parse_nmap_xml

NMAP_XML = """<?xml version="1.0"?>
<nmaprun scanner="nmap">
  <host>
    <status state="up" reason="arp-response"/>
    <address addr="192.168.1.1" addrtype="ipv4"/>
    <address addr="AA:BB:CC:DD:EE:FF" addrtype="mac" vendor="Example Corp"/>
    <hostnames>
      <hostname name="router.lan" type="PTR"/>
      <hostname name="router" type="user"/>
    </hostnames>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open" reason="syn-ack"/>
        <service name="ssh" product="OpenSSH" version="9.6" extrainfo="Ubuntu">
          <cpe>cpe:/a:openbsd:openssh:9.6</cpe>
        </service>
      </port>
      <port protocol="tcp" portid="443">
        <state state="open" reason="syn-ack"/>
        <service name="http" product="nginx" version="1.24.0" tunnel="ssl">
          <cpe>cpe:/a:nginx:nginx:1.24.0</cpe>
        </service>
        <script id="ssl-cert" output="subject=CN=router"/>
      </port>
      <port protocol="tcp" portid="8080">
        <state state="closed" reason="reset"/>
      </port>
    </ports>
    <os>
      <osmatch name="Linux 5.0 - 5.14" accuracy="98">
        <osclass type="general purpose" vendor="Linux"/>
      </osmatch>
    </os>
    <hostscript>
      <script id="smb-os-discovery" output="OS: Unix"/>
    </hostscript>
  </host>
  <host>
    <status state="down" reason="no-response"/>
    <address addr="192.168.1.2" addrtype="ipv4"/>
  </host>
</nmaprun>
"""


class CompressPortsTests(unittest.TestCase):
    def test_ranges(self) -> None:
        self.assertEqual(compress_ports([80, 81, 82, 443, 445, 446]), "80-82,443,445-446")
        self.assertEqual(compress_ports([22]), "22")
        self.assertEqual(compress_ports([]), "")

    def test_deduplicates_and_sorts(self) -> None:
        self.assertEqual(compress_ports([443, 80, 443]), "80,443")

    def test_ignores_out_of_range(self) -> None:
        self.assertEqual(compress_ports([0, 80, 70000]), "80")


class NmapXmlTests(unittest.TestCase):
    def test_parse_hosts_and_services(self) -> None:
        result = parse_nmap_xml(NMAP_XML)
        self.assertEqual(len(result.hosts), 2)
        host = result.hosts[0]
        self.assertEqual(host.ip, "192.168.1.1")
        self.assertEqual(host.status, "up")
        self.assertEqual(host.mac, "AA:BB:CC:DD:EE:FF")
        self.assertEqual(host.vendor, "Example Corp")
        self.assertEqual(host.hostnames, ["router.lan", "router"])
        self.assertEqual(host.os_matches[0], ("Linux 5.0 - 5.14", 98))
        self.assertEqual(host.device_types, ["general purpose"])
        self.assertEqual([service.port for service in host.services], [22, 443])

        ssh = host.services[0]
        self.assertEqual(ssh.service, "ssh")
        self.assertEqual(ssh.product, "OpenSSH")
        self.assertEqual(ssh.version, "9.6")
        self.assertIn("cpe:/a:openbsd:openssh:9.6", ssh.extra or "")
        self.assertEqual(ssh.confidence, 95)
        self.assertEqual(ssh.method, "nmap")

        https = host.services[1]
        self.assertEqual(https.service, "http/ssl")
        self.assertEqual(https.banner, "ssl-cert: subject=CN=router")
        self.assertIn("smb-os-discovery", host.scripts)

        down = result.hosts[1]
        self.assertEqual(down.status, "down")
        self.assertEqual(down.services, [])

    def test_empty_or_invalid_xml(self) -> None:
        self.assertEqual(parse_nmap_xml("").hosts, [])
        result = parse_nmap_xml("<not-closed>")
        self.assertEqual(result.hosts, [])
        self.assertTrue(result.warnings)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
