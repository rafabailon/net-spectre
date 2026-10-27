"""Static data used across Net Spectre.

Keeping the data in one module makes it easy to audit and extend the
fingerprinting rules without touching the scanning logic.
"""

from __future__ import annotations

from . import __version__

# ---------------------------------------------------------------------------
# Application identity
# ---------------------------------------------------------------------------

#: Human readable product name used in prompts, reports and user agents.
APP_NAME = "Net Spectre"

#: User agent sent by the read-only HTTP, RTSP, SSDP and OUI probes.
USER_AGENT = f"{APP_NAME}/{__version__} (authorized network inventory)"

#: Compact form for protocols that only need a product token.
USER_AGENT_SHORT = f"{APP_NAME}/{__version__}"

# ---------------------------------------------------------------------------
# TCP / UDP port knowledge base
# ---------------------------------------------------------------------------

#: Well known / commonly exposed TCP ports mapped to their canonical service.
PORT_SERVICES: dict[int, str] = {
    20: "ftp-data",
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    67: "dhcp",
    68: "dhcp",
    69: "tftp",
    80: "http",
    81: "http-alt",
    88: "kerberos",
    110: "pop3",
    111: "rpcbind",
    123: "ntp",
    135: "msrpc",
    137: "netbios-ns",
    138: "netbios-dgm",
    139: "netbios-ssn",
    143: "imap",
    161: "snmp",
    162: "snmptrap",
    179: "bgp",
    389: "ldap",
    443: "https",
    445: "microsoft-ds",
    465: "smtps",
    500: "isakmp",
    514: "syslog",
    515: "printer",
    548: "afp",
    554: "rtsp",
    587: "submission",
    631: "ipp",
    636: "ldaps",
    646: "ldp",
    873: "rsync",
    902: "vmware",
    989: "ftps-data",
    990: "ftps",
    993: "imaps",
    995: "pop3s",
    1025: "nfs-or-msrpc",
    1080: "socks",
    1194: "openvpn",
    1433: "mssql",
    1521: "oracle",
    1701: "l2tp",
    1723: "pptp",
    1883: "mqtt",
    1900: "ssdp",
    2049: "nfs",
    2082: "cpanel",
    2083: "cpanel-ssl",
    2181: "zookeeper",
    2222: "ssh-alt",
    2375: "docker",
    2376: "docker-tls",
    3000: "grafana",
    3128: "squid",
    3260: "iscsi",
    3306: "mysql",
    3389: "rdp",
    3478: "stun",
    3689: "daap",
    4443: "https-alt",
    4505: "salt",
    4506: "salt",
    5000: "upnp",
    5060: "sip",
    5061: "sips",
    5353: "mdns",
    5432: "postgresql",
    5555: "adb",
    5601: "kibana",
    5672: "amqp",
    5900: "vnc",
    5938: "teamviewer",
    5984: "couchdb",
    6000: "x11",
    6379: "redis",
    6443: "kubernetes-api",
    6667: "irc",
    7001: "weblogic",
    7077: "spark",
    8000: "http-alt",
    8008: "http-alt",
    8009: "ajp13",
    8080: "http-proxy",
    8081: "http-alt",
    8088: "http-alt",
    8090: "http-alt",
    8123: "home-assistant",
    8181: "http-alt",
    8200: "vault",
    8443: "https-alt",
    8500: "consul",
    8554: "rtsp-alt",
    8880: "http-alt",
    8883: "mqtt-tls",
    8888: "http-alt",
    9000: "http-alt",
    9042: "cassandra",
    9090: "http-alt",
    9092: "kafka",
    9100: "jetdirect",
    9200: "elasticsearch",
    9300: "elasticsearch",
    9418: "git",
    9443: "https-alt",
    9999: "http-alt",
    10000: "webmin",
    10250: "kubelet",
    11211: "memcached",
    11311: "sensu",
    15672: "rabbitmq-mgmt",
    16384: "hazelcast",
    25565: "minecraft",
    27017: "mongodb",
    27018: "mongodb",
    32400: "plex",
    49152: "upnp",
    50000: "sap",
    50070: "hdfs",
    61616: "activemq",
    62078: "iphone-sync",
    64738: "mumble",
}

#: Frequently used UDP services (used for labelling and optional UDP probing).
UDP_SERVICES: dict[int, str] = {
    53: "dns",
    67: "dhcp",
    68: "dhcp",
    69: "tftp",
    111: "rpcbind",
    123: "ntp",
    137: "netbios-ns",
    138: "netbios-dgm",
    161: "snmp",
    162: "snmptrap",
    500: "isakmp",
    514: "syslog",
    520: "rip",
    631: "ipp",
    1194: "openvpn",
    1701: "l2tp",
    1900: "ssdp",
    3478: "stun",
    4500: "ipsec-nat-t",
    5060: "sip",
    5353: "mdns",
    5355: "llmnr",
    5683: "coap",
    64738: "mumble",
}

#: Default TCP port set.  A curated list of the ports most likely to be
#: interesting during a first pass; it stays fast even on large networks.
TOP_TCP_PORTS: tuple[int, ...] = tuple(sorted(PORT_SERVICES))

#: Smallest useful TCP set; used to enrich network discovery results.
QUICK_SCAN_PORTS: tuple[int, ...] = (
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 515, 548,
    554, 587, 631, 873, 993, 995, 1433, 1883, 2049, 2375, 3000, 3306, 3389,
    5000, 5060, 5432, 5555, 5900, 5984, 6379, 8008, 8009, 8080, 8081, 8443,
    8888, 9000, 9090, 9100, 9200, 9443, 11211, 15672, 27017, 32400, 62078,
)

#: Ports probed to detect hosts that silently drop ICMP echo requests.
DISCOVERY_TCP_PORTS: tuple[int, ...] = (
    80, 443, 22, 445, 3389, 8080, 53, 8000, 8888, 631, 9100, 5000, 62078,
)

#: Ports where a TLS handshake is attempted first.
TLS_PORTS: frozenset[int] = frozenset(
    {443, 465, 636, 853, 993, 995, 2376, 4443, 5061, 8443, 8883, 9443, 10443}
)

#: Ports where an HTTP request is sent.
HTTP_PORTS: frozenset[int] = frozenset(
    {
        80, 81, 443, 3000, 4443, 5000, 5601, 8000, 8008, 8080, 8081, 8088,
        8090, 8123, 8181, 8200, 8443, 8500, 8880, 8888, 9000, 9090, 9200,
        9443, 10000, 10250, 15672, 2375, 2376, 32400, 50070, 6443,
    }
)

#: Ports that speak HTTP after a TLS handshake.
HTTPS_PORTS: frozenset[int] = frozenset(
    {443, 4443, 2376, 5061, 6443, 8443, 8883, 9443, 10443}
)

#: TCP ports that normally send a welcome banner before the client speaks.
BANNER_FIRST_PORTS: frozenset[int] = frozenset(
    {21, 22, 23, 25, 110, 143, 465, 587, 993, 995, 3306, 5432, 5900, 6379}
)

# ---------------------------------------------------------------------------
# Service fingerprinting
# ---------------------------------------------------------------------------

#: Protocol specific probes.  All probes are read-only and harmless.
PROBES: dict[str, bytes] = {
    "http": (
        b"GET / HTTP/1.0\r\n"
        b"Host: {host}\r\n"
        b"User-Agent: " + USER_AGENT.encode("ascii") + b"\r\n"
        b"Accept: */*\r\n"
        b"Accept-Encoding: identity\r\n"
        b"Connection: close\r\n\r\n"
    ),
    "smtp": b"EHLO net-spectre.local\r\n",
    "redis": b"INFO server\r\n",
    "memcached": b"version\r\n",
    "rtsp": (
        b"OPTIONS rtsp://{host}:554/ RTSP/1.0\r\n"
        b"CSeq: 1\r\n"
        b"User-Agent: " + USER_AGENT_SHORT.encode("ascii") + b"\r\n\r\n"
    ),
    "mqtt": b"\x10\x0c\x00\x04MQTT\x04\x02\x00\x3c\x00\x00",
    "echo": b"\r\n",
}

#: Ordered banner signatures: (compiled regex, canonical service, confidence).
#: The regex is matched against the decoded banner / HTTP response text.
BANNER_SIGNATURES: tuple[tuple[str, str, str, int], ...] = (
    (r"^SSH-(\d+\.\d+)-(\S+)", "ssh", "high", 95),
    (r"^220[ -].*?(?:FTP|FileZilla|vsftpd|ProFTPD|Pure-FTPd)", "ftp", "high", 90),
    (r"^220[ -].*?(?:SMTP|Postfix|Exim|Sendmail|MailEnable|Microsoft ESMTP)", "smtp", "high", 90),
    (r"^\* OK.*?(?:IMAP|Dovecot|Courier)", "imap", "high", 90),
    (r"^\+OK.*", "pop3", "high", 75),
    (r"^RFB (\d{3}\.\d{3})", "vnc", "high", 95),
    (r"^-ERR unknown command|^\+PONG", "redis", "high", 90),
    (r"^STAT pid|^VERSION ", "memcached", "high", 90),
    (r"^AMQP\x00", "amqp", "high", 90),
    (r"^MQTT", "mqtt", "medium", 70),
    (r"^MySQL|^\x0a\d+\.\d+\.\d+", "mysql", "medium", 70),
    (r"^HTTP/\d\.\d", "http", "high", 90),
    (r"^RTSP/\d\.\d", "rtsp", "high", 90),
    (r"^SIP/\d\.\d", "sip", "medium", 70),
    (r"^(\d{3})[ -].*?(?:telnet|login)", "telnet", "medium", 65),
)

#: HTTP ``Server`` header product parsing.  Order matters: the first match wins.
SERVER_PRODUCTS: tuple[tuple[str, str], ...] = (
    (r"(?i)nginx(?:/([0-9.]+))?", "nginx"),
    (r"(?i)apache(?:/([0-9.]+))?", "Apache httpd"),
    (r"(?i)microsoft-iis(?:/([0-9.]+))?", "Microsoft IIS"),
    (r"(?i)lighttpd(?:/([0-9.]+))?", "lighttpd"),
    (r"(?i)caddy(?:/([0-9.]+))?", "Caddy"),
    (r"(?i)openresty(?:/([0-9.]+))?", "OpenResty"),
    (r"(?i)cloudflare", "Cloudflare"),
    (r"(?i)awselb(?:/([0-9.]+))?", "AWS ELB"),
    (r"(?i)gunicorn(?:/([0-9.]+))?", "Gunicorn"),
    (r"(?i)uvicorn", "Uvicorn"),
    (r"(?i)jetty(?:\(([0-9.]+)\))?", "Jetty"),
    (r"(?i)tomcat(?:/([0-9.]+))?", "Apache Tomcat"),
    (r"(?i)werkzeug(?:/([0-9.]+))?", "Werkzeug"),
    (r"(?i)php(?:/([0-9.]+))?", "PHP"),
)

#: Vendor keywords used to infer what a device probably is.
VENDOR_DEVICE_HINTS: tuple[tuple[str, str], ...] = (
    ("espressif", "IoT / embedded device"),
    ("raspberry pi", "Single board computer"),
    ("sonos", "Smart speaker"),
    ("roku", "Streaming device"),
    ("amazon", "Amazon device (Echo / Fire TV / Kindle)"),
    ("google", "Google device (Chromecast / Nest)"),
    ("apple", "Apple device"),
    ("samsung", "Samsung device"),
    ("xiaomi", "Xiaomi device"),
    ("huawei", "Huawei device"),
    ("ubiquiti", "Network equipment (Ubiquiti)"),
    ("tp-link", "Network equipment (TP-Link)"),
    ("netgear", "Network equipment (Netgear)"),
    ("d-link", "Network equipment (D-Link)"),
    ("cisco", "Network equipment (Cisco)"),
    ("aruba", "Network equipment (Aruba)"),
    ("mikrotik", "Network equipment (MikroTik)"),
    ("avm", "Router / modem (AVM Fritz!Box)"),
    ("technicolor", "Router / modem"),
    ("sagemcom", "Router / modem"),
    ("zyxel", "Network equipment (Zyxel)"),
    ("intel", "Computer"),
    ("dell", "Computer"),
    ("lenovo", "Computer"),
    ("hp inc", "Computer"),
    ("hewlett packard", "Computer or printer"),
    ("canon", "Printer"),
    ("brother", "Printer"),
    ("epson", "Printer"),
    ("lexmark", "Printer"),
    ("xerox", "Printer"),
    ("synology", "NAS"),
    ("qnap", "NAS"),
    ("western digital", "NAS / storage"),
    ("seagate", "NAS / storage"),
    ("hikvision", "IP camera"),
    ("dahua", "IP camera"),
    ("axis", "IP camera"),
    ("reolink", "IP camera"),
    ("tuya", "Smart home device"),
    ("shelly", "Smart home device"),
    ("philips", "Smart home device"),
    ("lg electronics", "Smart TV / appliance"),
    ("sony", "Consumer electronics"),
    ("nintendo", "Game console"),
    ("microsoft", "Microsoft device"),
)

#: Hostname keywords used for device type inference.
HOSTNAME_DEVICE_HINTS: tuple[tuple[str, str], ...] = (
    ("iphone", "Apple iPhone"),
    ("ipad", "Apple iPad"),
    ("macbook", "Apple MacBook"),
    ("imac", "Apple iMac"),
    ("android", "Android device"),
    ("galaxy", "Samsung Galaxy device"),
    ("pixel", "Google Pixel device"),
    ("printer", "Printer"),
    ("print", "Printer"),
    ("nas", "NAS"),
    ("router", "Router"),
    ("gateway", "Router / gateway"),
    ("firewall", "Firewall"),
    ("switch", "Network switch"),
    ("access-point", "Access point"),
    ("ap-", "Access point"),
    ("camera", "IP camera"),
    ("cam-", "IP camera"),
    ("tv", "Smart TV"),
    ("chromecast", "Chromecast"),
    ("xbox", "Game console"),
    ("playstation", "Game console"),
    ("ps5", "Game console"),
    ("switch-", "Game console"),
    ("laptop", "Computer"),
    ("desktop", "Computer"),
    ("server", "Server"),
)

#: TCP ports that strongly suggest a device role.
PORT_DEVICE_HINTS: tuple[tuple[frozenset[int], str], ...] = (
    (frozenset({9100}), "Printer (JetDirect)"),
    (frozenset({515, 631}), "Printer"),
    (frozenset({548, 2049, 5000, 9000}), "NAS / file server"),
    (frozenset({8008, 8009}), "Chromecast / Google Cast"),
    (frozenset({32400}), "Plex media server"),
    (frozenset({3389}), "Windows host"),
    (frozenset({5060, 5061}), "VoIP device"),
    (frozenset({554, 8554}), "IP camera / RTSP device"),
    (frozenset({62078}), "Apple mobile device"),
    (frozenset({1883, 8883}), "MQTT / IoT device"),
    (frozenset({2375, 2376, 6443, 10250}), "Container host / Kubernetes node"),
    (frozenset({3306, 5432, 1433, 27017, 6379, 9200}), "Server with database services"),
)

#: Conservative OS guesses based on the IPv4 TTL of a ping reply.
TTL_OS_HINTS: tuple[tuple[int, str], ...] = (
    (255, "Network device / embedded OS"),
    (128, "Windows"),
    (64, "Linux / Unix / macOS / Android"),
    (32, "Embedded / legacy system"),
)

#: Ports used by the lightweight UDP prober.  These probes are best effort.
UDP_PROBE_PORTS: tuple[int, ...] = (53, 123, 161, 1900, 5353)

#: User facing port presets.
PORT_PRESETS: dict[str, tuple[int, ...]] = {
    "quick": QUICK_SCAN_PORTS,
    "common": TOP_TCP_PORTS,
    "full": tuple(range(1, 65536)),
    "web": (80, 81, 443, 8000, 8008, 8080, 8081, 8088, 8443, 8888, 9000, 9443),
    "database": (1433, 1521, 3306, 5432, 6379, 9042, 9200, 11211, 27017),
}
