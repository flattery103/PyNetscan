#!/usr/bin/env python3

"""
PyNetScan - single-file Linux network scanner with a curses TUI.

The program intentionally remains a standalone Python file. Optional mDNS
support uses zeroconf when it is installed, but every core feature uses only
Python's standard library and common Linux networking commands.
"""

import argparse
import asyncio
import copy
import csv
import errno
import math
import secrets
import threading
from collections import deque
import curses
import ipaddress
import json
import os
import re
import shutil
import socket
import ssl
import struct
import subprocess
import textwrap
import time
import urllib.request
from dataclasses import asdict, dataclass, field, fields, replace
from datetime import datetime
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple

# ============================================================
# VERSION / CONFIG
# ============================================================

VERSION = "2.1.0"
APP_NAME = "PyNetScan"

AUTO_DETECT_SUBNET = True
CUSTOM_SUBNETS = ["192.168.1.0/24"]

# TCP-only lists. UDP-oriented services are intentionally not mixed into
# these profiles.
QUICK_TCP_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 515, 554, 631,
    993, 995, 1433, 1883, 2375, 3306, 3389, 5432, 5900, 5985, 6379, 8080,
    8443, 9100,
]

STANDARD_TCP_PORTS = [
    20, 21, 22, 23, 25, 53, 80, 88, 110, 111, 119, 135, 139, 143, 389,
    443, 445, 465, 512, 513, 514, 515, 548, 554, 587, 631, 636, 873, 902,
    989, 990, 993, 995, 1080, 1433, 1521, 1723, 1883, 2049, 2375, 2376,
    3306, 3389, 3690, 4369, 5060, 5061, 5432, 5671, 5672, 5900, 5985,
    5986, 6379, 6443, 6667, 7001, 8000, 8008, 8080, 8081, 8443, 8530,
    8531, 8883, 9000, 9042, 9092, 9100, 9200, 9300, 9418, 9999, 11211,
    15672, 27017, 27018, 27019,
]

# Deep scans add the well-known range plus selected higher-value ports.
DEEP_TCP_PORTS = sorted(set(range(1, 1025)).union(STANDARD_TCP_PORTS))

DISCOVERY_TCP_PORTS = [80, 443, 22, 445, 3389, 8080, 8443, 9100]

DEFAULT_TCP_TIMEOUT = 0.5
DEFAULT_HOST_CONCURRENCY = 200
DEFAULT_PORT_CONCURRENCY = 800
DEFAULT_MAX_RETRIES = 1
MIN_ADAPTIVE_TIMEOUT = 0.1
MAX_ADAPTIVE_TIMEOUT = 2.0

ARP_TIMEOUT = 1.0
ARP_BATCH_SIZE = 64
ARP_BATCH_LISTEN = 0.03

OUI_URL = "https://standards-oui.ieee.org/oui/oui.csv"
OUI_CACHE_FILE = os.path.expanduser("~/.cache/netscan/oui.json")
OUI_MAX_AGE_DAYS = 30
ALIASES_FILE = os.path.expanduser("~/.config/netscan/aliases.json")

MDNS_TIMEOUT = 2.0
SSDP_TIMEOUT = 2.0

LARGE_HOST_THRESHOLD = 4096
LARGE_ATTEMPT_THRESHOLD = 2_000_000

PROFILE_DESCRIPTIONS = {
    "discover": "Find responsive devices without a general port scan",
    "quick": "Common TCP services; fastest useful inventory",
    "standard": "Broad TCP service inventory (recommended)",
    "deep": "TCP 1-1024 plus common high ports and banners",
    "full": "All TCP ports 1-65535; slow and noisy",
    "custom": "Enter a custom TCP port list or ranges",
}

SERVICE_FALLBACK = {
    20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
    53: "domain", 67: "dhcp-server", 68: "dhcp-client", 69: "tftp",
    80: "http", 88: "kerberos", 110: "pop3", 111: "rpcbind",
    123: "ntp", 135: "msrpc", 137: "netbios-ns", 138: "netbios-dgm",
    139: "netbios-ssn", 143: "imap", 161: "snmp", 162: "snmptrap",
    389: "ldap", 443: "https", 445: "microsoft-ds", 465: "smtps",
    500: "isakmp", 514: "syslog", 515: "printer", 548: "afp",
    554: "rtsp", 587: "submission", 631: "ipp", 636: "ldaps",
    873: "rsync", 902: "vmware", 989: "ftps-data", 990: "ftps",
    993: "imaps", 995: "pop3s", 1080: "socks", 1433: "mssql",
    1521: "oracle", 1701: "l2tp", 1723: "pptp", 1812: "radius",
    1813: "radius-acct", 1883: "mqtt", 1900: "ssdp", 2049: "nfs",
    2375: "docker", 2376: "docker-tls", 3306: "mysql", 3389: "rdp",
    3690: "svn", 4369: "epmd", 4789: "vxlan", 5060: "sip",
    5061: "sips", 5432: "postgresql", 5671: "amqps", 5672: "amqp",
    5900: "vnc", 5985: "winrm", 5986: "winrm-tls", 6379: "redis",
    6443: "kubernetes-api", 6667: "irc", 7001: "weblogic",
    8000: "http-alt", 8008: "http-alt", 8080: "http-proxy",
    8081: "http-alt", 8443: "https-alt", 8530: "wsus", 8531: "wsus-tls",
    8883: "mqtt-tls", 9000: "http-alt", 9042: "cassandra",
    9092: "kafka", 9100: "jetdirect", 9200: "elasticsearch",
    9300: "elasticsearch-node", 9418: "git", 9999: "distinct",
    11211: "memcached", 15672: "rabbitmq-mgmt", 27017: "mongodb",
    27018: "mongodb", 27019: "mongodb",
}

REVIEW_TCP_PORTS = {
    21: "FTP is unencrypted",
    23: "Telnet is unencrypted",
    111: "RPC service exposed",
    139: "Legacy NetBIOS file sharing",
    445: "SMB service exposed",
    1433: "Microsoft SQL Server exposed",
    1521: "Oracle database exposed",
    2375: "Unauthenticated Docker API may be dangerous",
    3306: "MySQL service exposed",
    3389: "Remote Desktop exposed",
    5432: "PostgreSQL service exposed",
    5900: "VNC remote access exposed",
    5985: "Unencrypted WinRM",
    6379: "Redis service exposed",
    7001: "WebLogic administration/service port",
    9200: "Elasticsearch service exposed",
    11211: "Memcached service exposed",
    27017: "MongoDB service exposed",
    27018: "MongoDB service exposed",
    27019: "MongoDB service exposed",
}

HTTP_PORTS = {
    80, 443, 2375, 2376, 5985, 5986, 6443, 8000, 8008, 8080, 8081,
    8443, 8530, 8531, 9000, 9200, 15672,
}
HTTPS_PORTS = {443, 2376, 5986, 6443, 8443, 8531}
GREETING_PORTS = {21, 22, 25, 110, 143, 465, 587, 993, 995}

# ============================================================
# MODEL
# ============================================================

# A compact byte per port avoids millions of Python result objects on full scans.
PROBE_STATES = (
    "not_scanned", "open", "refused", "no_response", "error", "responded",
    "unverified_response", "unsupported",
)
STATE_CODE = {state: index for index, state in enumerate(PROBE_STATES)}


@dataclass
class ProbeResult:
    state: str
    detail: str = ""
    elapsed: float = 0.0
    attempts: int = 1
    verified: bool = False

    def __bool__(self) -> bool:
        return self.state in {"open", "responded"}


@dataclass
class PortResults:
    codes: bytearray = field(default_factory=bytearray, repr=False)
    details: Dict[int, str] = field(default_factory=dict)
    attempts: int = 0
    completed: int = 0
    last_response_at: Optional[str] = None

    def record(self, port: int, result: ProbeResult) -> None:
        if len(self.codes) <= port:
            self.codes.extend(b"\x00" * (port + 1 - len(self.codes)))
        self.codes[port] = STATE_CODE[result.state]
        self.attempts += result.attempts
        if result.state in {"open", "refused", "responded", "unverified_response"}:
            self.last_response_at = datetime.now().isoformat(timespec="seconds")
        # Common outcomes need no per-port string allocation. Bound diagnostics
        # when a whole large range fails for the same local resource reason.
        if result.detail and (port in self.details or len(self.details) < 256):
            self.details[port] = result.detail[:300]

    def state(self, port: int) -> str:
        return PROBE_STATES[self.codes[port]] if port < len(self.codes) else "not_scanned"

    def ports(self, state: str) -> List[int]:
        code = STATE_CODE[state]
        return [port for port, value in enumerate(self.codes) if value == code and port > 0]

    def count(self, state: Optional[str] = None) -> int:
        if state is not None:
            return self.codes.count(STATE_CODE[state])
        return len(self.codes) - self.codes.count(0)

    def to_dict(self) -> Dict[str, object]:
        return {
            "state_ranges": {
                state: compact_ranges(self.ports(state))
                for state in PROBE_STATES[1:] if self.count(state)
            },
            "details": {str(port): text for port, text in sorted(self.details.items())},
            "attempts": self.attempts,
            "completed_ports": self.completed,
            "last_response_at": self.last_response_at,
            "default_state": "not_scanned",
        }


def compact_ranges(ports: Sequence[int]) -> str:
    """Encode sorted ports as inclusive ranges without discarding exact scope."""
    if not ports:
        return ""
    values = sorted(set(ports))
    result: List[str] = []
    start = end = values[0]
    for port in values[1:]:
        if port == end + 1:
            end = port
        else:
            result.append(str(start) if start == end else f"{start}-{end}")
            start = end = port
    result.append(str(start) if start == end else f"{start}-{end}")
    return ",".join(result)


@dataclass
class DiscoveryResult:
    alive: bool
    ttl: Optional[int] = None
    method: str = ""
    outcome: str = "no_response"


@dataclass
class Host:
    ip: str
    mac: str = "-"
    manufacturer: str = "-"
    name: str = "(unknown)"
    open_tcp_ports: List[int] = field(default_factory=list)
    open_udp_ports: List[int] = field(default_factory=list)
    os_guess: str = "Unknown"
    device_type: str = "Unknown device"
    discovery_method: str = "Unknown"
    mdns_names: List[str] = field(default_factory=list)
    mdns_services: List[str] = field(default_factory=list)
    ssdp_locations: List[str] = field(default_factory=list)
    ssdp_meta: List[str] = field(default_factory=list)
    banners: Dict[str, str] = field(default_factory=dict)
    review_items: List[str] = field(default_factory=list)
    status: str = "CURRENT"
    changes: List[str] = field(default_factory=list)
    reachability: str = "unknown"
    last_seen: Optional[str] = None
    scan_completed_at: Optional[str] = None
    scan_cancelled: bool = False
    discovery_complete: bool = False
    tcp_complete: bool = False
    udp_complete: bool = False
    identification_complete: bool = False
    tcp_requested: int = 0
    udp_requested: int = 0
    tcp_results: PortResults = field(default_factory=PortResults)
    udp_results: PortResults = field(default_factory=PortResults)
    last_known_tcp_ports: List[int] = field(default_factory=list)
    last_known_udp_ports: List[int] = field(default_factory=list)

    @property
    def open_ports(self) -> List[int]:
        """Compatibility property for older code and callers."""
        return self.open_tcp_ports


@dataclass
class RouteInfo:
    interface: Optional[str]
    source_ip: Optional[str]
    gateway: Optional[str]
    direct: bool
    raw: str = ""


@dataclass
class ScanOptions:
    subnet: str
    profile: str
    tcp_ports: List[int]
    udp_ports: List[int]
    interface: Optional[str] = None
    tcp_timeout: float = DEFAULT_TCP_TIMEOUT
    host_concurrency: int = DEFAULT_HOST_CONCURRENCY
    port_concurrency: int = DEFAULT_PORT_CONCURRENCY
    enable_dns: bool = True
    enable_mdns: bool = True
    enable_ssdp: bool = True
    enable_banners: bool = False
    force: bool = False
    update_oui: bool = False
    enable_oui: bool = True
    output: Optional[str] = None
    auto_json: bool = False
    discovery_ports: Optional[List[int]] = None
    skip_discovery: bool = False
    max_rate: float = 0.0
    max_retries: int = DEFAULT_MAX_RETRIES
    adaptive_timeout: bool = True
    snmp_community: Optional[str] = field(default=None, repr=False)


@dataclass
class ScanReport:
    subnet: str
    profile: str
    started_at: str
    completed_at: str
    elapsed_seconds: float
    hosts: Dict[str, Host]
    warnings: List[str]
    cancelled: bool
    discovery_method: str
    route: RouteInfo
    tcp_ports: List[int]
    udp_ports: List[int]
    discovery_complete: bool = False
    discovery_outcomes: Dict[str, str] = field(default_factory=dict)
    settings: Dict[str, object] = field(default_factory=dict)

# ============================================================
# CLI
# ============================================================

def parse_ports_list(value: str) -> List[int]:
    """Parse comma-separated ports and inclusive ranges."""
    ports: Set[int] = set()
    if not value:
        return []

    for chunk in value.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        if "-" in chunk:
            start_text, end_text = chunk.split("-", 1)
            if not start_text.strip().isdigit() or not end_text.strip().isdigit():
                raise ValueError(f"Invalid port range '{chunk}'")
            start = int(start_text)
            end = int(end_text)
            if start > end:
                start, end = end, start
            if start < 1 or end > 65535:
                raise ValueError(f"Port range outside 1-65535: {chunk}")
            ports.update(range(start, end + 1))
        else:
            if not chunk.isdigit():
                raise ValueError(f"Invalid port '{chunk}'")
            port = int(chunk)
            if not 1 <= port <= 65535:
                raise ValueError(f"Port out of range: {port}")
            ports.add(port)
    return sorted(ports)


def parse_args():
    parser = argparse.ArgumentParser(
        description="PyNetScan - standalone Linux network scanner with a TUI"
    )
    parser.add_argument("-n", "--network", help="Subnet in CIDR notation")
    parser.add_argument(
        "--profile",
        choices=["discover", "quick", "standard", "deep", "full", "custom"],
        help="Scan profile; supplying this skips the startup profile menu",
    )
    parser.add_argument(
        "-a", "--all-ports", action="store_true",
        help="Scan all TCP ports 1-65535 (equivalent to --profile full)",
    )
    parser.add_argument(
        "-p", "--ports",
        help="Custom TCP ports/ranges, for example 22,80,443,8000-8100",
    )
    parser.add_argument(
        "--udp-ports",
        help="Optional response-based UDP probes, for example 53,123,137,161,1900",
    )
    parser.add_argument("--interface", help="Network interface to use, for example ens18")
    parser.add_argument(
        "--timeout", type=float, default=None,
        help=f"Fixed per-attempt TCP/UDP timeout; disables adaptive timing (default starts at {DEFAULT_TCP_TIMEOUT}s)",
    )
    parser.add_argument(
        "--concurrency", type=int, default=DEFAULT_HOST_CONCURRENCY,
        help=f"Concurrent hosts (default: {DEFAULT_HOST_CONCURRENCY})",
    )
    parser.add_argument(
        "--port-concurrency", type=int, default=DEFAULT_PORT_CONCURRENCY,
        help=f"Total concurrent TCP attempts (default: {DEFAULT_PORT_CONCURRENCY})",
    )
    parser.add_argument("--discovery-ports", help="TCP discovery ports/ranges; an explicit refusal also proves responsiveness")
    parser.add_argument("--skip-discovery", "--scan-all-targets", action="store_true",
                        help="Scan every target even when discovery probes would fail")
    parser.add_argument("--max-rate", type=float, default=0.0,
                        help="Maximum TCP/UDP probe attempts/sec, including discovery and retries (0: unlimited)")
    parser.add_argument("--max-retries", type=int, default=DEFAULT_MAX_RETRIES,
                        help="Retries for no-response probes only, 0-5 (default: 1)")
    parser.add_argument("--no-adaptive-timeout", action="store_true",
                        help="Use the default fixed timeout instead of adapting to measured responses")
    parser.add_argument("--snmp-community-env", metavar="VARIABLE",
                        help="Environment variable containing an explicitly supplied read-only SNMPv2c community; never guessed")
    parser.add_argument("--no-dns", action="store_true", help="Disable reverse DNS")
    parser.add_argument("--no-mdns", action="store_true", help="Disable mDNS discovery")
    parser.add_argument("--no-ssdp", action="store_true", help="Disable SSDP discovery")
    parser.add_argument("--banners", action="store_true", help="Enable basic service/banner detection")
    parser.add_argument("--output", help="Preferred export filename or base path")
    parser.add_argument("--json", action="store_true", help="Automatically export JSON after scanning")
    parser.add_argument("--force", action="store_true", help="Skip large-scan confirmation")
    parser.add_argument("--no-menu", action="store_true", help="Use the standard profile without a startup menu")
    parser.add_argument("--update-oui", action="store_true", help="Force an IEEE OUI database refresh")
    parser.add_argument("--no-oui", action="store_true", help="Disable manufacturer lookups")
    parser.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")
    args = parser.parse_args()

    if args.timeout is not None and (not math.isfinite(args.timeout) or args.timeout <= 0):
        parser.error("--timeout must be a finite number greater than zero")
    if not math.isfinite(args.max_rate) or args.max_rate < 0:
        parser.error("--max-rate must be a finite number greater than or equal to zero")
    if not 0 <= args.max_retries <= 5:
        parser.error("--max-retries must be between 0 and 5")
    if args.discovery_ports is not None:
        try:
            if not parse_ports_list(args.discovery_ports):
                raise ValueError("--discovery-ports must contain at least one port")
        except ValueError as exc:
            parser.error(str(exc))
    if args.snmp_community_env:
        community = os.environ.get(args.snmp_community_env, "")
        if not community or len(community.encode("utf-8")) > 255:
            parser.error("The SNMP community environment variable must contain 1-255 UTF-8 bytes")
    if args.concurrency < 1:
        parser.error("--concurrency must be at least 1")
    if args.port_concurrency < 1:
        parser.error("--port-concurrency must be at least 1")
    if args.profile == "custom" and not args.ports:
        parser.error("--profile custom requires --ports")
    return args


def ports_for_profile(profile: str) -> List[int]:
    if profile == "discover":
        return []
    if profile == "quick":
        return list(QUICK_TCP_PORTS)
    if profile == "standard":
        return list(STANDARD_TCP_PORTS)
    if profile == "deep":
        return list(DEEP_TCP_PORTS)
    if profile == "full":
        return list(range(1, 65536))
    return []

# ============================================================
# BASIC HELPERS / ROUTING
# ============================================================

def run_command(args: Sequence[str], timeout: float = 5.0) -> subprocess.CompletedProcess:
    return subprocess.run(
        list(args), capture_output=True, text=True, timeout=timeout, check=False
    )


def get_default_iface() -> Optional[str]:
    try:
        result = run_command(["ip", "-4", "route", "show", "default"])
        match = re.search(r"\bdev\s+(\S+)", result.stdout)
        return match.group(1) if match else None
    except (OSError, subprocess.SubprocessError):
        return None


def get_interface_ipv4(interface: str) -> Tuple[Optional[str], Optional[str]]:
    """Return (address, cidr) for an interface's first global IPv4 address."""
    try:
        result = run_command(["ip", "-o", "-4", "addr", "show", "dev", interface, "scope", "global"])
        match = re.search(r"\binet\s+(\d+\.\d+\.\d+\.\d+)/(\d+)", result.stdout)
        if match:
            address = match.group(1)
            cidr = str(ipaddress.ip_network(f"{address}/{match.group(2)}", strict=False))
            return address, cidr
    except (OSError, subprocess.SubprocessError, ValueError):
        pass
    return None, None


def get_route_info(target_ip: str, preferred_interface: Optional[str] = None) -> RouteInfo:
    try:
        result = run_command(["ip", "-4", "route", "get", target_ip])
        raw = result.stdout.strip()
        interface_match = re.search(r"\bdev\s+(\S+)", raw)
        source_match = re.search(r"\bsrc\s+(\d+\.\d+\.\d+\.\d+)", raw)
        gateway_match = re.search(r"\bvia\s+(\d+\.\d+\.\d+\.\d+)", raw)
        detected_interface = interface_match.group(1) if interface_match else None
        detected_source = source_match.group(1) if source_match else None
        if detected_interface and not detected_source:
            detected_source, _ = get_interface_ipv4(detected_interface)
        if preferred_interface:
            preferred_source, _ = get_interface_ipv4(preferred_interface)
            return RouteInfo(
                interface=preferred_interface,
                source_ip=preferred_source,
                gateway=gateway_match.group(1) if gateway_match else None,
                direct=gateway_match is None and detected_interface == preferred_interface,
                raw=raw + f" (user interface: {preferred_interface})",
            )
        return RouteInfo(
            interface=detected_interface,
            source_ip=detected_source,
            gateway=gateway_match.group(1) if gateway_match else None,
            direct=gateway_match is None and detected_interface is not None,
            raw=raw,
        )
    except (OSError, subprocess.SubprocessError):
        return RouteInfo(None, None, None, False, "")


def detect_local_subnet(preferred_interface: Optional[str] = None) -> Optional[str]:
    interface = preferred_interface or get_default_iface()
    if interface:
        _, cidr = get_interface_ipv4(interface)
        if cidr:
            return cidr

    # Compatibility fallback for minimal Linux installations.
    try:
        ips = run_command(["hostname", "-I"]).stdout.strip().split()
        if not ips:
            return None
        local_ip = ips[0]
        result = run_command(["ip", "-4", "route", "show", "scope", "link"])
        for line in result.stdout.splitlines():
            if f"src {local_ip}" in line:
                token = line.split()[0]
                if "/" in token:
                    return str(ipaddress.ip_network(token, strict=False))
    except (OSError, subprocess.SubprocessError, ValueError):
        pass
    return None


def usable_host_count(network: ipaddress.IPv4Network) -> int:
    if network.prefixlen == 32:
        return 1
    if network.prefixlen == 31:
        return 2
    return max(0, int(network.num_addresses) - 2)


def first_target_ip(network: ipaddress.IPv4Network) -> str:
    try:
        return str(next(iter(network.hosts())))
    except StopIteration:
        return str(network.network_address)


def load_aliases() -> Dict[str, str]:
    try:
        with open(ALIASES_FILE, encoding="utf-8") as file_handle:
            data = json.load(file_handle)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError, TypeError):
        return {}


def save_aliases(aliases: Dict[str, str]) -> None:
    os.makedirs(os.path.dirname(ALIASES_FILE), exist_ok=True)
    temp_file = ALIASES_FILE + ".tmp"
    with open(temp_file, "w", encoding="utf-8") as file_handle:
        json.dump(aliases, file_handle, indent=2, sort_keys=True)
    os.replace(temp_file, ALIASES_FILE)

# ============================================================
# OUI MANUFACTURER DATABASE
# ============================================================

def load_oui_cache() -> Tuple[Dict[str, str], bool]:
    try:
        with open(OUI_CACHE_FILE, encoding="utf-8") as file_handle:
            data = json.load(file_handle)
        age_seconds = time.time() - os.path.getmtime(OUI_CACHE_FILE)
        fresh = age_seconds <= OUI_MAX_AGE_DAYS * 86400
        return (data if isinstance(data, dict) else {}), fresh
    except (OSError, ValueError, TypeError):
        return {}, False


def save_oui(data: Dict[str, str]) -> None:
    os.makedirs(os.path.dirname(OUI_CACHE_FILE), exist_ok=True)
    temp_file = OUI_CACHE_FILE + ".tmp"
    with open(temp_file, "w", encoding="utf-8") as file_handle:
        json.dump(data, file_handle)
    os.replace(temp_file, OUI_CACHE_FILE)


def update_oui_database(cancel_event: Optional[asyncio.Event] = None) -> Tuple[Dict[str, str], Optional[str]]:
    try:
        chunks = []
        size = 0
        with urllib.request.urlopen(OUI_URL, timeout=3.0) as response:
            while not (cancel_event is not None and cancel_event.is_set()):
                chunk = response.read(65536)
                if not chunk:
                    break
                chunks.append(chunk)
                size += len(chunk)
                if size > 32 * 1024 * 1024:
                    raise ValueError("OUI download exceeds 32 MiB")
        if cancel_event is not None and cancel_event.is_set():
            return {}, "OUI refresh cancelled"
        text = b"".join(chunks).decode("utf-8", "replace")
    except Exception as exc:  # Network errors vary by Python/platform.
        return {}, f"OUI update failed: {exc}"

    mappings: Dict[str, str] = {}
    try:
        reader = csv.DictReader(text.splitlines())
        for row in reader:
            assignment = (row.get("Assignment") or "").replace("-", "").replace(":", "").upper()
            organization = (row.get("Organization Name") or "").strip()
            if len(assignment) == 6 and organization:
                mappings[assignment] = organization
    except (csv.Error, TypeError) as exc:
        return {}, f"OUI data could not be parsed: {exc}"

    if not mappings:
        return {}, "OUI update returned no usable assignments"
    try:
        if cancel_event is None or not cancel_event.is_set():
            save_oui(mappings)
    except OSError as exc:
        return mappings, f"OUI cache could not be saved: {exc}"
    return mappings, None


def get_oui_database(force_update: bool = False, cancel_event: Optional[asyncio.Event] = None) -> Tuple[Dict[str, str], Optional[str]]:
    cached, fresh = load_oui_cache()
    if cached and fresh and not force_update:
        return cached, None

    updated, warning = update_oui_database(cancel_event)
    if updated:
        return updated, warning
    if cached:
        fallback_warning = warning or "OUI refresh failed"
        return cached, f"{fallback_warning}; using the existing cache"
    return {}, warning or "Manufacturer database unavailable"


def oui_lookup(mac: str, oui: Dict[str, str]) -> str:
    normalized = mac.replace(":", "").replace("-", "").upper()
    if len(normalized) < 6:
        return "-"
    return oui.get(normalized[:6], "-")

# ============================================================
# RAW ARP DISCOVERY
# ============================================================

def build_arp_packet(source_mac: str, source_ip: str, target_ip: str) -> bytes:
    def mac_to_bytes(value: str) -> bytes:
        return bytes(int(part, 16) for part in value.split(":"))

    return struct.pack(
        "!HHBBH6s4s6s4s",
        1,                 # Ethernet
        0x0800,            # IPv4
        6,
        4,
        1,                 # Request
        mac_to_bytes(source_mac),
        socket.inet_aton(source_ip),
        b"\x00" * 6,
        socket.inet_aton(target_ip),
    )


def get_local_mac(interface: str) -> Optional[str]:
    try:
        with open(f"/sys/class/net/{interface}/address", encoding="ascii") as file_handle:
            return file_handle.read().strip()
    except OSError:
        return None


def parse_arp_reply(frame: bytes) -> Optional[Tuple[str, str]]:
    if len(frame) < 42:
        return None

    ethernet_type = struct.unpack("!H", frame[12:14])[0]
    arp_offset = 14
    if ethernet_type == 0x8100 and len(frame) >= 46:  # 802.1Q VLAN tag
        ethernet_type = struct.unpack("!H", frame[16:18])[0]
        arp_offset = 18
    if ethernet_type != 0x0806 or len(frame) < arp_offset + 28:
        return None

    arp = frame[arp_offset:arp_offset + 28]
    opcode = struct.unpack("!H", arp[6:8])[0]
    if opcode != 2:
        return None
    mac_address = ":".join(f"{byte:02x}" for byte in arp[8:14])
    ip_address = socket.inet_ntoa(arp[14:18])
    return ip_address, mac_address


def arp_sweep(
    subnet: str,
    interface: str,
    source_ip: str,
    progress: Dict[str, object],
    cancel_event: asyncio.Event,
) -> Tuple[Dict[str, str], Optional[str]]:
    source_mac = get_local_mac(interface)
    if not source_mac:
        return {}, f"Could not read a MAC address for interface {interface}"

    try:
        arp_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0806))
    except PermissionError:
        return {}, "Raw ARP is unavailable without root/CAP_NET_RAW; using ICMP/TCP fallback"
    except OSError as exc:
        return {}, f"Raw ARP is unavailable ({exc}); using ICMP/TCP fallback"

    try:
        arp_socket.bind((interface, 0))
        arp_socket.settimeout(ARP_BATCH_LISTEN)
    except OSError as exc:
        arp_socket.close()
        return {}, f"Could not bind ARP discovery to {interface}: {exc}"

    network = ipaddress.ip_network(subnet, strict=False)
    source_mac_bytes = bytes(int(part, 16) for part in source_mac.split(":"))
    ethernet_header = b"\xff" * 6 + source_mac_bytes + struct.pack("!H", 0x0806)
    results: Dict[str, str] = {}
    io_errors: List[str] = []

    def receive_until(deadline: float) -> None:
        while time.monotonic() < deadline and not cancel_event.is_set():
            try:
                frame = arp_socket.recv(2048)
            except socket.timeout:
                continue
            except OSError as exc:
                if not io_errors:
                    io_errors.append(str(exc))
                return
            parsed = parse_arp_reply(frame)
            if parsed:
                ip_address, mac_address = parsed
                if ipaddress.ip_address(ip_address) in network:
                    results[ip_address] = mac_address

    try:
        # A second pass helps with dropped frames while still avoiding a giant
        # in-memory list for unusually large, explicitly forced scans.
        for pass_number in range(2):
            batch_count = 0
            for address in network.hosts():
                if cancel_event.is_set():
                    break
                target_ip = str(address)
                if target_ip == source_ip or (pass_number == 1 and target_ip in results):
                    continue
                try:
                    packet = build_arp_packet(source_mac, source_ip, target_ip)
                    arp_socket.send(ethernet_header + packet)
                except OSError as exc:
                    if not io_errors:
                        io_errors.append(str(exc))
                progress["done"] = int(progress.get("done", 0)) + 1
                batch_count += 1
                if batch_count >= ARP_BATCH_SIZE:
                    receive_until(time.monotonic() + ARP_BATCH_LISTEN)
                    batch_count = 0
            receive_until(time.monotonic() + ARP_TIMEOUT)
            if cancel_event.is_set():
                break
    finally:
        arp_socket.close()

    return results, f"ARP I/O error: {io_errors[0]}; missing replies are inconclusive" if io_errors else None

# ============================================================
# ICMP / TCP / UDP PROBES
# ============================================================

def icmp_checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    total = (total >> 16) + (total & 0xFFFF)
    total += total >> 16
    return (~total) & 0xFFFF


def raw_icmp_supported() -> bool:
    try:
        test_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        test_socket.close()
        return True
    except OSError:
        return False


async def raw_icmp_ping(ip: str, timeout: float = 0.8) -> Tuple[bool, Optional[int]]:
    identifier = os.getpid() & 0xFFFF
    sequence = int(time.monotonic() * 1000) & 0xFFFF
    payload = b"PYNETSCAN"
    if len(payload) % 2:
        payload += b"\x00"
    header = struct.pack("!BBHHH", 8, 0, 0, identifier, sequence)
    checksum = icmp_checksum(header + payload)
    packet = struct.pack("!BBHHH", 8, 0, checksum, identifier, sequence) + payload

    try:
        icmp_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        icmp_socket.setblocking(False)
        icmp_socket.sendto(packet, (ip, 0))
    except OSError:
        try:
            icmp_socket.close()
        except Exception:
            pass
        return False, None

    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    try:
        while loop.time() < deadline:
            remaining = deadline - loop.time()
            try:
                data, address = await asyncio.wait_for(
                    recv_datagram(icmp_socket, 2048), timeout=remaining
                )
            except asyncio.TimeoutError:
                break
            except OSError:
                break
            if not address or address[0] != ip or len(data) < 28:
                continue
            ihl = (data[0] & 0x0F) * 4
            if len(data) < ihl + 8:
                continue
            icmp_type = data[ihl]
            response_id, response_sequence = struct.unpack("!HH", data[ihl + 4:ihl + 8])
            if icmp_type == 0 and response_id == identifier and response_sequence == sequence:
                return True, data[8]
    finally:
        icmp_socket.close()
    return False, None


async def system_ping(ip: str, timeout: float = 1.2) -> Tuple[bool, Optional[int]]:
    if not shutil.which("ping"):
        return False, None
    process = None
    try:
        process = await asyncio.create_subprocess_exec(
            "ping", "-n", "-c", "1", "-W", "1", ip,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL,
        )
        stdout, _ = await asyncio.wait_for(process.communicate(), timeout=timeout)
        match = re.search(r"\bttl[= ](\d+)", stdout.decode("utf-8", "ignore"), re.IGNORECASE)
        return process.returncode == 0, int(match.group(1)) if match else None
    except (OSError, asyncio.TimeoutError):
        return False, None
    finally:
        # communicate() cancellation alone does not terminate its child process.
        if process is not None and process.returncode is None:
            try:
                process.kill()
            except ProcessLookupError:
                pass
            await process.communicate()


async def tcp_connect(
    ip: str, port: int, semaphore: asyncio.Semaphore, timeout: float,
) -> ProbeResult:
    async with semaphore:
        writer = None
        started = time.monotonic()
        try:
            _, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=timeout)
            return ProbeResult("open", elapsed=time.monotonic() - started, verified=True)
        except (asyncio.TimeoutError, TimeoutError):
            return ProbeResult("no_response", elapsed=time.monotonic() - started)
        except OSError as exc:
            if exc.errno == errno.ECONNREFUSED or isinstance(exc, ConnectionRefusedError):
                return ProbeResult("refused", elapsed=time.monotonic() - started, verified=True)
            if exc.errno == errno.ETIMEDOUT:
                return ProbeResult("no_response", elapsed=time.monotonic() - started)
            return ProbeResult("error", f"{exc.__class__.__name__}: {exc}", time.monotonic() - started)
        finally:
            if writer is not None:
                writer.close()
                try:
                    await asyncio.wait_for(writer.wait_closed(), timeout=0.2)
                except (OSError, AttributeError, asyncio.TimeoutError):
                    pass


@dataclass
class UDPRequest:
    payload: bytes
    protocol: str
    token: bytes = b""
    community: bytes = field(default=b"", repr=False)


def encode_netbios_name(name: bytes) -> bytes:
    if len(name) != 16:
        raise ValueError("A NetBIOS name must contain exactly 16 bytes")
    return bytes(part for byte in name for part in (65 + (byte >> 4), 65 + (byte & 15)))


def netbios_query(transaction_id: Optional[bytes] = None) -> bytes:
    transaction_id = transaction_id or secrets.token_bytes(2)
    wildcard = encode_netbios_name(b"*" + b"\x00" * 15)
    return transaction_id + bytes.fromhex("00000001000000000000") + b"\x20" + wildcard + b"\x00\x00\x21\x00\x01"


def dns_name(data: bytes, offset: int) -> Tuple[bytes, int]:
    """Read a bounded DNS-style name, including compression pointers."""
    labels: List[bytes] = []
    end = None
    visited: Set[int] = set()
    length = 0
    while True:
        if offset >= len(data) or offset in visited:
            raise ValueError("Truncated or cyclic DNS name")
        visited.add(offset)
        size = data[offset]
        if size & 0xC0 == 0xC0:
            if offset + 1 >= len(data):
                raise ValueError("Truncated DNS pointer")
            if end is None:
                end = offset + 2
            offset = ((size & 63) << 8) | data[offset + 1]
            continue
        if size & 0xC0 or size > 63:
            raise ValueError("Invalid DNS label")
        offset += 1
        if not size:
            return b".".join(labels).lower(), end if end is not None else offset
        if offset + size > len(data):
            raise ValueError("Truncated DNS label")
        length += size + 1
        if length > 255:
            raise ValueError("Oversized DNS name")
        labels.append(data[offset:offset + size])
        offset += size


def dns_records(data: bytes) -> Tuple[int, List[Tuple[bytes, int, int]], List[Tuple[int, int, bytes]]]:
    if len(data) < 12:
        raise ValueError("Truncated DNS header")
    _, flags, questions, answers, authorities, additional = struct.unpack("!6H", data[:12])
    if questions + answers + authorities + additional > 512:
        raise ValueError("Too many DNS records")
    offset = 12
    parsed_questions = []
    records = []
    for _ in range(questions):
        name, offset = dns_name(data, offset)
        if offset + 4 > len(data):
            raise ValueError("Truncated DNS question")
        rtype, rclass = struct.unpack("!HH", data[offset:offset + 4])
        parsed_questions.append((name, rtype, rclass))
        offset += 4
    for _ in range(answers + authorities + additional):
        _, offset = dns_name(data, offset)
        if offset + 10 > len(data):
            raise ValueError("Truncated DNS resource record")
        rtype, rclass, _, size = struct.unpack("!HHIH", data[offset:offset + 10])
        offset += 10
        if offset + size > len(data):
            raise ValueError("Truncated DNS resource data")
        records.append((rtype, rclass, data[offset:offset + size]))
        offset += size
    return flags, parsed_questions, records


def parse_netbios_response(data: bytes, transaction_id: bytes) -> Tuple[bool, str]:
    try:
        if data[:2] != transaction_id:
            return False, "NetBIOS transaction ID did not match"
        flags, _, records = dns_records(data)
        if flags & 0x8000 == 0 or flags & 0x780F:
            return False, "Not a successful NetBIOS status response"
        for rtype, rclass, payload in records:
            if rtype != 0x21 or rclass != 1 or not payload:
                continue
            count = payload[0]
            if len(payload) < 1 + count * 18 + 6:
                continue
            candidates = []
            for index in range(count):
                entry = payload[1 + index * 18:1 + (index + 1) * 18]
                flags = struct.unpack("!H", entry[16:18])[0]
                if flags & 0x8000:  # Group/workgroup names are not hostnames.
                    continue
                name = entry[:15].decode("ascii", "replace").strip(" \x00")
                if not name or any(ord(char) < 32 for char in name):
                    continue
                priority = 0 if entry[15] == 0 else 1 if entry[15] == 0x20 else 2
                candidates.append((priority, name))
            return True, min(candidates)[1] if candidates else ""
    except (ValueError, struct.error, IndexError):
        pass
    return False, "Malformed NetBIOS status response"


def ber_tlv(tag: int, payload: bytes) -> bytes:
    size = len(payload)
    if size < 128:
        length = bytes([size])
    else:
        raw = size.to_bytes((size.bit_length() + 7) // 8, "big")
        length = bytes([0x80 | len(raw)]) + raw
    return bytes([tag]) + length + payload


def read_ber(data: bytes, offset: int = 0) -> Tuple[int, bytes, int]:
    if offset + 2 > len(data):
        raise ValueError("Truncated BER value")
    tag, size = data[offset:offset + 2]
    offset += 2
    if size & 0x80:
        count = size & 127
        if count == 0 or count > 4 or offset + count > len(data):
            raise ValueError("Invalid BER length")
        size = int.from_bytes(data[offset:offset + count], "big")
        offset += count
    end = offset + size
    if end > len(data):
        raise ValueError("Truncated BER payload")
    return tag, data[offset:end], end


def ber_integer(value: int) -> bytes:
    payload = value.to_bytes(max(1, (value.bit_length() + 8) // 8), "big")
    return ber_tlv(2, payload)


SNMP_SYSDESCR_OID = bytes.fromhex("2b06010201010100")


def make_udp_request(port: int, snmp_community: Optional[str] = None) -> Optional[UDPRequest]:
    if port == 53:
        token = secrets.token_bytes(2)
        # A root NS query with recursion disabled avoids triggering recursive
        # lookups of an unrelated external hostname on every discovered resolver.
        payload = token + bytes.fromhex("000000010000000000000000020001")
        return UDPRequest(payload, "dns", token)
    if port == 123:
        now = time.time() + 2208988800
        token = struct.pack("!II", int(now) & 0xFFFFFFFF, int((now % 1) * (1 << 32)))
        return UDPRequest(b"\x23" + b"\x00" * 39 + token, "ntp", token)
    if port == 137:
        token = secrets.token_bytes(2)
        return UDPRequest(netbios_query(token), "netbios", token)
    if port == 161:
        if not snmp_community:
            return None
        community = snmp_community.encode("utf-8")
        if len(community) > 255:
            raise ValueError("SNMP community is too long")
        request_id = secrets.randbelow(0x7FFFFFFE) + 1
        oid = ber_tlv(6, SNMP_SYSDESCR_OID)
        bindings = ber_tlv(0x30, ber_tlv(0x30, oid + ber_tlv(5, b"")))
        pdu = ber_tlv(0xA0, ber_integer(request_id) + ber_integer(0) + ber_integer(0) + bindings)
        payload = ber_tlv(0x30, ber_integer(1) + ber_tlv(4, community) + pdu)
        return UDPRequest(payload, "snmp", request_id.to_bytes(4, "big"), community)
    if port == 1900:
        payload = (
            "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n"
            'MAN: "ssdp:discover"\r\nMX: 1\r\nST: ssdp:all\r\n\r\n'
        ).encode()
        return UDPRequest(payload, "ssdp")
    return UDPRequest(b"\x00", "generic")


def udp_probe_payload(port: int) -> bytes:
    """Compatibility helper. An empty value means the probe is unsupported."""
    request = make_udp_request(port)
    return request.payload if request is not None else b""


def ssdp_headers(data: bytes) -> Optional[Dict[str, str]]:
    lines = data.decode("utf-8", "replace").splitlines()
    if not lines or not re.fullmatch(r"HTTP/1\.[01]\s+200(?:\s+.*)?", lines[0].strip(), re.I):
        return None
    headers = {}
    for line in lines[1:]:
        if not line.strip():
            break
        key, separator, value = line.partition(":")
        if separator:
            headers[key.strip().lower()] = value.strip()
    if not headers.get("st") or not headers.get("usn"):
        return None
    return headers


def validate_snmp_response(request: UDPRequest, data: bytes) -> Tuple[bool, str]:
    try:
        tag, message, end = read_ber(data)
        if tag != 0x30 or end != len(data):
            return False, "Invalid SNMP envelope"
        tag, version, pos = read_ber(message)
        if tag != 2 or int.from_bytes(version, "big", signed=True) != 1:
            return False, "Not an SNMPv2c response"
        tag, community, pos = read_ber(message, pos)
        if tag != 4 or not secrets.compare_digest(community, request.community):
            return False, "SNMP response did not match the request"
        tag, pdu, pos = read_ber(message, pos)
        if tag != 0xA2 or pos != len(message):
            return False, "Not an SNMP GetResponse"
        tag, value, offset = read_ber(pdu)
        if tag != 2 or int.from_bytes(value, "big", signed=True) != int.from_bytes(request.token, "big"):
            return False, "SNMP request ID did not match"
        tag, status, offset = read_ber(pdu, offset)
        if tag != 2:
            return False, "Invalid SNMP error status"
        error_status = int.from_bytes(status, "big", signed=True)
        tag, _, offset = read_ber(pdu, offset)
        if tag != 2:
            return False, "Invalid SNMP error index"
        tag, bindings, offset = read_ber(pdu, offset)
        if tag != 0x30 or offset != len(pdu):
            return False, "Invalid SNMP bindings"
        if error_status:
            return True, f"SNMPv2c responded with error status {error_status}; sysDescr not read"
        tag, binding, end = read_ber(bindings)
        if tag != 0x30 or end != len(bindings):
            return False, "Unexpected SNMP bindings"
        tag, oid, offset = read_ber(binding)
        if tag != 6 or oid != SNMP_SYSDESCR_OID:
            return False, "SNMP OID did not match sysDescr.0"
        tag, value, offset = read_ber(binding, offset)
        if offset != len(binding):
            return False, "Invalid SNMP value"
        if tag == 4:
            text = re.sub(r"\s+", " ", value.decode("utf-8", "replace")).strip()
            return True, "SNMPv2c sysDescr: " + text[:220]
        if tag in (0x80, 0x81):
            return True, "SNMPv2c responded; sysDescr.0 is unavailable"
        return False, "Unexpected sysDescr value type"
    except (ValueError, IndexError, struct.error):
        return False, "Malformed SNMP response"


def validate_udp_response(request: UDPRequest, data: bytes) -> Tuple[bool, str]:
    """Validate the reply against this request, not merely its UDP port number."""
    try:
        if request.protocol == "dns":
            if data[:2] != request.token:
                return False, "DNS transaction ID did not match"
            flags, questions, _ = dns_records(data)
            _, expected, _ = dns_records(request.payload)
            if flags & 0x8000 == 0 or flags & 0x7800 or questions != expected:
                return False, "DNS response/question did not match"
            return True, f"DNS reply (rcode={flags & 15})"
        if request.protocol == "ntp":
            if (len(data) < 48 or data[0] & 7 != 4 or (data[0] >> 3) & 7 not in (3, 4)
                    or data[24:32] != request.token or data[40:48] == b"\x00" * 8 or data[1] > 16):
                return False, "NTP header/origin timestamp did not match"
            if data[1] == 0:
                return True, "NTP response: kiss-of-death " + data[12:16].decode("ascii", "replace")
            return True, f"NTP server reply (stratum={data[1]})"
        if request.protocol == "netbios":
            valid, name = parse_netbios_response(data, request.token)
            return valid, ("NetBIOS name: " + name) if valid and name else ("NetBIOS status reply" if valid else name)
        if request.protocol == "ssdp":
            headers = ssdp_headers(data)
            return (True, "SSDP response: " + headers["st"][:160]) if headers else (False, "Invalid SSDP response")
        if request.protocol == "snmp":
            return validate_snmp_response(request, data)
    except (ValueError, struct.error, IndexError):
        return False, f"Malformed {request.protocol.upper()} response"
    return False, "Generic UDP reply; application protocol was not verified"


async def udp_probe(
    ip: str, port: int, semaphore: asyncio.Semaphore, timeout: float,
    snmp_community: Optional[str] = None,
) -> ProbeResult:
    request = make_udp_request(port, snmp_community)
    if request is None:
        return ProbeResult("unsupported", "SNMP probe skipped: no explicitly supplied community", attempts=0)
    async with semaphore:
        udp_socket = None
        started = time.monotonic()
        seen_reply = False
        invalid_detail = ""
        try:
            udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            udp_socket.setblocking(False)
            udp_socket.connect((ip, port))  # Accept datagrams only from this peer.
            loop = asyncio.get_running_loop()
            await asyncio.wait_for(loop.sock_sendall(udp_socket, request.payload), timeout)
            deadline = loop.time() + timeout
            while loop.time() < deadline:
                data = await asyncio.wait_for(loop.sock_recv(udp_socket, 65535), deadline - loop.time())
                seen_reply = True  # A zero-length datagram is still a datagram.
                valid, detail = validate_udp_response(request, data)
                if valid:
                    return ProbeResult("responded", detail, time.monotonic() - started, verified=True)
                invalid_detail = detail
                if request.protocol == "generic":
                    break
        except (asyncio.TimeoutError, TimeoutError):
            pass
        except OSError as exc:
            if exc.errno == errno.ECONNREFUSED or isinstance(exc, ConnectionRefusedError):
                return ProbeResult("refused", "UDP port unreachable/refused; may originate from an intermediary", time.monotonic() - started)
            return ProbeResult("error", f"{exc.__class__.__name__}: {exc}", time.monotonic() - started)
        finally:
            if udp_socket is not None:
                udp_socket.close()
        if seen_reply:
            return ProbeResult("unverified_response", invalid_detail, time.monotonic() - started)
        return ProbeResult("no_response", elapsed=time.monotonic() - started)


class RateLimiter:
    """Spacing, rather than a bursty token bucket, for TCP/UDP wire attempts."""
    def __init__(self, rate: float):
        self.interval = 1.0 / rate if rate > 0 else 0.0
        self.last = 0.0
        self.lock = asyncio.Lock()

    async def wait(self) -> None:
        if not self.interval:
            return
        async with self.lock:
            loop = asyncio.get_running_loop()
            delay = self.last + self.interval - loop.time()
            if delay > 0:
                await asyncio.sleep(delay)
            self.last = loop.time()


class _NoLimit:
    async def __aenter__(self):
        return self

    async def __aexit__(self, *_):
        return False


class ProbeController:
    """One connection budget, rate limiter and timing estimator per scan."""
    def __init__(self, options: ScanOptions, progress: Dict[str, object], warnings: List[str],
                 cancel_event: asyncio.Event, semaphore: Optional[asyncio.Semaphore] = None):
        self.options = options
        self.progress = progress
        self.warnings = warnings
        self.cancel_event = cancel_event
        self.concurrency = options.port_concurrency
        try:
            import resource
            soft_limit, _ = resource.getrlimit(resource.RLIMIT_NOFILE)
            if soft_limit != resource.RLIM_INFINITY:
                try:
                    in_use = len(os.listdir("/proc/self/fd"))
                except OSError:
                    in_use = 16
                self.concurrency = min(self.concurrency, max(1, soft_limit - in_use - 64))
        except (ImportError, OSError, ValueError):
            pass
        if self.concurrency < options.port_concurrency:
            self.warn(f"Connection concurrency reduced to {self.concurrency} to reserve file descriptors")
        self.semaphore = semaphore or asyncio.Semaphore(self.concurrency)
        self.rate_limiter = RateLimiter(options.max_rate)
        self.timings: Dict[Tuple[str, str], List[float]] = {}
        self.cooldown_until = 0.0
        self.no_limit = _NoLimit()

    def warn(self, message: str) -> None:
        if message not in self.warnings and len(self.warnings) < 100:
            self.warnings.append(message)

    def timeout_for(self, ip: str, protocol: str) -> float:
        if not self.options.adaptive_timeout:
            return self.options.tcp_timeout
        timing = self.timings.get((ip, protocol))
        return timing[3] if timing else self.options.tcp_timeout

    def observe(self, ip: str, protocol: str, result: ProbeResult) -> None:
        if not self.options.adaptive_timeout:
            return
        key = (ip, protocol)
        timing = self.timings.setdefault(key, [0.0, 0.0, 0.0, self.options.tcp_timeout])
        if result.state in {"open", "refused", "responded"} and result.elapsed > 0:
            if timing[2] == 0:
                timing[0], timing[1] = result.elapsed, result.elapsed / 2
            else:
                timing[1] = 0.75 * timing[1] + 0.25 * abs(timing[0] - result.elapsed)
                timing[0] = 0.875 * timing[0] + 0.125 * result.elapsed
            timing[2] += 1
            if timing[2] >= 4:
                timing[3] = min(MAX_ADAPTIVE_TIMEOUT, max(MIN_ADAPTIVE_TIMEOUT, timing[0] + 4 * timing[1]))
        elif result.state == "no_response":
            timing[3] = min(MAX_ADAPTIVE_TIMEOUT, max(self.options.tcp_timeout, timing[3] * 2))

    async def probe(self, ip: str, port: int, protocol: str = "tcp", record=None) -> ProbeResult:
        if protocol == "udp" and port == 161 and not self.options.snmp_community:
            self.warn("UDP 161 skipped: use --snmp-community-env for an explicitly authorized SNMPv2c read-only probe")
            result = ProbeResult("unsupported", "No explicit SNMP community; no datagram was sent", attempts=0)
            if record is not None:
                record(result)
            return result
        attempts = 0
        result = ProbeResult("not_scanned", attempts=0)
        for retry in range(self.options.max_retries + 1):
            if self.cancel_event.is_set():
                break
            async with self.semaphore:
                if self.cancel_event.is_set():
                    break
                delay = self.cooldown_until - time.monotonic()
                if delay > 0:
                    await asyncio.sleep(delay)
                await self.rate_limiter.wait()
                if self.cancel_event.is_set():
                    break
                timeout = self.timeout_for(ip, protocol)
                attempts += 1
                self.progress["wire_attempts"] = int(self.progress.get("wire_attempts", 0)) + 1
                if retry:
                    self.progress["retry_attempts"] = int(self.progress.get("retry_attempts", 0)) + 1
                if protocol == "tcp":
                    result = await tcp_connect(ip, port, self.no_limit, timeout)
                else:
                    result = await udp_probe(ip, port, self.no_limit, timeout, self.options.snmp_community)
            if record is not None:
                record(result)
            self.observe(ip, protocol, result)
            if result.state == "error":
                self.warn(f"Probe error for {ip}:{port}/{protocol}: {result.detail}")
                self.cooldown_until = time.monotonic() + 0.1
            if result.state != "no_response":
                break
        result.attempts = attempts
        return result


def effective_discovery_ports(options: ScanOptions) -> List[int]:
    if options.discovery_ports is not None:
        return list(options.discovery_ports)
    # A short custom list should all participate in discovery; a full port scan
    # must not accidentally become a full-range discovery scan of every address.
    selected = options.tcp_ports if len(options.tcp_ports) <= 32 else options.tcp_ports[:8]
    return list(dict.fromkeys(DISCOVERY_TCP_PORTS + selected))


async def icmp_ping(ip: str, use_raw_icmp: bool, timeout: float) -> Tuple[bool, Optional[int], str]:
    if use_raw_icmp:
        alive, ttl = await raw_icmp_ping(ip, max(0.4, min(timeout * 2, 1.5)))
    else:
        alive, ttl = await system_ping(ip)
    return alive, ttl, "ICMP" if alive else ""


async def hybrid_ping(
    ip: str, port_semaphore: asyncio.Semaphore, options: ScanOptions,
    use_raw_icmp: bool, controller: Optional[ProbeController] = None,
) -> DiscoveryResult:
    alive, ttl, method = await icmp_ping(ip, use_raw_icmp, options.tcp_timeout)
    if alive:
        return DiscoveryResult(True, ttl, method, "responsive")
    errors = False
    for port in effective_discovery_ports(options):
        if controller and controller.cancel_event.is_set():
            return DiscoveryResult(False, outcome="not_scanned")
        result = (await controller.probe(ip, port) if controller else
                  await tcp_connect(ip, port, port_semaphore, options.tcp_timeout))
        if result.state in {"open", "refused"}:
            evidence = "accepted" if result.state == "open" else "refused; possible intermediary"
            return DiscoveryResult(True, None, f"TCP/{port} ({evidence})", "responsive")
        errors = errors or result.state == "error"
    return DiscoveryResult(False, outcome="error" if errors else "no_response")


# ============================================================
# NAME / MULTICAST DISCOVERY
# ============================================================

# Native resolver/OUI calls cannot be interrupted in a worker thread. Daemon
# workers let cancelled scans return and the program exit without waiting on a
# stuck resolver. Bound their count, and never start new enrichment after q.
_BACKGROUND_SLOTS = threading.BoundedSemaphore(32)


def background_call(function, *args) -> asyncio.Future:
    loop = asyncio.get_running_loop()
    future = loop.create_future()
    if not _BACKGROUND_SLOTS.acquire(blocking=False):
        future.set_exception(RuntimeError("Background lookup limit reached"))
        return future

    def deliver(value, error):
        if not future.done():
            if error is not None:
                future.set_exception(error)
            else:
                future.set_result(value)

    def worker():
        value = error = None
        try:
            value = function(*args)
        except Exception as exc:
            error = exc
        finally:
            _BACKGROUND_SLOTS.release()
        try:
            loop.call_soon_threadsafe(deliver, value, error)
        except RuntimeError:
            pass  # The cancelled scan's loop has already closed.

    threading.Thread(target=worker, name="netscan-lookup", daemon=True).start()
    return future


async def reverse_dns(ip: str, timeout: float = 0.8) -> str:
    def lookup() -> str:
        return socket.gethostbyaddr(ip)[0]
    try:
        return await asyncio.wait_for(background_call(lookup), timeout=timeout)
    except (OSError, RuntimeError, asyncio.TimeoutError):
        return "-"


async def netbios_name(ip: str) -> str:
    transaction_id = secrets.token_bytes(2)
    packet = netbios_query(transaction_id)
    netbios_socket = None
    try:
        netbios_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        netbios_socket.setblocking(False)
        netbios_socket.connect((ip, 137))
        loop = asyncio.get_running_loop()
        await asyncio.wait_for(loop.sock_sendall(netbios_socket, packet), 0.4)
        deadline = loop.time() + 0.4
        while loop.time() < deadline:
            data = await asyncio.wait_for(loop.sock_recv(netbios_socket, 4096), deadline - loop.time())
            valid, name = parse_netbios_response(data, transaction_id)
            if valid:
                return name or "-"
    except (OSError, asyncio.TimeoutError):
        pass
    finally:
        if netbios_socket is not None:
            netbios_socket.close()
    return "-"


def ssdp_friendly_name(meta_lines: Sequence[str]) -> Optional[str]:
    # A USN is an identifier, not a friendly name. In particular, the "1" in
    # urn:schemas-upnp-org:device:MediaRenderer:1 is a device-type version.
    for line in meta_lines:
        key, separator, value = line.partition(":")
        if separator and key.strip().lower() in {"friendlyname", "x-friendly-name"}:
            candidate = value.strip()
            if candidate and not candidate.isdigit() and all(ord(char) >= 32 for char in candidate):
                return candidate[:200]
    return None


def pick_pretty_name(
    ip: str, aliases: Dict[str, str], mdns_hostnames: Dict[str, Set[str]],
    ssdp_name: Optional[str], netbios: str, rdns: str, manufacturer: str,
) -> str:
    if aliases.get(ip):
        return aliases[ip]
    if mdns_hostnames.get(ip):
        return sorted(mdns_hostnames[ip])[0]
    if netbios and netbios != "-":
        return netbios
    if rdns and rdns != "-":
        return rdns
    if ssdp_name:
        return ssdp_name
    if manufacturer and manufacturer != "-":
        return f"({manufacturer})"
    return "(unknown)"


async def resolve_name(
    ip: str, mdns_hostnames: Dict[str, Set[str]], aliases: Dict[str, str],
    manufacturer: str, ssdp_meta_lines: Sequence[str], enable_dns: bool,
) -> str:
    if aliases.get(ip) or mdns_hostnames.get(ip):
        return pick_pretty_name(ip, aliases, mdns_hostnames, None, "-", "-", manufacturer)
    tasks = [asyncio.create_task(netbios_name(ip))]
    if enable_dns:
        tasks.append(asyncio.create_task(reverse_dns(ip)))
    try:
        values = await asyncio.gather(*tasks)
        return pick_pretty_name(ip, aliases, mdns_hostnames, ssdp_friendly_name(ssdp_meta_lines),
                                values[0], values[1] if enable_dns else "-", manufacturer)
    finally:
        for task in tasks:
            if not task.done():
                task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)


async def pause_or_cancel(seconds: float, cancel_event: Optional[asyncio.Event]) -> None:
    if cancel_event is None:
        await asyncio.sleep(seconds)
    else:
        try:
            await asyncio.wait_for(cancel_event.wait(), timeout=seconds)
        except asyncio.TimeoutError:
            pass


async def mdns_discovery(
    cancel_event: Optional[asyncio.Event] = None,
) -> Tuple[Dict[str, Set[str]], Dict[str, Set[str]], Optional[str]]:
    try:
        from zeroconf.asyncio import AsyncServiceBrowser, AsyncZeroconf
    except ImportError:
        return {}, {}, "mDNS disabled because the optional 'zeroconf' module is not installed"

    hostnames: Dict[str, Set[str]] = {}
    services: Dict[str, Set[str]] = {}
    processing_tasks: Set[asyncio.Task] = set()
    seen: Set[Tuple[str, str]] = set()
    browsers = []
    async_zeroconf = None
    warning = None
    closing = False

    async def process_service(service_type: str, name: str) -> None:
        nonlocal warning
        try:
            info = await async_zeroconf.async_get_service_info(service_type, name, timeout=1000)
            if info:
                for address in info.addresses:
                    if len(address) == 4:
                        ip = socket.inet_ntoa(address)
                        if info.server:
                            hostnames.setdefault(ip, set()).add(info.server.rstrip("."))
                        services.setdefault(ip, set()).add(service_type.rstrip("."))
        except Exception as exc:
            warning = f"Some mDNS service details could not be read: {exc}"

    def handler(zeroconf, service_type, name, state_change) -> None:
        # zeroconf invokes these exact keyword names. Do not prefix them with _.
        nonlocal warning
        if closing or (cancel_event is not None and cancel_event.is_set()):
            return
        if str(getattr(state_change, "name", state_change)).lower().endswith("removed"):
            return
        key = (service_type, name)
        if key in seen:
            return
        if len(processing_tasks) >= 128:
            warning = "mDNS detail lookups limited to 128 concurrent services"
            return
        seen.add(key)
        task = asyncio.create_task(process_service(service_type, name))
        processing_tasks.add(task)
        task.add_done_callback(processing_tasks.discard)

    try:
        if cancel_event is not None and cancel_event.is_set():
            return hostnames, services, None
        async_zeroconf = AsyncZeroconf()
        service_types = ["_workstation._tcp.local.", "_http._tcp.local.", "_https._tcp.local.",
                         "_ssh._tcp.local.", "_printer._tcp.local.", "_ipp._tcp.local.", "_smb._tcp.local."]
        for service_type in service_types:
            browsers.append(AsyncServiceBrowser(async_zeroconf.zeroconf, service_type, handlers=[handler]))
        await pause_or_cancel(MDNS_TIMEOUT, cancel_event)
        if processing_tasks and not (cancel_event is not None and cancel_event.is_set()):
            await asyncio.wait(list(processing_tasks), timeout=1.1)
    except asyncio.CancelledError:
        pass  # Return whatever was collected, after closing the browsers below.
    except Exception as exc:
        warning = f"mDNS discovery failed: {exc}"
    finally:
        closing = True
        for browser in browsers:
            try:
                await asyncio.wait_for(browser.async_cancel(), timeout=1.0)
            except Exception as exc:
                warning = f"mDNS browser cleanup: {exc}"
        pending = list(processing_tasks)
        for task in pending:
            task.cancel()
        if pending:
            await asyncio.gather(*pending, return_exceptions=True)
        if async_zeroconf is not None:
            try:
                await asyncio.wait_for(async_zeroconf.async_close(), timeout=2.0)
            except Exception as exc:
                warning = f"mDNS shutdown: {exc}"
    return hostnames, services, warning


async def recv_datagram(sock: socket.socket, size: int):
    loop = asyncio.get_running_loop()
    if hasattr(loop, "sock_recvfrom"):
        return await loop.sock_recvfrom(sock, size)
    # Compatibility with Python versions before loop.sock_recvfrom was added.
    while True:
        try:
            return sock.recvfrom(size)
        except (BlockingIOError, InterruptedError):
            ready = loop.create_future()
            def readable():
                if not ready.done():
                    ready.set_result(None)
            loop.add_reader(sock.fileno(), readable)
            try:
                await ready
            finally:
                loop.remove_reader(sock.fileno())


async def ssdp_discovery(
    cancel_event: Optional[asyncio.Event] = None,
) -> Tuple[Dict[str, List[str]], Dict[str, List[str]], Optional[str]]:
    locations: Dict[str, List[str]] = {}
    metadata: Dict[str, List[str]] = {}
    ssdp_socket = None
    warning = None
    try:
        if cancel_event is not None and cancel_event.is_set():
            return locations, metadata, None
        ssdp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        ssdp_socket.setblocking(False)
        # A small nonblocking UDP send is immediate or fails; it cannot hold up q.
        ssdp_socket.sendto(make_udp_request(1900).payload, ("239.255.255.250", 1900))
        loop = asyncio.get_running_loop()
        deadline = loop.time() + SSDP_TIMEOUT
        while loop.time() < deadline and not (cancel_event is not None and cancel_event.is_set()):
            try:
                data, (ip, _) = await asyncio.wait_for(recv_datagram(ssdp_socket, 65535),
                                                     min(0.15, deadline - loop.time()))
            except asyncio.TimeoutError:
                continue
            headers = ssdp_headers(data)
            if headers is None:
                continue
            location = headers.get("location")
            if location and location not in locations.setdefault(ip, []):
                locations[ip].append(location)
            metadata.setdefault(ip, [])
            for key in ("st", "usn", "server", "friendlyname", "x-friendly-name"):
                value = headers.get(key)
                if value:
                    line = f"{key.upper()}: {value}"
                    if line not in metadata[ip]:
                        metadata[ip].append(line)
    except asyncio.CancelledError:
        pass
    except OSError as exc:
        warning = f"SSDP discovery failed: {exc}"
    finally:
        if ssdp_socket is not None:
            ssdp_socket.close()
    return locations, metadata, warning


# ============================================================
# IDENTIFICATION / BANNERS
# ============================================================

def ttl_to_os(ttl: Optional[int]) -> str:
    if ttl is None:
        return "Unknown"
    if ttl >= 200:
        return "Network/Unix"
    if ttl >= 100:
        return "Windows"
    if ttl >= 50:
        return "Linux/Unix"
    return "Unknown"


def service_name(port: int, protocol: str = "tcp") -> str:
    try:
        return socket.getservbyport(port, protocol)
    except OSError:
        return SERVICE_FALLBACK.get(port, "unknown")


def format_ports(ports: Sequence[int], protocol: str = "tcp", limit: Optional[int] = None) -> str:
    selected = list(ports if limit is None else ports[:limit])
    values = [f"{port}/{service_name(port, protocol)}" for port in selected]
    if limit is not None and len(ports) > limit:
        values.append("…")
    return ", ".join(values) if values else "none"


def classify_device(
    name: str,
    manufacturer: str,
    tcp_ports: Sequence[int],
    udp_ports: Sequence[int],
    mdns_services: Sequence[str],
    ssdp_meta: Sequence[str],
    os_guess: str,
) -> str:
    text = " ".join([name, manufacturer, *mdns_services, *ssdp_meta]).lower()
    tcp = set(tcp_ports)
    udp = set(udp_ports)

    if tcp.intersection({515, 631, 9100}) or any(word in text for word in ("printer", "jetdirect", "epson", "brother")):
        return "Printer"
    if 554 in tcp and any(word in text for word in ("camera", "hikvision", "axis", "dahua")):
        return "Camera"
    if any(word in text for word in ("access point", "wireless", "unifi ap", "ruckus", "aruba ap")):
        return "Wireless AP"
    if any(word in text for word in ("switch", "cisco", "meraki", "juniper", "arista", "netgear")) and not tcp.intersection({445, 3389}):
        return "Network device"
    if any(word in text for word in ("router", "firewall", "gateway", "pfsense", "fortinet", "sonicwall", "mikrotik")):
        return "Router/Firewall"
    if any(word in text for word in ("synology", "qnap", "nas")) or (tcp.intersection({445, 2049}) and 22 in tcp):
        return "NAS/File server"
    if 3389 in tcp or (445 in tcp and os_guess == "Windows"):
        return "Windows computer"
    if 22 in tcp and os_guess in ("Linux/Unix", "Network/Unix"):
        return "Linux/Unix host"
    if 1900 in udp or any(word in text for word in ("roku", "chromecast", "smart tv", "media")):
        return "Media/IoT device"
    if tcp.intersection({80, 443, 8080, 8443}) and not tcp.intersection({22, 445, 3389}):
        return "Web appliance"
    return "Unknown device"


def review_items_for_ports(tcp_ports: Sequence[int]) -> List[str]:
    return [f"TCP {port}/{service_name(port)}: {REVIEW_TCP_PORTS[port]}" for port in tcp_ports if port in REVIEW_TCP_PORTS]


async def open_stream(
    ip: str,
    port: int,
    timeout: float,
    use_tls: bool = False,
) -> Tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    ssl_context = None
    server_hostname = None
    if use_tls:
        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE
    return await asyncio.wait_for(
        asyncio.open_connection(ip, port, ssl=ssl_context, server_hostname=server_hostname),
        timeout=timeout,
    )


async def grab_banner(ip: str, port: int, timeout: float, semaphore: asyncio.Semaphore) -> Optional[str]:
    if port not in HTTP_PORTS and port not in GREETING_PORTS:
        return None

    async with semaphore:
        reader = None
        writer = None
        try:
            if port in HTTP_PORTS:
                reader, writer = await open_stream(ip, port, timeout, port in HTTPS_PORTS)
                request = (
                    f"GET / HTTP/1.0\r\nHost: {ip}\r\n"
                    f"User-Agent: PyNetScan/{VERSION}\r\nConnection: close\r\n\r\n"
                ).encode()
                writer.write(request)
                await writer.drain()
                data = await asyncio.wait_for(reader.read(8192), timeout=timeout)
                text = data.decode("utf-8", "ignore")
                status = text.splitlines()[0].strip() if text.splitlines() else "HTTP response"
                server_match = re.search(r"(?im)^Server:\s*(.+)$", text)
                title_match = re.search(r"(?is)<title[^>]*>(.*?)</title>", text)
                parts = [status]
                if server_match:
                    parts.append(f"Server={server_match.group(1).strip()}")
                if title_match:
                    title = re.sub(r"\s+", " ", title_match.group(1)).strip()
                    if title:
                        parts.append(f"Title={title[:120]}")
                return " | ".join(parts)[:300]

            reader, writer = await open_stream(ip, port, timeout, port in {465, 993, 995})
            data = await asyncio.wait_for(reader.read(512), timeout=timeout)
            banner = re.sub(r"\s+", " ", data.decode("utf-8", "ignore")).strip()
            return banner[:300] if banner else None
        except (OSError, ssl.SSLError, asyncio.TimeoutError):
            return None
        finally:
            if writer:
                writer.close()
                try:
                    await asyncio.wait_for(writer.wait_closed(), timeout=0.3)
                except (OSError, AttributeError, asyncio.TimeoutError):
                    pass


async def collect_banners(
    ip: str,
    open_ports: Sequence[int],
    timeout: float,
    semaphore: asyncio.Semaphore,
) -> Dict[str, str]:
    eligible = [port for port in open_ports if port in HTTP_PORTS or port in GREETING_PORTS]
    tasks = [asyncio.create_task(grab_banner(ip, port, timeout, semaphore)) for port in eligible]
    values = await asyncio.gather(*tasks, return_exceptions=True)
    banners: Dict[str, str] = {}
    for port, value in zip(eligible, values):
        if isinstance(value, str) and value:
            banners[f"{port}/tcp"] = value
    return banners

# ============================================================
# SCANNING ENGINE
# ============================================================

async def run_tasks_until_cancel(tasks: Sequence[asyncio.Task], cancel_event: asyncio.Event) -> None:
    """Cancel active workers promptly, retaining results already recorded."""
    if not tasks:
        return
    group = asyncio.gather(*tasks)
    watcher = asyncio.create_task(cancel_event.wait())
    try:
        await asyncio.wait([group, watcher], return_when=asyncio.FIRST_COMPLETED)
        if watcher.done() and cancel_event.is_set():
            for task in tasks:
                if not task.done():
                    task.cancel()
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for result in results:
                if isinstance(result, Exception):
                    raise result
        else:
            await group
    finally:
        watcher.cancel()
        for task in tasks:
            if not task.done():
                task.cancel()
        await asyncio.gather(watcher, *tasks, return_exceptions=True)
        # Retrieve the gather's cancellation/exception as well as each worker's.
        if not group.done():
            group.cancel()
        await asyncio.gather(group, return_exceptions=True)


async def optional_result(future, cancel_event: asyncio.Event, fallback=None):
    if future is None:
        return fallback
    watcher = asyncio.create_task(cancel_event.wait())
    try:
        if not future.done():
            await asyncio.wait([future, watcher], return_when=asyncio.FIRST_COMPLETED)
        if future.done() and not future.cancelled():
            return future.result()
        future.cancel()
        if isinstance(future, asyncio.Task):
            try:
                return await future
            except asyncio.CancelledError:
                pass
        return fallback
    finally:
        watcher.cancel()
        await asyncio.gather(watcher, return_exceptions=True)


async def discover_hosts(
    network: ipaddress.IPv4Network, route: RouteInfo, options: ScanOptions,
    progress: Dict[str, object], cancel_event: asyncio.Event, warnings: List[str],
    port_semaphore: asyncio.Semaphore, controller: Optional[ProbeController] = None,
    outcomes: Optional[Dict[str, str]] = None,
) -> Tuple[Dict[str, Dict[str, object]], Dict[str, str], str]:
    total_hosts = usable_host_count(network)
    controller = controller or ProbeController(options, progress, warnings, cancel_event, port_semaphore)
    outcomes = outcomes if outcomes is not None else {}
    arp_results: Dict[str, str] = {}
    discovery: Dict[str, Dict[str, object]] = {}
    progress["discovery_complete"] = False

    if options.skip_discovery:
        progress.update(stage="Selecting all targets (discovery skipped)", done=0, total=total_hosts)
        for index, address in enumerate(network.hosts()):
            if cancel_event.is_set():
                break
            discovery[str(address)] = {"mac": "-", "ttl": None, "method": "Discovery skipped", "responsive": False}
            progress["done"] = index + 1
            if index % 512 == 0:
                await asyncio.sleep(0)
        return discovery, {}, "Skipped; every selected address is scanned"

    if route.direct and route.interface and route.source_ip:
        progress.update(stage="ARP discovery", done=0, total=max(1, total_hosts * 2))
        arp_results, warning = await asyncio.get_running_loop().run_in_executor(
            None, arp_sweep, str(network), route.interface, route.source_ip, progress, cancel_event,
        )
        if warning:
            controller.warn(warning)
        for ip, mac in arp_results.items():
            discovery[ip] = {"mac": mac, "ttl": None, "method": "ARP", "responsive": True, "seen_at": datetime.now().isoformat(timespec="seconds")}
            outcomes[ip] = "responsive"
        if arp_results or cancel_event.is_set():
            progress["discovery_complete"] = not cancel_event.is_set() and not warning
            return discovery, arp_results, "ARP"
        controller.warn("ARP found no devices; probing each address with ICMP/TCP")
    elif route.gateway:
        controller.warn(f"Target is routed through {route.gateway}; ARP cannot discover remote devices")
    else:
        controller.warn("No directly connected route was found; using ICMP/TCP discovery")

    progress.update(stage="ICMP/TCP discovery", done=0, total=max(1, total_hosts))
    use_raw_icmp = raw_icmp_supported()
    if not use_raw_icmp and not shutil.which("ping"):
        controller.warn("Raw ICMP and ping are unavailable; discovery is TCP-only")
    address_iterator = iter(network.hosts())

    async def worker() -> None:
        while not cancel_event.is_set():
            try:
                ip = str(next(address_iterator))
            except StopIteration:
                return
            result = await hybrid_ping(ip, port_semaphore, options, use_raw_icmp, controller)
            if result.outcome == "not_scanned":
                return
            outcomes[ip] = result.outcome
            progress["done"] = int(progress.get("done", 0)) + 1
            if result.alive:
                discovery[ip] = {"mac": "-", "ttl": result.ttl, "method": result.method, "responsive": True, "seen_at": datetime.now().isoformat(timespec="seconds")}
                progress["hosts_discovered"] = len(discovery)

    count = min(options.host_concurrency, max(1, total_hosts))
    await run_tasks_until_cancel([asyncio.create_task(worker()) for _ in range(count)], cancel_event)
    progress["discovery_complete"] = int(progress["done"]) == total_hosts and not cancel_event.is_set()
    return discovery, arp_results, "ICMP/TCP"


class FairPortQueue:
    """A lazy round-robin queue with both an active-host and a worker bound.

    At most host_limit hosts have outstanding jobs, and at most worker_count
    jobs are in flight. A lone host can use the full global connection budget.
    No task or queued object is allocated for every target/port combination.
    """
    def __init__(self, ips: Sequence[str], ports: Sequence[int], host_limit: int):
        self.remaining = iter(ips)
        self.ports = ports
        self.active: Dict[str, List[int]] = {}
        self.ready = deque()
        self.condition = asyncio.Condition()
        if ports:
            for _ in range(min(len(ips), host_limit)):
                self.add_host()

    def add_host(self) -> None:
        try:
            ip = next(self.remaining)
        except StopIteration:
            return
        self.active[ip] = [0, 0]  # next port index, in-flight jobs
        self.ready.append(ip)

    async def next(self) -> Optional[Tuple[str, int]]:
        async with self.condition:
            while True:
                if self.ready:
                    ip = self.ready.popleft()
                    entry = self.active[ip]
                    port = self.ports[entry[0]]
                    entry[0] += 1
                    entry[1] += 1
                    if entry[0] < len(self.ports):
                        self.ready.append(ip)
                    return ip, port
                if not self.active:
                    return None
                await self.condition.wait()

    async def complete(self, ip: str) -> None:
        async with self.condition:
            entry = self.active[ip]
            entry[1] -= 1
            if entry[0] == len(self.ports) and entry[1] == 0:
                del self.active[ip]
                self.add_host()
            self.condition.notify_all()


async def scan_protocol(
    ips: Sequence[str], ports: Sequence[int], protocol: str, options: ScanOptions,
    progress: Dict[str, object], cancel_event: asyncio.Event, controller: ProbeController,
    results: Dict[str, PortResults],
) -> None:
    if not ips or not ports or cancel_event.is_set():
        return
    total = len(ips) * len(ports)
    progress.update(stage="TCP port scan" if protocol == "tcp" else "UDP response probes",
                    done=0, total=total, attempt_done=0, attempt_total=total,
                    open_count=0, rate_started=time.monotonic())
    queue = FairPortQueue(ips, ports, options.host_concurrency)

    async def worker() -> None:
        while not cancel_event.is_set():
            job = await queue.next()
            if job is None:
                return
            ip, port = job
            try:
                result = await controller.probe(ip, port, protocol, record=lambda value: results[ip].record(port, value))
                if result.state != "not_scanned":
                    results[ip].completed += 1
                    progress["done"] = int(progress.get("done", 0)) + 1
                    progress["attempt_done"] = int(progress.get("attempt_done", 0)) + 1
                    if result.state in {"open", "responded"}:
                        progress["open_count"] = int(progress.get("open_count", 0)) + 1
            finally:
                await queue.complete(ip)

    count = min(controller.concurrency, total)
    await run_tasks_until_cancel([asyncio.create_task(worker()) for _ in range(count)], cancel_event)


async def scan_tcp_ports_for_host(ip, ports, options, semaphore, progress, cancel_event) -> PortResults:
    results = {ip: PortResults()}
    controller = ProbeController(options, progress, [], cancel_event, semaphore)
    await scan_protocol([ip], ports, "tcp", options, progress, cancel_event, controller, results)
    return results[ip]


async def scan_udp_ports_for_host(ip, ports, options, semaphore, progress, cancel_event) -> PortResults:
    results = {ip: PortResults()}
    controller = ProbeController(options, progress, [], cancel_event, semaphore)
    await scan_protocol([ip], ports, "udp", options, progress, cancel_event, controller, results)
    return results[ip]


async def scan_all_ports(
    ips: Sequence[str], options: ScanOptions, progress: Dict[str, object],
    cancel_event: asyncio.Event, tcp_semaphore: asyncio.Semaphore,
    controller: Optional[ProbeController] = None,
    tcp_results: Optional[Dict[str, PortResults]] = None,
    udp_results: Optional[Dict[str, PortResults]] = None,
) -> Tuple[Dict[str, PortResults], Dict[str, PortResults]]:
    tcp_results = tcp_results if tcp_results is not None else {ip: PortResults() for ip in ips}
    udp_results = udp_results if udp_results is not None else {ip: PortResults() for ip in ips}
    controller = controller or ProbeController(options, progress, [], cancel_event, tcp_semaphore)
    await scan_protocol(ips, options.tcp_ports, "tcp", options, progress, cancel_event, controller, tcp_results)
    await scan_protocol(ips, options.udp_ports, "udp", options, progress, cancel_event, controller, udp_results)
    return tcp_results, udp_results


def update_host_observations(host: Host, options: ScanOptions, observed_at: str) -> None:
    host.open_tcp_ports = host.tcp_results.ports("open")
    host.open_udp_ports = host.udp_results.ports("responded")
    host.tcp_requested = len(options.tcp_ports)
    host.udp_requested = len(options.udp_ports)
    host.tcp_complete = host.tcp_results.completed == len(options.tcp_ports)
    host.udp_complete = host.udp_results.completed == len(options.udp_ports)
    responsive = (host.reachability == "responsive" or host.open_tcp_ports or host.open_udp_ports
                  or host.tcp_results.count("refused") or host.udp_results.count("refused")
                  or host.udp_results.count("unverified_response"))
    if responsive:
        host.reachability = "responsive"
        timestamps = [value for value in (host.last_seen, host.tcp_results.last_response_at,
                                          host.udp_results.last_response_at) if value]
        host.last_seen = max(timestamps) if timestamps else observed_at
    elif host.tcp_results.count("error") or host.udp_results.count("error"):
        host.reachability = "error"
    elif host.tcp_results.count("no_response") or host.udp_results.count("no_response"):
        host.reachability = "no_response"
    else:
        host.reachability = "not_scanned"
    host.review_items = review_items_for_ports(host.open_tcp_ports)


def base_host_status(host: Host) -> str:
    if host.tcp_results.count("error") or host.udp_results.count("error"):
        return "ERROR"
    if host.reachability == "responsive":
        return "CURRENT" if host.tcp_complete and host.udp_complete and host.identification_complete else "PARTIAL"
    if host.reachability == "error":
        return "ERROR"
    if host.reachability == "no_response":
        return "NOT_OBSERVED"
    return "NOT_SCANNED"


async def scan_subnet(options: ScanOptions, progress: Dict[str, object], cancel_event: asyncio.Event) -> ScanReport:
    started_wall = datetime.now()
    started_monotonic = time.monotonic()
    warnings: List[str] = []
    network = ipaddress.ip_network(options.subnet, strict=False)
    if network.version != 4:
        raise ValueError("Only IPv4 targets are supported")
    route = get_route_info(first_target_ip(network), options.interface)
    progress.update(stage="Preparing discovery", done=0, total=1, warnings=warnings,
                    scan_started=started_monotonic, open_count=0, wire_attempts=0, retry_attempts=0)
    controller = ProbeController(options, progress, warnings, cancel_event)
    if not route.interface:
        controller.warn("No route/interface could be determined for the target network")
    elif not route.source_ip:
        controller.warn(f"No IPv4 source address was found on {route.interface}")
    if options.max_rate:
        controller.warn("--max-rate limits TCP/UDP discovery and port probes, including retries; ARP, ICMP, multicast and enrichment are separate")

    oui_future = None
    mdns_task = ssdp_task = None
    outcomes: Dict[str, str] = {}
    hosts: Dict[str, Host] = {}
    discovery_method = "Not started"
    fatal_error = False
    aliases = load_aliases()
    try:
        if not cancel_event.is_set():
            if options.enable_oui:
                oui_future = background_call(get_oui_database, options.update_oui, cancel_event)
            if options.enable_mdns:
                mdns_task = asyncio.create_task(mdns_discovery(cancel_event))
            if options.enable_ssdp:
                ssdp_task = asyncio.create_task(ssdp_discovery(cancel_event))

        discovery, arp_results, discovery_method = await discover_hosts(
            network, route, options, progress, cancel_event, warnings, controller.semaphore, controller, outcomes,
        )
        mdns_h, mdns_s, mdns_warning = await optional_result(mdns_task, cancel_event, ({}, {}, None))
        ssdp_l, ssdp_m, ssdp_warning = await optional_result(ssdp_task, cancel_event, ({}, {}, None))
        for warning in (mdns_warning, ssdp_warning):
            if warning:
                controller.warn(warning)
        for ip in set(mdns_h).union(ssdp_l).union(ssdp_m):
            try:
                if ipaddress.ip_address(ip) in network:
                    entry = discovery.setdefault(ip, {"mac": arp_results.get(ip, "-"), "ttl": None})
                    entry.update(method="mDNS/SSDP", responsive=True, seen_at=datetime.now().isoformat(timespec="seconds"))
                    outcomes[ip] = "responsive"
            except ValueError:
                continue
        ips = sorted(discovery, key=ip_sort_key)
        progress["targets_selected"] = len(ips)
        progress["hosts_discovered"] = sum(bool(info.get("responsive")) for info in discovery.values())
        for ip in ips:
            details = discovery[ip]
            hosts[ip] = Host(
                ip=ip, mac=str(details.get("mac") or "-"),
                name=pick_pretty_name(ip, aliases, mdns_h, ssdp_friendly_name(ssdp_m.get(ip, [])), "-", "-", "-"),
                os_guess=ttl_to_os(details.get("ttl")),
                discovery_method=str(details.get("method", "Unknown")),
                discovery_complete=bool(details.get("responsive")),
                last_seen=(str(details.get("seen_at")) if details.get("seen_at") else started_wall.isoformat(timespec="seconds")) if details.get("responsive") else None,
                reachability="responsive" if details.get("responsive") else "not_scanned",
                mdns_names=sorted(mdns_h.get(ip, set())), mdns_services=sorted(mdns_s.get(ip, set())),
                ssdp_locations=ssdp_l.get(ip, []), ssdp_meta=ssdp_m.get(ip, []),
            )
        await scan_all_ports(
            ips, options, progress, cancel_event, controller.semaphore, controller,
            {ip: host.tcp_results for ip, host in hosts.items()},
            {ip: host.udp_results for ip, host in hosts.items()},
        )
        observed_at = datetime.now().isoformat(timespec="seconds")
        for host in hosts.values():
            update_host_observations(host, options, observed_at)
        progress["hosts_discovered"] = sum(host.reachability == "responsive" for host in hosts.values())

        oui: Dict[str, str] = {}
        try:
            oui, oui_warning = await optional_result(oui_future, cancel_event, ({}, None))
            if oui_warning:
                controller.warn(oui_warning)
        except Exception as exc:
            controller.warn(f"Manufacturer lookup unavailable: {exc}")
        for host in hosts.values():
            host.manufacturer = oui_lookup(host.mac, oui) if options.enable_oui else "-"
            if host.name == "(unknown)" and host.manufacturer != "-":
                host.name = f"({host.manufacturer})"

        progress.update(stage="Identifying devices", done=0, total=max(1, len(hosts)))
        host_iterator = iter(hosts.values())
        banner_semaphore = asyncio.Semaphore(min(controller.concurrency, 100))

        async def identify_worker() -> None:
            while not cancel_event.is_set():
                try:
                    host = next(host_iterator)
                except StopIteration:
                    return
                if host.reachability != "responsive":
                    progress["done"] = int(progress["done"]) + 1
                    continue
                host.name = await resolve_name(host.ip, mdns_h, aliases, host.manufacturer, host.ssdp_meta, options.enable_dns)
                if cancel_event.is_set():
                    return
                if options.enable_banners and host.open_tcp_ports:
                    host.banners = await collect_banners(host.ip, host.open_tcp_ports,
                        max(0.8, min(options.tcp_timeout * 4, 3.0)), banner_semaphore)
                host.identification_complete = True
                progress["done"] = int(progress["done"]) + 1

        if not cancel_event.is_set():
            count = min(options.host_concurrency, controller.concurrency, 100, len(hosts))
            await run_tasks_until_cancel([asyncio.create_task(identify_worker()) for _ in range(count)], cancel_event)
    except asyncio.CancelledError:
        cancel_event.set()
    except Exception as exc:
        fatal_error = True
        controller.warn(f"Scan stopped by an error: {exc.__class__.__name__}: {exc}")
    finally:
        for task in (mdns_task, ssdp_task):
            if task is not None and not task.done():
                task.cancel()
        await asyncio.gather(*(task for task in (mdns_task, ssdp_task) if task is not None), return_exceptions=True)
        if oui_future is not None and not oui_future.done():
            oui_future.cancel()
        elif oui_future is not None and not oui_future.cancelled():
            # Retrieve an error even when a different stage stopped before OUI was awaited.
            oui_future.exception()

    observed_at = datetime.now().isoformat(timespec="seconds")
    for host in hosts.values():
        update_host_observations(host, options, observed_at)
        host.scan_completed_at = observed_at
        host.scan_cancelled = cancel_event.is_set()
        host.device_type = classify_device(host.name, host.manufacturer, host.open_tcp_ports,
            host.open_udp_ports, host.mdns_services, host.ssdp_meta, host.os_guess)
        host.status = base_host_status(host)
    progress.update(stage="Cancelled" if cancel_event.is_set() else "Stopped with errors" if fatal_error else "Complete", done=1, total=1)
    return ScanReport(
        subnet=str(network), profile=options.profile,
        started_at=started_wall.isoformat(timespec="seconds"), completed_at=observed_at,
        elapsed_seconds=time.monotonic() - started_monotonic, hosts=hosts,
        warnings=list(dict.fromkeys(warnings)), cancelled=cancel_event.is_set(),
        discovery_method=discovery_method, route=route,
        tcp_ports=list(options.tcp_ports), udp_ports=list(options.udp_ports),
        discovery_complete=bool(progress.get("discovery_complete")) and not fatal_error,
        discovery_outcomes=outcomes,
        settings={"skip_discovery": options.skip_discovery,
                  "discovery_ports": effective_discovery_ports(options),
                  "timeout": options.tcp_timeout, "adaptive_timeout": options.adaptive_timeout,
                  "max_retries": options.max_retries, "max_rate": options.max_rate,
                  "effective_port_concurrency": controller.concurrency,
                  "host_concurrency": options.host_concurrency,
                  "wire_attempts": int(progress.get("wire_attempts", 0)),
                  "retry_attempts": int(progress.get("retry_attempts", 0)),
                  "snmp_probe_enabled": bool(options.snmp_community), "scan_error": fatal_error,
                  "probe_error_count": sum(h.tcp_results.count("error") + h.udp_results.count("error") for h in hosts.values())},
    )


# ============================================================
# CHANGE COMPARISON
# ============================================================

def compare_reports(previous: Optional[ScanReport], current: ScanReport) -> ScanReport:
    """Compare evidence, never infer closure from absence in a list of opens."""
    if previous is None:
        return current
    compared: Dict[str, Host] = {}
    network = ipaddress.ip_network(current.subnet, strict=False)
    for ip, host in current.hosts.items():
        old = previous.hosts.get(ip)
        positive = host.reachability == "responsive" or bool(host.open_tcp_ports or host.open_udp_ports)
        if old is None:
            if positive:
                host.changes = ["Newly discovered device"]
                host.status = ("ERROR" if base_host_status(host) == "ERROR" else
                               "NEW" if host.tcp_complete and host.udp_complete and host.identification_complete else "PARTIAL")
            compared[ip] = host
            continue

        changes: List[str] = []
        prior_tcp = set(old.open_tcp_ports).union(old.last_known_tcp_ports)
        prior_udp = set(old.open_udp_ports).union(old.last_known_udp_ports)
        current_tcp = set(host.open_tcp_ports)
        current_udp = set(host.open_udp_ports)
        refused_tcp = {port for port in prior_tcp if host.tcp_results.state(port) == "refused"}
        refused_udp = {port for port in prior_udp if host.udp_results.state(port) == "refused"}
        host.last_known_tcp_ports = sorted(prior_tcp - current_tcp - refused_tcp)
        host.last_known_udp_ports = sorted(prior_udp - current_udp - refused_udp)
        if not host.last_seen:
            host.last_seen = old.last_seen or (previous.completed_at if old.open_tcp_ports or old.open_udp_ports else None)
        if old.status in {"OFFLINE", "NOT_OBSERVED", "NOT_SCANNED", "ERROR"} and positive:
            changes.append("Device is responding again")
        if current_tcp - prior_tcp:
            changes.append(f"Newly observed TCP ports: {format_ports(sorted(current_tcp - prior_tcp))}")
        if refused_tcp:
            changes.append(f"TCP ports now explicitly refused (closed): {format_ports(sorted(refused_tcp))}")
        if current_udp - prior_udp:
            changes.append(f"New verified UDP responses: {format_ports(sorted(current_udp - prior_udp), 'udp')}")
        if refused_udp:
            changes.append(f"Previously responding UDP ports now refused: {format_ports(sorted(refused_udp), 'udp')}")
        for protocol, prior, observed, observations in (
            ("TCP", prior_tcp, current_tcp, host.tcp_results),
            ("UDP", prior_udp, current_udp, host.udp_results),
        ):
            missing = prior - observed
            no_response = sorted(port for port in missing if observations.state(port) == "no_response")
            not_checked = sorted(port for port in missing if observations.state(port) in {"not_scanned", "unsupported"})
            errors = sorted(port for port in missing if observations.state(port) == "error")
            unverified = sorted(port for port in missing if observations.state(port) == "unverified_response")
            if no_response:
                changes.append(f"{protocol} no response: {compact_ranges(no_response)}; closure not confirmed, last-known results retained")
            if not_checked:
                changes.append(f"{protocol} not rechecked: {compact_ranges(not_checked)}; last-known results retained")
            if errors:
                changes.append(f"{protocol} recheck errors: {compact_ranges(errors)}; last-known results retained")
            if unverified:
                changes.append(f"{protocol} replies not protocol-verified: {compact_ranges(unverified)}; last-known results retained")
        if host.identification_complete and old.name != host.name and host.name != "(unknown)":
            changes.append(f"Name changed: {old.name} -> {host.name}")
        elif host.name == "(unknown)" or (not host.identification_complete and host.name.startswith("(")):
            host.name = old.name
        if host.mac != old.mac and host.mac != "-" and old.mac != "-":
            changes.append(f"MAC changed: {old.mac} -> {host.mac}")
        if not positive and host.reachability == "unknown":
            host.reachability = "not_scanned"
        host.status = base_host_status(host)
        if positive and host.status == "CURRENT":
            host.status = "CHANGED" if changes else "CURRENT"
        host.changes = changes
        compared[ip] = host

    for ip, old in previous.hosts.items():
        if ip in current.hosts:
            continue
        # Carry identity and historical evidence, not old results masquerading
        # as freshly measured ports or as measurements from this scan's scope.
        host = copy.copy(old)
        host.open_tcp_ports = []
        host.open_udp_ports = []
        host.last_known_tcp_ports = sorted(set(old.open_tcp_ports).union(old.last_known_tcp_ports))
        host.last_known_udp_ports = sorted(set(old.open_udp_ports).union(old.last_known_udp_ports))
        host.tcp_results = PortResults()
        host.udp_results = PortResults()
        host.tcp_complete = host.udp_complete = host.identification_complete = False
        host.discovery_complete = False
        host.review_items = []
        host.banners = {}
        host.mdns_names = []
        host.mdns_services = []
        host.ssdp_locations = []
        host.ssdp_meta = []
        host.last_seen = old.last_seen or (previous.completed_at if old.reachability == "responsive" or old.open_tcp_ports or old.open_udp_ports else None)
        host.scan_completed_at = current.completed_at
        host.scan_cancelled = current.cancelled
        in_scope = ipaddress.ip_address(ip) in network
        outcome = current.discovery_outcomes.get(ip)
        arp_absence = in_scope and current.discovery_complete and current.discovery_method == "ARP"
        host.tcp_requested = len(current.tcp_ports) if in_scope else 0
        host.udp_requested = len(current.udp_ports) if in_scope else 0
        if in_scope and outcome == "error":
            host.status, host.reachability = "ERROR", "error"
            host.changes = ["Discovery encountered an error; previous results retained as last-known only"]
        elif in_scope and (outcome == "no_response" or arp_absence):
            host.status, host.reachability = "NOT_OBSERVED", "no_response"
            host.discovery_complete = True
            host.changes = ["Not observed by this scan's discovery probes; not proof the device is offline"]
        else:
            host.status, host.reachability = "NOT_SCANNED", "not_scanned"
            reason = "outside this scan's scope" if not in_scope else "not conclusively checked in this scan"
            host.changes = [f"Device {reason}; previous results retained as last-known only"]
        host.discovery_method = "No new positive observation"
        compared[ip] = host
    current.hosts = compared
    return current


# ============================================================
# EXPORTS
# ============================================================

def safe_subnet_name(subnet: str) -> str:
    return subnet.replace("/", "-").replace(":", "_")


def export_path(report: ScanReport, options: ScanOptions, extension: str) -> str:
    extension = extension.lstrip(".")
    if options.output:
        path = os.path.expanduser(options.output)
        root, existing_extension = os.path.splitext(path)
        if existing_extension.lower() == f".{extension}":
            return path
        if existing_extension:
            return root + f".{extension}"
        return path + f".{extension}"

    timestamp = datetime.now().strftime("%Y-%m-%d_%H%M%S")
    return f"pynetscan_{safe_subnet_name(report.subnet)}_{timestamp}.{extension}"


def host_to_dict(host: Host) -> Dict[str, object]:
    data = {item.name: getattr(host, item.name) for item in fields(host)}
    data["tcp_results"] = host.tcp_results.to_dict()
    data["udp_results"] = host.udp_results.to_dict()
    return data


def port_state_text(results: PortResults, requested: int) -> str:
    states = [f"{state}: {compact_ranges(results.ports(state))}"
              for state in PROBE_STATES[1:] if results.count(state)]
    remaining = max(0, requested - results.count())
    if remaining:
        states.append(f"not_scanned: {remaining} requested ports")
    return " | ".join(states) or ("not requested" if not requested else "not scanned")


def export_csv(report: ScanReport, options: ScanOptions) -> str:
    path = export_path(report, options, "csv")
    with open(path, "w", newline="", encoding="utf-8") as file_handle:
        writer = csv.writer(file_handle)
        writer.writerow([
            "IP", "Status", "Changes", "Name", "Device Type", "MAC", "Manufacturer",
            "OS Guess", "Discovery", "TCP Ports", "UDP Responded", "Review Items",
            "Banners", "mDNS Names", "mDNS Services", "SSDP Locations", "SSDP Metadata",
            "Reachability", "Last Seen", "Host Scan Completed", "Host Scan Cancelled", "Discovery Complete", "TCP Complete", "UDP Complete",
            "Identification Complete", "TCP Requested", "UDP Requested",
            "TCP Probe States", "UDP Probe States", "Last-known TCP", "Last-known UDP",
            "TCP Probe Details", "UDP Probe Details",
        ])
        for host in sorted(report.hosts.values(), key=lambda item: tuple(map(int, item.ip.split(".")))):
            writer.writerow([
                host.ip,
                host.status,
                " | ".join(host.changes),
                host.name,
                host.device_type,
                host.mac,
                host.manufacturer,
                host.os_guess,
                host.discovery_method,
                ",".join(map(str, host.open_tcp_ports)),
                ",".join(map(str, host.open_udp_ports)),
                " | ".join(host.review_items),
                " | ".join(f"{key}: {value}" for key, value in host.banners.items()),
                " | ".join(host.mdns_names),
                " | ".join(host.mdns_services),
                " | ".join(host.ssdp_locations),
                " | ".join(host.ssdp_meta),
                host.reachability, host.last_seen or "", host.scan_completed_at or "", host.scan_cancelled, host.discovery_complete,
                host.tcp_complete, host.udp_complete, host.identification_complete,
                host.tcp_requested, host.udp_requested,
                port_state_text(host.tcp_results, host.tcp_requested),
                port_state_text(host.udp_results, host.udp_requested),
                compact_ranges(host.last_known_tcp_ports), compact_ranges(host.last_known_udp_ports),
                " | ".join(f"{port}: {text}" for port, text in sorted(host.tcp_results.details.items())),
                " | ".join(f"{port}: {text}" for port, text in sorted(host.udp_results.details.items())),
            ])
    return path


def export_json(report: ScanReport, options: ScanOptions) -> str:
    path = export_path(report, options, "json")
    payload = {
        "application": APP_NAME,
        "version": VERSION,
        "schema_version": 2,
        "scan": {
            "subnet": report.subnet,
            "profile": report.profile,
            "started_at": report.started_at,
            "completed_at": report.completed_at,
            "elapsed_seconds": round(report.elapsed_seconds, 3),
            "cancelled": report.cancelled,
            "discovery_method": report.discovery_method,
            "route": asdict(report.route),
            "tcp_ports": report.tcp_ports,
            "udp_ports": report.udp_ports,
            "warnings": report.warnings,
            "discovery_complete": report.discovery_complete,
            "discovery_outcomes": report.discovery_outcomes,
            "settings": report.settings,
            "probe_state_default": "not_scanned",
            "port_state_encoding": "state_ranges contains comma-separated ports and inclusive ranges; missing ports are not_scanned, not closed; requested scope is tcp_ports/udp_ports",

        },
        "hosts": [
            host_to_dict(host)
            for host in sorted(report.hosts.values(), key=lambda item: tuple(map(int, item.ip.split("."))))
        ],
    }
    with open(path, "w", encoding="utf-8") as file_handle:
        json.dump(payload, file_handle, indent=2)
    return path

# ============================================================
# CURSES HELPERS
# ============================================================

def safe_addstr(window, y: int, x: int, text: str, attribute: int = 0) -> None:
    try:
        height, width = window.getmaxyx()
        if y < 0 or y >= height or x >= width:
            return
        window.addstr(y, x, str(text)[:max(0, width - x - 1)], attribute)
    except curses.error:
        pass


def prompt_text(stdscr, title: str, initial: str = "") -> Optional[str]:
    stdscr.nodelay(False)
    curses.curs_set(1)
    value = list(initial)
    cursor = len(value)

    try:
        while True:
            stdscr.erase()
            height, width = stdscr.getmaxyx()
            safe_addstr(stdscr, 0, 0, title, curses.A_BOLD)
            safe_addstr(stdscr, 2, 0, "Enter confirms | Esc cancels | Ctrl+U clears")
            display_width = max(1, width - 4)
            text = "".join(value)
            start_offset = max(0, cursor - display_width + 1)
            visible = text[start_offset:start_offset + display_width]
            safe_addstr(stdscr, 4, 0, "> " + visible)
            screen_cursor = 2 + cursor - start_offset
            try:
                stdscr.move(4, min(width - 2, max(2, screen_cursor)))
            except curses.error:
                pass
            stdscr.refresh()

            key = stdscr.get_wch()
            if key in ("\n", "\r"):
                return "".join(value).strip()
            if key == "\x1b":
                return None
            if key in (curses.KEY_BACKSPACE, "\b", "\x7f"):
                if cursor > 0:
                    del value[cursor - 1]
                    cursor -= 1
            elif key == curses.KEY_DC:
                if cursor < len(value):
                    del value[cursor]
            elif key == curses.KEY_LEFT:
                cursor = max(0, cursor - 1)
            elif key == curses.KEY_RIGHT:
                cursor = min(len(value), cursor + 1)
            elif key == curses.KEY_HOME:
                cursor = 0
            elif key == curses.KEY_END:
                cursor = len(value)
            elif key == "\x15":  # Ctrl+U
                value.clear()
                cursor = 0
            elif isinstance(key, str) and key.isprintable():
                value.insert(cursor, key)
                cursor += 1
    except (curses.error, KeyboardInterrupt):
        return None
    finally:
        curses.curs_set(0)
        stdscr.timeout(100)


def choose_profile(stdscr) -> Tuple[str, Optional[List[int]]]:
    profiles = ["discover", "quick", "standard", "deep", "full", "custom"]
    index = profiles.index("standard")
    stdscr.timeout(100)

    while True:
        stdscr.erase()
        height, width = stdscr.getmaxyx()
        safe_addstr(stdscr, 0, 0, f"{APP_NAME} {VERSION} — Select a scan profile", curses.A_BOLD)
        safe_addstr(stdscr, 1, 0, "Scan only networks you own or are authorized to administer.")
        for row, profile in enumerate(profiles, start=3):
            marker = "▶" if row - 3 == index else " "
            text = f"{marker} {profile.title():9}  {PROFILE_DESCRIPTIONS[profile]}"
            attribute = curses.A_REVERSE if row - 3 == index else 0
            safe_addstr(stdscr, row, 0, text, attribute)
        safe_addstr(stdscr, min(height - 1, 11), 0, "↑↓ select | Enter start | q quit")
        stdscr.refresh()

        key = stdscr.getch()
        if key in (ord("q"), 27):
            raise SystemExit(0)
        if key == curses.KEY_UP:
            index = (index - 1) % len(profiles)
        elif key == curses.KEY_DOWN:
            index = (index + 1) % len(profiles)
        elif key in (10, 13):
            profile = profiles[index]
            if profile == "custom":
                value = prompt_text(stdscr, "Custom TCP ports", "22,80,443")
                if value is None:
                    continue
                try:
                    return profile, parse_ports_list(value)
                except ValueError as exc:
                    show_message(stdscr, "Invalid ports", str(exc))
                    continue
            return profile, None


def show_message(stdscr, title: str, message: str) -> None:
    stdscr.erase()
    height, width = stdscr.getmaxyx()
    safe_addstr(stdscr, 0, 0, title, curses.A_BOLD)
    y = 2
    for paragraph in str(message).splitlines() or [""]:
        for line in textwrap.wrap(paragraph, max(20, width - 2)) or [""]:
            if y >= height - 2:
                break
            safe_addstr(stdscr, y, 0, line)
            y += 1
    safe_addstr(stdscr, height - 1, 0, "Press any key")
    stdscr.refresh()
    stdscr.nodelay(False)
    stdscr.getch()
    stdscr.timeout(100)


def confirm_large_scan(stdscr, network: ipaddress.IPv4Network, options: ScanOptions) -> bool:
    hosts = usable_host_count(network)
    discovery_attempts = 0 if options.skip_discovery else hosts * len(effective_discovery_ports(options))
    port_attempts = hosts * (len(options.tcp_ports) + len(options.udp_ports))
    attempts = (discovery_attempts + port_attempts) * (options.max_retries + 1)

    if options.force or (hosts <= LARGE_HOST_THRESHOLD and attempts <= LARGE_ATTEMPT_THRESHOLD):
        return True

    stdscr.erase()
    safe_addstr(stdscr, 0, 0, "Large scan confirmation", curses.A_BOLD)
    lines = [
        f"Network: {network}",
        f"Usable addresses: {hosts:,}",
        f"TCP ports per discovered host: {len(options.tcp_ports):,}",
        f"UDP probes per discovered host: {len(options.udp_ports):,}",
        f"Potential TCP/UDP attempts including discovery/retries: {attempts:,}",
        f"Discovery bypass: {'yes; every address will be scanned' if options.skip_discovery else 'no'}",
        "",
        "This scan could take a long time and generate substantial network traffic.",
        "Press y to continue or any other key to cancel.",
    ]
    for row, line in enumerate(lines, start=2):
        safe_addstr(stdscr, row, 0, line)
    stdscr.refresh()
    stdscr.nodelay(False)
    key = stdscr.getch()
    stdscr.timeout(100)
    return key in (ord("y"), ord("Y"))


def draw_progress(stdscr, progress: Dict[str, object], cancel_requested: bool = False) -> None:
    stdscr.erase()
    height, width = stdscr.getmaxyx()
    stage = str(progress.get("stage", "Scanning"))
    done = int(progress.get("done", 0))
    total = max(1, int(progress.get("total", 1)))
    percent = min(1.0, done / total)
    inner_width = max(8, width - 3)
    filled = min(inner_width, int(percent * inner_width))

    safe_addstr(stdscr, 0, 0, f"{APP_NAME} {VERSION} — {stage}", curses.A_BOLD)
    safe_addstr(stdscr, 2, 0, f"Progress: {done:,}/{total:,} ({percent * 100:5.1f}%)")
    safe_addstr(stdscr, 3, 0, "[" + "#" * filled + "-" * (inner_width - filled) + "]")

    attempt_done = int(progress.get("attempt_done", 0))
    attempt_total = int(progress.get("attempt_total", 0))
    if attempt_total:
        started = float(progress.get("rate_started", time.monotonic()))
        elapsed = max(0.001, time.monotonic() - started)
        rate = attempt_done / elapsed
        remaining = max(0, attempt_total - attempt_done)
        eta = remaining / rate if rate > 0 else 0
        safe_addstr(stdscr, 5, 0, f"Ports checked: {attempt_done:,}/{attempt_total:,} | Rate: {rate:,.1f}/sec | ETA: {format_duration(eta)}")
        safe_addstr(stdscr, 6, 0, f"Responsive/open results found: {int(progress.get('open_count', 0)):,}")
    safe_addstr(stdscr, 7, 0, f"TCP/UDP wire attempts: {int(progress.get('wire_attempts', 0)):,} | Retries: {int(progress.get('retry_attempts', 0)):,}")
    if progress.get("scan_started"):
        safe_addstr(stdscr, 9, 0, f"Elapsed: {format_duration(time.monotonic() - float(progress['scan_started']))}")
    if progress.get("hosts_discovered") is not None:
        safe_addstr(stdscr, 8, 0, f"Devices discovered: {int(progress.get('hosts_discovered', 0)):,}")

    warnings = progress.get("warnings", [])
    if isinstance(warnings, list) and warnings:
        safe_addstr(stdscr, max(10, height - 4), 0, f"Notice: {warnings[-1]}")
    footer = "Stopping active work; keeping completed observations…" if cancel_requested else "Press q to cancel and keep partial results"
    safe_addstr(stdscr, height - 1, 0, footer)
    stdscr.refresh()


def format_duration(seconds: float) -> str:
    seconds = max(0, int(seconds))
    hours, remainder = divmod(seconds, 3600)
    minutes, secs = divmod(remainder, 60)
    return f"{hours:02d}:{minutes:02d}:{secs:02d}"


def run_scan_ui(
    stdscr,
    event_loop: asyncio.AbstractEventLoop,
    options: ScanOptions,
) -> ScanReport:
    progress: Dict[str, object] = {"stage": "Starting", "done": 0, "total": 1, "warnings": []}
    cancel_event = asyncio.Event()
    task = event_loop.create_task(scan_subnet(options, progress, cancel_event))
    cancel_requested = False
    stdscr.nodelay(True)

    while not task.done():
        try:
            event_loop.run_until_complete(asyncio.wait_for(asyncio.shield(task), timeout=0.08))
        except asyncio.TimeoutError:
            pass
        key = stdscr.getch()
        if key in (ord("q"), 27) and not cancel_requested:
            cancel_requested = True
            cancel_event.set()
            progress["stage"] = "Cancelling"
        draw_progress(stdscr, progress, cancel_requested)

    report = event_loop.run_until_complete(task)
    stdscr.timeout(100)
    return report

# ============================================================
# TUI LIST / DETAILS
# ============================================================

SORT_MODES = ["ip", "name", "manufacturer", "os", "ports", "status"]
FILTER_MODES = ["all", "open", "review", "changed", "new", "not_observed", "partial", "errors"]


def ip_sort_key(value: str) -> Tuple[int, int, int, int]:
    return tuple(int(part) for part in value.split("."))


def filtered_hosts(
    hosts: Iterable[Host],
    search: str,
    filter_mode: str,
    sort_mode: str,
) -> List[Host]:
    search_lower = search.lower().strip()
    values: List[Host] = []
    for host in hosts:
        searchable = " ".join([
            host.ip,
            host.name,
            host.mac,
            host.manufacturer,
            host.os_guess,
            host.device_type,
            " ".join(map(str, host.open_tcp_ports)),
            " ".join(map(str, host.open_udp_ports)),
        ]).lower()
        if search_lower and search_lower not in searchable:
            continue
        if filter_mode == "open" and not (host.open_tcp_ports or host.open_udp_ports):
            continue
        if filter_mode == "review" and not host.review_items:
            continue
        if filter_mode == "changed" and not host.changes:
            continue
        if filter_mode == "new" and host.status != "NEW":
            continue
        if filter_mode in {"offline", "not_observed"} and host.status not in {"OFFLINE", "NOT_OBSERVED"}:
            continue
        if filter_mode == "partial" and host.status not in {"PARTIAL", "NOT_SCANNED"}:
            continue
        if filter_mode == "errors" and not (host.status == "ERROR" or host.tcp_results.count("error") or host.udp_results.count("error")):
            continue
        values.append(host)

    if sort_mode == "ip":
        values.sort(key=lambda host: ip_sort_key(host.ip))
    elif sort_mode == "name":
        values.sort(key=lambda host: (host.name.lower(), ip_sort_key(host.ip)))
    elif sort_mode == "manufacturer":
        values.sort(key=lambda host: (host.manufacturer.lower(), ip_sort_key(host.ip)))
    elif sort_mode == "os":
        values.sort(key=lambda host: (host.os_guess.lower(), ip_sort_key(host.ip)))
    elif sort_mode == "ports":
        values.sort(key=lambda host: (-(len(host.open_tcp_ports) + len(host.open_udp_ports)), ip_sort_key(host.ip)))
    elif sort_mode == "status":
        order = {"ERROR": 0, "NEW": 1, "CHANGED": 2, "PARTIAL": 3, "NOT_OBSERVED": 4, "NOT_SCANNED": 5, "OFFLINE": 6, "CURRENT": 7}
        values.sort(key=lambda host: (order.get(host.status, 9), ip_sort_key(host.ip)))
    return values


def compact_port_text(host: Host, limit: int = 8) -> str:
    values = [f"{port}/t" for port in host.open_tcp_ports]
    values.extend(f"{port}/u" for port in host.open_udp_ports)
    if len(values) > limit:
        return ",".join(values[:limit]) + ",…"
    if not values and (host.last_known_tcp_ports or host.last_known_udp_ports):
        return "last-known only"
    if not values and (host.tcp_results.count("unverified_response") or host.udp_results.count("unverified_response")):
        return "unverified reply"
    return ",".join(values) or "-"


def draw_list(
    stdscr,
    hosts: Sequence[Host],
    index: int,
    top: int,
    search: str,
    filter_mode: str,
    sort_mode: str,
    message: str,
    report: ScanReport,
) -> None:
    stdscr.erase()
    height, width = stdscr.getmaxyx()
    header = "↑↓ select | Enter details | / search | f filter | o sort | s rescan | a alias | e CSV | j JSON | ? help | q quit"
    safe_addstr(stdscr, 0, 0, header, curses.A_BOLD)
    context = f"Network {report.subnet} | Profile {report.profile} | Sort {sort_mode} | Filter {filter_mode}"
    if search:
        context += f" | Search '{search}'"
    safe_addstr(stdscr, 1, 0, context)

    if width >= 150:
        column_header = f"{'S':1} {'IP':15} {'Name':22} {'Type':17} {'MAC':17} {'Manufacturer':22} {'OS':12} {'Ports'}"
    elif width >= 105:
        column_header = f"{'S':1} {'IP':15} {'Name':22} {'Type':17} {'Manufacturer':20} {'Ports'}"
    else:
        column_header = f"{'S':1} {'IP':15} {'Name':22} {'Ports'}"
    safe_addstr(stdscr, 3, 0, column_header, curses.A_UNDERLINE)

    start_y = 4
    visible = max(0, height - start_y - 2)
    for row in range(visible):
        item_index = top + row
        if item_index >= len(hosts):
            break
        host = hosts[item_index]
        status_marker = {"NEW": "+", "CHANGED": "*", "OFFLINE": "-", "NOT_OBSERVED": "-",
                         "PARTIAL": "?", "NOT_SCANNED": "?", "ERROR": "E", "CURRENT": " "}.get(host.status, " ")
        if host.review_items and host.status not in {"PARTIAL", "NOT_SCANNED", "NOT_OBSERVED", "ERROR"}:
            status_marker = "!"
        ports = compact_port_text(host)
        if width >= 150:
            line = (
                f"{status_marker:1} {host.ip:15} {host.name:22.22} {host.device_type:17.17} "
                f"{host.mac:17} {host.manufacturer:22.22} {host.os_guess:12.12} {ports}"
            )
        elif width >= 105:
            line = (
                f"{status_marker:1} {host.ip:15} {host.name:22.22} {host.device_type:17.17} "
                f"{host.manufacturer:20.20} {ports}"
            )
        else:
            line = f"{status_marker:1} {host.ip:15} {host.name:22.22} {ports}"
        attribute = curses.A_REVERSE if item_index == index else 0
        safe_addstr(stdscr, start_y + row, 0, line, attribute)

    if not hosts:
        safe_addstr(stdscr, 6, 0, "No devices match the current search/filter.")

    footer = f"{index + 1 if hosts else 0}/{len(hosts)} | Total known: {len(report.hosts)}"
    if message:
        safe_addstr(stdscr, height - 2, 0, message)
    safe_addstr(stdscr, height - 1, max(0, width - len(footer) - 1), footer)
    stdscr.refresh()


def host_detail_lines(host: Host, width: int) -> List[str]:
    raw_lines = [
        f"IP:             {host.ip}",
        f"Status:         {host.status}",
        f"Reachability:   {host.reachability}",
        f"Last seen:      {host.last_seen or 'no positive observation recorded'}",
        f"Last scan ended: {host.scan_completed_at or 'not recorded'}; cancelled={host.scan_cancelled}",
        f"Name:           {host.name}",
        f"Device Type:    {host.device_type}",
        f"MAC:            {host.mac}",
        f"Manufacturer:   {host.manufacturer}",
        f"OS Guess:       {host.os_guess}",
        f"Discovered By:  {host.discovery_method}",
        f"TCP open now:   {format_ports(host.open_tcp_ports)}",
        f"UDP verified:   {format_ports(host.open_udp_ports, 'udp')}",
        f"Stages complete: discovery={host.discovery_complete}, TCP={host.tcp_complete}, UDP={host.udp_complete}, identification={host.identification_complete}",
        "Stage completion does not imply every probe succeeded; see individual states below.",
        f"TCP checked: {host.tcp_results.count()}/{host.tcp_requested}; not scanned: {max(0, host.tcp_requested - host.tcp_results.count())}",
        f"UDP recorded: {host.udp_results.count()}/{host.udp_requested}; not scanned: {max(0, host.udp_requested - host.udp_results.count())}",
        f"TCP states: {port_state_text(host.tcp_results, host.tcp_requested)}",
        f"UDP states: {port_state_text(host.udp_results, host.udp_requested)}",
        f"Last-known TCP (not current): {format_ports(host.last_known_tcp_ports)}",
        f"Last-known UDP (not current): {format_ports(host.last_known_udp_ports, 'udp')}",
    ]
    for protocol, observations in (("TCP", host.tcp_results), ("UDP", host.udp_results)):
        if observations.details:
            raw_lines.extend(["", f"{protocol} probe details (up to 256 ports):"])
            raw_lines.extend(f"  {port}: {text}" for port, text in sorted(observations.details.items()))
    if host.changes:
        raw_lines.extend(["", "Changes:"] + [f"  {value}" for value in host.changes])
    if host.review_items:
        raw_lines.extend(["", "Review:"] + [f"  ! {value}" for value in host.review_items])
    if host.banners:
        raw_lines.extend(["", "Service Information:"])
        raw_lines.extend(f"  {key}: {value}" for key, value in host.banners.items())
    if host.mdns_names or host.mdns_services:
        raw_lines.extend(["", "mDNS:"])
        raw_lines.extend(f"  Name: {value}" for value in host.mdns_names)
        raw_lines.extend(f"  Service: {value}" for value in host.mdns_services)
    if host.ssdp_locations or host.ssdp_meta:
        raw_lines.extend(["", "SSDP:"])
        raw_lines.extend(f"  Location: {value}" for value in host.ssdp_locations)
        raw_lines.extend(f"  {value}" for value in host.ssdp_meta)

    wrapped: List[str] = []
    wrap_width = max(20, width - 2)
    for line in raw_lines:
        if not line:
            wrapped.append("")
        else:
            wrapped.extend(textwrap.wrap(line, wrap_width, subsequent_indent="    ") or [""])
    return wrapped


def draw_details(stdscr, host: Host, offset: int) -> int:
    stdscr.erase()
    height, width = stdscr.getmaxyx()
    safe_addstr(stdscr, 0, 0, "Details — ↑↓/PgUp/PgDn scroll | b back | p ping | s rescan | a alias | q quit", curses.A_BOLD)
    lines = host_detail_lines(host, width)
    visible = max(1, height - 3)
    max_offset = max(0, len(lines) - visible)
    offset = max(0, min(offset, max_offset))
    for row, line in enumerate(lines[offset:offset + visible], start=2):
        safe_addstr(stdscr, row, 0, line)
    footer = f"Lines {offset + 1}-{min(len(lines), offset + visible)} of {len(lines)}"
    safe_addstr(stdscr, height - 1, max(0, width - len(footer) - 1), footer)
    stdscr.refresh()
    return max_offset


def show_help(stdscr, report: ScanReport) -> None:
    help_lines = [
        f"{APP_NAME} {VERSION}",
        "",
        "Keyboard shortcuts",
        "  ↑/↓, PgUp/PgDn   Move through devices or detail text",
        "  Enter             Open device details",
        "  /                 Search IP, name, MAC, manufacturer, OS, type, or port",
        "  x                 Clear the current search",
        "  f                 Cycle filters: all/open/review/changed/new/not_observed/partial/errors",
        "  o                 Cycle sort modes",
        "  r                 Refresh the entire subnet and compare changes",
        "  s                 Rescan only the selected device",
        "  a                 Add, change, or remove a device alias",
        "  e / j             Export CSV / JSON",
        "  p                 Ping the selected device from Details",
        "  ?                 Show this help",
        "  q                 Quit; during a scan, cancel and keep partial results",
        "",
        "Discovery behavior",
        "  Directly connected networks use ARP when raw socket permission is available.",
        "  Without raw permission, or on routed networks, every target is probed with",
        "  ICMP and selected TCP discovery ports. Accepted and explicitly refused TCP",
        "  connections are responsiveness evidence (a firewall may generate refusals).",
        "  --discovery-ports chooses discovery ports; --skip-discovery scans every target.",
        "  TCP-only discovery does not invent a TTL,",
        "  so its OS result remains Unknown unless a real ICMP TTL was received.",
        "",
        "UDP behavior",
        "  DNS, NTP, NetBIOS and SSDP replies are checked against their expected protocol.",
        "  SNMPv2c sysDescr is read only with an explicitly supplied community via",
        "  --snmp-community-env. Missing credentials skip the probe; nothing is guessed.",
        "  Generic/malformed replies are unverified_response, not a verified service.",
        "  No UDP response is not proof of closure. UDP refused may be an ICMP intermediary.",
        "",
        "Probe states and comparison",
        "  open / refused / no_response / error / not_scanned are distinct TCP states.",
        "  Only an explicit refusal confirms a closed/refused connection, never a timeout.",
        "  Interrupted, unselected or failed checks keep previous results as last-known",
        "  rather than presenting them as fresh open ports or declaring them closed.",
        "  NOT_OBSERVED means no discovery response, not proof that a device is offline.",
        "",
        "Performance controls",
        "  A fair worker pool shares the global connection budget across active hosts.",
        "  --max-rate limits TCP/UDP probe starts, including discovery and retries.",
        "  ARP, ICMP, multicast and enrichment are not included in that rate ceiling.",
        "  --max-retries sets no-response retries (default 1); errors/refusals are not retried.",
        "  Timing adapts to measured responses unless --timeout or --no-adaptive-timeout is set.",
        "",
        "Result symbols",
        "  + new   * changed   - not observed   ? incomplete/unscanned   E error",
        "  ! service needs review (not proof of a vulnerability)",
        "",
        "Warnings from the latest scan:",
    ]
    help_lines.extend(f"  - {warning}" for warning in report.warnings)
    if not report.warnings:
        help_lines.append("  none")

    offset = 0
    stdscr.timeout(100)
    while True:
        stdscr.erase()
        height, width = stdscr.getmaxyx()
        visible = max(1, height - 2)
        wrapped: List[str] = []
        for line in help_lines:
            wrapped.extend(textwrap.wrap(line, max(20, width - 2), subsequent_indent="    ") or [""])
        max_offset = max(0, len(wrapped) - visible)
        offset = max(0, min(offset, max_offset))
        for row, line in enumerate(wrapped[offset:offset + visible]):
            safe_addstr(stdscr, row, 0, line)
        safe_addstr(stdscr, height - 1, 0, "↑↓/PgUp/PgDn scroll | b or ? back")
        stdscr.refresh()
        key = stdscr.getch()
        if key in (ord("b"), ord("?"), ord("q"), 27):
            return
        if key == curses.KEY_UP:
            offset -= 1
        elif key == curses.KEY_DOWN:
            offset += 1
        elif key == curses.KEY_PPAGE:
            offset -= visible
        elif key == curses.KEY_NPAGE:
            offset += visible


def show_ping(stdscr, ip: str) -> None:
    if not shutil.which("ping"):
        show_message(stdscr, "Ping", "The ping command is not installed.")
        return
    try:
        result = run_command(["ping", "-n", "-c", "4", ip], timeout=8)
        output = (result.stdout + result.stderr).strip() or "No output"
    except (OSError, subprocess.SubprocessError) as exc:
        output = f"Ping failed: {exc}"
    show_message(stdscr, f"Ping {ip}", output)


def fallback_host_name(host: Host) -> str:
    if host.mdns_names:
        return host.mdns_names[0]
    ssdp_name = ssdp_friendly_name(host.ssdp_meta)
    if ssdp_name:
        return ssdp_name
    if host.manufacturer != "-":
        return f"({host.manufacturer})"
    return "(unknown)"


def edit_alias(stdscr, host: Host) -> str:
    aliases = load_aliases()
    current = aliases.get(host.ip, "")
    value = prompt_text(stdscr, f"Alias for {host.ip} (blank removes it)", current)
    if value is None:
        return "Alias edit cancelled"
    if value:
        aliases[host.ip] = value
        host.name = value
        message = f"Alias saved for {host.ip}"
    else:
        aliases.pop(host.ip, None)
        host.name = fallback_host_name(host)
        message = f"Alias removed for {host.ip}"
    try:
        save_aliases(aliases)
    except OSError as exc:
        return f"Alias could not be saved: {exc}"
    return message

# ============================================================
# MAIN TUI
# ============================================================

def build_scan_options(args, stdscr) -> ScanOptions:
    if args.all_ports:
        profile = "full"
        tcp_ports = list(range(1, 65536))
    elif args.ports:
        profile = args.profile or "custom"
        tcp_ports = parse_ports_list(args.ports)
    elif args.profile:
        profile = args.profile
        tcp_ports = ports_for_profile(profile)
    elif args.no_menu:
        profile = "standard"
        tcp_ports = list(STANDARD_TCP_PORTS)
    else:
        profile, custom_ports = choose_profile(stdscr)
        tcp_ports = custom_ports if custom_ports is not None else ports_for_profile(profile)

    udp_ports = parse_ports_list(args.udp_ports) if args.udp_ports else []

    if args.network:
        subnet = str(ipaddress.ip_network(args.network, strict=False))
    elif AUTO_DETECT_SUBNET:
        subnet = detect_local_subnet(args.interface) or CUSTOM_SUBNETS[0]
    else:
        subnet = CUSTOM_SUBNETS[0]

    if ipaddress.ip_network(subnet, strict=False).version != 4:
        raise ValueError("This release supports IPv4 targets only")
    if args.skip_discovery and not (tcp_ports or udp_ports):
        raise ValueError("--skip-discovery requires TCP or UDP ports to check")
    return ScanOptions(
        subnet=subnet,
        profile=profile,
        tcp_ports=tcp_ports,
        udp_ports=udp_ports,
        interface=args.interface,
        tcp_timeout=args.timeout if args.timeout is not None else DEFAULT_TCP_TIMEOUT,
        host_concurrency=args.concurrency,
        port_concurrency=args.port_concurrency,
        enable_dns=not args.no_dns,
        enable_mdns=not args.no_mdns,
        enable_ssdp=not args.no_ssdp,
        enable_banners=args.banners or profile == "deep",
        force=args.force,
        update_oui=args.update_oui,
        enable_oui=not args.no_oui,
        output=args.output,
        auto_json=args.json,
        discovery_ports=parse_ports_list(args.discovery_ports) if args.discovery_ports is not None else None,
        skip_discovery=args.skip_discovery,
        max_rate=args.max_rate,
        max_retries=args.max_retries,
        adaptive_timeout=not args.no_adaptive_timeout and args.timeout is None,
        snmp_community=os.environ.get(args.snmp_community_env) if args.snmp_community_env else None,
    )


def run_full_scan(
    stdscr,
    event_loop: asyncio.AbstractEventLoop,
    options: ScanOptions,
    previous: Optional[ScanReport],
) -> Optional[ScanReport]:
    network = ipaddress.ip_network(options.subnet, strict=False)
    if not confirm_large_scan(stdscr, network, options):
        return None
    report = run_scan_ui(stdscr, event_loop, options)
    return compare_reports(previous, report)


def main(stdscr, args) -> None:
    curses.curs_set(0)
    stdscr.keypad(True)
    stdscr.timeout(100)

    try:
        options = build_scan_options(args, stdscr)
    except ValueError as exc:
        show_message(stdscr, "Invalid option", str(exc))
        return

    event_loop = asyncio.new_event_loop()
    asyncio.set_event_loop(event_loop)
    try:
        report = run_full_scan(stdscr, event_loop, options, None)
        if report is None:
            return

        message = ""
        if report.cancelled:
            message = "Scan cancelled; displaying partial results"
        if options.auto_json:
            try:
                path = export_json(report, options)
                message = f"JSON exported to {path}"
            except OSError as exc:
                message = f"JSON export failed: {exc}"

        index = 0
        top = 0
        details = False
        details_offset = 0
        search = ""
        filter_mode = "all"
        sort_mode = "ip"

        while True:
            height, _ = stdscr.getmaxyx()
            visible_rows = max(1, height - 6)
            visible_hosts = filtered_hosts(report.hosts.values(), search, filter_mode, sort_mode)

            if visible_hosts:
                index = max(0, min(index, len(visible_hosts) - 1))
                if index < top:
                    top = index
                elif index >= top + visible_rows:
                    top = max(0, index - visible_rows + 1)
                top = max(0, min(top, max(0, len(visible_hosts) - visible_rows)))
            else:
                index = 0
                top = 0
                details = False

            if details and visible_hosts:
                max_offset = draw_details(stdscr, visible_hosts[index], details_offset)
                details_offset = max(0, min(details_offset, max_offset))
            else:
                draw_list(
                    stdscr,
                    visible_hosts,
                    index,
                    top,
                    search,
                    filter_mode,
                    sort_mode,
                    message,
                    report,
                )

            key = stdscr.getch()
            if key == -1:
                continue
            if key == ord("q"):
                break

            selected = visible_hosts[index] if visible_hosts else None

            if details:
                if key in (ord("b"), 27):
                    details = False
                    details_offset = 0
                elif key == curses.KEY_UP:
                    details_offset -= 1
                elif key == curses.KEY_DOWN:
                    details_offset += 1
                elif key == curses.KEY_PPAGE:
                    details_offset -= max(1, height - 4)
                elif key == curses.KEY_NPAGE:
                    details_offset += max(1, height - 4)
                elif key == curses.KEY_HOME:
                    details_offset = 0
                elif key == curses.KEY_END:
                    details_offset = 10 ** 9
                elif key == ord("p") and selected:
                    show_ping(stdscr, selected.ip)
                elif key == ord("a") and selected:
                    message = edit_alias(stdscr, selected)
                elif key == ord("s") and selected:
                    single_options = replace(options, subnet=f"{selected.ip}/32", force=True)
                    single_report = run_scan_ui(stdscr, event_loop, single_options)
                    previous_single = ScanReport(
                        subnet=single_options.subnet,
                        profile=options.profile,
                        started_at=report.started_at,
                        completed_at=report.completed_at,
                        elapsed_seconds=report.elapsed_seconds,
                        hosts={selected.ip: copy.deepcopy(selected)},
                        warnings=[],
                        cancelled=False,
                        discovery_method=report.discovery_method,
                        route=report.route,
                        tcp_ports=report.tcp_ports,
                        udp_ports=report.udp_ports,
                    )
                    single_report = compare_reports(previous_single, single_report)
                    report.hosts[selected.ip] = single_report.hosts.get(selected.ip, previous_single.hosts[selected.ip])
                    message = f"Rescan cancelled for {selected.ip}; partial observations retained" if single_report.cancelled else f"Rescanned {selected.ip}"
                    details_offset = 0
                continue

            if key == curses.KEY_UP:
                index -= 1
            elif key == curses.KEY_DOWN:
                index += 1
            elif key == curses.KEY_PPAGE:
                index -= visible_rows
            elif key == curses.KEY_NPAGE:
                index += visible_rows
            elif key in (10, 13) and selected:
                details = True
                details_offset = 0
            elif key == ord("/"):
                value = prompt_text(stdscr, "Search devices", search)
                if value is not None:
                    search = value
                    index = top = 0
            elif key == ord("x"):
                search = ""
                index = top = 0
                message = "Search cleared"
            elif key == ord("f"):
                filter_mode = FILTER_MODES[(FILTER_MODES.index(filter_mode) + 1) % len(FILTER_MODES)]
                index = top = 0
                message = f"Filter: {filter_mode}"
            elif key == ord("o"):
                sort_mode = SORT_MODES[(SORT_MODES.index(sort_mode) + 1) % len(SORT_MODES)]
                index = top = 0
                message = f"Sort: {sort_mode}"
            elif key == ord("?"):
                show_help(stdscr, report)
            elif key == ord("a") and selected:
                message = edit_alias(stdscr, selected)
            elif key == ord("e"):
                try:
                    path = export_csv(report, options)
                    message = f"CSV exported to {path}"
                except OSError as exc:
                    message = f"CSV export failed: {exc}"
            elif key == ord("j"):
                try:
                    path = export_json(report, options)
                    message = f"JSON exported to {path}"
                except OSError as exc:
                    message = f"JSON export failed: {exc}"
            elif key == ord("r"):
                refreshed = run_full_scan(stdscr, event_loop, options, report)
                if refreshed is not None:
                    report = refreshed
                    index = top = 0
                    message = "Subnet refreshed; changes are marked"
            elif key == ord("s") and selected:
                single_options = replace(options, subnet=f"{selected.ip}/32", force=True)
                single_report = run_scan_ui(stdscr, event_loop, single_options)
                previous_single = ScanReport(
                    subnet=single_options.subnet,
                    profile=options.profile,
                    started_at=report.started_at,
                    completed_at=report.completed_at,
                    elapsed_seconds=report.elapsed_seconds,
                    hosts={selected.ip: copy.deepcopy(selected)},
                    warnings=[],
                    cancelled=False,
                    discovery_method=report.discovery_method,
                    route=report.route,
                    tcp_ports=report.tcp_ports,
                    udp_ports=report.udp_ports,
                    discovery_complete=report.discovery_complete,
                    discovery_outcomes={selected.ip: report.discovery_outcomes.get(selected.ip, "not_scanned")},
                    settings=report.settings,
                )
                single_report = compare_reports(previous_single, single_report)
                report.hosts[selected.ip] = single_report.hosts.get(selected.ip, previous_single.hosts[selected.ip])
                message = f"Rescan cancelled for {selected.ip}; partial observations retained" if single_report.cancelled else f"Rescanned {selected.ip}"
    finally:
        pending = asyncio.all_tasks(event_loop)
        for task in pending:
            task.cancel()
        if pending:
            event_loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
        event_loop.close()


if __name__ == "__main__":
    cli_args = parse_args()
    try:
        curses.wrapper(main, cli_args)
    except KeyboardInterrupt:
        pass
