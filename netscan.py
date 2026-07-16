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
from dataclasses import asdict, dataclass, field, replace
from datetime import datetime
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple

# ============================================================
# VERSION / CONFIG
# ============================================================

VERSION = "2.0.0"
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
PER_HOST_TCP_WORKERS = 32
PER_HOST_UDP_WORKERS = 8

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
        "--timeout", type=float, default=DEFAULT_TCP_TIMEOUT,
        help=f"TCP/UDP timeout in seconds (default: {DEFAULT_TCP_TIMEOUT})",
    )
    parser.add_argument(
        "--concurrency", type=int, default=DEFAULT_HOST_CONCURRENCY,
        help=f"Concurrent hosts (default: {DEFAULT_HOST_CONCURRENCY})",
    )
    parser.add_argument(
        "--port-concurrency", type=int, default=DEFAULT_PORT_CONCURRENCY,
        help=f"Total concurrent TCP attempts (default: {DEFAULT_PORT_CONCURRENCY})",
    )
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

    if args.timeout <= 0:
        parser.error("--timeout must be greater than zero")
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


def update_oui_database() -> Tuple[Dict[str, str], Optional[str]]:
    try:
        response = urllib.request.urlopen(OUI_URL, timeout=20)
        text = response.read().decode("utf-8", "replace")
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
        save_oui(mappings)
    except OSError as exc:
        return mappings, f"OUI cache could not be saved: {exc}"
    return mappings, None


def get_oui_database(force_update: bool = False) -> Tuple[Dict[str, str], Optional[str]]:
    cached, fresh = load_oui_cache()
    if cached and fresh and not force_update:
        return cached, None

    updated, warning = update_oui_database()
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

    def receive_until(deadline: float) -> None:
        while time.monotonic() < deadline and not cancel_event.is_set():
            try:
                frame = arp_socket.recv(2048)
            except socket.timeout:
                continue
            except OSError:
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
                except OSError:
                    pass
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

    return results, None

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
                    loop.sock_recvfrom(icmp_socket, 2048), timeout=remaining
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
    try:
        process = await asyncio.create_subprocess_exec(
            "ping", "-n", "-c", "1", "-W", "1", ip,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        stdout, _ = await asyncio.wait_for(process.communicate(), timeout=timeout)
    except (OSError, asyncio.TimeoutError):
        return False, None
    text = stdout.decode("utf-8", "ignore")
    ttl_match = re.search(r"\bttl[= ](\d+)", text, re.IGNORECASE)
    ttl = int(ttl_match.group(1)) if ttl_match else None
    return process.returncode == 0, ttl


async def tcp_connect(
    ip: str,
    port: int,
    semaphore: asyncio.Semaphore,
    timeout: float,
) -> bool:
    async with semaphore:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port), timeout=timeout
            )
            del reader
            writer.close()
            try:
                await writer.wait_closed()
            except (OSError, AttributeError):
                pass
            return True
        except (OSError, asyncio.TimeoutError):
            return False


def udp_probe_payload(port: int) -> bytes:
    if port == 53:
        # Standard recursive DNS query for example.com A.
        return bytes.fromhex(
            "123401000001000000000000"
            "076578616d706c6503636f6d00"
            "00010001"
        )
    if port == 123:
        return b"\x1b" + b"\x00" * 47
    if port == 137:
        return bytes.fromhex("13370000000100000000000020" + "43" * 32 + "0000210001")
    if port == 1900:
        return (
            "M-SEARCH * HTTP/1.1\r\n"
            "HOST: 239.255.255.250:1900\r\n"
            'MAN: "ssdp:discover"\r\n'
            "MX: 1\r\n"
            "ST: ssdp:all\r\n\r\n"
        ).encode()
    return b"\x00"


async def udp_probe(
    ip: str,
    port: int,
    semaphore: asyncio.Semaphore,
    timeout: float,
) -> bool:
    """Return True only when a UDP service sends a response.

    Silence is intentionally not called open because UDP scanning cannot
    reliably distinguish an open service from packet filtering without raw
    ICMP error processing.
    """
    async with semaphore:
        udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp_socket.setblocking(False)
        loop = asyncio.get_running_loop()
        try:
            udp_socket.connect((ip, port))
            await loop.sock_sendall(udp_socket, udp_probe_payload(port))
            data = await asyncio.wait_for(loop.sock_recv(udp_socket, 4096), timeout=timeout)
            return bool(data)
        except (OSError, asyncio.TimeoutError):
            return False
        finally:
            udp_socket.close()


async def icmp_ping(ip: str, use_raw_icmp: bool, timeout: float) -> Tuple[bool, Optional[int], str]:
    if use_raw_icmp:
        alive, ttl = await raw_icmp_ping(ip, max(0.4, min(timeout * 2, 1.5)))
        if alive:
            return True, ttl, "ICMP"
    alive, ttl = await system_ping(ip)
    if alive:
        return True, ttl, "ICMP"
    return False, None, ""


async def hybrid_ping(
    ip: str,
    port_semaphore: asyncio.Semaphore,
    options: ScanOptions,
    use_raw_icmp: bool,
) -> Tuple[bool, Optional[int], str]:
    alive, ttl, method = await icmp_ping(ip, use_raw_icmp, options.tcp_timeout)
    if alive:
        return alive, ttl, method

    discovery_ports = []
    for port in DISCOVERY_TCP_PORTS + options.tcp_ports[:8]:
        if port not in discovery_ports:
            discovery_ports.append(port)
    for port in discovery_ports:
        if await tcp_connect(ip, port, port_semaphore, options.tcp_timeout):
            # A TCP response proves the device is reachable but provides no TTL.
            return True, None, f"TCP/{port}"
    return False, None, ""

# ============================================================
# NAME / MULTICAST DISCOVERY
# ============================================================

async def reverse_dns(ip: str, timeout: float = 0.8) -> str:
    loop = asyncio.get_running_loop()

    def lookup() -> str:
        try:
            name, _, _ = socket.gethostbyaddr(ip)
            return name
        except (OSError, socket.herror):
            return "-"

    try:
        return await asyncio.wait_for(loop.run_in_executor(None, lookup), timeout=timeout)
    except asyncio.TimeoutError:
        return "-"


async def netbios_name(ip: str) -> str:
    def lookup() -> str:
        netbios_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        netbios_socket.settimeout(0.4)
        try:
            packet = bytes.fromhex("13370000000100000000000020" + "43" * 32 + "0000210001")
            netbios_socket.sendto(packet, (ip, 137))
            data, _ = netbios_socket.recvfrom(1024)
            text = data.decode("latin-1", "ignore")
            matches = re.findall(r"[A-Z0-9_-]{1,15}\s+", text)
            return matches[0].strip() if matches else "-"
        except OSError:
            return "-"
        finally:
            netbios_socket.close()

    return await asyncio.get_running_loop().run_in_executor(None, lookup)


def ssdp_friendly_name(meta_lines: Sequence[str]) -> Optional[str]:
    for line in meta_lines:
        match = re.match(r"(?i)^USN:\s*(.+)$", line.strip())
        if not match:
            continue
        usn = match.group(1).strip()
        parts = usn.split(":")
        if len(parts) >= 3:
            candidate = parts[-1].strip()
            bad = {"upnp", "rootdevice", "device", "service"}
            if candidate and candidate.lower() not in bad and "uuid" not in candidate.lower():
                return candidate
    return None


def pick_pretty_name(
    ip: str,
    aliases: Dict[str, str],
    mdns_hostnames: Dict[str, Set[str]],
    ssdp_name: Optional[str],
    netbios: str,
    rdns: str,
    manufacturer: str,
) -> str:
    if aliases.get(ip):
        return aliases[ip]
    if ssdp_name:
        return ssdp_name
    if mdns_hostnames.get(ip):
        return sorted(mdns_hostnames[ip])[0]
    if netbios != "-":
        return netbios
    if rdns != "-":
        return rdns
    if manufacturer != "-":
        return f"({manufacturer})"
    return "(unknown)"


async def resolve_name(
    ip: str,
    mdns_hostnames: Dict[str, Set[str]],
    aliases: Dict[str, str],
    manufacturer: str,
    ssdp_meta_lines: Sequence[str],
    enable_dns: bool,
) -> str:
    nb_task = asyncio.create_task(netbios_name(ip))
    rdns_task = asyncio.create_task(reverse_dns(ip)) if enable_dns else None
    netbios = await nb_task
    rdns = await rdns_task if rdns_task else "-"
    return pick_pretty_name(
        ip,
        aliases,
        mdns_hostnames,
        ssdp_friendly_name(ssdp_meta_lines),
        netbios,
        rdns,
        manufacturer,
    )


async def mdns_discovery() -> Tuple[Dict[str, Set[str]], Dict[str, Set[str]], Optional[str]]:
    try:
        from zeroconf.asyncio import AsyncServiceBrowser, AsyncZeroconf
    except ImportError:
        return {}, {}, "mDNS disabled because the optional 'zeroconf' module is not installed"

    hostnames: Dict[str, Set[str]] = {}
    services: Dict[str, Set[str]] = {}
    processing_tasks: Set[asyncio.Task] = set()
    async_zeroconf = AsyncZeroconf()

    async def process_service(service_type: str, name: str) -> None:
        try:
            info = await async_zeroconf.async_get_service_info(service_type, name, timeout=1000)
            if not info:
                return
            for address in info.addresses:
                if len(address) == 4:
                    ip = socket.inet_ntoa(address)
                    if info.server:
                        hostnames.setdefault(ip, set()).add(info.server.rstrip("."))
                    services.setdefault(ip, set()).add(service_type.rstrip("."))
        except Exception:
            return

    def handler(_zeroconf, service_type, name, _state_change) -> None:
        task = asyncio.create_task(process_service(service_type, name))
        processing_tasks.add(task)
        task.add_done_callback(processing_tasks.discard)

    service_types = [
        "_workstation._tcp.local.",
        "_http._tcp.local.",
        "_https._tcp.local.",
        "_ssh._tcp.local.",
        "_printer._tcp.local.",
        "_ipp._tcp.local.",
        "_smb._tcp.local.",
    ]
    browsers = [AsyncServiceBrowser(async_zeroconf.zeroconf, value, handlers=[handler]) for value in service_types]
    await asyncio.sleep(MDNS_TIMEOUT)
    if processing_tasks:
        await asyncio.gather(*list(processing_tasks), return_exceptions=True)
    await async_zeroconf.async_close()
    return hostnames, services, None


async def ssdp_discovery() -> Tuple[Dict[str, List[str]], Dict[str, List[str]], Optional[str]]:
    group = ("239.255.255.250", 1900)
    message = (
        "M-SEARCH * HTTP/1.1\r\n"
        "HOST: 239.255.255.250:1900\r\n"
        'MAN: "ssdp:discover"\r\n'
        "MX: 1\r\n"
        "ST: ssdp:all\r\n\r\n"
    ).encode()

    def discover() -> Tuple[Dict[str, List[str]], Dict[str, List[str]], Optional[str]]:
        locations: Dict[str, List[str]] = {}
        metadata: Dict[str, List[str]] = {}
        ssdp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        ssdp_socket.settimeout(0.25)
        try:
            ssdp_socket.sendto(message, group)
            deadline = time.monotonic() + SSDP_TIMEOUT
            while time.monotonic() < deadline:
                try:
                    data, (ip, _) = ssdp_socket.recvfrom(65535)
                except socket.timeout:
                    continue
                text = data.decode("utf-8", "ignore")

                def field_value(key: str) -> Optional[str]:
                    match = re.search(rf"(?im)^{key}:\s*(.+)$", text)
                    return match.group(1).strip() if match else None

                location = field_value("location")
                if location:
                    locations.setdefault(ip, [])
                    if location not in locations[ip]:
                        locations[ip].append(location)
                metadata.setdefault(ip, [])
                for key in ("st", "usn", "server"):
                    value = field_value(key)
                    line = f"{key.upper()}: {value}" if value else None
                    if line and line not in metadata[ip]:
                        metadata[ip].append(line)
            return locations, metadata, None
        except OSError as exc:
            return {}, {}, f"SSDP discovery failed: {exc}"
        finally:
            ssdp_socket.close()

    return await asyncio.get_running_loop().run_in_executor(None, discover)

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
                    "User-Agent: PyNetScan/2.0\r\nConnection: close\r\n\r\n"
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
                    await writer.wait_closed()
                except (OSError, AttributeError):
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

async def discover_hosts(
    network: ipaddress.IPv4Network,
    route: RouteInfo,
    options: ScanOptions,
    progress: Dict[str, object],
    cancel_event: asyncio.Event,
    warnings: List[str],
    port_semaphore: asyncio.Semaphore,
) -> Tuple[Dict[str, Dict[str, object]], Dict[str, str], str]:
    total_hosts = usable_host_count(network)
    arp_results: Dict[str, str] = {}
    discovery: Dict[str, Dict[str, object]] = {}
    method = "ICMP/TCP"

    if route.direct and route.interface and route.source_ip:
        progress.update(stage="ARP discovery", done=0, total=max(1, total_hosts * 2))
        loop = asyncio.get_running_loop()
        arp_results, arp_warning = await loop.run_in_executor(
            None,
            arp_sweep,
            str(network),
            route.interface,
            route.source_ip,
            progress,
            cancel_event,
        )
        if arp_warning:
            warnings.append(arp_warning)
        if arp_results:
            method = "ARP"
            for ip, mac in arp_results.items():
                discovery[ip] = {"mac": mac, "ttl": None, "method": "ARP"}
            return discovery, arp_results, method
        if not cancel_event.is_set():
            warnings.append("ARP found no devices; probing each address with ICMP/TCP")
    else:
        if route.gateway:
            warnings.append(f"Target is routed through {route.gateway}; ARP cannot discover remote devices")
        else:
            warnings.append("No directly connected route was found; using ICMP/TCP discovery")

    progress.update(stage="ICMP/TCP discovery", done=0, total=max(1, total_hosts))
    use_raw_icmp = raw_icmp_supported()
    if not use_raw_icmp and not shutil.which("ping"):
        warnings.append("Raw ICMP and the ping command are unavailable; discovery is TCP-only")
    elif not use_raw_icmp:
        warnings.append("Raw ICMP is unavailable; using the system ping command and TCP fallback")

    address_iterator = iter(network.hosts())
    iterator_lock = asyncio.Lock()

    async def next_address() -> Optional[str]:
        async with iterator_lock:
            try:
                return str(next(address_iterator))
            except StopIteration:
                return None

    async def worker() -> None:
        while not cancel_event.is_set():
            ip = await next_address()
            if ip is None:
                return
            alive, ttl, found_by = await hybrid_ping(ip, port_semaphore, options, use_raw_icmp)
            progress["done"] = int(progress.get("done", 0)) + 1
            if alive:
                discovery[ip] = {"mac": "-", "ttl": ttl, "method": found_by or "Probe"}

    worker_count = min(options.host_concurrency, max(1, total_hosts))
    await asyncio.gather(*(worker() for _ in range(worker_count)))
    return discovery, arp_results, method


async def scan_tcp_ports_for_host(
    ip: str,
    ports: Sequence[int],
    options: ScanOptions,
    semaphore: asyncio.Semaphore,
    progress: Dict[str, object],
    cancel_event: asyncio.Event,
) -> List[int]:
    if not ports:
        return []
    port_iterator = iter(ports)
    open_ports: List[int] = []

    async def worker() -> None:
        while not cancel_event.is_set():
            try:
                port = next(port_iterator)
            except StopIteration:
                return
            is_open = await tcp_connect(ip, port, semaphore, options.tcp_timeout)
            progress["done"] = int(progress.get("done", 0)) + 1
            progress["attempt_done"] = int(progress.get("attempt_done", 0)) + 1
            if is_open:
                open_ports.append(port)
                progress["open_count"] = int(progress.get("open_count", 0)) + 1

    worker_count = min(PER_HOST_TCP_WORKERS, len(ports))
    await asyncio.gather(*(worker() for _ in range(worker_count)))
    return sorted(open_ports)


async def scan_udp_ports_for_host(
    ip: str,
    ports: Sequence[int],
    options: ScanOptions,
    semaphore: asyncio.Semaphore,
    progress: Dict[str, object],
    cancel_event: asyncio.Event,
) -> List[int]:
    if not ports:
        return []
    port_iterator = iter(ports)
    responding_ports: List[int] = []

    async def worker() -> None:
        while not cancel_event.is_set():
            try:
                port = next(port_iterator)
            except StopIteration:
                return
            responded = await udp_probe(ip, port, semaphore, options.tcp_timeout)
            progress["done"] = int(progress.get("done", 0)) + 1
            progress["attempt_done"] = int(progress.get("attempt_done", 0)) + 1
            if responded:
                responding_ports.append(port)
                progress["open_count"] = int(progress.get("open_count", 0)) + 1

    worker_count = min(PER_HOST_UDP_WORKERS, len(ports))
    await asyncio.gather(*(worker() for _ in range(worker_count)))
    return sorted(responding_ports)


async def scan_all_ports(
    ips: Sequence[str],
    options: ScanOptions,
    progress: Dict[str, object],
    cancel_event: asyncio.Event,
    tcp_semaphore: asyncio.Semaphore,
) -> Tuple[Dict[str, List[int]], Dict[str, List[int]]]:
    tcp_results: Dict[str, List[int]] = {ip: [] for ip in ips}
    udp_results: Dict[str, List[int]] = {ip: [] for ip in ips}
    udp_semaphore = asyncio.Semaphore(max(1, min(options.port_concurrency // 4, 200)))

    if options.tcp_ports:
        progress.update(
            stage="TCP port scan",
            done=0,
            total=max(1, len(ips) * len(options.tcp_ports)),
            attempt_done=0,
            attempt_total=len(ips) * len(options.tcp_ports),
            open_count=0,
            rate_started=time.monotonic(),
        )
        ip_iterator = iter(ips)
        iterator_lock = asyncio.Lock()

        async def next_ip() -> Optional[str]:
            async with iterator_lock:
                try:
                    return next(ip_iterator)
                except StopIteration:
                    return None

        async def tcp_host_worker() -> None:
            while not cancel_event.is_set():
                ip = await next_ip()
                if ip is None:
                    return
                tcp_results[ip] = await scan_tcp_ports_for_host(
                    ip, options.tcp_ports, options, tcp_semaphore, progress, cancel_event
                )

        worker_count = min(options.host_concurrency, max(1, len(ips)))
        await asyncio.gather(*(tcp_host_worker() for _ in range(worker_count)))

    if options.udp_ports and not cancel_event.is_set():
        progress.update(
            stage="UDP response probes",
            done=0,
            total=max(1, len(ips) * len(options.udp_ports)),
            attempt_done=0,
            attempt_total=len(ips) * len(options.udp_ports),
            open_count=0,
            rate_started=time.monotonic(),
        )
        ip_iterator = iter(ips)
        iterator_lock = asyncio.Lock()

        async def next_udp_ip() -> Optional[str]:
            async with iterator_lock:
                try:
                    return next(ip_iterator)
                except StopIteration:
                    return None

        async def udp_host_worker() -> None:
            while not cancel_event.is_set():
                ip = await next_udp_ip()
                if ip is None:
                    return
                udp_results[ip] = await scan_udp_ports_for_host(
                    ip, options.udp_ports, options, udp_semaphore, progress, cancel_event
                )

        worker_count = min(options.host_concurrency, max(1, len(ips)))
        await asyncio.gather(*(udp_host_worker() for _ in range(worker_count)))

    return tcp_results, udp_results


async def scan_subnet(
    options: ScanOptions,
    progress: Dict[str, object],
    cancel_event: asyncio.Event,
) -> ScanReport:
    started_wall = datetime.now()
    started_monotonic = time.monotonic()
    warnings: List[str] = []
    network = ipaddress.ip_network(options.subnet, strict=False)
    route = get_route_info(first_target_ip(network), options.interface)

    if not route.interface:
        warnings.append("No route/interface could be determined for the target network")
    elif not route.source_ip:
        warnings.append(f"No IPv4 source address was found on {route.interface}")

    progress.update(
        stage="Preparing discovery",
        done=0,
        total=1,
        warnings=warnings,
        scan_started=started_monotonic,
        open_count=0,
    )

    loop = asyncio.get_running_loop()
    oui_task = None
    if options.enable_oui:
        oui_task = loop.run_in_executor(None, get_oui_database, options.update_oui)

    mdns_task = asyncio.create_task(mdns_discovery()) if options.enable_mdns else None
    ssdp_task = asyncio.create_task(ssdp_discovery()) if options.enable_ssdp else None

    tcp_semaphore = asyncio.Semaphore(options.port_concurrency)
    discovery, arp_results, discovery_method = await discover_hosts(
        network, route, options, progress, cancel_event, warnings, tcp_semaphore
    )

    mdns_hostnames: Dict[str, Set[str]] = {}
    mdns_services: Dict[str, Set[str]] = {}
    ssdp_locations: Dict[str, List[str]] = {}
    ssdp_metadata: Dict[str, List[str]] = {}

    if mdns_task:
        mdns_hostnames, mdns_services, mdns_warning = await mdns_task
        if mdns_warning:
            warnings.append(mdns_warning)
    if ssdp_task:
        ssdp_locations, ssdp_metadata, ssdp_warning = await ssdp_task
        if ssdp_warning:
            warnings.append(ssdp_warning)

    # Multicast responses can reveal a local device missed by ARP/probes.
    for discovered_ip in set(mdns_hostnames).union(ssdp_locations).union(ssdp_metadata):
        try:
            if ipaddress.ip_address(discovered_ip) in network:
                discovery.setdefault(
                    discovered_ip,
                    {"mac": arp_results.get(discovered_ip, "-"), "ttl": None, "method": "mDNS/SSDP"},
                )
        except ValueError:
            continue

    ips = sorted(discovery, key=lambda value: tuple(int(part) for part in value.split(".")))
    progress["hosts_discovered"] = len(ips)

    if cancel_event.is_set():
        tcp_results = {ip: [] for ip in ips}
        udp_results = {ip: [] for ip in ips}
    else:
        tcp_results, udp_results = await scan_all_ports(
            ips, options, progress, cancel_event, tcp_semaphore
        )

    oui: Dict[str, str] = {}
    if oui_task:
        oui, oui_warning = await oui_task
        if oui_warning:
            warnings.append(oui_warning)

    aliases = load_aliases()
    hosts: Dict[str, Host] = {}
    progress.update(stage="Identifying devices", done=0, total=max(1, len(ips)))
    identify_semaphore = asyncio.Semaphore(min(options.host_concurrency, 100))
    banner_semaphore = asyncio.Semaphore(min(options.port_concurrency, 100))

    async def identify(ip: str) -> None:
        async with identify_semaphore:
            if cancel_event.is_set() and ip not in tcp_results:
                return
            details = discovery[ip]
            mac = str(details.get("mac") or "-")
            manufacturer = oui_lookup(mac, oui) if options.enable_oui else "-"
            tcp_ports = tcp_results.get(ip, [])
            udp_ports = udp_results.get(ip, [])
            name = await resolve_name(
                ip,
                mdns_hostnames,
                aliases,
                manufacturer,
                ssdp_metadata.get(ip, []),
                options.enable_dns,
            )
            banners: Dict[str, str] = {}
            if options.enable_banners and tcp_ports and not cancel_event.is_set():
                banners = await collect_banners(
                    ip,
                    tcp_ports,
                    max(0.8, min(options.tcp_timeout * 4, 3.0)),
                    banner_semaphore,
                )
            os_guess = ttl_to_os(details.get("ttl"))
            host = Host(
                ip=ip,
                mac=mac,
                manufacturer=manufacturer,
                name=name,
                open_tcp_ports=tcp_ports,
                open_udp_ports=udp_ports,
                os_guess=os_guess,
                discovery_method=str(details.get("method") or discovery_method),
                mdns_names=sorted(mdns_hostnames.get(ip, set())),
                mdns_services=sorted(mdns_services.get(ip, set())),
                ssdp_locations=ssdp_locations.get(ip, []),
                ssdp_meta=ssdp_metadata.get(ip, []),
                banners=banners,
                review_items=review_items_for_ports(tcp_ports),
            )
            host.device_type = classify_device(
                host.name,
                host.manufacturer,
                host.open_tcp_ports,
                host.open_udp_ports,
                host.mdns_services,
                host.ssdp_meta,
                host.os_guess,
            )
            hosts[ip] = host
            progress["done"] = int(progress.get("done", 0)) + 1

    await asyncio.gather(*(identify(ip) for ip in ips))
    elapsed = time.monotonic() - started_monotonic
    progress.update(stage="Complete" if not cancel_event.is_set() else "Cancelled", done=1, total=1)

    return ScanReport(
        subnet=str(network),
        profile=options.profile,
        started_at=started_wall.isoformat(timespec="seconds"),
        completed_at=datetime.now().isoformat(timespec="seconds"),
        elapsed_seconds=elapsed,
        hosts=hosts,
        warnings=list(dict.fromkeys(warnings)),
        cancelled=cancel_event.is_set(),
        discovery_method=discovery_method,
        route=route,
        tcp_ports=list(options.tcp_ports),
        udp_ports=list(options.udp_ports),
    )

# ============================================================
# CHANGE COMPARISON
# ============================================================

def compare_reports(previous: Optional[ScanReport], current: ScanReport) -> ScanReport:
    if previous is None:
        return current

    compared: Dict[str, Host] = {}
    for ip, host in current.hosts.items():
        old = previous.hosts.get(ip)
        if old is None:
            host.status = "NEW"
            host.changes = ["Newly discovered device"]
        else:
            changes: List[str] = []
            if old.status == "OFFLINE":
                changes.append("Device is responding again")
            new_tcp = sorted(set(host.open_tcp_ports) - set(old.open_tcp_ports))
            closed_tcp = sorted(set(old.open_tcp_ports) - set(host.open_tcp_ports))
            new_udp = sorted(set(host.open_udp_ports) - set(old.open_udp_ports))
            closed_udp = sorted(set(old.open_udp_ports) - set(host.open_udp_ports))
            if new_tcp:
                changes.append(f"New TCP ports: {format_ports(new_tcp)}")
            if closed_tcp:
                changes.append(f"Closed TCP ports: {format_ports(closed_tcp)}")
            if new_udp:
                changes.append(f"New UDP responses: {format_ports(new_udp, 'udp')}")
            if closed_udp:
                changes.append(f"Lost UDP responses: {format_ports(closed_udp, 'udp')}")
            if host.name != old.name:
                changes.append(f"Name changed: {old.name} -> {host.name}")
            if host.mac != old.mac and host.mac != "-" and old.mac != "-":
                changes.append(f"MAC changed: {old.mac} -> {host.mac}")
            host.status = "CHANGED" if changes else "CURRENT"
            host.changes = changes
        compared[ip] = host

    for ip, old_host in previous.hosts.items():
        if ip not in current.hosts:
            offline = copy.deepcopy(old_host)
            offline.status = "OFFLINE"
            offline.changes = ["Device did not respond to the latest scan"]
            compared[ip] = offline

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


def export_csv(report: ScanReport, options: ScanOptions) -> str:
    path = export_path(report, options, "csv")
    with open(path, "w", newline="", encoding="utf-8") as file_handle:
        writer = csv.writer(file_handle)
        writer.writerow([
            "IP", "Status", "Changes", "Name", "Device Type", "MAC", "Manufacturer",
            "OS Guess", "Discovery", "TCP Ports", "UDP Responded", "Review Items",
            "Banners", "mDNS Names", "mDNS Services", "SSDP Locations", "SSDP Metadata",
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
            ])
    return path


def export_json(report: ScanReport, options: ScanOptions) -> str:
    path = export_path(report, options, "json")
    payload = {
        "application": APP_NAME,
        "version": VERSION,
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
        },
        "hosts": [
            asdict(host)
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
    discovery_attempts = hosts * len(DISCOVERY_TCP_PORTS)
    port_attempts = hosts * (len(options.tcp_ports) + len(options.udp_ports))
    attempts = max(discovery_attempts if options.profile == "discover" else 0, port_attempts)

    if options.force or (hosts <= LARGE_HOST_THRESHOLD and attempts <= LARGE_ATTEMPT_THRESHOLD):
        return True

    stdscr.erase()
    safe_addstr(stdscr, 0, 0, "Large scan confirmation", curses.A_BOLD)
    lines = [
        f"Network: {network}",
        f"Usable addresses: {hosts:,}",
        f"TCP ports per discovered host: {len(options.tcp_ports):,}",
        f"UDP probes per discovered host: {len(options.udp_ports):,}",
        f"Potential port attempts: {port_attempts:,}",
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
        safe_addstr(stdscr, 5, 0, f"Attempts: {attempt_done:,}/{attempt_total:,} | Rate: {rate:,.1f}/sec | ETA: {format_duration(eta)}")
        safe_addstr(stdscr, 6, 0, f"Responsive/open results found: {int(progress.get('open_count', 0)):,}")
    if progress.get("hosts_discovered") is not None:
        safe_addstr(stdscr, 8, 0, f"Devices discovered: {int(progress.get('hosts_discovered', 0)):,}")

    warnings = progress.get("warnings", [])
    if isinstance(warnings, list) and warnings:
        safe_addstr(stdscr, max(10, height - 4), 0, f"Notice: {warnings[-1]}")
    footer = "Cancellation requested…" if cancel_requested else "Press q to cancel and keep partial results"
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
FILTER_MODES = ["all", "open", "review", "changed", "new", "offline"]


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
        if filter_mode == "changed" and host.status not in {"CHANGED", "NEW", "OFFLINE"}:
            continue
        if filter_mode == "new" and host.status != "NEW":
            continue
        if filter_mode == "offline" and host.status != "OFFLINE":
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
        order = {"NEW": 0, "CHANGED": 1, "OFFLINE": 2, "CURRENT": 3}
        values.sort(key=lambda host: (order.get(host.status, 9), ip_sort_key(host.ip)))
    return values


def compact_port_text(host: Host, limit: int = 8) -> str:
    values = [f"{port}/t" for port in host.open_tcp_ports]
    values.extend(f"{port}/u" for port in host.open_udp_ports)
    if len(values) > limit:
        return ",".join(values[:limit]) + ",…"
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
        status_marker = {"NEW": "+", "CHANGED": "*", "OFFLINE": "-", "CURRENT": " "}.get(host.status, " ")
        if host.review_items:
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
        f"Name:           {host.name}",
        f"Device Type:    {host.device_type}",
        f"MAC:            {host.mac}",
        f"Manufacturer:   {host.manufacturer}",
        f"OS Guess:       {host.os_guess}",
        f"Discovered By:  {host.discovery_method}",
        f"TCP Ports:      {format_ports(host.open_tcp_ports)}",
        f"UDP Responses:  {format_ports(host.open_udp_ports, 'udp')}",
    ]
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
        "  f                 Cycle filters: all/open/review/changed/new/offline",
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
        "  ICMP and selected TCP discovery ports. TCP-only discovery does not invent a TTL,",
        "  so its OS result remains Unknown unless a real ICMP TTL was received.",
        "",
        "UDP behavior",
        "  UDP entries are response-based probes only. Silence is not labeled open because",
        "  it can mean either an open service or packet filtering.",
        "",
        "Result symbols",
        "  + new device   * changed device   - offline   ! service needs review",
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

    return ScanOptions(
        subnet=subnet,
        profile=profile,
        tcp_ports=tcp_ports,
        udp_ports=udp_ports,
        interface=args.interface,
        tcp_timeout=args.timeout,
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
                    message = f"Rescanned {selected.ip}"
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
                )
                single_report = compare_reports(previous_single, single_report)
                report.hosts[selected.ip] = single_report.hosts.get(selected.ip, previous_single.hosts[selected.ip])
                message = f"Rescanned {selected.ip}"
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
