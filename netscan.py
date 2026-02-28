#!/usr/bin/env python3

import asyncio
import curses
import csv
import json
import os
import socket
import struct
import time
import re
import urllib.request
import ipaddress
import argparse
from dataclasses import dataclass

# ============================================================
# CONFIG
# ============================================================

AUTO_DETECT_SUBNET = True
CUSTOM_SUBNETS = ["192.168.1.0/24"]

PORT_CHECK_LIST = [
    20,21,22,23,25,53,67,68,69,80,88,110,111,119,123,135,137,138,139,143,161,162,
    389,443,445,465,500,512,513,514,515,548,554,587,631,636,873,902,989,990,993,995,
    1080,1194,1433,1521,1701,1723,1812,1813,1883,1900,2049,2375,2376,3306,3389,3690,
    4369,4789,5060,5061,5432,5671,5672,5900,5985,5986,6379,6443,6667,7001,8000,8008,
    8080,8081,8443,8530,8531,8883,9000,9042,9092,9100,9200,9300,9418,9999,11211,
    15672,27017,27018,27019
]
TCP_TIMEOUT = 0.5
PARALLEL = 200

ARP_TIMEOUT = 1.0
ICMP_AVAILABLE = None

OUI_URL = "https://standards-oui.ieee.org/oui/oui.csv"
OUI_CACHE_FILE = os.path.expanduser("~/.cache/netscan/oui.json")
ALIASES_FILE = os.path.expanduser("~/.config/netscan/aliases.json")

MDNS_TIMEOUT = 2
SSDP_TIMEOUT = 2

# ============================================================
# MODEL
# ============================================================

@dataclass
class Host:
    ip: str
    mac: str
    manufacturer: str
    name: str
    open_ports: list
    os_guess: str
    mdns_names: list
    mdns_services: list
    ssdp_locations: list
    ssdp_meta: list

# ============================================================
# CLI
# ============================================================

def parse_args():
    p = argparse.ArgumentParser(description="netscan - simple LAN scanner (TUI)")
    p.add_argument(
        "-n", "--network",
        help="Subnet in CIDR notation, e.g. 172.16.88.0/24",
        default=None
    )
    return p.parse_args()

# ============================================================
# BASIC HELPERS
# ============================================================

def detect_local_subnet():
    ips = os.popen("hostname -I").read().strip().split()
    if not ips:
        return None
    ip = ips[0]
    for line in os.popen("ip route").read().splitlines():
        if ip in line and "/" in line:
            return line.split()[0]
    return None

def load_aliases():
    try:
        with open(ALIASES_FILE) as f:
            return json.load(f)
    except:
        return {}

# ============================================================
# OUI MANUFACTURER
# ============================================================

def load_oui():
    try:
        with open(OUI_CACHE_FILE) as f:
            return json.load(f)
    except:
        return {}

def save_oui(d):
    os.makedirs(os.path.dirname(OUI_CACHE_FILE), exist_ok=True)
    with open(OUI_CACHE_FILE, "w") as f:
        json.dump(d, f)

def update_oui():
    try:
        data = urllib.request.urlopen(OUI_URL, timeout=20).read().decode()
    except:
        return {}
    m = {}
    for l in data.splitlines():
        p = l.split(",")
        if len(p) < 3:
            continue
        pref = p[1].replace("-", "").upper()
        name = p[2].strip().strip('"')
        if len(pref) == 6:
            m[pref] = name
    save_oui(m)
    return m

def oui_lookup(mac, oui):
    if mac == "-" or ":" not in mac:
        return "-"
    return oui.get(mac.replace(":", "").upper()[:6], "-")

# ============================================================
# RAW ARP SWEEP (DISCOVERS ALL DEVICES)
# ============================================================

def build_arp_packet(src_mac, src_ip, dst_ip):
    def mac2b(m):
        return bytes(int(x, 16) for x in m.split(":"))

    hw_type = 1
    proto_type = 0x0800
    hw_size = 6
    proto_size = 4
    opcode = 1

    src_mac_b = mac2b(src_mac)
    dst_mac_b = b"\x00" * 6

    return struct.pack(
        "!HHBBH6s4s6s4s",
        hw_type, proto_type, hw_size, proto_size, opcode,
        src_mac_b, socket.inet_aton(src_ip),
        dst_mac_b, socket.inet_aton(dst_ip),
    )

def get_local_mac(iface):
    try:
        return open(f"/sys/class/net/{iface}/address").read().strip()
    except:
        return None

def get_default_iface():
    out = os.popen("ip route show default").read()
    m = re.search(r"dev\s+(\S+)", out)
    return m.group(1) if m else None

def arp_sweep(subnet):
    iface = get_default_iface()
    if not iface:
        return {}

    mac = get_local_mac(iface)
    if not mac:
        return {}

    try:
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0806))
    except PermissionError:
        return {}
    except:
        return {}

    try:
        s.bind((iface, 0))
    except:
        try:
            s.close()
        except:
            pass
        return {}

    net = ipaddress.ip_network(subnet, strict=False)
    my_ips = os.popen("hostname -I").read().strip().split()
    if not my_ips:
        try:
            s.close()
        except:
            pass
        return {}
    my_ip = my_ips[0]

    src_mac_bytes = bytes(int(x, 16) for x in mac.split(":"))
    eth_hdr_prefix = bytes.fromhex("ff ff ff ff ff ff") + src_mac_bytes + struct.pack("!H", 0x0806)

    for ip in net.hosts():
        try:
            pkt = build_arp_packet(mac, my_ip, str(ip))
            s.send(eth_hdr_prefix + pkt)
        except:
            pass

    s.settimeout(ARP_TIMEOUT)
    results = {}

    end = time.time() + ARP_TIMEOUT
    while time.time() < end:
        try:
            frame = s.recv(2048)
            if len(frame) < 42:
                continue
            eth_proto = struct.unpack("!H", frame[12:14])[0]
            if eth_proto != 0x0806:
                continue
            arp = frame[14:42]
            opcode = struct.unpack("!H", arp[6:8])[0]
            if opcode != 2:
                continue
            mac_addr = ":".join(f"{b:02x}" for b in arp[8:14])
            ip_addr = socket.inet_ntoa(arp[14:18])
            results[ip_addr] = mac_addr
        except:
            break

    try:
        s.close()
    except:
        pass

    return results

# ============================================================
# HYBRID PING
# ============================================================

def icmp_checksum(data):
    if len(data) % 2:
        data += b"\x00"
    s = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return (~s) & 0xFFFF

async def try_raw_icmp(ip):
    global ICMP_AVAILABLE
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, 1)
    except PermissionError:
        ICMP_AVAILABLE = False
        return False, None
    except:
        ICMP_AVAILABLE = False
        return False, None

    ICMP_AVAILABLE = True
    s.setblocking(False)

    header = struct.pack("!BBHHH", 8, 0, 0, 999, 1)
    payload = b"X\x00"
    csum = icmp_checksum(header + payload)
    pkt = struct.pack("!BBHHH", 8, 0, csum, 999, 1) + payload

    try:
        s.sendto(pkt, (ip, 1))
    except:
        try:
            s.close()
        except:
            pass
        ICMP_AVAILABLE = False
        return False, None

    loop = asyncio.get_running_loop()
    end = loop.time() + 0.3

    while True:
        remaining = end - loop.time()
        if remaining <= 0:
            break
        try:
            data, addr = await asyncio.wait_for(loop.sock_recvfrom(s, 2048), timeout=remaining)
            if addr and addr[0] == ip and len(data) > 8:
                try:
                    s.close()
                except:
                    pass
                return True, data[8]
        except asyncio.TimeoutError:
            break
        except:
            pass

    try:
        s.close()
    except:
        pass
    return False, None

async def raw_icmp_ping(ip):
    payload = b"NETSCAN"
    if len(payload) % 2:
        payload += b"\x00"
    pid = os.getpid() & 0xFFFF
    header = struct.pack("!BBHHH", 8, 0, 0, pid, 1)
    csum = icmp_checksum(header + payload)
    pkt = struct.pack("!BBHHH", 8, 0, csum, pid, 1) + payload

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, 1)
    except PermissionError:
        return False, None
    except:
        return False, None

    s.setblocking(False)
    try:
        s.sendto(pkt, (ip, 1))
    except:
        try:
            s.close()
        except:
            pass
        return False, None

    loop = asyncio.get_running_loop()
    end = loop.time() + 1.0

    while True:
        remaining = end - loop.time()
        if remaining <= 0:
            break
        try:
            data, addr = await asyncio.wait_for(loop.sock_recvfrom(s, 2048), timeout=remaining)
            if addr and addr[0] == ip and len(data) > 8:
                try:
                    s.close()
                except:
                    pass
                return True, data[8]
        except asyncio.TimeoutError:
            break
        except:
            pass

    try:
        s.close()
    except:
        pass
    return False, None

async def tcp_syn(ip, port):
    try:
        fut = asyncio.open_connection(ip, port)
        r, w = await asyncio.wait_for(fut, timeout=TCP_TIMEOUT)
        w.close()
        try:
            await w.wait_closed()
        except:
            pass
        return True
    except:
        return False

async def hybrid_ping(ip):
    global ICMP_AVAILABLE
    if ICMP_AVAILABLE is None:
        ok, ttl = await try_raw_icmp(ip)
        if ok:
            ICMP_AVAILABLE = True
            return True, ttl
        ICMP_AVAILABLE = False

    if ICMP_AVAILABLE:
        ok, ttl = await raw_icmp_ping(ip)
        if ok:
            return True, ttl

    for p in (80, 443, 22):
        if await tcp_syn(ip, p):
            return True, 64
    return False, None

# ============================================================
# NAME DETECTION
# ============================================================

async def reverse_dns(ip):
    def block():
        try:
            socket.setdefaulttimeout(0.3)
            n, _, _ = socket.gethostbyaddr(ip)
            return n
        except:
            return "-"
    return await asyncio.get_running_loop().run_in_executor(None, block)

async def netbios(ip):
    def block():
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(0.3)
            pkt = bytes.fromhex("13370000000100000000000020" + "43" * 32 + "0000210001")
            s.sendto(pkt, (ip, 137))
            d, _ = s.recvfrom(1024)
            s.close()
            t = d.decode("latin-1", "ignore")
            m = re.findall(r"[A-Z0-9_-]{1,15}\s+", t)
            return m[0].strip() if m else "-"
        except:
            return "-"
    return await asyncio.get_running_loop().run_in_executor(None, block)

def ssdp_friendly_name(ssdp_meta_list):
    """
    Extract a human-friendly identifier from SSDP meta lines.
    Example:
      'USN: uuid:roku:ecp:Home Assistant' -> 'Home Assistant'
    """
    if not ssdp_meta_list:
        return None

    for line in ssdp_meta_list:
        m = re.match(r"(?i)^USN:\s*(.+)$", line.strip())
        if not m:
            continue
        usn = m.group(1).strip()

        parts = usn.split(":")
        if len(parts) >= 3:
            candidate = parts[-1].strip()
            bad = {"upnp", "rootdevice", "device"}
            if candidate and candidate.lower() not in bad and "uuid" not in candidate.lower():
                return candidate

    return None

def _pick_pretty_name(ip, aliases, mdns_h, ssdp_name, netbios_name, rdns_name, manufacturer):
    if ip in aliases and aliases[ip]:
        return aliases[ip]
    if ssdp_name:
        return ssdp_name
    if ip in mdns_h and mdns_h[ip]:
        return next(iter(mdns_h[ip]))
    if netbios_name and netbios_name != "-":
        return netbios_name
    if rdns_name and rdns_name != "-":
        return rdns_name
    if manufacturer and manufacturer != "-":
        return f"({manufacturer})"
    return "(unknown)"

async def resolve_name(ip, mdns_h, aliases, manufacturer, ssdp_meta_list):
    ssdp_name = ssdp_friendly_name(ssdp_meta_list)
    nb = await netbios(ip)
    rd = await reverse_dns(ip)
    return _pick_pretty_name(ip, aliases, mdns_h, ssdp_name, nb, rd, manufacturer)

# ============================================================
# MDNS
# ============================================================

async def mdns_discovery():
    try:
        from zeroconf.asyncio import AsyncZeroconf, AsyncServiceBrowser
    except:
        return {}, {}

    hostnames = {}
    services = {}

    async def handler(zc, stype, name, state):
        try:
            info = await az.async_get_service_info(stype, name, timeout=1000)
            if not info:
                return
            for a in info.addresses:
                if len(a) == 4:
                    ip = socket.inet_ntoa(a)
                    if info.server:
                        hostnames.setdefault(ip, set()).add(info.server.rstrip("."))
                    services.setdefault(ip, set()).add(stype.rstrip("."))
        except:
            pass

    az = AsyncZeroconf()
    zc = az.zeroconf
    types = ["_workstation._tcp.local.", "_http._tcp.local.", "_ssh._tcp.local."]
    browsers = [AsyncServiceBrowser(zc, t, handlers=[handler]) for t in types]
    await asyncio.sleep(MDNS_TIMEOUT)
    await az.async_close()
    return hostnames, services

# ============================================================
# SSDP
# ============================================================

async def ssdp_discovery():
    group = ("239.255.255.250", 1900)
    msg = (
        "M-SEARCH * HTTP/1.1\r\n"
        "HOST: 239.255.255.250:1900\r\n"
        'MAN: "ssdp:discover"\r\n'
        "MX: 1\r\n"
        "ST: ssdp:all\r\n\r\n"
    ).encode()

    def block():
        loc = {}
        meta = {}
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(SSDP_TIMEOUT)
            s.sendto(msg, group)
            start = time.time()
            while time.time() - start < SSDP_TIMEOUT:
                try:
                    d, (ip, _) = s.recvfrom(65535)
                except:
                    break
                t = d.decode("utf-8", "ignore")

                def f(k):
                    m = re.search(rf"(?im)^{k}:\s*(.+)$", t)
                    return m.group(1).strip() if m else None

                fl = f("location")
                if fl:
                    loc.setdefault(ip, []).append(fl)

                meta.setdefault(ip, [])
                for k in ["st", "usn", "server"]:
                    v = f(k)
                    if v:
                        meta[ip].append(f"{k.upper()}: {v}")
            s.close()
        except:
            pass
        return loc, meta

    return await asyncio.get_running_loop().run_in_executor(None, block)

# ============================================================
# OS FINGERPRINTING
# ============================================================

def ttl_to_os(ttl):
    if ttl is None:
        return "Unknown"
    if ttl >= 120:
        return "Windows"
    if ttl >= 64:
        return "Linux/Unix"
    return "Unknown"

# ============================================================
# MAIN SUBNET SCAN
# ============================================================

async def scan_subnet(subnet, progress):
    net = ipaddress.ip_network(subnet, strict=False)

    progress["stage"] = "ARP discovery"
    progress["total"] = max(1, int(net.num_addresses) - 2)
    progress["done"] = 0

    loop = asyncio.get_running_loop()
    arp_results = await loop.run_in_executor(None, arp_sweep, subnet)

    ips = sorted(arp_results.keys(), key=lambda x: tuple(map(int, x.split("."))))

    progress["stage"] = "Scanning hosts"
    progress["total"] = max(1, len(ips))
    progress["done"] = 0

    aliases = load_aliases()
    oui = load_oui() or update_oui()

    mdns_h, mdns_s = await mdns_discovery()
    ssdp_l, ssdp_m = await ssdp_discovery()

    results = {}
    sem = asyncio.Semaphore(PARALLEL)

    async def worker(ip):
        async with sem:
            mac = arp_results.get(ip, "-")
            manuf = oui_lookup(mac, oui)

            alive, ttl = await hybrid_ping(ip)
            os_guess = ttl_to_os(ttl)

            openp = []
            for p in PORT_CHECK_LIST:
                if await tcp_syn(ip, p):
                    openp.append(p)

            alive = alive or bool(openp)

            name = await resolve_name(ip, mdns_h, aliases, manuf, ssdp_m.get(ip, []))

            results[ip] = Host(
                ip=ip,
                mac=mac,
                manufacturer=manuf,
                name=name,
                open_ports=openp,
                os_guess=os_guess,
                mdns_names=list(mdns_h.get(ip, [])),
                mdns_services=list(mdns_s.get(ip, [])),
                ssdp_locations=ssdp_l.get(ip, []),
                ssdp_meta=ssdp_m.get(ip, []),
            )
            progress["done"] += 1

    await asyncio.gather(*(worker(ip) for ip in ips))
    return results, len(ips)

# ============================================================
# TUI
# ============================================================

def _safe_addstr(stdscr, y, x, s, attr=0):
    try:
        stdscr.addstr(y, x, s, attr)
    except:
        pass

def draw_progress(stdscr, progress):
    stdscr.erase()
    h, w = stdscr.getmaxyx()

    done = int(progress.get("done", 0))
    total = int(progress.get("total", 1))
    stage = str(progress.get("stage", "Scanning"))

    total = max(1, total)
    pct = done / total

    bar_width = max(10, w - 20)
    bar = int(pct * bar_width)

    _safe_addstr(stdscr, h // 2, 0, f"{stage}: {done}/{total}")
    _safe_addstr(stdscr, h // 2 + 1, 0, "[" + ("#" * bar) + ("-" * (bar_width - bar)) + "]")
    stdscr.refresh()

def draw_list(stdscr, hosts, idx, top):
    stdscr.erase()
    h, w = stdscr.getmaxyx()

    header = "netscan — ↑↓ select | Enter details | e export | r refresh | q quit"
    _safe_addstr(stdscr, 0, 0, header[: max(0, w - 1)], curses.A_BOLD)

    cols = (
        f"{'IP':15}   "
        f"{'Name':22}   "
        f"{'MAC':17}   "
        f"{'Manufacturer':20}   "
        f"{'OS':10}   "
        f"{'Ports'}"
    )
    _safe_addstr(stdscr, 2, 0, cols[: max(0, w - 1)], curses.A_UNDERLINE)

    start_y = 3
    visible = max(0, h - start_y - 1)

    for row in range(visible):
        i = top + row
        if i >= len(hosts):
            break
        hst = hosts[i]
        y = start_y + row

        ports = ",".join(map(str, hst.open_ports[:12]))
        if len(hst.open_ports) > 12:
            ports += ",…"

        line = (
            f"{hst.ip:15}   "
            f"{hst.name:22.22}   "
            f"{hst.mac:17}   "
            f"{hst.manufacturer:20.20}   "
            f"{hst.os_guess:10.10}   "
            f"{ports}"
        )
        line = line[: max(0, w - 1)]
        attr = curses.A_REVERSE if i == idx else 0
        _safe_addstr(stdscr, y, 0, line, attr)

    footer = f"{idx+1}/{len(hosts)}"
    _safe_addstr(stdscr, h - 1, max(0, w - len(footer) - 1), footer)

    stdscr.refresh()

def draw_details(stdscr, hst):
    stdscr.erase()
    h, w = stdscr.getmaxyx()
    _safe_addstr(stdscr, 0, 0, "Details — b back | p ping", curses.A_BOLD)

    y = 2
    lines = [
        f"IP:            {hst.ip}",
        f"Name:          {hst.name}",
        f"MAC:           {hst.mac}",
        f"Manufacturer:  {hst.manufacturer}",
        f"OS Guess:      {hst.os_guess}",
        f"Open Ports:    {', '.join(map(str, hst.open_ports)) or 'none'}",
        "",
        "mDNS Names:",
    ]
    for ln in lines:
        if y >= h - 1:
            break
        _safe_addstr(stdscr, y, 0, ln[: max(0, w - 1)])
        y += 1

    for m in hst.mdns_names:
        if y >= h - 1:
            break
        _safe_addstr(stdscr, y, 2, m[: max(0, w - 3)])
        y += 1

    if y < h - 1:
        y += 1
        _safe_addstr(stdscr, y, 0, "SSDP:")
        y += 1

    for loc in hst.ssdp_locations:
        if y >= h - 1:
            break
        _safe_addstr(stdscr, y, 2, ("LOC: " + loc)[: max(0, w - 3)])
        y += 1

    for meta in hst.ssdp_meta:
        if y >= h - 1:
            break
        _safe_addstr(stdscr, y, 2, meta[: max(0, w - 3)])
        y += 1

    stdscr.refresh()

def export_csv(hosts):
    with open("netscan_export.csv", "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["IP", "Name", "MAC", "Manufacturer", "OS", "Ports"])
        for hst in hosts:
            w.writerow([hst.ip, hst.name, hst.mac, hst.manufacturer, hst.os_guess, ",".join(map(str, hst.open_ports))])

# ============================================================
# MAIN
# ============================================================

def _clamp(n, lo, hi):
    return max(lo, min(hi, n))

def main(stdscr, subnet_override=None):
    curses.curs_set(0)
    stdscr.keypad(True)

    if subnet_override:
        subnet = subnet_override
    else:
        if AUTO_DETECT_SUBNET:
            det = detect_local_subnet()
            subnets = [det] + CUSTOM_SUBNETS if det else CUSTOM_SUBNETS
        else:
            subnets = CUSTOM_SUBNETS
        subnet = subnets[0]

    try:
        ipaddress.ip_network(subnet, strict=False)
    except Exception as e:
        raise SystemExit(f"Invalid subnet '{subnet}': {e}")

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    progress = {"done": 0, "total": 1, "stage": "starting"}
    stdscr.nodelay(True)

    scan_task = loop.create_task(scan_subnet(subnet, progress))
    while not scan_task.done():
        try:
            loop.run_until_complete(asyncio.wait_for(asyncio.shield(scan_task), timeout=0.1))
        except asyncio.TimeoutError:
            pass
        draw_progress(stdscr, progress)

    results, _total = loop.run_until_complete(scan_task)
    hosts = sorted(results.values(), key=lambda hh: tuple(map(int, hh.ip.split("."))))

    idx = 0
    top = 0
    details = False

    while True:
        h, w = stdscr.getmaxyx()
        visible = max(1, h - 3 - 1)

        if hosts:
            idx = _clamp(idx, 0, len(hosts) - 1)
            if idx < top:
                top = idx
            elif idx >= top + visible:
                top = max(0, idx - visible + 1)
            top = _clamp(top, 0, max(0, len(hosts) - visible))
        else:
            idx = 0
            top = 0

        if details and hosts:
            draw_details(stdscr, hosts[idx])
        else:
            draw_list(stdscr, hosts, idx, top)

        ch = stdscr.getch()
        if ch == -1:
            continue

        if ch == ord("q"):
            break

        if details:
            if ch == ord("b"):
                details = False
            elif ch == ord("p") and hosts:
                os.system(f"ping -c4 {hosts[idx].ip}")
                _safe_addstr(stdscr, min(20, curses.LINES - 1), 0, "Press any key…")
                stdscr.refresh()
                stdscr.getch()
            continue

        if ch == curses.KEY_UP:
            idx -= 1
        elif ch == curses.KEY_DOWN:
            idx += 1
        elif ch == curses.KEY_PPAGE:
            idx -= visible
        elif ch == curses.KEY_NPAGE:
            idx += visible
        elif ch in (10, 13):
            if hosts:
                details = True
        elif ch == ord("e"):
            export_csv(hosts)
            _safe_addstr(stdscr, 1, 0, "Exported netscan_export.csv")
            stdscr.refresh()
        elif ch == ord("r"):
            progress = {"done": 0, "total": 1, "stage": "starting"}
            scan_task = loop.create_task(scan_subnet(subnet, progress))

            while not scan_task.done():
                try:
                    loop.run_until_complete(asyncio.wait_for(asyncio.shield(scan_task), timeout=0.1))
                except asyncio.TimeoutError:
                    pass
                draw_progress(stdscr, progress)

            results, _total = loop.run_until_complete(scan_task)
            hosts = sorted(results.values(), key=lambda hh: tuple(map(int, hh.ip.split("."))))
            idx = 0
            top = 0
            details = False

if __name__ == "__main__":
    args = parse_args()
    curses.wrapper(main, args.network)
