#!/usr/bin/env python3
"""
netscan_plus.py — Improved Network Device Scanner
- Host discovery: ICMP ping + TCP connect probes (22, 80, 443, 139, 445, 3389)
- Robust MAC discovery: scapy ARP (if available) -> arping CLI -> ARP table fallback
- Vendor/OUI mapping (tiny built-in + optional local cache "oui_cache.json")
- Device type hints: Android vs iOS vs Desktop via OUI + mDNS/SSDP + hostname clues
- OS guess: TTL + open-port heuristics
- CSV/JSON export
- Cross-platform (Windows/macOS/Linux). For best results, run as admin/root.

Usage:
  python netscan_plus.py
"""

import socket
import subprocess
import platform
import re
import concurrent.futures
import ipaddress
import json
import csv
from datetime import datetime

# ----------------------- Config -----------------------
COMMON_PORTS = [22, 23, 53, 80, 443, 8080, 8443, 139, 445, 3389, 5900]
PING_TIMEOUT = 1.0
TCP_TIMEOUT = 0.6
MAX_THREADS = 100
OUI_CACHE_FILE = "oui_cache.json"  # optional, user-provided file with {"AA:BB:CC":"Vendor"}

# minimal sample OUI vendor hints; expand or use oui_cache.json locally
OUI_SAMPLE = {
    "AC:87:A3": "Apple, Inc.",
    "F4:5C:89": "Samsung Electronics",
    "88:32:9B": "Xiaomi Communications",
    "E8:9A:8F": "HUAWEI TECHNOLOGIES",
    "3C:5A:B4": "Google, Inc.",
    "D8:9E:F3": "OPPO",
    "00:1A:11": "Google, Inc.",
    "58:7F:66": "vivo Mobile",
    "74:4A:A4": "realme",
    "BC:92:6B": "OnePlus",
    "00:50:56": "VMware",
    "08:00:27": "Oracle VirtualBox",
    "52:54:00": "QEMU/KVM",
    "00:1D:D8": "Microsoft",
    "00:1B:63": "Apple, Inc.",
}

def load_oui_cache():
    try:
        with open(OUI_CACHE_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
            # normalize keys to upper AA:BB:CC
            return {k.upper(): v for k, v in data.items() if len(k.split(':')) == 3}
    except Exception:
        return {}

OUI_CACHE = load_oui_cache()

def mac_normalize(mac: str):
    if not mac or mac == "Unknown":
        return None
    mac = mac.strip().upper().replace('-', ':')
    parts = mac.split(':')
    if len(parts) == 6 and all(len(p) == 2 for p in parts):
        return ':'.join(parts)
    return None

def lookup_oui_vendor(mac: str):
    m = mac_normalize(mac)
    if not m:
        return "Unknown"
    prefix = ':'.join(m.split(':')[:3])
    return OUI_CACHE.get(prefix) or OUI_SAMPLE.get(prefix) or "Unknown"

class NetScanner:
    def __init__(self):
        self.os_name = platform.system().lower()
        self.prefix = self.get_prefix()

    def get_prefix(self):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("8.8.8.8", 80))
                ip = s.getsockname()[0]
            return '.'.join(ip.split('.')[:3])
        except Exception:
            return "192.168.1"

    # --------------- Host discovery ---------------
    def ping(self, ip):
        try:
            if self.os_name.startswith("windows"):
                cmd = ["ping", "-n", "1", "-w", str(int(PING_TIMEOUT*1000)), ip]
            elif self.os_name == "darwin":
                cmd = ["ping", "-c", "1", "-W", str(int(PING_TIMEOUT)), ip]
            else:
                cmd = ["ping", "-c", "1", "-W", str(int(PING_TIMEOUT)), ip]
            subprocess.check_output(cmd, stderr=subprocess.DEVNULL)
            return True
        except Exception:
            return False

    def tcp_probe(self, ip, port):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(TCP_TIMEOUT)
                s.connect((ip, port))
                try:
                    s.settimeout(0.5)
                    banner = s.recv(256)
                except Exception:
                    banner = b""
                return True, banner.decode(errors="ignore").strip()
        except Exception:
            return False, ""

    def refresh_arp(self, ip):
        # cause traffic so the kernel learns ARP; ignore errors
        for p in COMMON_PORTS:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(0.2)
                    s.connect((ip, p))
                    return
            except Exception:
                pass

    # --------------- MAC retrieval ---------------
    def mac_from_scapy(self, ip):
        try:
            from scapy.all import arping, conf
            conf.verb = 0
            ans, _ = arping(ip + "/32", timeout=1)
            for _, rcv in ans:
                mac = getattr(rcv, "hwsrc", None)
                if mac:
                    return mac_normalize(mac)
        except Exception:
            return None

    def mac_from_arping(self, ip):
        try:
            out = subprocess.check_output(["arping", "-c", "1", "-w", "1", ip],
                                          stderr=subprocess.DEVNULL).decode(errors="ignore")
            m = re.search(r"from\s+([0-9A-Fa-f:]{17})", out) or re.search(r"\[([0-9A-Fa-f:]{17})\]", out)
            if m:
                return mac_normalize(m.group(1))
        except Exception:
            return None

    def mac_from_table(self, ip):
        try:
            if self.os_name.startswith("windows"):
                out = subprocess.check_output(["arp", "-a", ip], stderr=subprocess.DEVNULL).decode(errors="ignore")
                m = re.search(r"([0-9A-Fa-f]{2}(?:-[0-9A-Fa-f]{2}){5})", out)
                if m:
                    return mac_normalize(m.group(1))
            else:
                # try ip neigh first
                try:
                    out = subprocess.check_output(["ip", "neigh"], stderr=subprocess.DEVNULL).decode(errors="ignore")
                    m = re.search(rf"{re.escape(ip)}.*lladdr\s+([0-9A-Fa-f:]{17})", out)
                    if m:
                        return mac_normalize(m.group(1))
                except Exception:
                    pass
                out = subprocess.check_output(["arp", "-n", ip], stderr=subprocess.DEVNULL).decode(errors="ignore")
                m = re.search(r"([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})", out)
                if m:
                    return mac_normalize(m.group(1))
        except Exception:
            return None
        return None

    def get_mac(self, ip):
        mac = self.mac_from_scapy(ip)
        if mac: return mac
        mac = self.mac_from_arping(ip)
        if mac: return mac
        self.refresh_arp(ip)
        mac = self.mac_from_table(ip)
        return mac or "Unknown"

    # --------------- Name / TTL / OS ---------------
    def reverse_dns(self, ip):
        try:
            name = socket.gethostbyaddr(ip)[0]
            return name if name and name != ip else "Unknown"
        except Exception:
            return "Unknown"

    def ttl_value(self, ip):
        try:
            if self.os_name.startswith("windows"):
                out = subprocess.check_output(["ping", "-n", "1", ip], stderr=subprocess.DEVNULL).decode(errors="ignore")
                m = re.search(r"TTL=(\d+)", out, re.IGNORECASE)
            else:
                out = subprocess.check_output(["ping", "-c", "1", ip], stderr=subprocess.DEVNULL).decode(errors="ignore")
                m = re.search(r"ttl=(\d+)", out, re.IGNORECASE)
            return int(m.group(1)) if m else None
        except Exception:
            return None

    def probe_ssdp(self, ip):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(0.6)
            msg = '\r\n'.join([
                'M-SEARCH * HTTP/1.1',
                'HOST: 239.255.255.250:1900',
                'MAN: "ssdp:discover"',
                'MX: 1',
                'ST: ssdp:all',
                '', ''
            ]).encode()
            s.sendto(msg, (ip, 1900))
            data, _ = s.recvfrom(2048)
            return data.decode(errors="ignore")
        except Exception:
            return ""

    def probe_mdns(self, ip):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(0.6)
            # lightweight "poke"; not a full DNS query
            s.sendto(b'\x00', (ip, 5353))
            data, _ = s.recvfrom(2048)
            return data.decode(errors="ignore")
        except Exception:
            return ""

    def guess_os(self, ttl, open_ports):
        if ttl is not None:
            if ttl <= 64: base = "Linux/Unix"
            elif ttl <= 128: base = "Windows"
            else: base = "Network Device"
        else:
            base = "Unknown"
        if 445 in open_ports or 3389 in open_ports or 139 in open_ports:
            return "Windows"
        if 22 in open_ports and base == "Unknown":
            return "Linux/Unix"
        return base

    # --------------- Per-host scan ---------------
    def scan_host(self, ip):
        alive = False
        open_ports = []
        banners = {}
        # ICMP
        if self.ping(ip):
            alive = True
        # TCP ports
        for p in COMMON_PORTS:
            ok, banner = self.tcp_probe(ip, p)
            if ok:
                alive = True
                open_ports.append(p)
                if banner:
                    banners[p] = banner
        if not alive:
            return None

        # Names and MAC
        hostname = self.reverse_dns(ip)
        mac = self.get_mac(ip)
        vendor = lookup_oui_vendor(mac)
        ttl = self.ttl_value(ip)
        os_guess = self.guess_os(ttl, open_ports)

        # extra hints
        ssdp = self.probe_ssdp(ip)
        mdns = self.probe_mdns(ip)
        combined = " ".join(filter(None, [hostname, ssdp, mdns])).lower()

        device_type = "Unknown"
        if "apple" in vendor.lower():
            device_type = "Apple (iPhone/iPad/Mac)"
        elif any(k in vendor.lower() for k in ["samsung", "huawei", "xiaomi", "google", "oneplus", "vivo", "oppo", "realme"]):
            device_type = "Android (phone/tablet)"
        if "iphone" in combined or "ipad" in combined:
            device_type = "Apple (iPhone/iPad)"
        if "android" in combined or hostname.lower().startswith(("sm-", "redmi", "mi-", "moto", "vivo", "oppo")):
            device_type = "Android (phone/tablet)"
        if device_type == "Unknown":
            device_type = os_guess

        return {
            "ip": ip,
            "hostname": hostname,
            "mac": mac,
            "vendor": vendor,
            "os": os_guess,
            "ttl": ttl,
            "open_ports": open_ports,
            "banners": banners,
            "device_type": device_type
        }

    # --------------- Scanning loops ---------------
    def scan_range(self, targets):
        devices = []
        start_time = datetime.now()
        total = len(targets)
        scanned = 0

        with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_THREADS) as ex:
            futures = {ex.submit(self.scan_host, ip): ip for ip in targets}
            for fut in concurrent.futures.as_completed(futures):
                scanned += 1
                ip = futures[fut]
                try:
                    d = fut.result()
                    if d:
                        devices.append(d)
                        print(f"• {d['ip']:15} | {d['hostname'][:18]:18} | {d['mac'] or 'Unknown':17} | {d['device_type']:<24} | ports:{','.join(map(str,d['open_ports']))}")
                except Exception as e:
                    print(f"⚠ Error scanning {ip}: {e}")
                print(f"   [{scanned}/{total}] scanned", end="\r")

        elapsed = (datetime.now() - start_time).total_seconds()
        print(f"\n✅ Scan completed in {elapsed:.2f} seconds")
        print(f"📊 Found {len(devices)} active devices\n")
        return devices

    def print_table(self, devices):
        if not devices:
            print("No devices found."); return
        print("-"*115)
        print(f"{'IP':15} | {'Hostname':20} | {'MAC':17} | {'Vendor':25} | {'Type/OS':20} | {'Open Ports':15} | TTL")
        print("-"*115)
        for d in sorted(devices, key=lambda x: int(ipaddress.IPv4Address(x['ip']))):
            ports = ",".join(map(str, d.get("open_ports", [])))
            print(f"{d['ip']:15} | {d['hostname'][:20]:20} | {(d['mac'] or 'Unknown'):17} | {d['vendor'][:25]:25} | {d['device_type'][:20]:20} | {ports[:15]:15} | {str(d.get('ttl',''))}")
        print("-"*115)

    def export_json(self, devices, path):
        with open(path, "w", encoding="utf-8") as f:
            json.dump(devices, f, indent=2)
        print(f"Saved JSON -> {path}")

    def export_csv(self, devices, path):
        keys = ["ip", "hostname", "mac", "vendor", "device_type", "os", "ttl", "open_ports"]
        with open(path, "w", newline='', encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(keys)
            for d in devices:
                w.writerow([
                    d.get("ip",""),
                    d.get("hostname",""),
                    d.get("mac",""),
                    d.get("vendor",""),
                    d.get("device_type",""),
                    d.get("os",""),
                    d.get("ttl",""),
                    ";".join(map(str, d.get("open_ports", [])))
                ])
        print(f"Saved CSV  -> {path}")

def targets_from_user_input(default_prefix, user_input):
    user_input = user_input.strip()
    if not user_input or user_input.lower() in ("all", "1-254", "1-255"):
        return [f"{default_prefix}.{i}" for i in range(1,255)]
    # CIDR
    if "/" in user_input:
        try:
            net = ipaddress.ip_network(user_input, strict=False)
            return [str(ip) for ip in net.hosts()]
        except Exception:
            pass
    # Range like "1-100" or "192.168.1.20-50"
    m = re.match(r"^(\d{1,3}(?:\.\d{1,3}){0,3})-(\d{1,3})$", user_input)
    if m:
        left = m.group(1)
        right = int(m.group(2))
        parts = left.split('.')
        if len(parts) == 4:
            prefix = '.'.join(parts[:3]); start = int(parts[3]); end = right
            return [f"{prefix}.{i}" for i in range(start, end+1)]
        elif len(parts) == 1:
            start = int(parts[0]); end = right
            return [f"{default_prefix}.{i}" for i in range(start, end+1)]
    # single host number
    if re.match(r"^\d{1,3}$", user_input):
        return [f"{default_prefix}.{int(user_input)}"]
    # single IP
    if re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", user_input):
        return [user_input]
    return []

def main():
    ns = NetScanner()
    print("\n" + "="*60)
    print("    NETWORK DEVICE SCANNER (enhanced)")
    print("="*60 + "\n")
    last = []

    while True:
        print("Menu:")
        print("1. Scan entire local /24")
        print("2. Scan CIDR/range/host (e.g., 192.168.1.0/24 | 1-50 | 192.168.1.10)")
        print("3. Export last results (csv/json)")
        print("4. Set ports to probe")
        print("5. Exit\n")

        choice = input("Enter your choice (1-4): ").strip()
        if choice == "1":
            targets = [f"{ns.prefix}.{i}" for i in range(1,255)]
            last = ns.scan_range(targets)
            ns.print_table(last)
        elif choice == "2":
            user = input(f"Enter targets (default prefix {ns.prefix}): ").strip()
            targets = targets_from_user_input(ns.prefix, user)
            if not targets:
                print("⚠️ Could not parse targets. Try '192.168.1.0/24', '1-50', '192.168.1.10'")
                continue
            last = ns.scan_range(targets)
            ns.print_table(last)
        elif choice == "3":
            if not last:
                print("No results to export. Run a scan first.")
                continue
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            fmt = input("Choose format (csv/json/both): ").strip().lower()
            if fmt in ("csv", "both"): ns.export_csv(last, f"scan_{ts}.csv")
            if fmt in ("json", "both"): ns.export_json(last, f"scan_{ts}.json")
        elif choice == "4":
            print("Bye!"); break
        else:
            print("Invalid choice.")
        print()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nInterrupted by user")
