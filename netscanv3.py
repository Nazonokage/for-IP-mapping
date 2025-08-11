#!/usr/bin/env python3
"""
Enhanced Network Device Scanner with local OUI cache support

Features:
- Uses local data/oui_cache.json for MAC vendor lookups
- Improved OS detection with multiple methods
- Better hostname resolution
- Thread-safe scanning
- Clean output formatting
"""

import os
import sys
import socket
import subprocess
import platform
import re
import json
import ipaddress
import concurrent.futures
from datetime import datetime
from pathlib import Path

class NetworkScanner:
    def __init__(self):
        self.os_type = platform.system().lower()
        self.network_prefix = self._get_network_prefix()
        self.oui_cache = self._load_oui_cache()
        self.scan_timeout = 1.0  # seconds
        self.max_threads = 50

    def _get_network_prefix(self):
        """Determine the local network prefix"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("8.8.8.8", 80))
                local_ip = s.getsockname()[0]
                return '.'.join(local_ip.split('.')[:3])
        except Exception as e:
            print(f"⚠️ Error determining network prefix: {e}", file=sys.stderr)
            return "192.168.1"  # Default fallback

    def _load_oui_cache(self):
        """Parse MAC vendor data from local oui.txt file"""
        cache_path = Path("data/oui.txt")
        oui_dict = {}
        try:
            with open(cache_path, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    # Match lines with (hex) or (base 16)
                    hex_match = re.match(
                        r'^([0-9A-Fa-f]{2}-[0-9A-Fa-f]{2}-[0-9A-Fa-f]{2})\s+\(hex\)\s+(.+)', 
                        line, 
                        re.IGNORECASE
                    )
                    base16_match = re.match(
                        r'^([0-9A-Fa-f]{6})\s+\(base 16\)\s+(.+)', 
                        line, 
                        re.IGNORECASE
                    )
                    
                    if hex_match:
                        oui_part = hex_match.group(1).replace('-', '').upper()
                        vendor = hex_match.group(2).split('\t')[0].strip()
                        oui_dict[oui_part] = vendor
                    elif base16_match:
                        oui_part = base16_match.group(1).upper()
                        vendor = base16_match.group(2).split('\t')[0].strip()
                        oui_dict[oui_part] = vendor
            return oui_dict
        except FileNotFoundError:
            print(f"⚠️ OUI file not found at {cache_path}", file=sys.stderr)
            return {}
        except Exception as e:
            print(f"⚠️ Error parsing OUI file: {e}", file=sys.stderr)
            return {}
        
    def _get_vendor_from_mac(self, mac):
        """Lookup vendor from MAC using local OUI cache"""
        if mac == "Unknown" or not mac:
            return "Unknown"

        # Normalize MAC address (remove all non-alphanumeric chars and uppercase)
        clean_mac = re.sub(r'[^0-9A-Fa-f]', '', mac).upper()
        if len(clean_mac) < 6:
            return "Unknown"

        oui_prefix = clean_mac[:6]  # First 6 chars of cleaned MAC
        return self.oui_cache.get(oui_prefix, "Unknown")

    def _get_mac_address(self, ip):
        """Get MAC address using system ARP table"""
        try:
            if self.os_type == "windows":
                cmd = f"arp -a {ip}"
                output = subprocess.check_output(cmd, shell=True, stderr=subprocess.DEVNULL).decode('cp850')
                match = re.search(r"([0-9A-Fa-f]{2}(?:-[0-9A-Fa-f]{2}){5})", output)
            else:
                cmd = f"arp -n {ip}"
                output = subprocess.check_output(cmd, shell=True, stderr=subprocess.DEVNULL).decode()
                match = re.search(r"([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})", output)

            return match.group(0).upper() if match else "Unknown"
        except Exception:
            return "Unknown"

    def _get_hostname(self, ip):
        """Resolve hostname using multiple methods"""
        try:
            # Try reverse DNS first (with timeout)
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(1.0)
                    hostname = socket.gethostbyaddr(ip)[0]
                    if hostname != ip:
                        return hostname
            except (socket.herror, socket.timeout):
                pass

            # Try NetBIOS for Windows networks
            if self.os_type == "windows":
                try:
                    nb_output = subprocess.check_output(
                        f"nbtstat -A {ip}",
                        shell=True,
                        stderr=subprocess.DEVNULL,
                        timeout=2.0
                    ).decode('cp850')
                    nb_match = re.search(r"<00>\s+UNIQUE\s+([^\s]+)", nb_output)
                    if nb_match:
                        return nb_match.group(1).strip()
                except (subprocess.TimeoutExpired, subprocess.CalledProcessError):
                    pass

            # Try mDNS/Bonjour for Apple devices
            try:
                mdns_output = subprocess.check_output(
                    f"ping -c 1 -W 1 {ip}.local",
                    shell=True,
                    stderr=subprocess.DEVNULL,
                    timeout=2.0
                ).decode()
                if "bytes from" in mdns_output:
                    return f"{ip}.local"
            except (subprocess.TimeoutExpired, subprocess.CalledProcessError):
                pass

            return "Unknown"
        except Exception:
            return "Unknown"
    
    def _ping_host(self, ip):
        """Check if host is responsive"""
        try:
            if self.os_type == "windows":
                cmd = f"ping -n 1 -w 500 {ip}"
            else:
                cmd = f"ping -c 1 -W 1 {ip}"

            subprocess.check_output(
                cmd,
                shell=True,
                stderr=subprocess.DEVNULL
            )
            return True
        except Exception:
            return False

    def _detect_os(self, ip):
        """Detect OS using multiple methods"""
        # Method 1: TTL-based detection
        os_guess = self._detect_os_by_ttl(ip)
        if os_guess != "Unknown":
            return os_guess

        # Method 2: Port-based detection
        os_guess = self._detect_os_by_ports(ip)
        if os_guess != "Unknown":
            return os_guess

        # Method 3: MAC vendor-based detection
        return self._detect_os_by_mac(ip)

    def _detect_os_by_ttl(self, ip):
        """Detect OS based on TTL value"""
        try:
            if self.os_type == "windows":
                cmd = f"ping -n 1 {ip}"
                output = subprocess.check_output(cmd, shell=True, stderr=subprocess.DEVNULL).decode()
                ttl_match = re.search(r"TTL=(\d+)", output)
            else:
                cmd = f"ping -c 1 {ip}"
                output = subprocess.check_output(cmd, shell=True, stderr=subprocess.DEVNULL).decode()
                ttl_match = re.search(r"ttl=(\d+)", output.lower())

            if ttl_match:
                ttl = int(ttl_match.group(1))
                if ttl <= 64:
                    return "Linux/Unix"
                elif ttl <= 128:
                    return "Windows"
                elif ttl <= 255:
                    return "Network Device"
        except Exception:
            pass
        return "Unknown"

    def _detect_os_by_ports(self, ip):
        """Detect OS based on open ports"""
        ports_to_check = {
            22: "Linux/Unix",      # SSH
            445: "Windows",        # SMB
            3389: "Windows",       # RDP
            62078: "iOS",          # iPhone USB
            3283: "Apple",         # Net Assistant
            5353: "Apple",        # Bonjour
            3689: "Apple",         # DAAP (iTunes)
            548: "Apple",          # AFP
            23: "Network Device",  # Telnet
            161: "Network Device", # SNMP
        }

        for port, os_type in ports_to_check.items():
            if self._is_port_open(ip, port):
                return os_type
        return "Unknown"

    def _is_port_open(self, ip, port):
        """Check if a TCP port is open"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(self.scan_timeout)
                return s.connect_ex((ip, port)) == 0
        except Exception:
            return False

    def _detect_os_by_mac(self, ip):
        """Detect OS based on MAC vendor"""
        mac = self._get_mac_address(ip)
        vendor = self._get_vendor_from_mac(mac)

        if "apple" in vendor.lower():
            return "macOS/iOS"
        elif "microsoft" in vendor.lower():
            return "Windows"
        elif "google" in vendor.lower():
            return "Android/ChromeOS"
        elif any(x in vendor.lower() for x in ["cisco", "d-link", "netgear", "tp-link"]):
            return "Network Device"
        return "Unknown"

    def scan_network(self, start=1, end=254):
        """Scan the network for active devices"""
        devices = []
        ip_range = [f"{self.network_prefix}.{i}" for i in range(start, end + 1)]

        print(f"🔍 Scanning {self.network_prefix}.{start}-{end} ({(end-start)+1} hosts)")
        print("This may take a few minutes...\n")

        start_time = datetime.now()

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            future_to_ip = {executor.submit(self._scan_host, ip): ip for ip in ip_range}
            
            for future in concurrent.futures.as_completed(future_to_ip):
                ip = future_to_ip[future]
                try:
                    device = future.result()
                    if device:
                        devices.append(device)
                        self._print_device_found(device)
                except Exception as e:
                    print(f"⚠️ Error scanning {ip}: {e}", file=sys.stderr)

        scan_time = (datetime.now() - start_time).total_seconds()
        print(f"\n✅ Scan completed in {scan_time:.2f} seconds")
        print(f"📊 Found {len(devices)} active devices")
        return devices

    def _scan_host(self, ip):
        """Scan a single host and return device info"""
        if not self._ping_host(ip):
            return None

        mac = self._get_mac_address(ip)
        hostname = self._get_hostname(ip)
        os_type = self._detect_os(ip)
        vendor = self._get_vendor_from_mac(mac)

        return {
            "ip": ip,
            "mac": mac,
            "hostname": hostname,
            "vendor": vendor,
            "os": os_type
        }

    def _print_device_found(self, device):
        """Print device discovery notification"""
        hostname = device['hostname'] if device['hostname'] != "Unknown" else "No hostname"
        print(f"• {device['ip']:15} | {hostname:20} | {device['mac']:17} | {device['os']}")

    def print_device_table(self, devices):
        """Print formatted device table"""
        if not devices:
            print("No devices found")
            return

        # Calculate column widths
        ip_width = max(len(d["ip"]) for d in devices) + 2
        mac_width = max(len(d["mac"]) for d in devices) + 2
        hostname_width = max(len(d["hostname"]) for d in devices) + 2
        vendor_width = max(len(d["vendor"]) for d in devices) + 2
        os_width = max(len(d["os"]) for d in devices) + 2

        # Header
        header = (f"\n{'IP':<{ip_width}} {'MAC':<{mac_width}} "
                 f"{'Hostname':<{hostname_width}} {'Vendor':<{vendor_width}} {'OS':<{os_width}}")
        separator = "-" * len(header.expandtabs())

        print("\n" + separator)
        print(header)
        print(separator)

        # Device rows
        for device in sorted(devices, key=lambda d: self._ip_to_int(d["ip"])):
            print(f"{device['ip']:<{ip_width}} "
                  f"{device['mac']:<{mac_width}} "
                  f"{device['hostname']:<{hostname_width}} "
                  f"{device['vendor']:<{vendor_width}} "
                  f"{device['os']:<{os_width}}")

        print(separator + "\n")

    def _ip_to_int(self, ip):
        """Convert IP address to integer for sorting"""
        try:
            return int(ipaddress.IPv4Address(ip))
        except ValueError:
            return 0

    def scan_specific_ips(self, ips):
        """Scan specific IP addresses"""
        devices = []
        
        print(f"🔍 Scanning {len(ips)} specified hosts")
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(self.max_threads, len(ips))) as executor:
            future_to_ip = {executor.submit(self._scan_host, ip): ip for ip in ips}
            
            for future in concurrent.futures.as_completed(future_to_ip):
                ip = future_to_ip[future]
                try:
                    device = future.result()
                    if device:
                        devices.append(device)
                        self._print_device_found(device)
                except Exception as e:
                    print(f"⚠️ Error scanning {ip}: {e}", file=sys.stderr)

        print(f"\n✅ Scan completed - found {len(devices)} active devices")
        return devices

def main():
    """Main CLI interface"""
    scanner = NetworkScanner()

    print("\n" + "="*50)
    print("    NETWORK DEVICE SCANNER WITH OS DETECTION")
    print("="*50 + "\n")

    while True:
        print("Menu:")
        print("1. Scan entire local network")
        print("2. Scan specific IP range")
        print("3. Scan specific IP addresses")
        print("4. Exit\n")

        choice = input("Enter your choice (1-4): ").strip()

        if choice == '1':
            devices = scanner.scan_network()
            scanner.print_device_table(devices)
        elif choice == '2':
            start_ip = input("Enter start IP: ").strip()
            end_ip = input("Enter end IP: ").strip()
            try:
                start = int(ipaddress.IPv4Address(start_ip))
                end = int(ipaddress.IPv4Address(end_ip))
                ips = [str(ipaddress.IPv4Address(ip)) for ip in range(start, end + 1)]
                devices = scanner.scan_specific_ips(ips)
                scanner.print_device_table(devices)
            except ValueError as e:
                print(f"⚠️ Invalid IP address: {e}", file=sys.stderr)
        elif choice == '3':
            ips = input("Enter IP addresses (comma separated): ").strip().split(',')
            ips = [ip.strip() for ip in ips if ip.strip()]
            devices = scanner.scan_specific_ips(ips)
            scanner.print_device_table(devices)
        elif choice == '4':
            print("Exiting...")
            break
        else:
            print("⚠️ Invalid choice. Please try again.", file=sys.stderr)

        print()  # Add blank line between operations

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nScan interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"⚠️ Fatal error: {e}", file=sys.stderr)
        sys.exit(1)