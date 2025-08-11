#!/usr/bin/env python3
"""
Simplified Network Device Scanner
"""

import socket
import subprocess
import platform
import re
import concurrent.futures
from datetime import datetime

class NetworkScanner:
    def __init__(self):
        self.os_type = platform.system().lower()
        self.network_prefix = self._get_network_prefix()
        self.scan_timeout = 1.0  # seconds
        self.max_threads = 50

    def _get_network_prefix(self):
        """Determine the local network prefix"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("8.8.8.8", 80))
                local_ip = s.getsockname()[0]
                return '.'.join(local_ip.split('.')[:3])
        except Exception:
            return "192.168.1"  # Default fallback

    def _ping_host(self, ip):
        """Check if host is responsive"""
        try:
            if self.os_type == "windows":
                cmd = f"ping -n 1 -w 500 {ip}"
            else:
                cmd = f"ping -c 1 -W 1 {ip}"

            subprocess.check_output(cmd, shell=True, stderr=subprocess.DEVNULL)
            return True
        except Exception:
            return False

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
        """Resolve hostname"""
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            return hostname if hostname != ip else "Unknown"
        except Exception:
            return "Unknown"

    def _detect_os(self, ip):
        """Simple OS detection based on TTL"""
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
                else:
                    return "Network Device"
        except Exception:
            pass
        return "Unknown"

    def _scan_host(self, ip):
        """Scan a single host and return device info"""
        if not self._ping_host(ip):
            return None

        mac = self._get_mac_address(ip)
        hostname = self._get_hostname(ip)
        os_type = self._detect_os(ip)

        return {
            "ip": ip,
            "mac": mac,
            "hostname": hostname,
            "os": os_type
        }

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
                        print(f"• {device['ip']:15} | {device['hostname']:20} | {device['mac']:17} | {device['os']}")
                except Exception as e:
                    print(f"⚠️ Error scanning {ip}: {e}")

        scan_time = (datetime.now() - start_time).total_seconds()
        print(f"\n✅ Scan completed in {scan_time:.2f} seconds")
        print(f"📊 Found {len(devices)} active devices")
        
        return devices

    def print_device_table(self, devices):
        """Print formatted device table"""
        if not devices:
            print("No devices found")
            return

        print("\n" + "-" * 80)
        print(f"{'IP':15} | {'Hostname':20} | {'MAC':17} | {'OS'}")
        print("-" * 80)

        for device in sorted(devices, key=lambda d: self._ip_to_int(d["ip"])):
            print(f"{device['ip']:15} | {device['hostname']:20} | {device['mac']:17} | {device['os']}")

        print("-" * 80 + "\n")

    def _ip_to_int(self, ip):
        """Convert IP address to integer for sorting"""
        try:
            parts = ip.split('.')
            return sum(int(part) << (8 * (3 - i)) for i, part in enumerate(parts))
        except Exception:
            return 0

def main():
    """Main CLI interface"""
    scanner = NetworkScanner()

    print("\n" + "="*50)
    print("    NETWORK DEVICE SCANNER")
    print("="*50 + "\n")

    while True:
        print("Menu:")
        print("1. Scan entire local network")
        print("2. Scan specific IP range")
        print("3. Exit\n")

        choice = input("Enter your choice (1-3): ").strip()

        if choice == '1':
            devices = scanner.scan_network()
            scanner.print_device_table(devices)
        elif choice == '2':
            try:
                start = int(input("Enter start host number (1-254): ").strip())
                end = int(input("Enter end host number (1-254): ").strip())
                if 1 <= start <= 254 and 1 <= end <= 254:
                    devices = scanner.scan_network(start, end)
                    scanner.print_device_table(devices)
                else:
                    print("⚠️ Invalid range. Values must be between 1 and 254.")
            except ValueError:
                print("⚠️ Invalid input. Please enter numbers only.")
        elif choice == '3':
            print("Exiting...")
            break
        else:
            print("⚠️ Invalid choice. Please try again.")

        print()  # Add blank line between operations

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nScan interrupted by user")
    except Exception as e:
        print(f"⚠️ Fatal error: {e}")