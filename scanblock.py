#!/usr/bin/env python3
"""
Enhanced Network Device Scanner with IP/MAC Blocking
"""

import socket
import subprocess
import platform
import re
import concurrent.futures
import json
import os
from datetime import datetime
from ipaddress import IPv4Address, IPv4Network

class NetworkBlocker:
    def __init__(self):
        self.os_type = platform.system().lower()
        self.blocked_ips_file = "blocked_ips.json"
        self.blocked_macs_file = "blocked_macs.json"
        self.blocked_ips = self._load_blocked_list(self.blocked_ips_file)
        self.blocked_macs = self._load_blocked_list(self.blocked_macs_file)

    def _load_blocked_list(self, filename):
        """Load blocked items from JSON file"""
        try:
            if os.path.exists(filename):
                with open(filename, 'r') as f:
                    return set(json.load(f))
        except Exception as e:
            print(f"⚠️ Error loading {filename}: {e}")
        return set()

    def _save_blocked_list(self, blocked_set, filename):
        """Save blocked items to JSON file"""
        try:
            with open(filename, 'w') as f:
                json.dump(list(blocked_set), f, indent=2)
            return True
        except Exception as e:
            print(f"⚠️ Error saving {filename}: {e}")
            return False

    def add_blocked_ip(self, ip):
        """Add IP to blocked list"""
        try:
            # Validate IP address
            IPv4Address(ip)
            self.blocked_ips.add(ip)
            self._save_blocked_list(self.blocked_ips, self.blocked_ips_file)
            print(f"✅ IP {ip} added to blocked list")
            return True
        except Exception as e:
            print(f"⚠️ Invalid IP address: {e}")
            return False

    def add_blocked_mac(self, mac):
        """Add MAC to blocked list"""
        # Normalize MAC address format
        mac = mac.upper().replace('-', ':')
        if re.match(r'^([0-9A-F]{2}:){5}[0-9A-F]{2}$', mac):
            self.blocked_macs.add(mac)
            self._save_blocked_list(self.blocked_macs, self.blocked_macs_file)
            print(f"✅ MAC {mac} added to blocked list")
            return True
        else:
            print(f"⚠️ Invalid MAC address format: {mac}")
            return False

    def remove_blocked_ip(self, ip):
        """Remove IP from blocked list"""
        if ip in self.blocked_ips:
            self.blocked_ips.remove(ip)
            self._save_blocked_list(self.blocked_ips, self.blocked_ips_file)
            print(f"✅ IP {ip} removed from blocked list")
            return True
        else:
            print(f"⚠️ IP {ip} not found in blocked list")
            return False

    def remove_blocked_mac(self, mac):
        """Remove MAC from blocked list"""
        mac = mac.upper().replace('-', ':')
        if mac in self.blocked_macs:
            self.blocked_macs.remove(mac)
            self._save_blocked_list(self.blocked_macs, self.blocked_macs_file)
            print(f"✅ MAC {mac} removed from blocked list")
            return True
        else:
            print(f"⚠️ MAC {mac} not found in blocked list")
            return False

    def is_ip_blocked(self, ip):
        """Check if IP is blocked"""
        return ip in self.blocked_ips

    def is_mac_blocked(self, mac):
        """Check if MAC is blocked"""
        mac = mac.upper().replace('-', ':')
        return mac in self.blocked_macs

    def block_ip_system_level(self, ip):
        """Block IP at system level using firewall"""
        try:
            if self.os_type == "windows":
                # Windows Firewall command
                cmd = f'netsh advfirewall firewall add rule name="Block_{ip}" dir=in action=block remoteip={ip}'
                subprocess.run(cmd, shell=True, check=True)
                cmd = f'netsh advfirewall firewall add rule name="Block_{ip}_out" dir=out action=block remoteip={ip}'
                subprocess.run(cmd, shell=True, check=True)
            elif self.os_type == "linux":
                # iptables command (requires sudo)
                cmd = f'sudo iptables -A INPUT -s {ip} -j DROP'
                subprocess.run(cmd, shell=True, check=True)
                cmd = f'sudo iptables -A OUTPUT -d {ip} -j DROP'
                subprocess.run(cmd, shell=True, check=True)
            elif self.os_type == "darwin":  # macOS
                # pfctl command (requires sudo)
                cmd = f'echo "block in from {ip} to any" | sudo pfctl -f -'
                subprocess.run(cmd, shell=True, check=True)
            
            print(f"✅ IP {ip} blocked at system level")
            return True
        except subprocess.CalledProcessError as e:
            print(f"⚠️ Failed to block IP {ip} at system level: {e}")
            return False
        except Exception as e:
            print(f"⚠️ Error blocking IP {ip}: {e}")
            return False

    def unblock_ip_system_level(self, ip):
        """Unblock IP at system level"""
        try:
            if self.os_type == "windows":
                cmd = f'netsh advfirewall firewall delete rule name="Block_{ip}"'
                subprocess.run(cmd, shell=True, check=True)
                cmd = f'netsh advfirewall firewall delete rule name="Block_{ip}_out"'
                subprocess.run(cmd, shell=True, check=True)
            elif self.os_type == "linux":
                cmd = f'sudo iptables -D INPUT -s {ip} -j DROP'
                subprocess.run(cmd, shell=True, check=True)
                cmd = f'sudo iptables -D OUTPUT -d {ip} -j DROP'
                subprocess.run(cmd, shell=True, check=True)
            
            print(f"✅ IP {ip} unblocked at system level")
            return True
        except subprocess.CalledProcessError as e:
            print(f"⚠️ Failed to unblock IP {ip}: {e}")
            return False

    def block_mac_system_level(self, mac):
        """Block MAC address (WiFi networks mainly)"""
        try:
            mac = mac.upper().replace('-', ':')
            if self.os_type == "linux":
                # Using iptables with MAC module
                cmd = f'sudo iptables -A INPUT -m mac --mac-source {mac} -j DROP'
                subprocess.run(cmd, shell=True, check=True)
                cmd = f'sudo iptables -A FORWARD -m mac --mac-source {mac} -j DROP'
                subprocess.run(cmd, shell=True, check=True)
                print(f"✅ MAC {mac} blocked at system level")
                return True
            else:
                print(f"⚠️ MAC blocking at system level not implemented for {self.os_type}")
                return False
        except subprocess.CalledProcessError as e:
            print(f"⚠️ Failed to block MAC {mac}: {e}")
            return False

class NetworkScanner:
    def __init__(self):
        self.os_type = platform.system().lower()
        self.network_prefix = self._get_network_prefix()
        self.scan_timeout = 1.0
        self.max_threads = 50
        self.blocker = NetworkBlocker()

    def _get_network_prefix(self):
        """Determine the local network prefix"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("8.8.8.8", 80))
                local_ip = s.getsockname()[0]
                return '.'.join(local_ip.split('.')[:3])
        except Exception:
            return "192.168.1"

    def _ping_host(self, ip):
        """Check if host is responsive (skip if blocked)"""
        if self.blocker.is_ip_blocked(ip):
            return False
            
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
        
        # Check if MAC is blocked
        if mac != "Unknown" and self.blocker.is_mac_blocked(mac):
            return None

        hostname = self._get_hostname(ip)
        os_type = self._detect_os(ip)

        return {
            "ip": ip,
            "mac": mac,
            "hostname": hostname,
            "os": os_type,
            "blocked": False
        }

    def scan_network(self, start=1, end=254, include_blocked=False):
        """Scan the network for active devices"""
        devices = []
        ip_range = [f"{self.network_prefix}.{i}" for i in range(start, end + 1)]

        print(f"🔍 Scanning {self.network_prefix}.{start}-{end} ({(end-start)+1} hosts)")
        if not include_blocked:
            print("(Blocked IPs/MACs will be skipped)")
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
                        status = "🚫" if self.blocker.is_ip_blocked(ip) or self.blocker.is_mac_blocked(device['mac']) else "✅"
                        print(f"{status} {device['ip']:15} | {device['hostname']:20} | {device['mac']:17} | {device['os']}")
                    elif include_blocked and self.blocker.is_ip_blocked(ip):
                        devices.append({
                            "ip": ip,
                            "mac": "Blocked",
                            "hostname": "Blocked",
                            "os": "Blocked",
                            "blocked": True
                        })
                        print(f"🚫 {ip:15} | {'Blocked':20} | {'Blocked':17} | Blocked")
                except Exception as e:
                    print(f"⚠️ Error scanning {ip}: {e}")

        scan_time = (datetime.now() - start_time).total_seconds()
        print(f"\n✅ Scan completed in {scan_time:.2f} seconds")
        print(f"📊 Found {len(devices)} devices")
        
        return devices

    def print_device_table(self, devices):
        """Print formatted device table"""
        if not devices:
            print("No devices found")
            return

        print("\n" + "-" * 85)
        print(f"{'Status':6} | {'IP':15} | {'Hostname':20} | {'MAC':17} | {'OS'}")
        print("-" * 85)

        for device in sorted(devices, key=lambda d: self._ip_to_int(d["ip"])):
            status = "🚫" if device.get('blocked') or self.blocker.is_ip_blocked(device['ip']) or self.blocker.is_mac_blocked(device['mac']) else "✅"
            print(f"{status:6} | {device['ip']:15} | {device['hostname']:20} | {device['mac']:17} | {device['os']}")

        print("-" * 85 + "\n")

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

    print("\n" + "="*60)
    print("    NETWORK SCANNER WITH IP/MAC BLOCKING")
    print("="*60 + "\n")

    while True:
        print("Menu:")
        print("1. Scan entire local network")
        print("2. Scan specific IP range")
        print("3. Block/Unblock IP address")
        print("4. Block/Unblock MAC address")
        print("5. View blocked IPs and MACs")
        print("6. System-level blocking (requires admin/sudo)")
        print("7. Exit\n")

        choice = input("Enter your choice (1-7): ").strip()

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
            print("\nIP Blocking Menu:")
            print("1. Block IP")
            print("2. Unblock IP")
            ip_choice = input("Choose (1-2): ").strip()
            
            if ip_choice in ['1', '2']:
                ip = input("Enter IP address: ").strip()
                if ip_choice == '1':
                    scanner.blocker.add_blocked_ip(ip)
                else:
                    scanner.blocker.remove_blocked_ip(ip)
                    
        elif choice == '4':
            print("\nMAC Blocking Menu:")
            print("1. Block MAC")
            print("2. Unblock MAC")
            mac_choice = input("Choose (1-2): ").strip()
            
            if mac_choice in ['1', '2']:
                mac = input("Enter MAC address: ").strip()
                if mac_choice == '1':
                    scanner.blocker.add_blocked_mac(mac)
                else:
                    scanner.blocker.remove_blocked_mac(mac)
                    
        elif choice == '5':
            print(f"\n📋 Blocked IPs ({len(scanner.blocker.blocked_ips)}):")
            for ip in sorted(scanner.blocker.blocked_ips):
                print(f"  🚫 {ip}")
                
            print(f"\n📋 Blocked MACs ({len(scanner.blocker.blocked_macs)}):")
            for mac in sorted(scanner.blocker.blocked_macs):
                print(f"  🚫 {mac}")
                
        elif choice == '6':
            print("\nSystem-Level Blocking (requires admin privileges):")
            print("1. Block IP at firewall level")
            print("2. Unblock IP at firewall level")
            print("3. Block MAC at system level")
            sys_choice = input("Choose (1-3): ").strip()
            
            if sys_choice == '1':
                ip = input("Enter IP to block: ").strip()
                scanner.blocker.block_ip_system_level(ip)
            elif sys_choice == '2':
                ip = input("Enter IP to unblock: ").strip()
                scanner.blocker.unblock_ip_system_level(ip)
            elif sys_choice == '3':
                mac = input("Enter MAC to block: ").strip()
                scanner.blocker.block_mac_system_level(mac)
                
        elif choice == '7':
            print("Exiting...")
            break
        else:
            print("⚠️ Invalid choice. Please try again.")

        print()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nScan interrupted by user")
    except Exception as e:
        print(f"⚠️ Fatal error: {e}")