#!/usr/bin/env python3
"""
Network Device Scanner - Lists all connected devices on a local network with OS detection

This script scans your local network to identify connected devices and attempts to
determine their operating systems using TTL values, open ports, and vendor information.

Note: For more accurate results, run with administrator/root privileges.
"""

import socket
import subprocess
import platform
import re
import concurrent.futures
import ipaddress
from datetime import datetime

class NetworkScanner:
    def __init__(self):
        self.network_prefix = self._get_network_prefix()
        self.os_type = platform.system().lower()
        
    def _get_network_prefix(self):
        """Get the local network prefix based on local IP address"""
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            # Connect to a public DNS server to determine local IP
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            # Get first three octets of IP
            prefix = '.'.join(local_ip.split('.')[:3])
            return prefix
        except Exception as e:
            print(f"Error determining network prefix: {e}")
            return "192.168.1"  # Default fallback
        finally:
            s.close()
    
    def _get_mac_address(self, ip):
        """Get MAC address for a given IP using ARP table"""
        try:
            if self.os_type == "windows":
                # Windows ARP command
                result = subprocess.check_output(f"arp -a {ip}", shell=True).decode('utf-8')
                mac_match = re.search(r'([0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2})', result)
                return mac_match.group(0) if mac_match else "Unknown"
            else:
                # Linux/Mac ARP command
                result = subprocess.check_output(f"arp -n {ip}", shell=True).decode('utf-8')
                mac_match = re.search(r'([0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2})', result)
                return mac_match.group(0) if mac_match else "Unknown"
        except Exception:
            return "Unknown"
    
    def _get_hostname(self, ip):
        """Try to resolve hostname using multiple methods"""
        try:
            # Method 1: Reverse DNS
            hostname = socket.gethostbyaddr(ip)[0]
            if hostname: return hostname
        except:
            pass
        
        # Method 2: Check ARP table for Windows
        if self.os_type == "windows":
            try:
                arp_output = subprocess.check_output(f"arp -a {ip}", shell=True).decode('utf-8')
                host_match = re.search(r"(\S+)\s+{}".format(ip.replace('.', '\\.')), arp_output)
                if host_match and host_match.group(1) != "?":
                    return host_match.group(1)
            except:
                pass
        
        return "Unknown"
    
    def _ping_host(self, ip):
        """Ping a host to check if it's alive"""
        try:
            if self.os_type == "windows":
                ping_param = "-n 1 -w 500"  # Windows ping parameters
            else:
                ping_param = "-c 1 -W 1"    # Linux/Mac ping parameters
            
            subprocess.check_output(f"ping {ping_param} {ip}", shell=True, stderr=subprocess.DEVNULL)
            return True
        except subprocess.CalledProcessError:
            return False
    
    def scan_network(self, start=1, end=254, max_threads=50):
        """
        Scan the network for active hosts
        
        Args:
            start: First host in range to scan (default: 1)
            end: Last host in range to scan (default: 254)
            max_threads: Maximum number of concurrent threads (default: 50)
        
        Returns:
            List of dictionaries with device information
        """
        devices = []
        
        print(f"Starting network scan on {self.network_prefix}.0/24")
        print(f"Scanning range: {self.network_prefix}.{start} to {self.network_prefix}.{end}")
        print("Please wait, this may take some time...")
        print("The OS detection feature uses port scanning which may trigger security alerts.")
        
        start_time = datetime.now()
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_threads) as executor:
            # Create a list of futures for each IP address
            ip_range = [f"{self.network_prefix}.{i}" for i in range(start, end + 1)]
            future_to_ip = {executor.submit(self._scan_host, ip): ip for ip in ip_range}
            
            # Process results as they complete
            for future in concurrent.futures.as_completed(future_to_ip):
                ip = future_to_ip[future]
                try:
                    device_info = future.result()
                    if device_info:
                        devices.append(device_info)
                        print(f"Found device: {ip} - {device_info['hostname']} ({device_info['mac']})")
                except Exception as e:
                    print(f"Error scanning {ip}: {e}")
        
        end_time = datetime.now()
        scan_time = (end_time - start_time).total_seconds()
        
        print(f"\nScan completed in {scan_time:.2f} seconds")
        print(f"Found {len(devices)} devices on the network")
        
        return devices
    
    def _scan_host(self, ip):
        """Scan a single host and return device information if available"""
        if self._ping_host(ip):
            mac = self._get_mac_address(ip)
            hostname = self._get_hostname(ip)
            os_info = self._detect_os(ip)
            
            return {
                "ip": ip,
                "mac": mac,
                "hostname": hostname,
                "vendor": self._get_vendor_from_mac(mac),
                "os": os_info
            }
        return None
        
    def _detect_os(self, ip):
        """Detect the operating system of a remote host using TTL and port scanning"""
        os_guess = "Unknown"
        
        # Method 1: TTL-based OS detection
        try:
            if self.os_type == "windows":
                # Windows ping output
                ping_output = subprocess.check_output(f"ping -n 1 {ip}", shell=True).decode('utf-8')
                ttl_match = re.search(r"TTL=(\d+)", ping_output)
            else:
                # Linux/Mac ping output
                ping_output = subprocess.check_output(f"ping -c 1 {ip}", shell=True).decode('utf-8')
                ttl_match = re.search(r"ttl=(\d+)", ping_output)
            
            if ttl_match:
                ttl = int(ttl_match.group(1))
                
                # TTL values can help identify OS (not 100% accurate)
                if ttl <= 64:
                    os_guess = "Linux/Unix"
                elif ttl <= 128:
                    os_guess = "Windows"
                elif ttl <= 255:
                    os_guess = "Cisco/Network Device"
            
            # Method 2: Try to improve detection with port scanning
            # Check for common open ports
            common_ports = {
                22: "SSH (Linux/Unix likely)",
                23: "Telnet (Network Device likely)",
                80: "HTTP",
                443: "HTTPS",
                445: "SMB (Windows likely)",
                3389: "RDP (Windows likely)",
                5900: "VNC (Cross-platform)"
            }
            
            # Try checking a few key ports to improve OS detection
            for port, service in common_ports.items():
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(0.5)  # Short timeout
                    result = sock.connect_ex((ip, port))
                    sock.close()
                    
                    if result == 0:  # Port is open
                        if port == 22 and os_guess == "Unknown":
                            os_guess = "Linux/Unix"
                        elif port == 445 and os_guess == "Unknown":
                            os_guess = "Windows"
                        elif port == 3389 and os_guess == "Unknown":
                            os_guess = "Windows"
                        elif port == 23 and os_guess == "Unknown":
                            os_guess = "Network Device"
                            
                except:
                    pass
            
            # Method 3: For local network devices, check MAC vendor for additional clues
            if os_guess == "Unknown":
                mac = self._get_mac_address(ip)
                vendor = self._get_vendor_from_mac(mac)
                
                if vendor in ["Apple", "Apple Inc."]:
                    os_guess = "macOS/iOS"
                elif vendor in ["Microsoft"]:
                    os_guess = "Windows"
                elif vendor in ["Google"]:
                    os_guess = "Android/ChromeOS"
                elif vendor in ["Cisco", "Cisco-Linksys", "Netgear", "D-Link", "TP-Link"]:
                    os_guess = "Network Device"
                    
        except Exception:
            pass
            
        return os_guess
    
    def _get_vendor_from_mac(self, mac):
        """
        Get vendor information from MAC address OUI (first 6 characters)
        This is a simplified version - for a real-world application, 
        you would use a MAC address database or API
        """
        if mac == "Unknown":
            return "Unknown"
        
        # This is a very simplified MAC vendor mapping
        # In a real application, you'd use a more comprehensive database
        mac_prefixes = {
            "00:0C:29": "VMware",
            "00:50:56": "VMware",
            "00:1A:11": "Google",
            "00:03:93": "Apple",
            "00:05:02": "Apple",
            "00:0A:27": "Apple",
            "00:0A:95": "Apple",
            "00:11:24": "Apple",
            "00:14:51": "Apple",
            "00:16:CB": "Apple",
            "00:17:F2": "Apple",
            "00:19:E3": "Apple",
            "00:1B:63": "Apple",
            "00:1D:4F": "Apple",
            "00:1E:52": "Apple",
            "00:1E:C2": "Apple",
            "00:1F:5B": "Apple",
            "00:1F:F3": "Apple",
            "00:21:E9": "Apple",
            "00:22:41": "Apple",
            "00:23:12": "Apple",
            "00:23:32": "Apple",
            "00:23:6C": "Apple",
            "00:23:DF": "Apple",
            "00:24:36": "Apple",
            "00:25:00": "Apple",
            "00:25:BC": "Apple",
            "00:26:08": "Apple",
            "00:26:BB": "Apple",
            "00:26:B0": "Apple",
            "00:60:08": "3Com",
            "00:01:42": "Cisco",
            "00:01:43": "Cisco",
            "00:01:63": "Cisco",
            "00:01:64": "Cisco",
            "00:01:96": "Cisco",
            "00:01:97": "Cisco",
            "00:01:C7": "Cisco",
            "00:01:C9": "Cisco",
            "00:0E:08": "Cisco-Linksys",
            "00:0F:66": "Cisco-Linksys",
            "00:13:10": "Cisco-Linksys",
            "00:18:F8": "Cisco-Linksys",
            "00:21:29": "Cisco-Linksys",
            "00:22:6B": "Cisco-Linksys",
            "00:25:9C": "Cisco-Linksys",
            "58:6D:8F": "Cisco-Linksys",
            "00:90:4C": "Epson",
            "00:0F:61": "HP",
            "00:14:38": "HP",
            "00:18:FE": "HP",
            "00:1C:C4": "HP",
            "00:21:5A": "HP",
            "00:23:7D": "HP",
            "00:08:74": "Dell",
            "00:0B:DB": "Dell",
            "00:12:3F": "Dell",
            "00:14:22": "Dell",
            "00:18:8B": "Dell",
            "00:1A:A0": "Dell",
            "00:1D:09": "Dell",
            "00:21:70": "Dell",
            "00:24:E8": "Dell",
            "00:26:B9": "Dell",
            "00:1D:D8": "Microsoft",
            "00:12:5A": "Microsoft",
            "00:50:F2": "Microsoft",
            "00:1F:6A": "PacketFlux",
            "00:90:96": "Askey",
            "00:0D:88": "D-Link",
            "00:05:5D": "D-Link",
            "00:0D:88": "D-Link",
            "00:17:9A": "D-Link",
            "00:1C:F0": "D-Link",
            "00:21:91": "D-Link",
            "00:22:B0": "D-Link",
            "00:24:01": "D-Link",
            "00:26:5A": "D-Link",
            "1C:BD:B9": "D-Link",
            "90:94:E4": "D-Link",
            "00:18:4D": "Netgear",
            "00:1F:33": "Netgear",
            "00:26:F2": "Netgear",
            "20:E5:2A": "Netgear",
            "C0:3F:0E": "Netgear",
            "00:14:78": "TP-Link",
            "00:19:E0": "TP-Link",
            "00:21:27": "TP-Link",
            "00:23:CD": "TP-Link",
            "00:25:86": "TP-Link",
            "08:00:27": "Oracle VirtualBox",
            "52:54:00": "QEMU/KVM",
            "BC:EE:7B": "ASUSTek",
            "00:13:D4": "ASUSTek",
            "00:1B:FC": "ASUSTek",
            "00:1E:8C": "ASUSTek",
            "00:22:15": "ASUSTek",
            "00:23:54": "ASUSTek",
            "00:26:18": "ASUSTek",
            "00:E0:18": "ASUSTek",
            "00:0C:41": "Linksys",
            "00:0F:66": "Linksys",
            "00:12:17": "Linksys",
            "00:16:B6": "Linksys",
            "00:18:39": "Linksys",
            "00:1A:70": "Linksys",
            "00:1C:10": "Linksys",
            "00:1D:7E": "Linksys",
            "00:1E:E5": "Linksys",
            "00:21:29": "Linksys",
            "00:22:6B": "Linksys",
            "00:23:69": "Linksys",
            "00:25:9C": "Linksys",
        }
        
        # Convert MAC to uppercase for matching
        mac_upper = mac.upper()
        
        # Check if the MAC prefix matches any in our database
        for prefix, vendor in mac_prefixes.items():
            if mac_upper.startswith(prefix.upper()):
                return vendor
        
        return "Unknown"
    
    def print_device_table(self, devices):
        """Print device information in a formatted table"""
        if not devices:
            print("No devices found on the network.")
            return
        
        # Calculate column widths
        ip_width = max(len("IP Address"), max(len(d["ip"]) for d in devices))
        mac_width = max(len("MAC Address"), max(len(d["mac"]) for d in devices))
        hostname_width = max(len("Hostname"), max(len(d["hostname"]) for d in devices))
        vendor_width = max(len("Vendor"), max(len(d["vendor"]) for d in devices))
        os_width = max(len("OS"), max(len(d["os"]) for d in devices))
        
        # Print table header
        total_width = ip_width + mac_width + hostname_width + vendor_width + os_width + 16
        print("\n" + "=" * total_width)
        print(f"{'IP Address':<{ip_width}} | {'MAC Address':<{mac_width}} | {'Hostname':<{hostname_width}} | {'Vendor':<{vendor_width}} | {'OS':<{os_width}}")
        print("-" * total_width)
        
        # Print each device
        for device in sorted(devices, key=lambda d: self._ip_to_int(d["ip"])):
            print(f"{device['ip']:<{ip_width}} | {device['mac']:<{mac_width}} | {device['hostname']:<{hostname_width}} | {device['vendor']:<{vendor_width}} | {device['os']:<{os_width}}")
        
        print("=" * total_width)
    
    def _ip_to_int(self, ip):
        """Convert IP address to integer for sorting"""
        try:
            return int(ipaddress.IPv4Address(ip))
        except Exception:
            return 0
    
    def scan_specific_ip_range(self, start_ip, end_ip):
        """Scan a specific IP range"""
        try:
            start = ipaddress.IPv4Address(start_ip)
            end = ipaddress.IPv4Address(end_ip)
            
            # Check if IPs are in the same subnet
            if str(start).split('.')[:3] != str(end).split('.')[:3]:
                print("Warning: Start and end IPs are not in the same subnet.")
                print("This may result in incomplete scanning.")
            
            devices = []
            
            print(f"Starting scan from {start} to {end}")
            
            # Convert to integers for iteration
            start_int = int(start)
            end_int = int(end)
            
            # Determine the number of IPs to scan
            num_ips = end_int - start_int + 1
            
            # Adjust thread count based on range size
            max_threads = min(50, num_ips)
            
            with concurrent.futures.ThreadPoolExecutor(max_workers=max_threads) as executor:
                # Create a list of futures for each IP address
                ip_futures = []
                for ip_int in range(start_int, end_int + 1):
                    ip = str(ipaddress.IPv4Address(ip_int))
                    ip_futures.append(executor.submit(self._scan_host, ip))
                
                # Process results as they complete
                for future in concurrent.futures.as_completed(ip_futures):
                    try:
                        device_info = future.result()
                        if device_info:
                            devices.append(device_info)
                            print(f"Found device: {device_info['ip']} - {device_info['hostname']} ({device_info['mac']})")
                    except Exception as e:
                        print(f"Error scanning: {e}")
            
            return devices
        
        except Exception as e:
            print(f"Error scanning IP range: {e}")
            return []

def main():
    scanner = NetworkScanner()
    
    print("Network Device Scanner with OS Detection")
    print("--------------------------------------")
    print("1. Scan entire local network")
    print("2. Scan specific IP range")
    print("3. Scan specific IP addresses")
    print("4. Exit")
    
    while True:
        choice = input("\nEnter your choice (1-4): ")
        
        if choice == '1':
            devices = scanner.scan_network()
            scanner.print_device_table(devices)
        
        elif choice == '2':
            start_ip = input("Enter start IP address: ")
            end_ip = input("Enter end IP address: ")
            devices = scanner.scan_specific_ip_range(start_ip, end_ip)
            scanner.print_device_table(devices)
        
        elif choice == '3':
            ip_list = input("Enter IP addresses separated by commas: ").split(',')
            devices = []
            for ip in ip_list:
                ip = ip.strip()
                print(f"Scanning {ip}...")
                device_info = scanner._scan_host(ip)
                if device_info:
                    devices.append(device_info)
                    print(f"Found device: {ip} - {device_info['hostname']} ({device_info['mac']})")
            scanner.print_device_table(devices)
        
        elif choice == '4':
            print("Exiting...")
            break
        
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()