#!/usr/bin/env python3
"""
Network Security Tool with DDoS/DoS Protection and Connection Filtering
"""

import socket
import subprocess
import platform
import re
import concurrent.futures
import json
import os
import time
import threading
from datetime import datetime, timedelta
from collections import defaultdict, deque
from ipaddress import IPv4Address, IPv4Network
import psutil

class ConnectionMonitor:
    def __init__(self):
        self.connection_logs = defaultdict(lambda: deque(maxlen=1000))
        self.connection_counts = defaultdict(int)
        self.suspicious_ips = set()
        self.monitoring = False
        self.monitor_thread = None
        
        # DDoS/DoS Detection Thresholds
        self.max_connections_per_ip = 50  # Max simultaneous connections per IP
        self.max_requests_per_minute = 100  # Max requests per minute per IP
        self.max_syn_flood_rate = 20  # Max SYN packets per second
        self.time_window = 60  # Time window in seconds for rate limiting
        
    def start_monitoring(self):
        """Start connection monitoring in background"""
        if not self.monitoring:
            self.monitoring = True
            self.monitor_thread = threading.Thread(target=self._monitor_connections, daemon=True)
            self.monitor_thread.start()
            print("🔍 Connection monitoring started")
    
    def stop_monitoring(self):
        """Stop connection monitoring"""
        self.monitoring = False
        if self.monitor_thread:
            self.monitor_thread.join()
        print("⏹️ Connection monitoring stopped")
    
    def _monitor_connections(self):
        """Monitor network connections continuously"""
        while self.monitoring:
            try:
                connections = psutil.net_connections(kind='inet')
                current_time = time.time()
                
                # Reset connection counts
                self.connection_counts.clear()
                
                for conn in connections:
                    if conn.raddr:  # Remote address exists
                        remote_ip = conn.raddr.ip
                        
                        # Count connections per IP
                        self.connection_counts[remote_ip] += 1
                        
                        # Log connection with timestamp
                        self.connection_logs[remote_ip].append({
                            'timestamp': current_time,
                            'local_port': conn.laddr.port if conn.laddr else None,
                            'remote_port': conn.raddr.port,
                            'status': conn.status,
                            'pid': conn.pid
                        })
                
                # Analyze for potential attacks
                self._analyze_for_attacks(current_time)
                
                time.sleep(1)  # Check every second
                
            except Exception as e:
                print(f"⚠️ Connection monitoring error: {e}")
                time.sleep(5)
    
    def _analyze_for_attacks(self, current_time):
        """Analyze connection patterns for potential DDoS/DoS attacks"""
        for ip, connections in self.connection_logs.items():
            # Check for too many simultaneous connections
            if self.connection_counts[ip] > self.max_connections_per_ip:
                self._flag_suspicious_ip(ip, f"Too many connections: {self.connection_counts[ip]}")
            
            # Check request rate in time window
            recent_connections = [c for c in connections if current_time - c['timestamp'] <= self.time_window]
            if len(recent_connections) > self.max_requests_per_minute:
                self._flag_suspicious_ip(ip, f"High request rate: {len(recent_connections)}/min")
            
            # Check for SYN flood (many SYN_SENT connections)
            syn_connections = [c for c in recent_connections if c['status'] == 'SYN_SENT']
            if len(syn_connections) > self.max_syn_flood_rate:
                self._flag_suspicious_ip(ip, f"Possible SYN flood: {len(syn_connections)} SYN packets")
    
    def _flag_suspicious_ip(self, ip, reason):
        """Flag an IP as suspicious"""
        if ip not in self.suspicious_ips:
            self.suspicious_ips.add(ip)
            print(f"🚨 SUSPICIOUS ACTIVITY from {ip}: {reason}")
            self._log_security_event(ip, reason)
    
    def _log_security_event(self, ip, reason):
        """Log security events to file"""
        try:
            log_entry = {
                'timestamp': datetime.now().isoformat(),
                'ip': ip,
                'reason': reason,
                'connections': self.connection_counts[ip]
            }
            
            with open('security_log.json', 'a') as f:
                f.write(json.dumps(log_entry) + '\n')
        except Exception as e:
            print(f"⚠️ Failed to log security event: {e}")
    
    def get_connection_stats(self):
        """Get current connection statistics"""
        stats = {
            'total_unique_ips': len(self.connection_counts),
            'total_connections': sum(self.connection_counts.values()),
            'suspicious_ips': len(self.suspicious_ips),
            'top_connectors': sorted(self.connection_counts.items(), 
                                   key=lambda x: x[1], reverse=True)[:10]
        }
        return stats

class TrafficFilter:
    def __init__(self):
        self.os_type = platform.system().lower()
        self.rate_limits = {}  # IP -> rate limit rules
        self.port_filters = {'tcp': set(), 'udp': set()}  # Blocked ports
        
    def add_rate_limit(self, ip, max_connections=10, time_window=60):
        """Add rate limiting rule for an IP"""
        self.rate_limits[ip] = {
            'max_connections': max_connections,
            'time_window': time_window,
            'connections': deque(maxlen=1000)
        }
        print(f"✅ Rate limit added for {ip}: {max_connections} connections per {time_window}s")
    
    def block_port(self, port, protocol='tcp'):
        """Block a specific port"""
        try:
            if self.os_type == "windows":
                cmd = f'netsh advfirewall firewall add rule name="Block_Port_{port}_{protocol}" dir=in action=block protocol={protocol} localport={port}'
                subprocess.run(cmd, shell=True, check=True)
            elif self.os_type == "linux":
                cmd = f'sudo iptables -A INPUT -p {protocol} --dport {port} -j DROP'
                subprocess.run(cmd, shell=True, check=True)
            
            self.port_filters[protocol].add(port)
            print(f"✅ Port {port}/{protocol} blocked")
            return True
        except subprocess.CalledProcessError as e:
            print(f"⚠️ Failed to block port {port}: {e}")
            return False
    
    def unblock_port(self, port, protocol='tcp'):
        """Unblock a specific port"""
        try:
            if self.os_type == "windows":
                cmd = f'netsh advfirewall firewall delete rule name="Block_Port_{port}_{protocol}"'
                subprocess.run(cmd, shell=True, check=True)
            elif self.os_type == "linux":
                cmd = f'sudo iptables -D INPUT -p {protocol} --dport {port} -j DROP'
                subprocess.run(cmd, shell=True, check=True)
            
            self.port_filters[protocol].discard(port)
            print(f"✅ Port {port}/{protocol} unblocked")
            return True
        except subprocess.CalledProcessError as e:
            print(f"⚠️ Failed to unblock port {port}: {e}")
            return False
    
    def create_ddos_protection_rules(self):
        """Create comprehensive DDoS protection rules"""
        try:
            if self.os_type == "linux":
                rules = [
                    # Limit new TCP connections
                    'sudo iptables -A INPUT -p tcp --dport 80 -m limit --limit 25/minute --limit-burst 100 -j ACCEPT',
                    'sudo iptables -A INPUT -p tcp --dport 443 -m limit --limit 25/minute --limit-burst 100 -j ACCEPT',
                    
                    # Protect against SYN flood
                    'sudo iptables -A INPUT -p tcp --syn -m limit --limit 1/s --limit-burst 3 -j ACCEPT',
                    
                    # Limit ping requests
                    'sudo iptables -A INPUT -p icmp --icmp-type echo-request -m limit --limit 1/s -j ACCEPT',
                    
                    # Drop invalid packets
                    'sudo iptables -A INPUT -m state --state INVALID -j DROP',
                    
                    # Connection tracking
                    'sudo iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT'
                ]
                
                for rule in rules:
                    subprocess.run(rule, shell=True, check=True)
                    
                print("✅ DDoS protection rules applied")
                return True
            else:
                print("⚠️ DDoS protection rules currently only available for Linux")
                return False
        except subprocess.CalledProcessError as e:
            print(f"⚠️ Failed to apply DDoS protection: {e}")
            return False

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

    def add_blocked_ip(self, ip, auto_system_block=False):
        """Add IP to blocked list"""
        try:
            IPv4Address(ip)
            self.blocked_ips.add(ip)
            self._save_blocked_list(self.blocked_ips, self.blocked_ips_file)
            print(f"✅ IP {ip} added to blocked list")
            
            if auto_system_block:
                self.block_ip_system_level(ip)
            return True
        except Exception as e:
            print(f"⚠️ Invalid IP address: {e}")
            return False

    def block_ip_system_level(self, ip):
        """Block IP at system level using firewall"""
        try:
            if self.os_type == "windows":
                cmd = f'netsh advfirewall firewall add rule name="Block_{ip}" dir=in action=block remoteip={ip}'
                subprocess.run(cmd, shell=True, check=True)
                cmd = f'netsh advfirewall firewall add rule name="Block_{ip}_out" dir=out action=block remoteip={ip}'
                subprocess.run(cmd, shell=True, check=True)
            elif self.os_type == "linux":
                cmd = f'sudo iptables -A INPUT -s {ip} -j DROP'
                subprocess.run(cmd, shell=True, check=True)
                cmd = f'sudo iptables -A OUTPUT -d {ip} -j DROP'
                subprocess.run(cmd, shell=True, check=True)
            
            print(f"✅ IP {ip} blocked at system level")
            return True
        except subprocess.CalledProcessError as e:
            print(f"⚠️ Failed to block IP {ip} at system level: {e}")
            return False

    def is_ip_blocked(self, ip):
        """Check if IP is blocked"""
        return ip in self.blocked_ips

class NetworkSecurityTool:
    def __init__(self):
        self.os_type = platform.system().lower()
        self.network_prefix = self._get_network_prefix()
        self.blocker = NetworkBlocker()
        self.monitor = ConnectionMonitor()
        self.filter = TrafficFilter()
        self.auto_block_enabled = False

    def _get_network_prefix(self):
        """Determine the local network prefix"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("8.8.8.8", 80))
                local_ip = s.getsockname()[0]
                return '.'.join(local_ip.split('.')[:3])
        except Exception:
            return "192.168.1"

    def enable_auto_protection(self):
        """Enable automatic blocking of suspicious IPs"""
        self.auto_block_enabled = True
        self.monitor.start_monitoring()
        
        # Start auto-blocking thread
        def auto_block_thread():
            while self.auto_block_enabled:
                for ip in list(self.monitor.suspicious_ips):
                    if not self.blocker.is_ip_blocked(ip):
                        print(f"🔒 Auto-blocking suspicious IP: {ip}")
                        self.blocker.add_blocked_ip(ip, auto_system_block=True)
                time.sleep(10)
        
        threading.Thread(target=auto_block_thread, daemon=True).start()
        print("🛡️ Auto-protection enabled")

    def disable_auto_protection(self):
        """Disable automatic blocking"""
        self.auto_block_enabled = False
        self.monitor.stop_monitoring()
        print("🛡️ Auto-protection disabled")

    def get_security_dashboard(self):
        """Display security dashboard"""
        stats = self.monitor.get_connection_stats()
        
        print("\n" + "="*70)
        print("                    SECURITY DASHBOARD")
        print("="*70)
        print(f"🌐 Monitoring Status: {'ACTIVE' if self.monitor.monitoring else 'INACTIVE'}")
        print(f"🔒 Auto-block: {'ENABLED' if self.auto_block_enabled else 'DISABLED'}")
        print(f"📊 Total Connections: {stats['total_connections']}")
        print(f"🏠 Unique IPs: {stats['total_unique_ips']}")
        print(f"🚨 Suspicious IPs: {stats['suspicious_ips']}")
        print(f"🚫 Blocked IPs: {len(self.blocker.blocked_ips)}")
        
        if stats['top_connectors']:
            print(f"\n📈 Top Connectors:")
            for ip, count in stats['top_connectors'][:5]:
                status = "🚫" if self.blocker.is_ip_blocked(ip) else "✅"
                suspicious = "⚠️" if ip in self.monitor.suspicious_ips else ""
                print(f"    {status} {ip:15} - {count:3} connections {suspicious}")
        
        print("="*70 + "\n")

def main():
    """Main CLI interface"""
    tool = NetworkSecurityTool()

    print("\n" + "="*70)
    print("        NETWORK SECURITY & DDoS PROTECTION TOOL")
    print("="*70 + "\n")

    while True:
        print("🛡️ Security Menu:")
        print("1. Start/Stop Connection Monitoring")
        print("2. View Security Dashboard")
        print("3. Enable/Disable Auto-Protection")
        print("4. Manual IP Blocking")
        print("5. Port Filtering")
        print("6. DDoS Protection Rules")
        print("7. View Security Logs")
        print("8. Connection Analysis")
        print("9. Exit\n")

        choice = input("Enter your choice (1-9): ").strip()

        if choice == '1':
            if tool.monitor.monitoring:
                tool.monitor.stop_monitoring()
            else:
                tool.monitor.start_monitoring()
                
        elif choice == '2':
            tool.get_security_dashboard()
            
        elif choice == '3':
            if tool.auto_block_enabled:
                tool.disable_auto_protection()
            else:
                tool.enable_auto_protection()
                
        elif choice == '4':
            print("\nIP Blocking:")
            print("1. Block IP manually")
            print("2. Unblock IP")
            print("3. View blocked IPs")
            
            block_choice = input("Choose (1-3): ").strip()
            if block_choice == '1':
                ip = input("Enter IP to block: ").strip()
                system_block = input("Apply system-level block? (y/n): ").lower() == 'y'
                tool.blocker.add_blocked_ip(ip, auto_system_block=system_block)
            elif block_choice == '3':
                print(f"Blocked IPs ({len(tool.blocker.blocked_ips)}):")
                for ip in sorted(tool.blocker.blocked_ips):
                    print(f"  🚫 {ip}")
                    
        elif choice == '5':
            print("\nPort Filtering:")
            print("1. Block port")
            print("2. Unblock port")
            print("3. View blocked ports")
            
            port_choice = input("Choose (1-3): ").strip()
            if port_choice == '1':
                try:
                    port = int(input("Enter port number: ").strip())
                    protocol = input("Protocol (tcp/udp) [tcp]: ").strip() or 'tcp'
                    tool.filter.block_port(port, protocol)
                except ValueError:
                    print("⚠️ Invalid port number")
            elif port_choice == '3':
                print("Blocked Ports:")
                for protocol, ports in tool.filter.port_filters.items():
                    if ports:
                        print(f"  {protocol.upper()}: {sorted(ports)}")
                        
        elif choice == '6':
            confirm = input("Apply DDoS protection rules? This requires sudo (y/n): ").lower()
            if confirm == 'y':
                tool.filter.create_ddos_protection_rules()
                
        elif choice == '7':
            if os.path.exists('security_log.json'):
                print("\nRecent Security Events:")
                try:
                    with open('security_log.json', 'r') as f:
                        lines = f.readlines()[-10:]  # Last 10 events
                        for line in lines:
                            event = json.loads(line.strip())
                            print(f"🚨 {event['timestamp'][:19]} - {event['ip']} - {event['reason']}")
                except Exception as e:
                    print(f"⚠️ Error reading logs: {e}")
            else:
                print("No security logs found")
                
        elif choice == '8':
            if tool.monitor.suspicious_ips:
                print("\n🔍 Suspicious IP Analysis:")
                for ip in tool.monitor.suspicious_ips:
                    connections = len(tool.monitor.connection_logs[ip])
                    current_conns = tool.monitor.connection_counts.get(ip, 0)
                    print(f"  ⚠️ {ip:15} - {current_conns} active, {connections} total logged")
            else:
                print("No suspicious activity detected")
                
        elif choice == '9':
            tool.disable_auto_protection()
            print("Exiting...")
            break
        else:
            print("⚠️ Invalid choice. Please try again.")

        print()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nProgram interrupted by user")
    except Exception as e:
        print(f"⚠️ Fatal error: {e}")