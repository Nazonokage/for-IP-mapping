#!/usr/bin/env python3
"""
Fixed Network Blocker with proper cleanup and detection-friendly blocking
"""

import subprocess
import platform
import json
import os
import signal
import sys
import atexit
from datetime import datetime

class ImprovedNetworkBlocker:
    def __init__(self):
        self.os_type = platform.system().lower()
        self.blocked_rules_file = "active_firewall_rules.json"
        self.active_rules = self._load_active_rules()
        
        # Register cleanup handlers
        atexit.register(self.cleanup_on_exit)
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)
        
    def _load_active_rules(self):
        """Load currently active firewall rules"""
        try:
            if os.path.exists(self.blocked_rules_file):
                with open(self.blocked_rules_file, 'r') as f:
                    return json.load(f)
        except Exception as e:
            print(f"Warning: Could not load active rules: {e}")
        return {"ips": [], "macs": [], "ports": []}
    
    def _save_active_rules(self):
        """Save currently active firewall rules"""
        try:
            with open(self.blocked_rules_file, 'w') as f:
                json.dump(self.active_rules, f, indent=2)
        except Exception as e:
            print(f"Error saving active rules: {e}")
    
    def signal_handler(self, signum, frame):
        """Handle termination signals"""
        print(f"\nReceived signal {signum}, cleaning up...")
        self.cleanup_all_rules()
        sys.exit(0)
    
    def cleanup_on_exit(self):
        """Cleanup function called on normal exit"""
        if hasattr(self, 'active_rules') and self.active_rules:
            print("Cleaning up firewall rules on exit...")
            self.cleanup_all_rules()
    
    def block_ip_improved(self, ip, detection_friendly=True):
        """
        Block IP with improved method that allows detection monitoring
        
        Args:
            ip: IP address to block
            detection_friendly: If True, allows monitoring tools to still see the traffic
        """
        try:
            if detection_friendly:
                # Use REJECT instead of DROP so detection tools can see the traffic
                # but connections are still blocked
                if self.os_type == "linux":
                    # Block new connections but allow existing monitoring
                    cmd_in = f'sudo iptables -A INPUT -s {ip} -m state --state NEW -j REJECT --reject-with icmp-host-prohibited'
                    cmd_out = f'sudo iptables -A OUTPUT -d {ip} -m state --state NEW -j REJECT --reject-with icmp-host-prohibited'
                    
                    subprocess.run(cmd_in, shell=True, check=True)
                    subprocess.run(cmd_out, shell=True, check=True)
                    
                    # Store the exact commands used for cleanup
                    rule_info = {
                        "ip": ip,
                        "type": "ip_detection_friendly",
                        "commands": [cmd_in, cmd_out],
                        "cleanup_commands": [
                            f'sudo iptables -D INPUT -s {ip} -m state --state NEW -j REJECT --reject-with icmp-host-prohibited',
                            f'sudo iptables -D OUTPUT -d {ip} -m state --state NEW -j REJECT --reject-with icmp-host-prohibited'
                        ],
                        "timestamp": datetime.now().isoformat()
                    }
                    
                elif self.os_type == "windows":
                    cmd_in = f'netsh advfirewall firewall add rule name="DetectionBlock_IN_{ip}" dir=in action=block remoteip={ip} enable=yes'
                    cmd_out = f'netsh advfirewall firewall add rule name="DetectionBlock_OUT_{ip}" dir=out action=block remoteip={ip} enable=yes'
                    
                    subprocess.run(cmd_in, shell=True, check=True)
                    subprocess.run(cmd_out, shell=True, check=True)
                    
                    rule_info = {
                        "ip": ip,
                        "type": "ip_detection_friendly",
                        "commands": [cmd_in, cmd_out],
                        "cleanup_commands": [
                            f'netsh advfirewall firewall delete rule name="DetectionBlock_IN_{ip}"',
                            f'netsh advfirewall firewall delete rule name="DetectionBlock_OUT_{ip}"'
                        ],
                        "timestamp": datetime.now().isoformat()
                    }
                    
            else:
                # Standard blocking (completely drops packets)
                if self.os_type == "linux":
                    cmd_in = f'sudo iptables -A INPUT -s {ip} -j DROP'
                    cmd_out = f'sudo iptables -A OUTPUT -d {ip} -j DROP'
                    
                    subprocess.run(cmd_in, shell=True, check=True)
                    subprocess.run(cmd_out, shell=True, check=True)
                    
                    rule_info = {
                        "ip": ip,
                        "type": "ip_standard",
                        "cleanup_commands": [
                            f'sudo iptables -D INPUT -s {ip} -j DROP',
                            f'sudo iptables -D OUTPUT -d {ip} -j DROP'
                        ],
                        "timestamp": datetime.now().isoformat()
                    }
            
            # Add to active rules
            self.active_rules["ips"].append(rule_info)
            self._save_active_rules()
            
            block_type = "detection-friendly" if detection_friendly else "standard"
            print(f"✅ IP {ip} blocked ({block_type} mode)")
            return True
            
        except subprocess.CalledProcessError as e:
            print(f"❌ Failed to block IP {ip}: {e}")
            return False
        except Exception as e:
            print(f"❌ Error blocking IP {ip}: {e}")
            return False
    
    def unblock_ip_improved(self, ip):
        """Properly unblock IP by removing the exact rules that were created"""
        success = True
        rules_to_remove = []
        
        for i, rule in enumerate(self.active_rules["ips"]):
            if rule["ip"] == ip:
                try:
                    # Execute cleanup commands
                    for cmd in rule["cleanup_commands"]:
                        try:
                            subprocess.run(cmd, shell=True, check=True, 
                                         stderr=subprocess.DEVNULL)
                        except subprocess.CalledProcessError:
                            # Rule might already be removed, continue
                            pass
                    
                    rules_to_remove.append(i)
                    print(f"✅ Removed firewall rule for IP {ip}")
                    
                except Exception as e:
                    print(f"⚠️ Error removing rule for {ip}: {e}")
                    success = False
        
        # Remove from active rules (in reverse order to maintain indices)
        for i in reversed(rules_to_remove):
            self.active_rules["ips"].pop(i)
        
        self._save_active_rules()
        
        if rules_to_remove:
            print(f"✅ IP {ip} unblocked successfully")
            return success
        else:
            print(f"⚠️ No active rules found for IP {ip}")
            return False
    
    def list_active_rules(self):
        """List all currently active firewall rules"""
        print("\n📋 Active Firewall Rules:")
        print("-" * 50)
        
        if not any(self.active_rules.values()):
            print("No active rules found")
            return
        
        for rule in self.active_rules["ips"]:
            rule_type = rule.get("type", "unknown")
            timestamp = rule.get("timestamp", "unknown")
            print(f"🚫 IP: {rule['ip']} | Type: {rule_type} | Created: {timestamp}")
        
        for rule in self.active_rules["macs"]:
            timestamp = rule.get("timestamp", "unknown")
            print(f"🚫 MAC: {rule['mac']} | Created: {timestamp}")
        
        for rule in self.active_rules["ports"]:
            timestamp = rule.get("timestamp", "unknown")
            print(f"🚫 Port: {rule['port']}/{rule['protocol']} | Created: {timestamp}")
    
    def cleanup_all_rules(self):
        """Remove all active firewall rules created by this tool"""
        if not any(self.active_rules.values()):
            print("No active rules to clean up")
            return
        
        print("🧹 Cleaning up all firewall rules...")
        
        # Cleanup IP rules
        for rule in self.active_rules["ips"]:
            for cmd in rule["cleanup_commands"]:
                try:
                    subprocess.run(cmd, shell=True, check=True, 
                                 stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
                except subprocess.CalledProcessError:
                    pass  # Rule might already be gone
        
        # Cleanup MAC rules
        for rule in self.active_rules["macs"]:
            for cmd in rule["cleanup_commands"]:
                try:
                    subprocess.run(cmd, shell=True, check=True, 
                                 stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
                except subprocess.CalledProcessError:
                    pass
        
        # Cleanup port rules
        for rule in self.active_rules["ports"]:
            for cmd in rule["cleanup_commands"]:
                try:
                    subprocess.run(cmd, shell=True, check=True, 
                                 stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
                except subprocess.CalledProcessError:
                    pass
        
        # Clear the active rules
        self.active_rules = {"ips": [], "macs": [], "ports": []}
        self._save_active_rules()
        
        print("✅ All firewall rules cleaned up")
    
    def test_connectivity(self, ip):
        """Test if IP is reachable after blocking"""
        print(f"🔍 Testing connectivity to {ip}...")
        
        try:
            if self.os_type == "windows":
                cmd = f"ping -n 1 -w 1000 {ip}"
            else:
                cmd = f"ping -c 1 -W 1 {ip}"
            
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            
            if result.returncode == 0:
                print(f"✅ {ip} is reachable (ping successful)")
                return True
            else:
                print(f"❌ {ip} is not reachable (ping failed)")
                return False
                
        except Exception as e:
            print(f"⚠️ Error testing connectivity: {e}")
            return False
    
    def create_test_environment(self):
        """Set up a test environment for DDoS detection"""
        print("🧪 Setting up test environment for DDoS detection...")
        
        # Create a temporary rule that allows monitoring but blocks actual connections
        test_ip = input("Enter IP to use for testing (e.g., your VM IP): ").strip()
        
        if not test_ip:
            print("❌ No IP provided")
            return False
        
        print(f"Creating detection-friendly block for {test_ip}...")
        success = self.block_ip_improved(test_ip, detection_friendly=True)
        
        if success:
            print(f"✅ Test environment ready!")
            print(f"📡 Your detection tools should still see traffic from {test_ip}")
            print(f"🚫 But actual connections will be blocked")
            print(f"💡 Try running hping3 from {test_ip} - it should be detected but blocked")
            
        return success

def main():
    blocker = ImprovedNetworkBlocker()
    
    while True:
        print("\n" + "="*60)
        print("    IMPROVED NETWORK BLOCKER")
        print("="*60)
        print("1. Block IP (detection-friendly)")
        print("2. Block IP (standard)")
        print("3. Unblock IP")
        print("4. List active rules")
        print("5. Test connectivity")
        print("6. Cleanup all rules")
        print("7. Setup test environment")
        print("8. Exit")
        
        choice = input("\nEnter choice (1-8): ").strip()
        
        if choice == '1':
            ip = input("Enter IP to block (detection-friendly): ").strip()
            if ip:
                blocker.block_ip_improved(ip, detection_friendly=True)
        
        elif choice == '2':
            ip = input("Enter IP to block (standard): ").strip()
            if ip:
                blocker.block_ip_improved(ip, detection_friendly=False)
        
        elif choice == '3':
            ip = input("Enter IP to unblock: ").strip()
            if ip:
                blocker.unblock_ip_improved(ip)
        
        elif choice == '4':
            blocker.list_active_rules()
        
        elif choice == '5':
            ip = input("Enter IP to test: ").strip()
            if ip:
                blocker.test_connectivity(ip)
        
        elif choice == '6':
            confirm = input("Remove ALL firewall rules? (y/N): ").strip().lower()
            if confirm == 'y':
                blocker.cleanup_all_rules()
        
        elif choice == '7':
            blocker.create_test_environment()
        
        elif choice == '8':
            blocker.cleanup_on_exit()
            print("Goodbye!")
            break
        
        else:
            print("Invalid choice")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nExiting...")
    except Exception as e:
        print(f"Error: {e}")