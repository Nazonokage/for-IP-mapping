# Network Scanning Tools Collection

A comprehensive collection of Python scripts for network scanning and security monitoring, providing functionality similar to nmap with additional features like OS detection, MAC address lookup, vendor identification, DDoS protection, and traffic filtering.

## Features

- **Host Discovery**: ICMP ping sweeps, TCP connect probes, and ARP scanning
- **OS Detection**: TTL-based detection, port fingerprinting, and MAC vendor analysis
- **MAC Address Lookup**: ARP table parsing, vendor OUI database integration
- **Device Type Identification**: Android/iOS detection, network device recognition
- **Security Monitoring**: DDoS/DoS attack detection and prevention
- **Traffic Filtering**: Port blocking, rate limiting, and connection monitoring
- **Export Capabilities**: CSV and JSON export for scan results
- **Cross-Platform Support**: Windows, macOS, and Linux compatibility
- **Threaded Scanning**: Concurrent scanning for improved performance

## Scripts Overview

### Core Scanning Tools

#### `netscan.py`
Basic network device scanner with OS detection and MAC lookup.
- Scans local network for active devices
- Performs OS detection using TTL values and open ports
- Retrieves MAC addresses and vendor information
- Supports custom IP ranges and specific host scanning

#### `netscan_plus.py`
Enhanced network scanner with advanced features.
- Robust host discovery using ICMP + TCP probes
- Multiple MAC discovery methods (ARP, arping, ARP table)
- Device type hints (Android, iOS, Desktop)
- CSV/JSON export functionality
- Improved OS detection with port scanning

#### `netscanbasic.py`
Simplified network scanner for basic operations.
- Lightweight scanning with essential features
- Fast network discovery
- Basic OS detection via TTL

#### `netscanv2.py`
Enhanced scanner with local OUI cache support (JSON format).
- Uses `data/oui_cache.json` for vendor lookups
- Improved hostname resolution (DNS, NetBIOS, mDNS)
- Multi-method OS detection
- Better error handling and logging

#### `netscanv3.py`
Similar to v2 but uses `data/oui.txt` for vendor database.
- Parses IEEE OUI text file format
- Enhanced port-based OS detection
- Support for various network device types

### Security and Protection Tools

#### `DOSscann.py`
Network security tool with DDoS/DoS protection.
- Real-time connection monitoring
- Automatic suspicious IP detection and blocking
- Traffic filtering and rate limiting
- Port blocking capabilities
- Security event logging
- DDoS protection rule creation

#### `scanblock.py`, `scanfilterblock.py`, `scan_block.py`
Various implementations of network blocking and filtering utilities.
- IP and MAC address blocking
- Traffic filtering rules
- Integration with system firewalls

## Installation

### Requirements
- Python 3.6+
- `psutil` library (for DOSscann.py): `pip install psutil`
- `scapy` library (optional, for enhanced MAC discovery in netscan_plus.py): `pip install scapy`

### Setup
1. Clone or download the repository
2. Ensure Python 3 is installed
3. Install required dependencies: `pip install psutil`
4. For enhanced features, install scapy: `pip install scapy`
5. Run scripts with administrator/root privileges for best results

## Usage

### Basic Network Scanning
```bash
# Run basic scanner
python netscan.py

# Run enhanced scanner
python netscan_plus.py

# Run simplified scanner
python netscanbasic.py
```

### Security Monitoring
```bash
# Run security tool
python DOSscann.py
```

### Example Output
```
🔍 Scanning 192.168.1.1-254 (254 hosts)
This may take a few minutes...

• 192.168.1.1      | router.local        | AA:BB:CC:DD:EE:FF | Network Device
• 192.168.1.100    | johns-macbook       | 12:34:56:78:9A:BC | macOS/iOS
• 192.168.1.150    | android-device      | DE:F0:12:34:56:78 | Android

✅ Scan completed in 45.23 seconds
📊 Found 15 active devices
```

## Data Files

### OUI Database Files
- `data/oui_cache.json`: JSON format vendor database for MAC address lookups
- `data/oui.txt`: IEEE OUI text file for vendor identification

### Security Files
- `blocked_ips.json`: List of blocked IP addresses
- `blocked_macs.json`: List of blocked MAC addresses
- `security_log.json`: Security event logs from monitoring

## Configuration

### OUI Database Setup
Download the latest IEEE OUI database and place it in the `data/` directory:
- For JSON format: Convert IEEE OUI data to `oui_cache.json`
- For text format: Use the standard `oui.txt` from IEEE

### Security Thresholds
Modify detection thresholds in `DOSscann.py`:
- `max_connections_per_ip`: Maximum simultaneous connections per IP
- `max_requests_per_minute`: Rate limiting threshold
- `max_syn_flood_rate`: SYN flood detection threshold

## Security Considerations

- **Privileges**: Run with administrator/root privileges for full functionality
- **Network Impact**: Scanning may trigger security alerts on monitored networks
- **Legal Compliance**: Ensure scanning activities comply with local laws and network policies
- **Resource Usage**: Large network scans may consume significant system resources

## Troubleshooting

### Common Issues
- **Permission Errors**: Run scripts as administrator/root
- **Missing Dependencies**: Install required Python packages
- **Firewall Blocking**: Temporarily disable firewall for local testing
- **Slow Scanning**: Reduce thread count or scan smaller ranges

### Performance Tips
- Use specific IP ranges instead of full network scans
- Adjust thread counts based on system capabilities
- Enable OUI caching for faster vendor lookups

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## License

This project is provided as-is for educational and network administration purposes. Use responsibly and in compliance with applicable laws and regulations.

## Disclaimer

These tools are for legitimate network administration and security testing purposes only. Unauthorized scanning of networks may violate laws and terms of service. The authors are not responsible for misuse of these tools.
