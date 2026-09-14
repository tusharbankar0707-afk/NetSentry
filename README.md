# NetSentry

A lightweight, multithreaded network port scanner and host discovery tool for auditing your own network.

NetSentry helps you find open ports and live hosts on networks you own or are authorized to test — useful for home network audits, lab environments, and learning network security fundamentals.

> ⚠️ **Legal & Ethical Use Only**
> Only scan hosts and networks you own or have explicit written permission to test. Scanning networks without authorization is illegal in most jurisdictions (e.g., under the U.S. Computer Fraud and Abuse Act) and violates most ISPs' terms of service. You are solely responsible for how you use this tool.

## Features

- 🔍 TCP connect scanning (single host or CIDR subnet)
- ⚡ Multithreaded for fast scans
- 🛰️ Basic live-host discovery mode
- 🏷️ Common service name guessing (SSH, HTTP, RDP, MySQL, etc.)
- 🎯 Flexible port selection: single ports, ranges, comma lists, or full 1–65535 scan
- 🧰 Zero third-party dependencies — pure Python standard library

## Requirements

- Python 3.7 or later
- No external packages required

## Installation

1. **Clone or download this repository:**
   ```bash
   git clone https://github.com/yourusername/netsentry.git
   cd netsentry
   ```

2. **(Optional) Create a virtual environment:**
   ```bash
   python3 -m venv venv
   source venv/bin/activate      # On Windows: venv\Scripts\activate
   ```

3. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```
   *(NetSentry has no third-party dependencies, but this keeps things consistent with standard Python project setup.)*

4. **Verify it runs:**
   ```bash
   python3 netscan.py --help
   ```

## Usage

```bash
# Quick scan of common ports on a single host
python3 netscan.py 192.168.1.10

# Scan a specific port range
python3 netscan.py 192.168.1.10 -p 1-1024

# Scan specific ports only
python3 netscan.py 192.168.1.10 -p 22,80,443

# Discover live hosts on a subnet
python3 netscan.py 192.168.1.0/24 --discover

# Full scan of all 65,535 ports
python3 netscan.py 192.168.1.10 --full

# Adjust thread count and timeout for speed/accuracy tradeoffs
python3 netscan.py 192.168.1.10 -t 200 --timeout 0.3
```

### Command-line Options

| Flag | Description | Default |
|---|---|---|
| `target` | IP address, hostname, or CIDR range | required |
| `-p`, `--ports` | Ports to scan (`80`, `1-1024`, or `22,80,443`) | common ports |
| `-t`, `--threads` | Number of scanning threads | 100 |
| `--timeout` | Socket timeout in seconds | 0.5 |
| `--discover` | Discover live hosts on a subnet instead of port scanning | off |
| `--full` | Scan all 65,535 ports (overrides `-p`) | off |

## How It Works

NetSentry uses TCP connect scans (`socket.connect_ex`) rather than raw SYN scans, so it does **not** require root/administrator privileges. Host discovery approximates liveness by probing a handful of commonly open ports, since true ICMP ping requires raw sockets.

## Roadmap Ideas

- Banner grabbing to confirm service identity beyond port-number guessing
- JSON/CSV export of scan results
- Baseline comparison mode to flag newly opened ports over time
- Scheduled scanning with alerting

## Contributing

Issues and pull requests are welcome. Please keep contributions focused on defensive/authorized-use functionality.

## License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.

## Disclaimer

This tool is provided for educational and authorized security-testing purposes only. The authors and contributors accept no liability for misuse or for any damage caused by this tool. Always obtain proper authorization before scanning any network or system you do not own.
