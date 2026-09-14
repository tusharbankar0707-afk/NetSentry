#!/usr/bin/env python3
"""
netscan.py — A simple, ethical network port scanner for your own network.

⚠️ LEGAL / ETHICAL NOTE:
Only scan hosts and networks you own or have explicit permission to test.
Scanning networks without authorization is illegal in most jurisdictions
(e.g., under the U.S. Computer Fraud and Abuse Act) and against most ISP
terms of service.

Features:
  - Scan a single host or a whole subnet (CIDR notation)
  - Quick scan (common ports) or full scan (custom range)
  - Multithreaded for speed
  - Basic service name guessing for open ports
  - Simple host discovery (ping-style check) before port scanning

Usage examples:
  python3 netscan.py 192.168.1.10                  # quick scan, common ports
  python3 netscan.py 192.168.1.10 -p 1-1024         # scan port range
  python3 netscan.py 192.168.1.0/24 --discover       # find live hosts on subnet
  python3 netscan.py 192.168.1.10 -p 22,80,443       # scan specific ports
  python3 netscan.py 192.168.1.10 -t 200             # use 200 threads
"""

import argparse
import ipaddress
import socket
import sys
import threading
import queue
import time
from datetime import datetime

# Common ports and their typical service names (not authoritative — just a guide)
COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 111: "RPCbind", 135: "MSRPC",
    139: "NetBIOS", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    993: "IMAPS", 995: "POP3S", 1723: "PPTP", 3306: "MySQL",
    3389: "RDP", 5900: "VNC", 8080: "HTTP-Proxy", 8443: "HTTPS-Alt",
    27017: "MongoDB", 6379: "Redis", 5432: "PostgreSQL", 9200: "Elasticsearch",
}

QUICK_SCAN_PORTS = sorted(COMMON_PORTS.keys())

print_lock = threading.Lock()


def parse_ports(port_arg):
    """Parse a port argument like '80', '1-1024', or '22,80,443'."""
    ports = set()
    if not port_arg:
        return QUICK_SCAN_PORTS
    for part in port_arg.split(","):
        part = part.strip()
        if "-" in part:
            start, end = part.split("-")
            ports.update(range(int(start), int(end) + 1))
        else:
            ports.add(int(part))
    return sorted(ports)


def guess_service(port):
    return COMMON_PORTS.get(port, "unknown")


def scan_port(ip, port, timeout, results):
    """Attempt a TCP connect to a single port."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, port))
            if result == 0:
                service = guess_service(port)
                results.append((port, service))
                with print_lock:
                    print(f"  [OPEN] {ip}:{port:<6} {service}")
    except socket.error:
        pass


def worker(ip, port_queue, timeout, results):
    while not port_queue.empty():
        try:
            port = port_queue.get_nowait()
        except queue.Empty:
            return
        scan_port(ip, port, timeout, results)
        port_queue.task_done()


def scan_host(ip, ports, threads, timeout):
    """Scan a single host across the given ports using a thread pool."""
    print(f"\nScanning {ip} ({len(ports)} ports)...")
    start = time.time()

    port_queue = queue.Queue()
    for p in ports:
        port_queue.put(p)

    results = []
    thread_list = []
    num_threads = min(threads, len(ports)) or 1

    for _ in range(num_threads):
        t = threading.Thread(target=worker, args=(ip, port_queue, timeout, results))
        t.start()
        thread_list.append(t)

    for t in thread_list:
        t.join()

    elapsed = time.time() - start
    results.sort(key=lambda r: r[0])

    print(f"\n  Scan of {ip} complete in {elapsed:.2f}s — {len(results)} open port(s) found.")
    return results


def host_is_up(ip, timeout=0.5):
    """
    Lightweight liveness check: try a connect on a couple of common ports.
    (True ICMP ping requires raw sockets / root privileges, so we approximate.)
    """
    test_ports = [80, 443, 22, 445, 139]
    for port in test_ports:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(timeout)
                if sock.connect_ex((str(ip), port)) == 0:
                    return True
        except socket.error:
            continue
    return False


def discover_hosts(network, threads, timeout):
    """Scan a subnet for live hosts."""
    net = ipaddress.ip_network(network, strict=False)
    print(f"\nDiscovering live hosts on {net} (this checks common ports, not ICMP)...")
    print("Note: hosts with no open ports among the probe list may be missed.\n")

    hosts = list(net.hosts())
    host_queue = queue.Queue()
    for h in hosts:
        host_queue.put(h)

    live_hosts = []
    lock = threading.Lock()

    def discover_worker():
        while not host_queue.empty():
            try:
                ip = host_queue.get_nowait()
            except queue.Empty:
                return
            if host_is_up(ip, timeout):
                with lock:
                    live_hosts.append(str(ip))
                    with print_lock:
                        print(f"  [UP] {ip}")
            host_queue.task_done()

    thread_list = []
    for _ in range(min(threads, len(hosts))):
        t = threading.Thread(target=discover_worker)
        t.start()
        thread_list.append(t)

    for t in thread_list:
        t.join()

    print(f"\nDiscovery complete — {len(live_hosts)} live host(s) found.")
    return live_hosts


def main():
    parser = argparse.ArgumentParser(
        description="A simple, ethical network port scanner for your own network.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Only scan networks/hosts you own or have explicit permission to test."
    )
    parser.add_argument("target", help="IP address or CIDR range (e.g., 192.168.1.10 or 192.168.1.0/24)")
    parser.add_argument("-p", "--ports", help="Ports to scan: '80', '1-1024', or '22,80,443'. Default: common ports.")
    parser.add_argument("-t", "--threads", type=int, default=100, help="Number of threads (default: 100)")
    parser.add_argument("--timeout", type=float, default=0.5, help="Socket timeout in seconds (default: 0.5)")
    parser.add_argument("--discover", action="store_true", help="Discover live hosts on a subnet instead of port scanning")
    parser.add_argument("--full", action="store_true", help="Full scan of all 65535 ports (overrides -p)")

    args = parser.parse_args()

    print("=" * 60)
    print("  netscan.py — Ethical Network Scanner")
    print(f"  Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 60)
    print("  Reminder: only scan systems you own or are authorized to test.")

    # Subnet discovery mode
    if args.discover or "/" in args.target:
        try:
            live_hosts = discover_hosts(args.target, args.threads, args.timeout)
        except ValueError as e:
            print(f"Error: invalid network - {e}")
            sys.exit(1)

        if args.discover:
            sys.exit(0)

        # If not purely a discover request but a CIDR was given without --discover,
        # ask before scanning every live host's ports (could be slow/loud).
        if not live_hosts:
            print("No live hosts to scan.")
            sys.exit(0)

        ports = list(range(1, 65536)) if args.full else parse_ports(args.ports)
        for ip in live_hosts:
            scan_host(ip, ports, args.threads, args.timeout)
        sys.exit(0)

    # Single host scan
    try:
        ip = str(ipaddress.ip_address(args.target))
    except ValueError:
        try:
            ip = socket.gethostbyname(args.target)
            print(f"  Resolved {args.target} -> {ip}")
        except socket.gaierror:
            print(f"Error: could not resolve host '{args.target}'")
            sys.exit(1)

    ports = list(range(1, 65536)) if args.full else parse_ports(args.ports)
    results = scan_host(ip, ports, args.threads, args.timeout)

    print("\n" + "=" * 60)
    print("  Summary")
    print("=" * 60)
    if results:
        for port, service in results:
            print(f"  {ip}:{port:<6} {service}")
    else:
        print("  No open ports found.")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nScan interrupted by user.")
        sys.exit(1)
