#!/usr/bin/env python3
"""
Port Scanner - A simple but powerful TCP port scanner
Author: [Sama Ismael Ahel]
GitHub: [https://github.com/sam-btw]
"""

import socket
import concurrent.futures
import argparse
import sys
from datetime import datetime

# Common ports with their service names
COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP",
    443: "HTTPS", 445: "SMB", 3306: "MySQL", 3389: "RDP",
    5432: "PostgreSQL", 6379: "Redis", 8080: "HTTP-Alt",
    8443: "HTTPS-Alt", 27017: "MongoDB"
}


def resolve_host(target: str) -> str:
    """Resolve hostname to IP address."""
    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        print(f"[ERROR] Cannot resolve host: {target}")
        sys.exit(1)


def scan_port(ip: str, port: int, timeout: float = 1.0) -> dict:
    """
    Scan a single port on the target IP.
    Returns a dict with port status and service name.
    """
    result = {"port": port, "state": "closed", "service": COMMON_PORTS.get(port, "unknown")}
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            connection = s.connect_ex((ip, port))
            if connection == 0:
                result["state"] = "open"
                # Try to grab banner
                try:
                    s.send(b"HEAD / HTTP/1.0\r\n\r\n")
                    banner = s.recv(1024).decode("utf-8", errors="ignore").strip()
                    result["banner"] = banner[:100] if banner else ""
                except Exception:
                    result["banner"] = ""
    except socket.error:
        pass
    return result


def scan_ports(target: str, ports: list, threads: int = 100, timeout: float = 1.0) -> list:
    """Scan multiple ports concurrently using a thread pool."""
    ip = resolve_host(target)
    open_ports = []

    print(f"\n{'='*55}")
    print(f"  PORT SCANNER")
    print(f"{'='*55}")
    print(f"  Target   : {target} ({ip})")
    print(f"  Ports    : {len(ports)} ports")
    print(f"  Threads  : {threads}")
    print(f"  Started  : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*55}\n")

    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(scan_port, ip, port, timeout): port for port in ports}
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result["state"] == "open":
                open_ports.append(result)
                service = result["service"]
                banner = f" | {result['banner'][:50]}" if result.get("banner") else ""
                print(f"  [OPEN]  Port {result['port']:<6} {service:<15}{banner}")

    open_ports.sort(key=lambda x: x["port"])
    return open_ports


def parse_ports(port_arg: str) -> list:
    """
    Parse port argument into a list of integers.
    Supports: '80', '80,443', '1-1000', 'common'
    """
    if port_arg == "common":
        return list(COMMON_PORTS.keys())

    ports = []
    for part in port_arg.split(","):
        part = part.strip()
        if "-" in part:
            start, end = part.split("-")
            ports.extend(range(int(start), int(end) + 1))
        else:
            ports.append(int(part))
    return ports


def print_summary(open_ports: list, start_time: datetime):
    """Print scan summary."""
    elapsed = (datetime.now() - start_time).total_seconds()
    print(f"\n{'='*55}")
    print(f"  SCAN COMPLETE")
    print(f"{'='*55}")
    print(f"  Open ports : {len(open_ports)}")
    print(f"  Time taken : {elapsed:.2f} seconds")
    if open_ports:
        print(f"\n  OPEN PORTS SUMMARY:")
        for p in open_ports:
            print(f"    {p['port']}/tcp  ->  {p['service']}")
    print(f"{'='*55}\n")


def main():
    parser = argparse.ArgumentParser(
        description="Simple TCP Port Scanner",
        epilog="Examples:\n"
               "  python scanner.py scanme.nmap.org -p common\n"
               "  python scanner.py 192.168.1.1 -p 1-1000\n"
               "  python scanner.py 10.0.0.1 -p 22,80,443,3306",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("target", help="Target IP or hostname")
    parser.add_argument("-p", "--ports", default="common",
                        help="Ports to scan: 'common', '1-1000', '80,443,8080' (default: common)")
    parser.add_argument("-t", "--threads", type=int, default=100,
                        help="Number of threads (default: 100)")
    parser.add_argument("--timeout", type=float, default=1.0,
                        help="Connection timeout in seconds (default: 1.0)")

    args = parser.parse_args()

    ports = parse_ports(args.ports)
    start_time = datetime.now()

    open_ports = scan_ports(args.target, ports, args.threads, args.timeout)
    print_summary(open_ports, start_time)


if __name__ == "__main__":
    main()
