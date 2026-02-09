#!/usr/bin/env python3
"""
network_port_scanner_embedded.py

- Uses an embedded mapping of port -> description (extracted from the provided Full-port-list.txt content).
- Performs TCP connect scans (IPv4) against a single host or all hosts in a CIDR.
- Produces an HTML report with color-coded statuses: Open (green), Closed (red), Invalid (gray).

Usage examples:
    python ports-scan.py --targets 192.168.1.10
    python ports-scan.py --targets 192.168.1.0/28 --workers 300 --timeout 0.8
    python ports-scan.py --targets 10.0.0.5 --ports 22,80,443

Notes:
- Only TCP connect scans are performed.
- Scan only networks/hosts you are authorized to test.
"""

import argparse
import socket
import concurrent.futures
import ipaddress
import time
import html
from datetime import datetime, UTC
import threading

# ---------------------------
# Embedded ports mapping 
# ---------------------------

PORTS_TOP50 = {
    20:  "FTP data",
    21:  "FTP control",
    22:  "SSH",
    23:  "Telnet",
    25:  "SMTP",
    53:  "DNS",
    67:  "BOOTP/DHCP server",
    68:  "BOOTP/DHCP client",
    69:  "TFTP",
    80:  "HTTP",
    110: "POP3",
    111: "ONC RPC",
    123: "NTP",
    135: "Microsoft EPMAP / DCE-RPC",
    137: "NetBIOS Name Service",
    138: "NetBIOS Datagram",
    139: "NetBIOS Session",
    143: "IMAP",
    161: "SNMP",
    162: "SNMP Trap",
    389: "LDAP",
    401: "UPS",
    427: "SLP",
    443: "HTTPS",
    445: "SMB / Microsoft-DS",
    500: "ISAKMP / IKE",
    512: "rexec",
    513: "rlogin",
    514: "rsh / syslog",
    515: "LPD",
    520: "RIP",
    546: "DHCPv6 client",
    547: "DHCPv6 server",
    548: "AFP",
    554: "RTSP",
    587: "SMTP submission",
    631: "IPP / CUPS",
    636: "LDAPS",
    860: "iSCSI",
    873: "rsync",
    902: "VMware ESXi",
    953: "BIND RNDC",
    989: "FTPS data",
    990: "FTPS control",
    993: "IMAPS",
    995: "POP3S",
    1080: "SOCKS proxy",
    1433: "Microsoft SQL Server",
    1521: "Oracle listener",
    1723: "PPTP",
    2049: "NFS",
    2082: "cPanel HTTP",
    2083: "cPanel HTTPS",
    2375: "Docker API (insecure)",
    2376: "Docker API (TLS)",
    2380: "etcd server",
    2483: "Oracle DB (insecure)",
    2484: "Oracle DB (SSL)",
    3128: "Squid proxy",
    3260: "iSCSI",
    3306: "MySQL",
    3389: "RDP",
    3690: "Subversion",
    3724: "Blizzard games",
    4444: "Metasploit",
}

# ---------------------------
# Scanner functions
# ---------------------------
def scan_port(host, port, timeout):
    """Return 'open', 'closed' or 'invalid' for a TCP connect attempt."""
    if not isinstance(port, int) or not (0 <= port <= 65535):
        return 'invalid'
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            res = s.connect_ex((host, port))
            return 'open' if res == 0 else 'closed'
    except socket.gaierror:
        return 'invalid'
    except Exception:
        return 'closed'

HTML_TEMPLATE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Port Scan Report - {title}</title>
<style>
body {{ font-family: Arial, Helvetica, sans-serif; margin: 20px; }}
h1 {{ font-size: 1.4em; }}
table {{ border-collapse: collapse; width: 100%; max-width: 1200px; }}
th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; font-size: 0.95em; }}
th {{ background: #f4f4f4; }}
.status-open {{ background: #d4f7d4; color: #0a6b0a; font-weight: bold; }}
.status-closed {{ background: #f7d4d4; color: #6b0a0a; font-weight: bold; }}
.status-invalid {{ background: #e8e8e8; color: #444; font-weight: bold; }}
.small {{ font-size: 0.85em; color: #666; }}
</style>
</head>
<body>
<h1>Port Scan Report - {title}</h1>
<p class="small">Generated: {generated}</p>
<table>
<thead>
<tr><th>Host</th><th>Port</th><th>Status</th><th>Description</th></tr>
</thead>
<tbody>
{rows}
</tbody>
</table>
</body>
</html>
"""

def generate_html_report(results, title):
    rows = []
    for host, port, status, desc in results:
        esc_desc = html.escape(desc or '')
        if status == 'open':
            cls = 'status-open'; label = 'Open'
        elif status == 'closed':
            cls = 'status-closed'; label = 'Closed'
        else:
            cls = 'status-invalid'; label = 'Invalid'
        rows.append(f"<tr><td>{html.escape(host)}</td><td>{port}</td><td class=\"{cls}\">{label}</td><td>{esc_desc}</td></tr>")
        
 #   return HTML_TEMPLATE.format(title=html.escape(title), generated=datetime.utcnow().isoformat() + "Z", rows="\n".join(rows))

 #   return HTML_TEMPLATE.format(title=html.escape(title), generated=datetime.now(UTC).isoformat().replace("+00:00", "Z"))
    
    return HTML_TEMPLATE.format(
    title=html.escape(title), generated=datetime.now(UTC).isoformat().replace("+00:00", "Z"), rows="\n".join(rows))


# ---------------------------
# Argument parsing and orchestration
# ---------------------------
def parse_ports_arg(s):
    """Parse comma-separated ports and ranges like '20-25,80,443'."""
    if not s:
        return []
    out = set()
    for token in s.split(','):
        token = token.strip()
        if not token:
            continue
        if '-' in token or '–' in token:
            parts = token.replace('–','-').split('-', 1)
            if parts[0].isdigit() and parts[1].isdigit():
                a, b = int(parts[0]), int(parts[1])
                if a > b:
                    a, b = b, a
                for p in range(max(0,a), min(65535,b)+1):
                    out.add(p)
        elif token.isdigit():
            p = int(token)
            if 0 <= p <= 65535:
                out.add(p)
    return sorted(out)

def main():
    parser = argparse.ArgumentParser(description="Port scanner with embedded port descriptions.")
    parser.add_argument('--targets', required=True, help='Target IP or CIDR (e.g., 192.168.1.10 or 192.168.1.0/28)')
    parser.add_argument('--ports', default='', help='Comma-separated ports or ranges (e.g., 20-25,80,443). If omitted, embedded mapping ports are used.')
    parser.add_argument('--timeout', type=float, default=1.0, help='Socket timeout in seconds (default 1.0)')
    parser.add_argument('--workers', type=int, default=200, help='Max concurrent worker threads (default 200)')
    parser.add_argument('--output', default='', help='Output HTML filename (default: scan_report_<timestamp>.html)')
    args = parser.parse_args()

    # Build target list
    targets = []
    try:
        if '/' in args.targets:
            net = ipaddress.ip_network(args.targets, strict=False)
            for ip in net.hosts():
                targets.append(str(ip))
        else:
            targets.append(args.targets)
    except Exception as e:
        print(f"Invalid target specification: {e}")
        return

    # Build ports list
    if args.ports:
        ports_to_scan = parse_ports_arg(args.ports)
        ports_map = {p: PORTS_TOP50.get(p, '') for p in ports_to_scan}
    else:
        ports_map = PORTS_TOP50.copy()
        ports_to_scan = sorted(ports_map.keys())

    if not ports_to_scan:
        print("No ports to scan. Provide --ports or ensure embedded mapping is not empty.")
        return

    print(f"Targets: {len(targets)} host(s). Ports to scan: {len(ports_to_scan)}. Workers: {args.workers}. Timeout: {args.timeout}s")

    tasks = [(host, p) for host in targets for p in ports_to_scan]
    results = []
    lock = threading.Lock()

    def worker(task):
        host, port = task
        status = scan_port(host, port, args.timeout)
        desc = ports_map.get(port, '')
        with lock:
            results.append((host, port, status, desc))

    start = time.time()
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as ex:
        ex.map(worker, tasks)
    elapsed = time.time() - start
    print(f"Scan completed in {elapsed:.2f}s. Entries: {len(results)}")

    # Sort results by host then port
    try:
        results.sort(key=lambda x: (ipaddress.ip_address(x[0]), x[1]))
    except Exception:
        results.sort(key=lambda x: (x[0], x[1]))

#    timestamp = datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')

    timestamp = datetime.now(UTC).strftime('%Y%m%dT%H%M%SZ')
    outname = args.output or f"scan_report_{timestamp}.html"
    html_text = generate_html_report(results, title=f"{args.targets} ports scan")
    with open(outname, 'w', encoding='utf-8') as f:
        f.write(html_text)
    print(f"Report written to {outname}")

if __name__ == '__main__':
    main()
