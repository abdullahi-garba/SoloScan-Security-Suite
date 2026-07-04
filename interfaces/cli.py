#!/usr/bin/env python3
"""
cli.py -- SoloScan Security Suite, standalone command-line interface.

This is a fully independent interface: every command here calls directly
into core/ (ScanEngine, PassiveEngine, WebVulnScanner, PacketSniffer,
IPManager, Honeypot, IntelEngine, database) and never imports or depends on
gui.py. You can use the whole toolkit from a terminal, a script, or a
headless/CI environment without ever launching the GUI.

Run `python cli.py --help` for the full command list, or
`python cli.py <command> --help` for one command's options.

Examples:
    python cli.py scan 192.168.1.5 --ports 22,80,1-100 --stealth
    python cli.py discover --subnet 10.0.0.0/24
    python cli.py osint example.com --export pdf
    python cli.py sniff --verbose
    python cli.py honeypot --port 22
    python cli.py db vulns --json
"""

import argparse
import json
import socket
import sys
import time
import ipaddress
from datetime import datetime

from core.engine import ScanEngine
from core.passive_recon import PassiveEngine
from core.vuln_scanner import WebVulnScanner
from core.defense import IPManager, Honeypot
from core.sniffer import PacketSniffer
from core.intel_engine import IntelEngine
from core import database as db
from core.utils import check_privileges, generate_pdf_report, export_results, get_default_subnet

# ==========================================
# OUTPUT HELPERS
# ==========================================
USE_COLOR = sys.stdout.isatty()
COLORS = {
    "green": "\033[92m", "red": "\033[91m", "orange": "\033[93m",
    "blue": "\033[94m", "grey": "\033[90m", "white": "\033[97m", "reset": "\033[0m",
}

def c(text, color):
    if not USE_COLOR or color not in COLORS:
        return text
    return f"{COLORS[color]}{text}{COLORS['reset']}"

def ok(msg):    print(c(f"[+] {msg}", "green"))
def info(msg):  print(c(f"[*] {msg}", "grey"))
def warn(msg):  print(c(f"[!] {msg}", "orange"))
def err(msg):   print(c(f"[-] {msg}", "red"))
def alert(msg): print(c(f"[!!] {msg}", "red"))

def emit(data, as_json=False):
    """Optionally dump raw structured data as JSON, e.g. for scripting/CI use."""
    if as_json:
        print(json.dumps(data, default=str, indent=2))
    return data

def parse_port_string(port_str):
    try:
        ports = []
        for part in port_str.split(","):
            part = part.strip()
            if "-" in part:
                start, end = map(int, part.split("-"))
                ports.extend(range(start, end + 1))
            else:
                ports.append(int(part))
        return sorted(set(ports))
    except Exception:
        return None

def export_data(data, fmt, title, filename, report_type):
    if not fmt:
        return
    if fmt == "pdf":
        path = generate_pdf_report(data, title=title, filename=filename)
    else:
        path = export_results(data if isinstance(data, list) else [data], report_type, fmt)
    if path:
        ok(f"Exported to {path}")
    else:
        err("Export failed.")


# ==========================================
# COMMAND HANDLERS
# ==========================================

def cmd_scan(args):
    ports = parse_port_string(args.ports)
    if ports is None:
        err("Invalid port format. Use e.g. 22,80,1-100"); sys.exit(1)

    info(f"Scanning {args.target} ({len(ports)} ports, {'stealth SYN' if args.stealth else 'TCP connect'})...")
    resolved_ip = ScanEngine.resolve_target(args.target)
    if resolved_ip:
        try: db.upsert_host(resolved_ip)
        except Exception: pass

    def on_port(port, status, service, banner):
        if status not in ("OPEN", "FILTERED"):
            return
        display = banner
        if status == "OPEN" and banner:
            vulns = WebVulnScanner.check_cve_heuristics(banner)
            if vulns:
                display = f"{banner}  |  {' / '.join(vulns)}"
                alert(f"{port}/tcp CVE MATCH: {' / '.join(vulns)}")
                if resolved_ip:
                    try: db.add_vulnerability(resolved_ip, "CVE Heuristic", "HIGH", f"Port {port}: {' / '.join(vulns)}")
                    except Exception: pass
        print(f"  [+] {port:<5}/tcp | {status:<8} | {service:<10} | {display}")
        if resolved_ip:
            try: db.add_port(resolved_ip, port, status, service, banner)
            except Exception: pass

    result = ScanEngine.stealth_syn_scan(args.target, ports, on_port) if args.stealth else ScanEngine.port_scan(args.target, ports, on_port)

    if result and isinstance(result, list) and result and "error" in result[0]:
        err(result[0]["error"]); sys.exit(1)

    ok(f"Scan complete. {len(result)} open/filtered port(s) found.")
    export_data(result, args.export, "Active Scan Report", "Active_Scan", "active_scan")
    emit(result, args.json)


def cmd_discover(args):
    subnet = args.subnet or get_default_subnet()
    info(f"Discovering devices on {subnet}...")

    def on_device(device):
        print(f"  [->] Device Found: IP = {device['ip']:<15} | MAC = {device['mac']}")
        try: db.upsert_host(device["ip"], mac=device["mac"])
        except Exception: pass

    result = ScanEngine.local_discovery(subnet, on_device)
    if result and isinstance(result, list) and result and "error" in result[0]:
        err(result[0]["error"]); sys.exit(1)
    ok(f"Discovery complete. {len(result)} device(s) found.")
    emit(result, args.json)


def cmd_traceroute(args):
    info(f"Tracing route to {args.target}...")
    hops = ScanEngine.network_traceroute(args.target)
    if hops and "error" in hops[0]:
        err(hops[0]["error"]); sys.exit(1)
    for h in hops:
        print(f"  Hop {h['hop']:<3} -> {h['ip']}")
    ok(f"Traceroute complete. {len(hops)} hop(s).")
    emit(hops, args.json)


def cmd_fingerprint(args):
    res = ScanEngine.fingerprint_os(args.target)
    if "error" in res:
        err(res["error"]); sys.exit(1)
    ok(f"{res['ip']}: likely {res['os_guess']} (TTL={res['ttl']})")
    try: db.upsert_host(res["ip"], os_guess=res["os_guess"])
    except Exception: pass
    emit(res, args.json)


def cmd_bruteforce(args):
    info(f"Testing default credentials against {args.target} ({args.service})...")
    res = ScanEngine.brute_force_login(args.target, args.service)
    if res.get("success"):
        alert(f"Valid credentials: {res['user']}:{res['password']}")
        try: db.add_credential(args.target, args.service, res["user"], res["password"])
        except Exception: pass
    else:
        ok("No common credentials succeeded.")
    emit(res, args.json)


def cmd_osint(args):
    target = args.domain
    info(f"Running OSINT pipeline against {target}...")
    findings = {}

    dns_info = PassiveEngine.get_dns_records(target)
    findings["dns"] = dns_info
    if "error" not in dns_info:
        resolved_ip = dns_info["Resolved IP"]
        ok(f"DNS: {resolved_ip} (aliases: {dns_info['Known Aliases']})")
        try:
            db.upsert_host(resolved_ip, hostname=target)
            db.add_osint_finding(target, "DNS", dns_info)
        except Exception: pass

        geo = PassiveEngine.get_ip_geolocation(resolved_ip)
        findings["geolocation"] = geo
        if "error" not in geo:
            ok(f"Geo: {geo.get('Country')}, {geo.get('City')} ({geo.get('ISP')})")
            try: db.add_osint_finding(target, "Geolocation", geo)
            except Exception: pass

        shodan = IntelEngine.query_shodan(resolved_ip)
        findings["shodan"] = shodan
        if "error" not in shodan:
            has_vulns = bool(shodan["vulnerabilities"])
            (alert if has_vulns else ok)(f"Shodan: org={shodan['organization']} os={shodan['os']} CVEs={', '.join(shodan['vulnerabilities']) or 'none'}")
            try:
                db.add_osint_finding(target, "Shodan", shodan)
                for cve in shodan["vulnerabilities"]:
                    db.add_vulnerability(resolved_ip, "Shodan", "HIGH", cve)
            except Exception: pass
        else:
            warn(f"Shodan: {shodan['error']}")

        findings["virustotal"] = {}
        for vt_label, vt_target, vt_type in (("ip", resolved_ip, "ip"), ("domain", target, "domain")):
            vt = IntelEngine.query_virustotal(vt_target, vt_type)
            findings["virustotal"][vt_label] = vt
            if "error" not in vt:
                printer = alert if vt["verdict"] == "MALICIOUS" else (warn if vt["verdict"] == "SUSPICIOUS" else ok)
                printer(f"VirusTotal ({vt_label}): {vt['verdict']} ({vt['malicious_hits']} malicious / {vt['suspicious_hits']} suspicious)")
                try:
                    db.add_osint_finding(target, f"VirusTotal ({vt_label})", vt)
                    if vt["verdict"] != "CLEAN":
                        db.add_vulnerability(vt_target, "VirusTotal", vt["verdict"], f"{vt['malicious_hits']} malicious / {vt['suspicious_hits']} suspicious engine hits")
                except Exception: pass
            else:
                warn(f"VirusTotal ({vt_label}): {vt['error']}")

        abuse = IntelEngine.query_abuseipdb(resolved_ip)
        findings["abuseipdb"] = abuse
        if "error" not in abuse:
            score = abuse["abuse_confidence_score"]
            (alert if score > 50 else (warn if score > 0 else ok))(f"AbuseIPDB: {score}% confidence, {abuse['total_reports']} report(s)")
            try:
                db.add_osint_finding(target, "AbuseIPDB", abuse)
                if score > 0:
                    db.add_vulnerability(resolved_ip, "AbuseIPDB", "HIGH" if score > 50 else "MEDIUM", f"Abuse confidence {score}%, {abuse['total_reports']} report(s)")
            except Exception: pass
        else:
            warn(f"AbuseIPDB: {abuse['error']}")

        reverse_ip = IntelEngine.query_hackertarget_reverse_ip(resolved_ip)
        findings["reverse_ip"] = reverse_ip
        hosted = reverse_ip.get("hosted_domains") if "error" not in reverse_ip else None
        if hosted:
            ok(f"Reverse IP: {len(hosted)} other domain(s) on {resolved_ip}")
            try: db.add_osint_finding(target, "Reverse IP Lookup", reverse_ip)
            except Exception: pass
    else:
        err(dns_info["error"])

    whois = PassiveEngine.get_whois(target)
    findings["whois"] = whois
    ok(f"WHOIS: {whois[:150]}...")
    try: db.add_osint_finding(target, "WHOIS", whois)
    except Exception: pass

    subs = PassiveEngine.get_subdomains(target)
    findings["subdomains"] = subs
    if subs:
        ok(f"Subdomains: {', '.join(subs[:10])}")
        try: db.add_osint_finding(target, "Subdomains", subs)
        except Exception: pass

    headers_audit = WebVulnScanner.analyze_website(target)
    findings["header_audit"] = headers_audit
    if headers_audit and "error" not in headers_audit[0]:
        for v in headers_audit:
            warn(f"[{v.get('severity')}] {v.get('vulnerability')}")
            if v.get("severity", "Info") != "Info":
                try: db.add_vulnerability(target, "Header Audit", v.get("severity", "MEDIUM"), v.get("vulnerability", ""))
                except Exception: pass

    fuzz = WebVulnScanner.fuzz_directories(target)
    findings["fuzzing"] = fuzz
    if fuzz:
        for f in fuzz:
            ok(f"Found path: {f['path']} ({f['status']})")
        try: db.add_osint_finding(target, "Fuzzing Hits", fuzz)
        except Exception: pass

    print()
    ok("OSINT pipeline complete.")
    export_data([{"category": k, "data": v} for k, v in findings.items()], args.export, "Passive OSINT Report", "Passive_OSINT", "osint")
    emit(findings, args.json)


def cmd_resolve(args):
    clean = args.domain.replace("https://", "").replace("http://", "").split("/")[0]
    try:
        ip = socket.gethostbyname(clean)
        ok(f"{clean} -> {ip}")
        emit({"domain": clean, "ip": ip}, args.json)
    except Exception:
        err(f"Failed to resolve {clean}."); sys.exit(1)


def cmd_subnet(args):
    try:
        net = ipaddress.ip_network(args.cidr, strict=False)
        hosts = list(net.hosts())
        first, last = (hosts[0], hosts[-1]) if hosts else ("N/A", "N/A")
        usable = net.num_addresses - 2 if net.num_addresses > 2 else 0
        ok(f"Network: {net.network_address}  Broadcast: {net.broadcast_address}")
        ok(f"Netmask: {net.netmask}  Usable Hosts: {usable}  Range: {first} -> {last}")
        emit({"network": str(net.network_address), "broadcast": str(net.broadcast_address),
              "netmask": str(net.netmask), "usable_hosts": usable, "first": str(first), "last": str(last)}, args.json)
    except Exception as ex:
        err(f"Invalid CIDR: {ex}"); sys.exit(1)


def cmd_whoami(args):
    ip = IPManager.get_current_ip()
    ok(f"Local IP: {ip}")
    emit({"local_ip": ip}, args.json)


def cmd_privileges(args):
    os_name, is_admin = check_privileges()
    ok(f"OS: {os_name} | Elevated: {is_admin}")
    emit({"os": os_name, "elevated": is_admin}, args.json)


def cmd_sniff(args):
    """Runs the IDS sniffer in the foreground. Blocks until Ctrl+C."""
    sniffer = PacketSniffer()

    def log_callback(msg, color_str="WHITE"):
        if args.verbose or color_str in ("RED", "ORANGE"):
            color_map = {"RED": "red", "ORANGE": "orange", "GREEN": "green", "BLUE": "blue", "GREY": "grey", "WHITE": "white"}
            print(c(msg, color_map.get(color_str, "white")))

    info("Sniffer starting. Press Ctrl+C to stop.")
    if not args.verbose:
        info("Showing alerts only -- use --verbose to see all traffic.")
    try:
        sniffer.start(log_callback)
    except KeyboardInterrupt:
        pass
    finally:
        sniffer.stop()
        ok("Sniffer stopped.")


def cmd_testtraffic(args):
    TEST_MODES = {
        "syn": (ScanEngine.ids_self_test_syn_flood, "SYN Flood"),
        "icmp": (ScanEngine.ids_self_test_icmp_flood, "ICMP Flood"),
        "portscan": (ScanEngine.ids_self_test_port_scan, "Port Scan"),
    }
    test_fn, label = TEST_MODES[args.mode]
    warn("This sends real (but harmless, loopback-only) packets to 127.0.0.1.")
    warn("Run 'python cli.py sniff' in another terminal first to see the alert.")
    res = test_fn()
    if "error" in res:
        err(res["error"]); sys.exit(1)
    ok(f"{label} self-test: sent {res['sent']} packet(s) to 127.0.0.1.")
    emit(res, args.json)


def cmd_honeypot(args):
    """Runs the honeypot listener in the foreground. Blocks until Ctrl+C."""
    hp = Honeypot(port=args.port)

    def log_callback(msg):
        print(c(msg, "red" if "INTRUSION" in msg else "green"))

    if not hp.start(log_callback):
        err("Failed to start honeypot (port may be in use, or insufficient privileges)."); sys.exit(1)

    info(f"Honeypot active on port {args.port}. Press Ctrl+C to stop.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        hp.stop()
        ok("Honeypot stopped.")


def cmd_monitor(args):
    """Polls a target's key ports and alerts on state changes. Blocks until Ctrl+C."""
    info(f"Monitoring {args.target} every {args.interval}s. Press Ctrl+C to stop.")
    last_state = {}
    try:
        while True:
            current_scan = ScanEngine.port_scan(args.target, [21, 22, 80, 443, 3306, 3389, 8080], workers=10)
            current_state = {str(p["port"]): p["status"] for p in current_scan if "port" in p}
            timestamp = datetime.now().strftime("%H:%M:%S")
            if last_state:
                for port, status in current_state.items():
                    old_status = last_state.get(port, "CLOSED")
                    if status != old_status:
                        alert(f"[{timestamp}] Port {port} changed from {old_status} -> {status}")
            else:
                info(f"[{timestamp}] Baseline established.")
            last_state = current_state
            time.sleep(args.interval)
    except KeyboardInterrupt:
        ok("Monitoring stopped.")


def cmd_setip(args):
    res = IPManager.change_windows_ip(args.adapter, args.ip, args.mask, args.gateway)
    (ok if "Success" in res else err)(res)
    emit({"result": res}, args.json)
    if "Success" not in res:
        sys.exit(1)


def cmd_simulate(args):
    """SIMULATED ONLY -- no networking code of any kind. Prints scripted fake output."""
    warn("[SIMULATED] No real network traffic will be sent.")
    info(f"[SIM] Initializing simulated flood against {args.target}:{args.port} ...")
    time.sleep(0.3)
    step, sent = max(1, args.count // 10), 0
    while sent < args.count:
        sent = min(args.count, sent + step)
        ok(f"[SIM] Packets dispatched: {sent}/{args.count} (fake, 0 bytes sent)")
        time.sleep(0.1)
    warn("[SIM] Simulation complete. Reminder: cosmetic only, nothing was sent.")


def cmd_db(args):
    sub = args.db_command
    if sub == "hosts":
        hosts = db.get_hosts()
        ok(f"{len(hosts)} host(s):")
        for h in hosts[:50]:
            print(f"  {h['ip']:<16} MAC={h['mac'] or '-':<18} OS={h['os_guess'] or '-':<20} last_seen={h['last_seen']}")
        emit(hosts, args.json)
    elif sub == "ports":
        ports = db.get_ports(args.host)
        ok(f"{len(ports)} port record(s):")
        for p in ports[:50]:
            print(f"  {p['host_ip']:<16} {p['port']:<6} {p['status']:<8} {p['service']}")
        emit(ports, args.json)
    elif sub == "vulns":
        vulns = db.get_vulnerabilities()
        ok(f"{len(vulns)} vulnerability record(s):")
        for v in vulns[:50]:
            print(f"  [{v['severity']}] {v['target']} ({v['source']}): {v['description']}")
        emit(vulns, args.json)
    elif sub == "creds":
        creds = db.get_credentials()
        ok(f"{len(creds)} credential record(s):")
        for cred in creds[:50]:
            print(f"  {cred['target']:<16} {cred['service']:<6} {cred['username']}:{cred['password']}")
        emit(creds, args.json)
    elif sub == "osint":
        findings = db.get_osint_findings(args.target)
        ok(f"{len(findings)} OSINT finding(s):")
        for f in findings[:50]:
            print(f"  {f['target']:<24} {f['category']:<20} {f['discovered_at']}")
        emit(findings, args.json)
    elif sub == "search":
        res = db.search_all(args.term)
        ok(f"'{args.term}': {len(res['hosts'])} host(s), {len(res['ports'])} port(s), {len(res['vulnerabilities'])} vuln(s), {len(res['credentials'])} credential(s)")
        emit(res, args.json)
    elif sub == "stats":
        stats = db.get_stats()
        ok(" | ".join(f"{k}: {v}" for k, v in stats.items()))
        emit(stats, args.json)
    elif sub == "clear":
        if not args.yes:
            confirm = input("This permanently deletes everything in the database. Type 'yes' to confirm: ")
            if confirm.strip().lower() != "yes":
                warn("Cancelled."); return
        db.clear_all()
        ok("Database cleared.")


# ==========================================
# ARGUMENT PARSER
# ==========================================
def build_parser():
    parser = argparse.ArgumentParser(
        description="SoloScan Security Suite -- standalone CLI (fully independent of the GUI).",
        epilog="Run '<this> <command> --help' for a specific command's options.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    # Shared --json flag for every result-returning (non-blocking) command
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--json", action="store_true", help="Also emit the raw result as JSON (for scripting)")

    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("scan", parents=[common], help="Port scan a target")
    p.add_argument("target")
    p.add_argument("--ports", default="21,22,23,25,53,80,443,8080", help="Comma list / ranges, e.g. 22,80,1-100")
    p.add_argument("--stealth", action="store_true", help="Use stealth SYN scan instead of TCP connect (Admin/root required)")
    p.add_argument("--export", choices=["json", "csv", "pdf"], help="Also save results to reports/")
    p.set_defaults(func=cmd_scan)

    p = sub.add_parser("discover", parents=[common], help="ARP-sweep a subnet for live hosts")
    p.add_argument("--subnet", help="CIDR range, e.g. 192.168.1.0/24 (defaults to your local subnet)")
    p.set_defaults(func=cmd_discover)

    p = sub.add_parser("traceroute", parents=[common], help="Trace the network hops to a target")
    p.add_argument("target")
    p.set_defaults(func=cmd_traceroute)

    p = sub.add_parser("fingerprint", parents=[common], help="Passive TTL-based OS guess")
    p.add_argument("target")
    p.set_defaults(func=cmd_fingerprint)

    p = sub.add_parser("bruteforce", parents=[common], help="Test default credentials against a service")
    p.add_argument("target")
    p.add_argument("--service", choices=["ftp", "http"], default="ftp")
    p.set_defaults(func=cmd_bruteforce)

    p = sub.add_parser("osint", parents=[common], help="Full passive OSINT + threat-intel pipeline")
    p.add_argument("domain")
    p.add_argument("--export", choices=["json", "csv", "pdf"], help="Also save results to reports/")
    p.set_defaults(func=cmd_osint)

    p = sub.add_parser("resolve", parents=[common], help="Resolve a domain to an IP address")
    p.add_argument("domain")
    p.set_defaults(func=cmd_resolve)

    p = sub.add_parser("subnet", parents=[common], help="Subnet/CIDR calculator")
    p.add_argument("cidr")
    p.set_defaults(func=cmd_subnet)

    p = sub.add_parser("whoami", parents=[common], help="Show this machine's current local IP")
    p.set_defaults(func=cmd_whoami)

    p = sub.add_parser("privileges", parents=[common], help="Show OS and admin/root elevation status")
    p.set_defaults(func=cmd_privileges)

    p = sub.add_parser("sniff", help="Run the IDS packet sniffer in the foreground (Ctrl+C to stop)")
    p.add_argument("--verbose", action="store_true", help="Show all traffic, not just alerts")
    p.set_defaults(func=cmd_sniff)

    p = sub.add_parser("testtraffic", parents=[common], help="Loopback-only self-test for one IDS detector")
    p.add_argument("mode", nargs="?", choices=["syn", "icmp", "portscan"], default="syn")
    p.set_defaults(func=cmd_testtraffic)

    p = sub.add_parser("honeypot", help="Run the honeypot listener in the foreground (Ctrl+C to stop)")
    p.add_argument("--port", type=int, default=22)
    p.set_defaults(func=cmd_honeypot)

    p = sub.add_parser("monitor", help="Poll a target's key ports, alert on changes (Ctrl+C to stop)")
    p.add_argument("target")
    p.add_argument("--interval", type=int, default=10, help="Seconds between polls (default: 10)")
    p.set_defaults(func=cmd_monitor)

    p = sub.add_parser("setip", parents=[common], help="Change a network adapter's static IP (Windows, Admin required)")
    p.add_argument("adapter")
    p.add_argument("ip")
    p.add_argument("--mask", default="255.255.255.0")
    p.add_argument("--gateway", default="192.168.1.1")
    p.set_defaults(func=cmd_setip)

    p = sub.add_parser("simulate", help="SIMULATED ONLY -- cosmetic flood-console demo, sends nothing real")
    p.add_argument("--target", default="10.0.0.5")
    p.add_argument("--port", default="80")
    p.add_argument("--count", type=int, default=300)
    p.set_defaults(func=cmd_simulate)

    p = sub.add_parser("db", help="Query or manage the persisted database")
    db_sub = p.add_subparsers(dest="db_command", required=True)
    db_sub.add_parser("hosts", parents=[common], help="List discovered hosts")
    pp = db_sub.add_parser("ports", parents=[common], help="List discovered ports"); pp.add_argument("host", nargs="?", help="Filter by host IP")
    db_sub.add_parser("vulns", parents=[common], help="List discovered vulnerabilities")
    db_sub.add_parser("creds", parents=[common], help="List harvested credentials")
    po = db_sub.add_parser("osint", parents=[common], help="List OSINT findings"); po.add_argument("target", nargs="?", help="Filter by target")
    ps = db_sub.add_parser("search", parents=[common], help="Search all tables for a substring"); ps.add_argument("term")
    db_sub.add_parser("stats", parents=[common], help="Show record counts per table")
    pc = db_sub.add_parser("clear", help="Wipe the entire database"); pc.add_argument("--yes", action="store_true", help="Skip the confirmation prompt")
    p.set_defaults(func=cmd_db)

    return parser


def run_cli():
    """Entry point imported by main.py (`from interfaces.cli import run_cli`).
    Also works standalone: `python interfaces/cli.py <command> ...`"""
    parser = build_parser()
    args = parser.parse_args()

    try:
        db.init_db()
    except Exception as ex:
        warn(f"Database init failed, persistence disabled this run: {ex}")

    args.func(args)


if __name__ == "__main__":
    run_cli()