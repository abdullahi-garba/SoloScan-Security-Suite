import flet as ft
import threading
import time
import random
import ipaddress
import socket
import shlex
import os
import platform
from datetime import datetime

# Import Custom Core Modules
from core.engine import ScanEngine
from core.passive_recon import PassiveEngine
from core.vuln_scanner import WebVulnScanner
from core.defense import IPManager, Honeypot
from core.sniffer import PacketSniffer
from core.utils import SCAN_MODES, export_results, generate_pdf_report, check_privileges

def get_default_subnet():
    """Helper to calculate the host's /24 subnet for the discovery tool."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return f"{s.getsockname()[0].rsplit('.', 1)[0]}.0/24"
    except Exception: 
        return "192.168.1.0/24"

# Instantiate global tools so they persist across tab switches
global_honeypot = Honeypot(port=22)
sniffer_instance = PacketSniffer()

def run_gui():
    def main(page: ft.Page):
        # ----------------------------------------------------
        # WINDOW CONFIGURATION
        # ----------------------------------------------------
        page.title = "SoloScan Security Suite PRO"
        page.theme_mode = ft.ThemeMode.DARK
        page.adaptive = True  # Lets supported controls render natively per-platform (Android/iOS/desktop)
        page.window_width = 1350
        page.window_height = 800
        page.padding = 0  # Remove padding for edge-to-edge splash screen

        # ==========================================
        # 🎬 PHASE 1: SPLASH SCREEN
        # ==========================================
        splash_screen = ft.Container(
            expand=True,
            bgcolor="#050505", # Deep dark background
            alignment=ft.alignment.center,
            content=ft.Column(
                alignment=ft.MainAxisAlignment.CENTER,
                horizontal_alignment=ft.CrossAxisAlignment.CENTER,
                controls=[
                    ft.Lottie(
                        src="https://lottie.host/c5ecfd06-d250-4821-ba30-74e2dce4eb87/n3U9Z5w25X.json", 
                        width=300, 
                        height=300, 
                        repeat=True, 
                        animate=True
                    ),
                    ft.Text("SoloScan", size=55, weight="bold", color=ft.colors.GREEN_ACCENT_700, font_family="Consolas"),
                    ft.Text("S E C U R I T Y   S U I T E   P R O", size=18, weight="w400", color=ft.colors.WHITE),
                    ft.Container(height=30),
                    
                    ft.ProgressBar(width=400, color=ft.colors.GREEN_ACCENT_700, bgcolor=ft.colors.GREY_900),
                    ft.Text("Initializing Core Modules & Engines...", size=12, color=ft.colors.GREY_500, italic=True),
                    
                    ft.Container(height=80),
                    ft.Text("built by GarbaTheAnalyst, The Analyst Consultancy, ©2026. SoloScan™", size=12, color=ft.colors.GREY_600, italic=True)
                ]
            )
        )
        
        # Display the splash screen
        page.add(splash_screen)
        page.update()
        
        # Hold the splash screen for 4.5 seconds to simulate loading
        time.sleep(4.5)
        
        # Clear the splash screen
        page.controls.clear()
        page.padding = 10 
        page.update()

        # ==========================================
        # ⚖️ PHASE 2: EULA / TERMS & CONDITIONS
        # ==========================================
        def show_eula():
            def accept_eula(e):
                page.controls.clear()
                build_main_interface()

            def decline_eula(e):
                # Forcefully terminate the application if declined
                os._exit(0) 

            eula_text = """
### END USER LICENSE AGREEMENT AND DISCLAIMER OF LIABILITY

**By clicking "I AGREE & CONTINUE", you explicitly agree to the following terms:**

**1. Authorized Use Only** This Software is engineered strictly for academic research, authorized penetration testing, and defensive system auditing. You may only execute active scans, brute-force modules, and packet interception against networks, endpoints, and domains for which you have explicit, documented, and legal authorization to test.

**2. Prohibition of Malicious Use** You shall not use the Software to conduct unauthorized denial-of-service (DoS) attacks, intercept third-party communications without consent, bypass access controls, or facilitate any activity that violates local, state, national, or international computer misuse and wiretapping laws.

**3. Disclaimer of Warranties** The Software is provided "AS IS", without warranty of any kind, express or implied, including but not limited to the warranties of merchantability, fitness for a particular purpose, and non-infringement.

**4. Limitation of Liability** Under no circumstances shall the developer (Garba the analyst), The Analyst Consultancy, or Newgate University Minna be held liable for any direct, indirect, incidental, special, exemplary, or consequential damages arising in any way out of the use, misuse, or inability to use this Software.
            """

            eula_container = ft.Container(
                expand=True,
                padding=40,
                content=ft.Column([
                    ft.Row([
                        ft.Icon(ft.icons.WARNING_AMBER_ROUNDED, color=ft.colors.RED_400, size=40), 
                        ft.Text("RESTRICTED SYSTEM: AUTHORIZED USE ONLY", size=24, weight="bold", color=ft.colors.RED_400)
                    ]),
                    ft.Divider(color=ft.colors.RED_900),
                    ft.Container(
                        content=ft.Markdown(eula_text, selectable=True),
                        expand=True,
                        padding=20,
                        border=ft.border.all(1, ft.colors.GREY_800),
                        border_radius=5,
                        bgcolor="#0A0A0A"
                    ),
                    ft.Container(height=10),
                    ft.Row([
                        ft.ElevatedButton("DECLINE & EXIT", icon=ft.icons.CLOSE, on_click=decline_eula, bgcolor=ft.colors.RED_900, color=ft.colors.WHITE),
                        ft.ElevatedButton("I AGREE & CONTINUE", icon=ft.icons.CHECK, on_click=accept_eula, bgcolor=ft.colors.GREEN_700, color=ft.colors.WHITE)
                    ], alignment=ft.MainAxisAlignment.END)
                ])
            )
            page.add(eula_container)
            page.update()

        # ==========================================
        # 🚀 PHASE 3: THE MAIN APPLICATION BUILDER
        # ==========================================
        def build_main_interface():
            gui_area = ft.Container(expand=5, padding=10)
            page.client_storage.set("port_data", [])
            page.client_storage.set("passive_data", [])

            def make_collapsible(title, content, initially_expanded=False):
                """Lightweight, version-safe collapsible section: click the header to
                show/hide the body. Used to keep dense views from feeling cluttered."""
                body = ft.Container(content=content, visible=initially_expanded, padding=ft.padding.only(top=8, bottom=4))
                chevron = ft.Icon(ft.icons.KEYBOARD_ARROW_DOWN if initially_expanded else ft.icons.KEYBOARD_ARROW_RIGHT, color=ft.colors.BLUE_200)

                def toggle(e):
                    body.visible = not body.visible
                    chevron.name = ft.icons.KEYBOARD_ARROW_DOWN if body.visible else ft.icons.KEYBOARD_ARROW_RIGHT
                    page.update()

                header = ft.Container(
                    content=ft.Row([chevron, ft.Text(title, weight="bold", color=ft.colors.BLUE_200)]),
                    on_click=toggle, padding=ft.padding.symmetric(vertical=4), ink=True
                )
                return ft.Column([header, body], spacing=0)

            # ----------------------------------------------------
            # EMBEDDED CLI TERMINAL (Right Side Panel)
            # ----------------------------------------------------
            cli_output = ft.ListView(expand=True, auto_scroll=True, spacing=2)
            
            def print_cli(text, color=ft.colors.WHITE):
                cli_output.controls.append(ft.Text(text, color=color, font_family="Consolas", size=12, selectable=True))
                page.update()

            def parse_port_string(port_str):
                """Shared port-range parser used by both the GUI scan form and the 'scan' terminal command."""
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

            def cli_sniffer_log(msg, color_str="WHITE"):
                # Only surface real alerts (RED/ORANGE) in the compact embedded terminal --
                # routine per-packet traffic belongs on the dedicated Sniffer tab panel.
                if color_str in ("RED", "ORANGE"):
                    print_cli(f"SNIFFER: {msg}", ft.colors.RED_400 if color_str == "RED" else ft.colors.ORANGE_400)

            HELP_TEXT = {
                "scan":        "scan <target> [ports] [--stealth]   Port scan. e.g. scan 192.168.1.5 22,80,1-100 --stealth",
                "discover":    "discover [subnet]                   ARP-sweep a /24 for live hosts (defaults to your local subnet)",
                "traceroute":  "traceroute <target>                 Trace the network hops to a target",
                "bruteforce":  "bruteforce <target> [ftp|http]      Test default credentials against a service (default: ftp)",
                "osint":       "osint <domain>                      Run the full passive OSINT pipeline",
                "resolve":     "resolve <domain>                    Resolve a domain to an IP address",
                "subnet":      "subnet <CIDR>                       Calculate network/broadcast/usable host range",
                "whoami":      "whoami | ip                         Show this machine's current local IP",
                "privileges":  "privileges                           Show OS and admin/root elevation status",
                "sniff":       "sniff <start|stop>                  Start or stop the IDS packet sniffer",
                "testtraffic": "testtraffic                         Loopback-only SYN burst to test the sniffer's flood alert",
                "honeypot":    "honeypot <start|stop> [port]        Deploy or stop the intrusion-detection honeypot",
                "setip":       "setip <adapter> <ip> [mask] [gw]    Change a network adapter's static IP (Windows, Admin required)",
                "simulate":    "simulate [target] [port] [count]    SIMULATED ONLY -- prints a fake flood log, sends nothing real",
                "clear":       "clear                               Clear the terminal output",
                "help":        "help [command]                      List all commands, or detailed syntax for one",
            }

            def print_help(specific=None):
                if specific and specific.lower() in HELP_TEXT:
                    print_cli(HELP_TEXT[specific.lower()], ft.colors.GREEN_ACCENT); return
                print_cli("Available commands:", ft.colors.BLUE_200)
                for line in HELP_TEXT.values():
                    print_cli(f"  {line}", ft.colors.WHITE)

            def execute_cli_command(e):
                cmd_str = cli_input.value.strip()
                if not cmd_str: return
                print_cli(f"PS> {cmd_str}", ft.colors.BLUE_200)
                cli_input.value = ""
                page.update()

                try:
                    args = shlex.split(cmd_str)
                except ValueError:
                    print_cli("[-] Error parsing command. Check your quotes.", ft.colors.RED_400)
                    return
                if not args:
                    return

                command = args[0].lower()
                rest = args[1:]
                arg = lambda i, default=None: rest[i] if i < len(rest) else default

                try:
                    if command == "help":
                        print_help(arg(0))

                    elif command == "clear":
                        cli_output.controls.clear(); page.update()

                    elif command == "scan":
                        if not rest:
                            print_cli("[-] Usage: scan <target> [ports] [--stealth]", ft.colors.RED_400); return
                        target = rest[0]
                        stealth = "--stealth" in rest
                        port_arg = next((a for a in rest[1:] if not a.startswith("--")), None)
                        ports = parse_port_string(port_arg or "21,22,23,25,53,80,443,8080")
                        if ports is None:
                            print_cli("[-] Invalid port format. Use e.g. 22,80,1-100", ft.colors.RED_400); return

                        print_cli(f"[*] Scanning {target} ({len(ports)} ports, {'stealth SYN' if stealth else 'TCP connect'})...", ft.colors.GREY_400)

                        def cli_on_port(port, status, service, banner):
                            if status in ("OPEN", "FILTERED"):
                                print_cli(f"  [+] {port:<5}/tcp | {status:<8} | {service:<10} | {banner}", ft.colors.GREEN_ACCENT if status == "OPEN" else ft.colors.ORANGE_400)

                        def run():
                            res = ScanEngine.stealth_syn_scan(target, ports, cli_on_port) if stealth else ScanEngine.port_scan(target, ports, cli_on_port)
                            if res and isinstance(res, list) and res and "error" in res[0]:
                                print_cli(f"[-] {res[0]['error']}", ft.colors.RED_400)
                            else:
                                print_cli(f"[*] Scan complete. {len(res)} open/filtered port(s) found.", ft.colors.GREEN_ACCENT)
                        threading.Thread(target=run, daemon=True).start()

                    elif command == "discover":
                        subnet = arg(0, get_default_subnet())
                        print_cli(f"[*] Discovering devices on {subnet}...", ft.colors.GREY_400)

                        def cli_on_device(d):
                            print_cli(f"  [->] {d['ip']:<15} | {d['mac']}", ft.colors.GREEN_ACCENT)

                        def run():
                            res = ScanEngine.local_discovery(subnet, cli_on_device)
                            if res and isinstance(res, list) and res and "error" in res[0]:
                                print_cli(f"[-] {res[0]['error']}", ft.colors.RED_400)
                            else:
                                print_cli(f"[*] Discovery complete. {len(res)} device(s) found.", ft.colors.GREEN_ACCENT)
                        threading.Thread(target=run, daemon=True).start()

                    elif command == "traceroute":
                        if not rest:
                            print_cli("[-] Usage: traceroute <target>", ft.colors.RED_400); return
                        target = rest[0]

                        def run():
                            hops = ScanEngine.network_traceroute(target)
                            if hops and "error" in hops[0]:
                                print_cli(f"[-] {hops[0]['error']}", ft.colors.RED_400)
                            else:
                                for h in hops:
                                    print_cli(f"  Hop {h['hop']:<3} -> {h['ip']}", ft.colors.WHITE)
                                print_cli(f"[*] Traceroute complete. {len(hops)} hop(s).", ft.colors.GREEN_ACCENT)
                        threading.Thread(target=run, daemon=True).start()

                    elif command == "bruteforce":
                        if not rest:
                            print_cli("[-] Usage: bruteforce <target> [ftp|http]", ft.colors.RED_400); return
                        target, service = rest[0], arg(1, "ftp")

                        def run():
                            res = ScanEngine.brute_force_login(target, service)
                            if res.get("success"):
                                print_cli(f"[!!] Valid credentials: {res['user']}:{res['password']}", ft.colors.RED_400)
                            else:
                                print_cli("[*] No common credentials succeeded.", ft.colors.GREEN_ACCENT)
                        threading.Thread(target=run, daemon=True).start()

                    elif command == "osint":
                        if not rest:
                            print_cli("[-] Usage: osint <domain>", ft.colors.RED_400); return
                        target = rest[0]

                        def run():
                            dns_info = PassiveEngine.get_dns_records(target)
                            if "error" not in dns_info:
                                print_cli(f"[+] DNS: {dns_info['Resolved IP']} (aliases: {dns_info['Known Aliases']})", ft.colors.GREEN_ACCENT)
                                geo = PassiveEngine.get_ip_geolocation(dns_info["Resolved IP"])
                                if "error" not in geo:
                                    print_cli(f"[+] Geo: {geo.get('Country')}, {geo.get('City')} ({geo.get('ISP')})", ft.colors.GREEN_ACCENT)
                            else:
                                print_cli(f"[-] {dns_info['error']}", ft.colors.RED_400)
                            print_cli(f"[+] WHOIS: {PassiveEngine.get_whois(target)[:150]}...", ft.colors.GREEN_ACCENT)
                            subs = PassiveEngine.get_subdomains(target)
                            if subs: print_cli(f"[+] Subdomains: {', '.join(subs[:10])}", ft.colors.GREEN_ACCENT)
                            for v in WebVulnScanner.analyze_website(target):
                                if "error" not in v:
                                    print_cli(f"  [!] [{v.get('severity')}] {v.get('vulnerability')}", ft.colors.ORANGE_400)
                            for f in WebVulnScanner.fuzz_directories(target):
                                print_cli(f"  [+] Found path: {f['path']} ({f['status']})", ft.colors.GREEN_ACCENT)
                            print_cli("[*] OSINT pipeline complete.", ft.colors.GREEN_ACCENT)
                        threading.Thread(target=run, daemon=True).start()

                    elif command == "resolve":
                        if not rest:
                            print_cli("[-] Usage: resolve <domain>", ft.colors.RED_400); return
                        clean = rest[0].replace("https://", "").replace("http://", "").split("/")[0]
                        try:
                            print_cli(f"[+] {clean} -> {socket.gethostbyname(clean)}", ft.colors.GREEN_ACCENT)
                        except Exception:
                            print_cli(f"[-] Failed to resolve {clean}.", ft.colors.RED_400)

                    elif command == "subnet":
                        if not rest:
                            print_cli("[-] Usage: subnet <CIDR>", ft.colors.RED_400); return
                        try:
                            net = ipaddress.ip_network(rest[0], strict=False)
                            hosts = list(net.hosts())
                            first, last = (hosts[0], hosts[-1]) if hosts else ("N/A", "N/A")
                            usable = net.num_addresses - 2 if net.num_addresses > 2 else 0
                            print_cli(f"[+] Network: {net.network_address}  Broadcast: {net.broadcast_address}", ft.colors.GREEN_ACCENT)
                            print_cli(f"[+] Netmask: {net.netmask}  Usable Hosts: {usable}  Range: {first} -> {last}", ft.colors.GREEN_ACCENT)
                        except Exception as ex:
                            print_cli(f"[-] Invalid CIDR: {ex}", ft.colors.RED_400)

                    elif command in ("whoami", "ip"):
                        print_cli(f"[+] Local IP: {IPManager.get_current_ip()}", ft.colors.GREEN_ACCENT)

                    elif command == "privileges":
                        os_name, is_admin = check_privileges()
                        print_cli(f"[+] OS: {os_name} | Elevated: {is_admin}", ft.colors.GREEN_ACCENT)

                    elif command == "sniff":
                        sub = (arg(0) or "").lower()
                        if sub == "start":
                            if sniffer_instance.running:
                                print_cli("[-] Sniffer is already running.", ft.colors.ORANGE_400)
                            else:
                                threading.Thread(target=sniffer_instance.start, args=(cli_sniffer_log,), daemon=True).start()
                                print_cli("[*] Sniffer started (open the Sniffer tab to view live traffic).", ft.colors.GREEN_ACCENT)
                        elif sub == "stop":
                            if sniffer_instance.running:
                                sniffer_instance.stop(); print_cli("[*] Sniffer stopped.", ft.colors.GREEN_ACCENT)
                            else:
                                print_cli("[-] Sniffer is not running.", ft.colors.ORANGE_400)
                        else:
                            print_cli("[-] Usage: sniff <start|stop>", ft.colors.RED_400)

                    elif command == "testtraffic":
                        if not sniffer_instance.running:
                            print_cli("[-] Start the sniffer first ('sniff start') so it can observe the test traffic.", ft.colors.ORANGE_400); return

                        def run():
                            test_ports = list(range(20000, 20070))
                            res = ScanEngine.stealth_syn_scan("127.0.0.1", test_ports)
                            if res and isinstance(res, list) and res and "error" in res[0]:
                                print_cli(f"[-] {res[0]['error']}", ft.colors.RED_400)
                            else:
                                print_cli(f"[*] Sent {len(test_ports)} real SYN packets to 127.0.0.1. Watch for a SYN Flood alert.", ft.colors.GREEN_ACCENT)
                        threading.Thread(target=run, daemon=True).start()

                    elif command == "honeypot":
                        sub = (arg(0) or "").lower()
                        if sub == "start":
                            try: port = int(arg(1, 22))
                            except Exception: port = 22
                            if global_honeypot.is_active:
                                print_cli("[-] Honeypot is already active.", ft.colors.ORANGE_400)
                            else:
                                global_honeypot.port = port
                                if global_honeypot.start(lambda m: print_cli(f"HONEYPOT: {m}", ft.colors.RED_400 if "INTRUSION" in m else ft.colors.GREEN_ACCENT)):
                                    print_cli(f"[*] Honeypot deployed on port {port}.", ft.colors.GREEN_ACCENT)
                        elif sub == "stop":
                            if global_honeypot.is_active:
                                global_honeypot.stop(); print_cli("[*] Honeypot stopped.", ft.colors.GREEN_ACCENT)
                            else:
                                print_cli("[-] Honeypot is not active.", ft.colors.ORANGE_400)
                        else:
                            print_cli("[-] Usage: honeypot <start|stop> [port]", ft.colors.RED_400)

                    elif command == "setip":
                        if len(rest) < 2:
                            print_cli("[-] Usage: setip <adapter> <ip> [mask] [gateway]", ft.colors.RED_400); return
                        res = IPManager.change_windows_ip(rest[0], rest[1], arg(2, "255.255.255.0"), arg(3, "192.168.1.1"))
                        print_cli(f"[*] {res}", ft.colors.GREEN_ACCENT if "Success" in res else ft.colors.RED_400)

                    elif command == "simulate":
                        # Cosmetic only -- mirrors the Sim DoS tab. No sockets, no real traffic.
                        target, port = arg(0, "10.0.0.5"), arg(1, "80")
                        try: count = max(1, min(int(arg(2, "300")), 5000))
                        except Exception: count = 300
                        print_cli("[SIMULATED] No real network traffic will be sent.", ft.colors.ORANGE_400)

                        def run():
                            print_cli(f"[*] [SIM] Initializing simulated flood against {target}:{port} ...", ft.colors.WHITE)
                            time.sleep(0.3)
                            step, sent = max(1, count // 10), 0
                            while sent < count:
                                sent = min(count, sent + step)
                                print_cli(f"[+] [SIM] Packets dispatched: {sent}/{count} (fake, 0 bytes sent)", ft.colors.GREEN_ACCENT)
                                time.sleep(0.1)
                            print_cli("[OK] [SIM] Simulation complete. Reminder: cosmetic only, nothing was sent.", ft.colors.ORANGE_400)
                        threading.Thread(target=run, daemon=True).start()

                    else:
                        print_cli(f"[-] Unknown command: '{command}'. Type 'help' for the command list.", ft.colors.RED_400)

                except Exception as ex:
                    print_cli(f"[-] Command error: {ex}", ft.colors.RED_400)

            cli_input = ft.TextField(
                hint_text="Terminal...", bgcolor=ft.colors.BLACK, color=ft.colors.GREEN_ACCENT_400, 
                text_style=ft.TextStyle(font_family="Consolas"), on_submit=execute_cli_command
            )
            
            cli_area = ft.Container(
                expand=4, bgcolor="#0A0A0A", padding=10, border_radius=10, border=ft.border.all(1, ft.colors.GREY_800),
                content=ft.Column([
                    ft.Row([
                        ft.Icon(ft.icons.TERMINAL, color=ft.colors.WHITE), 
                        ft.Text("Embedded Terminal", weight="bold", font_family="Consolas", expand=True)
                    ]),
                    ft.Divider(color=ft.colors.GREY_800), cli_output, cli_input
                ])
            )

            # --- BOILERPLATE HEADER ---
            def load_boilerplate():
                is_elevated = "ELEVATED" if check_privileges()[1] else "STANDARD"
                print_cli("╔══════════════════════════════════════════════════════════════════╗", ft.colors.GREEN_ACCENT)
                print_cli("║                   SOLOSCAN SECURITY SUITE PRO                    ║", ft.colors.GREEN_ACCENT)
                print_cli("║             Developed by: GarbaTheAnalyst Consultancy            ║", ft.colors.GREEN_ACCENT)
                print_cli("╚══════════════════════════════════════════════════════════════════╝", ft.colors.GREEN_ACCENT)
                print_cli(f"[*] System Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", ft.colors.BLUE_200)
                print_cli(f"[*] OS Kernel: {platform.system()} {platform.release()}", ft.colors.BLUE_200)
                print_cli(f"[*] Privileges: {is_elevated}", ft.colors.BLUE_200)
                print_cli("[*] Environment: Ready for Reconnaissance & Defense", ft.colors.GREEN_ACCENT)
                print_cli("-" * 68)
                print_cli("Type 'help' for command list.", ft.colors.GREY_500)

            load_boilerplate()

            # ----------------------------------------------------
            # VIEW 1: ACTIVE RECONNAISSANCE 
            # ----------------------------------------------------
            def active_recon_view():
                target_input = ft.TextField(label="Target IP / Domain", value="127.0.0.1", expand=True)
                ports_input = ft.TextField(label="Ports (e.g. 22,80,1-1000)", value="22,80,443", width=200)
                profile_dropdown = ft.Dropdown(
                    label="Scan Profile", options=[ft.dropdown.Option(k) for k in SCAN_MODES.keys()], 
                    value="Standard (TCP Connect)", width=250
                )
                progress = ft.ProgressRing(visible=False, width=20, height=20)
                status_text = ft.Text("")
                table = ft.DataTable(columns=[
                    ft.DataColumn(ft.Text("Port")), ft.DataColumn(ft.Text("Status")), ft.DataColumn(ft.Text("Service/Banner"))
                ], rows=[])

                def export_active_pdf(e):
                    data = page.client_storage.get("port_data")
                    if not data:
                        status_text.value = "No data to export."; page.update(); return
                    path = generate_pdf_report(data, title="Active Scan Report", filename="Active_Scan")
                    status_text.value = f"PDF Saved: {path}" if path else "PDF Export Failed."
                    print_cli(f"[*] Exported Active Scan PDF to {path}", ft.colors.GREEN_ACCENT)
                    page.update()

                def start_scan(e):
                    table.rows.clear(); progress.visible = True; status_text.value = ""; page.update()
                    target = target_input.value
                    is_stealth = SCAN_MODES[profile_dropdown.value]["stealth"]

                    ports = parse_port_string(ports_input.value)
                    if ports is None:
                        progress.visible = False; status_text.value = "Invalid Ports Format"; page.update(); return

                    print_cli(f"PS> scan {target} {len(ports)} ports", ft.colors.BLUE_200)

                    def on_port(port, status, service, banner):
                        color = ft.colors.GREEN_ACCENT if status == "OPEN" else ft.colors.ORANGE_400
                        display_banner = banner
                        # Flag banners that match known-vulnerable service signatures
                        if status == "OPEN" and banner:
                            vulns = WebVulnScanner.check_cve_heuristics(banner)
                            if vulns:
                                display_banner = f"{banner}  |  {' / '.join(vulns)}"
                                color = ft.colors.RED_400
                                print_cli(f"  [!!] {port}/tcp CVE MATCH: {' / '.join(vulns)}", ft.colors.RED_400)
                        table.rows.append(ft.DataRow(cells=[
                            ft.DataCell(ft.Text(str(port))), ft.DataCell(ft.Text(status, color=color)), ft.DataCell(ft.Text(f"{service} | {display_banner}"))
                        ]))
                        print_cli(f"  [+] {port:<5}/tcp | {status:<8} | {service}", color)
                        page.update()

                    def run():
                        try:
                            res = ScanEngine.stealth_syn_scan(target, ports, on_port) if is_stealth else ScanEngine.port_scan(target, ports, on_port)
                            page.client_storage.set("port_data", res)
                        except Exception as ex:
                            status_text.value, status_text.color = f"Scan failed: {ex}", ft.colors.RED_400
                        finally:
                            progress.visible = False; page.update()

                    threading.Thread(target=run, daemon=True).start()

                # --- Local Network Device Discovery (ARP sweep) ---
                subnet_input = ft.TextField(label="Subnet (CIDR)", value=get_default_subnet(), width=220)
                discover_progress = ft.ProgressRing(visible=False, width=18, height=18)
                discover_status = ft.Text("")
                device_table = ft.DataTable(columns=[
                    ft.DataColumn(ft.Text("IP Address")), ft.DataColumn(ft.Text("MAC Address"))
                ], rows=[])

                def start_discovery(e):
                    device_table.rows.clear(); discover_progress.visible = True; discover_status.value = ""; page.update()
                    subnet = subnet_input.value
                    print_cli(f"PS> discover {subnet}", ft.colors.BLUE_200)

                    def on_device(device):
                        device_table.rows.append(ft.DataRow(cells=[
                            ft.DataCell(ft.Text(device["ip"])), ft.DataCell(ft.Text(device["mac"]))
                        ]))
                        print_cli(f"  [➔] Device Found: IP = {device['ip']:<15} | MAC = {device['mac']}", ft.colors.GREEN_ACCENT)
                        page.update()

                    def run():
                        try:
                            res = ScanEngine.local_discovery(subnet, on_device)
                            if res and isinstance(res, list) and "error" in res[0]:
                                discover_status.value, discover_status.color = res[0]["error"], ft.colors.RED_400
                            else:
                                discover_status.value, discover_status.color = f"Found {len(res)} active device(s).", ft.colors.GREEN_ACCENT
                        except Exception as ex:
                            discover_status.value, discover_status.color = f"Discovery failed: {ex}", ft.colors.RED_400
                        finally:
                            discover_progress.visible = False; page.update()

                    threading.Thread(target=run, daemon=True).start()

                # --- Traceroute ---
                trace_status = ft.Text("")
                trace_output = ft.Column(spacing=2, scroll=ft.ScrollMode.AUTO)

                def start_traceroute(e):
                    trace_output.controls.clear(); trace_status.value, trace_status.color = "Tracing route...", ft.colors.GREY_400; page.update()
                    target = target_input.value
                    print_cli(f"PS> traceroute {target}", ft.colors.BLUE_200)

                    def run():
                        try:
                            hops = ScanEngine.network_traceroute(target)
                            if hops and "error" in hops[0]:
                                trace_status.value, trace_status.color = hops[0]["error"], ft.colors.RED_400
                            else:
                                trace_status.value, trace_status.color = f"{len(hops)} hop(s) found.", ft.colors.GREEN_ACCENT
                                for h in hops:
                                    line = f"  Hop {h['hop']:<3} -> {h['ip']}"
                                    trace_output.controls.append(ft.Text(line, font_family="Consolas", size=12))
                                    print_cli(line, ft.colors.WHITE)
                        except Exception as ex:
                            trace_status.value, trace_status.color = f"Traceroute failed: {ex}", ft.colors.RED_400
                        page.update()

                    threading.Thread(target=run, daemon=True).start()

                # --- Default Credential Audit ---
                bf_service_dropdown = ft.Dropdown(
                    label="Service", options=[ft.dropdown.Option("ftp"), ft.dropdown.Option("http")],
                    value="ftp", width=120
                )
                bf_status = ft.Text("")

                def start_bruteforce(e):
                    bf_status.value, bf_status.color = "Testing common credentials...", ft.colors.GREY_400; page.update()
                    target = target_input.value
                    service = bf_service_dropdown.value
                    print_cli(f"PS> credential-audit {target} --service {service}", ft.colors.BLUE_200)

                    def run():
                        try:
                            res = ScanEngine.brute_force_login(target, service)
                            if res.get("success"):
                                bf_status.value = f"Weak credentials found: {res['user']} / {res['password']}"
                                bf_status.color = ft.colors.RED_400
                                print_cli(f"  [!!] Valid credentials: {res['user']}:{res['password']}", ft.colors.RED_400)
                            else:
                                bf_status.value, bf_status.color = "No common credentials succeeded.", ft.colors.GREEN_ACCENT
                        except Exception as ex:
                            bf_status.value, bf_status.color = f"Credential audit failed: {ex}", ft.colors.RED_400
                        page.update()

                    threading.Thread(target=run, daemon=True).start()

                return ft.Column([
                    ft.Text("Active Network Probing", size=22, weight="bold"),
                    ft.Row([target_input, ports_input, profile_dropdown], wrap=True, spacing=10, run_spacing=10),
                    ft.Row([ft.ElevatedButton("Engage Target", on_click=start_scan), ft.ElevatedButton("Export PDF", on_click=export_active_pdf, icon=ft.icons.PICTURE_AS_PDF, icon_color=ft.colors.RED_400), progress], wrap=True),
                    status_text, ft.Divider(), ft.Container(ft.ListView([table], auto_scroll=True), height=240),

                    ft.Divider(),
                    make_collapsible("Local Network Device Discovery (ARP Sweep)", ft.Column([
                        ft.Row([subnet_input, ft.ElevatedButton("Discover Devices", on_click=start_discovery), discover_progress], wrap=True),
                        discover_status, ft.Container(ft.ListView([device_table], auto_scroll=True), height=150),
                    ])),

                    ft.Divider(),
                    make_collapsible("Traceroute & Default Credential Audit", ft.Column([
                        ft.Row([
                            ft.ElevatedButton("Trace Route", on_click=start_traceroute),
                            bf_service_dropdown,
                            ft.ElevatedButton("Test Default Credentials", on_click=start_bruteforce),
                        ], wrap=True),
                        trace_status, ft.Container(trace_output, height=100, padding=5, bgcolor="#0A0A0A", border_radius=5),
                        bf_status,
                    ])),
                ], expand=True, scroll=ft.ScrollMode.AUTO, spacing=8)

            # ----------------------------------------------------
            # VIEW 2: SIEM REAL-TIME MONITORING
            # ----------------------------------------------------
            def monitor_view():
                target_input = ft.TextField(label="Target to Monitor", value="127.0.0.1", expand=True)
                interval_input = ft.TextField(label="Interval (Seconds)", value="10", width=150)
                monitor_status = ft.Text("Status: Idle", color=ft.colors.GREY_400)
                log_list = ft.ListView(auto_scroll=True, spacing=5)
                
                is_monitoring = False; last_state = {}

                def toggle_monitor(e):
                    nonlocal is_monitoring, last_state
                    if is_monitoring:
                        is_monitoring = False
                        e.control.text, monitor_status.value, monitor_status.color = "Start Monitoring", "Status: Idle", ft.colors.GREY_400
                        print_cli("PS> monitor stop", ft.colors.BLUE_200)
                    else:
                        is_monitoring = True; last_state = {}
                        e.control.text, monitor_status.value, monitor_status.color = "Stop Monitoring", "Status: ACTIVE MONITORING", ft.colors.GREEN_ACCENT
                        print_cli(f"PS> monitor start {target_input.value} --interval {interval_input.value}", ft.colors.BLUE_200)
                        threading.Thread(target=monitor_loop, daemon=True).start()
                    page.update()

                def monitor_loop():
                    nonlocal last_state
                    target = target_input.value
                    try: interval = int(interval_input.value)
                    except Exception: interval = 10

                    while is_monitoring:
                        current_scan = ScanEngine.port_scan(target, [21,22,80,443,3306,3389,8080], workers=10)
                        current_state = {str(p["port"]): p["status"] for p in current_scan if "port" in p}
                        timestamp = datetime.now().strftime("%H:%M:%S")
                        
                        if last_state:
                            for port, status in current_state.items():
                                old_status = last_state.get(port, "CLOSED")
                                if status != old_status:
                                    msg = f"[{timestamp}] ALERT: Port {port} changed from {old_status} -> {status}"
                                    log_list.controls.append(ft.Text(msg, color=ft.colors.RED_400, weight="bold"))
                                    print_cli(f"SIEM ALERT: {msg}", ft.colors.RED_400)
                        else:
                            log_list.controls.append(ft.Text(f"[{timestamp}] Baseline established.", color=ft.colors.BLUE_200))
                        
                        last_state = current_state; page.update(); time.sleep(interval)

                return ft.Column([
                    ft.Text("Real-Time SIEM Monitoring", size=22, weight="bold"),
                    ft.Row([target_input, interval_input, ft.ElevatedButton("Start Monitoring", on_click=toggle_monitor)], wrap=True, spacing=10, run_spacing=10),
                    monitor_status, ft.Divider(),
                    ft.Container(log_list, height=400, bgcolor="#0A0A0A", padding=10, border_radius=5, border=ft.border.all(1, ft.colors.GREY_800))
                ], expand=True, scroll=ft.ScrollMode.AUTO, spacing=8)

            # ----------------------------------------------------
            # VIEW 3: PASSIVE RECONNAISSANCE 
            # ----------------------------------------------------
            def passive_recon_view():
                target_input = ft.TextField(label="Target Domain", value="example.com", expand=True)
                results_list = ft.ListView(spacing=10, auto_scroll=True)
                progress = ft.ProgressRing(visible=False, width=20, height=20)

                def export_passive_pdf(e):
                    data = page.client_storage.get("passive_data")
                    if data:
                        path = generate_pdf_report(data, title="Passive OSINT Report", filename="Passive_OSINT")
                        page.snack_bar = ft.SnackBar(ft.Text(f"PDF Saved: {path}")); page.snack_bar.open = True
                        print_cli(f"[*] Exported Passive PDF to {path}", ft.colors.GREEN_ACCENT)
                    page.update()

                def start_osint(e):
                    results_list.controls.clear(); progress.visible = True; page.update()
                    target = target_input.value
                    print_cli(f"PS> osint {target}", ft.colors.BLUE_200)

                    def run():
                        export_data = []
                        try:
                            dns_info = PassiveEngine.get_dns_records(target)
                            export_data.append({"DNS Records": dns_info})
                            if "error" not in dns_info:
                                results_list.controls.append(ft.Card(content=ft.Container(padding=15, content=ft.Column([
                                    ft.Text("DNS Resolution", weight="bold", color=ft.colors.BLUE_200),
                                    ft.Text(f"Domain: {dns_info['Target Domain']}", size=12),
                                    ft.Text(f"Resolved IP: {dns_info['Resolved IP']}", size=12),
                                    ft.Text(f"Aliases: {dns_info['Known Aliases']}", size=12),
                                ]))))
                                page.update()

                                geo = PassiveEngine.get_ip_geolocation(dns_info["Resolved IP"])
                                export_data.append({"Geolocation": geo})
                                if "error" not in geo:
                                    geo_text = "\n".join([f"{k}: {v}" for k, v in geo.items()])
                                    results_list.controls.append(ft.Card(content=ft.Container(padding=15, content=ft.Column([
                                        ft.Text("IP Geolocation", weight="bold", color=ft.colors.BLUE_200), ft.Text(geo_text, size=12)
                                    ]))))
                                    page.update()

                            whois = PassiveEngine.get_whois(target)
                            export_data.append({"WHOIS": whois})
                            results_list.controls.append(ft.Card(content=ft.Container(padding=15, content=ft.Column([
                                ft.Text("WHOIS Registry", weight="bold", color=ft.colors.BLUE_200), ft.Text(whois[:300] + "...", size=12)
                            ]))))
                            page.update()

                            subs = PassiveEngine.get_subdomains(target)
                            if subs:
                                export_data.append({"Subdomains": subs})
                                results_list.controls.append(ft.Card(content=ft.Container(padding=15, content=ft.Column([
                                    ft.Text("Subdomains", weight="bold", color=ft.colors.BLUE_200), ft.Text("\n".join(subs), size=12)
                                ]))))
                                page.update()

                            headers_audit = WebVulnScanner.analyze_website(target)
                            if headers_audit and "error" not in headers_audit[0]:
                                export_data.append({"Header Misconfigurations": headers_audit})
                                audit_text = "\n".join([f"[{v.get('severity', 'Info')}] {v.get('vulnerability', '')} - {v.get('remediation', '')}" for v in headers_audit])
                                results_list.controls.append(ft.Card(content=ft.Container(padding=15, content=ft.Column([
                                    ft.Text("HTTP Header Security Audit", weight="bold", color=ft.colors.ORANGE_400), ft.Text(audit_text, size=12)
                                ]))))
                                page.update()

                            fuzz = WebVulnScanner.fuzz_directories(target)
                            if fuzz:
                                export_data.append({"Fuzzing Hits": fuzz})
                                fuzz_text = "\n".join([f"{f['path']} ({f['status']})" for f in fuzz])
                                results_list.controls.append(ft.Card(content=ft.Container(padding=15, content=ft.Column([
                                    ft.Text("Fuzzing Hits", weight="bold", color=ft.colors.RED_300), ft.Text(fuzz_text, color=ft.colors.GREEN_ACCENT)
                                ]))))
                        except Exception as ex:
                            results_list.controls.append(ft.Text(f"OSINT pipeline error: {ex}", color=ft.colors.RED_400))
                        finally:
                            page.client_storage.set("passive_data", export_data)
                            progress.visible = False; page.update()

                    threading.Thread(target=run, daemon=True).start()

                return ft.Column([
                    ft.Text("Passive OSINT & Fuzzing", size=22, weight="bold"),
                    ft.Row([target_input, ft.ElevatedButton("Run Full OSINT", on_click=start_osint), ft.ElevatedButton("Export PDF", on_click=export_passive_pdf, icon=ft.icons.PICTURE_AS_PDF, icon_color=ft.colors.RED_400), progress], wrap=True, spacing=10, run_spacing=10),
                    ft.Divider(), ft.Container(results_list, height=450)
                ], expand=True, scroll=ft.ScrollMode.AUTO, spacing=8)

            # ----------------------------------------------------
            # VIEW 4: BLUE TEAM DEFENSE
            # ----------------------------------------------------
            def defense_view():
                current_ip = IPManager.get_current_ip()
                adapter_input = ft.TextField(label="Windows Adapter (e.g. Wi-Fi)", width=250)
                new_ip_input = ft.TextField(label="New Static IP", width=150)
                ip_status = ft.Text("")

                def update_ip(e):
                    ip_status.value = "Attempting to change IP (Requires Admin)..."; page.update()
                    print_cli(f"PS> setip {adapter_input.value} {new_ip_input.value}", ft.colors.BLUE_200)
                    res = IPManager.change_windows_ip(adapter_input.value, new_ip_input.value)
                    ip_status.value = res
                    ip_status.color = ft.colors.GREEN_ACCENT if "Success" in res else ft.colors.RED_400
                    print_cli(f"[*] {res}", ip_status.color)
                    page.update()

                hp_port_input = ft.TextField(label="Honeypot Port", value="22", width=120)
                hp_status = ft.Text("Status: Offline", color=ft.colors.GREY_400)
                hp_logs = ft.ListView(auto_scroll=True, spacing=5)

                def hp_logger(msg):
                    color = ft.colors.RED_400 if "INTRUSION" in msg else ft.colors.GREEN_ACCENT
                    hp_logs.controls.append(ft.Text(msg, color=color)); print_cli(f"HONEYPOT: {msg}", color); page.update()

                def toggle_honeypot(e):
                    if global_honeypot.is_active:
                        global_honeypot.stop()
                        e.control.text, e.control.bgcolor = "Deploy Honeypot", ft.colors.BLUE_700
                        hp_status.value, hp_status.color = "Status: Offline", ft.colors.GREY_400
                        print_cli("PS> honeypot stop", ft.colors.BLUE_200)
                    else:
                        global_honeypot.port = int(hp_port_input.value)
                        print_cli(f"PS> honeypot start --port {global_honeypot.port}", ft.colors.BLUE_200)
                        if global_honeypot.start(hp_logger):
                            e.control.text, e.control.bgcolor = "Deactivate Honeypot", ft.colors.RED_700
                            hp_status.value, hp_status.color = "Status: ACTIVE", ft.colors.GREEN_ACCENT
                    page.update()

                return ft.Column([
                    ft.Text("Blue Team Defense Tools", size=22, weight="bold"), ft.Divider(),
                    ft.Text("Host Network Management", weight="bold", color=ft.colors.BLUE_200),
                    ft.Text(f"Current Local IP Address: {current_ip}", size=16, color=ft.colors.GREEN_ACCENT),
                    ft.Row([adapter_input, new_ip_input, ft.ElevatedButton("Change IP", on_click=update_ip)], wrap=True, spacing=10, run_spacing=10), ip_status,
                    ft.Divider(),
                    ft.Text("Intrusion Detection Honeypot", weight="bold", color=ft.colors.BLUE_200),
                    ft.Text("Deploys a fake service to log unauthorized network scans against your machine.", color=ft.colors.GREY_400),
                    ft.Row([hp_port_input, ft.ElevatedButton("Deploy Honeypot", on_click=toggle_honeypot, bgcolor=ft.colors.BLUE_700)], wrap=True, spacing=10, run_spacing=10), hp_status,
                    ft.Container(hp_logs, height=280, border=ft.border.all(1, ft.colors.GREY_800), padding=10, border_radius=5)
                ], expand=True, scroll=ft.ScrollMode.AUTO, spacing=8)

            # ----------------------------------------------------
            # VIEW 5: IDS PACKET SNIFFER
            # ----------------------------------------------------
            def sniffer_view():
                log_list = ft.ListView(auto_scroll=True, spacing=2)
                status_text = ft.Text("Sniffer Offline", color=ft.colors.GREY_400)
                test_status = ft.Text("")
                
                def map_color(color_str):
                    colors = {"WHITE": ft.colors.WHITE, "RED": ft.colors.RED_400, "GREEN": ft.colors.GREEN_ACCENT, "ORANGE": ft.colors.ORANGE_400, "GREY": ft.colors.GREY_500}
                    return colors.get(color_str, ft.colors.WHITE)

                def sniffer_log(msg, color_str="WHITE"):
                    log_list.controls.append(ft.Text(msg, color=map_color(color_str), font_family="Consolas", size=12))
                    if len(log_list.controls) > 500: log_list.controls.pop(0) 
                    page.update()

                def toggle_sniffer(e):
                    if sniffer_instance.running:
                        sniffer_instance.stop()
                        e.control.text, e.control.icon, e.control.bgcolor = "Start Sniffing", ft.icons.PLAY_ARROW, ft.colors.SURFACE_VARIANT
                        status_text.value, status_text.color = "Sniffer Offline", ft.colors.GREY_400
                        print_cli("PS> sniff stop", ft.colors.BLUE_200)
                    else:
                        log_list.controls.clear()
                        e.control.text, e.control.icon, e.control.bgcolor = "Stop Sniffing", ft.icons.STOP, ft.colors.RED_900
                        status_text.value, status_text.color = "ACTIVE - Capturing Traffic...", ft.colors.GREEN_ACCENT
                        print_cli("PS> sniff start", ft.colors.BLUE_200)
                        threading.Thread(target=sniffer_instance.start, args=(sniffer_log,), daemon=True).start()
                    page.update()

                def generate_test_traffic(e):
                    """Sends a real, harmless SYN burst to localhost only -- enough to legitimately
                    trip SecurityMonitor.SYN_THRESHOLD and demonstrate the live alert above."""
                    if not sniffer_instance.running:
                        test_status.value, test_status.color = "Start the sniffer above first, so it can observe the test traffic.", ft.colors.ORANGE_400
                        page.update(); return

                    test_status.value, test_status.color = "Sending test SYN burst to 127.0.0.1...", ft.colors.GREY_400
                    page.update()
                    print_cli("PS> generate-test-traffic 127.0.0.1 (loopback only, 70 SYN packets)", ft.colors.BLUE_200)

                    def run():
                        try:
                            # 70 high, unused local ports -> 70 real SYN packets to 127.0.0.1.
                            # No spoofing, no external target -- purely to exercise the IDS threshold.
                            test_ports = list(range(20000, 20070))
                            res = ScanEngine.stealth_syn_scan("127.0.0.1", test_ports)
                            if res and isinstance(res, list) and "error" in res[0]:
                                test_status.value, test_status.color = res[0]["error"], ft.colors.RED_400
                            else:
                                test_status.value, test_status.color = (
                                    f"Sent {len(test_ports)} real SYN packets to 127.0.0.1 -- "
                                    "watch the log above for a SYN Flood alert."
                                ), ft.colors.GREEN_ACCENT
                        except Exception as ex:
                            test_status.value, test_status.color = f"Test traffic failed: {ex}", ft.colors.RED_400
                        page.update()

                    threading.Thread(target=run, daemon=True).start()

                return ft.Column([
                    ft.Text("Intrusion Detection Sniffer", size=22, weight="bold"),
                    ft.Text("Monitors local interfaces for suspicious traffic and MITRE ATT&CK patterns.", color=ft.colors.GREY_400),
                    ft.Row([ft.ElevatedButton("Start Sniffing", icon=ft.icons.PLAY_ARROW, on_click=toggle_sniffer), status_text], wrap=True), ft.Divider(),
                    ft.Container(log_list, height=380, bgcolor="#0A0A0A", padding=10, border_radius=5, border=ft.border.all(1, ft.colors.GREY_800)),
                    ft.Divider(),
                    ft.Text("IDS Self-Test", weight="bold", color=ft.colors.BLUE_200),
                    ft.Text("Generates real (but harmless) SYN packets to 127.0.0.1 only, to verify the SYN-flood detector above fires correctly.", color=ft.colors.GREY_400, size=12),
                    ft.Row([ft.ElevatedButton("Generate Test Traffic (Loopback)", icon=ft.icons.BUG_REPORT, on_click=generate_test_traffic), test_status], wrap=True)
                ], expand=True, scroll=ft.ScrollMode.AUTO, spacing=8)

            # ----------------------------------------------------
            # VIEW 6: TOOLS & AUDIT LOGS
            # ----------------------------------------------------
            def tools_view():
                resolve_input = ft.TextField(label="Domain/URL to Resolve", value="google.com", expand=True)
                resolve_output = ft.Text("")

                def do_resolve(e):
                    clean = resolve_input.value.replace("https://", "").replace("http://", "").split("/")[0]
                    print_cli(f"PS> resolve {clean}", ft.colors.BLUE_200)
                    try:
                        ip = socket.gethostbyname(clean)
                        resolve_output.value, resolve_output.color = f"Target {clean} resolves to IP: {ip}", ft.colors.GREEN_ACCENT
                        print_cli(f"[+] {clean} -> {ip}", ft.colors.GREEN_ACCENT)
                    except Exception:
                        resolve_output.value, resolve_output.color = f"Failed to resolve {clean}.", ft.colors.RED_400
                        print_cli(f"[-] Failed to resolve {clean}.", ft.colors.RED_400)
                    page.update()

                ip_input = ft.TextField(label="CIDR Network Range (e.g. 192.168.1.0/24)", expand=True)
                output_col = ft.Column(spacing=8)

                def calculate(e):
                    output_col.controls.clear()
                    print_cli(f"PS> subnet {ip_input.value}", ft.colors.BLUE_200)
                    try:
                        net = ipaddress.ip_network(ip_input.value, strict=False)
                        hosts = list(net.hosts())
                        first, last = (hosts[0], hosts[-1]) if hosts else ("N/A", "N/A")
                        usable = net.num_addresses - 2 if net.num_addresses > 2 else 0
                        output_col.controls = [
                            ft.Text(f"Network Address: {net.network_address}"), ft.Text(f"Broadcast: {net.broadcast_address}"),
                            ft.Text(f"Netmask: {net.netmask}"), ft.Text(f"Usable Hosts: {usable}", color=ft.colors.BLUE_200),
                            ft.Text(f"Host Range: {first} -> {last}")
                        ]
                        print_cli(f"[+] Network: {net.network_address}  Usable Hosts: {usable}", ft.colors.GREEN_ACCENT)
                    except Exception as ex:
                        output_col.controls.append(ft.Text(f"Error: {ex}", color=ft.colors.RED_400))
                        print_cli(f"[-] Invalid CIDR: {ex}", ft.colors.RED_400)
                    page.update()

                log_display = ft.Text("Click 'Refresh Logs' to load system events.", font_family="Consolas", size=12, color=ft.colors.GREY_400)
                
                def refresh_audit_logs(e):
                    try:
                        with open("soloscan_debug.log", "r") as f:
                            lines = f.readlines()[-15:]
                            log_display.value, log_display.color = "".join(lines) if lines else "Log file is empty.", ft.colors.GREEN_ACCENT
                    except FileNotFoundError:
                        log_display.value, log_display.color = "soloscan_debug.log not found. System has not generated background logs yet.", ft.colors.ORANGE_400
                    page.update()

                return ft.Column([
                    ft.Text("Networking Utilities & System Audit", size=22, weight="bold"), ft.Divider(),
                    ft.Text("Domain-to-IP Resolver", weight="bold", color=ft.colors.BLUE_200),
                    ft.Row([resolve_input, ft.ElevatedButton("Resolve IP", on_click=do_resolve)], wrap=True, spacing=10, run_spacing=10), resolve_output,
                    ft.Divider(),
                    ft.Text("Subnet Calculator", weight="bold", color=ft.colors.BLUE_200),
                    ft.Row([ip_input, ft.ElevatedButton("Compute Subnet", on_click=calculate)], wrap=True, spacing=10, run_spacing=10), output_col,
                    ft.Divider(),
                    ft.Row([ft.Text("Background System Audit Logs", weight="bold", color=ft.colors.BLUE_200), ft.IconButton(icon=ft.icons.REFRESH, on_click=refresh_audit_logs, tooltip="Refresh Logs")], wrap=True),
                    ft.Container(log_display, height=220, bgcolor="#0A0A0A", padding=10, border_radius=5, border=ft.border.all(1, ft.colors.GREY_800))
                ], expand=True, scroll=ft.ScrollMode.AUTO, spacing=8)

            # ----------------------------------------------------
            # VIEW 7: DOS / DDOS CONSOLE -- VISUAL SIMULATION ONLY
            # ----------------------------------------------------
            def dos_ddos_sim_view():
                """
                Cosmetic mock-up of a flood-attack console for classroom/demo purposes.
                This function contains NO networking logic of any kind: no sockets,
                no Scapy, no requests, no DNS resolution. It only prints scripted
                strings with randomized fake counters via time.sleep(). It is not
                capable of sending a single real packet to anything.
                """
                target_input = ft.TextField(label="Target Host (cosmetic only)", value="10.0.0.5", width=200)
                port_input = ft.TextField(label="Port (cosmetic only)", value="80", width=120)
                method_dropdown = ft.Dropdown(
                    label="Method (label only)",
                    options=[ft.dropdown.Option(m) for m in [
                        "SYN Flood (Simulated)", "ICMP Flood (Simulated)",
                        "UDP Flood (Simulated)", "HTTP Flood (Simulated)"
                    ]],
                    value="SYN Flood (Simulated)", width=220
                )
                count_input = ft.TextField(label="Packet Count (cosmetic only)", value="500", width=170)
                term_output = ft.ListView(auto_scroll=True, spacing=1)
                run_state = {"running": False}

                def sim_print(line, color=ft.colors.GREEN_ACCENT_400):
                    term_output.controls.append(ft.Text(line, color=color, font_family="Consolas", size=12))
                    if len(term_output.controls) > 400: term_output.controls.pop(0)
                    page.update()

                def run_simulation(e):
                    if run_state["running"]:
                        return
                    try:
                        total = max(1, min(int(count_input.value), 5000))
                    except Exception:
                        total = 500
                    target, port, method = target_input.value, port_input.value, method_dropdown.value
                    print_cli(f"PS> simulate {method} {target}:{port} --count {total} (SIMULATED, no real traffic)", ft.colors.ORANGE_400)

                    run_state["running"] = True
                    term_output.controls.clear(); page.update()
                    sim_print("=" * 60, ft.colors.GREY_600)
                    sim_print("[SIMULATED CONSOLE] No real network traffic will be sent.", ft.colors.ORANGE_400)
                    sim_print("=" * 60, ft.colors.GREY_600)

                    def run():
                        try:
                            sim_print(f"[*] [SIM] Resolving target {target} ...", ft.colors.WHITE)
                            time.sleep(0.4)
                            sim_print(f"[*] [SIM] Target resolved (fake): {target}", ft.colors.WHITE)
                            time.sleep(0.3)
                            sim_print(f"[*] [SIM] Initializing {method} against {target}:{port} ...", ft.colors.WHITE)
                            time.sleep(0.4)
                            sim_print(f"[*] [SIM] Spawning {min(total, 50)} fake worker thread(s) ...", ft.colors.WHITE)
                            time.sleep(0.5)

                            step = max(1, total // 40)
                            sent = 0
                            while sent < total and run_state["running"]:
                                sent = min(total, sent + step)
                                fake_rate = random.randint(800, 2400)
                                sim_print(f"[+] [SIM] Packets dispatched: {sent}/{total}  (fake rate: {fake_rate}/s, 0 bytes actually sent)", ft.colors.GREEN_ACCENT)
                                time.sleep(0.1)

                            if run_state["running"]:
                                sim_print("-" * 60, ft.colors.GREY_600)
                                sim_print(f"[OK] [SIM] Simulation complete. Total simulated packets: {total}.", ft.colors.GREEN_ACCENT)
                                sim_print("[i] [SIM] Reminder: this panel is cosmetic only -- no sockets were opened, no packets left this process.", ft.colors.ORANGE_400)
                                sim_print("[i] [SIM] For REAL flood detection (safely), use 'Generate Test Traffic' under the Sniffer tab.", ft.colors.BLUE_200)
                            else:
                                sim_print("[!] [SIM] Simulation stopped by user.", ft.colors.ORANGE_400)
                        finally:
                            run_state["running"] = False
                            page.update()

                    threading.Thread(target=run, daemon=True).start()

                def stop_simulation(e):
                    run_state["running"] = False

                return ft.Column([
                    ft.Row([
                        ft.Icon(ft.icons.WARNING_AMBER_ROUNDED, color=ft.colors.ORANGE_400),
                        ft.Text("DoS / DDoS Console -- SIMULATION ONLY", size=22, weight="bold", color=ft.colors.ORANGE_400),
                    ], wrap=True),
                    ft.Container(
                        padding=10, bgcolor="#231a08", border_radius=5, border=ft.border.all(1, ft.colors.ORANGE_400),
                        content=ft.Text(
                            "This panel is a visual mock-up for demos and training only. It does not open sockets, "
                            "craft packets, resolve hosts, or send any network traffic of any kind -- it only prints "
                            "scripted text with fake counters. For a real, safe demonstration of the IDS detecting an "
                            "actual flood, use 'Generate Test Traffic' on the Sniffer tab (loopback only).",
                            color=ft.colors.ORANGE_100, size=12
                        )
                    ),
                    ft.Row([target_input, port_input, method_dropdown, count_input], wrap=True, spacing=10, run_spacing=10),
                    ft.Row([
                        ft.ElevatedButton("Run Simulation", icon=ft.icons.PLAY_ARROW, on_click=run_simulation, bgcolor=ft.colors.ORANGE_900, color=ft.colors.WHITE),
                        ft.ElevatedButton("Stop", icon=ft.icons.STOP, on_click=stop_simulation, bgcolor=ft.colors.SURFACE_VARIANT),
                    ], wrap=True),
                    ft.Divider(),
                    ft.Container(term_output, height=380, bgcolor="#0A0A0A", padding=10, border_radius=5, border=ft.border.all(1, ft.colors.GREY_800))
                ], expand=True, scroll=ft.ScrollMode.AUTO, spacing=8)

            # ----------------------------------------------------
            # GLOBAL NAVIGATION & FRAME ASSEMBLY
            # ----------------------------------------------------
            def navigation_handler(e):
                index = e.control.selected_index
                # Only build the view that was actually selected -- the previous version
                # called every view-builder on every click, which silently re-created
                # monitor_view()/sniffer_view() (resetting their state) even when you
                # clicked an unrelated tab, orphaning any running monitor/sniffer thread.
                view_builders = [active_recon_view, monitor_view, passive_recon_view, defense_view, sniffer_view, tools_view, dos_ddos_sim_view]
                gui_area.content = view_builders[index]()
                # Keep both navigation controls (rail for desktop, bottom bar for mobile) in sync,
                # since only one of them is mounted at a time but the other should resume at the
                # right tab if the window is resized/rotated across the mobile breakpoint.
                nav_rail.selected_index = index
                nav_bar.selected_index = index
                page.update()

            NAV_ITEMS = [
                (ft.icons.BOLT, "Active"), (ft.icons.MONITOR_HEART, "SIEM"), (ft.icons.RADAR, "Passive"),
                (ft.icons.SHIELD, "Defense"), (ft.icons.WAVES, "Sniffer"), (ft.icons.BUILD, "Tools"),
                (ft.icons.WARNING_AMBER_ROUNDED, "Sim DoS"),
            ]

            nav_rail = ft.NavigationRail(
                selected_index=0, label_type=ft.NavigationRailLabelType.ALL, min_width=80,
                destinations=[ft.NavigationRailDestination(icon=icon, label=label) for icon, label in NAV_ITEMS],
                on_change=navigation_handler,
            )
            nav_bar = ft.NavigationBar(
                selected_index=0,
                destinations=[ft.NavigationBarDestination(icon=icon, label=label) for icon, label in NAV_ITEMS],
                on_change=navigation_handler,
            )
            
            gui_area.content = active_recon_view()
            div1, div2 = ft.VerticalDivider(width=1), ft.VerticalDivider(width=1)

            def set_view_mode(mode):
                if mode == "Split View":
                    nav_rail.visible, div1.visible, gui_area.visible, div2.visible, cli_area.visible = True, True, True, True, True
                elif mode == "GUI Only":
                    nav_rail.visible, div1.visible, gui_area.visible = True, True, True
                    cli_area.visible, div2.visible = False, False
                elif mode == "CLI Only":
                    nav_rail.visible, div1.visible, gui_area.visible, div2.visible = False, False, False, False
                    cli_area.visible = True
                page.update()

            page.appbar = ft.AppBar(
                title=ft.Row([ft.Icon(ft.icons.SECURITY, color=ft.colors.GREEN_ACCENT), ft.Text("SoloScan Workspace", weight="bold")]),
                bgcolor=ft.colors.SURFACE_VARIANT,
                actions=[
                    ft.TextButton("GUI Only", on_click=lambda e: set_view_mode("GUI Only")),
                    ft.TextButton("CLI Only", on_click=lambda e: set_view_mode("CLI Only")),
                    ft.TextButton("Split View", on_click=lambda e: set_view_mode("Split View")),
                ],
            )

            # Mobile (Android/iOS/narrow window) breakpoint: NavigationRail doesn't fit well
            # on phone-width screens, and a side-by-side GUI+Terminal split is unusable there.
            # Below this width we swap to a bottom NavigationBar and stack the panels vertically.
            MOBILE_BREAKPOINT = 700
            content_holder = ft.Container(expand=True)

            def apply_responsive_layout(e=None):
                is_mobile = (page.width or 1350) < MOBILE_BREAKPOINT
                if is_mobile:
                    page.navigation_bar = nav_bar
                    gui_area.expand, cli_area.expand, cli_area.height = True, None, 320
                    content_holder.content = ft.Column([gui_area, ft.Divider(height=1), cli_area], expand=True)
                else:
                    page.navigation_bar = None
                    cli_area.height = None
                    gui_area.expand, cli_area.expand = 5, 4
                    content_holder.content = ft.Row([nav_rail, div1, gui_area, div2, cli_area], expand=True)
                page.update()

            page.on_resized = apply_responsive_layout

            # Assemble the Final UI
            page.add(
                ft.Column([
                    content_holder,
                    ft.Container(
                        content=ft.Text("built by GarbaTheAnalyst, The Analyst Consultancy, ©2026. SoloScan™", size=10, color=ft.colors.GREY_600, italic=True),
                        alignment=ft.alignment.bottom_right,
                        padding=ft.padding.only(right=10, bottom=5)
                    )
                ], expand=True)
            )
            apply_responsive_layout()

        # TRIGGER THE EULA SCREEN AFTER SPLASH
        show_eula()

    ft.app(target=main)