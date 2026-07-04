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
from core.intel_engine import IntelEngine
from core import database as db
from core.utils import SCAN_MODES, export_results, generate_pdf_report, check_privileges

def get_default_subnet():
    """Helper to calculate the host's /24 subnet for the discovery tool."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return f"{s.getsockname()[0].rsplit('.', 1)[0]}.0/24"
    except Exception: 
        return "192.168.1.0/24"

# Instantiate global tools so they persist across tab switches AND survive a
# view being rebuilt without spawning duplicate background threads -- see
# monitor_view() for why this needs to be shared state rather than a local
# variable.
global_honeypot = Honeypot(port=22)
sniffer_instance = PacketSniffer()
monitor_state = {"running": False, "last_state": {}}

def run_gui():
    def main(page: ft.Page):
        # ----------------------------------------------------
        # FLET VERSION COMPATIBILITY SHIMS
        # Flet >=0.80 dropped lowercase aliases (ft.colors, ft.icons,
        # ft.border.all, ft.padding.only/symmetric) in favour of PascalCase
        # (ft.Colors, ft.Icons) and raw class constructors. Patch them back
        # onto the module ONCE here, before any widget code runs, so every
        # existing call site throughout the file keeps working unchanged on
        # both old and new Flet versions. Every shim tested end-to-end
        # against the real API before committing.
        # ----------------------------------------------------
        if not hasattr(ft, 'colors'):
            ft.colors = ft.Colors

        if not hasattr(ft.icons, 'CLOSE'):
            ft.icons = ft.Icons

        if not hasattr(ft.border, 'all'):
            def _border_all(width, color):
                side = ft.border.BorderSide(width, color)
                return ft.border.Border(left=side, top=side, right=side, bottom=side)
            ft.border.all = _border_all

        if not hasattr(ft.padding, 'only'):
            def _padding_only(left=0, top=0, right=0, bottom=0):
                return ft.padding.Padding(left=left, top=top, right=right, bottom=bottom)
            ft.padding.only = _padding_only

        if not hasattr(ft.padding, 'symmetric'):
            def _padding_symmetric(horizontal=0, vertical=0):
                return ft.padding.Padding(left=horizontal, top=vertical, right=horizontal, bottom=vertical)
            ft.padding.symmetric = _padding_symmetric

        # ----------------------------------------------------
        # WINDOW CONFIGURATION
        # ----------------------------------------------------
        page.title = "SoloScan Security Suite PRO"
        page.theme_mode = ft.ThemeMode.DARK
        page.adaptive = True
        page.padding = 0
        page.bgcolor = "#000000"
        # window size: moved to page.window in newer Flet
        try:
            page.window.width = 1350
            page.window.height = 800
        except Exception:
            try:
                page.window_width = 1350
                page.window_height = 800
            except Exception:
                pass

        # TUI color/font palette -- defined here (not inside build_main_interface)
        # so the splash screen and EULA can use it too, since they run directly in
        # main()'s body before build_main_interface is ever called.
        #
        # Each color carries a deliberate meaning, used consistently everywhere:
        #   TUI_GREEN  - primary/structural (borders, titles, normal text, success)
        #   TUI_CYAN   - secondary headers / informational accents
        #   TUI_RED    - danger, alerts, destructive actions, malicious findings
        #   TUI_ORANGE - warnings, caution, simulated/non-real states
        #   TUI_BG     - the shared near-black background every panel sits on
        TUI_GREEN, TUI_CYAN, TUI_RED, TUI_ORANGE, TUI_BG, TUI_FONT = \
            "#33FF33", "#33FFFF", "#FF4444", "#FFA500", "#000000", "Consolas"

        def safe_alignment(name, x, y):
            """Flet's alignment API has shipped as both lowercase module-level
            instances (e.g. ft.alignment.center) and an Alignment class with
            UPPERCASE members (e.g. ft.alignment.Alignment.CENTER) across
            different releases. Try the lowercase form first since the rest of
            this codebase already depends on similarly-shaped older-style APIs
            (ft.colors.*, ft.icons.*, ft.border.*, ft.padding.*) working, then
            fall back progressively rather than assuming either form."""
            try:
                return getattr(ft.alignment, name)
            except AttributeError:
                pass
            try:
                return getattr(ft.alignment.Alignment, name.upper())
            except AttributeError:
                pass
            try:
                return ft.alignment.Alignment(x, y)
            except Exception:
                return None  # let Flet fall back to its own default

        # ==========================================
        # 🎬 PHASE 1: SPLASH SCREEN
        # ==========================================
        loading_bar_text = ft.Text("", font_family=TUI_FONT, color=TUI_GREEN, size=16)
        loading_status_text = ft.Text("Initializing Core Modules & Engines...", size=12, color=TUI_CYAN, italic=True, font_family=TUI_FONT)

        def render_loading_bar(percent, width_chars=40):
            percent = max(0, min(100, percent))
            filled = int(width_chars * percent / 100)
            loading_bar_text.value = "[" + ("█" * filled) + ("░" * (width_chars - filled)) + f"] {percent:>3.0f}%"

        render_loading_bar(0)

        splash_screen = ft.Container(
            expand=True,
            bgcolor=TUI_BG,
            alignment=safe_alignment("center", 0, 0),
            content=ft.Column(
                alignment=ft.MainAxisAlignment.CENTER,
                horizontal_alignment=ft.CrossAxisAlignment.CENTER,
                controls=[
                    ft.Text("╔═══════════════════════════════════╗", font_family=TUI_FONT, color=TUI_GREEN, size=18),
                    ft.Text("║          S O L O S C A N           ║", font_family=TUI_FONT, color=TUI_GREEN, size=18, weight="bold"),
                    ft.Text("╚═══════════════════════════════════╝", font_family=TUI_FONT, color=TUI_GREEN, size=18),
                    ft.Container(height=10),
                    ft.Text("S E C U R I T Y   S U I T E   P R O", size=16, weight="w400", color=TUI_CYAN, font_family=TUI_FONT),
                    ft.Container(height=30),

                    loading_bar_text,
                    loading_status_text,

                    ft.Container(height=80),
                    ft.Text("built by GarbaTheAnalyst, The Analyst Consultancy, ©2026. SoloScan™", size=12, color=ft.colors.GREY_600, italic=True, font_family=TUI_FONT)
                ]
            )
        )

        # Display the splash screen
        page.add(splash_screen)
        page.update()

        # Animate a text-rendered loading bar across the same hold period the
        # original splash used, instead of a static progress bar.
        loading_steps = [
            (10, "Loading configuration..."), (25, "Initializing scan engine..."),
            (40, "Connecting to threat intel APIs..."), (55, "Starting database..."),
            (70, "Preparing sniffer & IDS modules..."), (85, "Building interface..."),
            (100, "Ready."),
        ]
        for percent, status in loading_steps:
            render_loading_bar(percent)
            loading_status_text.value = status
            page.update()
            time.sleep(4.5 / len(loading_steps))

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

            eula_sections = [
                ("1. Authorized Use Only",
                 "This Software is engineered strictly for academic research, authorized penetration "
                 "testing, and defensive system auditing. You may only execute active scans, brute-force "
                 "modules, and packet interception against networks, endpoints, and domains for which you "
                 "have explicit, documented, and legal authorization to test."),
                ("2. Prohibition of Malicious Use",
                 "You shall not use the Software to conduct unauthorized denial-of-service (DoS) attacks, "
                 "intercept third-party communications without consent, bypass access controls, or "
                 "facilitate any activity that violates local, state, national, or international computer "
                 "misuse and wiretapping laws."),
                ("3. Disclaimer of Warranties",
                 "The Software is provided \"AS IS\", without warranty of any kind, express or implied, "
                 "including but not limited to the warranties of merchantability, fitness for a particular "
                 "purpose, and non-infringement."),
                ("4. Limitation of Liability",
                 "Under no circumstances shall the developer (Garba the analyst), The Analyst Consultancy, "
                 "or Newgate University Minna be held liable for any direct, indirect, incidental, special, "
                 "exemplary, or consequential damages arising in any way out of the use, misuse, or "
                 "inability to use this Software."),
            ]

            eula_body = ft.Column([
                ft.Text("END USER LICENSE AGREEMENT AND DISCLAIMER OF LIABILITY", size=16, weight="bold", color=TUI_GREEN, font_family=TUI_FONT),
                ft.Text("By clicking \"I AGREE & CONTINUE\", you explicitly agree to the following terms:", color=TUI_CYAN, font_family=TUI_FONT),
                ft.Container(height=10),
            ] + [
                item for title, body in eula_sections for item in (
                    ft.Text(title, weight="bold", color=TUI_GREEN, font_family=TUI_FONT, size=14),
                    ft.Text(body, color=ft.colors.WHITE, font_family=TUI_FONT, selectable=True),
                    ft.Container(height=12),
                )
            ], scroll=ft.ScrollMode.AUTO, spacing=4)

            def tui_outline_button(label, icon, color, on_click):
                """A bordered, transparent-fill button matching the rest of the
                app's TUI look, instead of a solid filled Material pill."""
                return ft.ElevatedButton(
                    label, icon=icon, on_click=on_click, color=color, bgcolor=TUI_BG,
                    style=ft.ButtonStyle(side=ft.BorderSide(1, color), shape=ft.RoundedRectangleBorder(radius=2))
                )

            eula_container = ft.Container(
                expand=True,
                bgcolor=TUI_BG,
                padding=40,
                content=ft.Column([
                    ft.Row([
                        ft.Icon(ft.icons.WARNING_AMBER_ROUNDED, color=TUI_RED, size=40), 
                        ft.Text("RESTRICTED SYSTEM: AUTHORIZED USE ONLY", size=24, weight="bold", color=TUI_RED, font_family=TUI_FONT)
                    ]),
                    ft.Divider(color=TUI_RED),
                    ft.Container(
                        content=eula_body,
                        expand=True,
                        padding=20,
                        border=ft.border.all(1, TUI_RED),
                        border_radius=2,
                        bgcolor="#0A0000",
                    ),
                    ft.Container(height=10),
                    ft.Row([
                        tui_outline_button("DECLINE & EXIT", ft.icons.CLOSE, TUI_RED, decline_eula),
                        tui_outline_button("I AGREE & CONTINUE", ft.icons.CHECK, TUI_GREEN, accept_eula),
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
            # Simple in-memory store replacing page.client_storage (removed in
            # newer Flet). Only two keys are used: port_data and passive_data.
            _session = {"port_data": [], "passive_data": []}

            try:
                db.init_db()
            except Exception as ex:
                print(f"[SoloScan] Database init failed, persistence disabled this session: {ex}")

            def make_collapsible(title, content, initially_expanded=False):
                """Lightweight, version-safe collapsible section: click the header to
                show/hide the body. Used to keep dense views from feeling cluttered."""
                body = ft.Container(content=content, visible=initially_expanded, padding=ft.padding.only(top=8, bottom=4))
                chevron = ft.Icon(ft.icons.KEYBOARD_ARROW_DOWN if initially_expanded else ft.icons.KEYBOARD_ARROW_RIGHT, color=TUI_CYAN)

                def toggle(e):
                    body.visible = not body.visible
                    chevron.name = ft.icons.KEYBOARD_ARROW_DOWN if body.visible else ft.icons.KEYBOARD_ARROW_RIGHT
                    page.update()

                header = ft.Container(
                    content=ft.Row([chevron, ft.Text(title, weight="bold", color=TUI_CYAN, font_family=TUI_FONT)]),
                    on_click=toggle, padding=ft.padding.symmetric(vertical=4), ink=True
                )
                return ft.Column([header, body], spacing=0)

            # ----------------------------------------------------
            # TUI-STYLE WIDGET HELPERS (termbox-inspired dashboard pieces)
            # ----------------------------------------------------
            TUI_GREEN, TUI_CYAN, TUI_BG, TUI_FONT = "#33FF33", "#33FFFF", "#000000", "Consolas"

            def tui_box(title, content, accent=None):
                """An ASCII-bordered panel -- a real Flet border + a styled title
                row, rather than hand-drawn Unicode box characters (which render
                inconsistently across fonts/platforms). Used to give key panels the
                bordered-terminal look from the termbox reference image."""
                accent = accent or TUI_GREEN
                header = ft.Row([
                    ft.Text("─", font_family=TUI_FONT, color=accent, size=13),
                    ft.Text(f" {title} ", font_family=TUI_FONT, color=accent, weight="bold", size=13),
                ])
                return ft.Container(
                    content=ft.Column([header, ft.Divider(height=1, color=accent), content], spacing=4, tight=True),
                    border=ft.border.all(1, accent), bgcolor=TUI_BG, border_radius=2, padding=8,
                )

            def make_tui_gauge(label, accent=None, width_chars=20):
                """Returns (control, update_fn). Call update_fn(percent) to redraw the bar."""
                accent = accent or TUI_GREEN
                bar_text = ft.Text("", font_family=TUI_FONT, color=accent, size=14)
                pct_text = ft.Text("", font_family=TUI_FONT, color=accent, size=12, width=45)

                def update(percent):
                    percent = max(0, min(100, percent))
                    filled = int(width_chars * percent / 100)
                    bar_text.value = "█" * filled + "░" * (width_chars - filled)
                    pct_text.value = f"{percent:>3.0f}%"

                update(0)
                control = ft.Row([ft.Text(label, font_family=TUI_FONT, color=accent, size=12, width=110), bar_text, pct_text])
                return control, update

            def make_tui_sparkline(label, accent=None, max_points=40):
                """Returns (control, push_fn). Call push_fn(value) to append a new
                data point -- renders the recent history as a Unicode block sparkline."""
                accent = accent or TUI_CYAN
                SPARK_CHARS = "▁▂▃▄▅▆▇█"
                spark_text = ft.Text("", font_family=TUI_FONT, color=accent, size=14)
                history = []

                def push(value):
                    history.append(max(0, value))
                    if len(history) > max_points:
                        history.pop(0)
                    mx = max(history) or 1
                    spark_text.value = "".join(SPARK_CHARS[min(7, int(v / mx * 7))] for v in history)

                push(0)
                control = ft.Row([ft.Text(label, font_family=TUI_FONT, color=accent, size=12, width=110), spark_text])
                return control, push

            def tui_bar_chart(data, accent_map=None, width_chars=24, default_accent=None):
                """data: list of (label, value) tuples. accent_map: optional {label: color}."""
                default_accent = default_accent or TUI_GREEN
                accent_map = accent_map or {}
                mx = max((v for _, v in data), default=1) or 1
                rows = []
                for label, value in data:
                    filled = int(width_chars * value / mx) if mx else 0
                    color = accent_map.get(str(label).upper(), default_accent)
                    rows.append(ft.Row([
                        ft.Text(f"{label:<12}", font_family=TUI_FONT, color=color, size=12, width=100),
                        ft.Text("█" * filled, font_family=TUI_FONT, color=color, size=14),
                        ft.Text(str(value), font_family=TUI_FONT, color=color, size=12),
                    ]))
                if not rows:
                    rows = [ft.Text("(no data yet)", font_family=TUI_FONT, color=ft.colors.GREY_600, size=12)]
                return ft.Column(rows, spacing=2)
            cli_output = ft.ListView(expand=True, auto_scroll=True, spacing=2)

            # Two append-only session transcripts: one for everything triggered from the
            # GUI (buttons/forms), one for everything typed/run in the embedded terminal.
            # Both are written live, line by line, so a crash never loses earlier output.
            LOG_DIR = "logs"
            _session_ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            GUI_LOG_PATH = os.path.join(LOG_DIR, f"gui_session_{_session_ts}.txt")
            CLI_LOG_PATH = os.path.join(LOG_DIR, f"cli_session_{_session_ts}.txt")

            def _write_log_line(path, text):
                try:
                    os.makedirs(LOG_DIR, exist_ok=True)
                    with open(path, "a", encoding="utf-8") as f:
                        f.write(f"[{datetime.now().strftime('%H:%M:%S')}] {text}\n")
                except Exception:
                    pass  # logging failures should never break the UI

            def print_cli(text, color=ft.colors.WHITE, source="GUI"):
                cli_output.controls.append(ft.Text(text, color=color, font_family="Consolas", size=12, selectable=True))
                page.update()
                _write_log_line(GUI_LOG_PATH if source == "GUI" else CLI_LOG_PATH, text)

            _base_print_cli = print_cli  # captured here (outer scope) so execute_cli_command can safely shadow the name below

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
                    print_cli(f"SNIFFER: {msg}", ft.colors.RED_400 if color_str == "RED" else ft.colors.ORANGE_400, source="CLI")

            HELP_TEXT = {
                "scan":        "scan <target> [ports] [--stealth]   Port scan. e.g. scan 192.168.1.5 22,80,1-100 --stealth",
                "discover":    "discover [subnet]                   ARP-sweep a /24 for live hosts (defaults to your local subnet)",
                "traceroute":  "traceroute <target>                 Trace the network hops to a target",
                "bruteforce":  "bruteforce <target> [ftp|http]      Test default credentials against a service (default: ftp)",
                "osint":       "osint <domain>                      Run the full passive OSINT + threat-intel pipeline",
                "resolve":     "resolve <domain>                    Resolve a domain to an IP address",
                "subnet":      "subnet <CIDR>                       Calculate network/broadcast/usable host range",
                "whoami":      "whoami | ip                         Show this machine's current local IP",
                "privileges":  "privileges                           Show OS and admin/root elevation status",
                "sniff":       "sniff <start|stop>                  Start or stop the IDS packet sniffer",
                "testtraffic": "testtraffic [syn|icmp|portscan]     Loopback-only self-test for one IDS detector (default: syn)",
                "fingerprint": "fingerprint <target>                Passive TTL-based OS guess",
                "db":          "db <hosts|ports|vulns|creds|osint|search <term>|stats|clear>   Query or manage the persisted database",
                "honeypot":    "honeypot <start|stop> [port]        Deploy or stop the intrusion-detection honeypot",
                "setip":       "setip <adapter> <ip> [mask] [gw]    Change a network adapter's static IP (Windows, Admin required)",
                "simulate":    "simulate [target] [port] [count]    SIMULATED ONLY -- prints a fake flood log, sends nothing real",
                "clear":       "clear                               Clear the terminal output",
                "help":        "help [command]                      List all commands, or detailed syntax for one",
            }

            def print_help(specific=None):
                if specific and specific.lower() in HELP_TEXT:
                    print_cli(HELP_TEXT[specific.lower()], ft.colors.GREEN_ACCENT, source="CLI"); return
                print_cli("Available commands:", ft.colors.BLUE_200, source="CLI")
                for line in HELP_TEXT.values():
                    print_cli(f"  {line}", ft.colors.WHITE, source="CLI")

            def execute_cli_command(e):
                # Shadow print_cli for the whole rest of this function (and anything
                # defined inside it, like the background run() closures) so every
                # existing print_cli(...) call below is tagged CLI-sourced automatically.
                def print_cli(text, color=ft.colors.WHITE):
                    _base_print_cli(text, color, source="CLI")

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
                                resolved_ip = dns_info["Resolved IP"]
                                print_cli(f"[+] DNS: {resolved_ip} (aliases: {dns_info['Known Aliases']})", ft.colors.GREEN_ACCENT)
                                geo = PassiveEngine.get_ip_geolocation(resolved_ip)
                                if "error" not in geo:
                                    print_cli(f"[+] Geo: {geo.get('Country')}, {geo.get('City')} ({geo.get('ISP')})", ft.colors.GREEN_ACCENT)

                                shodan = IntelEngine.query_shodan(resolved_ip)
                                if "error" not in shodan:
                                    print_cli(f"[+] Shodan: org={shodan['organization']} os={shodan['os']} CVEs={', '.join(shodan['vulnerabilities']) or 'none'}", ft.colors.RED_400 if shodan["vulnerabilities"] else ft.colors.GREEN_ACCENT)
                                else:
                                    print_cli(f"[-] Shodan: {shodan['error']}", ft.colors.GREY_500)

                                for vt_label, vt_target, vt_type in (("IP", resolved_ip, "ip"), ("Domain", target, "domain")):
                                    vt = IntelEngine.query_virustotal(vt_target, vt_type)
                                    if "error" not in vt:
                                        color = {"MALICIOUS": ft.colors.RED_400, "SUSPICIOUS": ft.colors.ORANGE_400, "CLEAN": ft.colors.GREEN_ACCENT}.get(vt["verdict"], ft.colors.WHITE)
                                        print_cli(f"[+] VirusTotal ({vt_label}): {vt['verdict']} ({vt['malicious_hits']} malicious / {vt['suspicious_hits']} suspicious)", color)
                                    else:
                                        print_cli(f"[-] VirusTotal ({vt_label}): {vt['error']}", ft.colors.GREY_500)

                                abuse = IntelEngine.query_abuseipdb(resolved_ip)
                                if "error" not in abuse:
                                    score = abuse["abuse_confidence_score"]
                                    print_cli(f"[+] AbuseIPDB: {score}% confidence, {abuse['total_reports']} report(s)", ft.colors.RED_400 if score > 50 else (ft.colors.ORANGE_400 if score > 0 else ft.colors.GREEN_ACCENT))
                                else:
                                    print_cli(f"[-] AbuseIPDB: {abuse['error']}", ft.colors.GREY_500)

                                reverse_ip = IntelEngine.query_hackertarget_reverse_ip(resolved_ip)
                                hosted = reverse_ip.get("hosted_domains") if "error" not in reverse_ip else None
                                if hosted:
                                    print_cli(f"[+] Reverse IP: {len(hosted)} other domain(s) on {resolved_ip}", ft.colors.GREEN_ACCENT)
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

                        mode = (arg(0) or "syn").lower()
                        TEST_MODES = {
                            "syn": (ScanEngine.ids_self_test_syn_flood, "SYN Flood"),
                            "icmp": (ScanEngine.ids_self_test_icmp_flood, "ICMP Flood"),
                            "portscan": (ScanEngine.ids_self_test_port_scan, "Port Scan"),
                        }
                        if mode not in TEST_MODES:
                            print_cli("[-] Usage: testtraffic [syn|icmp|portscan]", ft.colors.RED_400); return
                        test_fn, label = TEST_MODES[mode]

                        def run():
                            res = test_fn()
                            if "error" in res:
                                print_cli(f"[-] {res['error']}", ft.colors.RED_400)
                            else:
                                print_cli(f"[*] {label} self-test: sent {res['sent']} packet(s) to 127.0.0.1. Watch for the matching alert.", ft.colors.GREEN_ACCENT)
                        threading.Thread(target=run, daemon=True).start()

                    elif command == "fingerprint":
                        if not rest:
                            print_cli("[-] Usage: fingerprint <target>", ft.colors.RED_400); return
                        target = rest[0]

                        def run():
                            res = ScanEngine.fingerprint_os(target)
                            if "error" in res:
                                print_cli(f"[-] {res['error']}", ft.colors.RED_400)
                            else:
                                print_cli(f"[+] {res['ip']}: likely {res['os_guess']} (TTL={res['ttl']})", ft.colors.GREEN_ACCENT)
                                try: db.upsert_host(res["ip"], os_guess=res["os_guess"])
                                except Exception: pass
                        threading.Thread(target=run, daemon=True).start()

                    elif command == "db":
                        sub = (arg(0) or "").lower()
                        if sub == "hosts":
                            hosts = db.get_hosts()
                            print_cli(f"[+] {len(hosts)} host(s):", ft.colors.GREEN_ACCENT)
                            for h in hosts[:30]:
                                print_cli(f"  {h['ip']:<16} MAC={h['mac'] or '-':<18} OS={h['os_guess'] or '-':<20} last_seen={h['last_seen']}", ft.colors.WHITE)
                        elif sub == "ports":
                            ports = db.get_ports(arg(1))
                            print_cli(f"[+] {len(ports)} port record(s):", ft.colors.GREEN_ACCENT)
                            for p in ports[:30]:
                                print_cli(f"  {p['host_ip']:<16} {p['port']:<6} {p['status']:<8} {p['service']}", ft.colors.WHITE)
                        elif sub == "vulns":
                            vulns = db.get_vulnerabilities()
                            print_cli(f"[+] {len(vulns)} vulnerability record(s):", ft.colors.GREEN_ACCENT)
                            for v in vulns[:30]:
                                print_cli(f"  [{v['severity']}] {v['target']} ({v['source']}): {v['description']}", ft.colors.RED_400 if (v['severity'] or '').upper() in ("HIGH", "CRITICAL", "MALICIOUS") else ft.colors.ORANGE_400)
                        elif sub == "creds":
                            creds = db.get_credentials()
                            print_cli(f"[+] {len(creds)} credential record(s):", ft.colors.GREEN_ACCENT)
                            for c in creds[:30]:
                                print_cli(f"  {c['target']:<16} {c['service']:<6} {c['username']}:{c['password']}", ft.colors.RED_400)
                        elif sub == "osint":
                            findings = db.get_osint_findings(arg(1))
                            print_cli(f"[+] {len(findings)} OSINT finding(s):", ft.colors.GREEN_ACCENT)
                            for f in findings[:30]:
                                print_cli(f"  {f['target']:<24} {f['category']:<20} {f['discovered_at']}", ft.colors.WHITE)
                        elif sub == "search":
                            term = arg(1)
                            if not term:
                                print_cli("[-] Usage: db search <term>", ft.colors.RED_400); return
                            res = db.search_all(term)
                            print_cli(f"[+] '{term}': {len(res['hosts'])} host(s), {len(res['ports'])} port(s), {len(res['vulnerabilities'])} vuln(s), {len(res['credentials'])} credential(s)", ft.colors.GREEN_ACCENT)
                        elif sub == "stats":
                            stats = db.get_stats()
                            print_cli(f"[+] {' | '.join(f'{k}: {v}' for k, v in stats.items())}", ft.colors.GREEN_ACCENT)
                        elif sub == "clear":
                            db.clear_all()
                            print_cli("[*] Database cleared.", ft.colors.ORANGE_400)
                        else:
                            print_cli("[-] Usage: db <hosts|ports|vulns|creds|osint|search|stats|clear>", ft.colors.RED_400)

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
                expand=4, bgcolor=TUI_BG, padding=10, border_radius=2, border=ft.border.all(1, TUI_GREEN),
                content=ft.Column([
                    ft.Row([
                        ft.Icon(ft.icons.TERMINAL, color=TUI_GREEN), 
                        ft.Text("Embedded Terminal", weight="bold", font_family=TUI_FONT, color=TUI_GREEN, expand=True)
                    ]),
                    ft.Divider(color=TUI_GREEN), cli_output, cli_input
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
                print_cli(f"[*] Session logs: {GUI_LOG_PATH} (GUI) | {CLI_LOG_PATH} (CLI)", ft.colors.GREY_500)
                print_cli("-" * 68)
                print_cli("Type 'help' for command list.", ft.colors.GREY_500)

            load_boilerplate()

            # ----------------------------------------------------
            # VIEW 1: ACTIVE RECONNAISSANCE 
            # ----------------------------------------------------
            def active_recon_view():
                target_input = ft.TextField(label="Target IP / Domain", value="127.0.0.1", width=280)
                ports_input = ft.TextField(label="Ports (e.g. 22,80,1-1000)", value="22,80,443", width=200)
                profile_dropdown = ft.Dropdown(
                    label="Scan Profile", options=[ft.dropdown.Option(k) for k in SCAN_MODES.keys()], 
                    value="Standard (TCP Connect)", width=250
                )
                progress = ft.ProgressRing(visible=False, width=20, height=20)
                status_text = ft.Text("", font_family=TUI_FONT, color=TUI_GREEN)
                table = ft.DataTable(columns=[
                    ft.DataColumn(ft.Text("Port", font_family=TUI_FONT, color=TUI_GREEN)), ft.DataColumn(ft.Text("Status", font_family=TUI_FONT, color=TUI_GREEN)), ft.DataColumn(ft.Text("Service/Banner", font_family=TUI_FONT, color=TUI_GREEN))
                ], rows=[])

                def export_active_pdf(e):
                    data = _session["port_data"]
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
                    resolved_ip = ScanEngine.resolve_target(target)
                    if resolved_ip:
                        try: db.upsert_host(resolved_ip)
                        except Exception: pass

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
                                if resolved_ip:
                                    try: db.add_vulnerability(resolved_ip, "CVE Heuristic", "HIGH", f"Port {port}: {' / '.join(vulns)}")
                                    except Exception: pass
                        table.rows.append(ft.DataRow(cells=[
                            ft.DataCell(ft.Text(str(port), font_family=TUI_FONT, color=TUI_GREEN)), ft.DataCell(ft.Text(status, color=color, font_family=TUI_FONT)), ft.DataCell(ft.Text(f"{service} | {display_banner}", font_family=TUI_FONT, color=TUI_GREEN))
                        ]))
                        print_cli(f"  [+] {port:<5}/tcp | {status:<8} | {service}", color)
                        if resolved_ip:
                            try: db.add_port(resolved_ip, port, status, service, banner)
                            except Exception: pass
                        page.update()

                    def run():
                        try:
                            res = ScanEngine.stealth_syn_scan(target, ports, on_port) if is_stealth else ScanEngine.port_scan(target, ports, on_port)
                            _session["port_data"] = res
                        except Exception as ex:
                            status_text.value, status_text.color = f"Scan failed: {ex}", ft.colors.RED_400
                        finally:
                            progress.visible = False; page.update()

                    threading.Thread(target=run, daemon=True).start()

                # --- Local Network Device Discovery (ARP sweep) ---
                subnet_input = ft.TextField(label="Subnet (CIDR)", value=get_default_subnet(), width=220)
                discover_progress = ft.ProgressRing(visible=False, width=18, height=18)
                discover_status = ft.Text("", font_family=TUI_FONT, color=TUI_GREEN)
                device_table = ft.DataTable(columns=[
                    ft.DataColumn(ft.Text("IP Address", font_family=TUI_FONT, color=TUI_GREEN)), ft.DataColumn(ft.Text("MAC Address", font_family=TUI_FONT, color=TUI_GREEN))
                ], rows=[])

                def start_discovery(e):
                    device_table.rows.clear(); discover_progress.visible = True; discover_status.value = ""; page.update()
                    subnet = subnet_input.value
                    print_cli(f"PS> discover {subnet}", ft.colors.BLUE_200)

                    def on_device(device):
                        device_table.rows.append(ft.DataRow(cells=[
                            ft.DataCell(ft.Text(device["ip"], font_family=TUI_FONT, color=TUI_GREEN)), ft.DataCell(ft.Text(device["mac"], font_family=TUI_FONT, color=TUI_GREEN))
                        ]))
                        print_cli(f"  [➔] Device Found: IP = {device['ip']:<15} | MAC = {device['mac']}", ft.colors.GREEN_ACCENT)
                        try: db.upsert_host(device["ip"], mac=device["mac"])
                        except Exception: pass
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
                trace_status = ft.Text("", font_family=TUI_FONT, color=TUI_GREEN)
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

                # --- OS Fingerprint ---
                fingerprint_status = ft.Text("", font_family=TUI_FONT, color=TUI_GREEN)

                def start_fingerprint(e):
                    fingerprint_status.value, fingerprint_status.color = "Fingerprinting OS...", ft.colors.GREY_400; page.update()
                    target = target_input.value
                    print_cli(f"PS> fingerprint {target}", ft.colors.BLUE_200)

                    def run():
                        res = ScanEngine.fingerprint_os(target)
                        if "error" in res:
                            fingerprint_status.value, fingerprint_status.color = res["error"], ft.colors.RED_400
                            print_cli(f"[-] {res['error']}", ft.colors.RED_400)
                        else:
                            fingerprint_status.value = f"{res['ip']}: likely {res['os_guess']} (TTL={res['ttl']})"
                            fingerprint_status.color = ft.colors.GREEN_ACCENT
                            print_cli(f"[+] OS Fingerprint: {res['ip']} -> {res['os_guess']} (TTL={res['ttl']})", ft.colors.GREEN_ACCENT)
                            try: db.upsert_host(res["ip"], os_guess=res["os_guess"])
                            except Exception: pass
                        page.update()

                    threading.Thread(target=run, daemon=True).start()

                # --- Default Credential Audit ---
                bf_service_dropdown = ft.Dropdown(
                    label="Service", options=[ft.dropdown.Option("ftp"), ft.dropdown.Option("http")],
                    value="ftp", width=120
                )
                bf_status = ft.Text("", font_family=TUI_FONT, color=TUI_GREEN)

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
                                try: db.add_credential(target, service, res["user"], res["password"])
                                except Exception: pass
                            else:
                                bf_status.value, bf_status.color = "No common credentials succeeded.", ft.colors.GREEN_ACCENT
                                print_cli("[*] No common credentials succeeded.", ft.colors.GREEN_ACCENT)
                        except Exception as ex:
                            bf_status.value, bf_status.color = f"Credential audit failed: {ex}", ft.colors.RED_400
                            print_cli(f"[-] Credential audit failed: {ex}", ft.colors.RED_400)
                        page.update()

                    threading.Thread(target=run, daemon=True).start()

                return ft.Column([
                    ft.Text("Active Network Probing", size=22, weight="bold", font_family=TUI_FONT, color=TUI_GREEN),
                    ft.Row([target_input, ports_input, profile_dropdown], wrap=True, spacing=10, run_spacing=10),
                    ft.Row([ft.ElevatedButton("Engage Target", on_click=start_scan), ft.ElevatedButton("Export PDF", on_click=export_active_pdf, icon=ft.icons.PICTURE_AS_PDF, icon_color=ft.colors.RED_400), progress], wrap=True),
                    status_text, ft.Divider(), tui_box("SCAN RESULTS", ft.Container(ft.ListView([table], auto_scroll=True), height=240)),

                    ft.Divider(),
                    make_collapsible("Local Network Device Discovery (ARP Sweep)", ft.Column([
                        ft.Row([subnet_input, ft.ElevatedButton("Discover Devices", on_click=start_discovery), discover_progress], wrap=True),
                        discover_status, tui_box("DISCOVERED DEVICES", ft.Container(ft.ListView([device_table], auto_scroll=True), height=150)),
                    ])),

                    ft.Divider(),
                    make_collapsible("Traceroute, OS Fingerprint & Default Credential Audit", ft.Column([
                        ft.Row([
                            ft.ElevatedButton("Trace Route", on_click=start_traceroute),
                            ft.ElevatedButton("Fingerprint OS", on_click=start_fingerprint),
                            bf_service_dropdown,
                            ft.ElevatedButton("Test Default Credentials", on_click=start_bruteforce),
                        ], wrap=True),
                        trace_status, tui_box("TRACEROUTE", ft.Container(trace_output, height=100, padding=5)),
                        fingerprint_status, bf_status,
                    ])),
                ], expand=True, scroll=ft.ScrollMode.AUTO, spacing=8)

            # ----------------------------------------------------
            # VIEW 2: SIEM REAL-TIME MONITORING
            # ----------------------------------------------------
            def monitor_view():
                is_running_now = monitor_state["running"]
                target_input = ft.TextField(label="Target to Monitor", value="127.0.0.1", width=280)
                interval_input = ft.TextField(label="Interval (Seconds)", value="10", width=150)
                monitor_status = ft.Text(
                    "Status: ACTIVE MONITORING" if is_running_now else "Status: Idle",
                    color=ft.colors.GREEN_ACCENT if is_running_now else ft.colors.GREY_400
                , font_family=TUI_FONT)
                log_list = ft.ListView(auto_scroll=True, spacing=5)
                open_gauge, update_gauge = make_tui_gauge("Ports Open")
                toggle_button = ft.ElevatedButton("Stop Monitoring" if is_running_now else "Start Monitoring")

                def toggle_monitor(e):
                    # monitor_state is shared module-level state (see its definition),
                    # not a local variable -- so this stays correct even if this view
                    # gets rebuilt for any reason while monitoring is active, instead
                    # of letting a second monitor_loop spawn alongside an already-
                    # running one against the same target.
                    if monitor_state["running"]:
                        monitor_state["running"] = False
                        e.control.text, monitor_status.value, monitor_status.color = "Start Monitoring", "Status: Idle", ft.colors.GREY_400
                        print_cli("PS> monitor stop", ft.colors.BLUE_200)
                    else:
                        monitor_state["running"] = True
                        monitor_state["last_state"] = {}
                        e.control.text, monitor_status.value, monitor_status.color = "Stop Monitoring", "Status: ACTIVE MONITORING", ft.colors.GREEN_ACCENT
                        print_cli(f"PS> monitor start {target_input.value} --interval {interval_input.value}", ft.colors.BLUE_200)
                        threading.Thread(target=monitor_loop, daemon=True).start()
                    page.update()

                toggle_button.on_click = toggle_monitor

                def monitor_loop():
                    target = target_input.value
                    try: interval = int(interval_input.value)
                    except Exception: interval = 10
                    monitored_ports = [21, 22, 80, 443, 3306, 3389, 8080]

                    while monitor_state["running"]:
                        current_scan = ScanEngine.port_scan(target, monitored_ports, workers=10)
                        current_state = {str(p["port"]): p["status"] for p in current_scan if "port" in p}
                        timestamp = datetime.now().strftime("%H:%M:%S")
                        open_count = sum(1 for s in current_state.values() if s == "OPEN")
                        update_gauge(100 * open_count / len(monitored_ports))

                        last_state = monitor_state["last_state"]
                        if last_state:
                            for port, status in current_state.items():
                                old_status = last_state.get(port, "CLOSED")
                                if status != old_status:
                                    msg = f"[{timestamp}] ALERT: Port {port} changed from {old_status} -> {status}"
                                    log_list.controls.append(ft.Text(msg, color=ft.colors.RED_400, weight="bold", font_family=TUI_FONT))
                                    print_cli(f"SIEM ALERT: {msg}", ft.colors.RED_400)
                        else:
                            log_list.controls.append(ft.Text(f"[{timestamp}] Baseline established.", color=ft.colors.BLUE_200, font_family=TUI_FONT))

                        monitor_state["last_state"] = current_state
                        page.update(); time.sleep(interval)

                return ft.Column([
                    ft.Text("Real-Time SIEM Monitoring", size=22, weight="bold", font_family=TUI_FONT, color=TUI_GREEN),
                    ft.Row([target_input, interval_input, toggle_button], wrap=True, spacing=10, run_spacing=10),
                    monitor_status, open_gauge, ft.Divider(),
                    tui_box("SIEM EVENT LOG", ft.Container(log_list, height=400, padding=4))
                ], expand=True, scroll=ft.ScrollMode.AUTO, spacing=8)

            # ----------------------------------------------------
            # VIEW 3: PASSIVE RECONNAISSANCE 
            # ----------------------------------------------------
            def passive_recon_view():
                target_input = ft.TextField(label="Target Domain", value="example.com", width=280)
                results_list = ft.ListView(spacing=10, auto_scroll=True)
                progress = ft.ProgressRing(visible=False, width=20, height=20)

                def export_passive_pdf(e):
                    data = _session["passive_data"]
                    if data:
                        path = generate_pdf_report(data, title="Passive OSINT Report", filename="Passive_OSINT")
                        snack = ft.SnackBar(ft.Text(f"PDF Saved: {path}", font_family=TUI_FONT, color=TUI_GREEN), open=True)
                        page.overlay.append(snack)
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
                                    ft.Text("DNS Resolution", weight="bold", color=TUI_CYAN, font_family=TUI_FONT),
                                    ft.Text(f"Domain: {dns_info['Target Domain']}", size=12, font_family=TUI_FONT, color=TUI_GREEN),
                                    ft.Text(f"Resolved IP: {dns_info['Resolved IP']}", size=12, font_family=TUI_FONT, color=TUI_GREEN),
                                    ft.Text(f"Aliases: {dns_info['Known Aliases']}", size=12, font_family=TUI_FONT, color=TUI_GREEN),
                                ]))))
                                print_cli(f"[+] DNS: {dns_info['Resolved IP']} (aliases: {dns_info['Known Aliases']})", ft.colors.GREEN_ACCENT)
                                try:
                                    db.upsert_host(dns_info["Resolved IP"], hostname=target)
                                    db.add_osint_finding(target, "DNS", dns_info)
                                except Exception: pass
                                page.update()

                                geo = PassiveEngine.get_ip_geolocation(dns_info["Resolved IP"])
                                export_data.append({"Geolocation": geo})
                                if "error" not in geo:
                                    geo_text = "\n".join([f"{k}: {v}" for k, v in geo.items()])
                                    results_list.controls.append(ft.Card(content=ft.Container(padding=15, content=ft.Column([
                                        ft.Text("IP Geolocation", weight="bold", color=TUI_CYAN, font_family=TUI_FONT), ft.Text(geo_text, size=12, font_family=TUI_FONT, color=TUI_GREEN)
                                    ]))))
                                    print_cli(f"[+] Geo: {geo.get('Country')}, {geo.get('City')} ({geo.get('ISP')})", ft.colors.GREEN_ACCENT)
                                    try: db.add_osint_finding(target, "Geolocation", geo)
                                    except Exception: pass
                                    page.update()

                                # --- Threat Intelligence (Shodan / VirusTotal / AbuseIPDB / Reverse IP) ---
                                resolved_ip = dns_info["Resolved IP"]

                                shodan = IntelEngine.query_shodan(resolved_ip)
                                export_data.append({"Shodan": shodan})
                                if "error" not in shodan:
                                    has_vulns = bool(shodan["vulnerabilities"])
                                    shodan_text = (
                                        f"Organization: {shodan['organization']}\n"
                                        f"OS: {shodan['os']}\n"
                                        f"Historical Open Ports: {', '.join(map(str, shodan['ports'])) or 'None'}\n"
                                        f"Hostnames: {', '.join(shodan['hostnames']) or 'None'}\n"
                                        f"Known CVEs: {', '.join(shodan['vulnerabilities']) or 'None'}"
                                    )
                                    results_list.controls.append(ft.Card(content=ft.Container(padding=15, content=ft.Column([
                                        ft.Text("Shodan Threat Intelligence", weight="bold", color=ft.colors.RED_400 if has_vulns else ft.colors.BLUE_200, font_family=TUI_FONT),
                                        ft.Text(shodan_text, size=12, font_family=TUI_FONT, color=TUI_GREEN)
                                    ]))))
                                    print_cli(f"[+] Shodan: org={shodan['organization']} os={shodan['os']} CVEs={', '.join(shodan['vulnerabilities']) or 'none'}", ft.colors.RED_400 if has_vulns else ft.colors.GREEN_ACCENT)
                                    try:
                                        db.add_osint_finding(target, "Shodan", shodan)
                                        for cve in shodan["vulnerabilities"]:
                                            db.add_vulnerability(resolved_ip, "Shodan", "HIGH", cve)
                                    except Exception: pass
                                else:
                                    results_list.controls.append(ft.Card(content=ft.Container(padding=15, content=ft.Column([
                                        ft.Text("Shodan Threat Intelligence", weight="bold", color=ft.colors.GREY_400, font_family=TUI_FONT),
                                        ft.Text(shodan["error"], size=12, color=ft.colors.GREY_400, font_family=TUI_FONT)
                                    ]))))
                                    print_cli(f"[-] Shodan: {shodan['error']}", ft.colors.GREY_500)
                                page.update()

                                verdict_colors = {"MALICIOUS": ft.colors.RED_400, "SUSPICIOUS": ft.colors.ORANGE_400, "CLEAN": ft.colors.GREEN_ACCENT}
                                for vt_label, vt_target, vt_type in (("IP", resolved_ip, "ip"), ("Domain", target, "domain")):
                                    vt = IntelEngine.query_virustotal(vt_target, vt_type)
                                    export_data.append({f"VirusTotal ({vt_label})": vt})
                                    if "error" not in vt:
                                        vt_text = f"Verdict: {vt['verdict']}\nMalicious: {vt['malicious_hits']}  Suspicious: {vt['suspicious_hits']}  Harmless: {vt['harmless_hits']}"
                                        results_list.controls.append(ft.Card(content=ft.Container(padding=15, content=ft.Column([
                                            ft.Text(f"VirusTotal Reputation ({vt_label})", weight="bold", color=verdict_colors.get(vt["verdict"], ft.colors.WHITE), font_family=TUI_FONT),
                                            ft.Text(vt_text, size=12, font_family=TUI_FONT, color=TUI_GREEN)
                                        ]))))
                                        print_cli(f"[+] VirusTotal ({vt_label}): {vt['verdict']} ({vt['malicious_hits']} malicious / {vt['suspicious_hits']} suspicious)", verdict_colors.get(vt["verdict"], ft.colors.WHITE))
                                        try:
                                            db.add_osint_finding(target, f"VirusTotal ({vt_label})", vt)
                                            if vt["verdict"] != "CLEAN":
                                                db.add_vulnerability(vt_target, "VirusTotal", vt["verdict"], f"{vt['malicious_hits']} malicious / {vt['suspicious_hits']} suspicious engine hits")
                                        except Exception: pass
                                    else:
                                        results_list.controls.append(ft.Card(content=ft.Container(padding=15, content=ft.Column([
                                            ft.Text(f"VirusTotal Reputation ({vt_label})", weight="bold", color=ft.colors.GREY_400, font_family=TUI_FONT),
                                            ft.Text(vt["error"], size=12, color=ft.colors.GREY_400, font_family=TUI_FONT)
                                        ]))))
                                        print_cli(f"[-] VirusTotal ({vt_label}): {vt['error']}", ft.colors.GREY_500)
                                page.update()

                                abuse = IntelEngine.query_abuseipdb(resolved_ip)
                                export_data.append({"AbuseIPDB": abuse})
                                if "error" not in abuse:
                                    score = abuse["abuse_confidence_score"]
                                    score_color = ft.colors.RED_400 if score > 50 else (ft.colors.ORANGE_400 if score > 0 else ft.colors.GREEN_ACCENT)
                                    abuse_text = (
                                        f"Abuse Confidence Score: {score}%\n"
                                        f"Total Reports: {abuse['total_reports']}\n"
                                        f"Usage Type: {abuse['usage_type']}\n"
                                        f"Associated Domain: {abuse['domain']}"
                                    )
                                    results_list.controls.append(ft.Card(content=ft.Container(padding=15, content=ft.Column([
                                        ft.Text("AbuseIPDB Reputation", weight="bold", color=score_color, font_family=TUI_FONT), ft.Text(abuse_text, size=12, font_family=TUI_FONT, color=TUI_GREEN)
                                    ]))))
                                    print_cli(f"[+] AbuseIPDB: {score}% confidence, {abuse['total_reports']} report(s)", score_color)
                                    try:
                                        db.add_osint_finding(target, "AbuseIPDB", abuse)
                                        if score > 0:
                                            db.add_vulnerability(resolved_ip, "AbuseIPDB", "HIGH" if score > 50 else "MEDIUM", f"Abuse confidence {score}%, {abuse['total_reports']} report(s)")
                                    except Exception: pass
                                else:
                                    results_list.controls.append(ft.Card(content=ft.Container(padding=15, content=ft.Column([
                                        ft.Text("AbuseIPDB Reputation", weight="bold", color=ft.colors.GREY_400, font_family=TUI_FONT),
                                        ft.Text(abuse["error"], size=12, color=ft.colors.GREY_400, font_family=TUI_FONT)
                                    ]))))
                                    print_cli(f"[-] AbuseIPDB: {abuse['error']}", ft.colors.GREY_500)
                                page.update()

                                reverse_ip = IntelEngine.query_hackertarget_reverse_ip(resolved_ip)
                                export_data.append({"Reverse IP Lookup": reverse_ip})
                                hosted = reverse_ip.get("hosted_domains") if "error" not in reverse_ip else None
                                if hosted:
                                    results_list.controls.append(ft.Card(content=ft.Container(padding=15, content=ft.Column([
                                        ft.Text("Other Domains Hosted on This IP", weight="bold", color=TUI_CYAN, font_family=TUI_FONT),
                                        ft.Text("\n".join(hosted[:15]), size=12, font_family=TUI_FONT, color=TUI_GREEN)
                                    ]))))
                                    print_cli(f"[+] Reverse IP: {len(hosted)} other domain(s) on {resolved_ip}", ft.colors.GREEN_ACCENT)
                                    try: db.add_osint_finding(target, "Reverse IP Lookup", reverse_ip)
                                    except Exception: pass
                                    page.update()
                            else:
                                print_cli(f"[-] {dns_info['error']}", ft.colors.RED_400)

                            whois = PassiveEngine.get_whois(target)
                            export_data.append({"WHOIS": whois})
                            results_list.controls.append(ft.Card(content=ft.Container(padding=15, content=ft.Column([
                                ft.Text("WHOIS Registry", weight="bold", color=TUI_CYAN, font_family=TUI_FONT), ft.Text(whois[:300] + "...", size=12, font_family=TUI_FONT, color=TUI_GREEN)
                            ]))))
                            print_cli(f"[+] WHOIS: {whois[:150]}...", ft.colors.GREEN_ACCENT)
                            try: db.add_osint_finding(target, "WHOIS", whois)
                            except Exception: pass
                            page.update()

                            subs = PassiveEngine.get_subdomains(target)
                            if subs:
                                export_data.append({"Subdomains": subs})
                                results_list.controls.append(ft.Card(content=ft.Container(padding=15, content=ft.Column([
                                    ft.Text("Subdomains", weight="bold", color=TUI_CYAN, font_family=TUI_FONT), ft.Text("\n".join(subs), size=12, font_family=TUI_FONT, color=TUI_GREEN)
                                ]))))
                                print_cli(f"[+] Subdomains: {', '.join(subs[:10])}", ft.colors.GREEN_ACCENT)
                                try: db.add_osint_finding(target, "Subdomains", subs)
                                except Exception: pass
                                page.update()

                            headers_audit = WebVulnScanner.analyze_website(target)
                            if headers_audit and "error" not in headers_audit[0]:
                                export_data.append({"Header Misconfigurations": headers_audit})
                                audit_text = "\n".join([f"[{v.get('severity', 'Info')}] {v.get('vulnerability', '')} - {v.get('remediation', '')}" for v in headers_audit])
                                results_list.controls.append(ft.Card(content=ft.Container(padding=15, content=ft.Column([
                                    ft.Text("HTTP Header Security Audit", weight="bold", color=ft.colors.ORANGE_400, font_family=TUI_FONT), ft.Text(audit_text, size=12, font_family=TUI_FONT, color=TUI_GREEN)
                                ]))))
                                for v in headers_audit:
                                    print_cli(f"  [!] [{v.get('severity')}] {v.get('vulnerability')}", ft.colors.ORANGE_400)
                                    if v.get("severity", "Info") != "Info":
                                        try: db.add_vulnerability(target, "Header Audit", v.get("severity", "MEDIUM"), v.get("vulnerability", ""))
                                        except Exception: pass
                                page.update()

                            fuzz = WebVulnScanner.fuzz_directories(target)
                            if fuzz:
                                export_data.append({"Fuzzing Hits": fuzz})
                                fuzz_text = "\n".join([f"{f['path']} ({f['status']})" for f in fuzz])
                                results_list.controls.append(ft.Card(content=ft.Container(padding=15, content=ft.Column([
                                    ft.Text("Fuzzing Hits", weight="bold", color=ft.colors.RED_300, font_family=TUI_FONT), ft.Text(fuzz_text, color=ft.colors.GREEN_ACCENT, font_family=TUI_FONT)
                                ]))))
                                for f in fuzz:
                                    print_cli(f"  [+] Found path: {f['path']} ({f['status']})", ft.colors.GREEN_ACCENT)
                                try: db.add_osint_finding(target, "Fuzzing Hits", fuzz)
                                except Exception: pass

                            print_cli("[*] OSINT pipeline complete.", ft.colors.GREEN_ACCENT)
                        except Exception as ex:
                            results_list.controls.append(ft.Text(f"OSINT pipeline error: {ex}", color=ft.colors.RED_400, font_family=TUI_FONT))
                            print_cli(f"[-] OSINT pipeline error: {ex}", ft.colors.RED_400)
                        finally:
                            _session["passive_data"] = export_data
                            progress.visible = False; page.update()

                    threading.Thread(target=run, daemon=True).start()

                return ft.Column([
                    ft.Text("Passive OSINT & Fuzzing", size=22, weight="bold", font_family=TUI_FONT, color=TUI_GREEN),
                    ft.Row([target_input, ft.ElevatedButton("Run Full OSINT", on_click=start_osint), ft.ElevatedButton("Export PDF", on_click=export_passive_pdf, icon=ft.icons.PICTURE_AS_PDF, icon_color=ft.colors.RED_400), progress], wrap=True, spacing=10, run_spacing=10),
                    ft.Divider(), tui_box("OSINT FINDINGS", ft.Container(results_list, height=450))
                ], expand=True, scroll=ft.ScrollMode.AUTO, spacing=8)

            # ----------------------------------------------------
            # VIEW 4: BLUE TEAM DEFENSE
            # ----------------------------------------------------
            def defense_view():
                current_ip = IPManager.get_current_ip()
                adapter_input = ft.TextField(label="Windows Adapter (e.g. Wi-Fi)", width=250)
                new_ip_input = ft.TextField(label="New Static IP", width=150)
                ip_status = ft.Text("", font_family=TUI_FONT, color=TUI_GREEN)

                def update_ip(e):
                    ip_status.value = "Attempting to change IP (Requires Admin)..."; page.update()
                    print_cli(f"PS> setip {adapter_input.value} {new_ip_input.value}", ft.colors.BLUE_200)
                    res = IPManager.change_windows_ip(adapter_input.value, new_ip_input.value)
                    ip_status.value = res
                    ip_status.color = ft.colors.GREEN_ACCENT if "Success" in res else ft.colors.RED_400
                    print_cli(f"[*] {res}", ip_status.color)
                    page.update()

                hp_port_input = ft.TextField(label="Honeypot Port", value="22", width=120)
                hp_is_active_now = global_honeypot.is_active
                hp_status = ft.Text(
                    "Status: ACTIVE" if hp_is_active_now else "Status: Offline",
                    color=ft.colors.GREEN_ACCENT if hp_is_active_now else ft.colors.GREY_400
                , font_family=TUI_FONT)
                hp_logs = ft.ListView(auto_scroll=True, spacing=5)

                def hp_logger(msg):
                    color = ft.colors.RED_400 if "INTRUSION" in msg else ft.colors.GREEN_ACCENT
                    hp_logs.controls.append(ft.Text(msg, color=color, font_family=TUI_FONT)); print_cli(f"HONEYPOT: {msg}", color); page.update()

                def toggle_honeypot(e):
                    if global_honeypot.is_active:
                        global_honeypot.stop()
                        e.control.text, e.control.bgcolor = "Deploy Honeypot", None
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
                    ft.Text("Blue Team Defense Tools", size=22, weight="bold", font_family=TUI_FONT, color=TUI_GREEN), ft.Divider(),
                    ft.Text("Host Network Management", weight="bold", color=TUI_CYAN, font_family=TUI_FONT),
                    ft.Text(f"Current Local IP Address: {current_ip}", size=16, color=ft.colors.GREEN_ACCENT, font_family=TUI_FONT),
                    ft.Row([adapter_input, new_ip_input, ft.ElevatedButton("Change IP", on_click=update_ip)], wrap=True, spacing=10, run_spacing=10), ip_status,
                    ft.Divider(),
                    ft.Text("Intrusion Detection Honeypot", weight="bold", color=TUI_CYAN, font_family=TUI_FONT),
                    ft.Text("Deploys a fake service to log unauthorized network scans against your machine.", color=ft.colors.GREY_400, font_family=TUI_FONT),
                    ft.Row([hp_port_input, ft.ElevatedButton(
                        "Deactivate Honeypot" if hp_is_active_now else "Deploy Honeypot",
                        on_click=toggle_honeypot,
                        bgcolor=ft.colors.RED_700 if hp_is_active_now else None
                    )], wrap=True, spacing=10, run_spacing=10), hp_status,
                    tui_box("HONEYPOT LOG", ft.Container(hp_logs, height=280, padding=4))
                ], expand=True, scroll=ft.ScrollMode.AUTO, spacing=8)

            # ----------------------------------------------------
            # VIEW 5: IDS PACKET SNIFFER
            # ----------------------------------------------------
            def sniffer_view():
                is_running_now = sniffer_instance.running
                log_list = ft.ListView(auto_scroll=True, spacing=2)
                status_text = ft.Text(
                    "ACTIVE - Capturing Traffic..." if is_running_now else "Sniffer Offline",
                    color=ft.colors.GREEN_ACCENT if is_running_now else ft.colors.GREY_400
                , font_family=TUI_FONT)
                activity_spark, push_activity = make_tui_sparkline("Alert Activity")

                def map_color(color_str):
                    colors = {"WHITE": ft.colors.WHITE, "RED": ft.colors.RED_400, "GREEN": ft.colors.GREEN_ACCENT, "ORANGE": ft.colors.ORANGE_400, "GREY": ft.colors.GREY_500}
                    return colors.get(color_str, ft.colors.WHITE)

                def sniffer_log(msg, color_str="WHITE"):
                    log_list.controls.append(ft.Text(msg, color=map_color(color_str), font_family="Consolas", size=12))
                    if len(log_list.controls) > 500: log_list.controls.pop(0)
                    # Pulse the sparkline on each alert -- gives an at-a-glance sense
                    # of how frequently the IDS is firing, without spamming the log.
                    is_alert = color_str in ("RED", "ORANGE")
                    push_activity(1 if is_alert else 0)
                    if is_alert:
                        # Also mirror to the global terminal (matching cli_sniffer_log's
                        # behavior for the 'sniff start' command) -- this keeps alerts
                        # visible even if this tab gets rebuilt and its local log_list
                        # is orphaned, since the terminal panel is shared, not per-view.
                        print_cli(f"SNIFFER: {msg}", map_color(color_str))
                    page.update()

                def toggle_sniffer(e):
                    if sniffer_instance.running:
                        sniffer_instance.stop()
                        e.control.text, e.control.icon, e.control.bgcolor = "Start Sniffing", ft.icons.PLAY_ARROW, None
                        status_text.value, status_text.color = "Sniffer Offline", ft.colors.GREY_400
                        print_cli("PS> sniff stop", ft.colors.BLUE_200)
                    else:
                        log_list.controls.clear()
                        e.control.text, e.control.icon, e.control.bgcolor = "Stop Sniffing", ft.icons.STOP, ft.colors.RED_900
                        status_text.value, status_text.color = "ACTIVE - Capturing Traffic...", ft.colors.GREEN_ACCENT
                        print_cli("PS> sniff start", ft.colors.BLUE_200)
                        threading.Thread(target=sniffer_instance.start, args=(sniffer_log,), daemon=True).start()
                    page.update()

                def run_self_test(test_status, label, engine_call, success_msg):
                    """Shared driver for the three IDS self-test buttons below."""
                    if not sniffer_instance.running:
                        test_status.value, test_status.color = "Start the sniffer above first, so it can observe the test traffic.", ft.colors.ORANGE_400
                        page.update(); return
                    test_status.value, test_status.color = f"Running {label} self-test...", ft.colors.GREY_400
                    page.update()
                    print_cli(f"PS> testtraffic {label.lower().replace(' ', '')} (loopback only)", ft.colors.BLUE_200)

                    def run():
                        try:
                            res = engine_call()
                            if "error" in res:
                                test_status.value, test_status.color = res["error"], ft.colors.RED_400
                            else:
                                test_status.value, test_status.color = success_msg(res), ft.colors.GREEN_ACCENT
                        except Exception as ex:
                            test_status.value, test_status.color = f"{label} self-test failed: {ex}", ft.colors.RED_400
                        page.update()

                    threading.Thread(target=run, daemon=True).start()

                syn_test_status = ft.Text("", font_family=TUI_FONT, color=TUI_GREEN)
                icmp_test_status = ft.Text("", font_family=TUI_FONT, color=TUI_GREEN)
                portscan_test_status = ft.Text("", font_family=TUI_FONT, color=TUI_GREEN)

                def test_syn_flood(e):
                    run_self_test(syn_test_status, "SYN Flood",
                                  lambda: ScanEngine.ids_self_test_syn_flood(),
                                  lambda res: f"Sent {res['sent']} real SYN packets to 127.0.0.1:8765 -- watch for a SYN Flood alert.")

                def test_icmp_flood(e):
                    run_self_test(icmp_test_status, "ICMP Flood",
                                  lambda: ScanEngine.ids_self_test_icmp_flood(),
                                  lambda res: f"Sent {res['sent']} real ICMP echoes to 127.0.0.1 -- watch for an ICMP Flood alert.")

                def test_port_scan(e):
                    run_self_test(portscan_test_status, "Port Scan",
                                  lambda: ScanEngine.ids_self_test_port_scan(),
                                  lambda res: f"Sent 1 SYN each to {res['sent']} distinct ports on 127.0.0.1 -- watch for a Port Scan alert.")

                return ft.Column([
                    ft.Text("Intrusion Detection Sniffer", size=22, weight="bold", font_family=TUI_FONT, color=TUI_GREEN),
                    ft.Text("Monitors local interfaces for suspicious traffic and MITRE ATT&CK patterns.", color=ft.colors.GREY_400, font_family=TUI_FONT),
                    ft.Row([ft.ElevatedButton(
                        "Stop Sniffing" if is_running_now else "Start Sniffing",
                        icon=ft.icons.STOP if is_running_now else ft.icons.PLAY_ARROW,
                        bgcolor=ft.colors.RED_900 if is_running_now else None,
                        on_click=toggle_sniffer
                    ), status_text], wrap=True),
                    activity_spark, ft.Divider(),
                    tui_box("LIVE TRAFFIC", ft.Container(log_list, height=360)),
                    ft.Divider(),
                    ft.Text("IDS Self-Test", weight="bold", color=TUI_CYAN, font_family=TUI_FONT),
                    ft.Text("Each button fires real (but harmless, loopback-only) traffic designed to trip exactly one of the detectors above, so you can verify all three independently.", color=ft.colors.GREY_400, size=12, font_family=TUI_FONT),
                    ft.Row([ft.ElevatedButton("Test SYN Flood Detection", icon=ft.icons.BUG_REPORT, on_click=test_syn_flood), syn_test_status], wrap=True),
                    ft.Row([ft.ElevatedButton("Test ICMP Flood Detection", icon=ft.icons.BUG_REPORT, on_click=test_icmp_flood), icmp_test_status], wrap=True),
                    ft.Row([ft.ElevatedButton("Test Port Scan Detection", icon=ft.icons.BUG_REPORT, on_click=test_port_scan), portscan_test_status], wrap=True),
                ], expand=True, scroll=ft.ScrollMode.AUTO, spacing=8)

            # ----------------------------------------------------
            # VIEW 6: TOOLS & AUDIT LOGS
            # ----------------------------------------------------
            def tools_view():
                resolve_input = ft.TextField(label="Domain/URL to Resolve", value="google.com", width=280)
                resolve_output = ft.Text("", font_family=TUI_FONT, color=TUI_GREEN)

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

                ip_input = ft.TextField(label="CIDR Network Range (e.g. 192.168.1.0/24)", width=320)
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
                            ft.Text(f"Network Address: {net.network_address}", font_family=TUI_FONT, color=TUI_GREEN), ft.Text(f"Broadcast: {net.broadcast_address}", font_family=TUI_FONT, color=TUI_GREEN),
                            ft.Text(f"Netmask: {net.netmask}", font_family=TUI_FONT, color=TUI_GREEN), ft.Text(f"Usable Hosts: {usable}", color=TUI_GREEN, font_family=TUI_FONT),
                            ft.Text(f"Host Range: {first} -> {last}", font_family=TUI_FONT, color=TUI_GREEN)
                        ]
                        print_cli(f"[+] Network: {net.network_address}  Usable Hosts: {usable}", ft.colors.GREEN_ACCENT)
                    except Exception as ex:
                        output_col.controls.append(ft.Text(f"Error: {ex}", color=ft.colors.RED_400, font_family=TUI_FONT))
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
                    ft.Text("Networking Utilities & System Audit", size=22, weight="bold", font_family=TUI_FONT, color=TUI_GREEN), ft.Divider(),
                    ft.Text("Domain-to-IP Resolver", weight="bold", color=TUI_CYAN, font_family=TUI_FONT),
                    ft.Row([resolve_input, ft.ElevatedButton("Resolve IP", on_click=do_resolve)], wrap=True, spacing=10, run_spacing=10), resolve_output,
                    ft.Divider(),
                    ft.Text("Subnet Calculator", weight="bold", color=TUI_CYAN, font_family=TUI_FONT),
                    ft.Row([ip_input, ft.ElevatedButton("Compute Subnet", on_click=calculate)], wrap=True, spacing=10, run_spacing=10), output_col,
                    ft.Divider(),
                    ft.Row([ft.IconButton(icon=ft.icons.REFRESH, on_click=refresh_audit_logs, tooltip="Refresh Logs")], wrap=True),
                    tui_box("SYSTEM AUDIT LOG", ft.Container(log_display, height=220, padding=4))
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
                                sim_print("[i] [SIM] For REAL flood detection (safely), use the IDS Self-Test buttons on the Sniffer tab.", TUI_ORANGE)
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
                        ft.Icon(ft.icons.WARNING_AMBER_ROUNDED, color=TUI_ORANGE),
                        ft.Text("DoS / DDoS Console -- SIMULATION ONLY", size=22, weight="bold", color=TUI_ORANGE, font_family=TUI_FONT),
                    ], wrap=True),
                    ft.Container(
                        padding=10, bgcolor="#231a08", border_radius=2, border=ft.border.all(1, TUI_ORANGE),
                        content=ft.Text(
                            "This panel is a visual mock-up for demos and training only. It does not open sockets, "
                            "craft packets, resolve hosts, or send any network traffic of any kind -- it only prints "
                            "scripted text with fake counters. For a real, safe demonstration of the IDS detecting an "
                            "actual flood, use the IDS Self-Test buttons on the Sniffer tab (loopback only).",
                            color="#FFD699", size=12, font_family=TUI_FONT
                        )
                    ),
                    ft.Divider(),
                    ft.Row([target_input, port_input, method_dropdown, count_input], wrap=True, spacing=10, run_spacing=10),
                    ft.Row([
                        ft.ElevatedButton("Run Simulation", icon=ft.icons.PLAY_ARROW, on_click=run_simulation, color=TUI_ORANGE, bgcolor=TUI_BG,
                                          style=ft.ButtonStyle(side=ft.BorderSide(1, TUI_ORANGE), shape=ft.RoundedRectangleBorder(radius=2))),
                        ft.ElevatedButton("Stop", icon=ft.icons.STOP, on_click=stop_simulation, color=TUI_RED, bgcolor=TUI_BG,
                                          style=ft.ButtonStyle(side=ft.BorderSide(1, TUI_RED), shape=ft.RoundedRectangleBorder(radius=2))),
                    ], wrap=True),
                    ft.Divider(),
                    tui_box("SIMULATED CONSOLE -- NO REAL TRAFFIC", ft.Container(term_output, height=380, padding=4), accent="#FFA500")
                ], expand=True, scroll=ft.ScrollMode.AUTO, spacing=8)

            # ----------------------------------------------------
            # VIEW 8: DATABASE (persisted hosts / vulns / creds / OSINT)
            # ----------------------------------------------------
            def database_view():
                stats_text = ft.Text("", color=ft.colors.GREY_400, font_family=TUI_FONT)
                hosts_table = ft.DataTable(columns=[
                    ft.DataColumn(ft.Text("IP", font_family=TUI_FONT, color=TUI_GREEN)), ft.DataColumn(ft.Text("MAC", font_family=TUI_FONT, color=TUI_GREEN)), ft.DataColumn(ft.Text("Hostname", font_family=TUI_FONT, color=TUI_GREEN)),
                    ft.DataColumn(ft.Text("OS Guess", font_family=TUI_FONT, color=TUI_GREEN)), ft.DataColumn(ft.Text("Last Seen", font_family=TUI_FONT, color=TUI_GREEN))
                ], rows=[])
                vulns_table = ft.DataTable(columns=[
                    ft.DataColumn(ft.Text("Target", font_family=TUI_FONT, color=TUI_GREEN)), ft.DataColumn(ft.Text("Source", font_family=TUI_FONT, color=TUI_GREEN)), ft.DataColumn(ft.Text("Severity", font_family=TUI_FONT, color=TUI_GREEN)),
                    ft.DataColumn(ft.Text("Description", font_family=TUI_FONT, color=TUI_GREEN)), ft.DataColumn(ft.Text("Found", font_family=TUI_FONT, color=TUI_GREEN))
                ], rows=[])
                creds_table = ft.DataTable(columns=[
                    ft.DataColumn(ft.Text("Target", font_family=TUI_FONT, color=TUI_GREEN)), ft.DataColumn(ft.Text("Service", font_family=TUI_FONT, color=TUI_GREEN)), ft.DataColumn(ft.Text("User", font_family=TUI_FONT, color=TUI_GREEN)),
                    ft.DataColumn(ft.Text("Password", font_family=TUI_FONT, color=TUI_GREEN)), ft.DataColumn(ft.Text("Found", font_family=TUI_FONT, color=TUI_GREEN))
                ], rows=[])
                osint_table = ft.DataTable(columns=[
                    ft.DataColumn(ft.Text("Target", font_family=TUI_FONT, color=TUI_GREEN)), ft.DataColumn(ft.Text("Category", font_family=TUI_FONT, color=TUI_GREEN)), ft.DataColumn(ft.Text("Found", font_family=TUI_FONT, color=TUI_GREEN))
                ], rows=[])
                search_input = ft.TextField(label="Search hosts/vulns/creds (substring)", width=320)
                search_status = ft.Text("", font_family=TUI_FONT, color=TUI_GREEN)
                severity_chart_holder = ft.Container()

                SEV_COLORS = {"CRITICAL": ft.colors.RED_400, "HIGH": ft.colors.RED_400, "MALICIOUS": ft.colors.RED_400,
                              "MEDIUM": ft.colors.ORANGE_400, "SUSPICIOUS": ft.colors.ORANGE_400, "LOW": ft.colors.GREEN_ACCENT}
                SEV_CHART_COLORS = {"CRITICAL": "#FF3333", "HIGH": "#FF3333", "MALICIOUS": "#FF3333",
                                     "MEDIUM": TUI_CYAN, "SUSPICIOUS": TUI_CYAN, "LOW": TUI_GREEN}

                def refresh_all(e=None):
                    try:
                        stats = db.get_stats()
                        stats_text.value = (f"Hosts: {stats['hosts']}  |  Ports: {stats['ports']}  |  "
                                             f"Vulnerabilities: {stats['vulnerabilities']}  |  Credentials: {stats['credentials']}  |  "
                                             f"OSINT Findings: {stats['osint_findings']}")

                        hosts_table.rows = [ft.DataRow(cells=[
                            ft.DataCell(ft.Text(h["ip"], font_family=TUI_FONT, color=TUI_GREEN)), ft.DataCell(ft.Text(h["mac"] or "-", font_family=TUI_FONT, color=TUI_GREEN)), ft.DataCell(ft.Text(h["hostname"] or "-", font_family=TUI_FONT, color=TUI_GREEN)),
                            ft.DataCell(ft.Text(h["os_guess"] or "-", font_family=TUI_FONT, color=TUI_GREEN)), ft.DataCell(ft.Text(h["last_seen"] or "-", font_family=TUI_FONT, color=TUI_GREEN))
                        ]) for h in db.get_hosts()]

                        all_vulns = db.get_vulnerabilities()
                        vulns_table.rows = [ft.DataRow(cells=[
                            ft.DataCell(ft.Text(v["target"], font_family=TUI_FONT, color=TUI_GREEN)), ft.DataCell(ft.Text(v["source"] or "-", font_family=TUI_FONT, color=TUI_GREEN)),
                            ft.DataCell(ft.Text(v["severity"] or "-", color=SEV_COLORS.get((v["severity"] or "").upper(), ft.colors.WHITE), font_family=TUI_FONT)),
                            ft.DataCell(ft.Text((v["description"] or "")[:60], font_family=TUI_FONT, color=TUI_GREEN)), ft.DataCell(ft.Text(v["discovered_at"] or "-", font_family=TUI_FONT, color=TUI_GREEN))
                        ]) for v in all_vulns]

                        # Severity breakdown bar chart -- the dashboard-style summary
                        # view of the same vulnerabilities table above.
                        sev_counts = {}
                        for v in all_vulns:
                            sev = (v["severity"] or "UNKNOWN").upper()
                            sev_counts[sev] = sev_counts.get(sev, 0) + 1
                        severity_chart_holder.content = tui_box(
                            "VULNERABILITY SEVERITY BREAKDOWN",
                            tui_bar_chart(sorted(sev_counts.items(), key=lambda kv: -kv[1]), accent_map=SEV_CHART_COLORS)
                        )

                        creds_table.rows = [ft.DataRow(cells=[
                            ft.DataCell(ft.Text(c["target"], font_family=TUI_FONT, color=TUI_GREEN)), ft.DataCell(ft.Text(c["service"] or "-", font_family=TUI_FONT, color=TUI_GREEN)),
                            ft.DataCell(ft.Text(c["username"] or "-", font_family=TUI_FONT, color=TUI_GREEN)), ft.DataCell(ft.Text(c["password"] or "-", color=ft.colors.RED_400, font_family=TUI_FONT)),
                            ft.DataCell(ft.Text(c["discovered_at"] or "-", font_family=TUI_FONT, color=TUI_GREEN))
                        ]) for c in db.get_credentials()]

                        osint_table.rows = [ft.DataRow(cells=[
                            ft.DataCell(ft.Text(o["target"], font_family=TUI_FONT, color=TUI_GREEN)), ft.DataCell(ft.Text(o["category"] or "-", font_family=TUI_FONT, color=TUI_GREEN)), ft.DataCell(ft.Text(o["discovered_at"] or "-", font_family=TUI_FONT, color=TUI_GREEN))
                        ]) for o in db.get_osint_findings()]
                    except Exception as ex:
                        stats_text.value = f"Database error: {ex}"
                    page.update()

                def do_search(e):
                    term = search_input.value.strip()
                    if not term:
                        search_status.value = ""; page.update(); return
                    try:
                        res = db.search_all(term)
                        counts = {k: len(v) for k, v in res.items()}
                        search_status.value = f"'{term}': {counts['hosts']} host(s), {counts['ports']} port(s), {counts['vulnerabilities']} vuln(s), {counts['credentials']} credential(s)"
                        search_status.color = ft.colors.GREEN_ACCENT
                        print_cli(f"PS> db search {term}", ft.colors.BLUE_200)
                        print_cli(f"[+] {search_status.value}", ft.colors.GREEN_ACCENT)
                    except Exception as ex:
                        search_status.value, search_status.color = f"Search failed: {ex}", ft.colors.RED_400
                    page.update()

                def confirm_clear(e):
                    def do_clear(e2):
                        try:
                            db.clear_all()
                            print_cli("PS> db clear", ft.colors.BLUE_200)
                            print_cli("[*] Database cleared.", ft.colors.ORANGE_400)
                            refresh_all()
                        except Exception as ex:
                            print_cli(f"[-] Clear failed: {ex}", ft.colors.RED_400)
                        try: page.pop_dialog()
                        except Exception:
                            try: page.dialog.open = False
                            except Exception: pass
                        page.update()

                    def cancel(e2):
                        try: page.pop_dialog()
                        except Exception:
                            try: page.dialog.open = False
                            except Exception: pass
                        page.update()

                    dialog = ft.AlertDialog(
                        title=ft.Text("Clear all stored data?", font_family=TUI_FONT, color=TUI_GREEN),
                        content=ft.Text("This permanently deletes every host, port, vulnerability, credential, and OSINT finding in the database. This cannot be undone.", font_family=TUI_FONT, color=TUI_GREEN),
                        actions=[ft.TextButton("Cancel", on_click=cancel), ft.TextButton("Clear Everything", on_click=do_clear, style=ft.ButtonStyle(color=ft.colors.RED_400))],
                    )
                    try:
                        page.show_dialog(dialog)
                    except Exception:
                        page.dialog = dialog
                        dialog.open = True
                    page.update()

                refresh_all()

                return ft.Column([
                    ft.Text("Database (Persisted Findings)", size=22, weight="bold", font_family=TUI_FONT, color=TUI_GREEN),
                    ft.Text("The safe equivalent of Metasploit's database integration -- every scan, OSINT run, and credential audit across this app writes here automatically. SQLite-backed, so it works the same on Windows, Linux, and Android.", color=ft.colors.GREY_400, size=12, font_family=TUI_FONT),
                    ft.Row([ft.ElevatedButton("Refresh", icon=ft.icons.REFRESH, on_click=refresh_all), ft.ElevatedButton("Clear Everything", icon=ft.icons.DELETE_FOREVER, on_click=confirm_clear, bgcolor=ft.colors.RED_900)], wrap=True),
                    stats_text, ft.Divider(),
                    severity_chart_holder, ft.Divider(),
                    ft.Row([search_input, ft.ElevatedButton("Search", on_click=do_search)], wrap=True), search_status,
                    ft.Divider(),

                    make_collapsible("Hosts", ft.Container(ft.ListView([hosts_table], auto_scroll=True), height=200, bgcolor=TUI_BG, border=ft.border.all(1, TUI_GREEN), border_radius=2, padding=6), initially_expanded=True),
                    ft.Divider(),
                    make_collapsible("Vulnerabilities", ft.Container(ft.ListView([vulns_table], auto_scroll=True), height=200, bgcolor=TUI_BG, border=ft.border.all(1, TUI_GREEN), border_radius=2, padding=6), initially_expanded=True),
                    ft.Divider(),
                    make_collapsible("Credentials", ft.Container(ft.ListView([creds_table], auto_scroll=True), height=180, bgcolor=TUI_BG, border=ft.border.all(1, TUI_GREEN), border_radius=2, padding=6)),
                    ft.Divider(),
                    make_collapsible("OSINT Findings", ft.Container(ft.ListView([osint_table], auto_scroll=True), height=180, bgcolor=TUI_BG, border=ft.border.all(1, TUI_GREEN), border_radius=2, padding=6)),
                ], expand=True, scroll=ft.ScrollMode.AUTO, spacing=8)

            # ----------------------------------------------------
            # GLOBAL NAVIGATION & FRAME ASSEMBLY
            # ----------------------------------------------------
            view_builders = [active_recon_view, monitor_view, passive_recon_view, defense_view, sniffer_view, tools_view, dos_ddos_sim_view, database_view]
            view_cache = {}  # built once per tab, then reused -- see navigation_handler

            def navigation_handler(e):
                index = e.control.selected_index
                # Build each view at most once and cache it. Previously every click
                # called view_builders[index]() fresh, which threw away the old
                # instance (and any scan/OSINT/monitor results visible on it) even
                # though the underlying background thread kept running -- so work
                # appeared to vanish when you navigated away and back. Reusing the
                # same instance means the same widgets keep getting updated by that
                # thread regardless of which tab is currently shown.
                if index not in view_cache:
                    view_cache[index] = view_builders[index]()
                gui_area.content = view_cache[index]
                # Keep both navigation controls (rail for desktop, bottom bar for mobile) in sync,
                # since only one of them is mounted at a time but the other should resume at the
                # right tab if the window is resized/rotated across the mobile breakpoint.
                nav_rail.selected_index = index
                if nav_bar is not None:
                    nav_bar.selected_index = index
                page.update()

            NAV_ITEMS = [
                (ft.icons.BOLT, "Active"), (ft.icons.MONITOR_HEART, "SIEM"), (ft.icons.RADAR, "Passive"),
                (ft.icons.SHIELD, "Defense"), (ft.icons.WAVES, "Sniffer"), (ft.icons.BUILD, "Tools"),
                (ft.icons.WARNING_AMBER_ROUNDED, "Sim DoS"), (ft.icons.STORAGE, "Database"),
            ]

            nav_rail = ft.NavigationRail(
                selected_index=0, label_type=ft.NavigationRailLabelType.ALL, min_width=80,
                bgcolor="#000000",
                indicator_color=ft.colors.TRANSPARENT,
                destinations=[ft.NavigationRailDestination(icon=icon, label=label) for icon, label in NAV_ITEMS],
                on_change=navigation_handler,
            )

            # Flet has renamed this destination class across versions (some ship
            # NavigationBarDestination, others NavigationDestination). The bottom-nav
            # mobile layout is treated as fully optional: if neither class exists, or
            # construction fails for any other reason, nav_bar stays None and the app
            # simply always uses the desktop NavigationRail layout instead of crashing.
            nav_bar = None
            try:
                _NavBarDest = getattr(ft, "NavigationBarDestination", None) or getattr(ft, "NavigationDestination", None)
                if _NavBarDest is not None:
                    nav_bar = ft.NavigationBar(
                        selected_index=0,
                        bgcolor="#000000",
                        indicator_color=ft.colors.TRANSPARENT,
                        destinations=[_NavBarDest(icon=icon, label=label) for icon, label in NAV_ITEMS],
                        on_change=navigation_handler,
                    )
            except Exception as ex:
                print(f"[SoloScan] Mobile NavigationBar unavailable on this Flet version ({ex}); desktop layout only.")
                nav_bar = None
            
            view_cache[0] = active_recon_view()
            gui_area.content = view_cache[0]
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

            # --- The whole app's visual theme: green-on-black, monospace, TUI-styled.
            # This is the app's permanent look now, not an optional mode -- applied
            # once at startup, same on desktop and mobile. Flet's theming cascades to
            # every existing widget automatically (buttons, fields, cards, nav), so
            # this one theme object restyles the entire app without touching each
            # view's widget code.
            #
            # ft.ColorScheme's exact field set has changed between Flet releases
            # (e.g. 'surface_container' doesn't exist on every version) -- to avoid
            # a version-specific crash, introspect this installed copy's actual
            # fields and only pass ones that exist. If construction still fails for
            # any reason, fall back to the default theme rather than blocking the
            # rest of the app from loading.
            _desired_tui_colors = {
                "primary": TUI_GREEN, "on_primary": TUI_BG,
                "secondary": TUI_CYAN, "on_secondary": TUI_BG,
                "surface": TUI_BG, "on_surface": TUI_GREEN, "on_surface_variant": TUI_GREEN,
                "surface_container": TUI_BG, "surface_container_high": TUI_BG, "surface_container_highest": TUI_BG,
                "outline": TUI_GREEN, "error": "#FF3333", "on_error": TUI_BG,
                "background": TUI_BG, "surface_variant": TUI_BG
            }
            try:
                import dataclasses as _dc
                _valid_cs_fields = {f.name for f in _dc.fields(ft.ColorScheme)}
            except Exception:
                # Couldn't introspect -- fall back to the handful of core M3 fields
                # that have existed since Flet's earliest ColorScheme support.
                _valid_cs_fields = {"primary", "on_primary", "secondary", "on_secondary", "surface", "on_surface", "error", "on_error"}

            try:
                _safe_tui_colors = {k: v for k, v in _desired_tui_colors.items() if k in _valid_cs_fields}
                page.theme = ft.Theme(color_scheme=ft.ColorScheme(**_safe_tui_colors), font_family=TUI_FONT)
            except Exception as ex:
                print(f"[SoloScan] TUI theme unavailable on this Flet version ({ex}); using default theme instead.")
            page.theme_mode = ft.ThemeMode.DARK

            def print_terminal(e):
                """Exports the current terminal transcript to a text file under reports/
                -- the closest equivalent to 'printing' the terminal, since Flet has no
                direct OS print-dialog API. Open the saved file to actually print it."""
                try:
                    os.makedirs("reports", exist_ok=True)
                    path = f"reports/terminal_transcript_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
                    with open(path, "w", encoding="utf-8") as f:
                        for ctl in cli_output.controls:
                            f.write(f"{getattr(ctl, 'value', '')}\n")
                    print_cli(f"[*] Terminal transcript saved to {path}", ft.colors.GREEN_ACCENT)
                except Exception as ex:
                    print_cli(f"[-] Failed to save transcript: {ex}", ft.colors.RED_400)
                page.update()

            page.appbar = ft.AppBar(
                title=ft.Row([ft.Icon(ft.icons.SECURITY, color=ft.colors.GREEN_ACCENT), ft.Text("SoloScan Workspace", weight="bold", font_family=TUI_FONT)]),
                bgcolor=TUI_BG,
                actions=[
                    ft.TextButton("GUI Only", on_click=lambda e: set_view_mode("GUI Only")),
                    ft.TextButton("CLI Only", on_click=lambda e: set_view_mode("CLI Only")),
                    ft.TextButton("Split View", on_click=lambda e: set_view_mode("Split View")),
                    ft.IconButton(icon=ft.icons.PRINT, tooltip="Print Terminal (saves transcript to reports/)", on_click=print_terminal),
                ],
            )

            # Mobile (Android/iOS/narrow window) breakpoint: NavigationRail doesn't fit well
            # on phone-width screens, and a side-by-side GUI+Terminal split is unusable there.
            # Below this width we swap to a bottom NavigationBar and stack the panels vertically.
            MOBILE_BREAKPOINT = 700
            content_holder = ft.Container(expand=True)

            def apply_responsive_layout(e=None):
                is_mobile = nav_bar is not None and (page.width or 1350) < MOBILE_BREAKPOINT
                try:
                    if is_mobile:
                        page.navigation_bar = nav_bar
                        gui_area.expand, cli_area.expand, cli_area.height = True, None, 320
                        content_holder.content = ft.Column([gui_area, ft.Divider(height=1), cli_area], expand=True)
                    else:
                        page.navigation_bar = None
                        cli_area.height = None
                        gui_area.expand, cli_area.expand = 5, 4
                        content_holder.content = ft.Row([nav_rail, div1, gui_area, div2, cli_area], expand=True)
                except Exception as ex:
                    # Final safety net -- always fall back to the known-working desktop layout
                    # rather than leave the page blank if anything above isn't supported here.
                    print(f"[SoloScan] Responsive layout error, reverting to desktop layout: {ex}")
                    try: page.navigation_bar = None
                    except Exception: pass
                    content_holder.content = ft.Row([nav_rail, div1, gui_area, div2, cli_area], expand=True)
                page.update()

            # Flet has also renamed this event across versions (on_resize vs on_resized) --
            # bind to whichever this installed copy actually supports.
            _resize_attr = "on_resized" if hasattr(ft.Page, "on_resized") else "on_resize"
            try:
                setattr(page, _resize_attr, apply_responsive_layout)
            except Exception:
                pass

            # Assemble the Final UI
            page.add(
                ft.Column([
                    content_holder,
                    ft.Container(
                        content=ft.Text("built by GarbaTheAnalyst, The Analyst Consultancy, ©2026. SoloScan™", size=10, color=ft.colors.GREY_600, italic=True, font_family=TUI_FONT),
                        alignment=safe_alignment("bottom_right", 1, 1),
                        padding=ft.padding.only(right=10, bottom=5)
                    )
                ], expand=True)
            )
            apply_responsive_layout()

        # TRIGGER THE EULA SCREEN AFTER SPLASH
        show_eula()

    ft.app(target=main)