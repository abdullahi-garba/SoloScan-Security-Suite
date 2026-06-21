import flet as ft
import threading
import time
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
        page.window_width = 1350
        page.window_height = 800
        page.padding = 0  # Remove padding for edge-to-edge splash screen

        # ==========================================
        # 🎬 SPLASH SCREEN (VECTOR ANIMATION)
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
                    # Note: Removed letter_spacing to prevent Flet version errors. Added manual spacing.
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
        
        # Clear the splash screen to load the main application
        page.controls.clear()
        page.padding = 10 
        page.update()

        # ==========================================
        # ⚙️ INITIALIZE MAIN GUI VARIABLES
        # ==========================================
        gui_area = ft.Container(expand=5, padding=10)
        page.client_storage.set("port_data", [])
        page.client_storage.set("passive_data", [])

        # ----------------------------------------------------
        # EMBEDDED CLI TERMINAL (Right Side Panel)
        # ----------------------------------------------------
        cli_output = ft.ListView(expand=True, auto_scroll=True, spacing=2)
        
        def print_cli(text, color=ft.colors.WHITE):
            """Appends text to the terminal and auto-scrolls."""
            cli_output.controls.append(ft.Text(text, color=color, font_family="Consolas", size=12))
            page.update()

        def execute_cli_command(e):
            """Parses and executes commands typed into the bottom text box."""
            cmd_str = cli_input.value.strip()
            if not cmd_str: return
            
            print_cli(f"PS> {cmd_str}", ft.colors.BLUE_200)
            cli_input.value = ""
            page.update()

            try: 
                args = shlex.split(cmd_str)
            except ValueError:
                print_cli("[-] Error parsing command.", ft.colors.RED_400)
                return

            command = args[0].lower()
            
            if command == "clear": 
                cli_output.controls.clear()
                page.update()
            else: 
                print_cli(f"[*] Command executed: {command}. Check GUI for sync.", ft.colors.GREY_500)

        cli_input = ft.TextField(
            hint_text="Terminal...", 
            bgcolor=ft.colors.BLACK, 
            color=ft.colors.GREEN_ACCENT_400, 
            text_style=ft.TextStyle(font_family="Consolas"), 
            on_submit=execute_cli_command
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

        # ==========================================
        # BOILERPLATE HEADER (Enterprise Feel)
        # ==========================================
        def load_boilerplate():
            """Loads the professional terminal header silently on startup."""
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

        # Execute boilerplate printout immediately
        load_boilerplate()

        # ----------------------------------------------------
        # VIEW 1: ACTIVE RECONNAISSANCE 
        # ----------------------------------------------------
        def active_recon_view():
            target_input = ft.TextField(label="Target IP / Domain", value="127.0.0.1", expand=True)
            ports_input = ft.TextField(label="Ports (e.g. 22,80,1-1000)", value="22,80,443", width=200)
            profile_dropdown = ft.Dropdown(
                label="Scan Profile", 
                options=[ft.dropdown.Option(k) for k in SCAN_MODES.keys()], 
                value="Standard (TCP Connect)", width=250
            )
            progress = ft.ProgressRing(visible=False, width=20, height=20)
            status_text = ft.Text("")
            table = ft.DataTable(columns=[
                ft.DataColumn(ft.Text("Port")), 
                ft.DataColumn(ft.Text("Status")), 
                ft.DataColumn(ft.Text("Service/Banner"))
            ], rows=[])

            def export_active_pdf(e):
                data = page.client_storage.get("port_data")
                if not data:
                    status_text.value = "No data to export."
                    page.update()
                    return
                path = generate_pdf_report(data, title="Active Scan Report", filename="Active_Scan")
                status_text.value = f"PDF Saved: {path}" if path else "PDF Export Failed."
                print_cli(f"[*] Exported Active Scan PDF to {path}", ft.colors.GREEN_ACCENT)
                page.update()

            def start_scan(e):
                table.rows.clear()
                progress.visible = True
                page.update()
                
                target = target_input.value
                is_stealth = SCAN_MODES[profile_dropdown.value]["stealth"]

                # Advanced Port Parsing (handles ranges like 1-1000)
                try:
                    ports = []
                    for part in ports_input.value.split(","):
                        part = part.strip()
                        if "-" in part:
                            start, end = map(int, part.split("-"))
                            ports.extend(range(start, end + 1))
                        else: ports.append(int(part))
                    ports = sorted(list(set(ports)))
                except Exception:
                    progress.visible = False
                    status_text.value = "Invalid Ports Format"
                    page.update()
                    return

                print_cli(f"PS> scan {target} {len(ports)} ports", ft.colors.BLUE_200)

                def on_port(port, status, service, banner):
                    color = ft.colors.GREEN_ACCENT if status == "OPEN" else ft.colors.ORANGE_400
                    table.rows.append(ft.DataRow(cells=[
                        ft.DataCell(ft.Text(str(port))), 
                        ft.DataCell(ft.Text(status, color=color)), 
                        ft.DataCell(ft.Text(f"{service} | {banner}"))
                    ]))
                    print_cli(f"  [+] {port:<5}/tcp | {status:<8} | {service}", color)
                    page.update()

                def run():
                    res = ScanEngine.stealth_syn_scan(target, ports, on_port) if is_stealth else ScanEngine.port_scan(target, ports, on_port)
                    page.client_storage.set("port_data", res)
                    progress.visible = False
                    page.update()

                threading.Thread(target=run, daemon=True).start()

            return ft.Column([
                ft.Text("Active Network Probing", size=22, weight="bold"),
                ft.Row([target_input, ports_input, profile_dropdown]),
                ft.Row([
                    ft.ElevatedButton("Engage Target", on_click=start_scan), 
                    ft.ElevatedButton("Export PDF", on_click=export_active_pdf, icon=ft.icons.PICTURE_AS_PDF, icon_color=ft.colors.RED_400), 
                    progress
                ]),
                status_text, ft.Divider(), ft.ListView([table], expand=True, auto_scroll=True)
            ], expand=True)

        # ----------------------------------------------------
        # VIEW 2: SIEM REAL-TIME MONITORING
        # ----------------------------------------------------
        def monitor_view():
            target_input = ft.TextField(label="Target to Monitor", value="127.0.0.1", expand=True)
            interval_input = ft.TextField(label="Interval (Seconds)", value="10", width=150)
            monitor_status = ft.Text("Status: Idle", color=ft.colors.GREY_400)
            log_list = ft.ListView(expand=True, auto_scroll=True, spacing=5)
            
            is_monitoring = False
            last_state = {}

            def toggle_monitor(e):
                nonlocal is_monitoring, last_state
                if is_monitoring:
                    is_monitoring = False
                    e.control.text = "Start Monitoring"
                    monitor_status.value, monitor_status.color = "Status: Idle", ft.colors.GREY_400
                else:
                    is_monitoring = True
                    last_state = {}
                    e.control.text = "Stop Monitoring"
                    monitor_status.value, monitor_status.color = "Status: ACTIVE MONITORING", ft.colors.GREEN_ACCENT
                    threading.Thread(target=monitor_loop, daemon=True).start()
                page.update()

            def monitor_loop():
                nonlocal last_state
                target = target_input.value
                try: 
                    interval = int(interval_input.value)
                except Exception: 
                    interval = 10

                while is_monitoring:
                    # Scan common critical ports
                    current_scan = ScanEngine.port_scan(target, [21,22,80,443,3306,3389,8080], workers=10)
                    current_state = {str(p["port"]): p["status"] for p in current_scan if "port" in p}
                    timestamp = datetime.now().strftime("%H:%M:%S")
                    
                    if last_state:
                        # Compare against previous loop state to find anomalies
                        for port, status in current_state.items():
                            old_status = last_state.get(port, "CLOSED")
                            if status != old_status:
                                msg = f"[{timestamp}] ALERT: Port {port} changed from {old_status} -> {status}"
                                log_list.controls.append(ft.Text(msg, color=ft.colors.RED_400, weight="bold"))
                                print_cli(f"SIEM ALERT: {msg}", ft.colors.RED_400)
                    else:
                        log_list.controls.append(ft.Text(f"[{timestamp}] Baseline established.", color=ft.colors.BLUE_200))
                    
                    last_state = current_state
                    page.update()
                    time.sleep(interval)

            return ft.Column([
                ft.Text("Real-Time SIEM Monitoring", size=22, weight="bold"),
                ft.Row([target_input, interval_input, ft.ElevatedButton("Start Monitoring", on_click=toggle_monitor)]),
                monitor_status, ft.Divider(), log_list
            ], expand=True)

        # ----------------------------------------------------
        # VIEW 3: PASSIVE RECONNAISSANCE 
        # ----------------------------------------------------
        def passive_recon_view():
            target_input = ft.TextField(label="Target Domain", value="example.com", expand=True)
            results_list = ft.ListView(expand=True, spacing=10, auto_scroll=True)
            progress = ft.ProgressRing(visible=False, width=20, height=20)

            def export_passive_pdf(e):
                data = page.client_storage.get("passive_data")
                if data:
                    path = generate_pdf_report(data, title="Passive OSINT Report", filename="Passive_OSINT")
                    page.snack_bar = ft.SnackBar(ft.Text(f"PDF Saved: {path}"))
                    page.snack_bar.open = True
                    print_cli(f"[*] Exported Passive PDF to {path}", ft.colors.GREEN_ACCENT)
                page.update()

            def start_osint(e):
                results_list.controls.clear()
                progress.visible = True
                page.update()
                
                target = target_input.value
                print_cli(f"PS> osint {target}", ft.colors.BLUE_200)

                def run():
                    export_data = []
                    
                    whois = PassiveEngine.get_whois(target)
                    export_data.append({"WHOIS": whois})
                    results_list.controls.append(ft.Card(content=ft.Container(padding=15, content=ft.Column([
                        ft.Text("WHOIS Registry", weight="bold", color=ft.colors.BLUE_200), 
                        ft.Text(whois[:300] + "...", size=12)
                    ]))))
                    
                    subs = PassiveEngine.get_subdomains(target)
                    if subs:
                        export_data.append({"Subdomains": subs})
                        results_list.controls.append(ft.Card(content=ft.Container(padding=15, content=ft.Column([
                            ft.Text("Subdomains", weight="bold", color=ft.colors.BLUE_200), 
                            ft.Text("\n".join(subs), size=12)
                        ]))))
                        
                    fuzz = WebVulnScanner.fuzz_directories(target)
                    if fuzz:
                        export_data.append({"Fuzzing Hits": fuzz})
                        fuzz_text = "\n".join([f"{f['path']} ({f['status']})" for f in fuzz])
                        results_list.controls.append(ft.Card(content=ft.Container(padding=15, content=ft.Column([
                            ft.Text("Fuzzing Hits", weight="bold", color=ft.colors.RED_300), 
                            ft.Text(fuzz_text, color=ft.colors.GREEN_ACCENT)
                        ]))))
                    
                    page.client_storage.set("passive_data", export_data)
                    progress.visible = False
                    page.update()
                    
                threading.Thread(target=run, daemon=True).start()

            return ft.Column([
                ft.Text("Passive OSINT & Fuzzing", size=22, weight="bold"),
                ft.Row([
                    target_input, 
                    ft.ElevatedButton("Run Full OSINT", on_click=start_osint), 
                    ft.ElevatedButton("Export PDF", on_click=export_passive_pdf, icon=ft.icons.PICTURE_AS_PDF, icon_color=ft.colors.RED_400), 
                    progress
                ]),
                ft.Divider(), results_list
            ], expand=True)

        # ----------------------------------------------------
        # VIEW 4: BLUE TEAM DEFENSE
        # ----------------------------------------------------
        def defense_view():
            current_ip = IPManager.get_current_ip()
            adapter_input = ft.TextField(label="Windows Adapter (e.g. Wi-Fi)", width=250)
            new_ip_input = ft.TextField(label="New Static IP", width=150)
            ip_status = ft.Text("")

            def update_ip(e):
                ip_status.value = "Attempting to change IP (Requires Admin)..."
                page.update()
                res = IPManager.change_windows_ip(adapter_input.value, new_ip_input.value)
                ip_status.value = res
                ip_status.color = ft.colors.GREEN_ACCENT if "Success" in res else ft.colors.RED_400
                page.update()

            hp_port_input = ft.TextField(label="Honeypot Port", value="22", width=120)
            hp_status = ft.Text("Status: Offline", color=ft.colors.GREY_400)
            hp_logs = ft.ListView(expand=True, auto_scroll=True, spacing=5)

            def hp_logger(msg):
                color = ft.colors.RED_400 if "INTRUSION" in msg else ft.colors.GREEN_ACCENT
                hp_logs.controls.append(ft.Text(msg, color=color))
                print_cli(f"HONEYPOT: {msg}", color)
                page.update()

            def toggle_honeypot(e):
                if global_honeypot.is_active:
                    global_honeypot.stop()
                    e.control.text = "Deploy Honeypot"
                    e.control.bgcolor = ft.colors.BLUE_700
                    hp_status.value, hp_status.color = "Status: Offline", ft.colors.GREY_400
                else:
                    global_honeypot.port = int(hp_port_input.value)
                    if global_honeypot.start(hp_logger):
                        e.control.text = "Deactivate Honeypot"
                        e.control.bgcolor = ft.colors.RED_700
                        hp_status.value, hp_status.color = "Status: ACTIVE", ft.colors.GREEN_ACCENT
                page.update()

            return ft.Column([
                ft.Text("Blue Team Defense Tools", size=22, weight="bold"), ft.Divider(),
                ft.Text("Host Network Management", weight="bold", color=ft.colors.BLUE_200),
                ft.Text(f"Current Local IP Address: {current_ip}", size=16, color=ft.colors.GREEN_ACCENT),
                ft.Row([adapter_input, new_ip_input, ft.ElevatedButton("Change IP", on_click=update_ip)]), ip_status,
                ft.Container(height=20), ft.Divider(),
                ft.Text("Intrusion Detection Honeypot", weight="bold", color=ft.colors.BLUE_200),
                ft.Text("Deploys a fake service to log unauthorized network scans against your machine.", color=ft.colors.GREY_400),
                ft.Row([hp_port_input, ft.ElevatedButton("Deploy Honeypot", on_click=toggle_honeypot, bgcolor=ft.colors.BLUE_700)]), hp_status,
                ft.Container(hp_logs, expand=True, border=ft.border.all(1, ft.colors.GREY_800), padding=10, border_radius=5)
            ], expand=True)

        # ----------------------------------------------------
        # VIEW 5: IDS PACKET SNIFFER
        # ----------------------------------------------------
        def sniffer_view():
            log_list = ft.ListView(expand=True, auto_scroll=True, spacing=2)
            status_text = ft.Text("Sniffer Offline", color=ft.colors.GREY_400)
            
            def map_color(color_str):
                colors = {"WHITE": ft.colors.WHITE, "RED": ft.colors.RED_400, "GREEN": ft.colors.GREEN_ACCENT, "ORANGE": ft.colors.ORANGE_400, "GREY": ft.colors.GREY_500}
                return colors.get(color_str, ft.colors.WHITE)

            def sniffer_log(msg, color_str="WHITE"):
                log_list.controls.append(ft.Text(msg, color=map_color(color_str), font_family="Consolas", size=12))
                # Prune list to prevent GUI memory lag
                if len(log_list.controls) > 500: log_list.controls.pop(0) 
                page.update()

            def toggle_sniffer(e):
                if sniffer_instance.running:
                    sniffer_instance.stop()
                    e.control.text = "Start Sniffing"
                    e.control.icon = ft.icons.PLAY_ARROW
                    e.control.bgcolor = ft.colors.SURFACE_VARIANT
                    status_text.value, status_text.color = "Sniffer Offline", ft.colors.GREY_400
                else:
                    log_list.controls.clear()
                    e.control.text = "Stop Sniffing"
                    e.control.icon = ft.icons.STOP
                    e.control.bgcolor = ft.colors.RED_900
                    status_text.value, status_text.color = "ACTIVE - Capturing Traffic...", ft.colors.GREEN_ACCENT
                    # Run sniffer loop on background thread to prevent GUI lockup
                    threading.Thread(target=sniffer_instance.start, args=(sniffer_log,), daemon=True).start()
                page.update()

            return ft.Column([
                ft.Text("Intrusion Detection Sniffer", size=22, weight="bold"),
                ft.Text("Monitors local interfaces for suspicious traffic and MITRE ATT&CK patterns.", color=ft.colors.GREY_400),
                ft.Row([ft.ElevatedButton("Start Sniffing", icon=ft.icons.PLAY_ARROW, on_click=toggle_sniffer), status_text]), ft.Divider(),
                ft.Container(log_list, expand=True, bgcolor="#0A0A0A", padding=10, border_radius=5, border=ft.border.all(1, ft.colors.GREY_800))
            ], expand=True)

        # ----------------------------------------------------
        # VIEW 6: TOOLS & AUDIT LOGS
        # ----------------------------------------------------
        def tools_view():
            # Domain-to-IP Resolver
            resolve_input = ft.TextField(label="Domain/URL to Resolve", value="google.com", expand=True)
            resolve_output = ft.Text("")

            def do_resolve(e):
                clean = resolve_input.value.replace("https://", "").replace("http://", "").split("/")[0]
                print_cli(f"PS> resolve {clean}", ft.colors.BLUE_200)
                try:
                    ip = socket.gethostbyname(clean)
                    resolve_output.value = f"Target {clean} resolves to IP: {ip}"
                    resolve_output.color = ft.colors.GREEN_ACCENT
                    print_cli(f"[+] {clean} -> {ip}", ft.colors.GREEN_ACCENT)
                except Exception:
                    resolve_output.value = f"Failed to resolve {clean}."
                    resolve_output.color = ft.colors.RED_400
                    print_cli(f"[-] Failed to resolve {clean}.", ft.colors.RED_400)
                page.update()

            # Subnet Calculator
            ip_input = ft.TextField(label="CIDR Network Range (e.g. 192.168.1.0/24)", expand=True)
            output_col = ft.Column(spacing=8)

            def calculate(e):
                output_col.controls.clear()
                try:
                    net = ipaddress.ip_network(ip_input.value, strict=False)
                    hosts = list(net.hosts())
                    first, last = (hosts[0], hosts[-1]) if hosts else ("N/A", "N/A")
                    usable = net.num_addresses - 2 if net.num_addresses > 2 else 0
                    output_col.controls = [
                        ft.Text(f"Network Address: {net.network_address}"), 
                        ft.Text(f"Broadcast: {net.broadcast_address}"),
                        ft.Text(f"Netmask: {net.netmask}"), 
                        ft.Text(f"Usable Hosts: {usable}", color=ft.colors.BLUE_200),
                        ft.Text(f"Host Range: {first} -> {last}")
                    ]
                except Exception as ex:
                    output_col.controls.append(ft.Text(f"Error: {ex}", color=ft.colors.RED_400))
                page.update()

            # SYSTEM AUDIT LOG VIEWER
            log_display = ft.Text("Click 'Refresh Logs' to load system events.", font_family="Consolas", size=12, color=ft.colors.GREY_400)
            
            def refresh_audit_logs(e):
                try:
                    with open("soloscan_debug.log", "r") as f:
                        # Grab the last 15 lines of the log file
                        lines = f.readlines()[-15:]
                        log_display.value = "".join(lines) if lines else "Log file is empty."
                        log_display.color = ft.colors.GREEN_ACCENT
                except FileNotFoundError:
                    log_display.value = "soloscan_debug.log not found. System has not generated background logs yet."
                    log_display.color = ft.colors.ORANGE_400
                page.update()

            return ft.Column([
                ft.Text("Networking Utilities & System Audit", size=22, weight="bold"), ft.Divider(),
                
                ft.Text("Domain-to-IP Resolver", weight="bold", color=ft.colors.BLUE_200),
                ft.Row([resolve_input, ft.ElevatedButton("Resolve IP", on_click=do_resolve)]), resolve_output,
                
                ft.Container(height=10), ft.Divider(),
                
                ft.Text("Subnet Calculator", weight="bold", color=ft.colors.BLUE_200),
                ft.Row([ip_input, ft.ElevatedButton("Compute Subnet", on_click=calculate)]), output_col,
                
                ft.Container(height=10), ft.Divider(),
                
                # Render the Log Viewer
                ft.Row([
                    ft.Text("Background System Audit Logs", weight="bold", color=ft.colors.BLUE_200), 
                    ft.IconButton(icon=ft.icons.REFRESH, on_click=refresh_audit_logs, tooltip="Refresh Logs")
                ]),
                ft.Container(log_display, expand=True, bgcolor="#0A0A0A", padding=10, border_radius=5, border=ft.border.all(1, ft.colors.GREY_800))
            ], expand=True)

        # ----------------------------------------------------
        # GLOBAL NAVIGATION & FRAME ASSEMBLY
        # ----------------------------------------------------
        def navigation_handler(e):
            """Swaps the center GUI view based on the sidebar selection."""
            index = e.control.selected_index
            views = [
                active_recon_view(), 
                monitor_view(), 
                passive_recon_view(), 
                defense_view(), 
                sniffer_view(), 
                tools_view()
            ]
            gui_area.content = views[index]
            page.update()

        nav_rail = ft.NavigationRail(
            selected_index=0, 
            label_type=ft.NavigationRailLabelType.ALL, 
            min_width=80,
            destinations=[
                ft.NavigationRailDestination(icon=ft.icons.BOLT, label="Active"),
                ft.NavigationRailDestination(icon=ft.icons.MONITOR_HEART, label="SIEM"),
                ft.NavigationRailDestination(icon=ft.icons.RADAR, label="Passive"),
                ft.NavigationRailDestination(icon=ft.icons.SHIELD, label="Defense"),
                ft.NavigationRailDestination(icon=ft.icons.WAVES, label="Sniffer"),
                ft.NavigationRailDestination(icon=ft.icons.BUILD, label="Tools"),
            ],
            on_change=navigation_handler,
        )
        
        gui_area.content = active_recon_view()
        div1 = ft.VerticalDivider(width=1)
        div2 = ft.VerticalDivider(width=1)

        def set_view_mode(mode):
            """Toggles visibility of GUI/CLI panes via the top AppBar."""
            if mode == "Split View":
                nav_rail.visible, div1.visible, gui_area.visible, div2.visible, cli_area.visible = True, True, True, True, True
            elif mode == "GUI Only":
                nav_rail.visible, div1.visible, gui_area.visible = True, True, True
                cli_area.visible, div2.visible = False, False
            elif mode == "CLI Only":
                nav_rail.visible, div1.visible, gui_area.visible, div2.visible = False, False, False, False
                cli_area.visible = True
            page.update()

        # Add the application top bar
        page.appbar = ft.AppBar(
            title=ft.Row([ft.Icon(ft.icons.SECURITY, color=ft.colors.GREEN_ACCENT), ft.Text("SoloScan Workspace", weight="bold")]),
            bgcolor=ft.colors.SURFACE_VARIANT,
            actions=[
                ft.TextButton("GUI Only", on_click=lambda e: set_view_mode("GUI Only")),
                ft.TextButton("CLI Only", on_click=lambda e: set_view_mode("CLI Only")),
                ft.TextButton("Split View", on_click=lambda e: set_view_mode("Split View")),
            ],
        )

        # Add the main UI layout to the page (After splash screen clears)
        page.add(
            ft.Column([
                ft.Row([nav_rail, div1, gui_area, div2, cli_area], expand=True),
                # Developer custom footer
                ft.Container(
                    content=ft.Text("built by GarbaTheAnalyst, The Analyst Consultancy, ©2026. SoloScan™", size=10, color=ft.colors.GREY_600, italic=True),
                    alignment=ft.alignment.bottom_right,
                    padding=ft.padding.only(right=10, bottom=5)
                )
            ], expand=True)
        )

    ft.app(target=main)