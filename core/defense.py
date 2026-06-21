import socket
import subprocess
import threading
import re
import ipaddress
from datetime import datetime

class IPManager:
    """Handles discovery and modification of the local host machine's IP settings."""
    
    @staticmethod
    def get_current_ip():
        """Connects a dummy UDP socket to safely extract the active local IP."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("8.8.8.8", 80))
                return s.getsockname()[0]
        except Exception:
            return "127.0.0.1"

    @staticmethod
    def change_windows_ip(adapter_name, new_ip, subnet_mask="255.255.255.0", gateway="192.168.1.1"):
        """
        Uses Windows 'netsh' to modify network adapters programmatically.
        Requires the app to be running as Administrator.
        """
        # --- Input validation (prevents shell/command injection) ---
        # Adapter names are free text in Windows but should never contain shell
        # metacharacters; allow letters, numbers, spaces, hyphens, underscores, periods.
        if not adapter_name or not re.fullmatch(r"[\w\s\-\.]{1,64}", adapter_name):
            return "Invalid adapter name. Only letters, numbers, spaces, '-', '_' and '.' are allowed."

        for label, value in (("IP address", new_ip), ("subnet mask", subnet_mask), ("gateway", gateway)):
            try:
                ipaddress.ip_address(value)
            except ValueError:
                return f"Invalid {label}: '{value}' is not a valid IPv4/IPv6 address."

        try:
            # Pass arguments as a list with shell=False so user input can never be
            # interpreted by the shell, no matter what characters it contains.
            cmd = [
                "netsh", "interface", "ip", "set", "address",
                f"name={adapter_name}", "static", new_ip, subnet_mask, gateway
            ]
            result = subprocess.run(cmd, shell=False, capture_output=True, text=True)

            if result.returncode == 0:
                return f"Successfully changed {adapter_name} to {new_ip}"
            else:
                return f"Failed to change IP. Ensure you have Admin rights. Error: {result.stderr}"
        except Exception as e:
            return f"Error executing netsh command: {e}"

class Honeypot:
    """
    Deploys a fake listening service on the host machine to detect 
    and log incoming network scans or intrusion attempts.
    """
    
    def __init__(self, port=22, fake_banner=b"SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.1\r\n"):
        self.port = port
        self.fake_banner = fake_banner
        self.is_active = False
        self.socket = None

    def start(self, log_callback):
        """Starts the honeypot listener on a background thread."""
        self.is_active = True
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.bind(("0.0.0.0", self.port))
            self.socket.listen(5)
            log_callback(f"[*] Honeypot Active. Listening on port {self.port}...")

            def listen():
                while self.is_active:
                    try:
                        conn, addr = self.socket.accept()
                        timestamp = datetime.now().strftime("%H:%M:%S")
                        
                        log_callback(f"[!] INTRUSION DETECTED [{timestamp}]: Connection from {addr[0]}:{addr[1]}")
                        
                        conn.send(self.fake_banner)
                        conn.close()
                    except Exception:
                        break 
                        
            threading.Thread(target=listen, daemon=True).start()
            return True
        except Exception as e:
            log_callback(f"[-] Failed to start honeypot (Port may be in use): {e}")
            self.is_active = False
            return False

    def stop(self):
        """Safely shuts down the listening socket."""
        self.is_active = False
        if self.socket:
            try: 
                self.socket.close()
            except Exception: 
                pass