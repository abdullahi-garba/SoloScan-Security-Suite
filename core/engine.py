import socket
import requests
import ftplib
import logging
from concurrent.futures import ThreadPoolExecutor

# Suppress Scapy warning messages in the terminal
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import ARP, Ether, srp, IP, TCP, sr1, traceroute

from core.utils import logger, COMMON_SERVICES, check_privileges, COMMON_CREDENTIALS

class ScanEngine:
    
    @staticmethod
    def resolve_target(target):
        """Cleans URL strings and resolves them to an IPv4 address."""
        try:
            # Strip http, https, and trailing slashes
            clean_target = target.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
            return socket.gethostbyname(clean_target)
        except socket.gaierror:
            logger.error(f"Could not resolve hostname: {target}")
            return None

    @staticmethod
    def _test_single_port(ip, port):
        """Internal helper to test a standard TCP connection on a single port."""
        service_name = COMMON_SERVICES.get(port, "Unknown")
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1.5)
                result = s.connect_ex((ip, port))
                
                if result == 0:
                    # Attempt to grab the service banner if port is open
                    try:
                        s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                        banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
                        banner = banner.replace('\n', ' ').replace('\r', '')[:80]
                        if not banner: 
                            banner = "No banner returned"
                    except Exception:
                        banner = "Timeout waiting for banner"
                        
                    return port, "OPEN", service_name, banner
                else:
                    return port, "CLOSED", service_name, ""
        except Exception as e:
            return port, "ERROR", service_name, str(e)

    @staticmethod
    def port_scan(target, ports, result_callback=None, workers=100):
        """Executes a standard, noisy 3-way handshake TCP scan using threading."""
        open_and_filtered_ports = []
        ip = ScanEngine.resolve_target(target)
        
        if not ip:
            return [{"error": f"Could not resolve {target}"}]
            
        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = {executor.submit(ScanEngine._test_single_port, ip, port): port for port in ports}
            for future in futures:
                port, status, service, banner = future.result()
                if status in ["OPEN", "FILTERED"]:
                    open_and_filtered_ports.append({
                        "target": target, "ip": ip, "port": port, 
                        "service": service, "status": status, "banner": banner
                    })
                # Push real-time result to the GUI callback
                if result_callback:
                    result_callback(port, status, service, banner)
                    
        return open_and_filtered_ports

    @staticmethod
    def stealth_syn_scan(target, ports, result_callback=None):
        """Executes a stealthy half-open SYN scan using raw sockets (Scapy)."""
        os_name, is_admin = check_privileges()
        if os_name == "android":
            return [{"error": "Advanced OS detection and SYN scans are not supported on this device."}]
        if not is_admin:
            error_msg = "Run application with Administrator rights." if os_name == "windows" else "Run application using sudo."
            return [{"error": f"Permission Denied. {error_msg}"}]

        open_ports = []
        ip = ScanEngine.resolve_target(target)
        if not ip:
            return [{"error": f"Could not resolve {target}"}]

        for port in ports:
            service_name = COMMON_SERVICES.get(port, "Unknown")
            try:
                # Craft a raw IP packet with a TCP SYN flag
                packet = IP(dst=ip)/TCP(dport=port, flags="S")
                response = sr1(packet, timeout=1.5, verbose=0)
                
                if response is None:
                    status = "FILTERED"
                elif response.haslayer(TCP):
                    # 0x12 means SYN-ACK (Port is open)
                    if response.getlayer(TCP).flags == 0x12:
                        # Send RST to tear down connection quietly
                        sr1(IP(dst=ip)/TCP(dport=port, flags="R"), timeout=1, verbose=0)
                        status = "OPEN"
                    # 0x14 means RST-ACK (Port is closed)
                    elif response.getlayer(TCP).flags == 0x14:
                        status = "CLOSED"
                    else:
                        status = "UNKNOWN"
                else:
                    status = "UNKNOWN"
                
                if status in ["OPEN", "FILTERED"]:
                    open_ports.append({
                        "target": target, "ip": ip, "port": port,
                        "service": service_name, "status": status, "banner": "N/A (Stealth)"
                    })
                if result_callback:
                    result_callback(port, status, service_name, "N/A (Stealth)")
            except Exception as e:
                logger.error(f"SYN scan error on port {port}: {e}")
                
        return open_ports

    @staticmethod
    def network_traceroute(target):
        """Maps the physical network hops required to reach the target."""
        os_name, is_admin = check_privileges()
        if not is_admin:
            return [{"error": "Traceroute requires Administrator/Sudo privileges."}]
            
        ip = ScanEngine.resolve_target(target)
        if not ip: 
            return [{"error": "Could not resolve target."}]
        
        try:
            # Send packets with increasing Time-To-Live (TTL)
            ans, unans = traceroute(ip, maxttl=15, verbose=0)
            hops = []
            for snd, rcv in ans:
                hops.append({"hop": snd.ttl, "ip": rcv.src})
            return hops
        except Exception as e:
            return [{"error": f"Traceroute failed: {e}"}]

    @staticmethod
    def brute_force_login(target, service="ftp"):
        """Attempts to log in to target services using a common credential wordlist."""
        ip = ScanEngine.resolve_target(target)
        if not ip: 
            return {"error": "Could not resolve target."}
        
        for user, pwd in COMMON_CREDENTIALS:
            try:
                if service == "ftp":
                    # Attempt FTP Login
                    ftp = ftplib.FTP(ip, timeout=3)
                    ftp.login(user, pwd)
                    ftp.quit()
                    return {"success": True, "user": user, "password": pwd}
                    
                elif service == "http":
                    # Attempt Basic HTTP Authentication
                    url = f"http://{ip}"
                    r = requests.get(url, auth=(user, pwd), timeout=3)
                    # Status 200 means authentication succeeded
                    if r.status_code == 200 and "Access denied" not in r.text:
                        return {"success": True, "user": user, "password": pwd}
            except Exception:
                continue # Ignore timeouts and failed auths, try next password
                
        return {"success": False}