import socket
import requests
import ftplib
import logging
from concurrent.futures import ThreadPoolExecutor

# Suppress Scapy warning messages in the terminal
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import ARP, Ether, srp, IP, TCP, ICMP, sr1, send, traceroute

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
    def local_discovery(subnet, progress_callback=None, timeout=2):
        """Performs an ARP sweep across the given subnet to discover live hosts on the local network."""
        os_name, is_admin = check_privileges()
        if os_name == "android":
            return [{"error": "ARP-based discovery is not supported on this device."}]
        if not is_admin:
            error_msg = "Run application with Administrator rights." if os_name == "windows" else "Run application using sudo."
            return [{"error": f"Permission Denied. {error_msg}"}]

        devices = []
        try:
            # Build a broadcast Ethernet frame carrying an ARP "who-has" request
            # for every host address in the target subnet.
            arp_request = ARP(pdst=subnet)
            broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = broadcast / arp_request

            # srp() sends at Layer 2 and returns (answered, unanswered) pairs.
            answered, _ = srp(packet, timeout=timeout, verbose=0)

            for _, received in answered:
                device = {"ip": received.psrc, "mac": received.hwsrc}
                devices.append(device)
                # Stream each discovered host back to the GUI/CLI as it's found
                if progress_callback:
                    progress_callback(device)

        except Exception as e:
            logger.error(f"Local discovery error on subnet {subnet}: {e}")
            return [{"error": f"Discovery failed: {e}"}]

        return devices

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

    @staticmethod
    def fingerprint_os(target):
        """
        Lightweight passive OS guess based on the IP TTL of a single ICMP echo
        reply. Heuristic only -- TTL-based fingerprinting is not exact (NAT,
        custom sysctl tuning, and route distance can all shift the observed
        value), but it's the standard low-cost first signal real recon tools
        use before falling back to more invasive techniques.
        """
        os_name, is_admin = check_privileges()
        if os_name == "android":
            return {"error": "OS fingerprinting is not supported on this device."}
        if not is_admin:
            error_msg = "Run application with Administrator rights." if os_name == "windows" else "Run application using sudo."
            return {"error": f"Permission Denied. {error_msg}"}

        ip = ScanEngine.resolve_target(target)
        if not ip:
            return {"error": f"Could not resolve {target}"}

        try:
            response = sr1(IP(dst=ip)/ICMP(), timeout=2, verbose=0)
            if response is None:
                return {"error": "No ICMP response (host may be down, or blocking ICMP)."}

            ttl = response.ttl
            if ttl <= 64:
                guess = "Linux / Unix / macOS"
            elif ttl <= 128:
                guess = "Windows"
            else:
                guess = "Network device (router/switch) or legacy Unix"

            return {"ip": ip, "ttl": ttl, "os_guess": guess}
        except Exception as e:
            return {"error": f"Fingerprint failed: {e}"}

    # ==========================================
    # IDS SELF-TEST UTILITIES
    # ==========================================
    # These three methods exist for ONE purpose: let the user verify their own
    # SecurityMonitor (sniffer.py) actually fires its SYN-flood / ICMP-flood /
    # port-scan alerts. Each is hardcoded to 127.0.0.1 -- there is no target
    # parameter, by design, so this can't be repurposed into a generic
    # packet-flooding tool against an arbitrary host the way attack.py was.

    @staticmethod
    def ids_self_test_syn_flood(port=8765, count=60):
        """Fires `count` real SYN packets at a single loopback port (no response
        waiting) -- enough to cross SecurityMonitor.SYN_THRESHOLD on its own,
        without also tripping the port-scan detector (same port every time)."""
        os_name, is_admin = check_privileges()
        if os_name == "android":
            return {"error": "Raw packet sending is not supported on this device."}
        if not is_admin:
            error_msg = "Run application with Administrator rights." if os_name == "windows" else "Run application using sudo."
            return {"error": f"Permission Denied. {error_msg}"}
        try:
            send(IP(dst="127.0.0.1")/TCP(dport=port, flags="S"), count=count, verbose=0)
            return {"sent": count}
        except Exception as e:
            return {"error": f"SYN flood self-test failed: {e}"}

    @staticmethod
    def ids_self_test_icmp_flood(count=110):
        """Fires `count` real ICMP echo requests at loopback -- enough to cross
        SecurityMonitor.ICMP_THRESHOLD (100/window)."""
        os_name, is_admin = check_privileges()
        if os_name == "android":
            return {"error": "Raw packet sending is not supported on this device."}
        if not is_admin:
            error_msg = "Run application with Administrator rights." if os_name == "windows" else "Run application using sudo."
            return {"error": f"Permission Denied. {error_msg}"}
        try:
            send(IP(dst="127.0.0.1")/ICMP(), count=count, verbose=0)
            return {"sent": count}
        except Exception as e:
            return {"error": f"ICMP flood self-test failed: {e}"}

    @staticmethod
    def ids_self_test_port_scan(port_count=15):
        """Fires one SYN each at `port_count` distinct loopback ports -- enough to
        cross SecurityMonitor.PORT_SCAN_THRESHOLD (10 distinct ports), but well
        under SYN_THRESHOLD (50), so it tests the port-scan detector in isolation
        rather than also triggering a SYN-flood alert."""
        os_name, is_admin = check_privileges()
        if os_name == "android":
            return {"error": "Raw packet sending is not supported on this device."}
        if not is_admin:
            error_msg = "Run application with Administrator rights." if os_name == "windows" else "Run application using sudo."
            return {"error": f"Permission Denied. {error_msg}"}
        try:
            ports = list(range(30000, 30000 + port_count))
            for port in ports:
                send(IP(dst="127.0.0.1")/TCP(dport=port, flags="S"), verbose=0)
            return {"sent": len(ports)}
        except Exception as e:
            return {"error": f"Port-scan self-test failed: {e}"}