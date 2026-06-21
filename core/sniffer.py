import struct
import textwrap
import time
import logging
from typing import Optional
from dataclasses import dataclass
from enum import Enum
from collections import defaultdict, Counter
from datetime import datetime

# Suppress Scapy warning messages in the terminal
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import sniff, raw

# ==========================================
# PROTOCOLS & PORT MAPPINGS
# ==========================================
class ProtocolType(Enum):
    ICMP = 1
    TCP = 6
    UDP = 17
    IPV4 = 8

# Common port mappings
COMMON_PORTS = {
    20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "TELNET", 25: "SMTP",
    53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS",
    445: "SMB", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
    5900: "VNC", 6379: "Redis", 8080: "HTTP-Proxy", 8443: "HTTPS-Alt",
    27017: "MongoDB"
}

# Suspicious ports commonly used in attacks
SUSPICIOUS_PORTS = {
    1337: "LEET (Common Backdoor)",
    31337: "Back Orifice",
    4444: "Metasploit Default",
    5555: "Android Debug/Backdoor",
    6666: "IRC Backdoor",
    6667: "IRC",
    6668: "IRC",
    6669: "IRC",
    12345: "NetBus",
    27374: "SubSeven",
    54321: "Back Orifice 2000",
    1234: "Common Backdoor",
    9999: "Common Backdoor",
    8888: "Common Backdoor",
    7777: "Common Backdoor"
}

# MITRE ATT&CK Technique Mapping
MITRE_MAP = {
    "ICMP_FLOOD": "T1499 - Endpoint Denial of Service",
    "PORT_SCAN": "T1046 - Network Service Discovery",
    "SYN_FLOOD": "T1499.004 - Application or System Exploitation",
    "SUSPICIOUS_PORT": "T1571 - Non-Standard Port",
    "ARP_SPOOF": "T1557.002 - ARP Cache Poisoning"
}

# ==========================================
# DATA CLASSES FOR PACKET PARSING
# ==========================================
@dataclass
class EthernetFrame:
    dest_mac: str
    source_mac: str
    protocol: int
    data: bytes

@dataclass
class IPv4Packet:
    version: int
    header_length: int
    ttl: int
    protocol: int
    source: str
    target: str
    data: bytes

@dataclass
class ICMPPacket:
    type: int
    code: int
    checksum: int
    data: bytes

@dataclass
class TCPSegment:
    src_port: int
    dest_port: int
    sequence: int
    acknowledgment: int
    flags: dict
    data: bytes

@dataclass
class UDPSegment:
    src_port: int
    dest_port: int
    length: int
    data: bytes

# ==========================================
# SECURITY MONITOR (IDS LOGIC)
# ==========================================
class SecurityMonitor:
    """Monitors and detects suspicious network activity based on packet volume and ports."""
    
    def __init__(self):
        self.syn_counter = defaultdict(int)
        self.icmp_counter = defaultdict(int)
        self.port_scan_tracker = defaultdict(set)  # IP -> set of ports
        self.connection_tracker = defaultdict(int)
        self.last_reset = time.time()
        self.alerts = []
        
        # Detection Thresholds
        self.SYN_THRESHOLD = 50        # SYN packets per IP in window
        self.ICMP_THRESHOLD = 100      # ICMP packets per IP in window
        self.PORT_SCAN_THRESHOLD = 10  # Different ports from same IP
        self.TIME_WINDOW = 60          # Reset window in seconds
    
    def reset_counters(self):
        """Resets the packet counters periodically to prevent false positives over long sessions."""
        current_time = time.time()
        if current_time - self.last_reset > self.TIME_WINDOW:
            self.syn_counter.clear()
            self.icmp_counter.clear()
            self.port_scan_tracker.clear()
            self.last_reset = current_time
    
    def check_syn_flood(self, src_ip: str, flags: dict) -> Optional[str]:
        """Detects potential SYN flood attacks (DoS)."""
        if flags.get("SYN") and not flags.get("ACK"):
            self.syn_counter[src_ip] += 1
            if self.syn_counter[src_ip] > self.SYN_THRESHOLD:
                alert = f"⚠️ ALERT: Possible SYN Flood from {src_ip} ({self.syn_counter[src_ip]} packets)"
                return f"{alert} | {MITRE_MAP['SYN_FLOOD']}"
        return None
    
    def check_icmp_flood(self, src_ip: str) -> Optional[str]:
        """Detects potential ICMP flood attacks (Ping Flood)."""
        self.icmp_counter[src_ip] += 1
        if self.icmp_counter[src_ip] > self.ICMP_THRESHOLD:
            alert = f"⚠️ ALERT: Possible ICMP Flood from {src_ip} ({self.icmp_counter[src_ip]} packets)"
            return f"{alert} | {MITRE_MAP['ICMP_FLOOD']}"
        return None
    
    def check_port_scan(self, src_ip: str, dest_port: int) -> Optional[str]:
        """Detects sequential or randomized port scanning behavior."""
        self.port_scan_tracker[src_ip].add(dest_port)
        if len(self.port_scan_tracker[src_ip]) > self.PORT_SCAN_THRESHOLD:
            alert = f"⚠️ ALERT: Possible Port Scan from {src_ip} ({len(self.port_scan_tracker[src_ip])} ports)"
            return f"{alert} | {MITRE_MAP['PORT_SCAN']}"
        return None
    
    def check_suspicious_port(self, port: int, direction: str) -> Optional[str]:
        """Flags traffic on ports commonly used by malware and backdoors."""
        if port in SUSPICIOUS_PORTS:
            alert = f"🚨 SUSPICIOUS PORT: {port} ({SUSPICIOUS_PORTS[port]}) - {direction}"
            return f"{alert} | {MITRE_MAP['SUSPICIOUS_PORT']}"
        return None

# ==========================================
# PACKET SNIFFER ENGINE
# ==========================================
class PacketSniffer:
    """Handles raw packet capture and passes data to the SecurityMonitor."""
    
    def __init__(self, filter_protocol: Optional[ProtocolType] = None):
        self.filter_protocol = filter_protocol
        self.running = False
        self.security_monitor = SecurityMonitor()
        self.packet_count = 0

    def start(self, log_callback):
        """Starts the sniffing loop using Scapy and passes output to the GUI callback."""
        self.running = True
        log_callback("[*] Sniffer Started. Analyzing local traffic...", "GREEN")
        
        def packet_handler(pkt):
            if not self.running: 
                return True # Signals Scapy to stop sniffing
            self.packet_count += 1
            self.security_monitor.reset_counters()
            # Pass the raw byte data of the packet into the custom parser
            self.process_packet(raw(pkt), log_callback)
            
        try:
            # Scapy's sniff works cross-platform (requires Npcap on Windows, sudo on Linux)
            sniff(prn=packet_handler, store=False, stop_filter=lambda p: not self.running)
        except Exception as e:
            log_callback(f"[-] Sniffer Error: Ensure Npcap is installed and running as Admin. Details: {e}", "RED")
            self.running = False

    def stop(self):
        """Safely terminates the sniffing loop."""
        self.running = False

    def get_service_name(self, port: int) -> str:
        """Resolves port numbers to standard service names."""
        if port in COMMON_PORTS:
            return COMMON_PORTS[port]
        elif port < 1024:
            return "Well-Known"
        elif port < 49152:
            return "Registered"
        else:
            return "Dynamic/Private"

    def process_packet(self, raw_data: bytes, log_callback):
        """Unpacks byte data and runs it through the security checks."""
        try:
            eth = self.ethernet_frame(raw_data)
            
            if eth.protocol == ProtocolType.IPV4.value:
                ip = self.ipv4_packet(eth.data)
                
                # Apply protocol filters if set
                if self.filter_protocol and ip.protocol != self.filter_protocol.value: 
                    return

                if ip.protocol == ProtocolType.TCP.value:
                    tcp = self.tcp_segment(ip.data)
                    src_srv = self.get_service_name(tcp.src_port)
                    dst_srv = self.get_service_name(tcp.dest_port)
                    
                    # Log standard traffic connection to the GUI
                    log_callback(f"TCP | {ip.source}:{tcp.src_port} ({src_srv}) → {ip.target}:{tcp.dest_port} ({dst_srv})", "WHITE")
                    
                    # ----- Security Checks -----
                    syn_alert = self.security_monitor.check_syn_flood(ip.source, tcp.flags)
                    if syn_alert: log_callback(syn_alert, "RED")
                    
                    scan_alert = self.security_monitor.check_port_scan(ip.source, tcp.dest_port)
                    if scan_alert: log_callback(scan_alert, "ORANGE")
                    
                    src_port_alert = self.security_monitor.check_suspicious_port(tcp.src_port, "Source")
                    if src_port_alert: log_callback(src_port_alert, "RED")
                    
                    dst_port_alert = self.security_monitor.check_suspicious_port(tcp.dest_port, "Destination")
                    if dst_port_alert: log_callback(dst_port_alert, "RED")
                    
                elif ip.protocol == ProtocolType.UDP.value:
                    udp = self.udp_segment(ip.data)
                    src_srv = self.get_service_name(udp.src_port)
                    dst_srv = self.get_service_name(udp.dest_port)
                    log_callback(f"UDP | {ip.source}:{udp.src_port} ({src_srv}) → {ip.target}:{udp.dest_port} ({dst_srv})", "GREY")
                    
                    # UDP Security Checks
                    src_port_alert = self.security_monitor.check_suspicious_port(udp.src_port, "Source")
                    if src_port_alert: log_callback(src_port_alert, "RED")
                    
                    dst_port_alert = self.security_monitor.check_suspicious_port(udp.dest_port, "Destination")
                    if dst_port_alert: log_callback(dst_port_alert, "RED")
                    
                elif ip.protocol == ProtocolType.ICMP.value:
                    log_callback(f"ICMP | Ping from {ip.source} → {ip.target}", "BLUE")
                    icmp_alert = self.security_monitor.check_icmp_flood(ip.source)
                    if icmp_alert: log_callback(icmp_alert, "RED")

        except Exception:
            # Silently drop malformed packets to prevent GUI crashes or log spam
            pass

    # ==========================================
    # BYTE UNPACKING UTILITIES
    # ==========================================
    def ethernet_frame(self, data: bytes) -> EthernetFrame:
        """Unpacks the raw Ethernet frame."""
        import socket
        dest_mac, source_mac, proto = struct.unpack('! 6s 6s H', data[:14])
        return EthernetFrame(
            dest_mac=self.get_mac_addr(dest_mac), 
            source_mac=self.get_mac_addr(source_mac), 
            protocol=socket.htons(proto), 
            data=data[14:]
        )

    def ipv4_packet(self, data: bytes) -> IPv4Packet:
        """Unpacks the IPv4 header."""
        version_header_length = data[0]
        header_length = (version_header_length & 15) * 4
        ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
        return IPv4Packet(
            version=version_header_length >> 4, 
            header_length=header_length, 
            ttl=ttl, 
            protocol=proto, 
            source=self.ipv4(src), 
            target=self.ipv4(target), 
            data=data[header_length:]
        )

    def tcp_segment(self, data: bytes) -> TCPSegment:
        """Unpacks the TCP header and extracts control flags."""
        (src_port, dest_port, seq, ack, offset_reserved_flags) = struct.unpack('! H H L L H', data[:14])
        offset = (offset_reserved_flags >> 12) * 4
        flags = {
            'URG': (offset_reserved_flags & 32) >> 5, 
            'ACK': (offset_reserved_flags & 16) >> 4, 
            'PSH': (offset_reserved_flags & 8) >> 3, 
            'RST': (offset_reserved_flags & 4) >> 2, 
            'SYN': (offset_reserved_flags & 2) >> 1, 
            'FIN': offset_reserved_flags & 1
        }
        return TCPSegment(src_port, dest_port, seq, ack, flags, data[offset:])

    def udp_segment(self, data: bytes) -> UDPSegment:
        """Unpacks the UDP header."""
        src_port, dest_port, size = struct.unpack('! H H 2x H', data[:8])
        return UDPSegment(src_port, dest_port, size, data[8:])

    @staticmethod
    def get_mac_addr(bytes_addr: bytes) -> str: 
        """Returns a properly formatted MAC address."""
        return ':'.join(map('{:02x}'.format, bytes_addr)).upper()
        
    @staticmethod
    def ipv4(addr: bytes) -> str: 
        """Returns a properly formatted IPv4 address."""
        return '.'.join(map(str, addr))