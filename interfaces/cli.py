import argparse
import sys
import socket
from core.engine import ScanEngine

def cli_port_handler(port, status, service, banner):
    if status in ["OPEN", "FILTERED"]:
        print(f"  [+] {port:<5}/tcp | {status:<8} | {service:<10} | {banner}")

def cli_device_handler(device):
    print(f"  [➔] Device Found: IP = {device['ip']:<15} | MAC = {device['mac']}")

def get_default_subnet():
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
        octets = local_ip.split('.')
        return f"{octets[0]}.{octets[1]}.{octets[2]}.0/24"
    except Exception:
        return "192.168.1.0/24"

def run_cli():
    parser = argparse.ArgumentParser(description="SoloScan CLI Mode")
    
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-d", "--discover", action="store_true", help="Discover active devices on local network")
    group.add_argument("-t", "--target", type=str, help="Target IP or Domain for port scan")
    
    parser.add_argument("-p", "--ports", type=str, default="21,22,23,25,53,80,443,8080", help="Comma-separated ports")
    parser.add_argument("-r", "--range", type=str, help="Custom subnet range")
    parser.add_argument("--stealth", action="store_true", help="Use Stealth SYN Scan (Requires Admin)")

    args = parser.parse_args()

    if args.discover:
        target_subnet = args.range if args.range else get_default_subnet()
        print(f"\n📡 Scanning Subnet: {target_subnet}\n" + "="*70)
        devices = ScanEngine.local_discovery(target_subnet, progress_callback=cli_device_handler)
        print("="*70 + f"\n📊 Found {len(devices)} active device(s).\n")

    elif args.target:
        # --- UPGRADED PORT PARSING LOGIC ---
        try:
            port_list = []
            for part in args.ports.split(","):
                part = part.strip()
                if "-" in part:
                    start, end = map(int, part.split("-"))
                    port_list.extend(range(start, end + 1))
                else:
                    port_list.append(int(part))
            port_list = sorted(list(set(port_list)))
        except ValueError:
            print("[-] Error: Ports must be comma-separated or hyphenated ranges (e.g., 22,80,1-100).")
            sys.exit(1)
        # -----------------------------------
            
        print(f"\n🔒 Scanning Target: {args.target} ({'SYN Stealth' if args.stealth else 'TCP Connect'})\n" + "="*70)
        if args.stealth:
            ScanEngine.stealth_syn_scan(args.target, port_list, result_callback=cli_port_handler)
        else:
            ScanEngine.port_scan(args.target, port_list, result_callback=cli_port_handler)
        print("="*70 + "\n📊 Port Scan Finished.\n")

if __name__ == "__main__":
    run_cli()