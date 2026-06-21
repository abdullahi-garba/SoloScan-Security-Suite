import json
import csv
import logging
import os
import sys
import platform
import ctypes
from datetime import datetime
from fpdf import FPDF

# ==========================================
# CONFIGURATIONS & DICTIONARIES
# ==========================================
# Standard port mappings for service identification
COMMON_SERVICES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 135: "RPC", 139: "NetBIOS", 143: "IMAP",
    443: "HTTPS", 445: "SMB", 3306: "MySQL", 3389: "RDP", 8080: "HTTP-Proxy"
}

# Scan mode configurations
SCAN_MODES = {
    "Standard (TCP Connect)": {"stealth": False},
    "Stealth (SYN - Admin Required)": {"stealth": True}
}

# Wordlist for the Passive Recon web fuzzer
COMMON_WEB_PATHS = [
    "/admin", "/login", "/robots.txt", "/.env", "/.git/config", 
    "/backup.zip", "/phpinfo.php", "/api/", "/wp-admin/"
]

# Wordlist for the Brute-Force authentication tool
COMMON_CREDENTIALS = [
    ("admin", "admin"), ("admin", "password"), ("admin", "12345"),
    ("root", "root"), ("root", "toor"), ("user", "password"),
    ("administrator", "password"), ("guest", "guest")
]

# ==========================================
# SYSTEM UTILITIES
# ==========================================
def check_privileges():
    """
    Checks if the application is running with elevated privileges.
    Returns a tuple: (operating_system_name, is_admin_boolean)
    """
    if 'ANDROID_ROOT' in os.environ or hasattr(sys, 'getandroidapilevel'):
        return "android", False

    system = platform.system().lower()
    
    if system == "windows":
        try:
            is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
            return "windows", is_admin
        except Exception:
            return "windows", False
    else:
        try:
            is_admin = os.geteuid() == 0
            return "linux", is_admin
        except Exception:
            return system, False

def setup_logger():
    """Configures the background logging framework for debugging."""
    log_filename = "soloscan_debug.log"
    logging.basicConfig(
        filename=log_filename,
        level=logging.INFO,
        format="%(asctime)s | %(levelname)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )
    return logging.getLogger("SoloScan")

logger = setup_logger()

# ==========================================
# REPORTING ENGINES
# ==========================================
def export_results(data, scan_type, file_format="json"):
    """Exports raw scan data to JSON or CSV formats."""
    if not data:
        logger.warning(f"Attempted to save empty {scan_type} report.")
        return None

    if not os.path.exists("reports"):
        os.makedirs("reports")

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"reports/{scan_type}_{timestamp}.{file_format}"

    try:
        if file_format == "json":
            with open(filename, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=4)
        elif file_format == "csv":
            with open(filename, "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=data[0].keys())
                writer.writeheader()
                writer.writerows(data)
        return filename
    except Exception as e:
        logger.error(f"Export failed: {e}")
        return None

def generate_pdf_report(report_data, title="Executive Security Report", filename="Report"):
    """
    Compiles raw data into a formatted PDF document suitable for clients or management.
    """
    if not os.path.exists("reports"):
        os.makedirs("reports")
        
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filepath = f"reports/{filename}_{timestamp}.pdf"
    
    try:
        pdf = FPDF()
        pdf.add_page()
        
        # Header Section
        pdf.set_font("Helvetica", style='B', size=16)
        pdf.cell(0, 10, txt=title, ln=True, align="C")
        
        pdf.set_font("Helvetica", size=10)
        pdf.cell(0, 10, txt=f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", ln=True, align="C")
        pdf.line(10, 30, 200, 30)
        pdf.ln(10)
        
        # Body Data Section
        pdf.set_font("Helvetica", style="B", size=12)
        pdf.cell(0, 10, txt="System Findings & OSINT Data:", ln=True)
        pdf.set_font("Helvetica", size=10)
        
        # Iterate through the data and write it to the PDF safely
        if isinstance(report_data, list):
            for item in report_data:
                text_to_print = str(item)
                if isinstance(item, dict):
                    # Format dictionaries as clean key-value pairs
                    text_to_print = "\n".join([f"{k}: {v}" for k, v in item.items()])
                
                # Sanitize text for PDF encoding (removes emojis/weird characters)
                clean_text = text_to_print.encode('ascii', 'ignore').decode('ascii')
                pdf.multi_cell(0, 8, txt=clean_text)
                pdf.ln(3)
        else:
            clean_text = str(report_data).encode('ascii', 'ignore').decode('ascii')
            pdf.multi_cell(0, 8, txt=clean_text)
            
        # Custom Developer Footer
        pdf.ln(15)
        pdf.set_font("Helvetica", style="I", size=8)
        pdf.cell(0, 10, txt="built by GarbaTheAnalyst, The Analyst Consultancy, 2026. SoloScan", ln=True, align="C")
        
        pdf.output(filepath)
        return filepath
    except Exception as e:
        logger.error(f"PDF generation failed: {e}")
        return None