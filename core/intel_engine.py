import requests
import logging
from core.utils import logger

# ==========================================
# THREAT INTELLIGENCE API CONFIGURATIONS
# ==========================================
# In a production environment, these should be loaded from core/config.py
# or environment variables (.env) to prevent credential leakage.
try:
    from core.config import SHODAN_API_KEY, VIRUSTOTAL_API_KEY, ABUSEIPDB_API_KEY
except ImportError:
    # Fallbacks if config.py is not fully set up yet
    SHODAN_API_KEY = None
    VIRUSTOTAL_API_KEY = None
    ABUSEIPDB_API_KEY = None


class IntelEngine:
    """
    Handles global threat intelligence gathering by interfacing with 
    commercial and open-source OSINT APIs (Shodan, VirusTotal, AbuseIPDB).
    """

    @staticmethod
    def query_shodan(ip_address):
        """
        Queries Shodan.io to retrieve historical port, service, and vulnerability 
        data for a specific IP address without sending active packets.
        """
        if not SHODAN_API_KEY:
            return {"error": "Shodan API key is missing from core/config.py."}

        try:
            url = f"https://api.shodan.io/shodan/host/{ip_address}?key={SHODAN_API_KEY}"
            response = requests.get(url, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                return {
                    "organization": data.get("org", "Unknown"),
                    "os": data.get("os", "Unknown"),
                    "ports": data.get("ports", []),
                    "vulnerabilities": data.get("vulns", []),
                    "hostnames": data.get("hostnames", [])
                }
            elif response.status_code == 404:
                return {"error": "No data available on Shodan for this IP."}
            else:
                return {"error": f"Shodan API error: {response.status_code}"}
                
        except Exception as e:
            logger.error(f"Shodan query failed for {ip_address}: {e}")
            return {"error": f"Connection error: {e}"}

    @staticmethod
    def query_virustotal(target, indicator_type="ip"):
        """
        Queries VirusTotal to check if an IP address or Domain has been 
        flagged as malicious by global antivirus engines.
        
        :param target: The IP or Domain to check.
        :param indicator_type: "ip" or "domain".
        """
        if not VIRUSTOTAL_API_KEY:
            return {"error": "VirusTotal API key is missing from core/config.py."}

        try:
            # Determine the correct endpoint based on indicator type
            endpoint = f"ip_addresses/{target}" if indicator_type == "ip" else f"domains/{target}"
            url = f"https://www.virustotal.com/api/v3/{endpoint}"
            
            headers = {
                "accept": "application/json",
                "x-apikey": VIRUSTOTAL_API_KEY
            }
            
            response = requests.get(url, headers=headers, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                
                malicious = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)
                harmless = stats.get("harmless", 0)
                
                return {
                    "malicious_hits": malicious,
                    "suspicious_hits": suspicious,
                    "harmless_hits": harmless,
                    "verdict": "MALICIOUS" if malicious > 0 else ("SUSPICIOUS" if suspicious > 0 else "CLEAN")
                }
            else:
                return {"error": f"VirusTotal API error: {response.status_code}"}
                
        except Exception as e:
            logger.error(f"VirusTotal query failed for {target}: {e}")
            return {"error": f"Connection error: {e}"}

    @staticmethod
    def query_abuseipdb(ip_address):
        """
        Queries AbuseIPDB to see if an IP address has been reported 
        by other sysadmins for malicious activities (DDoS, spam, hacking).
        """
        if not ABUSEIPDB_API_KEY:
            return {"error": "AbuseIPDB API key is missing from core/config.py."}

        try:
            url = "https://api.abuseipdb.com/api/v2/check"
            querystring = {
                "ipAddress": ip_address,
                "maxAgeInDays": "90"
            }
            headers = {
                "Accept": "application/json",
                "Key": ABUSEIPDB_API_KEY
            }
            
            response = requests.get(url, headers=headers, params=querystring, timeout=10)
            
            if response.status_code == 200:
                data = response.json().get("data", {})
                return {
                    "abuse_confidence_score": data.get("abuseConfidenceScore", 0),
                    "total_reports": data.get("totalReports", 0),
                    "usage_type": data.get("usageType", "Unknown"),
                    "domain": data.get("domain", "Unknown")
                }
            else:
                return {"error": f"AbuseIPDB API error: {response.status_code}"}
                
        except Exception as e:
            logger.error(f"AbuseIPDB query failed for {ip_address}: {e}")
            return {"error": f"Connection error: {e}"}

    @staticmethod
    def query_hackertarget_reverse_ip(ip_address):
        """
        Queries HackerTarget (No API key required for basic tier) to find 
        all domains currently hosted on a specific IP address.
        """
        try:
            url = f"https://api.hackertarget.com/reverseiplookup/?q={ip_address}"
            response = requests.get(url, timeout=10)
            
            if response.status_code == 200:
                # HackerTarget returns plain text lines
                if "error" in response.text.lower() or "no records" in response.text.lower():
                    return {"hosted_domains": []}
                    
                domains = response.text.strip().split("\n")
                return {"hosted_domains": domains}
            else:
                return {"error": f"HackerTarget API error: {response.status_code}"}
                
        except Exception as e:
            logger.error(f"Reverse IP query failed for {ip_address}: {e}")
            return {"error": f"Connection error: {e}"}