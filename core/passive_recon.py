import socket
import requests
from core.utils import logger

class PassiveEngine:
    
    @staticmethod
    def get_dns_records(domain):
        try:
            clean_domain = domain.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
            ip = socket.gethostbyname(clean_domain)
            try:
                aliases = socket.gethostbyname_ex(clean_domain)[1]
            except:
                aliases = []
            return {
                "Target Domain": clean_domain,
                "Resolved IP": ip,
                "Known Aliases": ", ".join(aliases) if aliases else "None found"
            }
        except Exception as e:
            logger.error(f"DNS lookup failed for {domain}: {e}")
            return {"error": f"Could not resolve domain: {domain}"}

    @staticmethod
    def get_ip_geolocation(ip_address):
        if not ip_address or ip_address in ["127.0.0.1", "0.0.0.0"]:
            return {"error": "Localhost addresses cannot be geolocated."}
        try:
            url = f"http://ip-api.com/json/{ip_address}"
            response = requests.get(url, headers={"User-Agent": "SoloScan/1.0"}, timeout=5)
            data = response.json()
            if data.get("status") == "success":
                return {
                    "Country": data.get("country"), "City": data.get("city"),
                    "ISP": data.get("isp"), "Organization": data.get("org")
                }
            return {"error": "External lookup failed."}
        except Exception as e:
            return {"error": "Service unavailable."}

    @staticmethod
    def get_whois(domain):
        clean_domain = domain.replace("https://", "").replace("http://", "").split("/")[0]
        try:
            r = requests.get(f"https://api.hackertarget.com/whois/?q={clean_domain}", timeout=10)
            return r.text if r.text else "No WHOIS data found."
        except Exception as e:
            return f"WHOIS error: {e}"

    @staticmethod
    def get_subdomains(domain):
        clean_domain = domain.replace("https://", "").replace("http://", "").split("/")[0]
        try:
            r = requests.get(f"https://api.hackertarget.com/hostsearch/?q={clean_domain}", timeout=10)
            if "error" in r.text.lower(): return []
            lines = r.text.strip().split('\n')
            subdomains = [line.split(',')[0] for line in lines if ',' in line]
            return subdomains[:15]
        except:
            return []