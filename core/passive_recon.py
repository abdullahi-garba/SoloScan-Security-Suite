import socket
import requests
from core.utils import logger

try:
    from core.config import WHOISJSON_API_KEY
except ImportError:
    WHOISJSON_API_KEY = None

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

        if not WHOISJSON_API_KEY:
            return ("WHOIS error: No WhoisJSON API key configured. "
                     "Copy core/config.py.example to core/config.py and add your key "
                     "(get a free one at https://whoisjson.com/free-domain-api).")

        try:
            r = requests.get(
                "https://whoisjson.com/api/v1/whois",
                params={"domain": clean_domain},
                headers={"Authorization": f"TOKEN={WHOISJSON_API_KEY}"},
                timeout=10
            )

            if r.status_code == 401:
                return "WHOIS error: Invalid or missing WhoisJSON API key (401 Unauthorized)."
            if r.status_code == 429:
                return "WHOIS error: WhoisJSON monthly quota or rate limit reached (429)."
            if r.status_code != 200:
                return f"WHOIS error: WhoisJSON returned status {r.status_code}: {r.text[:200]}"

            data = r.json()

            # Normalize the JSON response into the same kind of plain-text block the
            # rest of the app (PDF export, GUI cards) already expects from get_whois().
            lines = []
            for key in ("domain", "registrar", "createdDate", "updatedDate", "expiresDate", "status", "dnssec"):
                if data.get(key):
                    lines.append(f"{key}: {data[key]}")

            name_servers = data.get("nameServers") or data.get("nameservers")
            if isinstance(name_servers, dict):
                name_servers = name_servers.get("hostNames", [])
            if name_servers:
                lines.append(f"nameServers: {', '.join(str(ns) for ns in name_servers)}")

            contact = data.get("registrant") or data.get("contacts")
            if contact:
                lines.append(f"registrant: {contact}")

            return "\n".join(lines) if lines else (str(data) or "No WHOIS data found.")

        except requests.exceptions.RequestException as e:
            return f"WHOIS error: {e}"
        except ValueError:
            return "WHOIS error: WhoisJSON returned a non-JSON response."

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