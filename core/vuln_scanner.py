import requests
from core.utils import logger, COMMON_WEB_PATHS

class WebVulnScanner:
    
    @staticmethod
    def analyze_website(url):
        if not url.startswith("http"):
            url = f"http://{url}"
        findings = []
        try:
            headers = {"User-Agent": "SoloScan Security Auditor/1.0"}
            response = requests.get(url, headers=headers, timeout=5, verify=False)
            server_headers = response.headers
            
            if url.lower().startswith("https") and "Strict-Transport-Security" not in server_headers:
                findings.append({"vulnerability": "Missing HSTS Header", "severity": "Medium", "why_and_how": "Missing HTTPS enforcement.", "remediation": "Add Strict-Transport-Security header."})
            if "X-Frame-Options" not in server_headers and "Content-Security-Policy" not in server_headers:
                findings.append({"vulnerability": "Missing Clickjacking Protection", "severity": "Medium", "why_and_how": "Site can be framed by malicious actors.", "remediation": "Add X-Frame-Options header."})
            if "Server" in server_headers:
                findings.append({"vulnerability": "Tech Disclosure", "severity": "Low", "why_and_how": f"Server broadcasted: {server_headers['Server']}", "remediation": "Obfuscate server headers."})
                
            if not findings:
                findings.append({"vulnerability": "No Standard Misconfigurations", "severity": "Info", "why_and_how": "Headers look secure.", "remediation": "N/A"})
            return findings
        except Exception as e:
            return [{"error": f"Failed connection: {e}"}]

    @staticmethod
    def fuzz_directories(url):
        if not url.startswith("http"): url = f"http://{url}"
        url = url.rstrip('/')
        found_paths = []
        for path in COMMON_WEB_PATHS:
            try:
                r = requests.get(url + path, headers={"User-Agent": "SoloScan/1.0"}, timeout=3, verify=False)
                if r.status_code in [200, 403]:
                    found_paths.append({"path": path, "status": r.status_code})
            except:
                pass
        return found_paths

    @staticmethod
    def check_cve_heuristics(banner):
        banner = banner.lower()
        vulns = []
        if "openssh 8." in banner or "openssh 9.0" in banner:
            vulns.append("CRITICAL: Vulnerable to CVE-2023-38408 (RCE)")
        if "nginx 1.18" in banner:
            vulns.append("HIGH: Vulnerable to CVE-2021-23017 (DNS Poisoning)")
        if "apache/2.4.49" in banner or "apache/2.4.50" in banner:
            vulns.append("CRITICAL: Vulnerable to CVE-2021-41773 (Path Traversal)")
        if "vsftpd 2.3.4" in banner:
            vulns.append("CRITICAL: Backdoor Command Execution (CVE-2011-2523)")
        return vulns