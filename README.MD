# SoloScan Security Suite PRO
**Developed by:** GarbaTheAnalyst Consultancy  
**Institution:** Newgate University Minna  
**Department:** Cyber Security Science  
**Context:** Practical framework implementation supporting research in Digital Resilience and Nigerian National Security.

---

## 📌 Executive Summary
SoloScan is an enterprise-grade, hybrid GUI/CLI cybersecurity framework designed for both Offensive Security (Red Team) and Active Defense (Blue Team) operations. The suite bypasses traditional disjointed tooling by combining active network probing, OSINT reconnaissance, intrusion detection, and automated executive reporting into a single, multi-threaded workspace.

## 🛡️ Core Capabilities

### 1. Active Probing & Reconnaissance
* **Standard & Stealth Scanning:** Supports both standard 3-way TCP handshakes and raw-socket half-open SYN scans (Scapy) to evade basic firewalls.
* **Network Topology Mapping:** Integrated ICMP/UDP traceroute capabilities to visually map network hops.
* **Automated Fuzzing:** Dictionary-based directory brute-forcing for standard web server misconfigurations.

### 2. Blue Team Defense & SIEM
* **Intrusion Detection System (IDS):** A localized packet sniffer that evaluates raw Ethernet frames to identify MITRE ATT&CK patterns, including:
  * T1499: Endpoint Denial of Service (SYN/ICMP Floods)
  * T1046: Network Service Discovery (Sequential Port Scanning)
  * T1571: Non-Standard Port usage (Malware/Backdoor detection)
* **Active Honeypot Deployment:** Synthetically opens listening sockets to mimic vulnerable services (e.g., SSH on Port 22) to trap, log, and alert on unauthorized lateral movement.
* **Real-Time SIEM Polling:** Establishes a baseline of open ports on target infrastructure and asynchronously alerts the operator of state changes.

### 3. Intelligence & Reporting
* **Executive PDF Generation:** Utilizes `fpdf2` to dynamically compile raw JSON arrays and system findings into formatted, readable reports for stakeholders.
* **Background Auditing:** Implements standard Python `logging` for persistent, non-blocking background error handling and system state tracking.

## ⚙️ Technical Architecture
* **Frontend:** Built via `flet`, establishing a concurrent, state-managed GUI alongside an embedded, fully synchronized terminal emulator.
* **Networking Engine:** Python's native `socket` library paired with `requests`, `ftplib`, and `scapy` for Layer 2 to Layer 7 traffic manipulation.
* **Concurrency:** Leverages `ThreadPoolExecutor` and background `threading` to maintain UI responsiveness during heavy I/O bound network operations.

## 🚀 Execution Instructions
1. Navigate to the project directory.
2. Install dependencies: `pip install -r requirements.txt`
3. Launch the application (Administrator privileges recommended for raw socket access):
   ```cmd
   python main.py