# SoloScan Security Suite PRO

A modular, GUI-and-terminal cybersecurity toolkit built for a school cybersecurity competition, where students host personal networks (online and offline) and assess each other's setups. SoloScan combines active/passive reconnaissance, an intrusion detection sniffer, defensive tooling, OSINT and threat-intel lookups, a persisted findings database, and an embedded terminal — all in a single cross-platform Flet application (Windows, Linux, Android).

> **Built by GarbaTheAnalyst, The Analyst Consultancy — © 2026, SoloScan™**

---

## Table of Contents

1. [What This Is (and Isn't)](#what-this-is-and-isnt)
2. [Features](#features)
3. [Project Structure](#project-structure)
4. [Installation](#installation)
5. [Configuration (API Keys)](#configuration-api-keys)
6. [Running the App](#running-the-app)
7. [The GUI: Tab-by-Tab Guide](#the-gui-tab-by-tab-guide)
8. [The Embedded Terminal: Full Command Reference](#the-embedded-terminal-full-command-reference)
9. [The Standalone CLI (`cli.py`)](#the-standalone-cli-clipy)
10. [The Database](#the-database)
11. [Logs and Reports](#logs-and-reports)
12. [Permissions & Privileges](#permissions--privileges)
13. [Building / Compiling for Windows, Linux & Android](#building--compiling-for-windows-linux--android)
14. [Legal & Ethical Use](#legal--ethical-use)
15. [Known Limitations](#known-limitations)
16. [Credits](#credits)

---

## What This Is (and Isn't)

SoloScan is a **defensive-leaning network security suite**: a port/vulnerability scanner, OSINT/threat-intel aggregator, intrusion detection sniffer, and basic defensive toolkit, wrapped in both a desktop/mobile GUI and a scriptable terminal.

**It deliberately does not include:**
- Real DoS/DDoS attack capability (no packet flooding against arbitrary targets, no IP spoofing)
- Exploits, payloads, or a Meterpreter/msfvenom-style implant system
- AV/EDR evasion, encoders, or NOP generators
- Pivoting or post-exploitation tooling

Where those capabilities would normally live, SoloScan instead ships **safe equivalents**: a clearly-labeled cosmetic "Sim DoS" console (prints fake flood output, sends zero real packets) instead of a real flood tool, and self-tests that verify the IDS's own detectors using harmless loopback-only traffic instead of attacking anything. See [Legal & Ethical Use](#legal--ethical-use).

---

## Features

### Reconnaissance (Active)
- **TCP Connect & Stealth SYN port scanning** with banner grabbing
- **CVE heuristic matching** against scanned banners (flags known-vulnerable service versions, e.g. vsftpd 2.3.4, Apache 2.4.49/50, OpenSSH 8.x, nginx 1.18)
- **ARP-based local network discovery** (subnet sweep for live hosts + MAC addresses)
- **Traceroute**
- **Passive OS fingerprinting** (TTL-heuristic guess: Linux/Unix/macOS vs Windows vs network device)
- **Default credential auditing** against FTP and HTTP Basic Auth using a common-credentials wordlist

### Reconnaissance (Passive / OSINT)
- DNS resolution + alias discovery
- IP geolocation
- WHOIS lookups (via [WhoisJSON](https://whoisjson.com))
- Subdomain enumeration
- HTTP header security audit (missing HSTS, clickjacking protection, server-version disclosure)
- Web directory/path fuzzing against a common wordlist
- **Threat intelligence aggregation:**
  - [Shodan](https://shodan.io) — historical ports, OS, hostnames, known CVEs
  - [VirusTotal](https://virustotal.com) — reputation verdict for both the resolved IP and the domain
  - [AbuseIPDB](https://abuseipdb.com) — abuse confidence score and report history
  - HackerTarget reverse-IP lookup — other domains hosted on the same IP

### Defense
- **Intrusion Detection Sniffer** — live packet capture with MITRE ATT&CK–mapped alerting:
  - SYN flood detection (T1499.004)
  - ICMP flood detection (T1499)
  - Port scan detection (T1046)
  - Suspicious/backdoor port detection (T1571) — flags known malware ports (Metasploit default 4444, Back Orifice, NetBus, SubSeven, etc.)
- **IDS Self-Tests** — three buttons that fire real (but loopback-only, harmless) traffic specifically engineered to trip one detector each, so you can verify your own IDS actually works:
  - Test SYN Flood Detection
  - Test ICMP Flood Detection
  - Test Port Scan Detection
- **Honeypot** — fake banner-presenting listener that logs intrusion attempts
- **Host IP management** — view/change a Windows adapter's static IP (input-validated, injection-hardened)

### Real-Time Monitoring (SIEM)
- Periodic baseline + delta polling of a target's key ports, alerting when a port's state changes (e.g. closed → open)

### Database
- Every scan, discovery, credential audit, OS fingerprint, and OSINT finding is automatically persisted to a local SQLite database — browsable, searchable, and clearable from the GUI or terminal. This is the safe equivalent of Metasploit's native database integration, built on SQLite instead of PostgreSQL so it runs standalone with zero setup on Windows, Linux, *and* Android.

### Reporting
- One-click PDF export for Active Scan results and Passive OSINT results
- JSON/CSV export support for raw scan data

### Sim DoS (cosmetic only)
- A flood-console *visual mock-up* for demos/training. Contains no networking code whatsoever — no sockets, no Scapy, no DNS resolution. It only prints scripted text with fake counters via `time.sleep()`. Clearly labeled as a simulation in the UI itself.

### Embedded Terminal
- A scriptable command-line interface built directly into the GUI, with full command parsing (not just a log viewer) — see [full reference](#the-embedded-terminal-full-command-reference)
- Every GUI action mirrors its equivalent command into the terminal in real time, and vice versa
- Three independently switchable layouts: **GUI Only**, **CLI Only**, **Split View**

### Cross-Platform & Responsive
- Single codebase compiles to Windows, Linux, and Android (via Flet/Flutter)
- Responsive layout: desktop gets a side navigation rail + side-by-side terminal; narrow/mobile screens get a bottom navigation bar with a stacked, scrollable layout

---

## Project Structure

```
soloscan/
├── gui.py                      # Main Flet GUI application (entry point)
├── cli.py                      # Standalone argparse-based CLI (separate from the embedded terminal)
├── core/
│   ├── __init__.py
│   ├── engine.py               # ScanEngine: port scan, SYN scan, discovery, traceroute,
│   │                           #   bruteforce, OS fingerprint, IDS self-tests
│   ├── passive_recon.py        # PassiveEngine: DNS, geolocation, WHOIS, subdomains
│   ├── vuln_scanner.py         # WebVulnScanner: header audit, fuzzing, CVE heuristics
│   ├── sniffer.py              # PacketSniffer + SecurityMonitor (IDS logic)
│   ├── defense.py              # IPManager, Honeypot
│   ├── intel_engine.py         # IntelEngine: Shodan, VirusTotal, AbuseIPDB, reverse-IP
│   ├── database.py             # SQLite persistence layer
│   ├── utils.py                # Shared constants, logger, PDF/CSV export, privilege check
│   ├── config.py               # Your real API keys (gitignored -- not committed)
│   └── config.py.example       # Template showing which keys to fill in
├── logs/                       # Auto-created: per-session GUI/CLI transcripts
├── data/                       # Auto-created: soloscan.db (SQLite database)
├── reports/                    # Auto-created: PDF/JSON/CSV exports
├── .gitignore
└── requirements.txt
```

---

## Installation

### Requirements
- **Python 3.10+**
- **Npcap** (Windows) or raw-socket capability (Linux/macOS) for Scapy-based features (SYN scan, ARP discovery, sniffer, traceroute, OS fingerprint, IDS self-tests)
- Administrator (Windows) / `sudo` (Linux/macOS) privileges for any raw-socket feature

### Dependencies

```
flet
scapy
requests
fpdf2
```

Install everything with:

```bash
pip install -r requirements.txt
```

If `requirements.txt` isn't present yet, generate one after installing the packages above:

```bash
pip freeze > requirements.txt
```

### Setting up your API keys

```bash
cp core/config.py.example core/config.py
```

Then edit `core/config.py` and fill in whichever keys you have (see [Configuration](#configuration-api-keys) below). You don't need all of them — every integration degrades gracefully and just reports "key missing" for whichever source you skip.

---

## Configuration (API Keys)

`core/config.py` is **gitignored** — never commit your real keys. `core/config.py.example` is the safe-to-commit template.

| Variable | Used For | Get a Free Key |
|---|---|---|
| `WHOISJSON_API_KEY` | WHOIS lookups | https://whoisjson.com/free-domain-api |
| `SHODAN_API_KEY` | Shodan threat intel | https://account.shodan.io/ |
| `VIRUSTOTAL_API_KEY` | VirusTotal reputation checks | https://www.virustotal.com/gui/my-apikey |
| `ABUSEIPDB_API_KEY` | AbuseIPDB reputation checks | https://www.abuseipdb.com/account/api |

> **Note:** VirusTotal's free tier is rate-limited (4 requests/minute). The OSINT pipeline makes 2 VT calls per run, so heavy concurrent use across many students sharing one key may hit 429s.

---

## Running the App

```bash
# GUI (primary entry point)
python gui.py

# Standalone CLI mode (separate from the embedded terminal inside the GUI)
python cli.py --discover
python cli.py --target 192.168.1.1 --ports 22,80,443 --stealth
```

On first launch, the GUI shows a splash screen, then a EULA you must accept to proceed.

---

## The GUI: Tab-by-Tab Guide

The navigation rail (desktop) / bottom navigation bar (mobile) has 8 tabs:

| Tab | Purpose |
|---|---|
| **Active** | Port scanning, device discovery, traceroute, OS fingerprinting, credential auditing |
| **SIEM** | Real-time port-state change monitoring/alerting |
| **Passive** | Full OSINT pipeline: DNS, geo, WHOIS, subdomains, threat intel, header audit, fuzzing |
| **Defense** | IP management, honeypot deployment |
| **Sniffer** | Live IDS packet sniffing + the three detector self-tests |
| **Tools** | Domain resolver, subnet calculator, background audit logs |
| **Sim DoS** | Cosmetic flood-console simulation (no real networking) |
| **Database** | Browse/search/clear every persisted finding |

Each view, once opened, **stays alive in the background** — switching tabs doesn't stop or reset an in-progress scan, OSINT run, or sniffer session; you'll see its current progress/results exactly as you left them when you switch back.

At the top of the window, three buttons control the terminal panel's visibility: **GUI Only**, **CLI Only**, **Split View**.

---

## The Embedded Terminal: Full Command Reference

Type `help` in the terminal for this list at any time, or `help <command>` for one command's syntax.

| Command | Syntax | Description |
|---|---|---|
| `scan` | `scan <target> [ports] [--stealth]` | Port scan. e.g. `scan 192.168.1.5 22,80,1-100 --stealth` |
| `discover` | `discover [subnet]` | ARP-sweep a /24 for live hosts (defaults to your local subnet) |
| `traceroute` | `traceroute <target>` | Trace the network hops to a target |
| `fingerprint` | `fingerprint <target>` | Passive TTL-based OS guess |
| `bruteforce` | `bruteforce <target> [ftp\|http]` | Test default credentials against a service (default: ftp) |
| `osint` | `osint <domain>` | Run the full passive OSINT + threat-intel pipeline |
| `resolve` | `resolve <domain>` | Resolve a domain to an IP address |
| `subnet` | `subnet <CIDR>` | Calculate network/broadcast/usable host range |
| `whoami` / `ip` | `whoami` | Show this machine's current local IP |
| `privileges` | `privileges` | Show OS and admin/root elevation status |
| `sniff` | `sniff <start\|stop>` | Start or stop the IDS packet sniffer |
| `testtraffic` | `testtraffic [syn\|icmp\|portscan]` | Loopback-only self-test for one IDS detector (default: syn) |
| `honeypot` | `honeypot <start\|stop> [port]` | Deploy or stop the intrusion-detection honeypot |
| `setip` | `setip <adapter> <ip> [mask] [gw]` | Change a network adapter's static IP (Windows, Admin required) |
| `db` | `db <hosts\|ports\|vulns\|creds\|osint\|search <term>\|stats\|clear>` | Query or manage the persisted database |
| `simulate` | `simulate [target] [port] [count]` | **SIMULATED ONLY** — prints a fake flood log, sends nothing real |
| `clear` | `clear` | Clear the terminal output |
| `help` | `help [command]` | List all commands, or detailed syntax for one |

Every action triggered from the GUI also echoes its equivalent command into this terminal in real time (e.g. clicking "Engage Target" prints `PS> scan 127.0.0.1 3 ports`), so the terminal always reflects everything happening in the app, regardless of where it was triggered.

---

## The Standalone CLI (`cli.py`)

Separate from the embedded terminal above — this is a traditional `argparse` CLI you run directly from your OS shell, useful for scripting or headless use:

```bash
python cli.py -d                          # Discover devices on your local subnet
python cli.py -d -r 10.0.0.0/24           # Discover on a specific subnet
python cli.py -t example.com -p 22,80,443 # Scan specific ports
python cli.py -t 192.168.1.5 --stealth    # Stealth SYN scan with default ports
```

| Flag | Description |
|---|---|
| `-d, --discover` | Discover active devices on the local network |
| `-t, --target` | Target IP or domain for a port scan |
| `-p, --ports` | Comma-separated ports / ranges (default: `21,22,23,25,53,80,443,8080`) |
| `-r, --range` | Custom subnet range for `--discover` |
| `--stealth` | Use stealth SYN scan instead of TCP connect (requires Admin/root) |

---

## The Database

SQLite file at `data/soloscan.db`, created automatically on first run. Five tables: `hosts`, `ports`, `vulnerabilities`, `credentials`, `osint_findings`. Browse and search it from the **Database** tab, or query it from the terminal with the `db` command (see above).

This exists so a competition round's findings persist across scans and across app restarts, instead of living only in scattered timestamped PDF exports.

---

## Logs and Reports

| Location | Contents |
|---|---|
| `logs/gui_session_<timestamp>.txt` | Every line printed to the terminal that originated from a GUI action, written live |
| `logs/cli_session_<timestamp>.txt` | Every line printed to the terminal that originated from a typed terminal command, written live |
| `data/soloscan.db` | Persisted hosts/ports/vulnerabilities/credentials/OSINT findings |
| `reports/*.pdf` / `*.json` / `*.csv` | One-off exports from the Active/Passive tabs' Export buttons |
| `soloscan_debug.log` | Background application debug log |

A new pair of session log files is created every time the app starts, so logs never overwrite each other across runs.

---

## Permissions & Privileges

Several features use raw sockets via Scapy and require elevated privileges:

| Feature | Requires |
|---|---|
| Stealth SYN scan | Admin (Windows) / `sudo` (Linux/macOS) |
| ARP device discovery | Admin / `sudo` |
| Traceroute | Admin / `sudo` |
| OS fingerprinting | Admin / `sudo` |
| Packet sniffer | Admin / `sudo` |
| IDS self-tests | Admin / `sudo` |
| `setip` / IP management | Admin (Windows only — uses `netsh`) |

Features without elevated privileges return a clear "Permission Denied" message rather than failing silently. None of these are supported on Android (raw sockets aren't available there); the app detects this and disables the relevant features with an explanatory message instead of crashing.

---

## Building / Compiling for Windows, Linux & Android

SoloScan uses [Flet](https://flet.dev), which packages Python+Flet apps into native builds via Flutter under the hood. The `flet build` command handles this.

### Prerequisites (one-time, per build machine)
- Flutter SDK installed and on your `PATH` (`flutter doctor` should run clean)
- For **Android** builds specifically: Android SDK + a JDK (Flutter's `flutter doctor --android-licenses` will guide you through accepting the required licenses)
- `pip install flet` (make sure you're on a recent Flet version — run `flet --version` to check)

### Windows
```bash
flet build windows
```
Produces a Windows executable under `build/windows`.

### Linux
```bash
flet build linux
```
Produces a Linux executable under `build/linux`.

### Android
```bash
flet build apk
```
Produces an installable `.apk` under `build/apk`. Use `flet build aab` instead if you need an `.aab` for Play Store-style distribution.

### Notes
- Run each build command from the project root (where `gui.py` lives).
- The exact flags and output paths can shift between Flet releases — run `flet build --help` or check [Flet's packaging docs](https://docs.flet.dev) if a command above doesn't match your installed version.
- Scapy-dependent features (SYN scan, sniffer, ARP discovery, OS fingerprint, IDS self-tests, traceroute) won't function on the Android build — there's no raw-socket access on that platform. The GUI already detects this (`check_privileges()` returns `"android"`) and disables those specific buttons with an explanatory message rather than crashing; the OSINT, passive recon, and database features work fully on Android.
- For Windows specifically, raw-socket features additionally require [Npcap](https://npcap.com/) to be installed on the *end user's* machine, not just the build machine.

---

## Legal & Ethical Use

SoloScan was built for a sanctioned school cybersecurity competition where participants explicitly consent to having their own networks probed by other students. **Only use this tool against systems and networks you own or have explicit, documented authorization to test.** Running active scans, brute-force credential audits, or any other feature here against a network you don't have permission to test may be illegal in your jurisdiction, regardless of intent.

By design, this app does **not** include:
- Real DoS/DDoS capability or IP spoofing
- Exploits, payloads, or remote-access implants
- AV/EDR evasion tooling

If your competition specifically requires demonstrating denial-of-service *detection*, use the IDS self-tests (`testtraffic`) — they generate real but harmless loopback-only traffic to verify your sniffer's alerting, without any actual attack capability.

---

## Known Limitations

- **First-visit-only refresh on some tabs:** since each tab's view is now built once and reused (so in-progress tasks survive switching tabs), a couple of one-time-fetch displays — e.g. Defense's current-IP label, Database's initial stats — only refresh on your *first* visit per session, not every time you return to that tab. Database has a manual **Refresh** button for this; Defense doesn't yet.
- **Sniffer traffic volume:** the embedded terminal only mirrors actual *alerts* from the sniffer (not routine per-packet traffic) to avoid flooding the compact terminal view — full traffic is visible on the dedicated Sniffer tab panel.
- **VirusTotal rate limits:** see [Configuration](#configuration-api-keys) above.
- **Flet API version drift:** a couple of Flet APIs (`NavigationBarDestination` vs `NavigationDestination`, `on_resize` vs `on_resized`) differ by version. The code detects which your installed Flet provides and falls back safely either way, but if you upgrade Flet and hit a blank screen, check the console output first — it prints which API failed.
- **OS fingerprinting is heuristic only:** TTL-based guessing is a coarse signal (NAT, custom sysctl tuning, and route distance can all shift the observed value) — treat it as a hint, not a certainty.

---

## Credits

Built by **GarbaTheAnalyst**, The Analyst Consultancy — © 2026, SoloScan™.