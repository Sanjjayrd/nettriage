# NetTriage — Network Traffic Triage Tool

> **A beginner-friendly, educational network traffic triage application designed for aspiring SOC analysts, cybersecurity students, and defenders.**

[![Privacy: 100% In-Browser](https://img.shields.io/badge/Privacy-100%25%20In--Browser-brightgreen)](#privacy-guarantee)
[![Architecture: Vanilla HTML/CSS/JS](https://img.shields.io/badge/Stack-HTML5%20%7C%20CSS3%20%7C%20Vanilla%20JS-blue)](#technology-stack)
[![Dependencies: Zero](https://img.shields.io/badge/Dependencies-Zero%20(No%20Install)-orange)](#quick-start)

---

## Table of Contents
1. [Project Overview](#project-overview)
2. [Quick Start (Windows & Static Hosting)](#quick-start)
3. [Privacy Guarantee](#privacy-guarantee)
4. [How to Think Like an Analyst](#how-to-think-like-an-analyst)
5. [How to Export Wireshark Packets as CSV](#how-to-export-wireshark-packets-as-csv)
6. [Supported CSV Columns & Aliases](#supported-csv-columns--aliases)
7. [Detection Rules & Configurable Thresholds](#detection-rules--configurable-thresholds)
8. [Transparent Investigation Scoring](#transparent-investigation-scoring)
9. [Pre-Packaged Demo Datasets](#pre-packaged-demo-datasets)
10. [Demonstration Guide (Recruiters & YouTube)](#demonstration-guide)
11. [Limitations & Potential False Positives](#limitations--potential-false-positives)
12. [Future Improvements Roadmap](#future-improvements-roadmap)

---

## Project Overview

When investigating a potential cyber incident, security operations center (SOC) analysts and network defenders often inspect packet captures (PCAP) to understand what occurred on the wire. However, raw packet captures can contain tens of thousands of frames, overwhelming beginners.

**NetTriage** bridges this gap:
1. You capture network traffic in Wireshark.
2. You export the packet summary as a standard CSV file.
3. You upload the CSV into NetTriage.
4. The tool parses the capture **locally in your browser** and applies 7 explainable detection heuristics.
5. You receive an intuitive triage dashboard highlighting hosts and traffic patterns worth investigating—with clear explanations of **why** the activity matters and **innocent reasons** that could explain it.

> ⚠️ **Core Philosophy:** *An anomaly is a starting point for investigation, not proof of compromise. Detection tells an analyst where to look. Investigation determines what actually happened.*

---

## Quick Start

### Running Locally on Windows
**No installation is required.** You do not need Node.js, Python, Docker, or any command-line tools.

1. Clone or download this project folder onto your Windows PC:
   ```
   D:\network triage tool\
   ```
2. Double-click `index.html` to open it in your default browser (Google Chrome, Microsoft Edge, Firefox, or Brave).
3. Click **"Load Mixed SOC Lab"** or drag your own exported Wireshark CSV to begin triaging!

### Static Hosting
Because NetTriage contains zero server-side code and zero build steps, you can host it directly on **GitHub Pages**, **Cloudflare Pages**, **Netlify**, or **AWS S3** by serving the root directory.

---

## Privacy Guarantee

*All packet analysis is performed 100% locally within your web browser using client-side JavaScript.*

- **No Remote Servers:** The uploaded file is read into your browser's local memory via the HTML5 FileReader API.
- **No External APIs:** No cloud services, external AI models, or third-party servers ever receive your data.
- **Zero Tracking:** No analytics scripts, cookies, telemetry, or advertisements are included.
- **Safe for Sensitive Captures:** Even internal corporate network captures remain strictly confidential on your local workstation.

---

## How to Think Like an Analyst

NetTriage reinforces standard SOC triage methodology:

1. **Observe Unusual Behaviour:** Spot outliers in packet volume, rapid host connections, or unusual protocol distributions.
2. **Identify Source & Destination:** Determine device identities. Is the sender an administrative server, a workstation, a printer, or an unknown rogue endpoint?
3. **Determine Involved Protocols:** Is the traffic using standard ports (e.g. 443 HTTPS, 53 DNS) or uncommon high ports? Is it plaintext or encrypted?
4. **Establish if Activity is Expected:** Check business context. Is there a scheduled backup running? Is an IT asset scanner scheduled?
5. **Look for Supporting Indicators:** Did the host follow a scan with credential guessing, SMB negotiations, or large data transfers?
6. **Correlate with Other Telemetry:** Verify endpoint logs (Windows Event Logs, Sysmon, EDR) and firewall logs to corroborate the findings.
7. **Decide Action & Document:** Conclude whether to dismiss the alert as benign business activity or escalate for incident containment.

---

## How to Export Wireshark Packets as CSV

To create a compatible CSV file from Wireshark:

1. Launch **Wireshark** and capture traffic on your authorized interface.
2. Stop the capture (red square button).
3. In Wireshark's top navigation menu, select:
   ```
   File → Export Packet Dissections → As CSV...
   ```
4. Save the file to your computer (e.g. `capture.csv`).
5. Drag and drop the saved CSV file into NetTriage.

> 🔒 **Legal & Ethical Notice:** Only capture network traffic on systems and networks you own or have explicit, documented permission to monitor. Unauthorized network sniffing may violate local laws and organizational policies.

---

## Supported CSV Columns & Aliases

Wireshark CSV exports usually contain 7 standard fields. NetTriage features an adaptive column parser that recognizes common variations and aliases:

| Standard Column | Accepted Aliases / Wireshark Field Names | Purpose in NetTriage |
|---|---|---|
| **No.** | `No`, `Frame Number`, `packet_number`, `#` | Frame sequence index |
| **Time** | `Time`, `Timestamp`, `frame.time_relative`, `frame.time` | Relative packet timing |
| **Source** | `Source IP`, `src`, `ip.src`, `ipv6.src`, `Source Address` | Identifies initiating host |
| **Destination** | `Destination IP`, `dst`, `ip.dst`, `ipv6.dst`, `Destination Address` | Identifies receiving host |
| **Protocol** | `proto`, `_ws.col.Protocol`, `ip.proto`, `transport` | Protocol breakdown & rule filters |
| **Length** | `len`, `frame.len`, `Packet Length`, `bytes` | Calculates average packet size |
| **Info** | `description`, `summary`, `_ws.col.Info` | Deep inspection for ports, SYN flags, DNS queries |

*If optional columns like Length or Info are omitted, NetTriage gracefully adapts without crashing.*

---

## Detection Rules & Configurable Thresholds

NetTriage uses an explainable rule-based engine. Every threshold is configurable under **"2. Detection Rule Thresholds"** in the app:

### Rule 1 — High Packet Volume
- **Default Threshold:** `> 50 packets` from a single source host.
- **Investigative Value:** Identifies hosts dominating network bandwidth.
- **Benign Explanations:** Scheduled cloud backups, operating system updates, file server copies, media streaming.

### Rule 2 — Possible Host Scanning
- **Default Threshold:** `> 10 unique destination IP addresses` from one source host.
- **Investigative Value:** Detects horizontal network discovery (ping sweeps or subnet enumeration).
- **Benign Explanations:** Network inventory tools, vulnerability management appliances, P2P software.

### Rule 3 — Possible Port Scanning
- **Default Threshold:** `> 10 unique destination ports` probed on a single target IP.
- **Investigative Value:** Identifies vertical service enumeration (reconnaissance to find open listening ports).
- **Benign Explanations:** IT configuration audits, multi-port application health probes, connection retries.

### Rule 4 — High ICMP Activity
- **Default Threshold:** `> 30 ICMP packets` from one source host.
- **Investigative Value:** Identifies active ping sweeps, router discovery storms, or ICMP denial-of-service attempts.
- **Benign Explanations:** IT administrators running continuous latency tests (`ping -t`), uptime monitoring agents (Nagios/Zabbix).

### Rule 5 — High DNS Query Activity
- **Default Threshold:** `> 30 DNS packets` from one source host.
- **Investigative Value:** Spots potential domain generation algorithm (DGA) malware, DNS tunneling, or aggressive web scrapers.
- **Benign Explanations:** Heavy web surfing across multi-CDN sites, email server reverse-DNS lookups, recursive resolver testing.

### Rule 6 — Repeated Source-to-Destination Traffic
- **Default Threshold:** `> 40 packets` exchanged between a specific IP pair.
- **Investigative Value:** Identifies heavy point-to-point dialogues, streaming channels, or potential command-and-control beaconing.
- **Benign Explanations:** Active remote desktop (RDP/SSH) sessions, video conferencing, database queries.

### Rule 7 — TCP SYN Heavy Activity
- **Default Threshold:** `> 20 TCP [SYN] packets` from one source host.
- **Investigative Value:** Identifies rapid half-open connection attempts or SYN flood patterns.
- **Benign Explanations:** Modern web browsers opening parallel connections, client retry loops against offline servers.

---

## Transparent Investigation Scoring

Unlike products that display arbitrary "97% Malicious" percentages, NetTriage uses an explainable, point-based **Triage Priority Score**:

| Triggered Condition | Points Added |
|---|---|
| Rule 1: High packet volume | **+20 pts** |
| Rule 2: Host scanning pattern | **+20 pts** |
| Rule 3: Port scanning pattern | **+15 pts** |
| Rule 4: High ICMP activity | **+15 pts** |
| Rule 5: High DNS query volume | **+10 pts** |
| Rule 6: Heavy IP pair exchange | **+10 pts** |
| Rule 7: Heavy TCP SYN rate | **+10 pts** |

### Priority Tiers
- **0 pts:** `Routine Activity` — Traffic conforms to baseline expectations.
- **1–20 pts:** `Low Priority Activity` — Minor activity observed; periodic review suggested.
- **21–50 pts:** `Moderate Activity` — Notable anomalies detected; review recommended.
- **51+ pts:** `Elevated Activity` — Multiple correlated indicators; prompt analyst investigation warranted.

---

## Pre-Packaged Demo Datasets

Three safe sample files are provided in the `/samples` folder and are embedded directly into the tool for instant one-click testing:

1. `samples/normal-traffic.csv`
   - Routine private network communication (DHCP, DNS queries, HTTP/TLS web sessions, ARP requests).
   - **Expected Result:** 0 alerts, 0 priority points ("Routine Activity").
2. `samples/high-volume-traffic.csv`
   - Normal background traffic plus host `192.168.1.55` generating 69 packets during a TLS file backup.
   - **Expected Result:** Triggers **Rule 1 (High Packet Volume)**; demonstrates clean single-alert handling.
3. `samples/mixed-soc-lab.csv`
   - Realistic multi-host scenario featuring subnet scanning (`10.0.0.99`), an ICMP ping sweep (`10.0.0.77`), and a sustained file transfer session (`192.168.1.100` → `192.168.1.200`).
   - **Expected Result:** Triggers Rules 1, 2, 4, and 6 with an **Elevated Activity** score (>50 pts).

---

## Demonstration Guide

When presenting this project to recruiters, peers, or in an instructional video:

### Step 1: Baseline Verification
- Click **"Load Normal Sample"**.
- Note the KPI summary cards, protocol chart, and 0 alerts.
- *Key Talking Point:* "A good triage tool should not generate false alerts on standard, everyday network traffic."

### Step 2: Volume Anomaly Handling
- Click **"Load High Volume Sample"**.
- Point out host `192.168.1.55` appearing under **Top Source Hosts** and triggering **Rule 1**.
- Highlight the alert explanation: it details possible benign reasons (e.g. backup, OS update) and actionable investigation steps.

### Step 3: Complex Multi-Vector Lab
- Click **"Load Mixed SOC Lab"**.
- Demonstrate how the Priority Score increments transparently and groups findings into Host Scanning, ICMP spikes, and repeated communication.
- Demonstrate filtering by severity and source IP (`10.0.0.99`).

### Step 4: The Core Analyst Lesson
- Emphasize the core cybersecurity takeaway:
  > *"Tools highlight what is unusual. Analysts determine whether it is malicious by correlating with business context, host roles, and endpoint telemetry."*

---

## Limitations & Potential False Positives

To ensure realistic expectations, this tool documents its technical boundaries:
- **CSV Summary vs. Full PCAP:** Wireshark CSV exports summarize packet headers. They do not contain complete packet payload streams, application layer reassembly, or cryptographic certificates.
- **Payload Encryption:** TLS 1.3 traffic encrypts application payloads; volume and frequency analysis must be supplemented with endpoint inspection.
- **Port Inspection Heuristic:** Destination port detection is extracted on a best-effort basis from Wireshark's formatted `Info` text column.
- **NAT Gateways:** Network Address Translation (NAT) devices may aggregate traffic from hundreds of internal hosts under a single IP address, skewing packet counts.
- **Environment Dependency:** A threshold of 50 packets is high for an idle IoT sensor but trivial for an active database server. Thresholds must always be tailored to the environment.

---

## Future Improvements Roadmap

Documented enhancements planned for subsequent versions:
- [ ] Direct client-side `.pcap` and `.pcapng` binary parsing via WebAssembly.
- [ ] Time-window sliding analysis (e.g. bursts per second rather than capture-wide totals).
- [ ] Visual network node communication graph.
- [ ] Offline GeoIP lookup for external IP addresses.
- [ ] Exportable SOC triage report (PDF / Markdown).
- [ ] Custom Snort/Suricata-style rule builder.

---

## License & Author

- **Author:** Developed for cybersecurity students, SOC trainees, and network defenders.
- **License:** Open Educational Resource (OER) — Free for educational and training purposes.
