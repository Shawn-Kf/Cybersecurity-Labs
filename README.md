# Cybersecurity Engineering & Incident Investigation Labs

A centralized portfolio repository showcasing hands-on detection engineering, threat emulation, digital forensics, and security operations workflows.

---

## Featured Projects

### 1. [Active Directory Detection Engineering & Threat Emulation Lab](./Active-Directory-Detection-Lab)

**Domain:** Enterprise Detection Engineering, SIEM, Identity Security  
**Environment:** Windows Server 2022 (AD-DC01), Ubuntu Server (Wazuh SIEM), Kali Linux

**Key Highlights**
- Aligned adversary emulation with **MITRE ATT&CK**, including Kerberoasting (`T1558.003`) and password spraying (`T1110.003`).
- Engineered custom Wazuh detection and stateful correlation rules analyzing Windows Event IDs `4769` and `4625`.
- Addressed Kerberoasting attack paths through AES-128/AES-256 cryptographic enforcement on Service Principal Names (SPNs).
- Designed automated incident-containment workflows using Wazuh Active Response.

**[View Full Documentation & Evidence](./Active-Directory-Detection-Lab)**

---

### 2. [WebStrike Network Traffic & Incident Analysis](./Cyberdefenders/Webstrike)

**Domain:** Digital Forensics & Incident Response (DFIR), Network Analysis  
**Tools:** Wireshark, PCAP forensics

**Key Highlights**
- Reconstructed HTTP streams to identify an initial-access vector involving an unrestricted file-upload vulnerability (`/reviews/upload.php`).
- Analyzed a double-extension payload (`image.jpg.php`) and identified a Netcat reverse shell establishing outbound command-and-control (C2) communication over port `8080`.
- Investigated evidence of remote code execution (RCE) and documented remediation controls, including server-side MIME-type enforcement and WAF rule tuning.

**[View Investigation Write-Up](./Cyberdefenders/Webstrike)**

---

### 3. [Python Security Log Analyzer & IOC Detection Tool](./security-log-analyzer)

**Domain:** Security Monitoring, Detection Engineering, Log Analysis  
**Tools:** Python, JSON, `unittest`

**Key Highlights**
- Built a Python tool to parse and validate authentication events from JSON logs.
- Implemented time-window-based detection for brute-force attempts and password spraying.
- Added severity classification and potential indicator-of-compromise (IOC) extraction.
- Generated structured JSON security reports and wrote automated tests for detection, input validation, and reporting.
- Included synthetic authentication events and screenshot evidence documenting the implementation and test results.

**[View Project Documentation, Source Code & Evidence](./security-log-analyzer)**

---

## Core Technical Competencies

- **SIEM & Telemetry:** Wazuh, Sysmon, Windows Event Logging, Zeek
- **Traffic & Forensics:** Wireshark, PCAP stream reassembly, network packet analysis
- **Offensive Emulation:** Impacket, NetExec, John the Ripper, Metasploit
- **Systems & Directory Services:** Windows Server 2022, Active Directory Domain Services, Linux (Ubuntu, Kali)
- **Scripting & Automation:** Python
- **Detection Engineering:** Authentication-event analysis, time-window detection rules, alert severity, IOC extraction, automated testing

---

## Repository Purpose

This repository documents practical cybersecurity labs and projects. Each project aims to demonstrate the investigation or engineering workflow, the tools used, the evidence collected, and the lessons learned. Lab results are presented for educational and portfolio purposes.
