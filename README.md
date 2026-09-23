# Cybersecurity Engineering & Incident Investigation Labs

A centralized portfolio repository showcasing end-to-end detection engineering, threat emulation, digital forensics, and security operations workflows.

---

## Featured Projects

### 1. [Active Directory Detection Engineering & Threat Emulation Lab](./Active-Directory-Detection-Lab)
* **Domain:** Enterprise Detection Engineering, SIEM, Identity Security
* **Environment:** Windows Server 2022 (AD-DC01), Ubuntu Server (Wazuh SIEM), Kali Linux
* **Key Highlights:**
  * Aligned adversary emulation with **MITRE ATT&CK**: Kerberoasting (`T1558.003`) and Password Spraying (`T1110.003`).
  * Engineered custom Wazuh detection and stateful correlation rules analyzing Windows Event IDs `4769` and `4625`.
  * Neutralized Kerberoasting attack paths through AES-128/AES-256 cryptographic enforcement on Service Principal Names (SPNs).
  * Designed automated incident containment workflows using Wazuh Active Response.

 **[View Full Documentation & Evidence](./Active-Directory-Detection-Lab)**

---

### 2. [WebStrike Network Traffic & Incident Analysis](./Cyberdefenders/Webstrike)
* **Domain:** Digital Forensics & Incident Response (DFIR), Network Analysis
* **Tools:** Wireshark, PCAP Forensics
* **Key Highlights:**
  * Reconstructed HTTP streams to identify an initial access vector via an unrestricted file upload vulnerability (`/reviews/upload.php`).
  * De-obfuscated a double-extension payload (`image.jpg.php`) exposing a Netcat reverse shell establishing outbound C2 communication over port 8080.
  * Confirmed Remote Code Execution (RCE) and formulated remediation controls including server-side MIME-type enforcement and WAF rule tuning.

 **[View Investigation Write-Up](./Cyberdefenders/Webstrike)**

---

## Core Technical Competencies

* **SIEM & Telemetry:** Wazuh, Sysmon, Windows Event Logging, Zeek
* **Traffic & Forensics:** Wireshark, PCAP Stream Reassembly, Network Packet Analysis
* **Offensive Emulation:** Impacket, NetExec, John the Ripper, Metasploit
* **Systems & Directory Services:** Windows Server 2022, Active Directory Domain Services, Linux (Ubuntu, Kali)
* **Scripting & Automation:** PowerShell, Python, Bash, XML
