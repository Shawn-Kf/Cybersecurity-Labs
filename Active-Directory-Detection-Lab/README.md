# Enterprise Detection Engineering & Threat Emulation Lab

## Project Overview
This project demonstrates an end-to-end security operations and detection engineering pipeline built inside an isolated Active Directory environment. The lab simulates real-world adversary tactics aligned with the **MITRE ATT&CK** framework, captures high-fidelity telemetry using Windows Event logs and Sysmon, engineers custom SIEM detection rules in **Wazuh**, and implements defensive hardening controls to mitigate credential access vectors.

---

## Lab Architecture & Technical Specifications

* **Hypervisor:** Oracle VM VirtualBox
* **Host Resource Management:** 12 GB RAM constraint managed via a phased 2-VM execution workflow.
* **Network Isolation:** Internal Host-Only Network (`10.0.2.0/24`).

| Machine Name | Role | OS | IP Address | Key Software / Services |
| :--- | :--- | :--- | :--- | :--- |
| **Kali Linux** | Offensive / Attack Node | Linux (Rolling) | `10.0.2.x` | Impacket, Nmap, NetExec, John the Ripper |
| **AD-DC01** | Domain Controller (Target) | Windows Server 2022 | `10.0.2.10` | Active Directory Domain Services, Sysmon, Wazuh Agent |
| **Wazuh-server** | SIEM / Telemetry Stack | Ubuntu Server 22.04 | `10.0.2.3` | Wazuh Indexer, Manager, & Dashboard |

```text
       [ Attack Node: Kali Linux ]
             (10.0.2.x - Host-Only)
                    |
      [ Offensive Actions: Impacket / NetExec ]
                    |
                    v
    [ Target: Windows Server 2022 DC ] <--- Sysmon + Windows Security Logs
         (AD-DC01 | 10.0.2.10)
                    |
      [ Agent Telemetry: Wazuh Agent ]
                    |
                    v
       [ SIEM: Wazuh Manager Stack ]
       (Ubuntu Server | 10.0.2.3)
                    |
     [ Ingestion & Correlation Rules ]
                    |
                    v
      [ SOC Analyst: Wazuh Dashboard ]
         (Monitoring & Triaging Alerts)
```

---

## Simulated Attacks & Detection Engineering

### Scenario 1: Kerberoasting Attack & Detection
* **MITRE ATT&CK Technique:** [T1558.003 - Steal or Forge Kerberos Tickets: Kerberoasting](https://attack.mitre.org/techniques/T1558/003/)
* **Offensive Execution:** Leveraged `impacket-GetUserSPNs` to query Active Directory for user accounts associated with a Service Principal Name (`svc_sql`) and requested a Ticket Granting Service (TGS) ticket encrypted via weak RC4 (`0x17`).
* **Offline Cracking:** Extracted the Kerberos ticket hash and cracked it offline using `John the Ripper` against `rockyou.txt`, successfully exposing the service credential without triggering account lockouts or generating network alert volume.
* **Detection Mechanism:** Monitored Windows Security Log **Event ID 4769** (*A Kerberos service ticket was requested*). Standard modern AD traffic requests tickets with AES encryption (`0x12`/`0x13`); an RC4 encryption request (`0x17`) for a non-machine/non-`krbtgt` account strongly correlates with ticket extraction tools.

#### Wazuh Custom Rule (`/var/ossec/etc/rules/local_rules.xml`)
```xml
<group name="windows,active_directory,">

  <!-- Custom Rule: Detect Kerberoasting Activity (Weak RC4 TGS Ticket Request) -->
  <rule id="100100" level="12">
    <if_group>windows</if_group>
    <field name="win.system.eventID">^4769$</field>
    <field name="win.eventdata.ticketEncryptionType">^0x17$</field>
    <field name="win.eventdata.serviceName" negate="yes">krbtgt</field>
    <description>SOC-LAB: Potential Kerberoasting Attack Detected (RC4 TGS Ticket Requested)</description>
    <mitre>
      <id>T1558.003</id>
    </mitre>
    <group>kerberoasting,credential_access,</group>
  </rule>

</group>
```

---

### Scenario 2: Active Directory Password Spraying & Brute Force
* **MITRE ATT&CK Technique:** [T1110.003 - Brute Force: Password Spraying](https://attack.mitre.org/techniques/T1110/003/)
* **Offensive Execution:** Simulated spray attempts across multiple domain accounts (`jdoe`, `jsmith`, `svc_sql`, `baduser1`, `baduser2`) targeting SMB/Kerberos to systematically test credentials while evading standard single-account lockout policies.
* **Detection Mechanism:** Engineered a stateful correlation rule that triggers when repeated failed logon attempts (**Event ID 4625** / Wazuh internal rule `60122`) occur in a short window.

#### Wazuh Custom Rule (`/var/ossec/etc/rules/local_rules.xml`)
```xml
<group name="windows,active_directory,">

  <!-- Custom Rule: Detect Password Spraying (Multiple Failed Logons) -->
  <rule id="100101" level="10" frequency="4" timeframe="60">
    <if_matched_sid>60122</if_matched_sid>
    <description>SOC-LAB: Multiple Failed Windows Logon Attempts Detected (Potential Password Spray)</description>
    <mitre>
      <id>T1110.003</id>
    </mitre>
    <group>authentication_failed,credential_access,</group>
  </rule>

</group>
```

---

## Defensive Engineering & Remediation

Detection without remediation leaves infrastructure exposed. To neutralize the Kerberoasting vector:

1. **Cryptographic Hardening:** Updated the `svc_sql` service account attribute `msDS-SupportedEncryptionTypes` to enforce AES-128 and AES-256 (`0x18` / Decimal 24).
2. **Validation:** Purged client ticket caches using `klist purge` and re-requested the ticket.
3. **Result:** Active Directory enforced `AES-256-CTS-HMAC-SHA1-96` encryption, eliminating the legacy RC4 downgrade vector and rendering offline dictionary cracking via standard wordlists ineffective.

---

## Verification Evidence

| Evidence / Alert | Description | Artifact Path |
| :--- | :--- | :--- |
| **Kerberoasting Alert (Rule 100100)** | Level 12 alert capturing RC4 TGS request for `svc_sql` | `Screenshots/15_wazuh_kerberoasting_alert_rule100100.png` |
| **Password Spray Alert (Rule 100101)** | Level 10 threshold correlation alert on Event ID 4625 | `Screenshots/16_wazuh_passwordspray_alert_rule100101.png` |
| **Cryptographic Remediation** | `klist` output confirming AES-256 enforcement on service ticket | `Screenshots/17_kerberos_aes256_remediation.png` |

## Automated Incident Containment (Active Response)

To bridge the gap between detection and automated response (SOAR):
* **Trigger:** Rule `100101` (Password Spraying detected).
* **Automated Action:** The Wazuh Manager triggers an Active Response command on `AD-DC01`.
* **Execution:** A containment script isolates the targeted identity (`Disable-ADAccount`) and writes an audit log entry to `C:\Tools\active-response.log`, stopping credential stuffing before analysts intervene manually.