# FUTURE_CS_01
Future Interns SOC Assignment 
# Malware Detection Incident Report – SOC Task 1

This repository contains the incident report, Splunk screenshots, dashboards, and alert classification data for a malware detection investigation performed as part of a SOC task. The project demonstrates malware detection, threat intelligence verification, and remediation strategies using **Splunk Enterprise** and open-source threat intel tools.

---

## Overview
On **03-Oct-2025**, multiple malware events were detected across internal hosts using Splunk.  
The alerts included:

- **Ransomware**
- **Trojan**
- **Rootkit**
- **Worm**
- **Spyware**

These incidents posed a **high risk to data confidentiality, integrity, and availability**, requiring immediate containment, remediation, and monitoring to prevent further compromise.

---

## Timeline of Events
Each malware detection event was logged with details such as **timestamp, user, IP address, type of threat, and severity**.  
Splunk screenshots were captured for proof of detection.  
Example threats detected:
- Ransomware detected on `172.16.0.3` (Critical)
- Rootkit detected on `10.0.0.5` (High)
- Trojan detected on multiple internal and external IPs
- Worm infection attempt on `203.0.113.77`

---

## Threat Intelligence Verification
IP addresses were verified using:
- **VirusTotal**
- **AbuseIPDB**
- **Talos Intelligence**

Findings:
- One internal IP (`10.0.0.5`) flagged by a vendor.
- Other IPs showed no external malicious reputation.
- Suggests events were primarily **internal threats**.

---

## Impact Assessment
- **Confidentiality**: Possible data leakage due to spyware.
- **Integrity**: Files could be encrypted/modified (ransomware impact).
- **Availability**: Systems may become unavailable until remediation.

---

## Root Cause Hypothesis
Possible infection vectors:
1. Phishing emails or malicious attachments.  
2. External/removable devices introducing malware.  
3. Lateral spread from compromised hosts.

---

## Containment & Remediation Steps
1. Isolate infected hosts.  
2. Block malicious IPs from Splunk alerts.  
3. Run full malware scans on affected systems.  
4. Reset passwords & enforce MFA.  
5. Monitor network traffic for anomalies.  
6. Apply security patches & strengthen endpoint protection.  

---

## Next Steps & Lessons Learned
- Improve SOC alert rules for ransomware/trojan/rootkit.  
- Conduct phishing awareness training.  
- Maintain regular system backups.  
- Continuously monitor dashboards & refine alerts.  

---

## Repository Contents
- **Incident Report PDF** – Full report with findings.  
- **Splunk Screenshots** – Malware detection alerts & dashboards.  
- **Malware Trend Dashboards** – Visual overview of threats.  
- **Alert Classification Spreadsheet** – Summary of detections, actions, and status.

Example structure of the spreadsheet:

| Timestamp | User    | IP Address   | Threat     | Severity | Tool   | Action Taken  | Status      |
|-----------|---------|-------------|------------|----------|--------|---------------|-------------|
| 2025-07-03 09:10:14 | bob     | 172.16.0.3 | Ransomware | High     | Splunk | Host isolated | Remediated |
| 2025-07-03 07:51:14 | eve     | 10.0.0.5   | Rootkit    | High     | Splunk | Host isolated | Pending    |
| ...       | ...     | ...         | ...        | ...      | ...    | ...           | ...         |

---

## Author
**Komal Ratnaparkhe**  
Cybersecurity Intern | SOC Analyst Trainee  

---

## ⚠️ Disclaimer
This project is for **educational purposes only** and simulates a SOC malware detection scenario in a controlled environment.
