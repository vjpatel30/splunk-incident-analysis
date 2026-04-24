# Splunk Incident Analysis: Brute Force and Security Event Investigation

## Overview
This project focused on using Splunk to investigate security events in a lab environment, including brute-force activity, multi-host log analysis, and event correlation across multiple systems.

## Objective
- Review log data from multiple systems in Splunk
- Search, filter, and analyze security-relevant events
- Investigate failed login activity and Windows event data
- Build familiarity with incident-response style workflows and SOC analysis concepts

## Tools Used
- Splunk
- Virtualized lab environment
- Windows and Linux systems
- Security logs
- MITRE ATT&CK framework

## Environment
Logs were collected from multiple lab systems and reviewed in Splunk to simulate centralized monitoring and investigation workflows in a SIEM-style environment.

## Steps Performed
1. Reviewed centralized logs from multiple lab systems in Splunk
2. Examined host visibility and event data across multiple systems
3. Investigated Windows event logs and failed login activity using searches, tables, and time-based analysis
4. Reviewed different query results to understand how Splunk supports monitoring and investigation workflows
5. Documented findings from security-relevant events and strengthened understanding of incident investigation concepts

## Key Findings
- Splunk can centralize logs from multiple systems for easier monitoring and investigation
- Multi-host log visibility improves security analysis and reduces the need to manually inspect each host
- Windows event logs and failed login trends can help identify suspicious authentication activity
- SIEM platforms support analysts by improving visibility, event review, and investigation efficiency

## Security Impact
This project reinforced how SIEM tools support security monitoring and incident analysis by centralizing event data and helping analysts identify suspicious activity more efficiently.

## SOC Relevance
This project helped build familiarity with centralized log analysis, failed login investigation, Windows event review, and ATT&CK-based threat research. These concepts are directly relevant to SOC work, where analysts investigate alerts, review event data, and use threat context to understand suspicious activity.

## MITRE ATT&CK Research
As part of this lab work, I also researched MITRE ATT&CK technique **T1559 (Inter-Process Communication)** and reviewed how its sub-techniques can be abused by real threat actors. This included:

- **T1559.001 – Component Object Model (COM)**
- **T1559.002 – Dynamic Data Exchange (DDE)**

The research connected these techniques to real-world threat actors including:

- **FIN7**, which has used DDE in phishing campaigns to execute malicious commands and deliver malware
- **APT32 (OceanLotus)**, which has abused COM-related techniques for persistence and evasion

This strengthened my understanding of attacker behavior, execution techniques, and how ATT&CK mappings can support security analysis and SOC investigations.

## Skills Demonstrated
- SIEM exposure
- Log analysis
- Security monitoring
- Incident investigation
- Pattern recognition
- MITRE ATT&CK technique mapping
- Threat actor research
- Security documentation

## Screenshots

### Centralized Host Visibility in Splunk
![Centralized Host Visibility in Splunk](splunk-agent-logs.png)

### Multi-Host Event Results
![Multi-Host Event Results](splunk-event-results.png)

### Windows Event Log Analysis
![Windows Event Log Analysis](splunk-windows-event-analysis.png)

### Failed Login Timechart Analysis
![Failed Login Timechart Analysis](splunk-failed-login-timechart.png)

### Host Metrics Query Results
![Host Metrics Query Results](splunk-host-metrics.png)


