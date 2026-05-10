# Splunk Incident Analysis: Brute Force Detection and Security Event Investigation

## Overview

This project simulates a SOC analyst investigation workflow using Splunk Enterprise 8.2.4 as the SIEM. Log data from multiple lab hosts was ingested, correlated, and analyzed to detect password spray and brute-force authentication activity, perform false positive analysis, assess incident scope and impact, and produce analyst-ready documentation.

---

## Objective

- Ingest and normalize log data from multiple systems into Splunk
- Use SPL queries, timecharts, and event correlation to investigate suspicious authentication activity
- Apply a structured SOC triage methodology to identify true vs. false positives
- Assess scope and impact of detected activity
- Produce auditable investigation documentation with containment and remediation recommendations

---

## Tools Used

- Splunk Enterprise 8.2.4 (SIEM)
- Windows Security Event Logs
- SPL (Search Processing Language)
- MITRE ATT&CK Framework
- Virtualized CentOS lab environment (192.168.190.10)

---

## Environment

Logs were collected from 5 lab hosts (host1, agent1, agent2, agent3, controller) and ingested into a centralized Splunk instance at 192.168.190.10:8000 to simulate a multi-endpoint SOC monitoring environment. Event sources included Windows Security logs (spray.csv), system process metrics (top), and host metrics.

---

## Investigation Walkthrough

### Step 1 — Establish Host Visibility
Confirmed log ingestion across all hosts using dedup query.

**SPL query:**
```spl
index=main host=** | table host | dedup host
```

**Results:**
- **206,979 total events** ingested (1/30/2025 5:00 PM to 1/31/2025 5:42 PM)
- **5 hosts confirmed:** host1, agent1, agent2, agent3, controller
- All hosts reporting — full coverage confirmed before investigation began

### Step 2 — Host Metrics Baseline
Reviewed process and memory metrics across hosts to establish normal activity baseline.

**SPL query:**
```spl
index=main source=top (host="agent1" OR host="agent2") | multikv fields pctMEM | table host,pctMEM | dedup host
```

**Results:**
- 3,249 events across agent1 and agent2 (1/30/2025 6:00 PM to 1/31/2025 6:57 PM)
- Process-level memory utilization reviewed per host
- No anomalous resource consumption identified — baseline established

### Step 3 — Memory Utilization Timechart (All Hosts)
Built a 15-minute interval timechart of maximum memory utilization across all hosts to identify any resource spikes correlating with the authentication events.

**SPL query:**
```spl
index=main source=** host=** | timechart span=15m max(pctMEM) by host
```

**Results:**
- 210,765 events matched across agent2, agent3, and controller
- Timestamps tracked from 2025-01-30 18:00:00 onward
- No significant memory spikes identified during the authentication attack window

### Step 4 — Windows Security Event Log Review
Investigated Windows Security Event logs from the spray.csv source ingested into the window_event host.

**SPL query:**
```spl
source="spray.csv" host="window_event" index="summary" sourcetype="csv"
```

**Results:**
- **4,833 total events** (dated 11/19/2019)
- Key Event IDs observed:
  - **4624** — An account was successfully logged on
  - **4625** — An account failed to log on
  - **4634** — An account was logged off
  - **4672** — Special privileges assigned to new logon
- Account DC1$ (SYSTEM) observed with special privilege assignments — noted for follow-up

### Step 5 — Failed Login Timechart (Event ID 4625)
Isolated Event ID 4625 (failed logon) events and built a 10-second interval timechart to identify authentication attack patterns.

**SPL query:**
```spl
source="spray.csv" host="windows_event" index="summary" sourcetype="csv" "Event ID"=4625 | timechart span=10s dc(_raw) by source
```

**Results:**
- **2,386 failed logon events** identified
- Attack window: **2019-11-19 17:51:40 to 17:52:50** (70 seconds total)
- Event counts per 10-second interval:

| Timestamp | Failed Logins |
|---|---|
| 2019-11-19 17:51:40 | 289 |
| 2019-11-19 17:51:50 | 363 |
| 2019-11-19 17:52:00 | 348 |
| 2019-11-19 17:52:10 | 367 |
| 2019-11-19 17:52:20 | 354 |
| 2019-11-19 17:52:30 | 345 |
| 2019-11-19 17:52:40 | 345 |
| 2019-11-19 17:52:50 | 55 |

**Peak rate: 367 failed logons in a single 10-second interval — consistent with automated password spray activity, not human behavior.**

### Step 6 — False Positive Analysis
Assessed whether the activity could be explained by legitimate users:
- Volume of 2,386 failed logons across 70 seconds is inconsistent with any legitimate user or system process
- Peak of 367 attempts in 10 seconds indicates automated tooling
- Pattern of consistent high-volume attempts across the full window is characteristic of a password spray attack (MITRE ATT&CK T1110.003)
- No single account lockout would explain this volume — spray technique deliberately distributes attempts across accounts to avoid lockout

**Verdict: True positive.** Activity assessed as an automated password spray attack.

### Step 7 — Scope and Impact Assessment
- Attack contained within window_event host log source
- 4,833 total authentication events during attack period including logons, logoffs, and privilege assignments
- DC1$ SYSTEM account observed with Event ID 4672 (special privileges) — requires further investigation to confirm if this is related to the spray activity or routine system behavior
- Full scope assessment would require cross-referencing 4624 (successful logon) events against the spray window to identify any successful authentications

### Step 8 — Containment and Remediation Recommendations
- Implement account lockout policy: 5 failed attempts triggers 15-minute lockout
- Deploy alerting on Event ID 4625 volume: threshold >50 failures in 10 seconds from any source
- Enable Multi-Factor Authentication across all accounts to neutralize credential spray impact
- Review DC1$ SYSTEM privilege assignment events (4672) occurring during attack window
- Investigate any Event ID 4624 (successful logon) events within the 17:51–17:53 UTC window for potential compromise
- Implement password spray detection rule in SIEM: high volume of 4625 events distributed across multiple accounts from single source

---

## MITRE ATT&CK Mapping

| Technique | ID | Description |
|---|---|---|
| Password Spraying | T1110.003 | 2,386 failed logons across 70 seconds — peak 367 per 10s interval |
| Valid Accounts | T1078 | DC1$ SYSTEM account observed with special privilege assignment during attack window |
| Inter-Process Communication | T1559 | Researched adjacent technique; abused by FIN7 (DDE/T1559.002) and APT32 (COM/T1559.001) |

---

## Key Findings Summary

| Finding | Detail |
|---|---|
| Hosts Monitored | 5 (host1, agent1, agent2, agent3, controller) |
| Total Events Ingested | 206,979 |
| Windows Auth Events | 4,833 |
| Failed Logon Events (4625) | 2,386 |
| Attack Window | 2019-11-19 17:51:40 – 17:52:50 UTC (70 seconds) |
| Peak Failure Rate | 367 failed logons in 10 seconds |
| Attack Type | Password Spray (T1110.003) |
| Verdict | True Positive |
| Impact | Medium — no confirmed successful logon identified |

---

## Screenshots

### Centralized Host Visibility in Splunk
![Centralized Host Visibility](splunk-agent-logs.png)

### Multi-Host Event Results
![Multi-Host Event Results](splunk-event-results.png)

### Windows Event Log Analysis
![Windows Event Log Analysis](splunk-windows-event-analysis.png)

### Failed Login Timechart (Event ID 4625)
![Failed Login Timechart](splunk-failed-login-timechart.png)

### Host Metrics Query Results
![Host Metrics](splunk-host-metrics.png)

---

## Skills Demonstrated

- SIEM log ingestion and multi-host monitoring (Splunk Enterprise 8.2.4)
- SPL query writing, timecharts, and event correlation
- Structured SOC triage methodology
- True/false positive analysis
- Password spray attack detection and analysis
- Scope and impact assessment
- MITRE ATT&CK technique mapping (T1110.003, T1078, T1559)
- Threat actor research (FIN7, APT32)
- Analyst-ready incident documentation
- Containment and remediation recommendations
