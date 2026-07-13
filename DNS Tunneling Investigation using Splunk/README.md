# 🚨 Windows Endpoint Investigation #2 | Detecting DNS Tunneling via Typosquatting Using Sysmon & Splunk

> *"It's just a Google DNS request... but it was gOogle.com, not google.com 😄"*

**Role:** SOC Analyst (Blue Team / DFIR)  
**Environment:** Isolated Windows Security Lab  
**Objective:** Reconstruct attacker activity from Windows Security Logs & Sysmon telemetry before the ransomware note appeared.

---

## Table of Contents

- [Attack Scenario Architecture](#attack-scenario-architecture)
- [Attack Timeline](#attack-timeline)
- [Investigation with Splunk](#investigation-with-splunk)
- [Splunk Search Queries](#splunk-search-queries)
- [MITRE ATT&CK Mapping](#mitre-attck-mapping)
- [Key Takeaways](#key-takeaways)
- [Screenshots](#screenshots)

---

## Attack Scenario Architecture

```mermaid
flowchart TD
    subgraph Attacker_Env["Attacker Environment"]
        A[("Attacker DNS Server<br/>gOogle.com")]
    end

    subgraph Victim_Env["Victim Windows Endpoint"]
        direction TB
        S1["Step 1: Email Client (Outlook)<br/>Phishing email delivered"]
        S2["Step 2: WINWORD.EXE<br/>User clicks 'Enable Content'"]
        S3["Step 3: Scheduled Task (schtasks.exe)<br/>Persistence every 3 minutes"]
        S4["Step 4: DNS Tunneling<br/>Encoded payload in subdomains"]
        S1 -->|User opens attachment<br/>enables macros| S2
        S2 -->|Macro creates| S3
        S3 -->|DNS queries to gOogle.com| S4
    end

    A -->|1. Phishing email with<br/>macro-enabled .docm| S1
    S4 -->|5. DNS queries resolve<br/>to attacker server| A
```

---

## Attack Timeline

```mermaid
flowchart TD
    subgraph Phase1["📧 Initial Access — T+0s"]
        P1["Phishing email delivered<br/>to Outlook"]
    end

    subgraph Phase2["👤 Execution — T+5s to T+15s"]
        direction TB
        P2["T+5s — User opens attachment"]
        P3["T+10s — User enables macros<br/>WINWORD.EXE launched<br/>Sysmon Event ID 1"]
        P4["T+15s — Malicious macro executes<br/>Sysmon Event ID 1"]
        P2 --> P3 --> P4
    end

    subgraph Phase3["⏰ Persistence — T+20s"]
        P5["Scheduled Task created<br/>(executes every 3 minutes)<br/>Sysmon Event ID 11"]
    end

    subgraph Phase4["🌐 DNS Tunneling — T+3min onwards"]
        direction TB
        P6["T+3min — DNS Query #1<br/>to gOogle.com<br/>Sysmon Event ID 22"]
        P7["T+6min — DNS Query #2<br/>to gOogle.com<br/>Sysmon Event ID 22"]
        P8["T+9min — DNS Query #3<br/>to gOogle.com<br/>Sysmon Event ID 22"]
        P9["... repeats every 3 minutes<br/>Sysmon Event ID 22"]
        P6 --> P7 --> P8 --> P9
    end

    P1 --> Phase2 --> Phase3 --> Phase4
```

---

### Attack Flow Summary

```mermaid
flowchart LR
    subgraph Phishing["📧 Initial Access"]
        A[Attacker] -->|Invoice-themed<br/>.docm attachment| B[Outlook]
    end
    subgraph Execution["👤 Execution & Persistence"]
        B -->|Enable Content| C[WINWORD.EXE]
        C -->|Creates| D[Scheduled Task<br/>3 min interval]
    end
    subgraph C2["🌐 C2 & Exfiltration"]
        D -->|DNS queries| E[gOogle.com<br/>Typosquatted domain]
        E -->|Data exfiltrated| A
    end
```

---

## Investigation with Splunk

### Sysmon Event IDs Used

| Event ID | Description      | Detection Point                        |
|----------|------------------|----------------------------------------|
| 1        | Process Creation | WINWORD.EXE launched from macro        |
| 11       | FileCreate       | Scheduled Task .job file written       |
| 22       | DNS Query        | Repeated queries to gOogle.com         |

### Detection Workflow

```mermaid
flowchart TD
    Search["Splunk Search<br/>index=* sourcetype=XmlWinEventLog"] --> E1

    subgraph E1["Step 1 — Event ID 1: Process Creation"]
        direction TB
        Q1["Query: EventCode=1 WINWORD.EXE"]
        R1["Result: WINWORD.EXE launched<br/>by Explorer.EXE"]
    end

    subgraph E2["Step 2 — Event ID 11: File Creation"]
        direction TB
        Q2["Query: EventCode=11 Invoice"]
        R2["Result: Scheduled Task .job<br/>file created by WINWORD"]
    end

    subgraph E3["Step 3 — Event ID 22: DNS Query"]
        direction TB
        Q3["Query: EventCode=22 google<br/>NOT query=*.google.com"]
        R3["Result: DNS queries to<br/>typosquatted gOogle.com"]
    end

    subgraph E4["Step 4 — Correlation"]
        direction TB
        R4["Link ProcessID across<br/>Event IDs 1, 11, 22<br/>Reconstruct full attack chain"]
    end

    E1 --> E2 --> E3 --> E4
```

---

## Splunk Search Queries

### 1️⃣ Detected Initial Execution — WINWORD.EXE launched

```spl
index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=1 WINWORD.EXE
| table _time, Computer, User, Image, CommandLine, ParentImage
```

**Purpose:** Identify when WINWORD.EXE was launched and which parent process spawned it.

### 2️⃣ Identified Persistence — Scheduled Task Creation

```spl
index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=11 Invoice
| table _time, Computer, User, Image, TargetFilename
```

**Purpose:** Detect file creation events related to Scheduled Task persistence triggered by the macro.

### 3️⃣ Detected Suspicious DNS Activity — Typosquatted Domain

```spl
index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=22 google
| search NOT query="*.google.com"
| table _time, Computer, User, Image, QueryName, QueryResults
```

**Purpose:** Find DNS queries containing "google" that do NOT resolve to legitimate google.com — revealing the typosquatted gOogle.com domain.

---

## MITRE ATT&CK Mapping

| Tactic                | Technique ID   | Technique Name                | How It Was Used                            |
|-----------------------|----------------|-------------------------------|--------------------------------------------|
| 📧 Initial Access     | T1566.001      | Spearphishing Attachment      | Invoice-themed email with .docm payload    |
| 👤 Execution          | T1204.002      | User Execution: Malicious File | User enabled macros in Word document       |
| ⏰ Persistence        | T1053.005      | Scheduled Task                | Macro created task repeating every 3 min   |
| 💻 Execution          | T1059.001      | PowerShell                    | Macro likely used PowerShell for payload   |
| 🌐 Command & Control  | T1071.004      | DNS                           | Data exfiltrated via DNS queries           |
| 🔒 Exfiltration       | T1001          | Data Obfuscation              | Encoded data hidden in DNS subdomains      |

---

## Key Takeaways

✅ Reconstructed the attack chain using **Sysmon Event IDs 1, 11 & 22**  
✅ Detected **Scheduled Task persistence** created by a malicious macro  
✅ Identified **DNS tunneling** hidden behind a **typosquatted domain** (gOogle.com)  
✅ Correlated seemingly unrelated events across process trees  
✅ Practiced **Threat Hunting**, **Windows Forensics**, **Splunk SPL**, and **MITRE ATT&CK Mapping**

> This investigation reminded me that not every DNS request is as innocent as it looks.  
> Sometimes the biggest indicator isn't malware running on the endpoint — it's a *"normal"* DNS query repeating every few minutes.

---

## Screenshots

### Attack Scenario Architecture

![Attack Scenario](Attack-Scenario-Architecture.png)

### Sysmon Event ID 1 — WINWORD.EXE Process Creation

![Sysmon Event 1 - WINWORD Execution](Sysmon-Event1-WINWORD-Execution.png)

### Sysmon Event ID 11 — Scheduled Task Persistence (Invoice)

![Sysmon Event 11 - Scheduled Task](Sysmon-Event11-ScheduledTask-Persistence.png)

### Sysmon Event ID 22 — DNS Tunneling to Typosquatted Domain

![Sysmon Event 22 - DNS Tunneling](Sysmon-Event22-DNS-Tunneling.png)

---

🛡️ *Looking forward to building more hands-on Blue Team investigations and sharpening my incident response skills.*
