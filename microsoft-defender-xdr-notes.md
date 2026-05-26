# Microsoft Defender XDR — EDR Investigation & SOC Analyst Notes

**Author:** Mohammed Ahmed  
**Category:** EDR | XDR | Endpoint Security | Incident Response  
**Format:** Study Notes & SOC Workflow Analysis  
**Date:** 2026

> **Note:** These are structured study notes compiled while learning Microsoft Defender XDR for endpoint detection and response. This documents SOC analyst workflows, investigation techniques, and detection capabilities within the Microsoft security ecosystem.

---

## What is Microsoft Defender XDR?

**Microsoft Defender XDR (Extended Detection and Response)** is Microsoft's unified security platform that correlates signals across endpoints, identities, email, and cloud applications into a single investigation and response interface at `security.microsoft.com`.

XDR solves a core SOC problem — analysts previously had to switch between multiple tools to investigate an incident. Defender XDR brings everything into one incident graph.

---

## Components of the Microsoft Defender XDR Suite

| Component | What It Protects | Key Capability |
|---|---|---|
| **Microsoft Defender for Endpoint (MDE)** | Windows, macOS, Linux, Mobile | EDR — process monitoring, behavioral detection, device isolation |
| **Microsoft Defender for Office 365 (MDO)** | Email & Collaboration (Teams, SharePoint) | Phishing detection, safe links, safe attachments |
| **Microsoft Defender for Identity (MDI)** | Active Directory, Azure AD | Identity threat detection, lateral movement |
| **Microsoft Defender for Cloud Apps (MDCA)** | SaaS Applications | Shadow IT, data exfiltration, cloud app monitoring |
| **Microsoft Sentinel** | Entire environment | Cloud-native SIEM for advanced hunting and automation |

As an L1 SOC analyst, the primary tools are **MDE** (for endpoint alerts) and the **Incident Queue** (which correlates alerts from all components).

---

## The Defender XDR Portal — SOC Analyst Interface

**URL:** `security.microsoft.com`

### Key Navigation Areas

| Section | Purpose |
|---|---|
| **Incidents & Alerts** | Primary analyst workspace — all active incidents |
| **Hunting** | Advanced KQL-based threat hunting |
| **Action Center** | Pending and completed remediation actions |
| **Threat Intelligence** | Threat actor profiles, IOC management |
| **Endpoints → Device Inventory** | All onboarded devices and their security status |
| **Email & Collaboration** | Email threat investigations |

---

## SOC L1 Analyst Workflow in Defender XDR

### Step 1: Incident Queue Review

The **Incident Queue** aggregates correlated alerts into incidents. Each incident shows:

- **Severity** (High / Medium / Low / Informational)
- **Incident name** — auto-generated description (e.g., "Multi-stage incident involving Initial access & Command and control")
- **Impacted assets** — users, devices, mailboxes affected
- **Detection source** — which Defender component detected it
- **MITRE ATT&CK categories** — tactics mapped automatically

**Triage priority:** High severity → review impacted asset count → check if active (ongoing vs historical).

### Step 2: Incident Investigation

Opening an incident reveals the **Attack Story** — an interactive graph showing:
- How the attack progressed across the kill chain
- Which processes spawned which children
- Network connections made during the attack
- Files dropped or modified

Key tabs inside an incident:

| Tab | What to Look At |
|---|---|
| **Attack story** | Full visual kill chain |
| **Alerts** | Individual alerts that make up the incident |
| **Assets** | All impacted users and devices |
| **Investigations** | Automated investigation results |
| **Evidence and response** | Files, IPs, URLs, emails identified as malicious |
| **Summary** | AI-generated incident summary |

### Step 3: Device Investigation (MDE)

For endpoint alerts, navigating to the impacted **device page** reveals:

**Device Timeline** — chronological view of all events on the device:
- Process creation events (what ran and when)
- Network connection events (what IPs were contacted)
- File creation/modification events
- Registry changes
- Logon events

**Key investigation questions:**
- Which process triggered the alert?
- What is the parent process? (legitimate or suspicious?)
- Did the process make any network connections?
- Were any files created or modified?
- Is this behavior normal for this device/user?

**Process Tree Example — Suspicious PowerShell:**
```
explorer.exe (user clicked something)
  └── cmd.exe (command prompt opened)
        └── powershell.exe -enc [base64 encoded command]  ← SUSPICIOUS
              └── net.exe user /add  ← account creation attempt
```
This pattern maps to **T1059.001 (PowerShell)** + **T1136 (Create Account)** — escalation required.

### Step 4: Evidence Analysis

The **Evidence and response** tab lists all IOCs identified in the incident:

| Evidence Type | Examples | Action |
|---|---|---|
| File | Malicious executable hash | Submit to VirusTotal, quarantine |
| IP Address | C2 server IP | Check reputation, block at firewall |
| URL | Phishing or payload URL | Block in proxy/Defender |
| Email | Phishing email | Delete from all mailboxes |
| Process | Malicious process name | Investigate parent, terminate |

### Step 5: Response Actions

MDE provides direct response actions from the portal — no need to physically access the device:

| Action | When to Use |
|---|---|
| **Isolate Device** | Active compromise — cut network access immediately |
| **Run Antivirus Scan** | Suspected malware present |
| **Collect Investigation Package** | Forensic data collection for L2/IR team |
| **Restrict App Execution** | Block all non-Microsoft-signed executables |
| **Initiate Live Response** | Remote shell for advanced investigation |

As L1: **Isolate Device** is the primary containment action. Always document before isolating.

---

## MITRE ATT&CK Integration

Defender XDR automatically maps every alert to MITRE ATT&CK tactics and techniques. This is visible in:
- The incident overview (tactic tags)
- Individual alert details (technique ID + description)
- The attack story graph (kill chain stage labels)

| Alert Type | Tactic | Technique |
|---|---|---|
| Suspicious PowerShell execution | Execution | T1059.001 |
| Mimikatz credential dumping | Credential Access | T1003 |
| Lateral movement via PsExec | Lateral Movement | T1021.002 |
| Suspicious scheduled task | Persistence | T1053.005 |
| Beaconing to known C2 | Command & Control | T1071 |
| Data staged before exfiltration | Collection | T1074 |

---

## Automated Investigation & Response (AIR)

Defender XDR can automatically investigate alerts and take remediation actions. As an analyst, you review AIR results rather than doing everything manually:

- **Automated investigation** — MDE investigates the alert, checks related entities, and determines verdict
- **Verdict options:** Malicious / Suspicious / No threats found
- **Pending actions** — some actions require analyst approval before execution (e.g., quarantine a file)
- **Action Center** — where you approve or reject pending automated actions

Key analyst task: Review AIR verdicts, approve legitimate remediation actions, override incorrect verdicts with justification.

---

## Microsoft Defender for Office 365 — Email Investigation

Directly relevant to phishing investigations (similar to LetsDefend SOC282 scenario):

**Threat Explorer** (`security.microsoft.com/threatexplorer`) allows analysts to:
- Search emails by sender, recipient, subject, URL, attachment hash
- View delivery action (Delivered / Blocked / Quarantined / Junked)
- Identify all recipients of a phishing campaign
- Soft delete malicious emails from all mailboxes simultaneously

**Email investigation flow:**
1. Alert fires for suspicious email
2. Open Threat Explorer → search sender address
3. Review email content, headers, URLs, attachments
4. Check URL reputation (Defender Safe Links verdict)
5. Check attachment hash against VirusTotal
6. If malicious → soft delete from all impacted mailboxes → document

---

## Defender XDR vs Other EDR/XDR Tools

| Feature | Microsoft Defender XDR | CrowdStrike Falcon | SentinelOne |
|---|---|---|---|
| Detection Approach | Behavioral + Signature | AI/Behavioral (cloud-native) | AI/Behavioral (Singularity) |
| Investigation Interface | Unified portal (security.microsoft.com) | Falcon Console | Singularity Console |
| Automated Response | Yes (AIR) | Yes (Fusion SOAR) | Yes (Storyline) |
| Identity Integration | Built-in (MDI + Entra ID) | Requires add-on | Requires add-on |
| Email Integration | Built-in (MDO) | Not native | Not native |
| SIEM Integration | Native Sentinel integration | Multiple SIEM support | Multiple SIEM support |
| Common in India | Large enterprise, Deloitte/Big4 | Banking, BFSI | IT, Mid-market |

Microsoft Defender XDR's biggest advantage in an enterprise SOC is the **native integration** across endpoint, email, identity, and cloud — reducing context switching during investigations.

---

## Key Takeaways

- XDR's power is correlation — a phishing email, endpoint execution, and C2 communication are linked into one incident automatically, something traditional SIEM requires manual correlation for
- The process tree / attack story view significantly reduces investigation time compared to manually querying raw logs
- Automated Investigation (AIR) handles routine alert investigation, allowing L1 analysts to focus on review and escalation rather than raw log analysis
- MITRE ATT&CK tags on every alert give immediate threat context — an analyst knows the intent of the attack before finishing the investigation
- Device isolation can be done directly from the portal in seconds — critical for containing active threats before they spread laterally

---

## Resources Used

- Microsoft Learn: SC-200 — Mitigate threats using Microsoft Defender XDR
- Microsoft Learn: SC-200 — Mitigate threats using Microsoft Defender for Endpoint
- MITRE ATT&CK Framework — `attack.mitre.org`
- Microsoft Security Blog — `microsoft.com/security/blog`

---

*These notes reflect structured study of Microsoft Defender XDR capabilities and SOC analyst workflows as part of preparing for enterprise endpoint detection and response roles.*
