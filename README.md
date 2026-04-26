# Sentinel Detection Engine

> **Enterprise Detection-as-Code (DaC) framework for Microsoft Sentinel.**
> Replace manual portal configurations with a GitOps pipeline that keeps every detection rule auditable, tested, and resilient against unauthorized changes.

---

## Table of contents

- [Overview](#overview)
- [How it works](#how-it-works)
- [Technical stack](#technical-stack)
- [Repository structure](#repository-structure)
- [Detection coverage](#detection-coverage)
- [Deployment guide](#deployment-guide)
- [Validation & testing](#validation--testing)
- [Governance model](#governance-model)
---

## Overview

This framework implements a full detection lifecycle pipeline — from authoring KQL analytics rules to proving they fire in production. Every detection rule is stored as a versioned ARM/JSON template, automatically validated against schema requirements, exercised by a red-team simulation script, and deployed to Microsoft Sentinel only after all checks pass.

**The problem it solves:** Detection rules that live only in the Sentinel portal cannot be peer reviewed, cannot be rolled back, and leave no audit trail when modified. This framework treats your defensive logic the same way engineering teams treat application code — with version control, automated testing, and mandatory review gates.

---

## How it works

```
Engineer opens PR
       │
       ▼
Peer review gate ──── (second engineer approves)
       │
       ▼
┌─────────────────────────────────────────┐
│         GitHub Actions CI pipeline       │
│                                         │
│  Gate 1 — ARM/JSON schema validation    │
│       ↓                                 │
│  Gate 2 — Attack simulation             │
│           simulate_attack.ps1           │
│       ↓                                 │
│  Gate 3 — Alert verification            │
│           EventID 4697 / 4625 confirmed │
└─────────────────────────────────────────┘
       │  all gates pass
       ▼
Sentinel Content Management syncs ARM templates
       │
       ▼
Detection rule active in SOC analyst queue
```

If any gate fails, the pull request is blocked and the engineer is notified. Nothing reaches production without passing all three checks.

---

## Technical stack

| Component | Technology |
| :--- | :--- |
| SIEM / SOAR | Microsoft Sentinel |
| Query language | Kusto Query Language (KQL) |
| Rule format | Azure Resource Manager (ARM / JSON) |
| CI/CD | GitHub Actions + Sentinel Repositories |
| Testing | PowerShell (`simulate_attack.ps1`) |
| Governance | GitHub pull requests + branch protection |

---

## Repository structure

```
Sentinel-Detection-Engine/
├── /Detections              # Production analytics rules (ARM/JSON templates)
│   ├── rdp-hijacking.json
│   ├── new-service-creation.json
│   └── brute-force-success.json
└── /Validation              # Attack simulation scripts (unit tests for detections)
    └── simulate_attack.ps1
```

**`/Detections`** — Each file is a fully self-contained ARM template defining a Sentinel Analytics Rule: the KQL query, scheduling parameters, severity, entity mapping, and MITRE ATT&CK metadata. These are the files Sentinel's Content Management integration deploys directly.

**`/Validation`** — PowerShell scripts that execute real attacker techniques on a designated test endpoint. The CI pipeline runs these scripts and then queries Log Analytics to confirm the expected EventIDs appeared. If the event is missing, the telemetry pipeline is broken or the detection logic is wrong — either way, deployment is blocked until it's resolved.

> **Rule:** Every file in `/Detections` must have a corresponding simulation in `/Validation`. No simulation = no deployment.

---

## Detection coverage

| Rule name | MITRE technique | Tactic | Severity | EventID |
| :--- | :--- | :--- | :--- | :--- |
| RDP hijacking | T1563.002 | Lateral Movement | Medium | — |
| New service creation | T1543.003 | Persistence | High | 4697 |
| Brute force success | T1110 | Credential Access | Critical | 4625 |

### Detection notes

**RDP hijacking (T1563.002)** detects adversaries using `tscon.exe` to take over an existing RDP session under SYSTEM context — a technique that requires no credentials and leaves no password in the log. Medium severity reflects the pre-existing elevated access required.

**New service creation (T1543.003)** flags services installed with suspicious binary paths (e.g., `cmd.exe`, `powershell.exe`, or paths outside `%SystemRoot%\System32`). Adversaries use this to survive reboots. High severity because persistence means the attacker intends to stay.

**Brute force success (T1110)** triggers on five or more EventID 4625 failures within a ten-minute window from the same source. Critical severity — credential access is the pivot point for everything that follows in the kill chain.

---

## Deployment guide

### Prerequisites

- Microsoft Sentinel workspace with Log Analytics
- Azure Monitor Agent (AMA) deployed to Windows endpoints
- GitHub Actions enabled on this repository
- Service principal with `Microsoft Sentinel Contributor` role

### Step 1 — Connect the repository to Sentinel

In the Azure portal, navigate to:

```
Microsoft Sentinel → Content Management → Repositories → Add
```

Authenticate with GitHub, select this repository, and set the branch to `main`. Sentinel will watch the `/Detections` path for ARM template changes.

### Step 2 — Add GitHub Actions secrets

In repository **Settings → Secrets and Variables → Actions**, add:

| Secret | Description |
| :--- | :--- |
| `AZURE_CLIENT_ID` | Service principal app ID |
| `AZURE_CLIENT_SECRET` | Service principal secret |
| `AZURE_TENANT_ID` | Azure AD tenant ID |
| `AZURE_SUBSCRIPTION_ID` | Target subscription ID |
| `LAW_WORKSPACE_ID` | Log Analytics workspace ID |

### Step 3 — Submit detections via pull request

1. Create a feature branch
2. Add or modify a detection template in `/Detections`
3. Add or update the corresponding simulation in `/Validation`
4. Open a pull request — GitHub Actions triggers automatically
5. All three CI gates must pass before the PR can be merged

### Step 4 — Verify end-to-end

After merge, navigate to:

```
Microsoft Sentinel → Analytics → Active Rules
```

Your rule should appear with a green status indicator. Run `simulate_attack.ps1` manually and confirm an alert appears in the Incident queue within the rule's configured query interval.

---

## Validation & testing

The `/Validation/simulate_attack.ps1` script executes two attack simulations:

### Simulation 1 — T1543.003 Persistence via new service creation

```powershell
# Creates a service with a suspicious binary path to simulate persistence
New-Service -Name "LegitMicrosoftUpdate" `
            -BinaryPathName "C:\Windows\System32\cmd.exe" `
            -Description "Persistence Test"
```

**Expected result:** EventID `4697` appears in the Windows Security log and is ingested into the `SecurityEvent` table in Log Analytics within 60 seconds. The analytics rule triggers and generates a High severity alert in Sentinel.

### Simulation 2 — T1110 Brute force (failed logon attempts)

```powershell
# Generates six sequential failed authentication events
$Account = "FakeAdmin"
for ($i = 1; $i -le 6; $i++) {
    try { net use \\127.0.0.1 /user:$Account "WrongPassword$i" } catch {}
}
```

**Expected result:** Six EventID `4625` entries appear in the Windows Security log. The analytics rule counts failures within the rolling time window, crosses the threshold, and generates a Critical severity alert in Sentinel.

### Confirming the pipeline is healthy

After running simulations, check:

```
Microsoft Sentinel → Logs
```

```kql
SecurityEvent
| where EventID in (4697, 4625)
| where TimeGenerated > ago(15m)
| project TimeGenerated, EventID, Computer, SubjectUserName, ServiceName
| order by TimeGenerated desc
```

If events are present, the full telemetry pipeline — endpoint → AMA agent → Log Analytics → Sentinel — is operating correctly.

---

## Governance model

| Control | Implementation |
| :--- | :--- |
| Change history | Every detection modification tracked as a Git commit |
| Peer review | Pull requests require at least one approving review |
| Automated testing | Three-gate CI pipeline blocks deployment on failure |
| Rollback | Revert a commit and the pipeline redeploys the previous version |
| MITRE mapping | Technique and tactic tags required in every ARM template |
| Audit evidence | GitHub PR history is the change management record |

This directly satisfies common compliance requirements for documented and authorized changes to security controls (SOC 2, NIST 800-53, ISO 27001).

---
