# 🛡️ Sentinel Detection Engine
### Enterprise Detection-as-Code (DaC) Framework for Microsoft Sentinel

> **What this project does:**
> Write security detection rules as code, automatically prove they work, and deploy them to Microsoft Sentinel — all without touching the portal manually.

[![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-v14-red)](https://attack.mitre.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

---

## 🎯 The Problem This Solves

Most security teams manage detection rules by clicking around in their SIEM portal. This creates three serious problems:

| Problem | Real-world impact |
|---|---|
| **No audit trail** | Anyone can modify a detection rule silently — no record of who changed what |
| **No testing** | Rules are deployed and assumed to work. Most teams never verify they actually fire |
| **No rollback** | A bad rule floods the SOC queue at 2am — and you can't easily undo it |

**This framework solves all three.** Detection rules live in Git. Every change is peer reviewed. Every rule is automatically tested before deployment. Broken pipelines get caught before they reach production.

---

## ⚙️ How It Works

The full flow from writing a detection rule to it going live in Sentinel:

```
┌─────────────────────────────────────────────────────────────────────┐
│                                                                     │
│   1. You write a detection rule (JSON) + a simulation script (PS1) │
│                           │                                         │
│                           ▼                                         │
│   2. You open a Pull Request on GitHub                              │
│                           │                                         │
│                           ▼                                         │
│   3. A second engineer reviews and approves                         │
│      (nobody deploys detection rules alone)                         │
│                           │                                         │
│                           ▼                                         │
│   ┌───────────────────────────────────────────────────────────┐    │
│   │              GitHub Actions — 3 Automated Gates            │    │
│   │                                                            │    │
│   │  ✅ GATE 1 — Schema Validation                            │    │
│   │     Is the JSON correctly formatted?                       │    │
│   │     Are all required fields present? (MITRE, severity...)  │    │
│   │                        │                                   │    │
│   │                        ▼                                   │    │
│   │  ✅ GATE 2 — Attack Simulation                            │    │
│   │     simulate_attack.ps1 runs on isolated test VM           │    │
│   │     Generates real Windows events (4697, 4625)             │    │
│   │                        │                                   │    │
│   │                        ▼                                   │    │
│   │  ✅ GATE 3 — Alert Verification                           │    │
│   │     Queries Log Analytics to confirm events arrived        │    │
│   │     Retries every 60s for up to 10 minutes                 │    │
│   └───────────────────────────────────────────────────────────┘    │
│                           │  all 3 gates pass                       │
│                           ▼                                         │
│   4. Sentinel syncs ARM templates → Detection rule goes live        │
│                           │                                         │
│                           ▼                                         │
│   5. Alert fires in SOC queue when a real attack matches the rule   │
│                                                                     │
│   ❌ If ANY gate fails → PR is blocked, nothing deploys             │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 📁 Repository Structure

```
Sentinel-Detection-Engine/
│
├── .github/
│   └── workflows/
│       └── dac-pipeline.yml        ← The CI/CD pipeline (all 3 gates live here)
│
├── Detections/                     ← Production detection rules (ARM/JSON)
│   ├── rdp-hijacking.json          ← T1563.002 Lateral Movement   [Medium]
│   ├── new-service-creation.json   ← T1543.003 Persistence        [High]
│   └── brute-force-success.json    ← T1110    Credential Access   [Critical]
│
├── Validation/                     ← Attack simulation scripts
│   └── simulate_attack.ps1         ← Fires T1543.003 + T1110 on test endpoint
│
├── Templates/                      ← Starting points for new rules
│   └── detection-skeleton.json     ← Fully commented template — copy this
│
└── README.md                       ← You are here
```

> **The golden rule:** Every file in `/Detections` must have a corresponding simulation in `/Validation`. If you can't simulate it and prove it fires, it doesn't ship.

---

## 🛠️ Technical Stack

| Component | Technology | Purpose |
|---|---|---|
| SIEM / SOAR | Microsoft Sentinel | Runs detection rules, generates alerts |
| Query language | KQL (Kusto Query Language) | Searches log data for attack patterns |
| Rule format | ARM / JSON templates | Deploys detection rules as Azure resources |
| CI/CD | GitHub Actions | Automates validation and deployment |
| Testing | PowerShell | Simulates real attack techniques |
| Governance | GitHub pull requests | Enforces peer review and audit trail |

---

## 🗺️ Detection Coverage

| Rule | MITRE ID | Tactic | Severity | EventID |
|---|---|---|---|---|
| [RDP Hijacking](Detections/rdp-hijacking.json) | T1563.002 | Lateral Movement | 🟡 Medium | 4688 |
| [New Service Creation](Detections/new-service-creation.json) | T1543.003 | Persistence | 🔴 High | 4697 |
| [Brute Force](Detections/brute-force-success.json) | T1110 | Credential Access | 🚨 Critical | 4625 |

<details>
<summary><b>What does each detection catch?</b></summary>

### 🟡 RDP Hijacking — T1563.002 — Medium
An attacker with SYSTEM privileges uses `tscon.exe` to take over another user's active RDP session — without their password. This technique is stealthy because it uses a legitimate Windows tool and leaves no password events in the log. Medium severity because it requires pre-existing elevated access.

**Triage tip:** When this fires, check what the attacker did immediately after taking the session. Look for subsequent process creation events from the hijacked session context.

---

### 🔴 New Service Creation — T1543.003 — High
An attacker installs a Windows service pointing at a malicious executable (often disguised with a legitimate-sounding name like `LegitMicrosoftUpdate`). Services survive reboots — this is how attackers ensure their malware restarts even if the machine is rebooted. High severity because persistence means the attacker intends to stay.

**The tell:** Legitimate Windows services run `svchost.exe`. Any service pointing at `cmd.exe`, `powershell.exe`, or a temp/user directory is suspicious.

**Triage tip:** Check `ServiceFileName` in the alert. Then check who created it (`SubjectUserName`) and what that account was doing in the 15 minutes before.

---

### 🚨 Brute Force — T1110 — Critical
Five or more failed logon attempts (EventID 4625) from the same IP within a 10-minute window. Critical because credential access is the pivot point in most attack chains. If this fires, the first thing to check is whether any of the failures were followed by a successful logon (EventID 4624) from the same source — that means the attacker found a valid password.

**Triage KQL — run this immediately when the alert fires:**
```kql
let AttackingIP = "PASTE_IP_FROM_ALERT_HERE";
SecurityEvent
| where TimeGenerated > ago(30m)
| where EventID in (4625, 4624)
| where IpAddress == AttackingIP
| project TimeGenerated, EventID, TargetUserName, IpAddress,
          LogonType, AuthenticationPackageName
| order by TimeGenerated asc
// A 4624 after a run of 4625s = successful brute force → escalate immediately
```

</details>

---

## ✅ Prerequisites

Work through this checklist before starting setup. Everything must be checked before you proceed.

### Azure
- [ ] Azure subscription (free trial works — see [No Azure Access?](#-no-azure-access-practice-here))
- [ ] Microsoft Sentinel workspace deployed
- [ ] Log Analytics workspace connected to Sentinel
- [ ] Azure CLI installed: `az --version` should return a version number
  - Install: https://docs.microsoft.com/cli/azure/install-azure-cli

### Test endpoint (read carefully — this is the most important prerequisite)
- [ ] A **dedicated Windows VM** for running attack simulations
- [ ] This VM must be **completely isolated** — no connection to production networks or corporate domains
- [ ] Azure Monitor Agent (AMA) installed on the test VM and forwarding to your Log Analytics workspace
- [ ] Windows Security event collection configured (EventIDs 4625, 4697, and 4688 must forward)

> ⛔ **Critical:** Never run `simulate_attack.ps1` on a production machine, a domain-joined corporate machine, or any machine you care about. The script has a safety guard that will block it, but the isolation requirement is your first line of defence.

### GitHub
- [ ] GitHub account with access to this repository
- [ ] Git installed: `git --version` should return a version number
- [ ] Basic Git knowledge: branch, commit, push, pull request

### Local machine
- [ ] PowerShell 7+: `pwsh --version`
- [ ] Code editor (VS Code recommended: https://code.visualstudio.com)

---

## 🚀 Setup Guide

### Step 1 — Fork and clone the repository

```bash
# Fork the repository on GitHub first (click Fork button top-right)
# Then clone YOUR fork:
git clone https://github.com/YOUR-USERNAME/Sentinel-Detection-Engine.git
cd Sentinel-Detection-Engine
```

---

### Step 2 — Create an Azure service principal

A service principal is a dedicated account that GitHub Actions uses to authenticate to Azure. Think of it as a robot account with only the permissions it needs.

```bash
# Log in to Azure
az login

# Find your subscription ID
az account show --query id -o tsv

# Create the service principal
# Replace YOUR_SUBSCRIPTION_ID and YOUR_RESOURCE_GROUP with your actual values
az ad sp create-for-rbac \
  --name "sentinel-dac-pipeline" \
  --role "Microsoft Sentinel Contributor" \
  --scopes "/subscriptions/YOUR_SUBSCRIPTION_ID/resourceGroups/YOUR_RESOURCE_GROUP" \
  --sdk-auth
```

The output looks like this — **copy it, you need it in the next step:**

```json
{
  "clientId":       "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
  "clientSecret":   "your-secret-value-here",
  "subscriptionId": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
  "tenantId":       "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
}
```

> ⚠️ This is the only time you'll see the `clientSecret`. Save it now.

---

### Step 3 — Add secrets to GitHub

In your repository on GitHub: **Settings → Secrets and variables → Actions → New repository secret**

Add each of the following secrets:

| Secret name | Where to get it |
|---|---|
| `AZURE_CLIENT_ID` | `clientId` from Step 2 output |
| `AZURE_CLIENT_SECRET` | `clientSecret` from Step 2 output |
| `AZURE_TENANT_ID` | `tenantId` from Step 2 output |
| `AZURE_SUBSCRIPTION_ID` | `subscriptionId` from Step 2 output |
| `LAW_WORKSPACE_ID` | Azure Portal → Log Analytics workspace → Overview → **Workspace ID** |
| `TEST_ENDPOINT_NAME` | The name of your isolated test VM |
| `TEST_RESOURCE_GROUP` | The resource group containing your test VM |
| `SENTINEL_RESOURCE_GROUP` | The resource group containing your Sentinel workspace |
| `SENTINEL_WORKSPACE_NAME` | Your Sentinel workspace name |
| `SENTINEL_SOURCECONTROL_ID` | See Step 4 below |

> **Why secrets?** Putting credentials directly in code files is a serious security risk — anyone with repo access can read them. GitHub Secrets encrypts these values and only exposes them to the pipeline during a run. They never appear in logs.

---

### Step 4 — Connect Sentinel to this repository

1. In the Azure Portal, go to **Microsoft Sentinel** → your workspace
2. Click **Content management** → **Repositories**
3. Click **+ Add**
4. Authenticate with GitHub when prompted
5. Select your forked repository
6. Set branch to `main`
7. Set content path to `/Detections`
8. Click **Save**

After saving, find the connection ID:
- In the Repositories list, click your connection
- The URL in your browser contains the source control ID:
  `...sourcecontrols/THIS-IS-YOUR-ID/...`
- Copy this ID and add it as the `SENTINEL_SOURCECONTROL_ID` secret

---

### Step 5 — Set the environment guard on your test VM

This is a one-time step on your isolated test VM. It's what allows the simulation script to run there (and only there).

```powershell
# Run this in PowerShell as Administrator on the test VM
# This sets the variable permanently so it persists across reboots
[System.Environment]::SetEnvironmentVariable("DAC_TEST_ENDPOINT", "true", "Machine")
```

---

### Step 6 — Enable branch protection

This is the governance control that makes the framework actually enforceable.

In GitHub: **Settings → Branches → Add branch protection rule**

- Branch name pattern: `main`
- ✅ Require a pull request before merging
- ✅ Require approvals → set to `1`
- ✅ Require status checks to pass before merging
  - Add: `Gate 1 — Schema Validation`
  - Add: `Gate 2 — Attack Simulation`
  - Add: `Gate 3 — Alert Verification`
- ✅ Do not allow bypassing the above settings

Click **Save changes**.

> Without this step, anyone with write access can push directly to `main` and skip every gate. This is the control that makes the audit trail meaningful.

---

### Step 7 — Verify everything works

Push a small change (like a whitespace edit to this README) to a branch and open a pull request. You should see all three gates appear and run in the **Checks** tab of the PR.

✅ Three green checkmarks = your pipeline is working end-to-end.

---

## ✍️ Writing a New Detection Rule

### Step 1 — Start from the skeleton

```bash
cp Templates/detection-skeleton.json Detections/your-detection-name.json
```

### Step 2 — Test your KQL in Sentinel Logs first

**Do not write the ARM template until your KQL query works.** In Microsoft Sentinel:

1. Click **Logs** in the left menu
2. Paste your query and click **Run**
3. Confirm it returns results
4. Note the exact column names — you'll need them for entity mappings

### Step 3 — Fill in the skeleton

Open your new file and replace every `REPLACE` value. The skeleton has a comment (`INSTRUCTION_*`) next to every field explaining what goes there.

**JSON syntax notes for KQL queries:**
- Newlines become `\n`
- Single backslash `\` becomes `\\`
- Double backslash `\\` becomes `\\\\`

Example — this KQL:
```kql
SecurityEvent
| where EventID == 4697
| where ServiceFileName !startswith "C:\Windows"
```

Becomes this in JSON:
```json
"query": "SecurityEvent\n| where EventID == 4697\n| where ServiceFileName !startswith 'C:\\\\Windows'"
```

> Note: single quotes are used inside the JSON string to avoid conflicting with the outer double quotes.

### Step 4 — Validate JSON syntax locally

```bash
# Catch syntax errors before pushing
cat Detections/your-detection.json | jq .
# If it prints formatted JSON: good. If it prints an error: fix it first.
```

### Step 5 — Add a simulation for your detection

Add a function to `Validation/simulate_attack.ps1` that generates the events your detection looks for. Use the existing functions as examples.

---

## 🔬 Running the Validation Script

> **Read every word of this section before running anything.**

### The checklist

Confirm all of these before executing the script. If any item is false, stop.

- [ ] I am on the **isolated test VM** — not a production or corporate machine
- [ ] The test VM has `DAC_TEST_ENDPOINT=true` set as a system environment variable
- [ ] I am running PowerShell **as Administrator**
- [ ] I understand the script creates a Windows service that persists until cleanup is run

### Running the script

```powershell
# On the isolated test VM, open PowerShell as Administrator

# Confirm the environment guard is set
echo $env:DAC_TEST_ENDPOINT
# Should output: true
# If it's blank, run: $env:DAC_TEST_ENDPOINT = "true"

# Run the full simulation
.\Validation\simulate_attack.ps1

# Wait 2-5 minutes, then verify in Sentinel → Logs:
# SecurityEvent
# | where EventID in (4697, 4625)
# | where TimeGenerated > ago(15m)
# | project TimeGenerated, EventID, Computer, SubjectUserName, ServiceName
# | order by TimeGenerated desc

# ALWAYS run cleanup when done
.\Validation\simulate_attack.ps1 -Cleanup
```

### What the script does, step by step

**Simulation 1 — T1543.003 (New Service Creation):**
Creates a Windows service named `LegitMicrosoftUpdate` pointing at `cmd.exe`. This generates EventID 4697 in the Windows Security log. The AMA agent forwards it to Log Analytics. The `New Service Creation` detection rule matches it and fires an alert in Sentinel.

**Simulation 2 — T1110 (Brute Force):**
Makes 6 failed authentication attempts against a fake account (`FakeAdmin_DACTest`). Each generates EventID 4625. When 5+ failures appear from the same source within 10 minutes, the `Brute Force` detection rule fires.

**Cleanup:**
The `-Cleanup` flag removes the `LegitMicrosoftUpdate` service. The CI pipeline runs cleanup automatically via an `if: always()` step — meaning cleanup happens even if the simulation fails.

---

## 📬 Submitting a Pull Request

### Step 1 — Create a branch

```bash
git checkout main
git pull origin main

# Branch name format: detection/technique-description
git checkout -b detection/t1543-new-service-creation
```

### Step 2 — Commit your files

```bash
git add Detections/your-detection.json
git add Validation/simulate_attack.ps1

git commit -m "Add T1543.003 New Service Creation detection

- KQL filters EventID 4697 for non-standard binary paths
- Entity mapping: Host (Computer), Account (SubjectUserName)
- Simulation verified on isolated test endpoint
- Cleanup tested and confirmed working
- MITRE: Persistence > T1543.003"

git push origin detection/t1543-new-service-creation
```

### Step 3 — Open the pull request

On GitHub, click the **Compare & pull request** button. Use this template for the description:

```markdown
## What this detection catches
[One paragraph: what attack technique, what the attacker is trying to do, why it matters]

## MITRE mapping
- Tactic: [e.g. Persistence]
- Technique: [e.g. T1543.003 — Create or Modify System Process: Windows Service]

## Testing evidence
- [ ] KQL tested in Sentinel Logs — returns expected results
- [ ] simulate_attack.ps1 run on isolated test endpoint
- [ ] EventID [INSERT ID] confirmed in Log Analytics within 5 minutes
- [ ] Cleanup (-Cleanup) run and confirmed working

## False positive considerations
[What legitimate activity might trigger this rule? How does the KQL handle it?]

## Severity justification
[Why did you choose this severity level?]
```

### Step 4 — Monitor the CI gates

Click the **Checks** tab in the PR. All three gates run automatically. If a gate fails, click into it — the log output tells you exactly what went wrong. Fix the issue, push a new commit, and the gates re-run.

---

## 🔒 Understanding the CI Gates

### Gate 1 — Schema Validation

**What it checks:** Every field required by the Sentinel ARM schema is present and has a valid value.

| Field | Allowed values |
|---|---|
| `severity` | `Informational`, `Low`, `Medium`, `High`, `Critical` |
| `status` | `Observation`, `Active`, `Deprecated` |
| `tactics` | Valid MITRE ATT&CK tactic names |
| `techniques` | Valid MITRE technique IDs |
| `entityMappings` | At least one entity with valid type |

**Most common failure:** Column name in `entityMappings` doesn't match what the KQL query actually outputs. Test your query in Sentinel Logs first and check column names carefully.

---

### Gate 2 — Attack Simulation

**What it checks:** `simulate_attack.ps1` executes on the CI test endpoint without errors. The script must exit with code 0. Cleanup runs automatically afterward regardless of outcome.

**Most common failure:** PowerShell syntax error in the simulation script. Test locally on your isolated VM first.

---

### Gate 3 — Alert Verification

**What it checks:** Queries Log Analytics for EventID 4697 and 4625 after the simulation. Retries every 60 seconds for up to 10 minutes to account for ingestion latency.

**Most common failure:** AMA agent on the test endpoint is not forwarding events. Verify with:

```kql
Heartbeat
| where Computer == "YOUR_TEST_VM_NAME"
| where TimeGenerated > ago(1h)
| order by TimeGenerated desc
```

If the heartbeat isn't showing up, the agent needs attention — not the detection rule.

---

## 🆓 No Azure Access? Practice Here

You don't need Azure access to learn the core skills in this framework. Here are three free options ranked from easiest to most complete.

### Option 1 — Practice KQL right now (no account needed)

Microsoft provides a free demo Sentinel environment pre-loaded with real security data. No account, no credit card, no installation required.

```
Go to: https://aka.ms/lademo
```

Practice the exact queries used in this framework:

```kql
-- Find failed logons (T1110)
SecurityEvent
| where EventID == 4625
| where TimeGenerated > ago(24h)
| summarize FailureCount = count() by Account, IpAddress
| where FailureCount > 5
| order by FailureCount desc
```

```kql
-- Find service installations (T1543.003)
SecurityEvent
| where EventID == 4697
| project TimeGenerated, Computer, ServiceName, ServiceFileName, SubjectUserName
| order by TimeGenerated desc
```

---

### Option 2 — Free Azure trial (recommended for full pipeline practice)

Microsoft gives you **90 days + $200 in credits** with a new Azure account. Enough to run this entire framework end-to-end.

```
Go to: https://azure.microsoft.com/free
Requirements: Microsoft account + credit card for identity verification only
```

Once you have the trial account, deploy the free Sentinel Training Lab:

```
Go to: https://github.com/Azure/Azure-Sentinel/tree/master/Solutions/Training/Azure-Sentinel-Training-Lab
```

This gives you a fully configured Sentinel workspace with sample data in about 20 minutes.

---

### Option 3 — Free Windows test VM (for simulation practice)

Microsoft distributes free Windows 11 developer VMs specifically for this kind of practice. Run locally in VirtualBox (free).

```
Go to: https://developer.microsoft.com/windows/downloads/virtual-machines
```

This gives you a legitimate isolated Windows machine to run `simulate_attack.ps1` against — completely on your laptop, no network exposure, no Azure account needed.

---

## 🔧 Troubleshooting

<details>
<summary><b>My KQL works in Sentinel Logs but Gate 1 fails saying the query is invalid</b></summary>

JSON requires special characters to be escaped. Inside a JSON string:
- Newlines → `\n`
- Single backslash `\` → `\\`
- Double backslash `\\` → `\\\\`

Your KQL:
```
SecurityEvent
| where ServiceFileName !startswith "C:\Windows"
```

In JSON (use single quotes inside to avoid escaping double quotes):
```json
"query": "SecurityEvent\n| where ServiceFileName !startswith 'C:\\\\Windows'"
```

</details>

<details>
<summary><b>Gate 3 fails with "EventID not found" but I can see the events in Sentinel</b></summary>

The pipeline is querying a different Log Analytics workspace than your test endpoint is forwarding to. Check that `LAW_WORKSPACE_ID` in GitHub Secrets matches the Workspace ID of the workspace receiving your test VM's events.

Verify which workspace has the events:
```kql
SecurityEvent
| where TimeGenerated > ago(30m)
| where Computer == "YOUR_TEST_VM_NAME"
| summarize count() by EventID
```
Run this in each workspace you have. The one that returns results is the correct one.

</details>

<details>
<summary><b>The simulation script says "SAFETY BLOCK" and won't run</b></summary>

The environment guard is working correctly — this is the right behaviour on non-test machines.

On your isolated test VM:
```powershell
# For the current session only:
$env:DAC_TEST_ENDPOINT = "true"

# Or permanently (requires admin, survives reboots):
[System.Environment]::SetEnvironmentVariable("DAC_TEST_ENDPOINT", "true", "Machine")
```

If you are not on the designated test VM, do not attempt to bypass this check.

</details>

<details>
<summary><b>I merged a PR but the rule isn't showing in Sentinel Analytics</b></summary>

1. Go to Sentinel → **Content management** → **Repositories**
2. Click your repository connection
3. Look for any error messages in the sync log
4. Common causes:
   - ARM template file is in a subdirectory (must be directly in `/Detections/`)
   - JSON is malformed: `cat Detections/yourfile.json | jq .`
   - Service principal doesn't have sufficient permissions

</details>

<details>
<summary><b>I accidentally ran the simulation on the wrong machine</b></summary>

1. Don't panic.
2. Immediately run cleanup: `.\Validation\simulate_attack.ps1 -Cleanup`
3. Confirm the service is gone: `Get-Service -Name "LegitMicrosoftUpdate"`
4. Check the Security event log for unexpected activity alongside the simulation events
5. Notify your team lead — they need to know so no alerts are miscorrelated

</details>

---

## 📖 Glossary

| Term | Plain English explanation |
|---|---|
| **AMA** | Azure Monitor Agent — software on endpoints that forwards Windows event logs to Log Analytics |
| **ARM template** | A JSON file that tells Azure what resources to create — in this framework, each one defines a Sentinel detection rule |
| **DaC** | Detection-as-Code — managing security detection rules as versioned, tested code rather than manual portal configurations |
| **EventID 4624** | Windows log entry: a user successfully logged on |
| **EventID 4625** | Windows log entry: a logon attempt failed |
| **EventID 4688** | Windows log entry: a new process was created |
| **EventID 4697** | Windows log entry: a service was installed on the system |
| **Gate** | An automated check in the CI pipeline — all three must pass before anything deploys |
| **GitHub Actions** | GitHub's built-in automation system — runs your pipeline whenever code changes |
| **KQL** | Kusto Query Language — the language used to search data in Microsoft Sentinel |
| **Log Analytics** | The Azure database where Sentinel stores all ingested log data |
| **MITRE ATT&CK** | A public catalogue of real-world attacker techniques, used to tag and organize detection rules |
| **PR / Pull Request** | A GitHub mechanism for proposing code changes — requires review before merging |
| **Service principal** | A dedicated Azure identity for automation — like a robot user account with specific permissions |
| **SIEM** | Security Information and Event Management — software that collects and analyses security logs |
| **SOAR** | Security Orchestration, Automation and Response — automation for security incident workflows |
| **Tactic** | In MITRE ATT&CK, the high-level goal (e.g., Persistence, Lateral Movement) |
| **Technique** | In MITRE ATT&CK, the specific method used to achieve a tactic (e.g., T1543.003) |

---

## 🤝 Contributing

1. Read this README fully before writing anything
2. Branch from `main`: `git checkout -b detection/your-detection-name`
3. Write your detection JSON using `Templates/detection-skeleton.json` as the base
4. Test your KQL in Sentinel Logs before putting it in the JSON
5. Add or update the simulation in `Validation/simulate_attack.ps1`
6. Test the simulation locally on the isolated test VM and run cleanup
7. Open a pull request using the PR template
8. All three CI gates must pass — the PR stays blocked until they do

---
Created by Mark Mooli
