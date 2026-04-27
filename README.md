# Sentinel Detection Engine
### Enterprise Detection-as-Code (DaC) Framework — Microsoft Sentinel

[![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-v14-red)](https://attack.mitre.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

A GitOps pipeline that manages the full lifecycle of Microsoft Sentinel analytics rules. Detection logic lives in Git — versioned, peer reviewed, red-team validated, and deployed via ARM. The portal is read-only.

> Built by [Mark Mooli](https://github.com/msmooli)

---

## The Problem This Solves

Most security teams manage detection rules directly in their SIEM portal. This creates three compounding problems:

| Problem | Real-world consequence |
|---|---|
| **No audit trail** | Rules get silently modified — no record of who changed what or why |
| **No testing** | Rules are deployed and assumed to work. Most teams never verify they actually fire |
| **No rollback** | A noisy rule floods the SOC queue at 2am and there's no clean way to undo it |

This framework treats detection rules the same way software teams treat application code — version controlled, peer reviewed, automatically tested, and deployed through a pipeline. Every rule is proven to fire before it reaches production. Every change has an author, a diff, and a reviewer.

---

## How It Works

```
┌──────────────────────────────────────────────────────────────────────┐
│  1. Write detection rule (JSON) + simulation function (PowerShell)   │
│                              │                                        │
│                              ▼                                        │
│  2. Open a Pull Request — second engineer reviews and approves        │
│                              │                                        │
│                              ▼                                        │
│  ┌────────────────────────────────────────────────────────────────┐  │
│  │                 GitHub Actions — 3 Gates                        │  │
│  │                                                                 │  │
│  │  Gate 1 — Schema Validation                                     │  │
│  │  Checks JSON structure, required fields, MITRE tags,            │  │
│  │  severity enum, entity mappings, API version                    │  │
│  │                         │                                       │  │
│  │                         ▼                                       │  │
│  │  Gate 2 — Attack Simulation                                     │  │
│  │  simulate_attack.ps1 runs on isolated test VM via               │  │
│  │  Azure Run Command. Cleanup runs regardless of outcome.         │  │
│  │                         │                                       │  │
│  │                         ▼                                       │  │
│  │  Gate 3 — Alert Verification                                    │  │
│  │  Polls Log Analytics for expected EventIDs.                     │  │
│  │  Retries every 60s for up to 10 minutes.                        │  │
│  └────────────────────────────────────────────────────────────────┘  │
│                              │  all gates pass                        │
│                              ▼                                        │
│  3. Merge to main → Sentinel Content Management syncs ARM templates  │
│                              │                                        │
│                              ▼                                        │
│  4. Detection rule is live — alert fires when a real attack matches  │
│                                                                       │
│  ❌ Any gate fails → PR blocked. Nothing deploys.                    │
└──────────────────────────────────────────────────────────────────────┘
```

---

## Repository Structure

```
Sentinel-Detection-Engine/
│
├── .github/
│   └── workflows/
│       └── dac-pipeline.yml        ← CI/CD pipeline (all 4 jobs defined here)
│
├── Detections/                     ← Production ARM/JSON analytics rule templates
│   ├── rdp-hijacking.json          ← T1563.002  Lateral Movement   Medium
│   ├── new-service-creation.json   ← T1543.003  Persistence        High
│   └── brute-force-success.json    ← T1110      Credential Access  Critical
│
├── Validation/
│   └── simulate_attack.ps1         ← Red-team simulation script
│
├── Templates/
│   └── detection-skeleton.json     ← Annotated starting point for new rules
│
└── README.md
```

**Non-negotiable rule:** Every file added to `/Detections` must have a corresponding simulation function in `Validation/simulate_attack.ps1`. No simulation = no merge.

---

## Technical Stack

| Component | Technology |
|---|---|
| SIEM / SOAR | Microsoft Sentinel |
| Query language | KQL (Kusto Query Language) |
| Rule deployment format | Azure Resource Manager (ARM / JSON) |
| CI/CD | GitHub Actions |
| Attack simulation | PowerShell |

---

## Detection Coverage

| Rule | MITRE | Tactic | Severity | EventID |
|---|---|---|---|---|
| [RDP Hijacking](Detections/rdp-hijacking.json) | T1563.002 | Lateral Movement | Medium | 4688 |
| [New Service Creation](Detections/new-service-creation.json) | T1543.003 | Persistence | High | 4697 |
| [Brute Force](Detections/brute-force-success.json) | T1110 | Credential Access | Critical | 4625 |

<details>
<summary><strong>Detection logic explained</strong></summary>

### RDP Hijacking — T1563.002 — Medium

**What the attacker does:** Uses `tscon.exe` — a legitimate Windows Remote Desktop Services utility — to transfer an active RDP session to themselves under SYSTEM context. No credentials required. No password event in the log.

**What the rule detects:** EventID 4688 (process creation) where `NewProcessName` ends with `tscon.exe` and the process runs under `SYSTEM` or is spawned by `cmd.exe` / `powershell.exe`. Legitimate enterprise use of `tscon.exe` is rare — watchlist known-good if it exists in your environment.

**Why Medium:** Requires pre-existing SYSTEM privileges. The attacker is already deeply inside by the time this fires.

**Triage:** What did the attacker do after session transfer? Check process creation events from the hijacked session context in the 10 minutes following the alert timestamp.

---

### New Service Creation — T1543.003 — High

**What the attacker does:** Registers a Windows service with a suspicious binary path — typically `cmd.exe`, `powershell.exe`, or an executable in a user-writable location — disguised with a legitimate-sounding name. Services survive reboots, giving the attacker persistent execution.

**What the rule detects:** EventID 4697 (service installed on system) where `ServiceFileName` does not match standard `svchost.exe` patterns and points to a known suspicious binary or path. An extended field `SuspiciousPath` is set to `true` when the binary matches a known LOLBin or user-writable directory.

**Why High:** Persistence means the attacker intends to maintain access. This is not opportunistic — it's deliberate.

**Triage:** Check `ServiceFileName` (where does the binary live?), `SubjectUserName` (is this a known service account?), and what that account did in the 15 minutes prior to service creation.

---

### Brute Force — T1110 — Critical

**What the attacker does:** Submits repeated failed authentication attempts against one or more accounts, attempting to guess valid credentials. The query aggregates EventID 4625 failures by source IP over a 10-minute tumbling window. When the count hits 5 or more, the alert fires.

**What the rule detects:** Five or more EventID 4625 failures from the same source IP within a 10-minute window. Loopback, link-local addresses, and machine accounts are excluded to reduce noise.

**Why Critical:** Credential access is the pivot point for most attack chains. If an attacker successfully authenticates after a brute force run, everything downstream — lateral movement, data access, persistence — becomes possible.

**Triage — run this immediately:**
```kql
let AttackingIP = "PASTE_IP_FROM_ALERT";
SecurityEvent
| where TimeGenerated > ago(30m)
| where EventID in (4625, 4624)
| where IpAddress == AttackingIP
| project TimeGenerated, EventID, TargetUserName, IpAddress, LogonType
| order by TimeGenerated asc
// A 4624 following a run of 4625s = credential compromise — escalate immediately
```

</details>

---

## Prerequisites

### Azure
- [ ] Subscription with an active Microsoft Sentinel workspace
- [ ] Service principal with two roles on the workspace resource group:
  - `Microsoft Sentinel Contributor` — rule deployment
  - `Log Analytics Reader` — Gate 3 event verification
- [ ] Azure CLI installed and authenticated (`az --version`)

### Test endpoint
- [ ] Isolated Windows VM dedicated to simulations — no production network path, not domain-joined
- [ ] Azure Monitor Agent (AMA) installed and forwarding to your Log Analytics workspace
- [ ] `Security` event log configured in the Data Collection Rule (EventIDs 4625, 4688, 4697)
- [ ] `DAC_TEST_ENDPOINT` environment variable set to `"true"` (see [Setup Step 4](#step-4--configure-the-test-endpoint))
- [ ] Process creation auditing enabled — required for RDP Hijacking detection (EventID 4688):

  ```
  GPO: Computer Configuration → Windows Settings → Security Settings
       → Advanced Audit Policy → Detailed Tracking
       → Audit Process Creation: Success

  GPO: Administrative Templates → System → Audit Process Creation
       → Include command line in process creation events: Enabled
  ```

### GitHub
- [ ] Actions enabled on the repository
- [ ] Admin access to configure branch protection

### Local
- [ ] PowerShell 7+ (`pwsh --version`)
- [ ] `jq` for local JSON validation (`jq --version`)

---

## Setup

### Step 1 — Fork and clone

```bash
# Fork on GitHub (top-right), then clone your fork
git clone https://github.com/YOUR-USERNAME/Sentinel-Detection-Engine.git
cd Sentinel-Detection-Engine
```

---

### Step 2 — Create a service principal

```bash
az login
az account show --query id -o tsv  # get your subscription ID

az ad sp create-for-rbac \
  --name "sentinel-dac-pipeline" \
  --role "Microsoft Sentinel Contributor" \
  --scopes "/subscriptions/YOUR_SUBSCRIPTION_ID/resourceGroups/YOUR_RESOURCE_GROUP" \
  --sdk-auth

# Assign Log Analytics Reader separately (required for Gate 3)
az role assignment create \
  --assignee YOUR_CLIENT_ID \
  --role "Log Analytics Reader" \
  --scope "/subscriptions/YOUR_SUBSCRIPTION_ID/resourceGroups/YOUR_RESOURCE_GROUP"
```

The `--sdk-auth` output contains all four credential values you need. **Save this output — the `clientSecret` is shown only once.**

---

### Step 3 — Add GitHub Secrets

**Settings → Secrets and variables → Actions → New repository secret**

| Secret | Where to get it |
|---|---|
| `AZURE_CLIENT_ID` | `clientId` from service principal output |
| `AZURE_CLIENT_SECRET` | `clientSecret` from service principal output |
| `AZURE_TENANT_ID` | `tenantId` from service principal output |
| `AZURE_SUBSCRIPTION_ID` | `subscriptionId` from service principal output |
| `LAW_WORKSPACE_ID` | Sentinel → Log Analytics → Overview → Workspace ID |
| `TEST_ENDPOINT_NAME` | Name of your isolated test VM |
| `TEST_RESOURCE_GROUP` | Resource group containing the test VM |
| `SENTINEL_RESOURCE_GROUP` | Resource group containing the Sentinel workspace |
| `SENTINEL_WORKSPACE_NAME` | Sentinel workspace name |
| `SENTINEL_SOURCECONTROL_ID` | From the repository connection URL (see Step 5) |

---

### Step 4 — Configure the test endpoint

On the isolated test VM, open PowerShell as Administrator:

```powershell
# Sets the environment guard permanently — survives reboots
[System.Environment]::SetEnvironmentVariable("DAC_TEST_ENDPOINT", "true", "Machine")
```

The simulation script checks for this variable at startup and exits immediately if it is not set. This prevents the script from running on any machine that hasn't been explicitly designated as a test endpoint.

---

### Step 5 — Connect Sentinel to this repository

1. Azure Portal → **Microsoft Sentinel** → your workspace
2. **Content management** → **Repositories** → **+ Add**
3. Authenticate GitHub, select this repository, set branch to `main`, path to `/Detections`
4. Save — then click the connection in the list
5. Copy the source control ID from the browser URL: `...sourcecontrols/THIS-ID/...`
6. Add this as the `SENTINEL_SOURCECONTROL_ID` secret

---

### Step 6 — Enable branch protection

**Settings → Branches → Add branch protection rule**

- Branch name pattern: `main`
- ✅ Require a pull request before merging
- ✅ Require approvals: `1`
- ✅ Require status checks to pass:
  - `Gate 1 — Schema Validation`
  - `Gate 2 — Attack Simulation`
  - `Gate 3 — Alert Verification`
- ✅ Do not allow bypassing the above settings

Without this, every gate is advisory. Anyone with write access can push to `main` and skip the pipeline entirely.

---

### Step 7 — Smoke test

Push a whitespace edit on a branch and open a PR. Confirm all three gates appear and run green in the **Checks** tab before proceeding.

---

## Authoring a Detection Rule

### 1 — Write and validate KQL first

Open **Microsoft Sentinel → Logs** and develop your query against real data. Do not touch the ARM template until the query returns what you expect. Note the exact output column names — they must match your entity mappings exactly.

### 2 — Copy the skeleton

```bash
cp Templates/detection-skeleton.json Detections/your-rule-name.json
```

### 3 — Fill required fields

Every field marked `REPLACE` must be updated. Gate 1 will fail on any missing or invalid value.

| Field | Allowed values |
|---|---|
| `severity` | `Informational` `Low` `Medium` `High` `Critical` |
| `status` | `Observation` `Active` `Deprecated` — **always start new rules as `Observation`** |
| `tactics` | MITRE ATT&CK tactic name e.g. `Persistence` |
| `techniques` | MITRE technique ID e.g. `T1543.003` |
| `entityMappings` | At least one entity; `columnName` must match query output |
| `apiVersion` | `2022-11-01-preview` — older versions will fail Gate 1 |

### 4 — Escape KQL for JSON

When pasting KQL into the `query` field:

| In KQL | In JSON string |
|---|---|
| newline | `\n` |
| `\` | `\\` |
| `\\` | `\\\\` |
| `"` inside query | use `'` single quotes |

### 5 — Validate locally before pushing

```bash
cat Detections/your-rule.json | jq .
# Formatted JSON output = valid. Error = fix before pushing.
```

### 6 — Add a simulation function

Add a corresponding simulation function to `Validation/simulate_attack.ps1` following the same pattern as `Invoke-ServiceCreationSim` and `Invoke-BruteForceSim`. The function must generate the specific Windows EventID your detection rule queries for.

---

## Running the Validation Script

### Confirm before every run

- [ ] You are on the **isolated test VM** — not a production or corporate machine
- [ ] `$env:DAC_TEST_ENDPOINT` equals `"true"`
- [ ] PowerShell is running as **Administrator**
- [ ] You will run `-Cleanup` when done

### Commands

```powershell
# Confirm environment guard
echo $env:DAC_TEST_ENDPOINT   # must output: true

# Full simulation (both T1543.003 and T1110)
.\Validation\simulate_attack.ps1

# Service creation only
.\Validation\simulate_attack.ps1 -SkipBruteForce

# Remove all artifacts after testing — always do this
.\Validation\simulate_attack.ps1 -Cleanup
```

### What each simulation does

**Simulation 1 — T1543.003 (New Service Creation)**
Calls `New-Service` with binary path `C:\Windows\System32\cmd.exe` under the name `LegitMicrosoftUpdate`. Writes EventID 4697 to the Windows Security log. The AMA agent forwards this to Log Analytics where the `New Service Creation` analytics rule matches it.

**Simulation 2 — T1110 (Brute Force)**
Fires 6 sequential `net use` attempts against `FakeAdmin_DACTest` with wrong passwords, with a 2-second delay between each to generate distinct timestamps. Each attempt writes EventID 4625. When 5+ failures from the same IP appear within the 10-minute tumbling window, the `Brute Force` rule fires.

**Cleanup**
The `-Cleanup` flag stops and deletes the `LegitMicrosoftUpdate` service. The CI pipeline runs cleanup automatically in an `if: always()` step — artifacts are removed whether the simulation succeeded or failed.

### Verify events reached Sentinel

Wait 2–5 minutes after running, then run in **Sentinel → Logs**:

```kql
SecurityEvent
| where EventID in (4697, 4625)
| where TimeGenerated > ago(15m)
| project TimeGenerated, EventID, Computer, SubjectUserName, ServiceName
| order by TimeGenerated desc
```

Expected: 1× EventID 4697, 6× EventID 4625. If either is missing, check AMA agent health before assuming a detection rule problem.

---

## Submitting a Pull Request

```bash
# Branch naming convention
git checkout -b detection/t1543-new-service-creation

# Stage only your detection and simulation files
git add Detections/your-rule.json
git add Validation/simulate_attack.ps1

# Commit with context
git commit -m "Add T1543.003 New Service Creation detection

- KQL: EventID 4697 filtered for non-svchost binary paths
- Entity mapping: Host (Computer), Account (SubjectUserName, SubjectDomainName)
- Simulation verified on isolated test endpoint
- EventID 4697 confirmed in Log Analytics
- Cleanup confirmed working
- MITRE: Persistence > T1543.003"

git push origin detection/t1543-new-service-creation
```

### PR description template

```markdown
## What this detection catches
One paragraph: technique, attacker objective, why it matters.

## MITRE mapping
- Tactic: Persistence
- Technique: T1543.003 — Create or Modify System Process: Windows Service

## Test evidence
- [ ] KQL validated in Sentinel Logs — returns expected results
- [ ] simulate_attack.ps1 run on isolated test endpoint
- [ ] EventID confirmed in Log Analytics within 5 minutes
- [ ] -Cleanup run and confirmed

## False positive analysis
What legitimate activity could trigger this rule and how is it handled?

## Severity justification
Why this severity level for this signal?
```

After opening the PR, monitor the **Checks** tab. All three gates run automatically. Gate failures include specific error messages — fix the issue, push a new commit, and the gates re-run.

---

## CI Gate Reference

### Gate 1 — Schema Validation

Runs `jq` against every `.json` file in `/Detections`. Checks:
- Valid JSON syntax
- All required fields present and non-null
- `severity` is in the allowed set
- `status` is in the allowed set
- `tactics` is a JSON array
- `entityMappings` contains at least one entry
- `apiVersion` is not an outdated value (`2020-01-01` and `2019-01-01-preview` are blocked)

**Most common failure:** `columnName` in `entityMappings` doesn't match what the query actually returns. Run your query in Sentinel Logs and check the output column names before writing the mapping.

---

### Gate 2 — Attack Simulation

Executes `simulate_attack.ps1` on the CI test endpoint via `az vm run-command invoke`. The VM is started at the beginning of the job in case it has an auto-shutdown schedule. Cleanup runs in an `if: always()` step — artifacts are removed regardless of simulation outcome.

**Most common failure:** PowerShell syntax error in the script. Test locally on the isolated VM before pushing.

---

### Gate 3 — Alert Verification

Polls Log Analytics for EventID 4697 (service name `LegitMicrosoftUpdate`) and EventID 4625 (target user `FakeAdmin_DACTest`). Retries up to 10 times at 60-second intervals. Queries are scoped to `TimeGenerated > ago(15m)` to avoid matching events from previous pipeline runs.

**Consistent failure with events visible in Sentinel:**
1. Verify `LAW_WORKSPACE_ID` matches the workspace your test VM forwards to
2. Confirm service principal has `Log Analytics Reader` role (separate from `Sentinel Contributor`)
3. Check the `log-analytics` CLI extension is installed — the pipeline installs it automatically

---

## Detection Lifecycle

New rules always start in `Observation` mode. No incidents are created until the rule is promoted to `Active`.

```
┌─────────────┐   7-day minimum    ┌──────────────┐   documented reason  ┌────────────┐
│ Observation │ ─────────────────▶ │    Active    │ ───────────────────▶ │ Deprecated │
│             │   FP rate < 10%    │              │                      │            │
│ alerts only │   PR + review      │ incidents on │   90-day retention   │ disabled   │
└─────────────┘                    └──────────────┘   then deleted       └────────────┘
```

**Observation → Active checklist:**
- [ ] Rule ran for at least 7 calendar days
- [ ] False positive rate documented (target: fewer than 1 in 10 alerts requires no action)
- [ ] Triage guidance written or linked in the `description` field
- [ ] Entity mappings verified — investigation graph populates correctly in Sentinel
- [ ] `"createIncident": true` set in the ARM template
- [ ] PR opened, reviewed, and merged

**Deprecation:** Keep deprecated rules at `status: Deprecated` for 90 days before deletion. The history and rationale stay in the Git log regardless.

---

## Operational Runbook

### Triage — New Service Creation (T1543.003)

```kql
// 1. Full service context
SecurityEvent
| where EventID == 4697
| where Computer == "HOSTNAME_FROM_ALERT"
| where TimeGenerated > ago(1h)
| project TimeGenerated, Computer, ServiceName, ServiceFileName,
          SubjectUserName, SubjectDomainName, SubjectLogonId

// 2. What was this account doing before the service was created?
SecurityEvent
| where SubjectLogonId == "LOGON_ID_FROM_ABOVE"
| where TimeGenerated between (ago(30m) .. now())
| project TimeGenerated, EventID, Activity, Computer
| order by TimeGenerated asc

// 3. Did the service binary execute after installation?
SecurityEvent
| where EventID == 4688
| where Computer == "HOSTNAME_FROM_ALERT"
| where NewProcessName == "SERVICE_FILENAME_FROM_ABOVE"
| where TimeGenerated > ago(1h)
| project TimeGenerated, NewProcessName, CommandLine, ParentProcessName
```

---

### Triage — Brute Force (T1110)

```kql
// 1. Did any failure lead to a successful logon? (critical question)
let AttackingIP = "SOURCE_IP_FROM_ALERT";
SecurityEvent
| where TimeGenerated > ago(30m)
| where IpAddress == AttackingIP
| where EventID in (4625, 4624)
| project TimeGenerated, EventID, TargetUserName, IpAddress, LogonType
| order by TimeGenerated asc
// 4624 after 4625 run = confirmed compromise — P1 escalation

// 2. How many accounts were targeted? (spray vs targeted)
SecurityEvent
| where EventID == 4625
| where IpAddress == AttackingIP
| where TimeGenerated > ago(30m)
| summarize Attempts = count() by TargetUserName
| order by Attempts desc
```

---

### Rolling back a bad rule

```bash
# Find the offending commit
git log --oneline Detections/rule-name.json

# Revert it
git revert <commit-hash>

# Or reset the specific file to a known-good state
git checkout <good-commit-hash> -- Detections/rule-name.json
git commit -m "revert: roll back rule-name — reason: <high FP rate / bad query>"

git push origin hotfix/revert-rule-name
# Open PR — on merge, Sentinel syncs the reverted template in ~2-3 minutes
```

---

### Detecting portal bypasses

Add this query to a Sentinel Workbook to catch anyone modifying rules directly in the portal instead of through the pipeline:

```kql
AzureActivity
| where OperationNameValue == "MICROSOFT.SECURITYINSIGHTS/ALERTRULES/WRITE"
| where Caller !startswith "sentinel-dac-pipeline"
| where TimeGenerated > ago(24h)
| project TimeGenerated, Caller, ResourceGroup, Properties
| order by TimeGenerated desc
```

---

## No Azure Access?

You don't need Azure access to learn the core skills in this framework.

**Practice KQL right now — no account required:**
Microsoft's Log Analytics demo environment is pre-loaded with real security data.
→ [https://aka.ms/lademo](https://aka.ms/lademo)

```kql
-- Brute force pattern (T1110)
SecurityEvent
| where EventID == 4625
| where TimeGenerated > ago(24h)
| summarize FailureCount = count() by IpAddress, TargetUserName
| where FailureCount > 5
| order by FailureCount desc

-- Service creation (T1543.003)
SecurityEvent
| where EventID == 4697
| project TimeGenerated, Computer, ServiceName, ServiceFileName, SubjectUserName
| order by TimeGenerated desc
```

**Free Azure trial — full pipeline practice:**
90 days + $200 credit. Enough to run this framework end-to-end.
→ [https://azure.microsoft.com/free](https://azure.microsoft.com/free)

Deploy a pre-configured Sentinel workspace in 20 minutes:
→ [Sentinel Training Lab](https://github.com/Azure/Azure-Sentinel/tree/master/Solutions/Training/Azure-Sentinel-Training-Lab)

**Free Windows test VM — local simulation practice:**
Microsoft's Windows 11 dev VM runs in VirtualBox (free). Fully isolated on your laptop.
→ [https://developer.microsoft.com/windows/downloads/virtual-machines](https://developer.microsoft.com/windows/downloads/virtual-machines)

---

## Troubleshooting

<details>
<summary><strong>Gate 1 fails — "Invalid apiVersion"</strong></summary>

Your ARM template is using an outdated API version (`2020-01-01` or `2019-01-01-preview`). Gate 1 explicitly blocks these because they do not support `entityMappings` or `alertDetailsOverride`.

Fix: change `apiVersion` to `2022-11-01-preview` in your detection JSON.

</details>

<details>
<summary><strong>Gate 1 fails — "Missing required field: entityMappings"</strong></summary>

Every detection template must include at least one entity mapping. Without this, the Sentinel investigation graph is empty and analysts cannot pivot on any alert entity.

Check that `entityMappings` is present, is a JSON array, and has at least one entry with a `columnName` that matches your query output. Run your KQL in Sentinel Logs first and inspect the returned columns.

</details>

<details>
<summary><strong>Gate 1 fails — "Invalid JSON syntax"</strong></summary>

Run locally to find the exact line:
```bash
cat Detections/your-file.json | jq .
```

Most common cause: unescaped backslashes in the KQL query string. In JSON, `\` must be `\\` and `\\` must be `\\\\`.

</details>

<details>
<summary><strong>Gate 2 fails — simulation script errors</strong></summary>

Test the script locally on the isolated VM first:
```powershell
$env:DAC_TEST_ENDPOINT = "true"
.\Validation\simulate_attack.ps1
```

If it runs locally but fails in CI, compare PowerShell versions between your VM and the CI runner.

</details>

<details>
<summary><strong>Gate 3 fails — "EventID not found" but events are visible in Sentinel</strong></summary>

The pipeline is querying a different workspace than your test VM is forwarding to.

Verify which workspace has the events:
```kql
SecurityEvent
| where Computer == "YOUR_TEST_VM_NAME"
| where TimeGenerated > ago(30m)
| summarize count() by EventID
```

Run this in each workspace you have access to. Update `LAW_WORKSPACE_ID` in GitHub Secrets to match the workspace that returns results.

</details>

<details>
<summary><strong>Simulation script prints "SAFETY BLOCK" and exits</strong></summary>

The environment guard is working correctly. The variable is not set on this machine.

On the designated test VM only:
```powershell
# Session only
$env:DAC_TEST_ENDPOINT = "true"

# Permanent (survives reboots — requires Administrator)
[System.Environment]::SetEnvironmentVariable("DAC_TEST_ENDPOINT", "true", "Machine")
```

Do not bypass this check on any machine other than the isolated test VM.

</details>

<details>
<summary><strong>Rule merged but not appearing in Sentinel Analytics</strong></summary>

1. Sentinel → **Content management** → **Repositories** → check sync log for errors
2. Confirm the JSON file is directly in `/Detections/` — not in a subdirectory
3. Validate JSON: `cat Detections/yourfile.json | jq .`
4. Verify service principal has `Microsoft Sentinel Contributor` on the correct resource group
5. Check `SENTINEL_SOURCECONTROL_ID` matches the connection URL exactly

</details>

---

**Before opening a PR:**
- KQL tested in Sentinel Logs against real or representative data
- Detection JSON validates locally: `cat Detections/rule.json | jq .`
- Simulation function added and tested on isolated VM
- EventIDs confirmed in Log Analytics
- Cleanup confirmed working
- `status` set to `Observation` — never `Active` on a new rule

**Reviewer checklist:**
- Does the KQL detect the actual technique or a proxy that generates excessive noise?
- Do `columnName` values in `entityMappings` match real query output columns?
- Is `apiVersion` set to `2022-11-01-preview` or later?
- Is `status` set to `Observation`?
- Is the simulation realistic enough to prove the detection path works end-to-end?
- Has the false positive scenario been identified and handled or documented?

---
