#Requires -RunAsAdministrator
<#
.SYNOPSIS
    DaC Validation Script — Sentinel Detection Engine
    Simulates T1543.003 (New Service Creation) and T1110 (Brute Force).

.PARAMETER Cleanup
    Removes all artifacts created by the simulation. Always run after testing.
    Example: .\simulate_attack.ps1 -Cleanup

.PARAMETER SkipBruteForce
    Skips the T1110 brute force simulation. Useful when testing service creation only.

.NOTES
    SAFETY: This script will NOT run unless $env:DAC_TEST_ENDPOINT is set to "true".
    Set this ONLY on the designated isolated test VM:
      [System.Environment]::SetEnvironmentVariable("DAC_TEST_ENDPOINT","true","Machine")

    Expected EventIDs (confirm in Sentinel Logs after 2-5 minutes):
      4697 — service installed on system        (T1543.003)
      4625 — account failed to log on           (T1110)

    Verify with:
      SecurityEvent
      | where EventID in (4697, 4625)
      | where TimeGenerated > ago(15m)
      | project TimeGenerated, EventID, Computer, SubjectUserName, ServiceName
      | order by TimeGenerated desc
#>

param(
    [switch]$Cleanup,
    [switch]$SkipBruteForce
)

# ─── Constants ────────────────────────────────────────────────────────────────
$SERVICE_NAME         = "LegitMicrosoftUpdate"
$SERVICE_BINARY       = "C:\Windows\System32\cmd.exe"
$SERVICE_DESCRIPTION  = "DAC Simulation Artifact — safe to delete"
$BRUTE_ACCOUNT        = "FakeAdmin_DACTest"
$BRUTE_ATTEMPTS       = 6

# ─── Environment Guard ────────────────────────────────────────────────────────
# Blocks execution on any machine that has not been explicitly designated
# as the isolated test endpoint. This is your first line of defence.
function Test-SafeEnvironment {
    if ($env:DAC_TEST_ENDPOINT -ne "true") {
        Write-Host ""
        Write-Host "╔══════════════════════════════════════════════════════════╗" -ForegroundColor Red
        Write-Host "║                    ⛔  SAFETY BLOCK                     ║" -ForegroundColor Red
        Write-Host "╠══════════════════════════════════════════════════════════╣" -ForegroundColor Red
        Write-Host "║  This script must ONLY run on the isolated test VM.     ║" -ForegroundColor Red
        Write-Host "║                                                          ║" -ForegroundColor Red
        Write-Host "║  On the test VM, set the environment variable:           ║" -ForegroundColor Red
        Write-Host "║                                                          ║" -ForegroundColor Red
        Write-Host "║  [System.Environment]::SetEnvironmentVariable(           ║" -ForegroundColor Red
        Write-Host "║      ""DAC_TEST_ENDPOINT"",""true"",""Machine"")               ║" -ForegroundColor Red
        Write-Host "║                                                          ║" -ForegroundColor Red
        Write-Host "║  If you are NOT on the test VM — stop here.             ║" -ForegroundColor Red
        Write-Host "╚══════════════════════════════════════════════════════════╝" -ForegroundColor Red
        Write-Host ""
        exit 1
    }
    Write-Host "✅ Environment guard passed." -ForegroundColor Green
}

# ─── Cleanup ──────────────────────────────────────────────────────────────────
# Idempotent — safe to run multiple times. CI pipeline calls this via
# an 'if: always()' step so artifacts are removed even on simulation failure.
function Invoke-Cleanup {
    Write-Host ""
    Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Yellow
    Write-Host "  CLEANUP" -ForegroundColor Yellow
    Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Yellow

    $svc = Get-Service -Name $SERVICE_NAME -ErrorAction SilentlyContinue
    if ($svc) {
        Write-Host "  Removing service '$SERVICE_NAME'..." -ForegroundColor Cyan
        Stop-Service -Name $SERVICE_NAME -Force -ErrorAction SilentlyContinue
        $result = sc.exe delete $SERVICE_NAME 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-Host "  ✅ Service removed." -ForegroundColor Green
        } else {
            Write-Host "  ⚠️  sc.exe: $result" -ForegroundColor Yellow
            Write-Host "     Reboot may be required to fully clear the service entry." -ForegroundColor Yellow
        }
    } else {
        Write-Host "  Service '$SERVICE_NAME' not found — nothing to remove." -ForegroundColor Gray
    }

    Write-Host ""
    Write-Host "  Cleanup complete." -ForegroundColor Green
    Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Yellow
}

# ─── Simulation 1: T1543.003 — New Service Creation ──────────────────────────
# Registers a service with a suspicious binary path (cmd.exe).
# Name is chosen to blend with Windows Update processes.
# Writes EventID 4697 to the Windows Security log.
function Invoke-ServiceCreationSim {
    Write-Host ""
    Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
    Write-Host "  SIM 1 — T1543.003: New Service Creation (Persistence)" -ForegroundColor Cyan
    Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
    Write-Host "  Expected EventID : 4697" -ForegroundColor Gray
    Write-Host "  Detection rule   : Suspicious Service Creation — Non-Standard Binary" -ForegroundColor Gray
    Write-Host ""

    # Guard: check if leftover from a previous run
    $existing = Get-Service -Name $SERVICE_NAME -ErrorAction SilentlyContinue
    if ($existing) {
        Write-Host "  ⚠️  Service '$SERVICE_NAME' already exists." -ForegroundColor Yellow
        Write-Host "     Run .\simulate_attack.ps1 -Cleanup first, then retry." -ForegroundColor Yellow
        return
    }

    Write-Host "  Creating service '$SERVICE_NAME'..." -ForegroundColor White
    try {
        New-Service `
            -Name           $SERVICE_NAME `
            -BinaryPathName $SERVICE_BINARY `
            -Description    $SERVICE_DESCRIPTION `
            -StartupType    Manual `
            -ErrorAction    Stop | Out-Null

        Write-Host "  ✅ Service created." -ForegroundColor Green
        Write-Host ""
        Write-Host "  Details:" -ForegroundColor Gray
        Write-Host "    Name        : $SERVICE_NAME" -ForegroundColor Gray
        Write-Host "    Binary path : $SERVICE_BINARY" -ForegroundColor Gray
        Write-Host "    Created by  : $env:USERNAME" -ForegroundColor Gray
        Write-Host ""
        Write-Host "  ⚠️  Run -Cleanup when done to remove this service." -ForegroundColor Yellow

    } catch {
        Write-Host "  ❌ Failed to create service: $_" -ForegroundColor Red
        Write-Host "     Ensure PowerShell is running as Administrator." -ForegroundColor Red
        exit 1
    }

    Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
}

# ─── Simulation 2: T1110 — Brute Force ───────────────────────────────────────
# Fires sequential failed authentication attempts against a non-existent account.
# Each attempt writes EventID 4625 to the Windows Security log.
# Delay between attempts ensures distinct timestamps for accurate aggregation.
function Invoke-BruteForceSim {
    Write-Host ""
    Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
    Write-Host "  SIM 2 — T1110: Brute Force (Credential Access)" -ForegroundColor Cyan
    Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
    Write-Host "  Expected EventID : 4625 (x$BRUTE_ATTEMPTS)" -ForegroundColor Gray
    Write-Host "  Detection rule   : Brute Force — Repeated Failed Logons" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  Firing $BRUTE_ATTEMPTS failed auth attempts against '$BRUTE_ACCOUNT'..." -ForegroundColor White
    Write-Host ""

    for ($i = 1; $i -le $BRUTE_ATTEMPTS; $i++) {
        Write-Host "  Attempt $i of $BRUTE_ATTEMPTS..." -ForegroundColor Gray
        try {
            $null = net use \\127.0.0.1 /user:$BRUTE_ACCOUNT "WrongPassword_DACTest_$i" 2>&1
        } catch {
            # Expected to fail — 4625 is the goal
        }
        Start-Sleep -Seconds 2   # Distinct timestamps, avoid lockout policy triggers
    }

    Write-Host ""
    Write-Host "  ✅ $BRUTE_ATTEMPTS failed attempts complete." -ForegroundColor Green
    Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
}

# ─── Verification query ───────────────────────────────────────────────────────
function Show-VerificationQuery {
    Write-Host ""
    Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Green
    Write-Host "  NEXT: Verify events in Sentinel (wait 2-5 min)" -ForegroundColor Green
    Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Green
    Write-Host ""
    Write-Host "  Run this in Sentinel → Logs:" -ForegroundColor White
    Write-Host ""
    Write-Host "  SecurityEvent" -ForegroundColor Yellow
    Write-Host "  | where EventID in (4697, 4625)" -ForegroundColor Yellow
    Write-Host "  | where TimeGenerated > ago(15m)" -ForegroundColor Yellow
    Write-Host "  | project TimeGenerated, EventID, Computer, SubjectUserName, ServiceName" -ForegroundColor Yellow
    Write-Host "  | order by TimeGenerated desc" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  Expected results:" -ForegroundColor White
    Write-Host "    1 × EventID 4697  (service creation)" -ForegroundColor Gray
    Write-Host "    $BRUTE_ATTEMPTS × EventID 4625  (failed logons)" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  Always run cleanup when done:" -ForegroundColor White
    Write-Host "    .\simulate_attack.ps1 -Cleanup" -ForegroundColor Yellow
    Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Green
}

# ─── Entry point ─────────────────────────────────────────────────────────────

Write-Host ""
Write-Host "╔══════════════════════════════════════════════════════════╗" -ForegroundColor Magenta
Write-Host "║   Sentinel Detection Engine — DaC Validation Script     ║" -ForegroundColor Magenta
Write-Host "║   Red-team simulation for pipeline gate verification    ║" -ForegroundColor Magenta
Write-Host "╚══════════════════════════════════════════════════════════╝" -ForegroundColor Magenta

if ($Cleanup) {
    Test-SafeEnvironment
    Invoke-Cleanup
    exit 0
}

Test-SafeEnvironment
Invoke-ServiceCreationSim

if (-not $SkipBruteForce) {
    Invoke-BruteForceSim
}

Show-VerificationQuery
