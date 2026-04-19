# Simulation for T1543.003 - Persistence via New Service Creation
Write-Host "Simulating Malicious Service Creation..." -ForegroundColor Red
New-Service -Name "LegitMicrosoftUpdate" -BinaryPathName "C:\Windows\System32\cmd.exe" -Description "Persistence Test"

# Simulation for T1110 - Brute Force (Failed Logins)
Write-Host "Simulating Brute Force Attempt..." -ForegroundColor Red
$Account = "FakeAdmin"
for ($i=1; $i -le 6; $i++) {
    try { $test = net use \\127.0.0.1 /user:$Account "WrongPassword$i" } catch {}
}
Write-Host "Attack Simulation Complete. Check Sentinel logs for EventID 4697 and 4625." -ForegroundColor Green
