<#
.SYNOPSIS
    T1136.003 - Guest User Invitation - Red Team TTP Demo
.DESCRIPTION
    Invites an external test email as a guest user to the tenant
    to generate SOC alerts for guest account creation.
    For authorized red team use only.
#>

# ─────────────────────────────────────────────
# STEP 1: Auto-install prerequisites
# ─────────────────────────────────────────────
Write-Host "`n[*] Checking prerequisites..." -ForegroundColor Cyan

$requiredModules = @("Az.Accounts", "Microsoft.Graph")

foreach ($module in $requiredModules) {
    if (-not (Get-Module -ListAvailable -Name $module)) {
        Write-Host "[*] Installing $module module..." -ForegroundColor Yellow
        Install-Module -Name $module -Force -Scope CurrentUser
        Write-Host "[+] $module installed." -ForegroundColor Green
    } else {
        Write-Host "[+] $module already installed." -ForegroundColor Green
    }
}

Import-Module Microsoft.Graph.Users -ErrorAction Stop
Import-Module Microsoft.Graph.Identity.SignIns -ErrorAction Stop
Write-Host "[+] Modules loaded.`n" -ForegroundColor Green

# ─────────────────────────────────────────────
# STEP 2: Interactive prompts
# ─────────────────────────────────────────────
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "  T1136.003 - Guest User Invitation Setup  " -ForegroundColor Cyan
Write-Host "============================================`n" -ForegroundColor Cyan

$TenantId      = Read-Host "Enter your Tenant ID or domain (e.g. company.onmicrosoft.com)"
$GuestEmail    = Read-Host "Enter the external test email to invite (e.g. redteamtest@gmail.com)"
$DisplayName   = Read-Host "Enter a display name for the guest (e.g. Red Team Test User)"
$RedirectUrl   = "https://myapplications.microsoft.com"

# ─────────────────────────────────────────────
# STEP 3: Confirm before running
# ─────────────────────────────────────────────
Write-Host "`n[*] About to send guest invitation:" -ForegroundColor Cyan
Write-Host "    Tenant      : $TenantId"
Write-Host "    Guest Email : $GuestEmail"
Write-Host "    Display Name: $DisplayName"

$confirm = Read-Host "`nProceed? (yes/no)"
if ($confirm -ne "yes") {
    Write-Host "[!] Aborted by user." -ForegroundColor Yellow
    exit
}

# ─────────────────────────────────────────────
# STEP 4: Authenticate to Microsoft Graph
# ─────────────────────────────────────────────
Write-Host "`n[*] Authenticating to Microsoft Graph..." -ForegroundColor Cyan
Write-Host "[*] A browser window will open for login.`n" -ForegroundColor Yellow

Connect-MgGraph -TenantId $TenantId -Scopes "User.Invite.All", "User.ReadWrite.All" -ErrorAction Stop

Write-Host "[+] Authenticated successfully.`n" -ForegroundColor Green

# ─────────────────────────────────────────────
# STEP 5: Send guest invitation
# ─────────────────────────────────────────────
Write-Host "[*] Sending guest invitation to $GuestEmail..." -ForegroundColor Yellow

try {
    $invitation = New-MgInvitation `
        -InvitedUserEmailAddress $GuestEmail `
        -InvitedUserDisplayName $DisplayName `
        -InviteRedirectUrl $RedirectUrl `
        -SendInvitationMessage:$false `
        -ErrorAction Stop

    Write-Host "[+] Guest invitation created successfully!" -ForegroundColor Green
    Write-Host "    Guest User ID  : $($invitation.InvitedUser.Id)"
    Write-Host "    Invite Status  : $($invitation.Status)"
    Write-Host "    Invited Email  : $GuestEmail"

    $Results = [PSCustomObject]@{
        GuestEmail   = $GuestEmail
        DisplayName  = $DisplayName
        UserId       = $invitation.InvitedUser.Id
        Status       = $invitation.Status
    }
}
catch {
    Write-Host "[-] Failed to create guest invitation." -ForegroundColor Red
    Write-Host "    Error: $($_.Exception.Message)" -ForegroundColor Red
    exit
}

# ─────────────────────────────────────────────
# STEP 6: Optional cleanup prompt
# ─────────────────────────────────────────────
Write-Host "`n[*] TTP demonstrated. Do you want to remove the guest account now?" -ForegroundColor Cyan
$cleanup = Read-Host "Remove guest account? (yes/no)"

if ($cleanup -eq "yes") {
    try {
        Remove-MgUser -UserId $invitation.InvitedUser.Id -ErrorAction Stop
        Write-Host "[+] Guest account removed successfully." -ForegroundColor Green
    }
    catch {
        Write-Host "[-] Could not auto-remove. Remove manually in Entra ID portal." -ForegroundColor Red
        Write-Host "    Guest User ID: $($invitation.InvitedUser.Id)" -ForegroundColor Yellow
    }
} else {
    Write-Host "[!] Remember to manually remove the guest account after the engagement:" -ForegroundColor Yellow
    Write-Host "    Guest User ID: $($invitation.InvitedUser.Id)" -ForegroundColor Yellow
}

# ─────────────────────────────────────────────
# STEP 7: Results summary
# ─────────────────────────────────────────────
Write-Host "`n============================================" -ForegroundColor Cyan
Write-Host "   Results Summary" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
$Results | Format-List

Write-Host "[*] TTP T1136.003 complete." -ForegroundColor Cyan
Write-Host "[*] Check Entra ID Audit Logs for:" -ForegroundColor Cyan
Write-Host "     - 'Invite external user' event" -ForegroundColor White
Write-Host "     - 'Add user' event with UserType = Guest" -ForegroundColor White
Write-Host "     - Microsoft Defender for Cloud Apps guest creation alert`n" -ForegroundColor White

Disconnect-MgGraph