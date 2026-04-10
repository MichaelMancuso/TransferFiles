<#
.SYNOPSIS
    T1526 - Cloud Service Discovery - Red Team TTP Demo
.DESCRIPTION
    Enumerates Azure/M365 cloud services and resources within the tenant.
    For authorized red team use only.
#>

# ─────────────────────────────────────────────
# STEP 1: Auto-install prerequisites
# ─────────────────────────────────────────────
Write-Host "`n[*] Checking prerequisites..." -ForegroundColor Cyan

$requiredModules = @("Az.Accounts", "Az.Resources")

foreach ($module in $requiredModules) {
    if (-not (Get-Module -ListAvailable -Name $module)) {
        Write-Host "[*] Installing $module module..." -ForegroundColor Yellow
        Install-Module -Name $module -Force -Scope CurrentUser
        Write-Host "[+] $module installed." -ForegroundColor Green
    } else {
        Write-Host "[+] $module already installed." -ForegroundColor Green
    }
}

Import-Module Az.Accounts -ErrorAction Stop
Import-Module Az.Resources -ErrorAction Stop
Write-Host "[+] Modules loaded.`n" -ForegroundColor Green

# ─────────────────────────────────────────────
# STEP 2: Interactive prompts
# ─────────────────────────────────────────────
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "  T1526 - Azure Resource Enumeration Setup  " -ForegroundColor Cyan
Write-Host "============================================`n" -ForegroundColor Cyan

$TenantId = Read-Host "Enter your Tenant ID or domain (e.g. company.onmicrosoft.com)"

Write-Host "`n[*] What would you like to enumerate?"
Write-Host "    1. Azure Subscriptions and Resource Groups"
Write-Host "    2. Entra ID Users and Groups"
Write-Host "    3. Service Principals and App Registrations"
Write-Host "    4. All of the above (full enumeration)`n"
$Choice = Read-Host "Enter choice (1-4)"

# ─────────────────────────────────────────────
# STEP 3: Confirm before running
# ─────────────────────────────────────────────
Write-Host "`n[*] About to enumerate tenant resources:" -ForegroundColor Cyan
Write-Host "    Tenant: $TenantId"
Write-Host "    Scope : Option $Choice"

$confirm = Read-Host "`nProceed? (yes/no)"
if ($confirm -ne "yes") {
    Write-Host "[!] Aborted by user." -ForegroundColor Yellow
    exit
}

# ─────────────────────────────────────────────
# STEP 4: Authenticate via Az only
# ─────────────────────────────────────────────
Write-Host "`n[*] Authenticating to Azure..." -ForegroundColor Cyan
Write-Host "[*] A browser window will open for login.`n" -ForegroundColor Yellow

Connect-AzAccount -TenantId $TenantId -ErrorAction Stop
Write-Host "[+] Authenticated successfully.`n" -ForegroundColor Green

# Get Graph token directly from Az session (no Graph SDK needed)
function Get-GraphToken {
    $token = (Get-AzAccessToken -ResourceUrl "https://graph.microsoft.com" -ErrorAction Stop).Token
    return @{ Authorization = "Bearer $token" }
}

# ─────────────────────────────────────────────
# STEP 5: Enumeration functions
# ─────────────────────────────────────────────

function Enumerate-Subscriptions {
    Write-Host "`n[*] Enumerating Azure Subscriptions and Resource Groups..." -ForegroundColor Yellow
    $subs = Get-AzSubscription
    Write-Host "`n    Found $($subs.Count) subscription(s):" -ForegroundColor Green
    $subs | Format-Table Name, Id, State -AutoSize

    foreach ($sub in $subs) {
        Set-AzContext -SubscriptionId $sub.Id | Out-Null
        $rgs = Get-AzResourceGroup
        Write-Host "    [$($sub.Name)] Resource Groups: $($rgs.Count)" -ForegroundColor Cyan
        $rgs | Format-Table ResourceGroupName, Location -AutoSize

        $resources = Get-AzResource
        Write-Host "    [$($sub.Name)] Total Resources: $($resources.Count)" -ForegroundColor Cyan
        $resources | Group-Object ResourceType | Sort-Object Count -Descending |
            Select-Object Count, Name | Format-Table -AutoSize
    }
}

function Enumerate-Users {
    Write-Host "`n[*] Enumerating Entra ID Users and Groups via Graph REST API..." -ForegroundColor Yellow

    try {
        $headers = Get-GraphToken

        # Get Users
        $usersResponse = Invoke-RestMethod `
            -Uri "https://graph.microsoft.com/v1.0/users?`$top=999&`$select=displayName,userPrincipalName,userType" `
            -Headers $headers `
            -ErrorAction Stop

        $users = $usersResponse.value
        Write-Host "`n    Found $($users.Count) user(s):" -ForegroundColor Green
        $users | Select-Object displayName, userPrincipalName, userType | Format-Table -AutoSize

        # Get Groups
        $groupsResponse = Invoke-RestMethod `
            -Uri "https://graph.microsoft.com/v1.0/groups?`$top=999&`$select=displayName,groupTypes,membershipRule" `
            -Headers $headers `
            -ErrorAction Stop

        $groups = $groupsResponse.value
        Write-Host "    Found $($groups.Count) group(s):" -ForegroundColor Green
        $groups | Select-Object displayName, groupTypes | Format-Table -AutoSize

    } catch {
        Write-Host "[-] Graph API call failed: $($_.Exception.Message)" -ForegroundColor Red
    }
}

function Enumerate-ServicePrincipals {
    Write-Host "`n[*] Enumerating Service Principals and App Registrations via Graph REST API..." -ForegroundColor Yellow

    try {
        $headers = Get-GraphToken

        # Get Service Principals
        $spResponse = Invoke-RestMethod `
            -Uri "https://graph.microsoft.com/v1.0/servicePrincipals?`$top=999&`$select=displayName,appId,servicePrincipalType" `
            -Headers $headers `
            -ErrorAction Stop

        $sps = $spResponse.value
        Write-Host "`n    Found $($sps.Count) service principal(s):" -ForegroundColor Green
        $sps | Select-Object displayName, appId, servicePrincipalType | Format-Table -AutoSize

        # Get App Registrations
        $appsResponse = Invoke-RestMethod `
            -Uri "https://graph.microsoft.com/v1.0/applications?`$top=999&`$select=displayName,appId" `
            -Headers $headers `
            -ErrorAction Stop

        $apps = $appsResponse.value
        Write-Host "    Found $($apps.Count) app registration(s):" -ForegroundColor Green
        $apps | Select-Object displayName, appId | Format-Table -AutoSize

    } catch {
        Write-Host "[-] Graph API call failed: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# ─────────────────────────────────────────────
# STEP 6: Run selected enumeration
# ─────────────────────────────────────────────
switch ($Choice) {
    "1" { Enumerate-Subscriptions }
    "2" { Enumerate-Users }
    "3" { Enumerate-ServicePrincipals }
    "4" {
        Enumerate-Subscriptions
        Enumerate-Users
        Enumerate-ServicePrincipals
    }
    default {
        Write-Host "[!] Invalid choice. Exiting." -ForegroundColor Red
        exit
    }
}

# ─────────────────────────────────────────────
# STEP 7: Results summary
# ─────────────────────────────────────────────
Write-Host "`n============================================" -ForegroundColor Cyan
Write-Host "   TTP T1526 Complete" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "[*] Check the following for SOC alerts:" -ForegroundColor Cyan
Write-Host "     - Azure Monitor: Unusual List/Read operations" -ForegroundColor White
Write-Host "     - Entra ID Audit Logs: Bulk user/group reads" -ForegroundColor White
Write-Host "     - Defender for Cloud Apps: Mass enumeration alert" -ForegroundColor White
Write-Host "     - Microsoft Sentinel: Cloud resource discovery rule`n" -ForegroundColor White

Disconnect-AzAccount | Out-Null
Write-Host "[+] Disconnected from Azure.`n" -ForegroundColor Green