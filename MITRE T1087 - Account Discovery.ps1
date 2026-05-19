<#
.SYNOPSIS
    AD user discovery via ADSI / System.DirectoryServices. No RSAT required.

.DESCRIPTION
    Enumerates all user accounts in the current (or specified) Active Directory
    domain using a paged LDAP search through System.DirectoryServices.DirectorySearcher.
    Resolves userAccountControl flags, converts FileTime fields to DateTime,
    expands memberOf, and writes results to CSV.

    Output CSVs (one per category) are written to -OutDir (default: .\ADRecon-<domain>-<timestamp>):
        users_all.csv             All user objects with parsed attributes
        users_enabled.csv         Enabled accounts only
        users_disabled.csv        Disabled accounts only
        users_admincount.csv      adminCount=1 (current or historic privileged)
        users_pwd_never_expires.csv
        users_pwd_not_required.csv
        users_no_preauth.csv      ASREPRoastable (DONT_REQ_PREAUTH)
        users_with_spn.csv        Kerberoastable (servicePrincipalName set)
        users_trusted_for_deleg.csv
        users_stale_90d.csv       lastLogonTimestamp older than 90 days
        users_pwd_in_description.csv  description field contains 'pass', 'pwd', etc.

.PARAMETER Server
    Optional DC / domain FQDN to bind to. Defaults to the current domain (RootDSE).

.PARAMETER SearchBase
    Optional LDAP search base. Defaults to defaultNamingContext from RootDSE.

.PARAMETER OutDir
    Output directory for CSVs. Created if missing.

.PARAMETER StaleDays
    Threshold (days) for stale-account CSV. Default 90.

.EXAMPLE
    .\Invoke-ADUserDiscovery.ps1

.EXAMPLE
    .\Invoke-ADUserDiscovery.ps1 -Server dc01.corp.local -OutDir C:\loot\adrecon

.NOTES
    Engagement: full enumeration / loud. No throttling, paged LDAP queries,
    all attributes pulled in one pass.
#>

[CmdletBinding()]
param(
    [string]$Server,
    [string]$SearchBase,
    [string]$OutDir,
    [int]$StaleDays = 90
)

# ---------- userAccountControl flags ----------
$UAC = [ordered]@{
    SCRIPT                          = 0x00000001
    ACCOUNTDISABLE                  = 0x00000002
    HOMEDIR_REQUIRED                = 0x00000008
    LOCKOUT                         = 0x00000010
    PASSWD_NOTREQD                  = 0x00000020
    PASSWD_CANT_CHANGE              = 0x00000040
    ENCRYPTED_TEXT_PWD_ALLOWED      = 0x00000080
    TEMP_DUPLICATE_ACCOUNT          = 0x00000100
    NORMAL_ACCOUNT                  = 0x00000200
    INTERDOMAIN_TRUST_ACCOUNT       = 0x00000800
    WORKSTATION_TRUST_ACCOUNT       = 0x00001000
    SERVER_TRUST_ACCOUNT            = 0x00002000
    DONT_EXPIRE_PASSWORD            = 0x00010000
    MNS_LOGON_ACCOUNT               = 0x00020000
    SMARTCARD_REQUIRED              = 0x00040000
    TRUSTED_FOR_DELEGATION          = 0x00080000
    NOT_DELEGATED                   = 0x00100000
    USE_DES_KEY_ONLY                = 0x00200000
    DONT_REQ_PREAUTH                = 0x00400000
    PASSWORD_EXPIRED                = 0x00800000
    TRUSTED_TO_AUTH_FOR_DELEGATION  = 0x01000000
    PARTIAL_SECRETS_ACCOUNT         = 0x04000000
}

function Convert-UAC {
    param([int]$Value)
    $flags = foreach ($k in $UAC.Keys) { if ($Value -band $UAC[$k]) { $k } }
    ($flags -join ',')
}

function Convert-FileTime {
    param($Value)
    if ($null -eq $Value -or $Value -eq 0 -or $Value -eq '9223372036854775807') { return $null }
    try { return [DateTime]::FromFileTimeUtc([Int64]$Value) } catch { return $null }
}

function Get-PropFirst {
    param($Result, [string]$Name)
    if ($Result.Properties.Contains($Name) -and $Result.Properties[$Name].Count -gt 0) {
        return $Result.Properties[$Name][0]
    }
    return $null
}

function Get-PropAll {
    param($Result, [string]$Name)
    if ($Result.Properties.Contains($Name)) { return @($Result.Properties[$Name]) }
    return @()
}

function Convert-Sid {
    param([byte[]]$Bytes)
    if (-not $Bytes) { return $null }
    try { return (New-Object System.Security.Principal.SecurityIdentifier($Bytes, 0)).Value } catch { return $null }
}

# ---------- bind to AD ----------
try {
    if ($Server) {
        $rootDseDN = "LDAP://$Server/RootDSE"
    } else {
        $rootDseDN = "LDAP://RootDSE"
    }
    $rootDse = New-Object System.DirectoryServices.DirectoryEntry($rootDseDN)
    if (-not $SearchBase) {
        $SearchBase = $rootDse.Properties['defaultNamingContext'].Value
    }
    $domainDnsRoot = ($SearchBase -replace 'DC=', '' -replace ',', '.')
    if ($Server) {
        $ldapPath = "LDAP://$Server/$SearchBase"
    } else {
        $ldapPath = "LDAP://$SearchBase"
    }
    Write-Host "[*] Binding to $ldapPath" -ForegroundColor Cyan
    $root = New-Object System.DirectoryServices.DirectoryEntry($ldapPath)
} catch {
    Write-Error "Failed to bind to AD: $_"
    return
}

# ---------- output dir ----------
if (-not $OutDir) {
    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $OutDir = Join-Path -Path (Get-Location) -ChildPath "ADRecon-$domainDnsRoot-$stamp"
}
if (-not (Test-Path $OutDir)) { New-Item -Path $OutDir -ItemType Directory -Force | Out-Null }
Write-Host "[*] Output directory: $OutDir" -ForegroundColor Cyan

# ---------- searcher ----------
$searcher = New-Object System.DirectoryServices.DirectorySearcher($root)
$searcher.Filter   = '(&(objectCategory=person)(objectClass=user))'
$searcher.PageSize = 1000
$searcher.SizeLimit = 0
$searcher.SearchScope = 'Subtree'

$attrs = @(
    'samaccountname','userprincipalname','displayname','description','distinguishedname',
    'useraccountcontrol','admincount','memberof','primarygroupid','serviceprincipalname',
    'mail','title','department','company','employeeid','manager','homedirectory',
    'profilepath','scriptpath','logoncount','badpwdcount','badpasswordtime',
    'lastlogon','lastlogontimestamp','lastlogoff','pwdlastset','accountexpires',
    'whencreated','whenchanged','objectsid','sidhistory','useraccountcontrol',
    'msds-supportedencryptiontypes'
) | Select-Object -Unique
$null = $searcher.PropertiesToLoad.AddRange($attrs)

Write-Host "[*] Querying users..." -ForegroundColor Cyan
$results = $searcher.FindAll()
Write-Host "[+] $($results.Count) user objects returned" -ForegroundColor Green

# ---------- shape results ----------
$users = New-Object System.Collections.Generic.List[object]
$i = 0
foreach ($r in $results) {
    $i++
    if ($i % 250 -eq 0) { Write-Host "    processed $i..." -ForegroundColor DarkGray }

    $uac = [int](Get-PropFirst $r 'useraccountcontrol')
    $flags = Convert-UAC -Value $uac
    $sidBytes = Get-PropFirst $r 'objectsid'

    $obj = [PSCustomObject]@{
        SamAccountName       = Get-PropFirst $r 'samaccountname'
        UserPrincipalName    = Get-PropFirst $r 'userprincipalname'
        DisplayName          = Get-PropFirst $r 'displayname'
        Description          = Get-PropFirst $r 'description'
        Mail                 = Get-PropFirst $r 'mail'
        Title                = Get-PropFirst $r 'title'
        Department           = Get-PropFirst $r 'department'
        Company              = Get-PropFirst $r 'company'
        Manager              = Get-PropFirst $r 'manager'
        DistinguishedName    = Get-PropFirst $r 'distinguishedname'
        ObjectSid            = Convert-Sid $sidBytes
        UAC                  = $uac
        UACFlags             = $flags
        Enabled              = -not ($uac -band $UAC.ACCOUNTDISABLE)
        AdminCount           = [int](Get-PropFirst $r 'admincount')
        PrimaryGroupID       = Get-PropFirst $r 'primarygroupid'
        PasswordNeverExpires = [bool]($uac -band $UAC.DONT_EXPIRE_PASSWORD)
        PasswordNotRequired  = [bool]($uac -band $UAC.PASSWD_NOTREQD)
        DontRequirePreAuth   = [bool]($uac -band $UAC.DONT_REQ_PREAUTH)
        TrustedForDelegation = [bool]($uac -band $UAC.TRUSTED_FOR_DELEGATION)
        TrustedToAuthForDeleg= [bool]($uac -band $UAC.TRUSTED_TO_AUTH_FOR_DELEGATION)
        SmartcardRequired    = [bool]($uac -band $UAC.SMARTCARD_REQUIRED)
        ServicePrincipalName = (Get-PropAll $r 'serviceprincipalname') -join ';'
        SPNCount             = (Get-PropAll $r 'serviceprincipalname').Count
        MemberOf             = (Get-PropAll $r 'memberof') -join ';'
        MemberOfCount        = (Get-PropAll $r 'memberof').Count
        LogonCount           = Get-PropFirst $r 'logoncount'
        BadPwdCount          = Get-PropFirst $r 'badpwdcount'
        BadPasswordTime      = Convert-FileTime (Get-PropFirst $r 'badpasswordtime')
        LastLogon            = Convert-FileTime (Get-PropFirst $r 'lastlogon')
        LastLogonTimestamp   = Convert-FileTime (Get-PropFirst $r 'lastlogontimestamp')
        PwdLastSet           = Convert-FileTime (Get-PropFirst $r 'pwdlastset')
        AccountExpires       = Convert-FileTime (Get-PropFirst $r 'accountexpires')
        WhenCreated          = Get-PropFirst $r 'whencreated'
        WhenChanged          = Get-PropFirst $r 'whenchanged'
        HomeDirectory        = Get-PropFirst $r 'homedirectory'
        ScriptPath           = Get-PropFirst $r 'scriptpath'
        ProfilePath          = Get-PropFirst $r 'profilepath'
        SupportedEncTypes    = Get-PropFirst $r 'msds-supportedencryptiontypes'
    }
    $users.Add($obj)
}
$results.Dispose()

# ---------- export ----------
$exports = @(
    @{ Name = 'users_all';                  Data = $users },
    @{ Name = 'users_enabled';              Data = $users | Where-Object Enabled },
    @{ Name = 'users_disabled';             Data = $users | Where-Object { -not $_.Enabled } },
    @{ Name = 'users_admincount';           Data = $users | Where-Object { $_.AdminCount -eq 1 } },
    @{ Name = 'users_pwd_never_expires';    Data = $users | Where-Object PasswordNeverExpires },
    @{ Name = 'users_pwd_not_required';     Data = $users | Where-Object PasswordNotRequired },
    @{ Name = 'users_no_preauth';           Data = $users | Where-Object DontRequirePreAuth },
    @{ Name = 'users_with_spn';             Data = $users | Where-Object { $_.SPNCount -gt 0 } },
    @{ Name = 'users_trusted_for_deleg';    Data = $users | Where-Object { $_.TrustedForDelegation -or $_.TrustedToAuthForDeleg } },
    @{ Name = 'users_stale_' + $StaleDays + 'd'; Data = $users | Where-Object {
            $_.LastLogonTimestamp -and $_.LastLogonTimestamp -lt (Get-Date).AddDays(-$StaleDays)
        } },
    @{ Name = 'users_pwd_in_description';   Data = $users | Where-Object {
            $_.Description -and ($_.Description -match '(?i)pass|pwd|secret|temp\d|welcome|changeme')
        } }
)

foreach ($e in $exports) {
    $path = Join-Path $OutDir ($e.Name + '.csv')
    $data = @($e.Data)
    if ($data.Count -gt 0) {
        $data | Export-Csv -Path $path -NoTypeInformation -Encoding UTF8
    } else {
        # write an empty file with headers so the user sees the category was checked
        '' | Out-File -FilePath $path -Encoding UTF8
    }
    Write-Host ("[+] {0,-32} {1,6} rows -> {2}" -f $e.Name, $data.Count, $path) -ForegroundColor Green
}

Write-Host ""
Write-Host "[*] Done. Domain: $domainDnsRoot" -ForegroundColor Cyan
Write-Host "[*] Total users: $($users.Count)" -ForegroundColor Cyan
Write-Host "[*] Output: $OutDir" -ForegroundColor Cyan
