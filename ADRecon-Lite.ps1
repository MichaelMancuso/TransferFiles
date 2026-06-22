<#
.SYNOPSIS
    ADRecon-Lite - An ADRecon-style Active Directory reconnaissance & audit collector.

.DESCRIPTION
    Read-only Active Directory enumeration tool written in pure .NET (System.DirectoryServices),
    so it runs on a domain-joined host WITHOUT RSAT / the ActiveDirectory module, and also supports
    targeting a remote DC with alternate credentials (useful from a non-domain-joined assessment box).

    It collects the high-value artifacts an auditor / red-teamer / blue-teamer cares about and writes
    one CSV per category plus a self-contained HTML summary report that highlights notable findings
    (Kerberoastable & AS-REP-roastable accounts, delegation, PASSWD_NOTREQD, stale privileged accounts,
    LAPS coverage, DCSync-capable principals, etc.).

    This tool only READS directory data the supplied credentials are already authorized to read.
    It does not exploit anything, modify the directory, or recover/store secrets by default.

    ===================================================================================
    AUTHORIZED USE ONLY. Run this only against environments you own or are explicitly
    contracted/permitted to assess. You are responsible for staying within scope.
    ===================================================================================

.PARAMETER Server
    Target domain controller / LDAP server (FQDN or IP). Omit to use the current domain.

.PARAMETER Credential
    Alternate credentials (PSCredential). Omit to use the current security context.

.PARAMETER Username
    Convenience alternative to -Credential (DOMAIN\user or user@domain). Used with -Password.

.PARAMETER Password
    Plaintext password to pair with -Username (will be wrapped into a PSCredential).

.PARAMETER Collect
    One or more collectors, or 'All' (default). See ValidateSet for the full list.
    'ACLs' and 'DNS' are best-effort/heavier and are included in 'All'.

.PARAMETER OutputDir
    Output folder. Defaults to .\ADRecon-Lite-<timestamp>.

.PARAMETER DormantDays
    Threshold (days) for flagging dormant/stale accounts via lastLogonTimestamp. Default 90.

.PARAMETER PageSize
    LDAP paging size. Default 1000.

.PARAMETER IncludeJson
    Also emit JSON alongside each CSV.

.EXAMPLE
    .\ADRecon-Lite.ps1
    Run all collectors against the current domain using current credentials.

.EXAMPLE
    .\ADRecon-Lite.ps1 -Server dc01.corp.local -Username CORP\auditor -Password 'P@ss' -Collect Users,Computers,Delegation

.EXAMPLE
    $c = Get-Credential
    .\ADRecon-Lite.ps1 -Server 10.0.0.10 -Credential $c -OutputDir C:\Engagements\CORP

.NOTES
    Inspired by ADRecon (https://github.com/adrecon/ADRecon). Windows PowerShell 5.1 or PowerShell 7+ on Windows.
    Tip: validate against a lab domain first.
#>

[CmdletBinding()]
param(
    [string]$Server,
    [System.Management.Automation.PSCredential]$Credential,
    [string]$Username,
    [string]$Password,

    [ValidateSet('All','Forest','Domain','PasswordPolicy','FineGrainedPwdPolicy','DomainControllers',
                 'Trusts','Sites','Subnets','Users','Kerberoastable','ASREPRoastable','Computers',
                 'Groups','PrivilegedGroups','OUs','GPOs','GPLinks','Delegation','LAPS','DNS','ACLs')]
    [string[]]$Collect = @('All'),

    [string]$OutputDir = (".\ADRecon-Lite-" + (Get-Date -Format 'yyyyMMdd-HHmmss')),
    [int]$DormantDays = 90,
    [int]$PageSize = 1000,
    [switch]$IncludeJson
)

# ----------------------------------------------------------------------------------------------------
# Globals & helpers
# ----------------------------------------------------------------------------------------------------
$ErrorActionPreference = 'Continue'

$script:ADRServerPrefix = if ($Server) { "$Server/" } else { "" }
$script:ADRPageSize     = $PageSize
$script:ADRResults      = [ordered]@{}
$script:ADRUsersCache   = $null
$script:ADRComputersCache = $null
$script:ADRGroupsCache  = $null

# Resolve credentials
$script:ADRCred = $null
if ($Credential) {
    $script:ADRCred = $Credential
} elseif ($Username) {
    $sec = if ($Password) { ConvertTo-SecureString $Password -AsPlainText -Force } else { (Read-Host "Password for $Username" -AsSecureString) }
    $script:ADRCred = New-Object System.Management.Automation.PSCredential($Username, $sec)
}

# userAccountControl flags
$script:UACFlags = [ordered]@{
    SCRIPT=0x1; ACCOUNTDISABLE=0x2; HOMEDIR_REQUIRED=0x8; LOCKOUT=0x10; PASSWD_NOTREQD=0x20;
    PASSWD_CANT_CHANGE=0x40; ENCRYPTED_TEXT_PWD_ALLOWED=0x80; TEMP_DUPLICATE_ACCOUNT=0x100;
    NORMAL_ACCOUNT=0x200; INTERDOMAIN_TRUST_ACCOUNT=0x800; WORKSTATION_TRUST_ACCOUNT=0x1000;
    SERVER_TRUST_ACCOUNT=0x2000; DONT_EXPIRE_PASSWORD=0x10000; MNS_LOGON_ACCOUNT=0x20000;
    SMARTCARD_REQUIRED=0x40000; TRUSTED_FOR_DELEGATION=0x80000; NOT_DELEGATED=0x100000;
    USE_DES_KEY_ONLY=0x200000; DONT_REQ_PREAUTH=0x400000; PASSWORD_EXPIRED=0x800000;
    TRUSTED_TO_AUTH_FOR_DELEGATION=0x1000000; PARTIAL_SECRETS_ACCOUNT=0x4000000
}

# Extended-rights / well-known objectType GUIDs of interest for ACL analysis
$script:RightsGuidMap = @{
    '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2' = 'DS-Replication-Get-Changes'
    '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2' = 'DS-Replication-Get-Changes-All'
    '89e95b76-444d-4c62-991a-0facbeda640c' = 'DS-Replication-Get-Changes-In-Filtered-Set'
    '00299570-246d-11d0-a768-00aa006e0529' = 'User-Force-Change-Password'
    'bf9679c0-0de6-11d0-a285-00aa003049e2' = 'Self-Membership (add to group)'
}

$script:FuncLevelMap = @{ 0='2000'; 1='2003 Interim'; 2='2003'; 3='2008'; 4='2008 R2'; 5='2012'; 6='2012 R2'; 7='2016+' }
$script:SchemaMap    = @{ 13='2000'; 30='2003'; 31='2003 R2'; 44='2008'; 47='2008 R2'; 56='2012'; 69='2012 R2'; 87='2016'; 88='2019/2022' }

function Write-ADRLog {
    param([string]$Message, [string]$Color = 'Gray')
    Write-Host ("[{0}] {1}" -f (Get-Date -Format 'HH:mm:ss'), $Message) -ForegroundColor $Color
}

function New-ADREntry {
    param([string]$Path)
    if ($script:ADRCred) {
        New-Object System.DirectoryServices.DirectoryEntry($Path, $script:ADRCred.UserName, $script:ADRCred.GetNetworkCredential().Password)
    } else {
        New-Object System.DirectoryServices.DirectoryEntry($Path)
    }
}

function Invoke-ADRSearch {
    param(
        [string]$SearchBase,
        [string]$Filter = '(objectClass=*)',
        [string[]]$Properties = @(),
        [ValidateSet('Base','OneLevel','Subtree')][string]$Scope = 'Subtree',
        [switch]$SecurityDescriptor
    )
    if ([string]::IsNullOrEmpty($SearchBase)) { $SearchBase = $script:ADRDefaultNC }
    $root = New-ADREntry -Path ("LDAP://{0}{1}" -f $script:ADRServerPrefix, $SearchBase)
    $searcher = New-Object System.DirectoryServices.DirectorySearcher
    $searcher.SearchRoot      = $root
    $searcher.Filter          = $Filter
    $searcher.PageSize        = $script:ADRPageSize
    $searcher.SearchScope     = $Scope
    $searcher.ReferralChasing = [System.DirectoryServices.ReferralChasingOption]::None
    foreach ($p in $Properties) { [void]$searcher.PropertiesToLoad.Add($p) }
    if ($SecurityDescriptor) { $searcher.SecurityMasks = [System.DirectoryServices.SecurityMasks]'Owner,Group,Dacl' }

    $list = New-Object System.Collections.Generic.List[object]
    try {
        $found = $searcher.FindAll()
        foreach ($r in $found) { [void]$list.Add($r) }
    } catch {
        Write-ADRLog ("  ! LDAP query failed [{0}]: {1}" -f $Filter, $_.Exception.Message) 'Red'
    }
    ,$list.ToArray()
}

function Get-ADRProp    { param($Result,[string]$Name) if ($Result.Properties.Contains($Name) -and $Result.Properties[$Name].Count -gt 0) { $Result.Properties[$Name][0] } else { $null } }
function Get-ADRPropAll { param($Result,[string]$Name) if ($Result.Properties.Contains($Name)) { @($Result.Properties[$Name]) } else { @() } }

function Convert-ADRFileTime {
    param([Parameter(ValueFromPipeline=$true)]$Value)
    process {
        if ($null -eq $Value) { return $null }
        try { $l = [Int64]$Value } catch { return $null }
        if ($l -le 0 -or $l -eq 9223372036854775807) { return $null }
        try { [DateTime]::FromFileTimeUtc($l) } catch { $null }
    }
}

function Convert-ADRDuration {
    # Active Directory stores durations as negative 100-ns intervals.
    param($Value)
    if ($null -eq $Value) { return $null }
    try { $l = [Int64]$Value } catch { return $null }
    if ($l -eq 0) { return 0 }
    if ($l -eq -9223372036854775808) { return 'Never' }
    [math]::Round((-$l) / 864000000000.0, 2)   # 1e7 ticks/s * 86400 s/day
}

function Convert-ADRSid  { param($Bytes) if (-not $Bytes) { return $null } try { (New-Object System.Security.Principal.SecurityIdentifier([byte[]]$Bytes,0)).Value } catch { $null } }
function Convert-ADRGuid { param($Bytes) if (-not $Bytes) { return $null } try { (New-Object Guid (,([byte[]]$Bytes))).Guid } catch { $null } }

function Get-ADRUACList {
    param([int]$UAC)
    ($script:UACFlags.Keys | Where-Object { $UAC -band $script:UACFlags[$_] }) -join '|'
}

function Resolve-ADRSidName {
    param([string]$Sid)
    if (-not $Sid) { return $null }
    try { (New-Object System.Security.Principal.SecurityIdentifier($Sid)).Translate([System.Security.Principal.NTAccount]).Value }
    catch { $Sid }
}

function Export-ADRData {
    param($Data, [string]$Name)
    $arr = @($Data)
    $script:ADRResults[$Name] = $arr
    if ($arr.Count -eq 0) { Write-ADRLog ("  [{0}] no objects" -f $Name) 'DarkYellow'; return }
    $csv = Join-Path $OutputDir "$Name.csv"
    $arr | Export-Csv -Path $csv -NoTypeInformation -Encoding UTF8
    if ($IncludeJson) { $arr | ConvertTo-Json -Depth 4 | Out-File (Join-Path $OutputDir "$Name.json") -Encoding UTF8 }
    Write-ADRLog ("  [{0}] {1} object(s) -> {0}.csv" -f $Name, $arr.Count) 'Green'
}

# Ranged retrieval of a multi-valued attribute (handles groups with >1500 members).
function Get-ADRRangedAttribute {
    param([string]$DN, [string]$Attribute = 'member')
    $values = New-Object System.Collections.Generic.List[string]
    $start = 0; $step = 1500
    while ($true) {
        $ranged = "{0};range={1}-{2}" -f $Attribute, $start, ($start + $step - 1)
        $res = Invoke-ADRSearch -SearchBase $DN -Scope Base -Filter '(objectClass=*)' -Properties @($ranged)
        if (-not $res -or $res.Count -eq 0) { break }
        $r = $res[0]
        $rangeProp = $r.Properties.PropertyNames | Where-Object { $_ -like "$Attribute;range=*" } | Select-Object -First 1
        if (-not $rangeProp) {
            if ($r.Properties.Contains($Attribute)) { foreach ($v in $r.Properties[$Attribute]) { $values.Add([string]$v) } }
            break
        }
        foreach ($v in $r.Properties[$rangeProp]) { $values.Add([string]$v) }
        if ($rangeProp -match '-\*$') { break }   # '*' = final chunk
        $start += $step
    }
    $values
}

# ----------------------------------------------------------------------------------------------------
# Connection / RootDSE
# ----------------------------------------------------------------------------------------------------
function Connect-ADR {
    Write-ADRLog "[*] Connecting to RootDSE ..." 'Cyan'
    try {
        $rootDSE = New-ADREntry -Path ("LDAP://{0}RootDSE" -f $script:ADRServerPrefix)
        $script:ADRDefaultNC = [string]$rootDSE.Properties['defaultNamingContext'].Value
        $script:ADRConfigNC  = [string]$rootDSE.Properties['configurationNamingContext'].Value
        $script:ADRSchemaNC  = [string]$rootDSE.Properties['schemaNamingContext'].Value
        $script:ADRRootNC    = [string]$rootDSE.Properties['rootDomainNamingContext'].Value
        $script:ADRDomainFL  = [string]$rootDSE.Properties['domainFunctionality'].Value
        $script:ADRForestFL  = [string]$rootDSE.Properties['forestFunctionality'].Value
        $script:ADRDcFL      = [string]$rootDSE.Properties['domainControllerFunctionality'].Value
        $script:ADRDcName    = [string]$rootDSE.Properties['dnsHostName'].Value

        if ([string]::IsNullOrEmpty($script:ADRDefaultNC)) { throw "Empty defaultNamingContext - bind likely failed." }

        # Domain SID from the domain root object
        $dom = Invoke-ADRSearch -SearchBase $script:ADRDefaultNC -Scope Base -Filter '(objectClass=*)' -Properties @('objectsid')
        $script:ADRDomainSID = if ($dom.Count) { Convert-ADRSid (Get-ADRProp $dom[0] 'objectsid') } else { $null }
        $script:ADRIsForestRoot = ($script:ADRDefaultNC -eq $script:ADRRootNC)

        Write-ADRLog ("    Domain NC : {0}" -f $script:ADRDefaultNC) 'Gray'
        Write-ADRLog ("    Domain SID: {0}" -f $script:ADRDomainSID) 'Gray'
        Write-ADRLog ("    Bound DC  : {0}" -f $script:ADRDcName) 'Gray'
        return $true
    } catch {
        Write-ADRLog ("[!] Connection failed: {0}" -f $_.Exception.Message) 'Red'
        Write-ADRLog "    Check: server reachability (LDAP/389), credentials, and that you can resolve the domain." 'Red'
        return $false
    }
}

# ----------------------------------------------------------------------------------------------------
# Collectors
# ----------------------------------------------------------------------------------------------------
function Get-ADRForest {
    Write-ADRLog "[*] Collecting Forest ..." 'Cyan'
    $schemaVer = $null
    $sch = Invoke-ADRSearch -SearchBase $script:ADRSchemaNC -Scope Base -Filter '(objectClass=*)' -Properties @('objectversion')
    if ($sch.Count) { $schemaVer = (Get-ADRProp $sch[0] 'objectversion') -as [int] }

    $tombstone = $null
    $ds = Invoke-ADRSearch -SearchBase ("CN=Directory Service,CN=Windows NT,CN=Services," + $script:ADRConfigNC) -Scope Base -Filter '(objectClass=*)' -Properties @('tombstonelifetime')
    if ($ds.Count) { $tombstone = (Get-ADRProp $ds[0] 'tombstonelifetime') -as [int] }

    # Domains in the forest (crossRef partitions)
    $parts = Invoke-ADRSearch -SearchBase ("CN=Partitions," + $script:ADRConfigNC) -Filter '(&(objectCategory=crossRef)(systemFlags:1.2.840.113556.1.4.803:=2))' -Properties @('dnsroot','ncname')
    $domains = ($parts | ForEach-Object { Get-ADRProp $_ 'dnsroot' }) -join ';'

    $out = [PSCustomObject][ordered]@{
        ForestName            = ($script:ADRRootNC -replace '^DC=' -replace ',DC=', '.')
        ForestFunctionalLevel = $script:FuncLevelMap[[string]$script:ADRForestFL]
        DomainFunctionalLevel = $script:FuncLevelMap[[string]$script:ADRDomainFL]
        SchemaVersion         = $schemaVer
        SchemaOSGuess         = $script:SchemaMap[[string]$schemaVer]
        TombstoneLifetimeDays = $tombstone
        DomainsInForest       = $domains
        RootDomainNC          = $script:ADRRootNC
    }
    Export-ADRData -Data $out -Name 'Forest'
}

function Get-ADRDomain {
    Write-ADRLog "[*] Collecting Domain ..." 'Cyan'
    $props = @('name','objectsid','whencreated','ms-ds-machineaccountquota','maxpwdage','minpwdage',
               'minpwdlength','pwdhistorylength','lockoutthreshold','lockoutduration','lockoutobservationwindow','pwdproperties')
    $res = Invoke-ADRSearch -SearchBase $script:ADRDefaultNC -Scope Base -Filter '(objectClass=*)' -Properties $props
    if (-not $res.Count) { return }
    $r = $res[0]
    $out = [PSCustomObject][ordered]@{
        DomainName            = ($script:ADRDefaultNC -replace '^DC=' -replace ',DC=', '.')
        DomainSID             = Convert-ADRSid (Get-ADRProp $r 'objectsid')
        DomainFunctionalLevel = $script:FuncLevelMap[[string]$script:ADRDomainFL]
        IsForestRoot          = $script:ADRIsForestRoot
        MachineAccountQuota   = (Get-ADRProp $r 'ms-ds-machineaccountquota') -as [int]
        Created               = $(try { ([datetime](Get-ADRProp $r 'whencreated')).ToString('u') } catch { $null })
    }
    Export-ADRData -Data $out -Name 'Domain'
}

function Get-ADRPasswordPolicy {
    Write-ADRLog "[*] Collecting Default Password Policy ..." 'Cyan'
    $props = @('maxpwdage','minpwdage','minpwdlength','pwdhistorylength','lockoutthreshold','lockoutduration','lockoutobservationwindow','pwdproperties')
    $res = Invoke-ADRSearch -SearchBase $script:ADRDefaultNC -Scope Base -Filter '(objectClass=*)' -Properties $props
    if (-not $res.Count) { return }
    $r = $res[0]
    $pwdProps = (Get-ADRProp $r 'pwdproperties') -as [int]
    $out = [PSCustomObject][ordered]@{
        MinPasswordLength     = (Get-ADRProp $r 'minpwdlength') -as [int]
        PasswordHistoryLength = (Get-ADRProp $r 'pwdhistorylength') -as [int]
        ComplexityEnabled     = [bool]($pwdProps -band 0x1)
        ReversibleEncryption  = [bool]($pwdProps -band 0x10)
        MaxPasswordAgeDays     = Convert-ADRDuration (Get-ADRProp $r 'maxpwdage')
        MinPasswordAgeDays     = Convert-ADRDuration (Get-ADRProp $r 'minpwdage')
        LockoutThreshold       = (Get-ADRProp $r 'lockoutthreshold') -as [int]
        LockoutDurationMin     = $(if ((Convert-ADRDuration (Get-ADRProp $r 'lockoutduration')) -is [double]) { (Convert-ADRDuration (Get-ADRProp $r 'lockoutduration')) * 1440 } else { Convert-ADRDuration (Get-ADRProp $r 'lockoutduration') })
        LockoutWindowMin       = $(if ((Convert-ADRDuration (Get-ADRProp $r 'lockoutobservationwindow')) -is [double]) { (Convert-ADRDuration (Get-ADRProp $r 'lockoutobservationwindow')) * 1440 } else { Convert-ADRDuration (Get-ADRProp $r 'lockoutobservationwindow') })
    }
    Export-ADRData -Data $out -Name 'PasswordPolicy'
}

function Get-ADRFineGrainedPwdPolicy {
    Write-ADRLog "[*] Collecting Fine-Grained Password Policies ..." 'Cyan'
    $base = "CN=Password Settings Container,CN=System," + $script:ADRDefaultNC
    $props = @('cn','msds-passwordsettingsprecedence','msds-minimumpasswordlength','msds-passwordhistorylength',
               'msds-lockoutthreshold','msds-maximumpasswordage','msds-minimumpasswordage','msds-lockoutobservationwindow',
               'msds-lockoutduration','msds-passwordcomplexityenabled','msds-passwordreversibleencryptionenabled','msds-psoappliesto')
    $res = Invoke-ADRSearch -SearchBase $base -Filter '(objectClass=msDS-PasswordSettings)' -Properties $props
    $out = foreach ($r in $res) {
        [PSCustomObject][ordered]@{
            Name              = Get-ADRProp $r 'cn'
            Precedence        = (Get-ADRProp $r 'msds-passwordsettingsprecedence') -as [int]
            MinLength         = (Get-ADRProp $r 'msds-minimumpasswordlength') -as [int]
            HistoryLength     = (Get-ADRProp $r 'msds-passwordhistorylength') -as [int]
            ComplexityEnabled = [bool](Get-ADRProp $r 'msds-passwordcomplexityenabled')
            Reversible        = [bool](Get-ADRProp $r 'msds-passwordreversibleencryptionenabled')
            MaxAgeDays        = Convert-ADRDuration (Get-ADRProp $r 'msds-maximumpasswordage')
            LockoutThreshold  = (Get-ADRProp $r 'msds-lockoutthreshold') -as [int]
            AppliesTo         = (Get-ADRPropAll $r 'msds-psoappliesto') -join ';'
        }
    }
    Export-ADRData -Data $out -Name 'FineGrainedPwdPolicy'
}

function Get-ADRDomainControllers {
    Write-ADRLog "[*] Collecting Domain Controllers ..." 'Cyan'
    $props = @('samaccountname','dnshostname','operatingsystem','operatingsystemversion','useraccountcontrol','whencreated','serviceprincipalname')
    $res = Invoke-ADRSearch -Filter '(userAccountControl:1.2.840.113556.1.4.803:=8192)' -Properties $props
    $out = foreach ($r in $res) {
        $uac = (Get-ADRProp $r 'useraccountcontrol') -as [int]
        [PSCustomObject][ordered]@{
            Name        = Get-ADRProp $r 'samaccountname'
            DNSHostName = Get-ADRProp $r 'dnshostname'
            OS          = Get-ADRProp $r 'operatingsystem'
            OSVersion   = Get-ADRProp $r 'operatingsystemversion'
            IsRODC      = [bool]($uac -band 0x4000000)
            Created     = $(try { ([datetime](Get-ADRProp $r 'whencreated')).ToString('u') } catch { $null })
        }
    }
    Export-ADRData -Data $out -Name 'DomainControllers'
}

function Get-ADRTrusts {
    Write-ADRLog "[*] Collecting Trusts ..." 'Cyan'
    $base = "CN=System," + $script:ADRDefaultNC
    $props = @('trustpartner','flatname','trustdirection','trusttype','trustattributes','securityidentifier','whencreated')
    $res = Invoke-ADRSearch -SearchBase $base -Filter '(objectClass=trustedDomain)' -Properties $props
    $dirMap  = @{ 1='Inbound'; 2='Outbound'; 3='Bidirectional' }
    $typeMap = @{ 1='Downlevel(NT)'; 2='Uplevel(AD)'; 3='MIT'; 4='DCE' }
    $out = foreach ($r in $res) {
        $attr = (Get-ADRProp $r 'trustattributes') -as [int]
        $flags = @()
        if ($attr -band 0x1)  { $flags += 'NonTransitive' }
        if ($attr -band 0x4)  { $flags += 'Quarantined(SIDFiltering)' }
        if ($attr -band 0x8)  { $flags += 'ForestTransitive' }
        if ($attr -band 0x20) { $flags += 'WithinForest' }
        if ($attr -band 0x40) { $flags += 'TreatAsExternal' }
        if ($attr -band 0x800){ $flags += 'TGTDelegationEnabled' }
        [PSCustomObject][ordered]@{
            TrustPartner   = Get-ADRProp $r 'trustpartner'
            FlatName       = Get-ADRProp $r 'flatname'
            Direction      = $dirMap[[int](Get-ADRProp $r 'trustdirection')]
            Type           = $typeMap[[int](Get-ADRProp $r 'trusttype')]
            Attributes     = ($flags -join '|')
            SIDFiltering   = [bool]($attr -band 0x4)
            PartnerSID     = Convert-ADRSid (Get-ADRProp $r 'securityidentifier')
            Created        = $(try { ([datetime](Get-ADRProp $r 'whencreated')).ToString('u') } catch { $null })
        }
    }
    Export-ADRData -Data $out -Name 'Trusts'
}

function Get-ADRSites {
    Write-ADRLog "[*] Collecting Sites ..." 'Cyan'
    $base = "CN=Sites," + $script:ADRConfigNC
    $res = Invoke-ADRSearch -SearchBase $base -Filter '(objectClass=site)' -Properties @('cn','description','whencreated')
    $out = foreach ($r in $res) {
        [PSCustomObject][ordered]@{ Name=Get-ADRProp $r 'cn'; Description=Get-ADRProp $r 'description'; Created=$(try{([datetime](Get-ADRProp $r 'whencreated')).ToString('u')}catch{$null}) }
    }
    Export-ADRData -Data $out -Name 'Sites'
}

function Get-ADRSubnets {
    Write-ADRLog "[*] Collecting Subnets ..." 'Cyan'
    $base = "CN=Subnets,CN=Sites," + $script:ADRConfigNC
    $res = Invoke-ADRSearch -SearchBase $base -Filter '(objectClass=subnet)' -Properties @('cn','siteobject','description','location')
    $out = foreach ($r in $res) {
        $site = [string](Get-ADRProp $r 'siteobject'); if ($site) { $site = ($site -split ',')[0] -replace '^CN=' }
        [PSCustomObject][ordered]@{ Subnet=Get-ADRProp $r 'cn'; Site=$site; Location=Get-ADRProp $r 'location'; Description=Get-ADRProp $r 'description' }
    }
    Export-ADRData -Data $out -Name 'Subnets'
}

function Get-ADRUsers {
    Write-ADRLog "[*] Collecting Users (this can take a while) ..." 'Cyan'
    $props = @('samaccountname','userprincipalname','displayname','mail','useraccountcontrol','pwdlastset',
               'lastlogontimestamp','whencreated','accountexpires','admincount','serviceprincipalname',
               'description','objectsid','distinguishedname','badpwdcount','logoncount','sidhistory','title','department')
    $res = Invoke-ADRSearch -Filter '(samAccountType=805306368)' -Properties $props
    $now = (Get-Date).ToUniversalTime()
    $out = foreach ($r in $res) {
        $uac = (Get-ADRProp $r 'useraccountcontrol') -as [int]; if ($null -eq $uac) { $uac = 0 }
        $pwdLong = (Get-ADRProp $r 'pwdlastset') -as [long]; if ($null -eq $pwdLong) { $pwdLong = 0 }
        $pwdSet = if ($pwdLong -gt 0) { [DateTime]::FromFileTimeUtc($pwdLong) } else { $null }
        $ll = (Get-ADRProp $r 'lastlogontimestamp') | Convert-ADRFileTime
        $spns = Get-ADRPropAll $r 'serviceprincipalname'
        [PSCustomObject][ordered]@{
            SamAccountName       = Get-ADRProp $r 'samaccountname'
            Enabled              = -not ($uac -band 0x2)
            UserPrincipalName    = Get-ADRProp $r 'userprincipalname'
            DisplayName          = Get-ADRProp $r 'displayname'
            AdminCount           = (((Get-ADRProp $r 'admincount') -as [int]) -eq 1)
            PasswordNotRequired  = [bool]($uac -band 0x20)
            PasswordNeverExpires = [bool]($uac -band 0x10000)
            PasswordMustChange   = ($pwdLong -eq 0)
            SmartcardRequired    = [bool]($uac -band 0x40000)
            DesKeyOnly           = [bool]($uac -band 0x200000)
            ASREPRoastable       = [bool]($uac -band 0x400000)
            Kerberoastable       = ($spns.Count -gt 0)
            UnconstrainedDeleg   = [bool]($uac -band 0x80000)
            HasSIDHistory        = ((Get-ADRPropAll $r 'sidhistory').Count -gt 0)
            PasswordAgeDays      = $(if ($pwdSet) { [math]::Round(($now - $pwdSet).TotalDays,1) } else { $null })
            PasswordLastSet      = $(if ($pwdSet) { $pwdSet.ToString('u') } else { $null })
            LastLogonTimestamp   = $(if ($ll) { $ll.ToString('u') } else { $null })
            Dormant              = $(if ($ll) { ($now - $ll).TotalDays -gt $DormantDays } else { $true })
            BadPwdCount          = (Get-ADRProp $r 'badpwdcount') -as [int]
            LogonCount           = (Get-ADRProp $r 'logoncount') -as [int]
            Description          = Get-ADRProp $r 'description'
            SPNCount             = $spns.Count
            SPNs                 = ($spns -join ';')
            SID                  = Convert-ADRSid (Get-ADRProp $r 'objectsid')
            DistinguishedName    = Get-ADRProp $r 'distinguishedname'
            UACFlags             = Get-ADRUACList $uac
        }
    }
    Export-ADRData -Data $out -Name 'Users'
    $script:ADRUsersCache = $out
}

function Get-ADRKerberoastable {
    Write-ADRLog "[*] Deriving Kerberoastable accounts ..." 'Cyan'
    if (-not $script:ADRUsersCache) { Get-ADRUsers }
    $k = $script:ADRUsersCache | Where-Object { $_.Kerberoastable -and $_.SamAccountName -ne 'krbtgt' } |
         Select-Object SamAccountName,Enabled,AdminCount,PasswordAgeDays,LastLogonTimestamp,SPNs,SID,DistinguishedName
    Export-ADRData -Data $k -Name 'Kerberoastable'
}

function Get-ADRASREPRoastable {
    Write-ADRLog "[*] Deriving AS-REP-roastable accounts ..." 'Cyan'
    if (-not $script:ADRUsersCache) { Get-ADRUsers }
    $a = $script:ADRUsersCache | Where-Object { $_.ASREPRoastable } |
         Select-Object SamAccountName,Enabled,AdminCount,PasswordAgeDays,LastLogonTimestamp,SID,DistinguishedName
    Export-ADRData -Data $a -Name 'ASREPRoastable'
}

function Get-ADRComputers {
    Write-ADRLog "[*] Collecting Computers ..." 'Cyan'
    $props = @('samaccountname','dnshostname','operatingsystem','operatingsystemversion','useraccountcontrol',
               'lastlogontimestamp','whencreated','objectsid','distinguishedname','description',
               'ms-mcs-admpwdexpirationtime','mslaps-passwordexpirationtime',
               'msds-allowedtoactonbehalfofotheridentity','msds-allowedtodelegateto')
    $res = Invoke-ADRSearch -Filter '(samAccountType=805306369)' -Properties $props
    $now = (Get-Date).ToUniversalTime()
    $out = foreach ($r in $res) {
        $uac = (Get-ADRProp $r 'useraccountcontrol') -as [int]; if ($null -eq $uac) { $uac = 0 }
        $ll  = (Get-ADRProp $r 'lastlogontimestamp') | Convert-ADRFileTime
        $cd  = Get-ADRPropAll $r 'msds-allowedtodelegateto'
        $rbcd = (Get-ADRPropAll $r 'msds-allowedtoactonbehalfofotheridentity').Count -gt 0
        $lapsExp = $null
        foreach ($la in @('ms-mcs-admpwdexpirationtime','mslaps-passwordexpirationtime')) {
            $v = Get-ADRProp $r $la; if ($v) { $lapsExp = ($v | Convert-ADRFileTime); break }
        }
        [PSCustomObject][ordered]@{
            Name                    = Get-ADRProp $r 'samaccountname'
            Enabled                 = -not ($uac -band 0x2)
            DNSHostName             = Get-ADRProp $r 'dnshostname'
            OperatingSystem         = Get-ADRProp $r 'operatingsystem'
            OSVersion               = Get-ADRProp $r 'operatingsystemversion'
            LastLogonTimestamp      = $(if ($ll) { $ll.ToString('u') } else { $null })
            Dormant                 = $(if ($ll) { ($now - $ll).TotalDays -gt $DormantDays } else { $true })
            UnconstrainedDelegation = [bool]($uac -band 0x80000)
            ConstrainedDelegation   = ($cd.Count -gt 0)
            ConstrainedTargets      = ($cd -join ';')
            ResourceBasedCD         = $rbcd
            LAPS_Present            = [bool]$lapsExp
            LAPS_ExpiresUTC         = $(if ($lapsExp) { $lapsExp.ToString('u') } else { $null })
            SID                     = Convert-ADRSid (Get-ADRProp $r 'objectsid')
            DistinguishedName       = Get-ADRProp $r 'distinguishedname'
            UACFlags                = Get-ADRUACList $uac
        }
    }
    Export-ADRData -Data $out -Name 'Computers'
    $script:ADRComputersCache = $out
}

function Get-ADRGroups {
    Write-ADRLog "[*] Collecting Groups ..." 'Cyan'
    $props = @('samaccountname','distinguishedname','grouptype','admincount','member','description','objectsid','whencreated')
    $res = Invoke-ADRSearch -Filter '(objectCategory=group)' -Properties $props
    $out = foreach ($r in $res) {
        $gt = (Get-ADRProp $r 'grouptype') -as [int]; if ($null -eq $gt) { $gt = 0 }
        $scope = if ($gt -band 0x2) { 'Global' } elseif ($gt -band 0x4) { 'DomainLocal' } elseif ($gt -band 0x8) { 'Universal' } else { 'Unknown' }
        [PSCustomObject][ordered]@{
            Name              = Get-ADRProp $r 'samaccountname'
            Scope             = $scope
            Security          = [bool]($gt -band 0x80000000)
            AdminCount        = (((Get-ADRProp $r 'admincount') -as [int]) -eq 1)
            DirectMemberCount = (Get-ADRPropAll $r 'member').Count
            Description       = Get-ADRProp $r 'description'
            SID               = Convert-ADRSid (Get-ADRProp $r 'objectsid')
            DistinguishedName = Get-ADRProp $r 'distinguishedname'
        }
    }
    Export-ADRData -Data $out -Name 'Groups'
    $script:ADRGroupsCache = $out
}

function Get-ADRPrivilegedGroups {
    Write-ADRLog "[*] Collecting Privileged Group Membership ..." 'Cyan'
    if (-not $script:ADRGroupsCache) { Get-ADRGroups }
    $d = $script:ADRDomainSID
    $targets = [ordered]@{
        'Domain Admins'                 = "$d-512"
        'Group Policy Creator Owners'   = "$d-520"
        'Cert Publishers'               = "$d-517"
        'Administrators'                = 'S-1-5-32-544'
        'Account Operators'             = 'S-1-5-32-548'
        'Backup Operators'              = 'S-1-5-32-551'
        'Server Operators'              = 'S-1-5-32-549'
        'Print Operators'               = 'S-1-5-32-550'
        'Remote Desktop Users'          = 'S-1-5-32-555'
    }
    if ($script:ADRIsForestRoot) {
        $targets['Enterprise Admins'] = "$d-519"
        $targets['Schema Admins']     = "$d-518"
    }

    $rows = New-Object System.Collections.Generic.List[object]
    foreach ($name in $targets.Keys) {
        $sid = $targets[$name]
        $grp = $script:ADRGroupsCache | Where-Object { $_.SID -eq $sid } | Select-Object -First 1
        if (-not $grp) {
            # DnsAdmins / others without a fixed RID: match by name later if needed
            continue
        }
        $members = Get-ADRRangedAttribute -DN $grp.DistinguishedName -Attribute 'member'
        if ($members.Count -gt 500) {
            $rows.Add([PSCustomObject][ordered]@{ Group=$name; MemberSam='<'+$members.Count+' members - resolution skipped>'; MemberType=''; Enabled=''; MemberDN='' })
            continue
        }
        foreach ($mdn in $members) {
            $m = Invoke-ADRSearch -SearchBase $mdn -Scope Base -Filter '(objectClass=*)' -Properties @('samaccountname','objectclass','useraccountcontrol')
            $sam=$null; $cls=$null; $en=$null
            if ($m.Count) {
                $sam = Get-ADRProp $m[0] 'samaccountname'
                $cls = (Get-ADRPropAll $m[0] 'objectclass')[-1]
                $u   = (Get-ADRProp $m[0] 'useraccountcontrol') -as [int]
                if ($null -ne $u) { $en = -not ($u -band 0x2) }
            }
            $rows.Add([PSCustomObject][ordered]@{ Group=$name; MemberSam=$sam; MemberType=$cls; Enabled=$en; MemberDN=$mdn })
        }
    }
    # DnsAdmins by name (no fixed RID, often high-value)
    $dnsAdmins = $script:ADRGroupsCache | Where-Object { $_.Name -eq 'DnsAdmins' } | Select-Object -First 1
    if ($dnsAdmins) {
        foreach ($mdn in (Get-ADRRangedAttribute -DN $dnsAdmins.DistinguishedName -Attribute 'member')) {
            $m = Invoke-ADRSearch -SearchBase $mdn -Scope Base -Filter '(objectClass=*)' -Properties @('samaccountname','objectclass')
            $rows.Add([PSCustomObject][ordered]@{ Group='DnsAdmins'; MemberSam=$(if($m.Count){Get-ADRProp $m[0] 'samaccountname'}); MemberType=$(if($m.Count){(Get-ADRPropAll $m[0] 'objectclass')[-1]}); Enabled=''; MemberDN=$mdn })
        }
    }
    Export-ADRData -Data $rows -Name 'PrivilegedGroupMembers'
}

function Get-ADROUs {
    Write-ADRLog "[*] Collecting OUs ..." 'Cyan'
    $res = Invoke-ADRSearch -Filter '(objectCategory=organizationalUnit)' -Properties @('ou','distinguishedname','description','gplink','whencreated')
    $out = foreach ($r in $res) {
        [PSCustomObject][ordered]@{
            Name              = Get-ADRProp $r 'ou'
            Description       = Get-ADRProp $r 'description'
            LinkedGPOs        = ((Get-ADRProp $r 'gplink') -split '\]\[' | Where-Object { $_ -match 'cn=\{' }).Count
            Created           = $(try { ([datetime](Get-ADRProp $r 'whencreated')).ToString('u') } catch { $null })
            DistinguishedName = Get-ADRProp $r 'distinguishedname'
        }
    }
    Export-ADRData -Data $out -Name 'OUs'
}

function Get-ADRGPOs {
    Write-ADRLog "[*] Collecting GPOs ..." 'Cyan'
    $res = Invoke-ADRSearch -Filter '(objectCategory=groupPolicyContainer)' -Properties @('displayname','name','gpcfilesyspath','versionnumber','flags','whencreated','whenchanged')
    $flagMap = @{ 0='AllEnabled'; 1='UserDisabled'; 2='ComputerDisabled'; 3='AllDisabled' }
    $out = foreach ($r in $res) {
        [PSCustomObject][ordered]@{
            DisplayName = Get-ADRProp $r 'displayname'
            GUID        = (Get-ADRProp $r 'name')
            Status      = $flagMap[[int]((Get-ADRProp $r 'flags') -as [int])]
            Version     = (Get-ADRProp $r 'versionnumber') -as [int]
            FileSysPath = Get-ADRProp $r 'gpcfilesyspath'
            Created     = $(try { ([datetime](Get-ADRProp $r 'whencreated')).ToString('u') } catch { $null })
            Modified    = $(try { ([datetime](Get-ADRProp $r 'whenchanged')).ToString('u') } catch { $null })
        }
    }
    Export-ADRData -Data $out -Name 'GPOs'
    $script:ADRGPOCache = $out
}

function Get-ADRGPLinks {
    Write-ADRLog "[*] Collecting GP Links ..." 'Cyan'
    if (-not $script:ADRGPOCache) { Get-ADRGPOs }
    $gpoByGuid = @{}; foreach ($g in $script:ADRGPOCache) { if ($g.GUID) { $gpoByGuid[$g.GUID.ToLower()] = $g.DisplayName } }

    # Domain root + all OUs carry gPLink
    $scoped = Invoke-ADRSearch -Filter '(|(objectClass=domainDNS)(objectCategory=organizationalUnit))' -Properties @('distinguishedname','gplink')
    $rows = New-Object System.Collections.Generic.List[object]
    foreach ($r in $scoped) {
        $gplink = [string](Get-ADRProp $r 'gplink')
        if (-not $gplink) { continue }
        foreach ($m in [regex]::Matches($gplink, '\[LDAP://(?<dn>[^;]+);(?<opt>\d)\]')) {
            $dn = $m.Groups['dn'].Value
            $guid = $null
            if ($dn -match 'cn=\{(?<g>[0-9A-Fa-f\-]+)\}') { $guid = "{$($Matches['g'])}" }
            $opt = [int]$m.Groups['opt'].Value
            $status = switch ($opt) { 0 {'Enabled'} 1 {'Disabled'} 2 {'Enforced'} 3 {'Disabled+Enforced'} default {"Opt$opt"} }
            $rows.Add([PSCustomObject][ordered]@{
                Target  = Get-ADRProp $r 'distinguishedname'
                GPOName = $(if ($guid -and $gpoByGuid.ContainsKey($guid.ToLower())) { $gpoByGuid[$guid.ToLower()] } else { $guid })
                GPOGuid = $guid
                Status  = $status
            })
        }
    }
    Export-ADRData -Data $rows -Name 'GPLinks'
}

function Get-ADRDelegation {
    Write-ADRLog "[*] Collecting Delegation (unconstrained / constrained / RBCD) ..." 'Cyan'
    $rows = New-Object System.Collections.Generic.List[object]

    # Unconstrained (exclude DCs which legitimately hold it - still report but flag)
    $uc = Invoke-ADRSearch -Filter '(userAccountControl:1.2.840.113556.1.4.803:=524288)' -Properties @('samaccountname','distinguishedname','useraccountcontrol','objectclass')
    foreach ($r in $uc) {
        $uac = (Get-ADRProp $r 'useraccountcontrol') -as [int]
        $rows.Add([PSCustomObject][ordered]@{
            Type='Unconstrained'; Account=Get-ADRProp $r 'samaccountname'
            ObjectClass=(Get-ADRPropAll $r 'objectclass')[-1]
            IsDC=[bool]($uac -band 0x2000); Target=''; DistinguishedName=Get-ADRProp $r 'distinguishedname'
        })
    }
    # Constrained (msDS-AllowedToDelegateTo)
    $cd = Invoke-ADRSearch -Filter '(msDS-AllowedToDelegateTo=*)' -Properties @('samaccountname','distinguishedname','msds-allowedtodelegateto','objectclass','useraccountcontrol')
    foreach ($r in $cd) {
        $uac = (Get-ADRProp $r 'useraccountcontrol') -as [int]
        $protoTrans = [bool]($uac -band 0x1000000)
        foreach ($t in (Get-ADRPropAll $r 'msds-allowedtodelegateto')) {
            $rows.Add([PSCustomObject][ordered]@{
                Type=$(if($protoTrans){'Constrained+ProtocolTransition'}else{'Constrained'})
                Account=Get-ADRProp $r 'samaccountname'; ObjectClass=(Get-ADRPropAll $r 'objectclass')[-1]
                IsDC=''; Target=$t; DistinguishedName=Get-ADRProp $r 'distinguishedname'
            })
        }
    }
    # Resource-based (msDS-AllowedToActOnBehalfOfOtherIdentity)
    $rb = Invoke-ADRSearch -Filter '(msDS-AllowedToActOnBehalfOfOtherIdentity=*)' -Properties @('samaccountname','distinguishedname','objectclass')
    foreach ($r in $rb) {
        $rows.Add([PSCustomObject][ordered]@{
            Type='Resource-Based(RBCD)'; Account=Get-ADRProp $r 'samaccountname'
            ObjectClass=(Get-ADRPropAll $r 'objectclass')[-1]; IsDC=''
            Target='<see msDS-AllowedToActOnBehalfOfOtherIdentity ACL>'; DistinguishedName=Get-ADRProp $r 'distinguishedname'
        })
    }
    Export-ADRData -Data $rows -Name 'Delegation'
}

function Get-ADRLAPS {
    Write-ADRLog "[*] Collecting LAPS coverage / readability ..." 'Cyan'
    # Expiration attributes are world-readable (presence => LAPS deployed). The secret attributes are
    # only returned if the current principal is permitted - we report READABILITY but never write secrets.
    $props = @('samaccountname','dnshostname','ms-mcs-admpwd','ms-mcs-admpwdexpirationtime','mslaps-password','mslaps-encryptedpassword','mslaps-passwordexpirationtime')
    $filter = '(&(samAccountType=805306369)(|(ms-mcs-admpwdexpirationtime=*)(mslaps-passwordexpirationtime=*)))'
    $res = Invoke-ADRSearch -Filter $filter -Properties $props
    $out = foreach ($r in $res) {
        $legacy = Get-ADRProp $r 'ms-mcs-admpwd'
        $clear  = Get-ADRProp $r 'mslaps-password'
        $enc    = Get-ADRProp $r 'mslaps-encryptedpassword'
        [PSCustomObject][ordered]@{
            Computer                = Get-ADRProp $r 'samaccountname'
            DNSHostName             = Get-ADRProp $r 'dnshostname'
            LegacyLAPS              = [bool](Get-ADRProp $r 'ms-mcs-admpwdexpirationtime')
            WindowsLAPS             = [bool](Get-ADRProp $r 'mslaps-passwordexpirationtime')
            LegacyPasswordReadable  = [bool]$legacy
            WindowsPasswordReadable = [bool]($clear -or $enc)
        }
    }
    Export-ADRData -Data $out -Name 'LAPS'
    Write-ADRLog "    (Cleartext LAPS secrets are intentionally NOT written to disk by default.)" 'DarkGray'
}

function Get-ADRDNS {
    Write-ADRLog "[*] Collecting DNS Zones (best-effort) ..." 'Cyan'
    $bases = @(
        ("DC=DomainDnsZones," + $script:ADRDefaultNC),
        ("DC=ForestDnsZones," + $script:ADRRootNC),
        ("CN=MicrosoftDNS,CN=System," + $script:ADRDefaultNC)
    )
    $rows = New-Object System.Collections.Generic.List[object]
    foreach ($b in $bases) {
        $res = Invoke-ADRSearch -SearchBase $b -Filter '(objectClass=dnsZone)' -Properties @('name','whencreated')
        foreach ($r in $res) {
            $rows.Add([PSCustomObject][ordered]@{ Zone=Get-ADRProp $r 'name'; Partition=($b -split ',')[0]; Created=$(try{([datetime](Get-ADRProp $r 'whencreated')).ToString('u')}catch{$null}) })
        }
    }
    Export-ADRData -Data ($rows | Sort-Object Zone -Unique) -Name 'DNSZones'
}

function Get-ADRACLs {
    Write-ADRLog "[*] Collecting ACLs on high-value objects (best-effort) ..." 'Cyan'
    # Scoped (for runtime sanity) to: domain root, AdminSDHolder, and privileged group objects.
    # Flags dangerous rights (GenericAll/WriteDacl/WriteOwner/AllExtendedRights) and DCSync replication rights.
    $targets = New-Object System.Collections.Generic.List[string]
    $targets.Add($script:ADRDefaultNC)
    $targets.Add("CN=AdminSDHolder,CN=System," + $script:ADRDefaultNC)
    if ($script:ADRGroupsCache) {
        foreach ($g in ($script:ADRGroupsCache | Where-Object { $_.AdminCount })) { $targets.Add($g.DistinguishedName) }
    }

    $dangerous = @('GenericAll','WriteDacl','WriteOwner','GenericWrite','AllExtendedRights')
    $rows = New-Object System.Collections.Generic.List[object]
    foreach ($dn in ($targets | Sort-Object -Unique)) {
        $res = Invoke-ADRSearch -SearchBase $dn -Scope Base -Filter '(objectClass=*)' -Properties @('ntsecuritydescriptor','distinguishedname') -SecurityDescriptor
        if (-not $res.Count) { continue }
        $raw = Get-ADRProp $res[0] 'ntsecuritydescriptor'
        if (-not $raw) { continue }
        $sd = New-Object System.DirectoryServices.ActiveDirectorySecurity
        try { $sd.SetSecurityDescriptorBinaryForm([byte[]]$raw) } catch { continue }
        foreach ($ace in $sd.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])) {
            $rights = $ace.ActiveDirectoryRights.ToString()
            $objType = $ace.ObjectType.ToString()
            $rightName = if ($script:RightsGuidMap.ContainsKey($objType)) { $script:RightsGuidMap[$objType] } else { $null }
            $isDangerous = ($dangerous | Where-Object { $rights -match $_ }).Count -gt 0
            $isRepl = $rightName -like 'DS-Replication-Get-Changes*'
            if ($ace.AccessControlType -eq 'Allow' -and ($isDangerous -or $isRepl)) {
                $rows.Add([PSCustomObject][ordered]@{
                    ObjectDN   = $dn
                    Trustee    = Resolve-ADRSidName ($ace.IdentityReference.Value)
                    TrusteeSID = $ace.IdentityReference.Value
                    Rights     = $rights
                    ExtRight   = $rightName
                    Inherited  = $ace.IsInherited
                    DCSyncCapable = $isRepl
                })
            }
        }
    }
    Export-ADRData -Data $rows -Name 'ACLs-HighValue'
}

# ----------------------------------------------------------------------------------------------------
# HTML summary report
# ----------------------------------------------------------------------------------------------------
function ConvertTo-ADRHtmlTable {
    param($Data, [string[]]$Columns, [int]$Max = 250)
    $arr = @($Data)
    if ($arr.Count -eq 0) { return "<p class='none'>None found.</p>" }
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append("<table><thead><tr>")
    foreach ($c in $Columns) { [void]$sb.Append("<th>$c</th>") }
    [void]$sb.Append("</tr></thead><tbody>")
    foreach ($row in ($arr | Select-Object -First $Max)) {
        [void]$sb.Append("<tr>")
        foreach ($c in $Columns) {
            $v = [System.Web.HttpUtility]::HtmlEncode([string]$row.$c)
            [void]$sb.Append("<td>$v</td>")
        }
        [void]$sb.Append("</tr>")
    }
    [void]$sb.Append("</tbody></table>")
    if ($arr.Count -gt $Max) { [void]$sb.Append("<p class='more'>... $($arr.Count - $Max) more row(s) in the CSV.</p>") }
    $sb.ToString()
}

function New-ADRReport {
    Write-ADRLog "[*] Building HTML summary report ..." 'Cyan'
    Add-Type -AssemblyName System.Web -ErrorAction SilentlyContinue

    $users = @($script:ADRResults['Users'])
    $comps = @($script:ADRResults['Computers'])

    $kerb   = @($script:ADRResults['Kerberoastable'])
    $asrep  = @($script:ADRResults['ASREPRoastable'])
    $pwdNot = @($users | Where-Object { $_.PasswordNotRequired })
    $unconstrUsers = @($users | Where-Object { $_.UnconstrainedDeleg })
    $unconstrComps = @($comps | Where-Object { $_.UnconstrainedDelegation })
    $staleAdmins   = @($users | Where-Object { $_.AdminCount -and $_.Enabled -and $_.Dormant })
    $oldPwdAdmins  = @($users | Where-Object { $_.AdminCount -and $_.Enabled -and $_.PasswordAgeDays -gt 365 })
    $priv  = @($script:ADRResults['PrivilegedGroupMembers'])
    $acl   = @($script:ADRResults['ACLs-HighValue'])
    $deleg = @($script:ADRResults['Delegation'])
    $laps  = @($script:ADRResults['LAPS'])

    $domainName = if ($script:ADRResults['Domain']) { $script:ADRResults['Domain'][0].DomainName } else { $script:ADRDefaultNC }

    $summary = @(
        [PSCustomObject]@{ Metric='Users (total)';                 Count=$users.Count }
        [PSCustomObject]@{ Metric='Computers (total)';             Count=$comps.Count }
        [PSCustomObject]@{ Metric='Kerberoastable accounts';       Count=$kerb.Count }
        [PSCustomObject]@{ Metric='AS-REP-roastable accounts';     Count=$asrep.Count }
        [PSCustomObject]@{ Metric='PASSWD_NOTREQD accounts';       Count=$pwdNot.Count }
        [PSCustomObject]@{ Metric='Unconstrained delegation (usr)';Count=$unconstrUsers.Count }
        [PSCustomObject]@{ Metric='Unconstrained delegation (cmp)';Count=$unconstrComps.Count }
        [PSCustomObject]@{ Metric='Stale enabled admins';          Count=$staleAdmins.Count }
        [PSCustomObject]@{ Metric='Enabled admins, pwd > 365d';    Count=$oldPwdAdmins.Count }
        [PSCustomObject]@{ Metric='DCSync-capable ACEs (scoped)';  Count=@($acl | Where-Object { $_.DCSyncCapable }).Count }
        [PSCustomObject]@{ Metric='LAPS-covered computers';        Count=$laps.Count }
    )

    $css = @'
<style>
 body{font-family:Segoe UI,Arial,sans-serif;margin:0;background:#0f1117;color:#e6e6e6}
 header{background:#161b22;border-bottom:2px solid #2ea043;padding:22px 30px}
 header h1{margin:0;font-size:22px;color:#fff}
 header .sub{color:#8b949e;font-size:13px;margin-top:4px}
 .wrap{padding:24px 30px;max-width:1200px}
 h2{color:#58a6ff;border-bottom:1px solid #21262d;padding-bottom:6px;margin-top:34px;font-size:18px}
 table{border-collapse:collapse;width:100%;margin:10px 0;font-size:12.5px}
 th{background:#21262d;color:#c9d1d9;text-align:left;padding:7px 10px;border:1px solid #30363d}
 td{padding:6px 10px;border:1px solid #21262d;color:#d0d7de}
 tr:nth-child(even) td{background:#11151c}
 .none{color:#8b949e;font-style:italic}
 .more{color:#8b949e;font-size:11px}
 .kpi{display:flex;flex-wrap:wrap;gap:12px;margin:14px 0}
 .card{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:14px 18px;min-width:170px}
 .card .n{font-size:26px;font-weight:700;color:#fff}
 .card .l{font-size:12px;color:#8b949e;margin-top:2px}
 .warn .n{color:#f85149}.ok .n{color:#3fb950}
 footer{color:#6e7681;font-size:11px;padding:18px 30px;border-top:1px solid #21262d;margin-top:30px}
 code{background:#21262d;padding:1px 5px;border-radius:4px}
</style>
'@

    $kpiHtml = ""
    foreach ($s in $summary) {
        $cls = if ($s.Metric -match 'Kerberoast|AS-REP|NOTREQD|delegation|Stale|DCSync|> 365') { if ($s.Count -gt 0) { 'card warn' } else { 'card ok' } } else { 'card' }
        $kpiHtml += "<div class='$cls'><div class='n'>$($s.Count)</div><div class='l'>$($s.Metric)</div></div>"
    }

    $html = @"
<!DOCTYPE html><html><head><meta charset='utf-8'>$css<title>ADRecon-Lite Report - $domainName</title></head><body>
<header><h1>ADRecon-Lite &mdash; Active Directory Audit Report</h1>
<div class='sub'>Domain: <code>$domainName</code> &nbsp;|&nbsp; Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') &nbsp;|&nbsp; Dormant threshold: $DormantDays days</div></header>
<div class='wrap'>
<h2>At a glance</h2>
<div class='kpi'>$kpiHtml</div>

<h2>Kerberoastable accounts</h2>
$(ConvertTo-ADRHtmlTable -Data $kerb -Columns 'SamAccountName','Enabled','AdminCount','PasswordAgeDays','LastLogonTimestamp','SPNs')

<h2>AS-REP-roastable accounts (Kerberos pre-auth disabled)</h2>
$(ConvertTo-ADRHtmlTable -Data $asrep -Columns 'SamAccountName','Enabled','AdminCount','PasswordAgeDays','LastLogonTimestamp')

<h2>Accounts with PASSWD_NOTREQD</h2>
$(ConvertTo-ADRHtmlTable -Data $pwdNot -Columns 'SamAccountName','Enabled','AdminCount','PasswordAgeDays','LastLogonTimestamp')

<h2>Unconstrained delegation</h2>
$(ConvertTo-ADRHtmlTable -Data $deleg -Columns 'Type','Account','ObjectClass','IsDC','Target')

<h2>Privileged group membership</h2>
$(ConvertTo-ADRHtmlTable -Data $priv -Columns 'Group','MemberSam','MemberType','Enabled')

<h2>Stale enabled privileged accounts</h2>
$(ConvertTo-ADRHtmlTable -Data $staleAdmins -Columns 'SamAccountName','PasswordAgeDays','LastLogonTimestamp','Description')

<h2>High-value ACLs (DCSync &amp; dangerous rights, scoped)</h2>
$(ConvertTo-ADRHtmlTable -Data $acl -Columns 'ObjectDN','Trustee','Rights','ExtRight','DCSyncCapable','Inherited')

<footer>
ADRecon-Lite &mdash; read-only collector inspired by ADRecon. Full per-category data is in the CSV files alongside this report.
Authorized use only. ACL and DNS sections are best-effort and scoped for runtime; expand <code>Get-ADRACLs</code> for a full-domain sweep.
</footer>
</div></body></html>
"@

    $path = Join-Path $OutputDir 'ADRecon-Lite_Report.html'
    $html | Out-File -FilePath $path -Encoding UTF8
    Write-ADRLog ("  [Report] -> ADRecon-Lite_Report.html") 'Green'
}

# ----------------------------------------------------------------------------------------------------
# Main
# ----------------------------------------------------------------------------------------------------
$banner = @'
   ___    ____  ____                          __    _ __
  / _ |  / __ \/ __ \___ _________  ___      / /   (_) /____
 / __ | / /_/ / / / / -_) __/ _ \/ _ \    / /__ / / __/ -_)
/_/ |_|/_____/_/ /_/\__/\__/\___/_//_/   /____//_/\__/\__/
        Active Directory recon & audit  (read-only)
'@
Write-Host $banner -ForegroundColor Green
Write-Host "  AUTHORIZED USE ONLY - assess only environments you are permitted to test." -ForegroundColor Yellow
Write-Host ""

if (-not (Connect-ADR)) { return }

if (-not (Test-Path $OutputDir)) { [void](New-Item -ItemType Directory -Path $OutputDir -Force) }
$OutputDir = (Resolve-Path $OutputDir).Path
Write-ADRLog ("[*] Output directory: {0}" -f $OutputDir) 'Cyan'

# Resolve collector list
$allCollectors = @('Forest','Domain','PasswordPolicy','FineGrainedPwdPolicy','DomainControllers','Trusts',
                   'Sites','Subnets','Users','Kerberoastable','ASREPRoastable','Computers','Groups',
                   'PrivilegedGroups','OUs','GPOs','GPLinks','Delegation','LAPS','DNS','ACLs')
$run = if ($Collect -contains 'All') { $allCollectors } else { $Collect }

$dispatch = @{
    'Forest'               = { Get-ADRForest }
    'Domain'               = { Get-ADRDomain }
    'PasswordPolicy'       = { Get-ADRPasswordPolicy }
    'FineGrainedPwdPolicy' = { Get-ADRFineGrainedPwdPolicy }
    'DomainControllers'    = { Get-ADRDomainControllers }
    'Trusts'               = { Get-ADRTrusts }
    'Sites'                = { Get-ADRSites }
    'Subnets'              = { Get-ADRSubnets }
    'Users'                = { Get-ADRUsers }
    'Kerberoastable'       = { Get-ADRKerberoastable }
    'ASREPRoastable'       = { Get-ADRASREPRoastable }
    'Computers'            = { Get-ADRComputers }
    'Groups'               = { Get-ADRGroups }
    'PrivilegedGroups'     = { Get-ADRPrivilegedGroups }
    'OUs'                  = { Get-ADROUs }
    'GPOs'                 = { Get-ADRGPOs }
    'GPLinks'              = { Get-ADRGPLinks }
    'Delegation'           = { Get-ADRDelegation }
    'LAPS'                 = { Get-ADRLAPS }
    'DNS'                  = { Get-ADRDNS }
    'ACLs'                 = { Get-ADRACLs }
}

$sw = [System.Diagnostics.Stopwatch]::StartNew()
foreach ($c in $allCollectors) {
    if ($run -notcontains $c) { continue }
    try { & $dispatch[$c] }
    catch { Write-ADRLog ("[!] Collector '{0}' errored: {1}" -f $c, $_.Exception.Message) 'Red' }
}

New-ADRReport
$sw.Stop()

Write-Host ""
Write-ADRLog ("[+] Done in {0:n1}s. Artifacts written to: {1}" -f $sw.Elapsed.TotalSeconds, $OutputDir) 'Green'
Write-ADRLog ("    Open ADRecon-Lite_Report.html for the summary; CSVs hold the full data." ) 'Green'