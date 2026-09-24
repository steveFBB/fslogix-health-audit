param (
    [string]$ReportPath = "C:\Temp",
    [int]$EventLookbackDays = 7,
    [ValidateRange(1,100)]
    [int]$ContainerWarningPercent = 90,
    [ValidateRange(1,10000)]
    [int]$MaxContainerFiles = 1000
)

$ErrorActionPreference = "Stop"
$ScriptVersion = "0.9.0"

# ------------------------------------------------------------
# Startup confirmation
# ------------------------------------------------------------

Clear-Host

Write-Host ""
Write-Host "==============================================" -ForegroundColor Cyan
Write-Host "             FSLogix Health Audit             " -ForegroundColor Cyan
Write-Host "==============================================" -ForegroundColor Cyan
Write-Host "Version $ScriptVersion"
Write-Host ""
Write-Host "This script performs a read-only health audit of the local FSLogix environment."
Write-Host ""
Write-Host "The audit may query:"
Write-Host " - Local registry settings"
Write-Host " - FSLogix services and drivers"
Write-Host " - Local FSLogix groups"
Write-Host " - Profile storage connectivity and capacity"
Write-Host " - FSLogix profile container file sizes"
Write-Host " - Microsoft Defender configuration"
Write-Host " - FSLogix event logs and text logs"
Write-Host " - Current FSLogix session/profile state"
Write-Host " - Active Directory and DNS connectivity"
Write-Host " - Azure Files capacity if Azure PowerShell is already authenticated"
Write-Host ""
Write-Host "No configuration changes, profile deletions, service restarts,"
Write-Host "storage modifications, container mounts, or Azure sign-in actions are performed."
Write-Host ""

$Choice = Read-Host "Do you want to run the audit? [R] Run  [Q] Quit"

switch ($Choice.ToUpperInvariant()) {

    "R" {
        Write-Host ""
        Write-Host "Starting FSLogix Health Audit..." -ForegroundColor Cyan
        Write-Host ""
    }

    "Q" {
        Write-Host ""
        Write-Host "Audit cancelled."
        return
    }

    default {
        Write-Host ""
        Write-Host "Invalid selection. Audit cancelled."
        return
    }
}

# ------------------------------------------------------------
# Initial setup
# ------------------------------------------------------------

if (-not (Test-Path $ReportPath)) {
    New-Item -Path $ReportPath -ItemType Directory -Force | Out-Null
}

$ComputerName = $env:COMPUTERNAME
$Timestamp    = Get-Date -Format "yyyyMMdd-HHmmss"
$Generated    = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

$Results = New-Object System.Collections.Generic.List[object]

function Add-HealthResult {
    param (
        [Parameter(Mandatory)]
        [ValidateSet("PASS","WARN","FAIL","INFO")]
        [string]$Status,

        [Parameter(Mandatory)]
        [string]$Check,

        [Parameter(Mandatory)]
        [string]$Finding,

        [string]$Evidence,
        [string]$Recommendation,
        [string]$Category = "General"
    )

    $Results.Add([PSCustomObject]@{
        Category       = $Category
        Status         = $Status
        Check          = $Check
        Finding        = $Finding
        Evidence       = $Evidence
        Recommendation = $Recommendation
    })
}

function ConvertTo-HtmlSafe {
    param (
        [AllowNull()]
        [object]$Value
    )

    if ($null -eq $Value) {
        return ""
    }

    return [System.Net.WebUtility]::HtmlEncode(
        [string]$Value
    )
}

function Normalize-PathString {
    param (
        [string]$Path
    )

    if ([string]::IsNullOrWhiteSpace($Path)) {
        return ""
    }

    $Normalized = $Path.Trim()

    $Normalized = $Normalized -replace '(?i)%username%', '*'
    $Normalized = [Environment]::ExpandEnvironmentVariables($Normalized)
    $Normalized = $Normalized -replace '/', '\'
    $Normalized = $Normalized.TrimEnd('\')

    return $Normalized.ToLowerInvariant()
}

function Test-PathCoverage {
    param (
        [Parameter(Mandatory)]
        [string]$RequiredPath,

        [AllowEmptyCollection()]
        [string[]]$ConfiguredPaths = @()
    )

    $Required = Normalize-PathString $RequiredPath

    foreach ($ConfiguredPath in $ConfiguredPaths) {

        $Configured = Normalize-PathString $ConfiguredPath

        if ([string]::IsNullOrWhiteSpace($Configured)) {
            continue
        }

        if ($Configured -eq $Required) {
            return $true
        }

        if ($Required -like $Configured) {
            return $true
        }

        if ($Configured -like $Required) {
            return $true
        }

        if (
            -not $Configured.Contains("*") -and
            $Required.StartsWith(
                $Configured.TrimEnd('\') + '\'
            )
        ) {
            return $true
        }
    }

    return $false
}

function Test-ProcessCoverage {
    param (
        [Parameter(Mandatory)]
        [string]$RequiredProcess,

        [AllowEmptyCollection()]
        [string[]]$ConfiguredProcesses = @()
    )

    $RequiredName = [System.IO.Path]::GetFileName(
        $RequiredProcess
    ).ToLowerInvariant()

    foreach ($Process in $ConfiguredProcesses) {

        if ([string]::IsNullOrWhiteSpace($Process)) {
            continue
        }

        $ConfiguredName = [System.IO.Path]::GetFileName(
            (Normalize-PathString $Process)
        ).ToLowerInvariant()

        if ($ConfiguredName -eq $RequiredName) {
            return $true
        }
    }

    return $false
}

function Test-ShareContainerCoverage {
    param (
        [Parameter(Mandatory)]
        [string]$SharePath,

        [AllowEmptyCollection()]
        [string[]]$ConfiguredPaths = @(),

        [AllowEmptyCollection()]
        [string[]]$ConfiguredExtensions = @()
    )

    $Share = (Normalize-PathString $SharePath).TrimEnd('\')

    if (
        Test-PathCoverage `
            -RequiredPath $Share `
            -ConfiguredPaths $ConfiguredPaths
    ) {
        return $true
    }

    $Extensions = @(
        $ConfiguredExtensions |
        Where-Object { $_ } |
        ForEach-Object {
            $_.TrimStart('.').ToLowerInvariant()
        }
    )

    if (
        ($Extensions -contains "vhd") -and
        ($Extensions -contains "vhdx")
    ) {
        return $true
    }

    $RequiredPatterns = @(
        "$Share\*\*.vhd",
        "$Share\*\*.vhd.lock",
        "$Share\*\*.vhd.meta",
        "$Share\*\*.vhd.metadata",
        "$Share\*\*.vhdx",
        "$Share\*\*.vhdx.lock",
        "$Share\*\*.vhdx.meta",
        "$Share\*\*.vhdx.metadata"
    )

    foreach ($Pattern in $RequiredPatterns) {

        if (-not (
            Test-PathCoverage `
                -RequiredPath $Pattern `
                -ConfiguredPaths $ConfiguredPaths
        )) {
            return $false
        }
    }

    return $true
}

function Get-LocalGroupMemberNames {
    param (
        [Parameter(Mandatory)]
        [string]$GroupName
    )

    try {

        return @(
            Get-LocalGroupMember `
                -Group $GroupName `
                -ErrorAction Stop |
            ForEach-Object {
                $_.Name
            }
        )
    }
    catch {

        try {

            $Group = [ADSI]"WinNT://$env:COMPUTERNAME/$GroupName,group"

            return @(
                @($Group.psbase.Invoke("Members")) |
                ForEach-Object {

                    $_.GetType().InvokeMember(
                        "Name",
                        "GetProperty",
                        $null,
                        $_,
                        $null
                    )
                }
            )
        }
        catch {
            throw
        }
    }
}

function Test-EveryoneMembership {
    param (
        [AllowEmptyCollection()]
        [string[]]$Members = @()
    )

    foreach ($Member in $Members) {

        if ($Member -match '(?i)(^|\\)everyone$') {
            return $true
        }
    }

    return $false
}

function Get-EffectiveProfileSetting {
    param (
        [Parameter(Mandatory)]
        [object]$ProfileConfig,

        [Parameter(Mandatory)]
        [string]$Name,

        [Parameter(Mandatory)]
        $DefaultValue
    )

    $Property = $ProfileConfig.PSObject.Properties[$Name]

    if ($null -ne $Property) {

        return [PSCustomObject]@{
            Value      = $Property.Value
            Configured = $true
        }
    }

    return [PSCustomObject]@{
        Value      = $DefaultValue
        Configured = $false
    }
}

function Get-ContainerFiles {
    param (
        [Parameter(Mandatory)]
        [string]$RootPath,

        [Parameter(Mandatory)]
        [int]$MaximumFiles
    )

    $FoundFiles   = @()
    $LimitReached = $false

    try {

        $RootFiles = @(
            Get-ChildItem `
                -LiteralPath $RootPath `
                -File `
                -ErrorAction Stop |
            Where-Object {
                $_.Extension -match '^\.(vhd|vhdx)$'
            }
        )

        foreach ($File in $RootFiles) {

            $FoundFiles += $File

            if ($FoundFiles.Count -ge $MaximumFiles) {
                $LimitReached = $true
                break
            }
        }

        if (-not $LimitReached) {

            $Directories = @(
                Get-ChildItem `
                    -LiteralPath $RootPath `
                    -Directory `
                    -ErrorAction Stop
            )

            foreach ($Directory in $Directories) {

                $DirectoryFiles = @(
                    Get-ChildItem `
                        -LiteralPath $Directory.FullName `
                        -File `
                        -ErrorAction SilentlyContinue |
                    Where-Object {
                        $_.Extension -match '^\.(vhd|vhdx)$'
                    }
                )

                foreach ($File in $DirectoryFiles) {

                    $FoundFiles += $File

                    if ($FoundFiles.Count -ge $MaximumFiles) {
                        $LimitReached = $true
                        break
                    }
                }

                if ($LimitReached) {
                    break
                }
            }
        }

        return [PSCustomObject]@{
            Files        = $FoundFiles
            LimitReached = $LimitReached
        }
    }
    catch {
        throw
    }
}

function Get-FSLogixEventClassification {
    param (
        [Parameter(Mandatory)]
        [int]$EventId,

        [Parameter(Mandatory)]
        [string]$Message,

        [bool]$DomainJoined,
        [bool]$AzureAdJoined
    )

    $MessageLower = $Message.ToLowerInvariant()

    if (
        $EventId -eq 26 -and
        $MessageLower -match "shsetknownfolderpath" -and
        $MessageLower -match "access denied"
    ) {

        return [PSCustomObject]@{
            Key            = "Event26-KnownFolderAccessDenied"
            Status         = "WARN"
            Name           = "Known-folder redirection access denied"
            Recommendation = "Check whether Prohibit User from manually redirecting Profile Folders is enabled and setting DisablePersonalDirChange=1."
        }
    }

    if (
        $EventId -eq 26 -and
        (
            $MessageLower -match "fully qualified distinguished name failed" -or
            $MessageLower -match "failed to get computer's group sids"
        )
    ) {

        if ($AzureAdJoined -and -not $DomainJoined) {

            return [PSCustomObject]@{
                Key            = "Event26-EntraOnlyLDAP"
                Status         = "INFO"
                Name           = "Expected Event 26 on Entra-only device"
                Recommendation = "This condition can occur normally on an Entra-only FSLogix host where Active Directory LDAP information is unavailable."
            }
        }
        else {

            return [PSCustomObject]@{
                Key            = "Event26-DomainLookupFailure"
                Status         = "WARN"
                Name           = "Domain lookup failure"
                Recommendation = "Review DNS, domain controller availability and the computer secure channel if this event repeats."
            }
        }
    }

    if ($EventId -eq 26) {

        return [PSCustomObject]@{
            Key            = "Event26-Other"
            Status         = "WARN"
            Name           = "Other Event ID 26 error"
            Recommendation = "Review the event message and FSLogix logs for the underlying cause."
        }
    }

    return [PSCustomObject]@{
        Key            = "Event$EventId"
        Status         = "WARN"
        Name           = "FSLogix Event ID $EventId"
        Recommendation = "Review the event message and corresponding FSLogix profile log."
    }
}

# ------------------------------------------------------------
# Host information
# ------------------------------------------------------------

$DomainJoined  = $false
$AzureAdJoined = $false
$DomainName    = $null

try {

    $OS = Get-CimInstance Win32_OperatingSystem

    Add-HealthResult `
        -Status "INFO" `
        -Category "Host" `
        -Check "Operating system" `
        -Finding "$($OS.Caption)" `
        -Evidence "Version $($OS.Version), Build $($OS.BuildNumber)"
}
catch {

    Add-HealthResult `
        -Status "WARN" `
        -Category "Host" `
        -Check "Operating system" `
        -Finding "Unable to query operating system information." `
        -Evidence $_.Exception.Message
}

try {

    $ComputerSystem = Get-CimInstance Win32_ComputerSystem

    $DomainJoined = [bool]$ComputerSystem.PartOfDomain
    $DomainName   = $ComputerSystem.Domain

    $DsRegOutput = dsregcmd /status 2>$null

    if ($DsRegOutput -match "AzureAdJoined\s*:\s*YES") {
        $AzureAdJoined = $true
    }

    $JoinDescription = switch ($true) {

        { $DomainJoined -and $AzureAdJoined } {
            "Hybrid joined"
            break
        }

        { $DomainJoined } {
            "Domain joined"
            break
        }

        { $AzureAdJoined } {
            "Entra joined"
            break
        }

        default {
            "Workgroup or unknown join state"
        }
    }

    Add-HealthResult `
        -Status "INFO" `
        -Category "Host" `
        -Check "Device join state" `
        -Finding $JoinDescription `
        -Evidence "DomainJoined=$DomainJoined; AzureAdJoined=$AzureAdJoined; Domain=$DomainName"
}
catch {

    Add-HealthResult `
        -Status "INFO" `
        -Category "Host" `
        -Check "Device join state" `
        -Finding "Unable to determine complete device join state." `
        -Evidence $_.Exception.Message
}

# ------------------------------------------------------------
# Current Active Directory / domain health
# ------------------------------------------------------------

if ($DomainJoined -and -not [string]::IsNullOrWhiteSpace($DomainName)) {

    try {

        $SecureChannel = Test-ComputerSecureChannel -ErrorAction Stop

        if ($SecureChannel) {

            Add-HealthResult `
                -Status "PASS" `
                -Category "Domain" `
                -Check "Computer secure channel" `
                -Finding "The computer secure channel to Active Directory is healthy." `
                -Evidence "Test-ComputerSecureChannel = True"
        }
        else {

            Add-HealthResult `
                -Status "FAIL" `
                -Category "Domain" `
                -Check "Computer secure channel" `
                -Finding "The computer secure channel to Active Directory is not healthy." `
                -Evidence "Test-ComputerSecureChannel = False" `
                -Recommendation "Investigate the computer account, domain connectivity and secure channel before relying on FSLogix domain-based authentication."
        }
    }
    catch {

        Add-HealthResult `
            -Status "WARN" `
            -Category "Domain" `
            -Check "Computer secure channel" `
            -Finding "Unable to verify the computer secure channel." `
            -Evidence $_.Exception.Message
    }

    try {

        $NltestOutput = @(
            & nltest.exe "/dsgetdc:$DomainName" 2>&1
        )

        $NltestExitCode = $LASTEXITCODE

        if ($NltestExitCode -eq 0) {

            $DcName = $null

            foreach ($Line in $NltestOutput) {

                if ($Line -match '^\s*DC:\s*\\\\(.+?)\s*$') {
                    $DcName = $Matches[1].Trim()
                    break
                }
            }

            $Evidence = if ($DcName) {
                "Discovered DC: $DcName"
            }
            else {
                ($NltestOutput -join " ")
            }

            Add-HealthResult `
                -Status "PASS" `
                -Category "Domain" `
                -Check "Domain controller discovery" `
                -Finding "A domain controller can be discovered for $DomainName." `
                -Evidence $Evidence
        }
        else {

            Add-HealthResult `
                -Status "FAIL" `
                -Category "Domain" `
                -Check "Domain controller discovery" `
                -Finding "A domain controller could not be discovered for $DomainName." `
                -Evidence ($NltestOutput -join " ") `
                -Recommendation "Check DNS, routing, firewall rules and domain controller availability."
        }
    }
    catch {

        Add-HealthResult `
            -Status "WARN" `
            -Category "Domain" `
            -Check "Domain controller discovery" `
            -Finding "Unable to perform domain controller discovery." `
            -Evidence $_.Exception.Message
    }

    try {

        $ResolveDnsNameCommand = Get-Command Resolve-DnsName `
            -ErrorAction SilentlyContinue

        if ($ResolveDnsNameCommand) {

            $SrvName = "_ldap._tcp.dc._msdcs.$DomainName"

            $SrvRecords = @(
                Resolve-DnsName `
                    -Name $SrvName `
                    -Type SRV `
                    -ErrorAction Stop |
                Where-Object {
                    $_.Type -eq "SRV"
                }
            )

            if ($SrvRecords.Count -gt 0) {

                $SrvTargets = (
                    $SrvRecords |
                    Select-Object -ExpandProperty NameTarget -Unique
                ) -join "; "

                Add-HealthResult `
                    -Status "PASS" `
                    -Category "Domain" `
                    -Check "Active Directory DNS SRV records" `
                    -Finding "Active Directory domain controller SRV records resolve successfully." `
                    -Evidence "$SrvName -> $SrvTargets"
            }
            else {

                Add-HealthResult `
                    -Status "FAIL" `
                    -Category "Domain" `
                    -Check "Active Directory DNS SRV records" `
                    -Finding "No domain controller SRV records were returned." `
                    -Evidence $SrvName `
                    -Recommendation "Review the DNS configuration used by the session host."
            }
        }
        else {

            Add-HealthResult `
                -Status "INFO" `
                -Category "Domain" `
                -Check "Active Directory DNS SRV records" `
                -Finding "Resolve-DnsName is unavailable, so the SRV record check was skipped."
        }
    }
    catch {

        Add-HealthResult `
            -Status "FAIL" `
            -Category "Domain" `
            -Check "Active Directory DNS SRV records" `
            -Finding "Active Directory domain controller SRV records could not be resolved." `
            -Evidence $_.Exception.Message `
            -Recommendation "Review the DNS servers and DNS suffix configuration used by the session host."
    }
}
else {

    Add-HealthResult `
        -Status "INFO" `
        -Category "Domain" `
        -Check "Active Directory health" `
        -Finding "Domain health checks were skipped because this device is not domain joined."
}

# ------------------------------------------------------------
# FSLogix installation
# ------------------------------------------------------------

$FSLogixPath      = "C:\Program Files\FSLogix\Apps"
$FSLogixInstalled = $false

if (Test-Path $FSLogixPath) {

    $FrxSvcExe = Join-Path $FSLogixPath "frxsvc.exe"

    if (Test-Path $FrxSvcExe) {

        $FSLogixInstalled = $true
        $Version = (Get-Item $FrxSvcExe).VersionInfo.FileVersion

        Add-HealthResult `
            -Status "PASS" `
            -Category "Install" `
            -Check "FSLogix installed" `
            -Finding "FSLogix is installed." `
            -Evidence "Version $Version"
    }
    else {

        Add-HealthResult `
            -Status "WARN" `
            -Category "Install" `
            -Check "FSLogix installed" `
            -Finding "The FSLogix application folder exists, but frxsvc.exe was not found." `
            -Evidence $FSLogixPath
    }
}
else {

    Add-HealthResult `
        -Status "FAIL" `
        -Category "Install" `
        -Check "FSLogix installed" `
        -Finding "FSLogix is not installed."
}

# ------------------------------------------------------------
# FSLogix service
# ------------------------------------------------------------

if ($FSLogixInstalled) {

    try {

        $Service = Get-CimInstance `
            Win32_Service `
            -Filter "Name='frxsvc'" `
            -ErrorAction Stop

        if ($Service.State -eq "Running") {

            Add-HealthResult `
                -Status "PASS" `
                -Category "Services" `
                -Check "FSLogix service" `
                -Finding "frxsvc is running." `
                -Evidence "Start mode: $($Service.StartMode)"
        }
        else {

            Add-HealthResult `
                -Status "FAIL" `
                -Category "Services" `
                -Check "FSLogix service" `
                -Finding "frxsvc is not running." `
                -Evidence "Current state: $($Service.State); Start mode: $($Service.StartMode)" `
                -Recommendation "Investigate why the FSLogix service is not running."
        }
    }
    catch {

        Add-HealthResult `
            -Status "FAIL" `
            -Category "Services" `
            -Check "FSLogix service" `
            -Finding "Unable to query the frxsvc service." `
            -Evidence $_.Exception.Message
    }
}
else {

    Add-HealthResult `
        -Status "INFO" `
        -Category "Services" `
        -Check "FSLogix service" `
        -Finding "Service check skipped because FSLogix is not installed."
}

# ------------------------------------------------------------
# FSLogix Profile Container configuration
# ------------------------------------------------------------

$ProfilesRegPath    = "HKLM:\SOFTWARE\FSLogix\Profiles"
$ProfileConfig      = $null
$VHDLocations       = @()
$EffectiveSizeInMBs = 30000

if (Test-Path $ProfilesRegPath) {

    try {

        $ProfileConfig = Get-ItemProperty -Path $ProfilesRegPath

        if ($ProfileConfig.Enabled -eq 1) {

            Add-HealthResult `
                -Status "PASS" `
                -Category "Configuration" `
                -Check "Profile Container enabled" `
                -Finding "FSLogix Profile Containers are enabled." `
                -Evidence "Enabled = 1"
        }
        else {

            Add-HealthResult `
                -Status "FAIL" `
                -Category "Configuration" `
                -Check "Profile Container enabled" `
                -Finding "FSLogix Profile Containers are not enabled." `
                -Evidence "Enabled = $($ProfileConfig.Enabled)" `
                -Recommendation "Enable FSLogix Profile Containers if this host is intended to use FSLogix profiles."
        }

        if (
            $null -ne $ProfileConfig.VHDLocations -and
            @($ProfileConfig.VHDLocations).Count -gt 0
        ) {

            $VHDLocations = @($ProfileConfig.VHDLocations)

            Add-HealthResult `
                -Status "PASS" `
                -Category "Configuration" `
                -Check "VHD Locations" `
                -Finding "Profile container storage location is configured." `
                -Evidence ($VHDLocations -join "; ")
        }
        else {

            Add-HealthResult `
                -Status "FAIL" `
                -Category "Configuration" `
                -Check "VHD Locations" `
                -Finding "No VHDLocations value is configured." `
                -Recommendation "Configure a valid FSLogix profile container storage location."
        }

        if ($ProfileConfig.DeleteLocalProfileWhenVHDShouldApply -eq 1) {

            Add-HealthResult `
                -Status "PASS" `
                -Category "Configuration" `
                -Check "Delete local profile when VHD should apply" `
                -Finding "Local profiles are removed when the FSLogix container should apply." `
                -Evidence "DeleteLocalProfileWhenVHDShouldApply = 1"
        }
        else {

            Add-HealthResult `
                -Status "WARN" `
                -Category "Configuration" `
                -Check "Delete local profile when VHD should apply" `
                -Finding "DeleteLocalProfileWhenVHDShouldApply is not enabled." `
                -Evidence "Current value: $($ProfileConfig.DeleteLocalProfileWhenVHDShouldApply)" `
                -Recommendation "Review whether stale local profiles could take precedence over the FSLogix container."
        }

        if ($ProfileConfig.PreventLoginWithFailure -eq 1) {

            Add-HealthResult `
                -Status "PASS" `
                -Category "Configuration" `
                -Check "Prevent login with failure" `
                -Finding "Users are prevented from signing in when the FSLogix container fails to attach." `
                -Evidence "PreventLoginWithFailure = 1"
        }
        else {

            Add-HealthResult `
                -Status "WARN" `
                -Category "Configuration" `
                -Check "Prevent login with failure" `
                -Finding "PreventLoginWithFailure is not enabled." `
                -Evidence "Current value: $($ProfileConfig.PreventLoginWithFailure)" `
                -Recommendation "Review whether users should be blocked from signing in when their profile container fails."
        }

        if ($ProfileConfig.PreventLoginWithTempProfile -eq 1) {

            Add-HealthResult `
                -Status "PASS" `
                -Category "Configuration" `
                -Check "Prevent login with temporary profile" `
                -Finding "Users are prevented from signing in with a temporary profile." `
                -Evidence "PreventLoginWithTempProfile = 1"
        }
        else {

            Add-HealthResult `
                -Status "WARN" `
                -Category "Configuration" `
                -Check "Prevent login with temporary profile" `
                -Finding "PreventLoginWithTempProfile is not enabled." `
                -Evidence "Current value: $($ProfileConfig.PreventLoginWithTempProfile)" `
                -Recommendation "Review whether temporary-profile sign-ins should be blocked."
        }

        # ----------------------------------------------------
        # Recommended configuration baseline
        # ----------------------------------------------------

        $LockedRetryCount = Get-EffectiveProfileSetting `
            -ProfileConfig $ProfileConfig `
            -Name "LockedRetryCount" `
            -DefaultValue 12

        if ([int]$LockedRetryCount.Value -eq 3) {

            Add-HealthResult `
                -Status "PASS" `
                -Category "Configuration" `
                -Check "LockedRetryCount" `
                -Finding "LockedRetryCount matches Microsoft's recommended value." `
                -Evidence "Effective value: 3; Configured=$($LockedRetryCount.Configured)"
        }
        else {

            Add-HealthResult `
                -Status "WARN" `
                -Category "Configuration" `
                -Check "LockedRetryCount" `
                -Finding "LockedRetryCount does not match Microsoft's recommended value of 3." `
                -Evidence "Effective value: $($LockedRetryCount.Value); Configured=$($LockedRetryCount.Configured)" `
                -Recommendation "Review whether LockedRetryCount should be set to 3 to provide a faster failure response when a container is locked."
        }

        $LockedRetryInterval = Get-EffectiveProfileSetting `
            -ProfileConfig $ProfileConfig `
            -Name "LockedRetryInterval" `
            -DefaultValue 5

        if ([int]$LockedRetryInterval.Value -eq 15) {

            Add-HealthResult `
                -Status "PASS" `
                -Category "Configuration" `
                -Check "LockedRetryInterval" `
                -Finding "LockedRetryInterval matches Microsoft's recommended value." `
                -Evidence "Effective value: 15 seconds; Configured=$($LockedRetryInterval.Configured)"
        }
        else {

            Add-HealthResult `
                -Status "WARN" `
                -Category "Configuration" `
                -Check "LockedRetryInterval" `
                -Finding "LockedRetryInterval does not match Microsoft's recommended value of 15 seconds." `
                -Evidence "Effective value: $($LockedRetryInterval.Value) seconds; Configured=$($LockedRetryInterval.Configured)" `
                -Recommendation "Review whether LockedRetryInterval should be set to 15."
        }

        $ReAttachRetryCount = Get-EffectiveProfileSetting `
            -ProfileConfig $ProfileConfig `
            -Name "ReAttachRetryCount" `
            -DefaultValue 60

        if ([int]$ReAttachRetryCount.Value -eq 3) {

            Add-HealthResult `
                -Status "PASS" `
                -Category "Configuration" `
                -Check "ReAttachRetryCount" `
                -Finding "ReAttachRetryCount matches Microsoft's recommended value." `
                -Evidence "Effective value: 3; Configured=$($ReAttachRetryCount.Configured)"
        }
        else {

            Add-HealthResult `
                -Status "WARN" `
                -Category "Configuration" `
                -Check "ReAttachRetryCount" `
                -Finding "ReAttachRetryCount does not match Microsoft's recommended value of 3." `
                -Evidence "Effective value: $($ReAttachRetryCount.Value); Configured=$($ReAttachRetryCount.Configured)" `
                -Recommendation "Review whether ReAttachRetryCount should be set to 3 to provide a faster failure response after an unexpected container disconnect."
        }

        $ReAttachIntervalSeconds = Get-EffectiveProfileSetting `
            -ProfileConfig $ProfileConfig `
            -Name "ReAttachIntervalSeconds" `
            -DefaultValue 10

        if ([int]$ReAttachIntervalSeconds.Value -eq 15) {

            Add-HealthResult `
                -Status "PASS" `
                -Category "Configuration" `
                -Check "ReAttachIntervalSeconds" `
                -Finding "ReAttachIntervalSeconds matches Microsoft's recommended value." `
                -Evidence "Effective value: 15 seconds; Configured=$($ReAttachIntervalSeconds.Configured)"
        }
        else {

            Add-HealthResult `
                -Status "WARN" `
                -Category "Configuration" `
                -Check "ReAttachIntervalSeconds" `
                -Finding "ReAttachIntervalSeconds does not match Microsoft's recommended value of 15 seconds." `
                -Evidence "Effective value: $($ReAttachIntervalSeconds.Value) seconds; Configured=$($ReAttachIntervalSeconds.Configured)" `
                -Recommendation "Review whether ReAttachIntervalSeconds should be set to 15."
        }

        $ProfileType = Get-EffectiveProfileSetting `
            -ProfileConfig $ProfileConfig `
            -Name "ProfileType" `
            -DefaultValue 0

        if ([int]$ProfileType.Value -eq 0) {

            Add-HealthResult `
                -Status "PASS" `
                -Category "Configuration" `
                -Check "ProfileType" `
                -Finding "ProfileType is configured for standard single-connection profile behaviour." `
                -Evidence "Effective value: 0; Configured=$($ProfileType.Configured)"
        }
        else {

            Add-HealthResult `
                -Status "INFO" `
                -Category "Configuration" `
                -Check "ProfileType" `
                -Finding "ProfileType is configured for concurrent profile behaviour." `
                -Evidence "Effective value: $($ProfileType.Value); Configured=$($ProfileType.Configured)" `
                -Recommendation "Confirm that concurrent profile access is intentional and consistently configured across all hosts."
        }

        $SizeInMBs = Get-EffectiveProfileSetting `
            -ProfileConfig $ProfileConfig `
            -Name "SizeInMBs" `
            -DefaultValue 30000

        $EffectiveSizeInMBs = [double]$SizeInMBs.Value

        Add-HealthResult `
            -Status "INFO" `
            -Category "Configuration" `
            -Check "Profile container maximum size" `
            -Finding "The effective profile container maximum size is $($SizeInMBs.Value) MB." `
            -Evidence "SizeInMBs=$($SizeInMBs.Value); Configured=$($SizeInMBs.Configured)"

        $VolumeType = Get-EffectiveProfileSetting `
            -ProfileConfig $ProfileConfig `
            -Name "VolumeType" `
            -DefaultValue "vhd"

        if (
            ([string]$VolumeType.Value).Trim().ToLowerInvariant() -eq "vhdx"
        ) {

            Add-HealthResult `
                -Status "PASS" `
                -Category "Configuration" `
                -Check "Volume type" `
                -Finding "New profile containers are configured to use VHDX." `
                -Evidence "Effective value: $($VolumeType.Value); Configured=$($VolumeType.Configured)"
        }
        else {

            Add-HealthResult `
                -Status "WARN" `
                -Category "Configuration" `
                -Check "Volume type" `
                -Finding "New profile containers use VHD rather than Microsoft's recommended VHDX format." `
                -Evidence "Effective value: $($VolumeType.Value); Configured=$($VolumeType.Configured)" `
                -Recommendation "VHDX is preferred for new containers. Changing this setting does not convert existing VHD containers."
        }

        $FlipFlopProfileDirectoryName = Get-EffectiveProfileSetting `
            -ProfileConfig $ProfileConfig `
            -Name "FlipFlopProfileDirectoryName" `
            -DefaultValue 0

        if ([int]$FlipFlopProfileDirectoryName.Value -eq 1) {

            Add-HealthResult `
                -Status "PASS" `
                -Category "Configuration" `
                -Check "Profile directory naming" `
                -Finding "FlipFlopProfileDirectoryName is enabled." `
                -Evidence "Effective value: 1; Configured=$($FlipFlopProfileDirectoryName.Configured)"
        }
        else {

            Add-HealthResult `
                -Status "INFO" `
                -Category "Configuration" `
                -Check "Profile directory naming" `
                -Finding "FlipFlopProfileDirectoryName is not enabled." `
                -Evidence "Effective value: $($FlipFlopProfileDirectoryName.Value); Configured=$($FlipFlopProfileDirectoryName.Configured)" `
                -Recommendation "Microsoft recommends this setting for easier container-folder browsing, but changing it in an existing environment can cause FSLogix to create new profile directories. Do not change it without planning the profile-folder migration."
        }

        # ----------------------------------------------------
        # Optional redirections.xml validation
        # ----------------------------------------------------

        if (
            $null -ne $ProfileConfig.RedirXMLSourceFolder -and
            -not [string]::IsNullOrWhiteSpace(
                [string]$ProfileConfig.RedirXMLSourceFolder
            )
        ) {

            $RedirSource = [Environment]::ExpandEnvironmentVariables(
                [string]$ProfileConfig.RedirXMLSourceFolder
            )

            $RedirSource = $RedirSource.TrimEnd('\')

            $RedirFile = Join-Path `
                $RedirSource `
                "redirections.xml"

            try {

                if (-not (Test-Path -LiteralPath $RedirSource)) {

                    Add-HealthResult `
                        -Status "WARN" `
                        -Category "Configuration" `
                        -Check "redirections.xml source" `
                        -Finding "RedirXMLSourceFolder is configured, but the source folder could not be reached." `
                        -Evidence $RedirSource `
                        -Recommendation "Verify the source path and that users/session hosts have read access."
                }
                elseif (-not (
                    Test-Path `
                        -LiteralPath $RedirFile `
                        -PathType Leaf
                )) {

                    Add-HealthResult `
                        -Status "FAIL" `
                        -Category "Configuration" `
                        -Check "redirections.xml" `
                        -Finding "RedirXMLSourceFolder is configured but redirections.xml was not found." `
                        -Evidence $RedirFile `
                        -Recommendation "Place a valid file named redirections.xml in the configured source folder or remove RedirXMLSourceFolder if custom redirections are no longer required."
                }
                else {

                    try {

                        [xml]$RedirXml = Get-Content `
                            -LiteralPath $RedirFile `
                            -Raw `
                            -ErrorAction Stop

                        if (
                            $null -eq
                            $RedirXml.FrxProfileFolderRedirection
                        ) {

                            Add-HealthResult `
                                -Status "FAIL" `
                                -Category "Configuration" `
                                -Check "redirections.xml" `
                                -Finding "redirections.xml is readable XML but does not contain the expected FSLogix root element." `
                                -Evidence $RedirFile `
                                -Recommendation "Review the structure of redirections.xml."
                        }
                        else {

                            $ExcludeCount = @(
                                $RedirXml.FrxProfileFolderRedirection.Excludes.Exclude
                            ).Count

                            $IncludeCount = @(
                                $RedirXml.FrxProfileFolderRedirection.Includes.Include
                            ).Count

                            $ExcludeCommonFolders =
                                $RedirXml.FrxProfileFolderRedirection.ExcludeCommonFolders

                            Add-HealthResult `
                                -Status "PASS" `
                                -Category "Configuration" `
                                -Check "redirections.xml" `
                                -Finding "Configured redirections.xml exists and contains valid XML." `
                                -Evidence "Source: $RedirFile; Excludes=$ExcludeCount; Includes=$IncludeCount; ExcludeCommonFolders=$ExcludeCommonFolders"
                        }
                    }
                    catch {

                        Add-HealthResult `
                            -Status "FAIL" `
                            -Category "Configuration" `
                            -Check "redirections.xml" `
                            -Finding "redirections.xml exists but could not be parsed as valid XML." `
                            -Evidence "$RedirFile - $($_.Exception.Message)" `
                            -Recommendation "Correct the XML syntax before using the file."
                    }
                }
            }
            catch {

                Add-HealthResult `
                    -Status "WARN" `
                    -Category "Configuration" `
                    -Check "redirections.xml" `
                    -Finding "Unable to validate the configured redirections.xml source." `
                    -Evidence "$RedirFile - $($_.Exception.Message)" `
                    -Recommendation "Verify the configured source and permissions."
            }
        }
    }
    catch {

        Add-HealthResult `
            -Status "WARN" `
            -Category "Configuration" `
            -Check "Profile Container configuration" `
            -Finding "Unable to read FSLogix Profile Container configuration." `
            -Evidence $_.Exception.Message
    }
}
else {

    Add-HealthResult `
        -Status "INFO" `
        -Category "Configuration" `
        -Check "Profile Container configuration" `
        -Finding "FSLogix Profiles registry configuration was not found."
}

# ------------------------------------------------------------
# FSLogix minifilter drivers
# ------------------------------------------------------------

if ($FSLogixInstalled) {

    $DriverFiles = @(
        "frxdrv.sys",
        "frxdrvvt.sys",
        "frxccd.sys"
    )

    $MissingDriverFiles = @()

    foreach ($DriverFile in $DriverFiles) {

        $DriverPath = Join-Path $FSLogixPath $DriverFile

        if (-not (Test-Path -LiteralPath $DriverPath)) {
            $MissingDriverFiles += $DriverFile
        }
    }

    if ($MissingDriverFiles.Count -eq 0) {

        Add-HealthResult `
            -Status "PASS" `
            -Category "Drivers" `
            -Check "FSLogix minifilter driver files" `
            -Finding "All expected FSLogix minifilter driver files are installed." `
            -Evidence ($DriverFiles -join "; ")
    }
    else {

        Add-HealthResult `
            -Status "FAIL" `
            -Category "Drivers" `
            -Check "FSLogix minifilter driver files" `
            -Finding "$($MissingDriverFiles.Count) expected FSLogix driver file(s) are missing." `
            -Evidence ($MissingDriverFiles -join "; ") `
            -Recommendation "Repair or reinstall FSLogix Apps."
    }

    try {

        $FltmcOutput = @(
            & fltmc.exe filters 2>&1
        )

        $FltmcExitCode = $LASTEXITCODE

        if ($FltmcExitCode -ne 0) {

            Add-HealthResult `
                -Status "INFO" `
                -Category "Drivers" `
                -Check "FSLogix minifilter state" `
                -Finding "Unable to reliably query loaded minifilter drivers." `
                -Evidence (($FltmcOutput | ForEach-Object { "$_" }) -join " ")
        }
        else {

            $LoadedFilters = @()

            foreach ($Line in $FltmcOutput) {

                if ($Line -match '^\s*(frxdrv|frxdrvvt|frxccd)\s+') {
                    $LoadedFilters += $Matches[1].ToLowerInvariant()
                }
            }

            $LoadedFilters = @(
                $LoadedFilters |
                Select-Object -Unique
            )

            foreach ($RequiredFilter in @(
                "frxdrv",
                "frxdrvvt",
                "frxccd"
            )) {

                if ($LoadedFilters -contains $RequiredFilter) {

                    Add-HealthResult `
                        -Status "PASS" `
                        -Category "Drivers" `
                        -Check "$RequiredFilter minifilter" `
                        -Finding "$RequiredFilter is loaded."
                }
                else {

                    Add-HealthResult `
                        -Status "FAIL" `
                        -Category "Drivers" `
                        -Check "$RequiredFilter minifilter" `
                        -Finding "$RequiredFilter is not currently loaded." `
                        -Recommendation "Review the FSLogix installation and service/driver state."
                }
            }
        }
    }
    catch {

        Add-HealthResult `
            -Status "INFO" `
            -Category "Drivers" `
            -Check "FSLogix minifilter state" `
            -Finding "Unable to query loaded minifilter drivers." `
            -Evidence $_.Exception.Message
    }
}
else {

    Add-HealthResult `
        -Status "INFO" `
        -Category "Drivers" `
        -Check "FSLogix minifilter drivers" `
        -Finding "Driver checks were skipped because FSLogix is not installed."
}

# ------------------------------------------------------------
# FSLogix local include/exclude groups
# ------------------------------------------------------------

if ($FSLogixInstalled) {

    $FSLogixGroups = @(
        "FSLogix Profile Include List",
        "FSLogix Profile Exclude List",
        "FSLogix ODFC Include List",
        "FSLogix ODFC Exclude List"
    )

    $ExistingGroups = @()
    $MissingGroups  = @()

    foreach ($GroupName in $FSLogixGroups) {

        try {

            $GroupExists = $false

            try {

                $null = Get-LocalGroup `
                    -Name $GroupName `
                    -ErrorAction Stop

                $GroupExists = $true
            }
            catch {

                try {

                    $Group = [ADSI]"WinNT://$env:COMPUTERNAME/$GroupName,group"
                    $null = $Group.Name
                    $GroupExists = $true
                }
                catch {
                    $GroupExists = $false
                }
            }

            if ($GroupExists) {
                $ExistingGroups += $GroupName
            }
            else {
                $MissingGroups += $GroupName
            }
        }
        catch {
            $MissingGroups += $GroupName
        }
    }

    if ($MissingGroups.Count -eq 0) {

        Add-HealthResult `
            -Status "PASS" `
            -Category "Groups" `
            -Check "FSLogix local groups" `
            -Finding "All four expected FSLogix local groups are present." `
            -Evidence ($FSLogixGroups -join "; ")
    }
    else {

        Add-HealthResult `
            -Status "FAIL" `
            -Category "Groups" `
            -Check "FSLogix local groups" `
            -Finding "$($MissingGroups.Count) expected FSLogix local group(s) are missing." `
            -Evidence ($MissingGroups -join "; ") `
            -Recommendation "Review or repair the FSLogix installation."
    }

    foreach ($IncludeGroup in @(
        "FSLogix Profile Include List",
        "FSLogix ODFC Include List"
    )) {

        if ($ExistingGroups -contains $IncludeGroup) {

            try {

                $Members = @(
                    Get-LocalGroupMemberNames `
                        -GroupName $IncludeGroup
                )

                if ($Members.Count -eq 0) {

                    Add-HealthResult `
                        -Status "WARN" `
                        -Category "Groups" `
                        -Check $IncludeGroup `
                        -Finding "The include group has no members." `
                        -Recommendation "Confirm that this is intentional because no users will be included through this group."
                }
                elseif (Test-EveryoneMembership -Members $Members) {

                    Add-HealthResult `
                        -Status "PASS" `
                        -Category "Groups" `
                        -Check $IncludeGroup `
                        -Finding "The include group contains Everyone." `
                        -Evidence ($Members -join "; ")
                }
                else {

                    Add-HealthResult `
                        -Status "INFO" `
                        -Category "Groups" `
                        -Check $IncludeGroup `
                        -Finding "The include group uses custom membership rather than Everyone." `
                        -Evidence ($Members -join "; ") `
                        -Recommendation "Confirm that the scoped membership is intentional."
                }
            }
            catch {

                Add-HealthResult `
                    -Status "INFO" `
                    -Category "Groups" `
                    -Check $IncludeGroup `
                    -Finding "Unable to enumerate group membership." `
                    -Evidence $_.Exception.Message
            }
        }
    }

    foreach ($ExcludeGroup in @(
        "FSLogix Profile Exclude List",
        "FSLogix ODFC Exclude List"
    )) {

        if ($ExistingGroups -contains $ExcludeGroup) {

            try {

                $Members = @(
                    Get-LocalGroupMemberNames `
                        -GroupName $ExcludeGroup
                )

                if ($Members.Count -eq 0) {

                    Add-HealthResult `
                        -Status "PASS" `
                        -Category "Groups" `
                        -Check $ExcludeGroup `
                        -Finding "The exclude group has no members."
                }
                else {

                    Add-HealthResult `
                        -Status "INFO" `
                        -Category "Groups" `
                        -Check $ExcludeGroup `
                        -Finding "$($Members.Count) member(s) are explicitly excluded from FSLogix processing." `
                        -Evidence ($Members -join "; ") `
                        -Recommendation "Confirm that the exclusions are intentional."
                }
            }
            catch {

                Add-HealthResult `
                    -Status "INFO" `
                    -Category "Groups" `
                    -Check $ExcludeGroup `
                    -Finding "Unable to enumerate group membership." `
                    -Evidence $_.Exception.Message
            }
        }
    }
}
else {

    Add-HealthResult `
        -Status "INFO" `
        -Category "Groups" `
        -Check "FSLogix local groups" `
        -Finding "Local group checks were skipped because FSLogix is not installed."
}

# ------------------------------------------------------------
# Storage connectivity and capacity
# ------------------------------------------------------------

if ($VHDLocations.Count -gt 0) {

    foreach ($Location in $VHDLocations) {

        if ($Location -match '^\\\\([^\\]+)\\(.+)$') {

            $StorageHost     = $Matches[1]
            $ShareAccessible = $false

            # ------------------------------------------------
            # TCP 445
            # ------------------------------------------------

            try {

                $TcpResult = Test-NetConnection `
                    -ComputerName $StorageHost `
                    -Port 445 `
                    -WarningAction SilentlyContinue

                if ($TcpResult.TcpTestSucceeded) {

                    Add-HealthResult `
                        -Status "PASS" `
                        -Category "Storage" `
                        -Check "SMB connectivity" `
                        -Finding "The FSLogix storage endpoint is reachable on TCP 445." `
                        -Evidence "$StorageHost : TCP 445"
                }
                else {

                    Add-HealthResult `
                        -Status "FAIL" `
                        -Category "Storage" `
                        -Check "SMB connectivity" `
                        -Finding "The FSLogix storage endpoint is not reachable on TCP 445." `
                        -Evidence "$StorageHost : TCP 445 failed" `
                        -Recommendation "Check DNS resolution, routing, firewalls, NSGs, VPN/ExpressRoute connectivity and storage firewall settings."
                }
            }
            catch {

                Add-HealthResult `
                    -Status "WARN" `
                    -Category "Storage" `
                    -Check "SMB connectivity" `
                    -Finding "Unable to test TCP 445 connectivity to the FSLogix storage endpoint." `
                    -Evidence $_.Exception.Message
            }

            # ------------------------------------------------
            # Share reachability
            # ------------------------------------------------

            try {

                if (Test-Path -Path $Location) {

                    $ShareAccessible = $true

                    Add-HealthResult `
                        -Status "PASS" `
                        -Category "Storage" `
                        -Check "Profile share reachability" `
                        -Finding "The configured FSLogix profile share is accessible." `
                        -Evidence $Location
                }
                else {

                    Add-HealthResult `
                        -Status "FAIL" `
                        -Category "Storage" `
                        -Check "Profile share reachability" `
                        -Finding "The configured FSLogix profile share could not be accessed." `
                        -Evidence $Location `
                        -Recommendation "Check share permissions, NTFS permissions, Azure Files identity configuration and the account used to run the audit."
                }
            }
            catch {

                Add-HealthResult `
                    -Status "WARN" `
                    -Category "Storage" `
                    -Check "Profile share reachability" `
                    -Finding "Unable to test access to the configured FSLogix profile share." `
                    -Evidence "$Location - $($_.Exception.Message)"
            }

            # ------------------------------------------------
            # Profile container file-size inventory
            # ------------------------------------------------

            if ($ShareAccessible -and $EffectiveSizeInMBs -gt 0) {

                try {

                    $ContainerScan = Get-ContainerFiles `
                        -RootPath $Location `
                        -MaximumFiles $MaxContainerFiles

                    $ContainerFiles = @(
                        $ContainerScan.Files
                    )

                    if ($ContainerFiles.Count -eq 0) {

                        Add-HealthResult `
                            -Status "INFO" `
                            -Category "Storage" `
                            -Check "Profile container sizes" `
                            -Finding "No VHD or VHDX profile container files were found at the share root or one directory level below it." `
                            -Evidence $Location
                    }
                    else {

                        $MaximumBytes =
                            [double]$EffectiveSizeInMBs * 1MB

                        $ContainerDetails = @(
                            $ContainerFiles |
                            ForEach-Object {

                                $SizeBytes = [double]$_.Length

                                $PercentOfMaximum = [math]::Round(
                                    (
                                        $SizeBytes /
                                        $MaximumBytes
                                    ) * 100,
                                    2
                                )

                                [PSCustomObject]@{
                                    Name             = $_.Name
                                    FullName         = $_.FullName
                                    SizeBytes        = $SizeBytes
                                    SizeGiB          = [math]::Round(
                                        ($SizeBytes / 1GB),
                                        2
                                    )
                                    PercentOfMaximum = $PercentOfMaximum
                                    LastWriteTime    = $_.LastWriteTime
                                }
                            }
                        )

                        $ContainersNearLimit = @(
                            $ContainerDetails |
                            Where-Object {
                                $_.PercentOfMaximum -ge
                                $ContainerWarningPercent
                            } |
                            Sort-Object PercentOfMaximum -Descending
                        )

                        $LargestContainers = @(
                            $ContainerDetails |
                            Sort-Object SizeBytes -Descending |
                            Select-Object -First 10
                        )

                        $TotalContainerBytes = (
                            $ContainerDetails |
                            Measure-Object `
                                -Property SizeBytes `
                                -Sum
                        ).Sum

                        if ($null -eq $TotalContainerBytes) {
                            $TotalContainerBytes = 0
                        }

                        $TotalContainerGiB = [math]::Round(
                            (
                                [double]$TotalContainerBytes /
                                1GB
                            ),
                            2
                        )

                        $LargestEvidence = (
                            $LargestContainers |
                            ForEach-Object {
                                "$($_.Name)=$($_.SizeGiB) GiB ($($_.PercentOfMaximum)% of configured maximum)"
                            }
                        ) -join "; "

                        $ScanSuffix = if ($ContainerScan.LimitReached) {
                            " Scan stopped after $MaxContainerFiles container files because the configured audit limit was reached."
                        }
                        else {
                            ""
                        }

                        if ($ContainersNearLimit.Count -gt 0) {

                            $NearLimitEvidence = (
                                $ContainersNearLimit |
                                Select-Object -First 10 |
                                ForEach-Object {
                                    "$($_.FullName)=$($_.SizeGiB) GiB ($($_.PercentOfMaximum)%)"
                                }
                            ) -join "; "

                            Add-HealthResult `
                                -Status "WARN" `
                                -Category "Storage" `
                                -Check "Profile container sizes" `
                                -Finding "$($ContainersNearLimit.Count) profile container file(s) are at or above the audit warning threshold of $ContainerWarningPercent% of SizeInMBs." `
                                -Evidence "Configured maximum=$EffectiveSizeInMBs MB; Containers scanned=$($ContainerDetails.Count); Total container file size=$TotalContainerGiB GiB; Near threshold: $NearLimitEvidence.$ScanSuffix" `
                                -Recommendation "Review the affected containers. Do not delete profile data or increase SizeInMBs without first determining why the container is large."
                        }
                        else {

                            Add-HealthResult `
                                -Status "PASS" `
                                -Category "Storage" `
                                -Check "Profile container sizes" `
                                -Finding "No scanned profile container files are at or above the audit warning threshold of $ContainerWarningPercent% of SizeInMBs." `
                                -Evidence "Configured maximum=$EffectiveSizeInMBs MB; Containers scanned=$($ContainerDetails.Count); Total container file size=$TotalContainerGiB GiB; Largest: $LargestEvidence.$ScanSuffix"
                        }

                        if ($ContainerScan.LimitReached) {

                            Add-HealthResult `
                                -Status "INFO" `
                                -Category "Storage" `
                                -Check "Profile container scan limit" `
                                -Finding "The profile container inventory was limited to $MaxContainerFiles files." `
                                -Evidence "The share contains at least $MaxContainerFiles VHD/VHDX files within the scanned layout." `
                                -Recommendation "Increase -MaxContainerFiles if a larger inventory is required."
                        }
                    }
                }
                catch {

                    Add-HealthResult `
                        -Status "INFO" `
                        -Category "Storage" `
                        -Check "Profile container sizes" `
                        -Finding "Unable to enumerate FSLogix profile container file sizes." `
                        -Evidence $_.Exception.Message
                }
            }

            # ------------------------------------------------
            # Azure Files capacity
            # ------------------------------------------------

            if (
                $Location -match
                '^\\\\([^.\\]+)\.file\.core\.windows\.net\\([^\\]+)'
            ) {

                $AzureStorageAccountName = $Matches[1]
                $AzureFileShareName      = $Matches[2]

                $AzContextCommand = Get-Command `
                    Get-AzContext `
                    -ErrorAction SilentlyContinue

                $AzStorageCommand = Get-Command `
                    Get-AzStorageAccount `
                    -ErrorAction SilentlyContinue

                $AzShareCommand = Get-Command `
                    Get-AzRmStorageShare `
                    -ErrorAction SilentlyContinue

                if (
                    -not $AzContextCommand -or
                    -not $AzStorageCommand -or
                    -not $AzShareCommand
                ) {

                    Add-HealthResult `
                        -Status "INFO" `
                        -Category "Storage" `
                        -Check "Azure Files capacity" `
                        -Finding "Azure Files capacity was not checked because the required Azure PowerShell modules are not available." `
                        -Evidence "$AzureStorageAccountName / $AzureFileShareName" `
                        -Recommendation "Capacity can be checked automatically when Az.Accounts and Az.Storage are installed and an Azure session already exists."
                }
                else {

                    try {

                        $AzContext = Get-AzContext `
                            -ErrorAction SilentlyContinue

                        if (
                            $null -eq $AzContext -or
                            $null -eq $AzContext.Account -or
                            $null -eq $AzContext.Subscription
                        ) {

                            Add-HealthResult `
                                -Status "INFO" `
                                -Category "Storage" `
                                -Check "Azure Files capacity" `
                                -Finding "Azure Files capacity was not checked because no authenticated Azure PowerShell context exists." `
                                -Evidence "$AzureStorageAccountName / $AzureFileShareName" `
                                -Recommendation "The audit does not initiate Azure authentication. If capacity data is required, authenticate to the appropriate Azure subscription before running the audit."
                        }
                        else {

                            try {

                                $MatchingStorageAccounts = @(
                                    Get-AzStorageAccount `
                                        -ErrorAction Stop |
                                    Where-Object {
                                        $_.StorageAccountName -eq
                                        $AzureStorageAccountName
                                    }
                                )

                                if ($MatchingStorageAccounts.Count -eq 0) {

                                    Add-HealthResult `
                                        -Status "INFO" `
                                        -Category "Storage" `
                                        -Check "Azure Files capacity" `
                                        -Finding "The Azure storage account could not be found in the current Azure subscription." `
                                        -Evidence "Storage account: $AzureStorageAccountName; Subscription: $($AzContext.Subscription.Name)" `
                                        -Recommendation "Confirm that the current Azure context has access to the subscription containing this storage account."
                                }
                                else {

                                    $StorageAccount =
                                        $MatchingStorageAccounts[0]

                                    $AzureShare = Get-AzRmStorageShare `
                                        -ResourceGroupName $StorageAccount.ResourceGroupName `
                                        -StorageAccountName $AzureStorageAccountName `
                                        -Name $AzureFileShareName `
                                        -GetShareUsage `
                                        -ErrorAction Stop

                                    $QuotaGiB =
                                        [double]$AzureShare.QuotaGiB

                                    $UsedBytes =
                                        [double]$AzureShare.ShareUsageBytes

                                    if (
                                        $QuotaGiB -gt 0 -and
                                        $UsedBytes -ge 0
                                    ) {

                                        $QuotaBytes =
                                            $QuotaGiB * 1GB

                                        $FreeBytes = [math]::Max(
                                            0,
                                            (
                                                $QuotaBytes -
                                                $UsedBytes
                                            )
                                        )

                                        $UsedGiB = [math]::Round(
                                            ($UsedBytes / 1GB),
                                            2
                                        )

                                        $FreeGiB = [math]::Round(
                                            ($FreeBytes / 1GB),
                                            2
                                        )

                                        $FreePercent = [math]::Round(
                                            (
                                                (
                                                    $FreeBytes /
                                                    $QuotaBytes
                                                ) * 100
                                            ),
                                            2
                                        )

                                        if ($FreePercent -lt 20) {

                                            Add-HealthResult `
                                                -Status "WARN" `
                                                -Category "Storage" `
                                                -Check "Azure Files capacity" `
                                                -Finding "The Azure file share has less than 20% free capacity remaining." `
                                                -Evidence "Share=$AzureFileShareName; Used=$UsedGiB GiB; Free=$FreeGiB GiB; Quota=$QuotaGiB GiB; Free=$FreePercent%" `
                                                -Recommendation "Review Azure Files capacity and projected FSLogix profile growth."
                                        }
                                        else {

                                            Add-HealthResult `
                                                -Status "PASS" `
                                                -Category "Storage" `
                                                -Check "Azure Files capacity" `
                                                -Finding "The Azure file share has at least 20% free capacity remaining." `
                                                -Evidence "Share=$AzureFileShareName; Used=$UsedGiB GiB; Free=$FreeGiB GiB; Quota=$QuotaGiB GiB; Free=$FreePercent%"
                                        }
                                    }
                                    else {

                                        Add-HealthResult `
                                            -Status "INFO" `
                                            -Category "Storage" `
                                            -Check "Azure Files capacity" `
                                            -Finding "Azure Files capacity information was returned but could not be evaluated." `
                                            -Evidence "QuotaGiB=$($AzureShare.QuotaGiB); ShareUsageBytes=$($AzureShare.ShareUsageBytes)"
                                    }
                                }
                            }
                            catch {

                                Add-HealthResult `
                                    -Status "INFO" `
                                    -Category "Storage" `
                                    -Check "Azure Files capacity" `
                                    -Finding "Azure Files capacity could not be queried using the current Azure context." `
                                    -Evidence $_.Exception.Message `
                                    -Recommendation "Confirm that the current Azure account has permission to read the storage account and file share."
                            }
                        }
                    }
                    catch {

                        Add-HealthResult `
                            -Status "INFO" `
                            -Category "Storage" `
                            -Check "Azure Files capacity" `
                            -Finding "Unable to determine whether an Azure PowerShell session is available." `
                            -Evidence $_.Exception.Message
                    }
                }
            }
            else {

                # --------------------------------------------
                # Traditional SMB capacity
                # --------------------------------------------

                $TemporaryDriveName = "FSLAudit"

                try {

                    if (
                        Get-PSDrive `
                            -Name $TemporaryDriveName `
                            -ErrorAction SilentlyContinue
                    ) {

                        Remove-PSDrive `
                            -Name $TemporaryDriveName `
                            -Force `
                            -ErrorAction SilentlyContinue
                    }

                    $null = New-PSDrive `
                        -Name $TemporaryDriveName `
                        -PSProvider FileSystem `
                        -Root $Location `
                        -Scope Script `
                        -ErrorAction Stop

                    $DriveInfo = Get-PSDrive `
                        -Name $TemporaryDriveName `
                        -ErrorAction Stop

                    if (
                        $null -ne $DriveInfo.Free -and
                        $null -ne $DriveInfo.Used -and
                        ($DriveInfo.Free + $DriveInfo.Used) -gt 0
                    ) {

                        $TotalBytes =
                            [double]$DriveInfo.Free +
                            [double]$DriveInfo.Used

                        $FreePercent = [math]::Round(
                            (
                                [double]$DriveInfo.Free /
                                $TotalBytes
                            ) * 100,
                            2
                        )

                        $FreeGiB = [math]::Round(
                            ([double]$DriveInfo.Free / 1GB),
                            2
                        )

                        $TotalGiB = [math]::Round(
                            ($TotalBytes / 1GB),
                            2
                        )

                        if ($FreePercent -lt 20) {

                            Add-HealthResult `
                                -Status "WARN" `
                                -Category "Storage" `
                                -Check "SMB storage capacity" `
                                -Finding "The profile storage has less than 20% free capacity remaining." `
                                -Evidence "Free=$FreeGiB GiB; Total=$TotalGiB GiB; Free=$FreePercent%" `
                                -Recommendation "Review available capacity and projected FSLogix profile growth."
                        }
                        else {

                            Add-HealthResult `
                                -Status "PASS" `
                                -Category "Storage" `
                                -Check "SMB storage capacity" `
                                -Finding "The profile storage has at least 20% free capacity remaining." `
                                -Evidence "Free=$FreeGiB GiB; Total=$TotalGiB GiB; Free=$FreePercent%"
                        }
                    }
                    else {

                        Add-HealthResult `
                            -Status "INFO" `
                            -Category "Storage" `
                            -Check "SMB storage capacity" `
                            -Finding "The SMB share is reachable, but capacity information was not exposed through the filesystem provider." `
                            -Evidence $Location
                    }
                }
                catch {

                    Add-HealthResult `
                        -Status "INFO" `
                        -Category "Storage" `
                        -Check "SMB storage capacity" `
                        -Finding "Unable to determine capacity for the SMB profile share." `
                        -Evidence $_.Exception.Message
                }
                finally {

                    Remove-PSDrive `
                        -Name $TemporaryDriveName `
                        -Force `
                        -ErrorAction SilentlyContinue
                }
            }
        }
        else {

            Add-HealthResult `
                -Status "WARN" `
                -Category "Storage" `
                -Check "VHD location format" `
                -Finding "The configured VHD location is not a standard UNC path." `
                -Evidence $Location `
                -Recommendation "Review the configured VHDLocations value."
        }
    }
}
else {

    Add-HealthResult `
        -Status "INFO" `
        -Category "Storage" `
        -Check "Storage checks" `
        -Finding "Storage checks were skipped because no VHDLocations value was available."
}

# ------------------------------------------------------------
# Microsoft Defender / Antivirus exclusions
# ------------------------------------------------------------

if ($FSLogixInstalled) {

    $DefenderAvailable  = $false
    $DefenderPreference = $null
    $DefenderStatus     = $null

    try {

        $DefenderPreference = Get-MpPreference -ErrorAction Stop
        $DefenderStatus     = Get-MpComputerStatus -ErrorAction Stop
        $DefenderAvailable  = $true
    }
    catch {

        Add-HealthResult `
            -Status "INFO" `
            -Category "Antivirus" `
            -Check "Defender exclusions" `
            -Finding "Microsoft Defender configuration could not be queried." `
            -Evidence $_.Exception.Message `
            -Recommendation "If a third-party antivirus product is active, validate the equivalent FSLogix exclusions in that product's management console."
    }

    if ($DefenderAvailable) {

        $ExclusionPaths = @(
            $DefenderPreference.ExclusionPath |
            Where-Object { $_ }
        )

        $ExclusionProcesses = @(
            $DefenderPreference.ExclusionProcess |
            Where-Object { $_ }
        )

        $ExclusionExtensions = @(
            $DefenderPreference.ExclusionExtension |
            Where-Object { $_ }
        )

        $DefenderActive = (
            $DefenderStatus.AntivirusEnabled -eq $true -and
            $DefenderStatus.RealTimeProtectionEnabled -eq $true
        )

        if ($DefenderActive) {

            Add-HealthResult `
                -Status "INFO" `
                -Category "Antivirus" `
                -Check "Active antivirus" `
                -Finding "Microsoft Defender Antivirus is active." `
                -Evidence "AntivirusEnabled=True; RealTimeProtectionEnabled=True"
        }
        else {

            Add-HealthResult `
                -Status "INFO" `
                -Category "Antivirus" `
                -Check "Active antivirus" `
                -Finding "Microsoft Defender is installed but does not appear to be the active real-time antivirus engine." `
                -Evidence "AntivirusEnabled=$($DefenderStatus.AntivirusEnabled); RealTimeProtectionEnabled=$($DefenderStatus.RealTimeProtectionEnabled)" `
                -Recommendation "Validate FSLogix exclusions in the active antivirus product."
        }

        $MissingExclusions = New-Object System.Collections.Generic.List[string]

        foreach ($RequiredProcess in @(
            "frxsvc.exe",
            "frxccds.exe"
        )) {

            if (-not (
                Test-ProcessCoverage `
                    -RequiredProcess $RequiredProcess `
                    -ConfiguredProcesses $ExclusionProcesses
            )) {

                $MissingExclusions.Add(
                    "Process: $RequiredProcess"
                )
            }
        }

        foreach ($RequiredPath in @(
            "C:\Program Files\FSLogix\Apps\",
            "C:\ProgramData\FSLogix\",
            "C:\Users\%username%\AppData\Local\FSLogix\"
        )) {

            if (-not (
                Test-PathCoverage `
                    -RequiredPath $RequiredPath `
                    -ConfiguredPaths $ExclusionPaths
            )) {

                $MissingExclusions.Add(
                    "Path: $RequiredPath"
                )
            }
        }

        foreach ($Driver in @(
            "C:\Program Files\FSLogix\Apps\frxdrv.sys",
            "C:\Program Files\FSLogix\Apps\frxdrvvt.sys",
            "C:\Program Files\FSLogix\Apps\frxccd.sys"
        )) {

            if (-not (
                Test-PathCoverage `
                    -RequiredPath $Driver `
                    -ConfiguredPaths $ExclusionPaths
            )) {

                $MissingExclusions.Add(
                    "Driver: $Driver"
                )
            }
        }

        foreach ($RequiredTempPath in @(
            "%TEMP%\*\*.VHD",
            "%TEMP%\*\*.VHDX",
            "%WINDIR%\TEMP\*\*.VHD",
            "%WINDIR%\TEMP\*\*.VHDX"
        )) {

            if (-not (
                Test-PathCoverage `
                    -RequiredPath $RequiredTempPath `
                    -ConfiguredPaths $ExclusionPaths
            )) {

                $RequiredExtension =
                    [System.IO.Path]::GetExtension(
                        $RequiredTempPath
                    ).TrimStart('.').ToLowerInvariant()

                $ExtensionCovered = @(
                    $ExclusionExtensions |
                    ForEach-Object {
                        $_.TrimStart('.').ToLowerInvariant()
                    }
                ) -contains $RequiredExtension

                if (-not $ExtensionCovered) {

                    $MissingExclusions.Add(
                        "Temporary VHD path: $RequiredTempPath"
                    )
                }
            }
        }

        foreach ($Location in $VHDLocations) {

            if (-not (
                Test-ShareContainerCoverage `
                    -SharePath $Location `
                    -ConfiguredPaths $ExclusionPaths `
                    -ConfiguredExtensions $ExclusionExtensions
            )) {

                $MissingExclusions.Add(
                    "Profile share: $Location"
                )
            }
        }

        if ($MissingExclusions.Count -eq 0) {

            Add-HealthResult `
                -Status "PASS" `
                -Category "Antivirus" `
                -Check "FSLogix Defender exclusions" `
                -Finding "Required FSLogix Defender exclusions are covered." `
                -Evidence "Validated using effective Defender path, process and extension exclusions."
        }
        else {

            $MissingText = $MissingExclusions -join "; "

            if ($DefenderActive) {

                Add-HealthResult `
                    -Status "FAIL" `
                    -Category "Antivirus" `
                    -Check "FSLogix Defender exclusions" `
                    -Finding "$($MissingExclusions.Count) required FSLogix exclusion(s) are not covered." `
                    -Evidence $MissingText `
                    -Recommendation "Add or correct the missing FSLogix exclusions in Microsoft Defender."
            }
            else {

                Add-HealthResult `
                    -Status "INFO" `
                    -Category "Antivirus" `
                    -Check "FSLogix Defender exclusions" `
                    -Finding "Defender exclusions are incomplete, but Defender does not appear to be the active real-time antivirus engine." `
                    -Evidence $MissingText `
                    -Recommendation "Validate equivalent FSLogix exclusions in the active antivirus product."
            }
        }
    }
}
else {

    Add-HealthResult `
        -Status "INFO" `
        -Category "Antivirus" `
        -Check "FSLogix antivirus exclusions" `
        -Finding "Antivirus exclusion checks were skipped because FSLogix is not installed."
}

# ------------------------------------------------------------
# FSLogix event log analysis
# ------------------------------------------------------------

if ($FSLogixInstalled) {

    $EventLogName = "Microsoft-FSLogix-Apps/Operational"
    $StartTime    = (Get-Date).AddDays(-$EventLookbackDays)

    try {

        $FSLogixErrors = @(
            Get-WinEvent `
                -FilterHashtable @{
                    LogName   = $EventLogName
                    Level     = 2
                    StartTime = $StartTime
                } `
                -ErrorAction Stop
        )

        if ($FSLogixErrors.Count -eq 0) {

            Add-HealthResult `
                -Status "PASS" `
                -Category "Runtime" `
                -Check "FSLogix event log errors" `
                -Finding "No FSLogix error-level events were recorded in the last $EventLookbackDays days." `
                -Evidence $EventLogName
        }
        else {

            $ClassifiedEvents = foreach ($Event in $FSLogixErrors) {

                $Classification = Get-FSLogixEventClassification `
                    -EventId $Event.Id `
                    -Message $Event.Message `
                    -DomainJoined $DomainJoined `
                    -AzureAdJoined $AzureAdJoined

                [PSCustomObject]@{
                    Event          = $Event
                    Classification = $Classification
                }
            }

            $Groups = $ClassifiedEvents |
                Group-Object {
                    $_.Classification.Key
                }

            foreach ($Group in $Groups) {

                $First          = $Group.Group[0]
                $Classification = $First.Classification

                $Samples = @(
                    $Group.Group |
                    Sort-Object {
                        $_.Event.TimeCreated
                    } -Descending |
                    Select-Object -First 3 |
                    ForEach-Object {

                        $CleanMessage = (
                            $_.Event.Message `
                            -replace '\r?\n', ' ' `
                            -replace '\s+', ' '
                        ).Trim()

                        if ($CleanMessage.Length -gt 350) {

                            $CleanMessage =
                                $CleanMessage.Substring(0,350) + "..."
                        }

                        "[{0}] Event {1}: {2}" -f `
                            $_.Event.TimeCreated.ToString("yyyy-MM-dd HH:mm"), `
                            $_.Event.Id, `
                            $CleanMessage
                    }
                )

                Add-HealthResult `
                    -Status $Classification.Status `
                    -Category "Runtime" `
                    -Check $Classification.Name `
                    -Finding "$($Group.Count) matching event(s) in the last $EventLookbackDays days." `
                    -Evidence ($Samples -join " | ") `
                    -Recommendation $Classification.Recommendation
            }
        }
    }
    catch {

        Add-HealthResult `
            -Status "INFO" `
            -Category "Runtime" `
            -Check "FSLogix event log errors" `
            -Finding "Unable to query the FSLogix Operational event log." `
            -Evidence $_.Exception.Message
    }
}
else {

    Add-HealthResult `
        -Status "INFO" `
        -Category "Runtime" `
        -Check "FSLogix event log errors" `
        -Finding "Event-log checks were skipped because FSLogix is not installed."
}

# ------------------------------------------------------------
# Current FSLogix session state
# ------------------------------------------------------------

if ($FSLogixInstalled) {

    $SessionRoot = "HKLM:\SOFTWARE\FSLogix\Profiles\Sessions"

    if (Test-Path $SessionRoot) {

        try {

            $SessionKeys = @(
                Get-ChildItem `
                    -Path $SessionRoot `
                    -ErrorAction Stop
            )

            if ($SessionKeys.Count -eq 0) {

                Add-HealthResult `
                    -Status "INFO" `
                    -Category "Runtime" `
                    -Check "Session attach status" `
                    -Finding "No FSLogix profile sessions are currently recorded."
            }
            else {

                $SessionStates = foreach ($Key in $SessionKeys) {

                    $Session = Get-ItemProperty `
                        -Path $Key.PSPath `
                        -ErrorAction SilentlyContinue

                    [PSCustomObject]@{
                        SID       = $Key.PSChildName
                        Status    = $Session.Status
                        ErrorCode = $Session.ErrorCode
                        Reason    = $Session.Reason
                    }
                }

                $FailedSessions = @(
                    $SessionStates |
                    Where-Object {
                        $null -ne $_.Status -and
                        $_.Status -ne 0
                    }
                )

                if ($FailedSessions.Count -eq 0) {

                    $SessionEvidence = (
                        $SessionStates |
                        ForEach-Object {
                            "$($_.SID): Status=$($_.Status)"
                        }
                    ) -join "; "

                    Add-HealthResult `
                        -Status "PASS" `
                        -Category "Runtime" `
                        -Check "Session attach status" `
                        -Finding "FSLogix session(s) recorded with no non-zero status values." `
                        -Evidence $SessionEvidence
                }
                else {

                    $SessionEvidence = (
                        $FailedSessions |
                        ForEach-Object {
                            "$($_.SID): Status=$($_.Status), ErrorCode=$($_.ErrorCode), Reason=$($_.Reason)"
                        }
                    ) -join "; "

                    Add-HealthResult `
                        -Status "WARN" `
                        -Category "Runtime" `
                        -Check "Session attach status" `
                        -Finding "$($FailedSessions.Count) FSLogix session(s) have a non-zero status." `
                        -Evidence $SessionEvidence `
                        -Recommendation "Review the affected session status against the FSLogix logs and error codes."
                }
            }
        }
        catch {

            Add-HealthResult `
                -Status "INFO" `
                -Category "Runtime" `
                -Check "Session attach status" `
                -Finding "Unable to inspect FSLogix session registry state." `
                -Evidence $_.Exception.Message
        }
    }
    else {

        Add-HealthResult `
            -Status "INFO" `
            -Category "Runtime" `
            -Check "Session attach status" `
            -Finding "No FSLogix session registry data is currently present."
    }
}
else {

    Add-HealthResult `
        -Status "INFO" `
        -Category "Runtime" `
        -Check "Session attach status" `
        -Finding "Session checks were skipped because FSLogix is not installed."
}

# ------------------------------------------------------------
# Temporary and orphaned profiles
# ------------------------------------------------------------

if ($FSLogixInstalled) {

    $ProfileListPath =
        "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList"

    $BakKeys     = @()
    $TempFolders = @()

    try {

        if (Test-Path $ProfileListPath) {

            $BakKeys = @(
                Get-ChildItem $ProfileListPath |
                Where-Object {
                    $_.PSChildName -like "*.bak"
                }
            )
        }

        if (Test-Path "C:\Users") {

            $TempFolders = @(
                Get-ChildItem `
                    "C:\Users" `
                    -Directory `
                    -ErrorAction SilentlyContinue |
                Where-Object {
                    $_.Name -eq "TEMP" -or
                    $_.Name -like "TEMP.*"
                }
            )
        }

        if (
            $BakKeys.Count -eq 0 -and
            $TempFolders.Count -eq 0
        ) {

            Add-HealthResult `
                -Status "PASS" `
                -Category "Runtime" `
                -Check "Temporary and orphaned profiles" `
                -Finding "No .bak ProfileList keys or TEMP profile folders were found."
        }
        else {

            $EvidenceParts = @()

            if ($BakKeys.Count -gt 0) {

                $EvidenceParts += (
                    "ProfileList .bak keys: " +
                    (($BakKeys | ForEach-Object {
                        $_.PSChildName
                    }) -join ", ")
                )
            }

            if ($TempFolders.Count -gt 0) {

                $EvidenceParts += (
                    "TEMP profile folders: " +
                    (($TempFolders | ForEach-Object {
                        $_.FullName
                    }) -join ", ")
                )
            }

            Add-HealthResult `
                -Status "WARN" `
                -Category "Runtime" `
                -Check "Temporary and orphaned profiles" `
                -Finding "Potential temporary or orphaned Windows profile data was found." `
                -Evidence ($EvidenceParts -join "; ") `
                -Recommendation "Review the affected profile entries before removing anything."
        }
    }
    catch {

        Add-HealthResult `
            -Status "INFO" `
            -Category "Runtime" `
            -Check "Temporary and orphaned profiles" `
            -Finding "Unable to inspect Windows profile state." `
            -Evidence $_.Exception.Message
    }
}
else {

    Add-HealthResult `
        -Status "INFO" `
        -Category "Runtime" `
        -Check "Temporary and orphaned profiles" `
        -Finding "Profile-state checks were skipped because FSLogix is not installed."
}

# ------------------------------------------------------------
# Local profile inventory
# ------------------------------------------------------------

if ($FSLogixInstalled) {

    try {

        $LocalProfiles = @(
            Get-CimInstance Win32_UserProfile |
            Where-Object {
                -not $_.Special -and
                $_.LocalPath -like "C:\Users\*"
            }
        )

        if ($LocalProfiles.Count -eq 0) {

            Add-HealthResult `
                -Status "PASS" `
                -Category "Runtime" `
                -Check "Local profile inventory" `
                -Finding "No non-special local Windows profiles were found."
        }
        else {

            $ProfileEvidence = (
                $LocalProfiles |
                ForEach-Object {
                    "$($_.LocalPath) [Loaded=$($_.Loaded)]"
                }
            ) -join "; "

            Add-HealthResult `
                -Status "INFO" `
                -Category "Runtime" `
                -Check "Local profile inventory" `
                -Finding "$($LocalProfiles.Count) non-special local profile(s) are present." `
                -Evidence $ProfileEvidence `
                -Recommendation "Review only if an unexpected user is using a local profile instead of an FSLogix container."
        }
    }
    catch {

        Add-HealthResult `
            -Status "INFO" `
            -Category "Runtime" `
            -Check "Local profile inventory" `
            -Finding "Unable to enumerate local Windows profiles." `
            -Evidence $_.Exception.Message
    }
}
else {

    Add-HealthResult `
        -Status "INFO" `
        -Category "Runtime" `
        -Check "Local profile inventory" `
        -Finding "Local profile inventory was skipped because FSLogix is not installed."
}

# ------------------------------------------------------------
# FSLogix text logging
# ------------------------------------------------------------

if ($FSLogixInstalled) {

    try {

        $LoggingRegPath = "HKLM:\SOFTWARE\FSLogix\Logging"
        $LogDir         = "C:\ProgramData\FSLogix\Logs"

        if (Test-Path $LoggingRegPath) {

            $LoggingConfig = Get-ItemProperty `
                -Path $LoggingRegPath `
                -ErrorAction SilentlyContinue

            if ($LoggingConfig.LogDir) {

                $LogDir = [Environment]::ExpandEnvironmentVariables(
                    [string]$LoggingConfig.LogDir
                )
            }
        }

        if (Test-Path $LogDir) {

            $RecentLogs = @(
                Get-ChildItem `
                    -Path $LogDir `
                    -Filter "*.log" `
                    -File `
                    -Recurse `
                    -ErrorAction SilentlyContinue |
                Where-Object {
                    $_.LastWriteTime -ge
                    (Get-Date).AddDays(-$EventLookbackDays)
                }
            )

            if ($RecentLogs.Count -gt 0) {

                Add-HealthResult `
                    -Status "PASS" `
                    -Category "Runtime" `
                    -Check "FSLogix text logging" `
                    -Finding "FSLogix text logging is active." `
                    -Evidence "$($RecentLogs.Count) log file(s) updated within the last $EventLookbackDays days. Log directory: $LogDir"
            }
            else {

                Add-HealthResult `
                    -Status "INFO" `
                    -Category "Runtime" `
                    -Check "FSLogix text logging" `
                    -Finding "The FSLogix log directory exists, but no recent .log files were found." `
                    -Evidence "Log directory: $LogDir"
            }
        }
        else {

            Add-HealthResult `
                -Status "INFO" `
                -Category "Runtime" `
                -Check "FSLogix text logging" `
                -Finding "The configured/default FSLogix log directory was not found." `
                -Evidence "Expected path: $LogDir" `
                -Recommendation "Review logging only if troubleshooting data is required."
        }
    }
    catch {

        Add-HealthResult `
            -Status "INFO" `
            -Category "Runtime" `
            -Check "FSLogix text logging" `
            -Finding "Unable to inspect FSLogix text logging." `
            -Evidence $_.Exception.Message
    }
}
else {

    Add-HealthResult `
        -Status "INFO" `
        -Category "Runtime" `
        -Check "FSLogix text logging" `
        -Finding "Logging checks were skipped because FSLogix is not installed."
}

# ------------------------------------------------------------
# Result totals
# ------------------------------------------------------------

$PassCount = @(
    $Results |
    Where-Object Status -eq "PASS"
).Count

$WarnCount = @(
    $Results |
    Where-Object Status -eq "WARN"
).Count

$FailCount = @(
    $Results |
    Where-Object Status -eq "FAIL"
).Count

$InfoCount = @(
    $Results |
    Where-Object Status -eq "INFO"
).Count

# ------------------------------------------------------------
# JSON output
# ------------------------------------------------------------

$JsonFile = Join-Path `
    $ReportPath `
    "FSLogix-Health-Audit-$ComputerName-$Timestamp.json"

$JsonOutput = [PSCustomObject]@{
    ScriptVersion = $ScriptVersion
    ComputerName  = $ComputerName
    Generated     = $Generated

    AuditParameters = [PSCustomObject]@{
        ReportPath              = $ReportPath
        EventLookbackDays       = $EventLookbackDays
        ContainerWarningPercent = $ContainerWarningPercent
        MaxContainerFiles       = $MaxContainerFiles
    }

    Summary = [PSCustomObject]@{
        Pass = $PassCount
        Warn = $WarnCount
        Fail = $FailCount
        Info = $InfoCount
    }

    Results = $Results
}

$JsonOutput |
    ConvertTo-Json -Depth 6 |
    Set-Content -Path $JsonFile -Encoding UTF8

# ------------------------------------------------------------
# HTML output
# ------------------------------------------------------------

$HtmlFile = Join-Path `
    $ReportPath `
    "FSLogix-Health-Audit-$ComputerName-$Timestamp.html"

$HtmlRows = foreach ($Result in $Results) {

    switch ($Result.Status) {

        "PASS" {
            $StatusClass = "pass"
        }

        "WARN" {
            $StatusClass = "warn"
        }

        "FAIL" {
            $StatusClass = "fail"
        }

        default {
            $StatusClass = "info"
        }
    }

    $SafeCategory       = ConvertTo-HtmlSafe $Result.Category
    $SafeStatus         = ConvertTo-HtmlSafe $Result.Status
    $SafeCheck          = ConvertTo-HtmlSafe $Result.Check
    $SafeFinding        = ConvertTo-HtmlSafe $Result.Finding
    $SafeEvidence       = ConvertTo-HtmlSafe $Result.Evidence
    $SafeRecommendation = ConvertTo-HtmlSafe $Result.Recommendation

    @"
<tr class="$StatusClass">
    <td>$SafeCategory</td>
    <td><strong>$SafeStatus</strong></td>
    <td>$SafeCheck</td>
    <td>$SafeFinding</td>
    <td>$SafeEvidence</td>
    <td>$SafeRecommendation</td>
</tr>
"@
}

$SafeComputerName = ConvertTo-HtmlSafe $ComputerName
$SafeGenerated    = ConvertTo-HtmlSafe $Generated
$SafeVersion      = ConvertTo-HtmlSafe $ScriptVersion
$SafeReportPath   = ConvertTo-HtmlSafe $ReportPath

$Html = @"
<!DOCTYPE html>
<html lang="en">

<head>
<meta charset="utf-8">

<title>FSLogix Health Audit - $SafeComputerName</title>

<style>

body {
    font-family: Segoe UI, Arial, sans-serif;
    margin: 30px;
    background: #f5f5f5;
    color: #222;
}

h1 {
    margin-bottom: 5px;
}

.meta {
    margin-bottom: 20px;
    color: #555;
    line-height: 1.5;
}

.parameters {
    background: white;
    border: 1px solid #ddd;
    border-radius: 6px;
    padding: 12px 16px;
    margin-bottom: 20px;
    line-height: 1.5;
}

.parameters strong {
    display: inline-block;
    min-width: 210px;
}

.summary {
    display: flex;
    gap: 12px;
    margin-bottom: 20px;
}

.summary-box {
    background: white;
    border: 1px solid #ddd;
    border-radius: 6px;
    padding: 10px 18px;
    min-width: 80px;
    text-align: center;
}

.summary-number {
    font-size: 24px;
    font-weight: 700;
}

.summary-label {
    font-size: 12px;
    color: #666;
}

table {
    width: 100%;
    border-collapse: collapse;
    background: white;
}

th {
    background: #333;
    color: white;
    text-align: left;
    padding: 10px;
}

td {
    padding: 10px;
    border-bottom: 1px solid #ddd;
    vertical-align: top;
    word-break: break-word;
}

.pass {
    border-left: 5px solid #2e7d32;
}

.warn {
    border-left: 5px solid #b8860b;
}

.fail {
    border-left: 5px solid #c62828;
}

.info {
    border-left: 5px solid #607d8b;
}

</style>
</head>

<body>

<h1>FSLogix Health Audit</h1>

<div class="meta">
Computer: $SafeComputerName<br>
Generated: $SafeGenerated<br>
Audit version: $SafeVersion
</div>

<div class="parameters">
<strong>Event lookback:</strong> $EventLookbackDays days<br>
<strong>Container warning threshold:</strong> $ContainerWarningPercent%<br>
<strong>Maximum container files:</strong> $MaxContainerFiles<br>
<strong>Report path:</strong> $SafeReportPath
</div>

<div class="summary">

<div class="summary-box">
    <div class="summary-number">$PassCount</div>
    <div class="summary-label">PASS</div>
</div>

<div class="summary-box">
    <div class="summary-number">$WarnCount</div>
    <div class="summary-label">WARN</div>
</div>

<div class="summary-box">
    <div class="summary-number">$FailCount</div>
    <div class="summary-label">FAIL</div>
</div>

<div class="summary-box">
    <div class="summary-number">$InfoCount</div>
    <div class="summary-label">INFO</div>
</div>

</div>

<table>

<tr>
    <th>Category</th>
    <th>Status</th>
    <th>Check</th>
    <th>Finding</th>
    <th>Evidence</th>
    <th>Recommendation</th>
</tr>

$($HtmlRows -join "`n")

</table>

</body>
</html>
"@

$Html |
    Set-Content -Path $HtmlFile -Encoding UTF8

# ------------------------------------------------------------
# Console output
# ------------------------------------------------------------

Write-Host ""
Write-Host "FSLogix Health Audit"
Write-Host "--------------------"
Write-Host "Version     : $ScriptVersion"
Write-Host "Computer    : $ComputerName"
Write-Host "PASS        : $PassCount"
Write-Host "WARN        : $WarnCount"
Write-Host "FAIL        : $FailCount"
Write-Host "INFO        : $InfoCount"
Write-Host ""
Write-Host "Parameters"
Write-Host "----------"
Write-Host "Event lookback days       : $EventLookbackDays"
Write-Host "Container warning percent : $ContainerWarningPercent"
Write-Host "Maximum container files   : $MaxContainerFiles"
Write-Host ""
Write-Host "JSON report : $JsonFile"
Write-Host "HTML report : $HtmlFile"
Write-Host ""

$Results |
    Sort-Object Category, Check |
    Format-Table Category, Status, Check, Finding -AutoSize