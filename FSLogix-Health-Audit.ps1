param (
    [string]$ReportPath = "C:\Temp",
    [int]$EventLookbackDays = 7
)

$ErrorActionPreference = "Stop"

# ------------------------------------------------------------
# Initial setup
# ------------------------------------------------------------

if (-not (Test-Path $ReportPath)) {
    New-Item -Path $ReportPath -ItemType Directory -Force | Out-Null
}

$ComputerName = $env:COMPUTERNAME
$Timestamp    = Get-Date -Format "yyyyMMdd-HHmmss"

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

function Normalize-PathString {
    param (
        [string]$Path
    )

    if ([string]::IsNullOrWhiteSpace($Path)) {
        return ""
    }

    $Normalized = $Path.Trim()

    # Treat a username-specific path as equivalent to a wildcard user path.
    $Normalized = $Normalized -replace '(?i)%username%', '*'

    # Expand standard Windows environment variables.
    $Normalized = [Environment]::ExpandEnvironmentVariables($Normalized)

    $Normalized = $Normalized -replace '/', '\'
    $Normalized = $Normalized.TrimEnd('\')

    return $Normalized.ToLowerInvariant()
}

function Test-PathCoverage {
    param (
        [Parameter(Mandatory)]
        [string]$RequiredPath,

        [Parameter(Mandatory)]
        [string[]]$ConfiguredPaths
    )

    $Required = Normalize-PathString $RequiredPath

    foreach ($ConfiguredPath in $ConfiguredPaths) {

        $Configured = Normalize-PathString $ConfiguredPath

        if ([string]::IsNullOrWhiteSpace($Configured)) {
            continue
        }

        # Exact match
        if ($Configured -eq $Required) {
            return $true
        }

        # Wildcard coverage
        if ($Required -like $Configured) {
            return $true
        }

        if ($Configured -like $Required) {
            return $true
        }

        # Parent folder exclusion covers children
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

        [Parameter(Mandatory)]
        [string[]]$ConfiguredProcesses
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

        [Parameter(Mandatory)]
        [string[]]$ConfiguredPaths,

        [Parameter(Mandatory)]
        [string[]]$ConfiguredExtensions
    )

    $Share = (Normalize-PathString $SharePath).TrimEnd('\')

    # Whole-share exclusion
    if (
        Test-PathCoverage `
            -RequiredPath $Share `
            -ConfiguredPaths $ConfiguredPaths
    ) {
        return $true
    }

    # Extension exclusions can also cover the container files.
    $Extensions = @(
        $ConfiguredExtensions |
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

    # Microsoft-style individual patterns.
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
        -Evidence "DomainJoined=$DomainJoined; AzureAdJoined=$AzureAdJoined"
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

$ProfilesRegPath = "HKLM:\SOFTWARE\FSLogix\Profiles"
$ProfileConfig   = $null
$VHDLocations    = @()

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
# Storage checks
# ------------------------------------------------------------

if ($VHDLocations.Count -gt 0) {

    foreach ($Location in $VHDLocations) {

        if ($Location -match '^\\\\([^\\]+)\\(.+)$') {

            $StorageHost = $Matches[1]

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

            try {

                if (Test-Path -Path $Location) {

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

                $First = $Group.Group[0]
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
                Get-ChildItem -Path $SessionRoot -ErrorAction Stop
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

                    Add-HealthResult `
                        -Status "PASS" `
                        -Category "Runtime" `
                        -Check "Session attach status" `
                        -Finding "$($SessionStates.Count) FSLogix session(s) recorded with no non-zero status values." `
                        -Evidence (
                            $SessionStates |
                            ForEach-Object {
                                "$($_.SID): Status=$($_.Status)"
                            }
                        ) -join "; "
                }
                else {

                    Add-HealthResult `
                        -Status "WARN" `
                        -Category "Runtime" `
                        -Check "Session attach status" `
                        -Finding "$($FailedSessions.Count) FSLogix session(s) have a non-zero status." `
                        -Evidence (
                            $FailedSessions |
                            ForEach-Object {
                                "$($_.SID): Status=$($_.Status), ErrorCode=$($_.ErrorCode), Reason=$($_.Reason)"
                            }
                        ) -join "; " `
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

    $BakKeys = @()
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
                Get-ChildItem "C:\Users" `
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

            # Deliberately INFO rather than WARN.
            # Admin/service profiles can legitimately exist on an AVD host.
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
        $LogDir = "C:\ProgramData\FSLogix\Logs"

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
                    -Evidence "$RecentLogs.Count log file(s) updated within the last $EventLookbackDays days. Log directory: $LogDir"
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
    ComputerName = $ComputerName
    Generated    = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    Summary      = [PSCustomObject]@{
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

    @"
<tr class="$StatusClass">
    <td>$($Result.Category)</td>
    <td><strong>$($Result.Status)</strong></td>
    <td>$($Result.Check)</td>
    <td>$($Result.Finding)</td>
    <td>$($Result.Evidence)</td>
    <td>$($Result.Recommendation)</td>
</tr>
"@
}

$Html = @"
<!DOCTYPE html>
<html lang="en">

<head>
<meta charset="utf-8">

<title>FSLogix Health Audit - $ComputerName</title>

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
Computer: $ComputerName<br>
Generated: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
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
Write-Host "JSON report : $JsonFile"
Write-Host "HTML report : $HtmlFile"
Write-Host ""

$Results |
    Sort-Object Category, Check |
    Format-Table Category, Status, Check, Finding -AutoSize