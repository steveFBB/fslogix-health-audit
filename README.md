# FSLogix Health Audit

A read-only PowerShell health audit for FSLogix Profile Container environments.

The script is designed to provide a practical, low-noise assessment of the local FSLogix configuration, runtime state, storage access, antivirus exclusions, profile container usage, and supporting Active Directory health.

It does not make configuration changes, delete profiles, restart services, mount containers, or initiate Azure authentication.

## Current Version

`0.9.4`

## What the Audit Checks

The script currently checks:

- Windows operating system and device join state
- Audit execution context (identity, elevation, PowerShell version)
- Active Directory computer secure channel
- Domain controller discovery
- Active Directory DNS SRV records
- FSLogix installation and version
- FSLogix service state
- Profile Container enablement
- Configured `VHDLocations` (MULTI_SZ or semicolon-separated REG_SZ)
- Configured Cloud Cache `CCDLocations` (SMB and Azure page-blob providers)
- `DeleteLocalProfileWhenVHDShouldApply`
- `PreventLoginWithFailure`
- `PreventLoginWithTempProfile`
- `LockedRetryCount`
- `LockedRetryInterval`
- `ReAttachRetryCount`
- `ReAttachIntervalSeconds`
- `ProfileType`
- `SizeInMBs`
- `VolumeType`
- `FlipFlopProfileDirectoryName`
- Optional `redirections.xml` validation when `RedirXMLSourceFolder` is configured
- FSLogix minifilter driver files
- Loaded FSLogix minifilter drivers
- FSLogix local include and exclude groups
- Include and exclude group membership
- SMB connectivity to profile storage
- Profile share reachability
- Profile container VHD/VHDX file-size inventory
- Profile containers approaching their configured `SizeInMBs` limit
- Optional Azure Files share capacity when Azure PowerShell is already available and authenticated
- Microsoft Defender Antivirus state
- Effective FSLogix Defender exclusions
- FSLogix Operational event-log errors
- Known Event ID 26 conditions
- Current FSLogix session Status, Reason and Error values
- Temporary and orphaned Windows profiles
- Local profile inventory, distinguishing FSLogix-attached profiles from true local profiles
- FSLogix text logging

## Read-Only Behaviour

When run interactively, the script displays a confirmation prompt before beginning.

Nothing is queried until the operator selects:

```text
[R] Run
```

The prompt is skipped when `-NonInteractive` is used.

The audit is read-only.

It does not:

- modify FSLogix settings
- modify Group Policy
- delete profiles
- modify VHD or VHDX files
- mount profile containers
- restart services
- repair the secure channel
- modify Defender exclusions
- install PowerShell modules
- sign in to Azure
- modify Azure resources

## Requirements

The script is intended to run locally on a Windows device using FSLogix.

Run PowerShell with sufficient rights to query:

- local registry settings
- services
- minifilter drivers
- local groups
- Windows event logs
- profile registry state
- configured FSLogix storage

Administrative (elevated) PowerShell is recommended. Defender exclusion validation is only performed when the audit is running elevated.

Windows PowerShell 5.1 is the primary target. When `Test-ComputerSecureChannel` is unavailable (for example, in PowerShell 7), the script falls back to `nltest /sc_query`.

FSLogix storage checks depend on the account running the audit having access to the configured profile share. The execution identity is recorded in the report so results can be interpreted in that context.

## Usage

Basic interactive usage:

```powershell
.\FSLogix-Health-Audit.ps1
```

Specify a different report location:

```powershell
.\FSLogix-Health-Audit.ps1 -ReportPath "C:\Reports"
```

Use a different event-log lookback period:

```powershell
.\FSLogix-Health-Audit.ps1 -EventLookbackDays 14
```

Change the profile-container warning threshold:

```powershell
.\FSLogix-Health-Audit.ps1 -ContainerWarningPercent 85
```

Increase the maximum number of profile containers that may be scanned:

```powershell
.\FSLogix-Health-Audit.ps1 -MaxContainerFiles 2000
```

Run without the confirmation prompt (automation):

```powershell
.\FSLogix-Health-Audit.ps1 -NonInteractive
```

Parameters can be combined:

```powershell
.\FSLogix-Health-Audit.ps1 `
    -ReportPath "C:\Reports" `
    -EventLookbackDays 14 `
    -ContainerWarningPercent 85 `
    -MaxContainerFiles 2000 `
    -NonInteractive
```

## Parameters

### `-ReportPath`

Default:

```text
C:\Temp
```

Controls where the HTML and JSON reports are written.

### `-EventLookbackDays`

Default:

```text
7
```

Controls how many days of FSLogix Operational event-log history are reviewed.

### `-ContainerWarningPercent`

Default:

```text
90
```

Controls when the audit warns that a profile container file is approaching the configured `SizeInMBs` maximum.

For example, with the default FSLogix maximum size of `30000 MB`, a 90% threshold is approximately `27000 MB`.

This threshold is an audit threshold and is configurable.

### `-MaxContainerFiles`

Default:

```text
1000
```

Limits the number of VHD/VHDX files inspected during the profile-container inventory.

This prevents the audit from performing an unrestricted scan of very large profile shares.

### `-NonInteractive`

Skips the startup confirmation prompt and exits with the audit exit code. Use this for scheduled tasks, Azure Run Command, Intune remediations or pipeline execution.

## Exit Codes

| Code | Meaning |
| ---- | ------- |
| `0` | No WARN or FAIL results |
| `1` | One or more WARN results, no FAIL |
| `2` | One or more FAIL results |

The exit code is also recorded in the HTML and JSON reports.

When calling the script from another process, use `powershell.exe -File` so the exit code is passed through directly. If using `-Command`, end the command with `exit $LASTEXITCODE`.

```powershell
powershell.exe -ExecutionPolicy Bypass -File .\FSLogix-Health-Audit.ps1 -NonInteractive
```

## Profile Storage Configuration

### VHDLocations

`VHDLocations` is supported as either MULTI_SZ or REG_SZ. Semicolon-separated REG_SZ values are split into individual locations, and each location is checked separately.

### Cloud Cache (CCDLocations)

When `CCDLocations` is configured, the script parses each provider's `type`, `name` and `connectionString`.

- `type=smb` providers are tested using the same SMB connectivity, share reachability, container inventory and capacity checks as `VHDLocations`.
- `type=azure` (page-blob) providers are recognised and reported as INFO, but are not tested with SMB/UNC checks.
- If both `VHDLocations` and `CCDLocations` are configured, a WARN is raised for review.
- If `CCDLocations` is present but no usable provider can be parsed, a FAIL is raised.

## Profile Container Size Scan

The script performs a read-only inspection of VHD and VHDX file metadata.

It does not mount the containers or inspect their contents.

The scan checks:

- VHD/VHDX files directly in the configured storage location
- VHD/VHDX files one directory level below the configured location

This covers common FSLogix profile-container directory layouts without recursively crawling the entire storage share.

The report includes:

- number of containers scanned
- total size of scanned container files
- largest containers
- percentage of configured `SizeInMBs`
- warning when a container reaches the configured audit threshold

Physical container file size approaching `SizeInMBs` does not by itself prove that the filesystem inside the container has little free space.

## Azure Files Capacity

Azure Files storage is detected when the configured path matches:

```text
\\<storageaccount>.file.core.windows.net\<share>
```

The script does not install Azure PowerShell or sign in to Azure.

Azure Files capacity is queried only when:

- the required Az PowerShell commands are already available
- an authenticated Azure PowerShell context already exists
- the current account can read the storage account and file share

If those requirements are not met, the capacity check returns `INFO` and the rest of the audit continues normally.

SMB connectivity and share-access checks do not require Azure PowerShell.

## Active Directory Health

For domain-joined devices, the script performs live checks for:

- computer secure channel (`Test-ComputerSecureChannel`, with `nltest /sc_query` fallback)
- domain controller discovery
- Active Directory DNS SRV records

These live checks are reported separately from historical FSLogix event-log warnings.

This allows the report to show, for example, that a domain lookup problem occurred recently while the computer's current domain connectivity is healthy.

For non-domain-joined devices, these checks are skipped and reported as informational.

## FSLogix Configuration Baseline

The audit evaluates important Profile Container settings and reports both the effective value and whether the setting is explicitly configured.

Settings currently evaluated include:

- `Enabled`
- `VHDLocations` / `CCDLocations`
- `DeleteLocalProfileWhenVHDShouldApply`
- `PreventLoginWithFailure`
- `PreventLoginWithTempProfile`
- `LockedRetryCount`
- `LockedRetryInterval`
- `ReAttachRetryCount`
- `ReAttachIntervalSeconds`
- `ProfileType`
- `SizeInMBs`
- `VolumeType`
- `FlipFlopProfileDirectoryName`

Where a registry value is absent, the script uses the applicable FSLogix default for the audit result.

## redirections.xml

The script does not require custom FSLogix redirections.

`RedirXMLSourceFolder` is only evaluated when it is already configured.

When configured, the audit checks:

- whether the source folder is reachable
- whether a file named `redirections.xml` exists
- whether the XML can be parsed
- whether the expected `FrxProfileFolderRedirection` root element exists
- number of include and exclude entries
- `ExcludeCommonFolders`

An environment that does not use `RedirXMLSourceFolder` is not treated as unhealthy.

## FSLogix Minifilter Drivers

The audit checks for the expected FSLogix driver files:

```text
frxdrv.sys
frxdrvvt.sys
frxccd.sys
```

It also queries the Windows Filter Manager using `fltmc.exe` and checks whether the following filters are loaded:

```text
frxdrv
frxdrvvt
frxccd
```

If `fltmc.exe` cannot be queried successfully, the script reports that the state could not be verified rather than incorrectly marking the filters as failed.

## FSLogix Local Groups

The following local groups are checked:

```text
FSLogix Profile Include List
FSLogix Profile Exclude List
FSLogix ODFC Include List
FSLogix ODFC Exclude List
```

The script also checks group membership.

Default-style configuration is recognised as:

- `Everyone` in the include groups
- no members in the exclude groups

Custom group membership is reported as informational rather than automatically treated as incorrect.

## Microsoft Defender Exclusions

When Microsoft Defender Antivirus is active, the audit validates effective FSLogix exclusions for:

- FSLogix processes (`frxsvc.exe`, `frxccds.exe`)
- FSLogix installation and data paths
- per-user FSLogix local data
- Cloud Cache `Cache` and `Proxy` paths (when Cloud Cache is configured)
- FSLogix driver files
- temporary VHD/VHDX paths
- profile-container storage (`.vhd`, `.vhdx` and associated `.lock`, `.meta`, `.metadata` files)
- VHD/VHDX extension coverage where applicable

Coverage is evaluated rather than relying only on exact string matches:

- a literal parent folder exclusion covers everything beneath it, including wildcard child paths
- a configured wildcard exclusion can cover a specific required path
- a narrow configured exclusion is never treated as covering a broader required wildcard path
- literal `[` and `]` characters in paths are escaped so they are not treated as wildcards

Exclusion validation is skipped (reported as INFO) when:

- the audit is not running elevated
- `HideExclusionsFromLocalAdmins` is enabled, or Defender returns hidden/placeholder exclusion data

In those cases, validate the exclusions in the centrally managed Defender policy.

If Microsoft Defender is not the active real-time antivirus engine, missing Defender exclusions are reported as informational and the active third-party antivirus configuration should be checked separately.

## Runtime Checks

The runtime section currently checks:

- recent FSLogix Operational event-log errors
- known Event ID 26 conditions
- current FSLogix session Status, Reason and Error values
- `.bak` ProfileList entries
- `TEMP` profile folders
- local profile inventory
- FSLogix text logging

Known Event ID 26 messages are classified separately where possible, including:

- known-folder redirection access-denied errors
- domain lookup failures
- Entra-only LDAP lookup behaviour

### Session state

Session state is read from `HKLM:\SOFTWARE\FSLogix\Profiles\Sessions\<SID>`. Each SID is resolved to an account name in the evidence.

- Status `1`–`28`, or a non-zero Error value: WARN
- Reason `3` (local profile exists), `7` (Windows temporary profile) or `9` (profile load failed): WARN
- Reason `1`, `2`, `4` or `8` (not included, excluded, inappropriate user type, non-AVD session): INFO
- Status `100`, `200` or `300` (normal setup or already-attached states): INFO
- Missing or unclassified Status: INFO
- Status `0` with Reason `0`: PASS

### Local profile inventory

FSLogix mounts attached containers at `C:\Users\<user>`, so these appear in the Windows profile list. The audit cross-references profiles against FSLogix session state and treats a profile as FSLogix-backed when its SID has Status `0` or `300` with Reason `0`.

- Only FSLogix-backed profiles present: PASS, with the attached profiles listed in the evidence
- Profiles not backed by an attached container: INFO, with local and FSLogix-backed profiles listed separately

## Result Statuses

### PASS

The check completed successfully and the detected state matches the expected healthy condition.

### WARN

The audit detected a condition that should be reviewed.

Warnings are intended for actionable or potentially significant findings rather than cosmetic deviations.

### FAIL

The audit detected a condition that directly indicates a failed or missing component required for the check.

### INFO

The result is informational, optional, intentionally non-evaluative, or could not be fully checked because an optional dependency was unavailable.

Examples include:

- operating system details
- execution context
- device join state
- Azure Files capacity when Azure PowerShell is unavailable
- custom group membership
- optional configuration differences

## Reports

Each run generates:

```text
FSLogix-Health-Audit-<computer>-<timestamp>.html
FSLogix-Health-Audit-<computer>-<timestamp>.json
```

The HTML report contains:

- computer name
- generation time
- audit version
- execution identity, elevation and PowerShell version
- audit parameters
- audit exit code
- PASS/WARN/FAIL/INFO totals
- full result table
- evidence
- recommendations

### HTML report layout

The HTML report is colour-coded so issues can be found at a glance:

- Summary boxes show the PASS, WARN, FAIL and INFO totals in solid status colours (green, amber, red and grey).
- Results are grouped into sections by category (Host, Domain, Install, Services, Configuration, Drivers, Groups, Storage, Antivirus, Runtime), each with its own coloured header.
- Each section header shows that section's status counts, so problem areas stand out without reading every row.
- Each result has a coloured status badge and a coloured left edge; WARN and FAIL rows are also tinted.
- Colours are chosen for readable white text and are preserved when the report is printed or saved to PDF.

The JSON report contains the same core result data in a structured format suitable for automation or later processing.

Example JSON structure:

```json
{
  "ScriptVersion": "0.9.4",
  "ComputerName": "HOST01",
  "Generated": "2026-09-24 19:08:17",
  "ExecutionContext": {
    "Identity": "CONTOSO\\admin",
    "Elevated": true,
    "PowerShellVersion": "5.1.26100.9444",
    "PowerShellEdition": "Desktop"
  },
  "AuditParameters": {
    "ReportPath": "C:\\Temp",
    "EventLookbackDays": 7,
    "ContainerWarningPercent": 90,
    "MaxContainerFiles": 1000,
    "NonInteractive": false
  },
  "Summary": {
    "Pass": 31,
    "Warn": 5,
    "Fail": 0,
    "Info": 7,
    "ExitCode": 1
  },
  "Results": []
}
```

Reports can contain usernames, SIDs and profile container file names. Review before sharing outside the organisation that owns the environment.

## HTML Report Safety

Dynamic report content is HTML-encoded before being written to the HTML file.

This prevents event-log messages, UNC paths, account names, or other returned values containing characters such as:

```text
<
>
&
```

from breaking the generated report markup.

## Design Goals

This project is intended to remain:

- read-only
- portable
- vendor-neutral
- useful on both Azure Files and traditional SMB storage
- conservative about reporting failures
- resistant to common FSLogix false positives
- useful for both troubleshooting and proactive health reviews
- suitable for both interactive and automated execution

The goal is not to enforce one specific FSLogix design.

Where a configuration can legitimately vary between environments, the script aims to report the detected state and distinguish between:

- an actual fault
- a recommendation
- an intentional custom configuration
- an optional check that could not be completed

## Limitations

The audit currently has several intentional limitations:

- Azure Files quota requires existing Azure PowerShell modules and an authenticated Azure context.
- Azure page-blob Cloud Cache providers are recognised but not connectivity-tested.
- Profile-container size scanning reads file metadata only and does not determine free space inside mounted VHD/VHDX files.
- Container scanning is limited to the share root and one directory level below it.
- Defender exclusion validation currently targets Microsoft Defender; third-party antivirus products must be reviewed separately.
- Defender exclusion validation requires elevation and is skipped when exclusions are hidden from local administrators.
- ODFC container configuration and ODFC session state are not currently evaluated.
- The audit does not remediate any detected condition.
- It does not replace detailed FSLogix log analysis for complex profile-attach failures.
- It does not currently perform full Azure Virtual Desktop host-pool or AVD-agent health checks.

## Output Interpretation

A report with warnings does not automatically mean FSLogix is unusable.

For example, a historical Event ID 26 warning may remain in the configured event lookback window while the current domain secure channel, DNS and profile attachment state all pass.

Review the evidence and recommendation for each finding rather than treating the summary counts as a standalone health score.

## Project Status

Version `0.9.4` is a pre-release. The next planned milestone is `1.0.0`.