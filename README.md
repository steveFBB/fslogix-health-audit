````markdown
# FSLogix Health Audit

A read-only PowerShell health audit for FSLogix Profile Container environments.

The script is designed to provide a practical, low-noise assessment of the local FSLogix configuration, runtime state, storage access, antivirus exclusions, profile container usage, and supporting Active Directory health.

It does not make configuration changes, delete profiles, restart services, mount containers, or initiate Azure authentication.

## Current Version

`0.9.0`

## What the Audit Checks

The script currently checks:

- Windows operating system and device join state
- Active Directory computer secure channel
- Domain controller discovery
- Active Directory DNS SRV records
- FSLogix installation and version
- FSLogix service state
- Profile Container enablement
- Configured `VHDLocations`
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
- Current FSLogix session attach status
- Temporary and orphaned Windows profiles
- Local non-special profile inventory
- FSLogix text logging

## Read-Only Behaviour

The script displays a confirmation prompt before beginning.

Nothing is queried until the operator selects:

```text
[R] Run
````

The audit is read-only.

It does not:

* modify FSLogix settings
* modify Group Policy
* delete profiles
* modify VHD or VHDX files
* mount profile containers
* restart services
* repair the secure channel
* modify Defender exclusions
* install PowerShell modules
* sign in to Azure
* modify Azure resources

## Requirements

The script is intended to run locally on a Windows device using FSLogix.

Run PowerShell with sufficient rights to query:

* local registry settings
* services
* minifilter drivers
* local groups
* Windows event logs
* profile registry state
* configured FSLogix storage

Administrative PowerShell is recommended.

FSLogix storage checks also depend on the account running the audit having access to the configured profile share.

## Usage

Basic usage:

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

Parameters can be combined:

```powershell
.\FSLogix-Health-Audit.ps1 `
    -ReportPath "C:\Reports" `
    -EventLookbackDays 14 `
    -ContainerWarningPercent 85 `
    -MaxContainerFiles 2000
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

## Profile Container Size Scan

The script performs a read-only inspection of VHD and VHDX file metadata.

It does not mount the containers or inspect their contents.

The scan checks:

* VHD/VHDX files directly in the configured `VHDLocations`
* VHD/VHDX files one directory level below the configured location

This covers common FSLogix profile-container directory layouts without recursively crawling the entire storage share.

The report includes:

* number of containers scanned
* total size of scanned container files
* largest containers
* percentage of configured `SizeInMBs`
* warning when a container reaches the configured audit threshold

## Azure Files Capacity

Azure Files storage is detected when the configured path matches:

```text
\\<storageaccount>.file.core.windows.net\<share>
```

The script does not install Azure PowerShell or sign in to Azure.

Azure Files capacity is queried only when:

* the required Az PowerShell commands are already available
* an authenticated Azure PowerShell context already exists
* the current account can read the storage account and file share

If those requirements are not met, the capacity check returns `INFO` and the rest of the audit continues normally.

SMB connectivity and share-access checks do not require Azure PowerShell.

## Active Directory Health

For domain-joined devices, the script performs live checks for:

* computer secure channel
* domain controller discovery
* Active Directory DNS SRV records

These live checks are reported separately from historical FSLogix event-log warnings.

This allows the report to show, for example, that a domain lookup problem occurred recently while the computer's current domain connectivity is healthy.

For non-domain-joined devices, these checks are skipped and reported as informational.

## FSLogix Configuration Baseline

The audit evaluates important Profile Container settings and reports both the effective value and whether the setting is explicitly configured.

Settings currently evaluated include:

* `Enabled`
* `VHDLocations`
* `DeleteLocalProfileWhenVHDShouldApply`
* `PreventLoginWithFailure`
* `PreventLoginWithTempProfile`
* `LockedRetryCount`
* `LockedRetryInterval`
* `ReAttachRetryCount`
* `ReAttachIntervalSeconds`
* `ProfileType`
* `SizeInMBs`
* `VolumeType`
* `FlipFlopProfileDirectoryName`

Where a registry value is absent, the script uses the applicable FSLogix default for the audit result.

## redirections.xml

The script does not require custom FSLogix redirections.

`RedirXMLSourceFolder` is only evaluated when it is already configured.

When configured, the audit checks:

* whether the source folder is reachable
* whether a file named `redirections.xml` exists
* whether the XML can be parsed
* whether the expected `FrxProfileFolderRedirection` root element exists
* number of include and exclude entries
* `ExcludeCommonFolders`

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

* `Everyone` in the include groups
* no members in the exclude groups

Custom group membership is reported as informational rather than automatically treated as incorrect.

## Microsoft Defender Exclusions

When Microsoft Defender Antivirus is active, the audit validates effective FSLogix exclusions for:

* FSLogix processes
* FSLogix installation paths
* FSLogix driver files
* temporary VHD/VHDX paths
* profile-container storage
* VHD/VHDX extension coverage where applicable

The script evaluates whether a configured exclusion effectively covers the required path rather than relying only on exact string matches.

This helps avoid false positives where environment variables, parent-folder exclusions, wildcards, or extension exclusions already provide effective coverage.

If Microsoft Defender is not the active real-time antivirus engine, missing Defender exclusions are reported as informational and the active third-party antivirus configuration should be checked separately.

## Runtime Checks

The runtime section currently checks:

* recent FSLogix Operational event-log errors
* known Event ID 26 conditions
* current FSLogix session registry state
* non-zero session attach status
* `.bak` ProfileList entries
* `TEMP` profile folders
* local non-special profiles
* FSLogix text logging

Known Event ID 26 messages are classified separately where possible, including:

* known-folder redirection access-denied errors
* domain lookup failures
* Entra-only LDAP lookup behaviour

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

* operating system details
* device join state
* local profile inventory
* Azure Files capacity when Azure PowerShell is unavailable
* custom group membership
* optional configuration differences

## Reports

Each run generates:

```text
FSLogix-Health-Audit-<computer>-<timestamp>.html
FSLogix-Health-Audit-<computer>-<timestamp>.json
```

The HTML report contains:

* computer name
* generation time
* audit version
* audit parameters
* PASS/WARN/FAIL/INFO totals
* full result table
* evidence
* recommendations

The JSON report contains the same core result data in a structured format suitable for automation or later processing.

Example JSON structure:

```json
{
  "ScriptVersion": "0.9.0",
  "ComputerName": "HOST01",
  "Generated": "2026-09-24 17:48:51",
  "AuditParameters": {
    "ReportPath": "C:\\Temp",
    "EventLookbackDays": 7,
    "ContainerWarningPercent": 90,
    "MaxContainerFiles": 1000
  },
  "Summary": {
    "Pass": 30,
    "Warn": 5,
    "Fail": 0,
    "Info": 7
  },
  "Results": []
}
```

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

* read-only
* portable
* vendor-neutral
* useful on both Azure Files and traditional SMB storage
* conservative about reporting failures
* resistant to common FSLogix false positives
* useful for both troubleshooting and proactive health reviews

The goal is not to enforce one specific FSLogix design.

Where a configuration can legitimately vary between environments, the script aims to report the detected state and distinguish between:

* an actual fault
* a recommendation
* an intentional custom configuration
* an optional check that could not be completed

## Limitations

The audit currently has several intentional limitations:

* Azure Files quota requires existing Azure PowerShell modules and an authenticated Azure context.
* Profile-container size scanning reads file metadata only and does not determine free space inside mounted VHD/VHDX files.
* Container scanning is limited to the share root and one directory level below it.
* Defender exclusion validation currently targets Microsoft Defender; third-party antivirus products must be reviewed separately.
* The audit does not remediate any detected condition.
* It does not replace detailed FSLogix log analysis for complex profile-attach failures.
* It does not currently perform full Azure Virtual Desktop host-pool or AVD-agent health checks.

## Output Interpretation

A report with warnings does not automatically mean FSLogix is unusable.

For example, a historical Event ID 26 warning may remain in the configured event lookback window while the current domain secure channel, DNS and profile attachment state all pass.

Review the evidence and recommendation for each finding rather than treating the summary counts as a standalone health score.

## Project Status

Version `0.9.0` represents the current feature-complete pre-release baseline.

The next planned milestone is `1.0.0`.

```
