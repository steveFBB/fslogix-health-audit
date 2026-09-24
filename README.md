````markdown
# FSLogix Health Audit

PowerShell health audit for FSLogix Profile Container environments.

The script performs a read-only assessment of FSLogix configuration, storage connectivity, antivirus exclusions, runtime state, profile health, and common configuration issues. It is intended for Windows and Azure Virtual Desktop environments.

## Features

The audit currently checks:

- Windows version and device join state
- FSLogix installation and version
- FSLogix service state
- Profile Container configuration
- VHD Locations
- DeleteLocalProfileWhenVHDShouldApply
- PreventLoginWithFailure
- PreventLoginWithTempProfile
- SMB connectivity to the configured profile share
- Profile share reachability
- Microsoft Defender active state
- FSLogix Defender exclusions
- FSLogix event log errors
- Current FSLogix session status
- Temporary and orphaned profiles
- Local profile inventory
- FSLogix text logging

## Defender Exclusion Validation

The Defender exclusion checks are designed to validate effective coverage rather than perform simple string matching.

The script accounts for:

- Environment variables such as `%ProgramFiles%` and `%ProgramData%`
- Wildcard user paths
- Parent folder exclusions covering child files
- Process exclusions
- VHD and VHDX extension exclusions
- Explicit VHD/VHDX share patterns
- `.lock`, `.meta`, and `.metadata` files
- Profile container shares defined in `VHDLocations`

If Microsoft Defender is not the active real-time antivirus engine, incomplete Defender exclusions are reported as informational rather than as a failure.

## Event Log Analysis

FSLogix event log errors from the previous 7 days are grouped by cause rather than Event ID alone.

For example, Event ID 26 messages are separated into:

- Known-folder redirection access denied
- Domain lookup failures
- Expected Entra-only LDAP conditions
- Other Event ID 26 errors

This helps avoid grouping unrelated causes into a single warning.

The event lookback period can be changed with:

```powershell
.\FSLogix-Health-Audit.ps1 -EventLookbackDays 14
````

## Status Levels

* **PASS** - the check completed successfully and the expected configuration or state was found
* **WARN** - a condition was detected that should be reviewed
* **FAIL** - an actionable configuration or health problem was detected
* **INFO** - informational result, skipped check, or condition requiring manual interpretation

## Output

The script generates both HTML and JSON reports.

Default output location:

```text
C:\Temp
```

Example filenames:

```text
FSLogix-Health-Audit-HOSTNAME-20260924-165838.html
FSLogix-Health-Audit-HOSTNAME-20260924-165838.json
```

## Usage

Run PowerShell as administrator and execute:

```powershell
.\FSLogix-Health-Audit.ps1
```

Specify a different report location:

```powershell
.\FSLogix-Health-Audit.ps1 -ReportPath C:\Reports
```

Specify a different event log lookback period:

```powershell
.\FSLogix-Health-Audit.ps1 -EventLookbackDays 14
```

Use both options:

```powershell
.\FSLogix-Health-Audit.ps1 -ReportPath C:\Reports -EventLookbackDays 14
```

## Requirements

* Windows PowerShell
* Administrative PowerShell session recommended
* FSLogix installed on the target system for FSLogix-specific checks
* Network access to the configured profile storage location
* Microsoft Defender PowerShell cmdlets for Defender exclusion validation

## Design Goals

* Read-only operation
* No configuration changes
* Minimise false positives
* Validate effective configuration rather than literal registry or exclusion strings
* Distinguish recommendations from genuine faults
* Handle third-party antivirus scenarios gracefully
* Produce readable HTML output
* Produce structured JSON output for automation and further analysis

## Scope and Limitations

The audit assesses the system on which it is executed.

Some conditions cannot be fully validated from a single session host, including:

* Antivirus exclusions configured only in a third-party management console
* Backend storage performance
* Storage-side antivirus configuration
* User permissions that differ from the identity running the audit
* Conditions on other session hosts in the same pool

Local Windows profiles are reported as informational because administrative or service profiles may legitimately exist on a session host.

Historical event log warnings remain visible until they fall outside the configured event lookback period.

## Safety

The script is read-only.

It does not:

* Modify FSLogix configuration
* Modify registry values
* Change antivirus exclusions
* Modify profile containers
* Delete local profiles
* Change storage permissions
* Restart services

Review all findings before making configuration changes.

```
