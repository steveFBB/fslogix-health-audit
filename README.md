

````markdown
# FSLogix Health Audit

PowerShell health audit for FSLogix profile container environments.

The script performs a read-only assessment of FSLogix configuration, storage connectivity, antivirus exclusions, services, profile state, event logs, and common configuration issues. It is intended for Windows and Azure Virtual Desktop environments.

## Checks

The audit currently validates:

- FSLogix installation and version
- Profile Container configuration
- VHD/VHDX settings
- Storage reachability and write access
- Azure Files / Kerberos configuration
- Microsoft Defender exclusions
- FSLogix services and drivers
- Include/exclude groups
- Profile attach state
- Temporary and orphaned profiles
- Local profiles
- FSLogix event log errors
- Host and AVD state

## Output

The script generates:

- HTML health report
- JSON results for automation and further analysis

Example:

```powershell
.\FSLogix-Health-Audit.ps1 -ReportPath C:\Temp
````

## Status Levels

* **PASS** - configuration or health check passed
* **WARN** - configuration should be reviewed
* **FAIL** - actionable issue requiring investigation
* **INFO** - informational result or configuration detail

## Design Goals

* Read-only operation
* No configuration changes
* Minimise false positives
* Validate effective configuration rather than only registry defaults
* Handle environment variables and wildcard exclusions correctly
* Distinguish recommendations from genuine faults
* Produce consistent results suitable for individual hosts or estate-wide auditing

## Scope

The script assesses the session host from which it is executed.

Some configuration cannot be fully validated from the session host alone, including:

* storage-side antivirus configuration
* user-specific Azure Files permissions
* backend storage performance
* configuration on other session hosts

## Requirements

* Windows PowerShell 5.1 or PowerShell 7
* Administrative PowerShell session recommended
* FSLogix installed on the target system

## Getting Started

Clone the repository:

```powershell
git clone https://github.com/steveFBB/fslogix-health-audit.git
cd fslogix-health-audit
```

Run the audit:

```powershell
.\FSLogix-Health-Audit.ps1 -ReportPath C:\Temp
```

## Development

This project is being developed to improve the accuracy of FSLogix health assessment, particularly around effective Defender exclusions, profile configuration, Azure Files authentication, and event-log analysis.

## Disclaimer

Review findings before making configuration changes. A warning or failure should be validated against the environment and current Microsoft documentation.

```

That gives us a solid initial README without pretending the script already has functionality we haven't built yet.

As we change the script, we should update the README at the same time rather than leaving documentation until the end. Your AVD repo already follows that kind of practical operational-documentation style. :contentReference[oaicite:1]{index=1}
```

[1]: https://github.com/steveFBB/avd-landing-zone "GitHub - steveFBB/avd-landing-zone · GitHub"
