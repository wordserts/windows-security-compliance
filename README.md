# Windows Security Compliance Extension

Multi-framework security compliance monitoring extension for Dynatrace.

## Overview

This extension monitors Windows Server 2019/2022 security configurations against:
- **CIS Windows Server Benchmarks** (Level 1)
- **Essential 8** (Australian Cyber Security Centre)
- **PCI-DSS v4.0**

## Coverage

The extension monitors **30 high-impact security controls** across:

### Authentication & Credentials (3 controls)
- LM Hash storage prevention
- LAN Manager authentication levels
- Cached logon limits

### User Account Control & Privileges (4 controls)
- UAC enablement and configuration
- Admin approval modes
- Elevation prompts

### Network Security (6 controls)
- SMB signing requirements
- LDAP client signing
- Anonymous enumeration prevention

### Audit & Logging (3 controls)
- Audit policy configuration
- Event log retention
- Event log sizing

### Remote Access (4 controls)
- RDP encryption levels
- Network Level Authentication
- Session timeouts

### System Hardening (10 controls)
- AutoPlay/AutoRun disabling
- WinRM authentication
- Installer elevation prevention
- Removable device restrictions

## Metrics

- `windows.security.compliance.status`: Compliance status
  - 1 = Compliant
  - 0 = Non-compliant
  - -1 = Not configured
- `windows.security.compliance.value`: Current registry value

## Installation

1. Upload the extension zip to your Dynatrace environment
2. Sign the extension (Hub or custom certificate)
3. Deploy to Windows hosts with OneAgent installed
4. Entities will appear automatically as monitoring begins

## Entity Structure

Each control creates a separate entity with full context:
- Control ID and name
- Category classification
- Framework mappings (CIS, Essential 8, PCI-DSS)
- Current vs expected values
- Compliance status
- Severity rating (Critical, High, Medium, Low)
- Description and registry details

## Alerting

Create custom events for anomalies based on:
- `windows.security.compliance.status` changing to 0 (non-compliant)
- Filter by **severity** (Critical, High, Medium, Low)
- Filter by **framework** (CIS, Essential8, PCI-DSS)
- Filter by **category** (Authentication, Network, Auditing, etc.)

### Example Alert Configuration

**Alert on Critical Non-Compliance:**
```
Metric: windows.security.compliance.status
Condition: < 1
Filter: severity=Critical
Alert when: Status remains below 1 for 2 consecutive measurements
```

## Dashboarding

Suggested visualizations:
- **Overall compliance percentage** by framework
- **Non-compliant controls** grouped by severity
- **Compliance trends** over time
- **Category-based compliance heatmaps**
- **Top 10 failing controls** across your environment

## Extension Details

- **Type**: Python-based OneAgent extension
- **Collection Frequency**: 15 minutes (default, configurable in extension.yaml)
- **Python Version**: 3.8+
- **Permissions Required**: Read access to HKEY_LOCAL_MACHINE registry
- **Supported OS**: Windows Server 2019, Windows Server 2022

## Control Mapping

Each control is mapped to specific framework requirements:

| Control | CIS | Essential 8 | PCI-DSS |
|---------|-----|-------------|---------|
| LM Hash Storage | ✓ | ✓ | ✓ |
| SMB Signing | ✓ | - | ✓ |
| UAC Enabled | ✓ | ✓ | - |
| Audit Policy | ✓ | ✓ | ✓ |

Full control mapping available in the Python script.

## Troubleshooting

**No entities appearing:**
- Verify OneAgent is running on Windows hosts
- Check extension is deployed and active
- Review OneAgent logs for Python execution errors

**Permission errors:**
- Ensure OneAgent service account has read access to registry
- Check Windows event logs for access denied errors

**Incorrect values reported:**
- Verify registry paths match your Windows Server version
- Some controls may not apply to all configurations

## Customization

To add additional controls:
1. Edit `extension/compliance_check.py`
2. Add control definition to `COMPLIANCE_CONTROLS` list
3. Increment version in `extension.yaml`
4. Re-package and upload

## Support

- **Created by**: Vince
- **Version**: 1.0.0
- **Minimum Dynatrace Version**: 1.268

## License

Internal use only.
