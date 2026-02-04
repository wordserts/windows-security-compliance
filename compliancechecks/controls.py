"""
Windows Security Compliance Controls
Comprehensive control definitions for CIS, Essential 8, and PCI-DSS frameworks
~100 high-impact registry-based security controls
"""

import winreg

# Control template:
# {
#     "control_id": "Framework-Section_Mapping",
#     "control_name": "Human-readable name",
#     "category": "Category for grouping",
#     "frameworks": "CIS,Essential8,PCI-DSS",
#     "severity": "Critical|High|Medium|Low",
#     "description": "What this control does",
#     "registry_hive": winreg.HKEY_*,
#     "registry_path": r"Path\To\Key",
#     "value_name": "ValueName",
#     "expected_value": expected_value,
#     "comparison": "eq|ne|gte|lte"  # Optional, defaults to eq
# }

# ============================================================================
# AUTHENTICATION & CREDENTIALS (8 controls)
# ============================================================================
AUTHENTICATION_CONTROLS = [
    {"control_id": "CIS-18.3.1_E8-H01_PCI-2.2.4", "control_name": "No LM Hash Storage", "category": "Authentication", "frameworks": "CIS,Essential8,PCI-DSS", "severity": "Critical", "description": "Prevents storage of LAN Manager password hashes", "registry_hive": winreg.HKEY_LOCAL_MACHINE, "registry_path": r"SYSTEM\CurrentControlSet\Control\Lsa", "value_name": "NoLMHash", "expected_value": 1},
    {"control_id": "CIS-2.3.11.8_PCI-2.2.4", "control_name": "LAN Manager Authentication Level", "category": "Authentication", "frameworks": "CIS,PCI-DSS", "severity": "High", "description": "Requires NTLMv2 authentication only", "registry_hive": winreg.HKEY_LOCAL_MACHINE, "registry_path": r"SYSTEM\CurrentControlSet\Control\Lsa", "value_name": "LmCompatibilityLevel", "expected_value": 5},
    {"control_id": "CIS-2.3.11.7_PCI-8.2.1", "control_name": "Cached Logons Limit", "category": "Authentication", "frameworks": "CIS,PCI-DSS", "severity": "Medium", "description": "Limits cached domain credentials", "registry_hive": winreg.HKEY_LOCAL_MACHINE, "registry_path": r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", "value_name": "CachedLogonsCount", "expected_value": 4, "comparison": "lte"},
    {"control_id": "CIS-2.3.7.7_PCI-8.2", "control_name": "Machine Inactivity Limit", "category": "Authentication", "frameworks": "CIS,PCI-DSS", "severity": "Medium", "description": "Auto-lock after inactivity", "registry_hive": winreg.HKEY_LOCAL_MACHINE, "registry_path": r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "value_name": "InactivityTimeoutSecs", "expected_value": 900, "comparison": "lte"},
    {"control_id": "CIS-2.3.7.8_PCI-8.2", "control_name": "Screen Saver Timeout", "category": "Authentication", "frameworks": "CIS,PCI-DSS", "severity": "Low", "description": "Screen saver activation delay", "registry_hive": winreg.HKEY_LOCAL_MACHINE, "registry_path": r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "value_name": "ScreenSaverGracePeriod", "expected_value": 5, "comparison": "lte"},
    {"control_id": "CIS-18.9.47.4.1_PCI-8.3", "control_name": "Send Unencrypted Password to SMB", "category": "Authentication", "frameworks": "CIS,PCI-DSS", "severity": "High", "description": "Prevents sending plaintext passwords", "registry_hive": winreg.HKEY_LOCAL_MACHINE, "registry_path": r"SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters", "value_name": "EnablePlainTextPassword", "expected_value": 0},
    {"control_id": "CIS-18.5.9.2_E8-M07", "control_name": "Require Secure RPC", "category": "Authentication", "frameworks": "CIS,Essential8", "severity": "High", "description": "Requires secure RPC connections", "registry_hive": winreg.HKEY_LOCAL_MACHINE, "registry_path": r"SOFTWARE\Policies\Microsoft\Windows NT\Rpc", "value_name": "RestrictRemoteClients", "expected_value": 1},
    {"control_id": "CIS-18.5.9.1", "control_name": "RPC Authentication Required", "category": "Authentication", "frameworks": "CIS", "severity": "High", "description": "Requires RPC client authentication", "registry_hive": winreg.HKEY_LOCAL_MACHINE, "registry_path": r"SOFTWARE\Policies\Microsoft\Windows NT\Rpc", "value_name": "EnableAuthEpResolution", "expected_value": 1},
]

# ============================================================================
# USER ACCOUNT CONTROL & PRIVILEGES (10 controls)
# ============================================================================
PRIVILEGE_CONTROLS = [
    {"control_id": "CIS-2.3.17.1_E8-H02", "control_name": "User Account Control Enabled", "category": "Privileges", "frameworks": "CIS,Essential8", "severity": "Critical", "description": "Enables User Account Control for all users", "registry_hive": winreg.HKEY_LOCAL_MACHINE, "registry_path": r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "value_name": "EnableLUA", "expected_value": 1},
    {"control_id": "CIS-2.3.17.2", "control_name": "UAC Admin Approval Mode", "category": "Privileges", "frameworks": "CIS", "severity": "High", "description": "Requires admin approval mode", "registry_hive": winreg.HKEY_LOCAL_MACHINE, "registry_path": r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "value_name": "FilterAdministratorToken", "expected_value": 1},
    {"control_id": "CIS-2.3.17.5", "control_name": "UAC Elevation Prompt for Admins", "category": "Privileges", "frameworks": "CIS", "severity": "High", "description": "Prompts for credentials on elevation", "registry_hive": winreg.HKEY_LOCAL_MACHINE, "registry_path": r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "value_name": "ConsentPromptBehaviorAdmin", "expected_value": 2},
    {"control_id": "CIS-2.3.17.6", "control_name": "UAC Elevation Prompt for Standard Users", "category": "Privileges", "frameworks": "CIS", "severity": "High", "description": "Denies elevation requests for standard users", "registry_hive": winreg.HKEY_LOCAL_MACHINE, "registry_path": r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "value_name": "ConsentPromptBehaviorUser", "expected_value": 0},
    {"control_id": "CIS-2.3.17.8_E8-M05", "control_name": "UAC Virtualization Enabled", "category": "Privileges", "frameworks": "CIS,Essential8", "severity": "Medium", "description": "Enables UAC file/registry virtualization", "registry_hive": winreg.HKEY_LOCAL_MACHINE, "registry_path": r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "value_name": "EnableVirtualization", "expected_value": 1},
    {"control_id": "CIS-2.3.17.3", "control_name": "UAC Detect Application Installations", "category": "Privileges", "frameworks": "CIS", "severity": "Medium", "description": "Detects application installations and prompts", "registry_hive": winreg.HKEY_LOCAL_MACHINE, "registry_path": r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "value_name": "EnableInstallerDetection", "expected_value": 1},
    {"control_id": "CIS-2.3.17.4", "control_name": "UAC Secure Desktop for Prompts", "category": "Privileges", "frameworks": "CIS", "severity": "Medium", "description": "Uses secure desktop for elevation prompts", "registry_hive": winreg.HKEY_LOCAL_MACHINE, "registry_path": r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "value_name": "PromptOnSecureDesktop", "expected_value": 1},
    {"control_id": "CIS-2.3.17.7", "control_name": "UAC Admin Mode for Built-in Admin", "category": "Privileges", "frameworks": "CIS", "severity": "High", "description": "Admin Approval Mode for built-in admin", "registry_hive": winreg.HKEY_LOCAL_MACHINE, "registry_path": r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "value_name": "EnableSecureUIAPaths", "expected_value": 1},
    {"control_id": "CIS-18.5.8_E8-M05", "control_name": "Installer Always Elevate", "category": "Privileges", "frameworks": "CIS,Essential8", "severity": "High", "description": "Prevents automatic elevation of installers", "registry_hive": winreg.HKEY_LOCAL_MACHINE, "registry_path": r"SOFTWARE\Policies\Microsoft\Windows\Installer", "value_name": "AlwaysInstallElevated", "expected_value": 0},
    {"control_id": "CIS-18.3.7_E8-M05", "control_name": "Remote Assistance Solicited", "category": "Privileges", "frameworks": "CIS,Essential8", "severity": "Medium", "description": "Controls Remote Assistance access", "registry_hive": winreg.HKEY_LOCAL_MACHINE, "registry_path": r"SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services", "value_name": "fAllowToGetHelp", "expected_value": 0},
]

# ============================================================================
# NETWORK SECURITY (12 controls)
# ============================================================================
NETWORK_CONTROLS = [
    {"control_id": "CIS-18.5.4.1_PCI-2.2", "control_name": "SMB Client Signing Required", "category": "Network", "frameworks": "CIS,PCI-DSS", "severity": "Critical", "description": "Requires SMB client packet signing", "registry_hive": winreg.HKEY_LOCAL_MACHINE, "registry_path": r"SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters", "value_name": "RequireSecuritySignature", "expected_value": 1},
    {"control_id": "CIS-18.5.8.1_PCI-2.2", "control_name": "SMB Server Signing Required", "category": "Network", "frameworks": "CIS,PCI-DSS", "severity": "Critical", "description": "Requires SMB server packet signing", "registry_hive": winreg.HKEY_LOCAL_MACHINE, "registry_path": r"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters", "value_name": "RequireSecuritySignature", "expected_value": 1},
    {"control_id": "CIS-2.3.11.9_PCI-2.2.4", "control_name": "LDAP Client Signing Required", "category": "Network", "frameworks": "CIS,PCI-DSS", "severity": "High", "description": "Requires LDAP client signing", "registry_hive": winreg.HKEY_LOCAL_MACHINE, "registry_path": r"SYSTEM\CurrentControlSet\Services\LDAP", "value_name": "LDAPClientIntegrity", "expected_value": 2},
    {"control_id": "CIS-2.3.10.12", "control_name": "Anonymous SID Translation Disabled", "category": "Network", "frameworks": "CIS", "severity": "High", "description": "Prevents anonymous SID/name translation", "registry_hive": winreg.HKEY_LOCAL_MACHINE, "registry_path": r"SYSTEM\CurrentControlSet\Control\Lsa", "value_name": "TurnOffAnonymousBlock", "expected_value": 1},
    {"control_id": "CIS-2.3.10.10", "control_name": "Anonymous SAM Enumeration Disabled", "category": "Network", "frameworks": "CIS", "severity": "High", "description": "Prevents anonymous SAM enumeration", "registry_hive": winreg.HKEY_LOCAL_MACHINE, "registry_path": r"SYSTEM\CurrentControlSet\Control\Lsa", "value_name": "RestrictAnonymousSAM", "expected_value": 1},
    {"control_id": "CIS-2.3.10.11", "control_name": "Anonymous Shares Enumeration Disabled", "category": "Network", "frameworks": "CIS", "severity": "High", "description": "Prevents anonymous share enumeration", "registry_hive": winreg.HKEY_LOCAL_MACHINE, "registry_path": r"SYSTEM\CurrentControlSet\Control\Lsa", "value_name": "RestrictAnonymous", "expected_value": 1},
    {"control_id": "CIS-18.5.19.2.1_PCI-1.3", "control_name": "Windows Firewall Domain Profile Enabled", "category": "Network", "frameworks": "CIS,PCI-DSS", "severity": "Critical", "description": "Enables Domain profile firewall", "registry_hive": winreg.HKEY_LOCAL_MACHINE, "registry_path": r"SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile", "value_name": "EnableFirewall", "expected_value": 1},
    {"control_id": "CIS-18.5.19.3.1_PCI-1.3", "control_name": "Windows Firewall Private Profile Enabled", "category": "Network", "frameworks": "CIS,PCI-DSS", "severity": "Critical", "description": "Enables Private profile firewall", "registry_hive": winreg.HKEY_LOCAL_MACHINE, "registry_path": r"SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile", "value_name": "EnableFirewall", "expected_value": 1},
    {"control_id": "CIS-18.5.19.4.1_PCI-1.3", "control_name": "Windows Firewall Public Profile Enabled", "category": "Network", "frameworks": "CIS,PCI-DSS", "severity": "Critical", "description": "Enables Public profile firewall", "registry_hive": winreg.HKEY_LOCAL_MACHINE, "registry_path": r"SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile", "value_name": "EnableFirewall", "expected_value": 1},
    {"control_id": "CIS-18.5.19.2.3_PCI-10.3", "control_name": "Firewall Domain Logging Enabled", "category": "Network", "frameworks": "CIS,PCI-DSS", "severity": "Medium", "description": "Enables firewall logging for Domain", "registry_hive": winreg.HKEY_LOCAL_MACHINE, "registry_path": r"SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging", "value_name": "LogDroppedPackets", "expected_value": 1},
    {"control_id": "CIS-18.4.6.1_PCI-2.2", "control_name": "IPv6 Transition Technologies Disabled", "category": "Network", "frameworks": "CIS,PCI-DSS", "severity": "Medium", "description": "Disables IPv6 transition technologies", "registry_hive": winreg.HKEY_LOCAL_MACHINE, "registry_path": r"SOFTWARE\Policies\Microsoft\Windows\TCPIP\v6Transition", "value_name": "Force_Tunneling", "expected_value": "Disabled"},
    {"control_id": "CIS-18.4.8.1", "control_name": "NetBT NodeType P-node", "category": "Network", "frameworks": "CIS", "severity": "Low", "description": "Configures NetBT to P-node", "registry_hive": winreg.HKEY_LOCAL_MACHINE, "registry_path": r"SYSTEM\CurrentControlSet\Services\NetBT\Parameters", "value_name": "NodeType", "expected_value": 2},
]

# ============================================================================
# AUDIT & LOGGING (5 controls)
# ============================================================================
AUDIT_CONTROLS = [
    {"control_id": "CIS-18.9.26.1.1_PCI-10.2", "control_name": "Audit Process Creation Details", "category": "Audit", "frameworks": "CIS,PCI-DSS", "severity": "High", "description": "Includes command line in process creation events", "registry_hive": winreg.HKEY_LOCAL_MACHINE, "registry_path": r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit", "value_name": "ProcessCreationIncludeCmdLine_Enabled", "expected_value": 1},
    {"control_id": "CIS-18.9.102.1.1_PCI-10.3", "control_name": "Event Log Max Size Application", "category": "Audit", "frameworks": "CIS,PCI-DSS", "severity": "Medium", "description": "Application log maximum size", "registry_hive": winreg.HKEY_LOCAL_MACHINE, "registry_path": r"SOFTWARE\Policies\Microsoft\Windows\EventLog\Application", "value_name": "MaxSize", "expected_value": 32768, "comparison": "gte"},
    {"control_id": "CIS-18.9.102.2.1_PCI-10.3", "control_name": "Event Log Max Size Security", "category": "Audit", "frameworks": "CIS,PCI-DSS", "severity": "High", "description": "Security log maximum size", "registry_hive": winreg.HKEY_LOCAL_MACHINE, "registry_path": r"SOFTWARE\Policies\Microsoft\Windows\EventLog\Security", "value_name": "MaxSize", "expected_value": 196608, "comparison": "gte"},
    {"control_id": "CIS-18.9.102.3.1_PCI-10.3", "control_name": "Event Log Max Size System", "category": "Audit", "frameworks": "CIS,PCI-DSS", "severity": "Medium", "description": "System log maximum size", "registry_hive": winreg.HKEY_LOCAL_MACHINE, "registry_path": r"SOFTWARE\Policies\Microsoft\Windows\EventLog\System", "value_name": "MaxSize", "expected_value": 32768, "comparison": "gte"},
    {"control_id": "CIS-18.9.30.2_PCI-10.2", "control_name": "PowerShell Script Block Logging", "category": "Audit", "frameworks": "CIS,PCI-DSS", "severity": "High", "description": "Enables PowerShell script block logging", "registry_hive": winreg.HKEY_LOCAL_MACHINE, "registry_path": r"SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging", "value_name": "EnableScriptBlockLogging", "expected_value": 1},
]

# ============================================================================
# REMOTE ACCESS (8 controls)
# ============================================================================
REMOTE_ACCESS_CONTROLS = [
    {"control_id": "CIS-18.9.65.3.3.1_PCI-8.2", "control_name": "RDP Encryption Level High", "category": "RemoteAccess", "frameworks": "CIS,PCI-DSS", "severity": "High", "description": "Requires high RDP encryption", "registry_hive": winreg.HKEY_LOCAL_MACHINE, "registry_path": r"SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services", "value_name": "MinEncryptionLevel", "expected_value": 3},
    {"control_id": "CIS-18.9.65.3.9.1_PCI-8.2", "control_name": "RDP NLA Required", "category": "RemoteAccess", "frameworks": "CIS,PCI-DSS", "severity": "Critical", "description": "Requires Network Level Authentication", "registry_hive": winreg.HKEY_LOCAL_MACHINE, "registry_path": r"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp", "value_name": "UserAuthentication", "expected_value": 1},
    {"control_id": "CIS-18.9.65.3.9.2_PCI-8.2", "control_name": "RDP Security Layer TLS", "category": "RemoteAccess", "frameworks": "CIS,PCI-DSS", "severity": "High", "description": "Requires TLS for RDP", "registry_hive": winreg.HKEY_LOCAL_MACHINE, "registry_path": r"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp", "value_name": "SecurityLayer", "expected_value": 2},
    {"control_id": "CIS-18.9.65.3.9.3", "control_name": "RDP Idle Session Limit", "category": "RemoteAccess", "frameworks": "CIS", "severity": "Medium", "description": "Limits idle RDP session time", "registry_hive": winreg.HKEY_LOCAL_MACHINE, "registry_path": r"SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services", "value_name": "MaxIdleTime", "expected_value": 900000, "comparison": "lte"},
    {"control_id": "CIS-18.9.65.3.9.4", "control_name": "RDP Disconnected Session Limit", "category": "RemoteAccess", "frameworks": "CIS", "severity": "Medium", "description": "Limits disconnected RDP session time", "registry_hive": winreg.HKEY_LOCAL_MACHINE, "registry_path": r"SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services", "value_name": "MaxDisconnectionTime", "expected_value": 60000, "comparison": "lte"},
    {"control_id": "CIS-18.9.65.3.2.1", "control_name": "RDP Client Connection Encryption", "category": "RemoteAccess", "frameworks": "CIS", "severity": "High", "description": "Requires client connection encryption", "registry_hive": winreg.HKEY_LOCAL_MACHINE, "registry_path": r"SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services", "value_name": "fEncryptRPCTraffic", "expected_value": 1},
    {"control_id": "CIS-18.9.65.2.2", "control_name": "RDP Always Prompt for Password", "category": "RemoteAccess", "frameworks": "CIS", "severity": "High", "description": "Always prompts for password on connection", "registry_hive": winreg.HKEY_LOCAL_MACHINE, "registry_path": r"SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services", "value_name": "fPromptForPassword", "expected_value": 1},
    {"control_id": "CIS-18.9.102.1.3", "control_name": "RDP Certificate Template", "category": "RemoteAccess", "frameworks": "CIS", "severity": "Medium", "description": "Specifies RDP certificate template", "registry_hive": winreg.HKEY_LOCAL_MACHINE, "registry_path": r"SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services", "value_name": "CertificateTemplateName", "expected_value": ""},
]

# ============================================================================
# SYSTEM HARDENING (15 controls)
# ============================================================================
SYSTEM_HARDENING_CONTROLS = [
    {"control_id": "CIS-18.9.8.1_E8-H03", "control_name": "AutoPlay Disabled", "category": "SystemHardening", "frameworks": "CIS,Essential8", "severity": "Medium", "description": "Disables AutoPlay for all drives", "registry_hive": winreg.HKEY_LOCAL_MACHINE, "registry_path": r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer", "value_name": "NoDriveTypeAutoRun", "expected_value": 255},
    {"control_id": "CIS-18.9.8.2_E8-H04", "control_name": "AutoPlay Default Behavior", "category": "SystemHardening", "frameworks": "CIS,Essential8", "severity": "Medium", "description": "Sets AutoPlay default to take no action", "registry_hive": winreg.HKEY_LOCAL_MACHINE, "registry_path": r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer", "value_name": "NoAutoplayfornonVolume", "expected_value": 1},
    {"control_id": "CIS-18.9.8.3_E8-H05", "control_name": "AutoRun Disabled", "category": "SystemHardening", "frameworks": "CIS,Essential8", "severity": "Medium", "description": "Disables AutoRun commands", "registry_hive": winreg.HKEY_LOCAL_MACHINE, "registry_path": r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer", "value_name": "NoAutorun", "expected_value": 1},
    {"control_id": "CIS-18.1.1.1", "control_name": "Removable Storage Driver Install Prevented", "category": "SystemHardening", "frameworks": "CIS", "severity": "Medium", "description": "Prevents installation of removable storage drivers", "registry_hive": winreg.HKEY_LOCAL_MACHINE, "registry_path": r"SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions", "value_name": "DenyRemovableDevices", "expected_value": 1},
    {"control_id": "CIS-18.5.4.2", "control_name": "NetBIOS Name Release on Demand", "category": "SystemHardening", "frameworks": "CIS", "severity": "Low", "description": "Allows NetBIOS name release", "registry_hive": winreg.HKEY_LOCAL_MACHINE, "registry_path": r"SYSTEM\CurrentControlSet\Services\NetBT\Parameters", "value_name": "NoNameReleaseOnDemand", "expected_value": 1},
    {"control_id": "CIS-18.5.9.1_E8-H06", "control_name": "WinRM Service Basic Auth Disabled", "category": "SystemHardening", "frameworks": "CIS,Essential8", "severity": "High", "description": "Disables WinRM Basic authentication", "registry_hive": winreg.HKEY_LOCAL_MACHINE, "registry_path": r"SOFTWARE\Policies\Microsoft\Windows\WinRM\Service", "value_name": "AllowBasic", "expected_value": 0},
    {"control_id": "CIS-18.5.9.2_E8-H07", "control_name": "WinRM Service Unencrypted Traffic", "category": "SystemHardening", "frameworks": "CIS,Essential8", "severity": "High", "description": "Prevents unencrypted WinRM traffic", "registry_hive": winreg.HKEY_LOCAL_MACHINE, "registry_path": r"SOFTWARE\Policies\Microsoft\Windows\WinRM\Service", "value_name": "AllowUnencryptedTraffic", "expected_value": 0},
    {"control_id": "CIS-18.5.9.3_E8-H08", "control_name": "WinRM Client Basic Auth Disabled", "category": "SystemHardening", "frameworks": "CIS,Essential8", "severity": "High", "description": "Disables WinRM client Basic auth", "registry_hive": winreg.HKEY_LOCAL_MACHINE, "registry_path": r"SOFTWARE\Policies\Microsoft\Windows\WinRM\Client", "value_name": "AllowBasic", "expected_value": 0},
    {"control_id": "CIS-18.5.9.4_E8-H09", "control_name": "WinRM Client Unencrypted Traffic", "category": "SystemHardening", "frameworks": "CIS,Essential8", "severity": "High", "description": "Prevents unencrypted WinRM client traffic", "registry_hive": winreg.HKEY_LOCAL_MACHINE, "registry_path": r"SOFTWARE\Policies\Microsoft\Windows\WinRM\Client", "value_name": "AllowUnencryptedTraffic", "expected_value": 0},
    {"control_id": "CIS-18.5.4.1", "control_name": "MSS DisableIPSourceRouting IPv4", "category": "SystemHardening", "frameworks": "CIS", "severity": "Medium", "description": "Disables IP source routing for IPv4", "registry_hive": winreg.HKEY_LOCAL_MACHINE, "registry_path": r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters", "value_name": "DisableIPSourceRouting", "expected_value": 2},
    {"control_id": "CIS-18.5.4.2", "control_name": "MSS DisableIPSourceRouting IPv6", "category": "SystemHardening", "frameworks": "CIS", "severity": "Medium", "description": "Disables IP source routing for IPv6", "registry_hive": winreg.HKEY_LOCAL_MACHINE, "registry_path": r"SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters", "value_name": "DisableIPSourceRouting", "expected_value": 2},
    {"control_id": "CIS-18.5.5.1", "control_name": "MSS KeepAliveTime", "category": "SystemHardening", "frameworks": "CIS", "severity": "Low", "description": "TCP Keep Alive time", "registry_hive": winreg.HKEY_LOCAL_MACHINE, "registry_path": r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters", "value_name": "KeepAliveTime", "expected_value": 300000, "comparison": "lte"},
    {"control_id": "CIS-18.9.47.5.1_PCI-2.2", "control_name": "Multicast Name Resolution Disabled", "category": "SystemHardening", "frameworks": "CIS,PCI-DSS", "severity": "Medium", "description": "Disables LLMNR multicast", "registry_hive": winreg.HKEY_LOCAL_MACHINE, "registry_path": r"SOFTWARE\Policies\Microsoft\Windows NT\DNSClient", "value_name": "EnableMulticast", "expected_value": 0},
    {"control_id": "CIS-18.9.80.1.1_PCI-11.3", "control_name": "Windows Error Reporting Disabled", "category": "SystemHardening", "frameworks": "CIS,PCI-DSS", "severity": "Low", "description": "Disables Windows Error Reporting", "registry_hive": winreg.HKEY_LOCAL_MACHINE, "registry_path": r"SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting", "value_name": "Disabled", "expected_value": 1},
    {"control_id": "CIS-18.9.95.1", "control_name": "App Privacy Force Location Off", "category": "SystemHardening", "frameworks": "CIS", "severity": "Low", "description": "Forces location privacy setting off", "registry_hive": winreg.HKEY_LOCAL_MACHINE, "registry_path": r"SOFTWARE\Policies\Microsoft\Windows\AppPrivacy", "value_name": "LetAppsAccessLocation", "expected_value": 2},
]

# ============================================================================
# WINDOWS DEFENDER (10 controls)
# ============================================================================
DEFENDER_CONTROLS = [
    {"control_id": "CIS-18.9.45.4.1.1_E8-A01_PCI-5.1", "control_name": "Windows Defender Real-Time Protection", "category": "AntiMalware", "frameworks": "CIS,Essential8,PCI-DSS", "severity": "Critical", "description": "Enables real-time protection", "registry_hive": winreg.HKEY_LOCAL_MACHINE, "registry_path": r"SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection", "value_name": "DisableRealtimeMonitoring", "expected_value": 0},
    {"control_id": "CIS-18.9.45.4.1.2_E8-A02_PCI-5.1", "control_name": "Windows Defender Behavior Monitoring", "category": "AntiMalware", "frameworks": "CIS,Essential8,PCI-DSS", "severity": "Critical", "description": "Enables behavior monitoring", "registry_hive": winreg.HKEY_LOCAL_MACHINE, "registry_path": r"SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection", "value_name": "DisableBehaviorMonitoring", "expected_value": 0},
    {"control_id": "CIS-18.9.45.4.3.1_E8-A03", "control_name": "Windows Defender Scan Removable Drives", "category": "AntiMalware", "frameworks": "CIS,Essential8", "severity": "High", "description": "Scans removable drives", "registry_hive": winreg.HKEY_LOCAL_MACHINE, "registry_path": r"SOFTWARE\Policies\Microsoft\Windows Defender\Scan", "value_name": "DisableRemovableDriveScanning", "expected_value": 0},
    {"control_id": "CIS-18.9.45.4.3.2_E8-A04", "control_name": "Windows Defender Scan Email", "category": "AntiMalware", "frameworks": "CIS,Essential8", "severity": "High", "description": "Scans email and attachments", "registry_hive": winreg.HKEY_LOCAL_MACHINE, "registry_path": r"SOFTWARE\Policies\Microsoft\Windows Defender\Scan", "value_name": "DisableEmailScanning", "expected_value": 0},
    {"control_id": "CIS-18.9.45.8_E8-A05", "control_name": "Windows Defender Cloud Protection", "category": "AntiMalware", "frameworks": "CIS,Essential8", "severity": "High", "description": "Enables cloud-delivered protection", "registry_hive": winreg.HKEY_LOCAL_MACHINE, "registry_path": r"SOFTWARE\Policies\Microsoft\Windows Defender\Spynet", "value_name": "SpynetReporting", "expected_value": 2},
    {"control_id": "CIS-18.9.45.11_E8-A06", "control_name": "Windows Defender Sample Submission", "category": "AntiMalware", "frameworks": "CIS,Essential8", "severity": "Medium", "description": "Enables automatic sample submission", "registry_hive": winreg.HKEY_LOCAL_MACHINE, "registry_path": r"SOFTWARE\Policies\Microsoft\Windows Defender\Spynet", "value_name": "SubmitSamplesConsent", "expected_value": 1, "comparison": "gte"},
    {"control_id": "CIS-18.9.45.3.2_E8-A07", "control_name": "Windows Defender Exploit Guard ASR", "category": "AntiMalware", "frameworks": "CIS,Essential8", "severity": "High", "description": "Attack Surface Reduction rules", "registry_hive": winreg.HKEY_LOCAL_MACHINE, "registry_path": r"SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR", "value_name": "ExploitGuard_ASR_Rules", "expected_value": 1},
    {"control_id": "CIS-18.9.45.13_E8-A08_PCI-5.1", "control_name": "Windows Defender PUA Protection", "category": "AntiMalware", "frameworks": "CIS,Essential8,PCI-DSS", "severity": "Medium", "description": "Blocks potentially unwanted applications", "registry_hive": winreg.HKEY_LOCAL_MACHINE, "registry_path": r"SOFTWARE\Policies\Microsoft\Windows Defender", "value_name": "PUAProtection", "expected_value": 1},
    {"control_id": "CIS-18.9.45.15_E8-A09", "control_name": "Windows Defender Tamper Protection", "category": "AntiMalware", "frameworks": "CIS,Essential8", "severity": "Critical", "description": "Prevents tampering with Defender", "registry_hive": winreg.HKEY_LOCAL_MACHINE, "registry_path": r"SOFTWARE\Policies\Microsoft\Windows Defender\Features", "value_name": "TamperProtection", "expected_value": 5},
    {"control_id": "CIS-18.9.45.1_PCI-5.1", "control_name": "Windows Defender Service Startup", "category": "AntiMalware", "frameworks": "CIS,PCI-DSS", "severity": "Critical", "description": "Ensures Defender service runs", "registry_hive": winreg.HKEY_LOCAL_MACHINE, "registry_path": r"SOFTWARE\Policies\Microsoft\Windows Defender", "value_name": "DisableAntiSpyware", "expected_value": 0},
]

# ============================================================================
# BITLOCKER & ENCRYPTION (5 controls)
# ============================================================================
ENCRYPTION_CONTROLS = [
    {"control_id": "CIS-18.9.10.1.1_PCI-3.4", "control_name": "BitLocker Fixed Data Drives Encryption", "category": "Encryption", "frameworks": "CIS,PCI-DSS", "severity": "High", "description": "Requires encryption for fixed drives", "registry_hive": winreg.HKEY_LOCAL_MACHINE, "registry_path": r"SOFTWARE\Policies\Microsoft\FVE", "value_name": "FDVEncryptionType", "expected_value": 1, "comparison": "gte"},
    {"control_id": "CIS-18.9.10.1.2_PCI-3.4", "control_name": "BitLocker Fixed Drives Recovery Password", "category": "Encryption", "frameworks": "CIS,PCI-DSS", "severity": "High", "description": "Requires recovery password for fixed drives", "registry_hive": winreg.HKEY_LOCAL_MACHINE, "registry_path": r"SOFTWARE\Policies\Microsoft\FVE", "value_name": "FDVRecoveryPassword", "expected_value": 2},
    {"control_id": "CIS-18.9.10.2.1_PCI-3.4", "control_name": "BitLocker OS Drive Encryption", "category": "Encryption", "frameworks": "CIS,PCI-DSS", "severity": "Critical", "description": "Requires OS drive encryption", "registry_hive": winreg.HKEY_LOCAL_MACHINE, "registry_path": r"SOFTWARE\Policies\Microsoft\FVE", "value_name": "OSEncryptionType", "expected_value": 1, "comparison": "gte"},
    {"control_id": "CIS-18.9.10.2.2_PCI-3.4", "control_name": "BitLocker OS Drive TPM Required", "category": "Encryption", "frameworks": "CIS,PCI-DSS", "severity": "High", "description": "Requires TPM for OS drive", "registry_hive": winreg.HKEY_LOCAL_MACHINE, "registry_path": r"SOFTWARE\Policies\Microsoft\FVE", "value_name": "UseTPM", "expected_value": 2},
    {"control_id": "CIS-18.9.10.3.1_PCI-3.4", "control_name": "BitLocker Removable Drives Encryption", "category": "Encryption", "frameworks": "CIS,PCI-DSS", "severity": "Medium", "description": "Requires removable drive encryption", "registry_hive": winreg.HKEY_LOCAL_MACHINE, "registry_path": r"SOFTWARE\Policies\Microsoft\FVE", "value_name": "RDVEncryptionType", "expected_value": 1, "comparison": "gte"},
]

# ============================================================================
# APPLICATION CONTROL (7 controls)
# ============================================================================
APP_CONTROL_CONTROLS = [
    {"control_id": "E8-M01-L1", "control_name": "AppLocker DLL Rules Enabled", "category": "ApplicationControl", "frameworks": "Essential8", "severity": "High", "description": "Enables AppLocker DLL rules", "registry_hive": winreg.HKEY_LOCAL_MACHINE, "registry_path": r"SOFTWARE\Policies\Microsoft\Windows\SrpV2", "value_name": "PolicyScope", "expected_value": 1},
    {"control_id": "E8-M01-L2", "control_name": "AppLocker Executable Rules Enabled", "category": "ApplicationControl", "frameworks": "Essential8", "severity": "Critical", "description": "Enables AppLocker EXE rules", "registry_hive": winreg.HKEY_LOCAL_MACHINE, "registry_path": r"SOFTWARE\Policies\Microsoft\Windows\SrpV2\Exe", "value_name": "EnforcementMode", "expected_value": 1},
    {"control_id": "E8-M01-L3", "control_name": "AppLocker Script Rules Enabled", "category": "ApplicationControl", "frameworks": "Essential8", "severity": "High", "description": "Enables AppLocker Script rules", "registry_hive": winreg.HKEY_LOCAL_MACHINE, "registry_path": r"SOFTWARE\Policies\Microsoft\Windows\SrpV2\Script", "value_name": "EnforcementMode", "expected_value": 1},
    {"control_id": "E8-M01-L4", "control_name": "AppLocker MSI Rules Enabled", "category": "ApplicationControl", "frameworks": "Essential8", "severity": "High", "description": "Enables AppLocker MSI rules", "registry_hive": winreg.HKEY_LOCAL_MACHINE, "registry_path": r"SOFTWARE\Policies\Microsoft\Windows\SrpV2\Msi", "value_name": "EnforcementMode", "expected_value": 1},
    {"control_id": "CIS-18.9.86.1.1_E8-M03", "control_name": "PowerShell Script Execution Policy", "category": "ApplicationControl", "frameworks": "CIS,Essential8", "severity": "High", "description": "Restricts PowerShell execution", "registry_hive": winreg.HKEY_LOCAL_MACHINE, "registry_path": r"SOFTWARE\Policies\Microsoft\Windows\PowerShell", "value_name": "EnableScripts", "expected_value": 0},
    {"control_id": "CIS-18.9.86.2.1_E8-M03", "control_name": "PowerShell Transcription Enabled", "category": "ApplicationControl", "frameworks": "CIS,Essential8", "severity": "High", "description": "Enables PowerShell transcription logging", "registry_hive": winreg.HKEY_LOCAL_MACHINE, "registry_path": r"SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription", "value_name": "EnableTranscripting", "expected_value": 1},
    {"control_id": "CIS-18.9.86.2.2_E8-M03", "control_name": "PowerShell Module Logging", "category": "ApplicationControl", "frameworks": "CIS,Essential8", "severity": "Medium", "description": "Enables PowerShell module logging", "registry_hive": winreg.HKEY_LOCAL_MACHINE, "registry_path": r"SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging", "value_name": "EnableModuleLogging", "expected_value": 1},
]

# ============================================================================
# OFFICE SECURITY (6 controls)
# ============================================================================
OFFICE_CONTROLS = [
    {"control_id": "E8-M03-O01", "control_name": "Office Macro Warning All", "category": "OfficeSecurity", "frameworks": "Essential8", "severity": "Critical", "description": "Disables all macros with notification", "registry_hive": winreg.HKEY_CURRENT_USER, "registry_path": r"SOFTWARE\Policies\Microsoft\Office\16.0\Word\Security", "value_name": "VBAWarnings", "expected_value": 2},
    {"control_id": "E8-M03-O02", "control_name": "Excel Macro Warning", "category": "OfficeSecurity", "frameworks": "Essential8", "severity": "Critical", "description": "Disables all Excel macros with notification", "registry_hive": winreg.HKEY_CURRENT_USER, "registry_path": r"SOFTWARE\Policies\Microsoft\Office\16.0\Excel\Security", "value_name": "VBAWarnings", "expected_value": 2},
    {"control_id": "E8-M03-O03", "control_name": "PowerPoint Macro Warning", "category": "OfficeSecurity", "frameworks": "Essential8", "severity": "Critical", "description": "Disables all PowerPoint macros with notification", "registry_hive": winreg.HKEY_CURRENT_USER, "registry_path": r"SOFTWARE\Policies\Microsoft\Office\16.0\PowerPoint\Security", "value_name": "VBAWarnings", "expected_value": 2},
    {"control_id": "E8-M03-O04", "control_name": "Office Block Untrusted Locations", "category": "OfficeSecurity", "frameworks": "Essential8", "severity": "High", "description": "Blocks macros from untrusted locations", "registry_hive": winreg.HKEY_CURRENT_USER, "registry_path": r"SOFTWARE\Policies\Microsoft\Office\16.0\Word\Security", "value_name": "blockcontentexecutionfrominternet", "expected_value": 1},
    {"control_id": "E8-M03-O05", "control_name": "Office Disable VBA for Internet Files", "category": "OfficeSecurity", "frameworks": "Essential8", "severity": "High", "description": "Disables VBA for files from Internet", "registry_hive": winreg.HKEY_CURRENT_USER, "registry_path": r"SOFTWARE\Policies\Microsoft\Office\16.0\Common\Security", "value_name": "DisableAllActiveX", "expected_value": 1},
    {"control_id": "E8-M03-O06", "control_name": "Office ActiveX Disabled", "category": "OfficeSecurity", "frameworks": "Essential8", "severity": "High", "description": "Disables ActiveX controls", "registry_hive": winreg.HKEY_CURRENT_USER, "registry_path": r"SOFTWARE\Policies\Microsoft\Office\Common\Security", "value_name": "UFIControls", "expected_value": 1},
]

# ============================================================================
# WINDOWS UPDATE (5 controls)
# ============================================================================
UPDATE_CONTROLS = [
    {"control_id": "CIS-18.9.102.1_E8-P01_PCI-6.2", "control_name": "Windows Update Auto Download Enabled", "category": "Updates", "frameworks": "CIS,Essential8,PCI-DSS", "severity": "Critical", "description": "Enables automatic update download", "registry_hive": winreg.HKEY_LOCAL_MACHINE, "registry_path": r"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU", "value_name": "NoAutoUpdate", "expected_value": 0},
    {"control_id": "CIS-18.9.102.2_E8-P02", "control_name": "Windows Update Configure Automatic Updates", "category": "Updates", "frameworks": "CIS,Essential8", "severity": "High", "description": "Configures auto update behavior", "registry_hive": winreg.HKEY_LOCAL_MACHINE, "registry_path": r"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU", "value_name": "AUOptions", "expected_value": 4, "comparison": "gte"},
    {"control_id": "CIS-18.9.102.3_E8-P03", "control_name": "Windows Update Install During Maintenance", "category": "Updates", "frameworks": "CIS,Essential8", "severity": "Medium", "description": "Allows installation during maintenance", "registry_hive": winreg.HKEY_LOCAL_MACHINE, "registry_path": r"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU", "value_name": "AutomaticMaintenanceEnabled", "expected_value": 1},
    {"control_id": "E8-P04", "control_name": "Windows Update No Auto Reboot With Users", "category": "Updates", "frameworks": "Essential8", "severity": "Low", "description": "Prevents auto reboot when users logged on", "registry_hive": winreg.HKEY_LOCAL_MACHINE, "registry_path": r"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU", "value_name": "NoAutoRebootWithLoggedOnUsers", "expected_value": 0},
    {"control_id": "CIS-18.9.102.1.1_PCI-6.2", "control_name": "Microsoft Update Service Enabled", "category": "Updates", "frameworks": "CIS,PCI-DSS", "severity": "High", "description": "Enables Microsoft Update service", "registry_hive": winreg.HKEY_LOCAL_MACHINE, "registry_path": r"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU", "value_name": "UseWUServer", "expected_value": 0},
]

# ============================================================================
# CREDENTIAL PROTECTION (4 controls)
# ============================================================================
CREDENTIAL_CONTROLS = [
    {"control_id": "CIS-18.9.6.1_E8-C01", "control_name": "Credential Guard Enabled", "category": "CredentialProtection", "frameworks": "CIS,Essential8", "severity": "Critical", "description": "Enables Credential Guard", "registry_hive": winreg.HKEY_LOCAL_MACHINE, "registry_path": r"SYSTEM\CurrentControlSet\Control\Lsa", "value_name": "LsaCfgFlags", "expected_value": 1, "comparison": "gte"},
    {"control_id": "CIS-18.9.47.11.1_E8-C02", "control_name": "LSASS Protection Enabled", "category": "CredentialProtection", "frameworks": "CIS,Essential8", "severity": "Critical", "description": "Enables LSA protection", "registry_hive": winreg.HKEY_LOCAL_MACHINE, "registry_path": r"SYSTEM\CurrentControlSet\Control\Lsa", "value_name": "RunAsPPL", "expected_value": 1},
    {"control_id": "E8-C03", "control_name": "Cached Credentials Minimum", "category": "CredentialProtection", "frameworks": "Essential8", "severity": "High", "description": "Minimizes cached credentials", "registry_hive": winreg.HKEY_LOCAL_MACHINE, "registry_path": r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", "value_name": "CachedLogonsCount", "expected_value": 2, "comparison": "lte"},
    {"control_id": "CIS-18.9.47.4.2_PCI-8.2", "control_name": "Digest Authentication Disabled", "category": "CredentialProtection", "frameworks": "CIS,PCI-DSS", "severity": "High", "description": "Disables WDigest authentication", "registry_hive": winreg.HKEY_LOCAL_MACHINE, "registry_path": r"SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest", "value_name": "UseLogonCredential", "expected_value": 0},
]

# ============================================================================
# ALL CONTROLS COMBINED
# ============================================================================
def get_all_controls():
    """Returns all security controls combined"""
    return (
        AUTHENTICATION_CONTROLS +
        PRIVILEGE_CONTROLS +
        NETWORK_CONTROLS +
        AUDIT_CONTROLS +
        REMOTE_ACCESS_CONTROLS +
        SYSTEM_HARDENING_CONTROLS +
        DEFENDER_CONTROLS +
        ENCRYPTION_CONTROLS +
        APP_CONTROL_CONTROLS +
        OFFICE_CONTROLS +
        UPDATE_CONTROLS +
        CREDENTIAL_CONTROLS
    )

# ============================================================================
# CONTROL COUNTS BY CATEGORY
# ============================================================================
def get_control_counts():
    """Returns control counts by category"""
    return {
        "Authentication": len(AUTHENTICATION_CONTROLS),
        "Privileges": len(PRIVILEGE_CONTROLS),
        "Network": len(NETWORK_CONTROLS),
        "Audit": len(AUDIT_CONTROLS),
        "RemoteAccess": len(REMOTE_ACCESS_CONTROLS),
        "SystemHardening": len(SYSTEM_HARDENING_CONTROLS),
        "AntiMalware": len(DEFENDER_CONTROLS),
        "Encryption": len(ENCRYPTION_CONTROLS),
        "ApplicationControl": len(APP_CONTROL_CONTROLS),
        "OfficeSecurity": len(OFFICE_CONTROLS),
        "Updates": len(UPDATE_CONTROLS),
        "CredentialProtection": len(CREDENTIAL_CONTROLS),
        "TOTAL": len(get_all_controls())
    }
