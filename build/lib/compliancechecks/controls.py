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
# SMB SECURITY (5 controls) - CRITICAL for ransomware protection
# ============================================================================
SMB_SECURITY_CONTROLS = [
    {"control_id": "CIS-18.3.1_E8-N01_PCI-2.2", "control_name": "SMBv1 Client Disabled", "category": "Network", "frameworks": "CIS,Essential8,PCI-DSS", "severity": "Critical", "description": "Disables SMBv1 client (WannaCry/NotPetya protection)", "registry_hive": winreg.HKEY_LOCAL_MACHINE, "registry_path": r"SYSTEM\CurrentControlSet\Services\mrxsmb10", "value_name": "Start", "expected_value": 4},
    {"control_id": "CIS-18.3.2_E8-N02_PCI-2.2", "control_name": "SMBv1 Server Disabled", "category": "Network", "frameworks": "CIS,Essential8,PCI-DSS", "severity": "Critical", "description": "Disables SMBv1 server (ransomware protection)", "registry_hive": winreg.HKEY_LOCAL_MACHINE, "registry_path": r"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters", "value_name": "SMB1", "expected_value": 0},
    {"control_id": "CIS-18.3.3_PCI-4.1", "control_name": "SMB Server Encryption Required", "category": "Network", "frameworks": "CIS,PCI-DSS", "severity": "High", "description": "Requires encryption for SMB traffic", "registry_hive": winreg.HKEY_LOCAL_MACHINE, "registry_path": r"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters", "value_name": "EncryptData", "expected_value": 1},
    {"control_id": "CIS-2.3.10.14", "control_name": "SMB Null Session Shares", "category": "Network", "frameworks": "CIS", "severity": "High", "description": "Prevents null session share enumeration", "registry_hive": winreg.HKEY_LOCAL_MACHINE, "registry_path": r"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters", "value_name": "NullSessionShares", "expected_value": ""},
    {"control_id": "CIS-2.3.10.15", "control_name": "SMB Null Session Pipes", "category": "Network", "frameworks": "CIS", "severity": "High", "description": "Prevents null session pipe access", "registry_hive": winreg.HKEY_LOCAL_MACHINE, "registry_path": r"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters", "value_name": "NullSessionPipes", "expected_value": ""},
]

# ============================================================================
# PROTOCOL ATTACK PREVENTION (6 controls) - CRITICAL for MITM attacks
# ============================================================================
PROTOCOL_ATTACK_CONTROLS = [
    {"control_id": "CIS-18.9.47.5.1_E8-N03", "control_name": "LLMNR Disabled", "category": "Network", "frameworks": "CIS,Essential8", "severity": "Critical", "description": "Disables LLMNR to prevent MITM attacks", "registry_hive": winreg.HKEY_LOCAL_MACHINE, "registry_path": r"SOFTWARE\Policies\Microsoft\Windows NT\DNSClient", "value_name": "EnableMulticast", "expected_value": 0},
    {"control_id": "CIS-18.9.47.5.2_E8-N04", "control_name": "WPAD Disabled", "category": "Network", "frameworks": "CIS,Essential8", "severity": "Critical", "description": "Disables WPAD to prevent proxy poisoning", "registry_hive": winreg.HKEY_LOCAL_MACHINE, "registry_path": r"SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Wpad", "value_name": "WpadOverride", "expected_value": 1},
    {"control_id": "CIS-18.4.8.1_E8-N05", "control_name": "NetBIOS over TCP/IP Disabled", "category": "Network", "frameworks": "CIS,Essential8", "severity": "High", "description": "Disables NetBT for security", "registry_hive": winreg.HKEY_LOCAL_MACHINE, "registry_path": r"SYSTEM\CurrentControlSet\Services\NetBT\Parameters", "value_name": "EnableLMHosts", "expected_value": 0},
    {"control_id": "CIS-18.5.11.2", "control_name": "ICMP Redirect Disabled", "category": "Network", "frameworks": "CIS", "severity": "Medium", "description": "Prevents ICMP redirect attacks", "registry_hive": winreg.HKEY_LOCAL_MACHINE, "registry_path": r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters", "value_name": "EnableICMPRedirect", "expected_value": 0},
    {"control_id": "CIS-18.4.6.2", "control_name": "IPv6 Transition ISATAP Disabled", "category": "Network", "frameworks": "CIS", "severity": "Medium", "description": "Disables ISATAP transition technology", "registry_hive": winreg.HKEY_LOCAL_MACHINE, "registry_path": r"SOFTWARE\Policies\Microsoft\Windows\TCPIP\v6Transition", "value_name": "ISATAP_State", "expected_value": "Disabled"},
    {"control_id": "CIS-18.4.6.3", "control_name": "IPv6 Transition Teredo Disabled", "category": "Network", "frameworks": "CIS", "severity": "Medium", "description": "Disables Teredo transition technology", "registry_hive": winreg.HKEY_LOCAL_MACHINE, "registry_path": r"SOFTWARE\Policies\Microsoft\Windows\TCPIP\v6Transition", "value_name": "Teredo_State", "expected_value": "Disabled"},
]

# ============================================================================
# INTERACTIVE LOGON (8 controls) - Compliance requirements
# ============================================================================
INTERACTIVE_LOGON_CONTROLS = [
    {"control_id": "CIS-2.3.7.1", "control_name": "Interactive Logon Message Title", "category": "Authentication", "frameworks": "CIS", "severity": "Medium", "description": "Legal notice caption for logon", "registry_hive": winreg.HKEY_LOCAL_MACHINE, "registry_path": r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "value_name": "LegalNoticeCaption", "expected_value": ""},
    {"control_id": "CIS-2.3.7.2", "control_name": "Interactive Logon Message Text", "category": "Authentication", "frameworks": "CIS", "severity": "Medium", "description": "Legal notice text for logon", "registry_hive": winreg.HKEY_LOCAL_MACHINE, "registry_path": r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "value_name": "LegalNoticeText", "expected_value": ""},
    {"control_id": "CIS-2.3.7.3", "control_name": "Don't Display Last Username", "category": "Authentication", "frameworks": "CIS", "severity": "Medium", "description": "Hides last logged on username", "registry_hive": winreg.HKEY_LOCAL_MACHINE, "registry_path": r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "value_name": "DontDisplayLastUserName", "expected_value": 1},
    {"control_id": "CIS-2.3.7.4", "control_name": "Require Ctrl+Alt+Del", "category": "Authentication", "frameworks": "CIS", "severity": "Low", "description": "Requires secure attention sequence", "registry_hive": winreg.HKEY_LOCAL_MACHINE, "registry_path": r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "value_name": "DisableCAD", "expected_value": 0},
    {"control_id": "CIS-2.3.7.5", "control_name": "Smart Card Removal Behavior", "category": "Authentication", "frameworks": "CIS", "severity": "Medium", "description": "Action on smart card removal", "registry_hive": winreg.HKEY_LOCAL_MACHINE, "registry_path": r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", "value_name": "ScRemoveOption", "expected_value": "2"},
    {"control_id": "CIS-2.3.7.6", "control_name": "Enable Administrator Account", "category": "Authentication", "frameworks": "CIS", "severity": "High", "description": "Monitors admin account status", "registry_hive": winreg.HKEY_LOCAL_MACHINE, "registry_path": r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "value_name": "dontdisplaylastusername", "expected_value": 1},
    {"control_id": "CIS-2.3.7.9", "control_name": "Disable Lock Workstation", "category": "Authentication", "frameworks": "CIS", "severity": "Low", "description": "Allows workstation lock feature", "registry_hive": winreg.HKEY_LOCAL_MACHINE, "registry_path": r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "value_name": "DisableLockWorkstation", "expected_value": 0},
    {"control_id": "CIS-18.9.6.2", "control_name": "Enumerate Local Users on Domain-Joined", "category": "Authentication", "frameworks": "CIS", "severity": "Medium", "description": "Prevents local user enumeration", "registry_hive": winreg.HKEY_LOCAL_MACHINE, "registry_path": r"SOFTWARE\Policies\Microsoft\Windows\System", "value_name": "EnumerateLocalUsers", "expected_value": 0},
]

# ============================================================================
# MSS (MICROSOFT SECURITY SETTINGS) (10 controls)
# ============================================================================
MSS_CONTROLS = [
    {"control_id": "CIS-18.5.4.3_MSS-01", "control_name": "MSS Safe DLL Search Mode", "category": "SystemHardening", "frameworks": "CIS", "severity": "High", "description": "Enables safe DLL search order", "registry_hive": winreg.HKEY_LOCAL_MACHINE, "registry_path": r"SYSTEM\CurrentControlSet\Control\Session Manager", "value_name": "SafeDllSearchMode", "expected_value": 1},
    {"control_id": "CIS-18.5.5.2_MSS-02", "control_name": "MSS Screen Saver Grace Period", "category": "SystemHardening", "frameworks": "CIS", "severity": "Medium", "description": "Screen saver grace period", "registry_hive": winreg.HKEY_LOCAL_MACHINE, "registry_path": r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", "value_name": "ScreenSaverGracePeriod", "expected_value": "5", "comparison": "lte"},
    {"control_id": "CIS-18.5.8.1_MSS-03", "control_name": "MSS Warning Level", "category": "SystemHardening", "frameworks": "CIS", "severity": "Medium", "description": "Disk quota warning percentage", "registry_hive": winreg.HKEY_LOCAL_MACHINE, "registry_path": r"SYSTEM\CurrentControlSet\Services\Eventlog\Security", "value_name": "WarningLevel", "expected_value": 90, "comparison": "lte"},
    {"control_id": "CIS-18.5.9.1_MSS-04", "control_name": "MSS Auto Logon Disabled", "category": "Authentication", "frameworks": "CIS", "severity": "High", "description": "Prevents automatic logon", "registry_hive": winreg.HKEY_LOCAL_MACHINE, "registry_path": r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", "value_name": "AutoAdminLogon", "expected_value": "0"},
    {"control_id": "CIS-18.5.11.3_MSS-05", "control_name": "MSS TCP Max Data Retransmissions IPv4", "category": "Network", "frameworks": "CIS", "severity": "Low", "description": "TCP data retransmission attempts", "registry_hive": winreg.HKEY_LOCAL_MACHINE, "registry_path": r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters", "value_name": "TcpMaxDataRetransmissions", "expected_value": 3, "comparison": "lte"},
    {"control_id": "CIS-18.5.11.4_MSS-06", "control_name": "MSS TCP Max Data Retransmissions IPv6", "category": "Network", "frameworks": "CIS", "severity": "Low", "description": "TCP data retransmission attempts IPv6", "registry_hive": winreg.HKEY_LOCAL_MACHINE, "registry_path": r"SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters", "value_name": "TcpMaxDataRetransmissions", "expected_value": 3, "comparison": "lte"},
    {"control_id": "CIS-18.5.14.1_MSS-07", "control_name": "MSS Enable Firewall", "category": "Network", "frameworks": "CIS", "severity": "Critical", "description": "Ensures Windows Firewall enabled", "registry_hive": winreg.HKEY_LOCAL_MACHINE, "registry_path": r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile", "value_name": "EnableFirewall", "expected_value": 1},
    {"control_id": "CIS-18.5.19.1_MSS-08", "control_name": "MSS Perform Router Discovery", "category": "Network", "frameworks": "CIS", "severity": "Medium", "description": "Controls router discovery", "registry_hive": winreg.HKEY_LOCAL_MACHINE, "registry_path": r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters", "value_name": "PerformRouterDiscovery", "expected_value": 0},
    {"control_id": "CIS-18.5.20.1_MSS-09", "control_name": "MSS No Name Release On Demand", "category": "Network", "frameworks": "CIS", "severity": "Low", "description": "Controls NetBIOS name release", "registry_hive": winreg.HKEY_LOCAL_MACHINE, "registry_path": r"SYSTEM\CurrentControlSet\Services\NetBT\Parameters", "value_name": "NoNameReleaseOnDemand", "expected_value": 1},
    {"control_id": "CIS-18.5.21.1_MSS-10", "control_name": "MSS Hidden Shares", "category": "Network", "frameworks": "CIS", "severity": "Medium", "description": "Requires admin shares", "registry_hive": winreg.HKEY_LOCAL_MACHINE, "registry_path": r"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters", "value_name": "AutoShareWks", "expected_value": 0},
]

# ============================================================================
# PRINT SERVICES & SYSTEM SERVICES (7 controls) - PrintNightmare mitigation
# ============================================================================
PRINT_SERVICES_CONTROLS = [
    {"control_id": "CIS-5.35_PN-01", "control_name": "Print Spooler Service Disabled", "category": "SystemHardening", "frameworks": "CIS", "severity": "High", "description": "Disables Print Spooler (PrintNightmare mitigation)", "registry_hive": winreg.HKEY_LOCAL_MACHINE, "registry_path": r"SYSTEM\CurrentControlSet\Services\Spooler", "value_name": "Start", "expected_value": 4},
    {"control_id": "CIS-18.9.59.1_PN-02", "control_name": "Point and Print Restrictions", "category": "SystemHardening", "frameworks": "CIS", "severity": "High", "description": "Restricts Point and Print operations", "registry_hive": winreg.HKEY_LOCAL_MACHINE, "registry_path": r"SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint", "value_name": "RestrictDriverInstallationToAdministrators", "expected_value": 1},
    {"control_id": "CIS-5.33", "control_name": "Remote Registry Service Disabled", "category": "SystemHardening", "frameworks": "CIS", "severity": "High", "description": "Disables Remote Registry service", "registry_hive": winreg.HKEY_LOCAL_MACHINE, "registry_path": r"SYSTEM\CurrentControlSet\Services\RemoteRegistry", "value_name": "Start", "expected_value": 4},
    {"control_id": "CIS-5.37", "control_name": "SNMP Service Disabled", "category": "SystemHardening", "frameworks": "CIS", "severity": "Medium", "description": "Disables SNMP service", "registry_hive": winreg.HKEY_LOCAL_MACHINE, "registry_path": r"SYSTEM\CurrentControlSet\Services\SNMP", "value_name": "Start", "expected_value": 4},
    {"control_id": "CIS-5.40", "control_name": "Windows Search Service", "category": "SystemHardening", "frameworks": "CIS", "severity": "Low", "description": "Controls Windows Search service", "registry_hive": winreg.HKEY_LOCAL_MACHINE, "registry_path": r"SYSTEM\CurrentControlSet\Services\WSearch", "value_name": "Start", "expected_value": 4},
    {"control_id": "CIS-18.9.59.2_PN-03", "control_name": "Package Point and Print NoWarning", "category": "SystemHardening", "frameworks": "CIS", "severity": "High", "description": "Shows warning for package point and print", "registry_hive": winreg.HKEY_LOCAL_MACHINE, "registry_path": r"SOFTWARE\Policies\Microsoft\Windows NT\Printers\PackagePointAndPrint", "value_name": "PackagePointAndPrintServerList", "expected_value": 1},
    {"control_id": "CIS-18.9.59.3_PN-04", "control_name": "UNC Hardened Access Paths", "category": "Network", "frameworks": "CIS", "severity": "High", "description": "Hardens UNC path access", "registry_hive": winreg.HKEY_LOCAL_MACHINE, "registry_path": r"SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths", "value_name": "\\*\\SYSVOL", "expected_value": "RequireMutualAuthentication=1,RequireIntegrity=1"},
]

# ============================================================================
# MICROSOFT EDGE BROWSER HARDENING (10 controls) - Essential 8 L2/L3
# ============================================================================
EDGE_BROWSER_CONTROLS = [
    {"control_id": "E8-M4-EDGE-01", "control_name": "Edge SmartScreen Enabled", "category": "BrowserSecurity", "frameworks": "Essential8", "severity": "High", "description": "Enables Edge SmartScreen filter", "registry_hive": winreg.HKEY_LOCAL_MACHINE, "registry_path": r"SOFTWARE\Policies\Microsoft\Edge", "value_name": "SmartScreenEnabled", "expected_value": 1},
    {"control_id": "E8-M4-EDGE-02", "control_name": "Edge SmartScreen PUA Enabled", "category": "BrowserSecurity", "frameworks": "Essential8", "severity": "High", "description": "Blocks potentially unwanted apps", "registry_hive": winreg.HKEY_LOCAL_MACHINE, "registry_path": r"SOFTWARE\Policies\Microsoft\Edge", "value_name": "SmartScreenPuaEnabled", "expected_value": 1},
    {"control_id": "E8-M4-EDGE-03", "control_name": "Edge Block Outdated Plugins", "category": "BrowserSecurity", "frameworks": "Essential8", "severity": "Medium", "description": "Blocks outdated plugins", "registry_hive": winreg.HKEY_LOCAL_MACHINE, "registry_path": r"SOFTWARE\Policies\Microsoft\Edge", "value_name": "DefaultPluginsSetting", "expected_value": 2},
    {"control_id": "E8-M4-EDGE-04", "control_name": "Edge Password Manager Disabled", "category": "BrowserSecurity", "frameworks": "Essential8", "severity": "Medium", "description": "Disables built-in password manager", "registry_hive": winreg.HKEY_LOCAL_MACHINE, "registry_path": r"SOFTWARE\Policies\Microsoft\Edge", "value_name": "PasswordManagerEnabled", "expected_value": 0},
    {"control_id": "E8-M4-EDGE-05", "control_name": "Edge Sync Disabled", "category": "BrowserSecurity", "frameworks": "Essential8", "severity": "Low", "description": "Disables browser sync for security", "registry_hive": winreg.HKEY_LOCAL_MACHINE, "registry_path": r"SOFTWARE\Policies\Microsoft\Edge", "value_name": "SyncDisabled", "expected_value": 1},
    {"control_id": "E8-M4-EDGE-06", "control_name": "Edge DNS over HTTPS", "category": "BrowserSecurity", "frameworks": "Essential8", "severity": "Medium", "description": "Enables encrypted DNS", "registry_hive": winreg.HKEY_LOCAL_MACHINE, "registry_path": r"SOFTWARE\Policies\Microsoft\Edge", "value_name": "DnsOverHttpsMode", "expected_value": "secure"},
    {"control_id": "E8-M4-EDGE-07", "control_name": "Edge Enhanced Security Mode", "category": "BrowserSecurity", "frameworks": "Essential8", "severity": "High", "description": "Enables enhanced security mode", "registry_hive": winreg.HKEY_LOCAL_MACHINE, "registry_path": r"SOFTWARE\Policies\Microsoft\Edge", "value_name": "EnhanceSecurityMode", "expected_value": 1},
    {"control_id": "E8-M4-EDGE-08", "control_name": "Edge Block Third-Party Cookies", "category": "BrowserSecurity", "frameworks": "Essential8", "severity": "Medium", "description": "Blocks third-party cookies", "registry_hive": winreg.HKEY_LOCAL_MACHINE, "registry_path": r"SOFTWARE\Policies\Microsoft\Edge", "value_name": "BlockThirdPartyCookies", "expected_value": 1},
    {"control_id": "E8-M4-EDGE-09", "control_name": "Edge SSL Error Override Disabled", "category": "BrowserSecurity", "frameworks": "Essential8", "severity": "High", "description": "Prevents SSL error bypasses", "registry_hive": winreg.HKEY_LOCAL_MACHINE, "registry_path": r"SOFTWARE\Policies\Microsoft\Edge", "value_name": "SSLErrorOverrideAllowed", "expected_value": 0},
    {"control_id": "E8-M4-EDGE-10", "control_name": "Edge Download Restrictions", "category": "BrowserSecurity", "frameworks": "Essential8", "severity": "Medium", "description": "Restricts dangerous downloads", "registry_hive": winreg.HKEY_LOCAL_MACHINE, "registry_path": r"SOFTWARE\Policies\Microsoft\Edge", "value_name": "DefaultDownloadDirectory", "expected_value": ""},
]

# ============================================================================
# ADDITIONAL FIREWALL CONTROLS (6 controls)
# ============================================================================
ADDITIONAL_FIREWALL_CONTROLS = [
    {"control_id": "CIS-18.5.19.2.7", "control_name": "Firewall Domain - Log Dropped Packets", "category": "Network", "frameworks": "CIS", "severity": "Medium", "description": "Logs dropped packets in Domain profile", "registry_hive": winreg.HKEY_LOCAL_MACHINE, "registry_path": r"SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging", "value_name": "LogDroppedPackets", "expected_value": 1},
    {"control_id": "CIS-18.5.19.2.8", "control_name": "Firewall Domain - Log Successful Connections", "category": "Network", "frameworks": "CIS", "severity": "Low", "description": "Logs successful connections", "registry_hive": winreg.HKEY_LOCAL_MACHINE, "registry_path": r"SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging", "value_name": "LogSuccessfulConnections", "expected_value": 1},
    {"control_id": "CIS-18.5.19.3.3", "control_name": "Firewall Private - Log Dropped Packets", "category": "Network", "frameworks": "CIS", "severity": "Medium", "description": "Logs dropped packets in Private profile", "registry_hive": winreg.HKEY_LOCAL_MACHINE, "registry_path": r"SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging", "value_name": "LogDroppedPackets", "expected_value": 1},
    {"control_id": "CIS-18.5.19.4.3", "control_name": "Firewall Public - Log Dropped Packets", "category": "Network", "frameworks": "CIS", "severity": "Medium", "description": "Logs dropped packets in Public profile", "registry_hive": winreg.HKEY_LOCAL_MACHINE, "registry_path": r"SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging", "value_name": "LogDroppedPackets", "expected_value": 1},
    {"control_id": "CIS-18.5.19.2.9", "control_name": "Firewall Domain - Unicast Response", "category": "Network", "frameworks": "CIS", "severity": "Medium", "description": "Controls unicast response to multicast", "registry_hive": winreg.HKEY_LOCAL_MACHINE, "registry_path": r"SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile", "value_name": "DisableUnicastResponsesToMulticastBroadcast", "expected_value": 1},
    {"control_id": "CIS-18.5.19.2.10", "control_name": "Firewall Domain - Notify on Listen", "category": "Network", "frameworks": "CIS", "severity": "Low", "description": "Notifies when app starts listening", "registry_hive": winreg.HKEY_LOCAL_MACHINE, "registry_path": r"SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile", "value_name": "DisableNotifications", "expected_value": 0},
]

# ============================================================================
# APPLICATION SECURITY - ADOBE, JAVA, SCRIPTS (10 controls)
# ============================================================================
APP_SECURITY_CONTROLS = [
    {"control_id": "E8-M4-ADOBE-01", "control_name": "Adobe Reader Protected Mode", "category": "ApplicationSecurity", "frameworks": "Essential8", "severity": "High", "description": "Enables Adobe Reader protected mode", "registry_hive": winreg.HKEY_LOCAL_MACHINE, "registry_path": r"SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown", "value_name": "bProtectedMode", "expected_value": 1},
    {"control_id": "E8-M4-ADOBE-02", "control_name": "Adobe Reader Enhanced Security", "category": "ApplicationSecurity", "frameworks": "Essential8", "severity": "High", "description": "Enables enhanced security in browser", "registry_hive": winreg.HKEY_LOCAL_MACHINE, "registry_path": r"SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown", "value_name": "bEnhancedSecurityInBrowser", "expected_value": 1},
    {"control_id": "E8-M4-ADOBE-03", "control_name": "Adobe Reader JavaScript Disabled", "category": "ApplicationSecurity", "frameworks": "Essential8", "severity": "High", "description": "Disables JavaScript in PDFs", "registry_hive": winreg.HKEY_LOCAL_MACHINE, "registry_path": r"SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown", "value_name": "bDisableJavaScript", "expected_value": 1},
    {"control_id": "E8-M4-JAVA-01", "control_name": "Java Deployment Security Level", "category": "ApplicationSecurity", "frameworks": "Essential8", "severity": "High", "description": "Sets Java security to high", "registry_hive": winreg.HKEY_LOCAL_MACHINE, "registry_path": r"SOFTWARE\JavaSoft\Java Runtime Environment", "value_name": "deployment.security.level", "expected_value": "HIGH"},
    {"control_id": "E8-M4-JAVA-02", "control_name": "Java Auto Update Disabled", "category": "ApplicationSecurity", "frameworks": "Essential8", "severity": "Medium", "description": "Disables Java auto-update", "registry_hive": winreg.HKEY_LOCAL_MACHINE, "registry_path": r"SOFTWARE\JavaSoft\Java Update\Policy", "value_name": "EnableAutoUpdateCheck", "expected_value": 0},
    {"control_id": "CIS-18.9.84.1_E8-M1", "control_name": "Windows Script Host Disabled", "category": "ApplicationControl", "frameworks": "CIS,Essential8", "severity": "High", "description": "Disables Windows Script Host", "registry_hive": winreg.HKEY_LOCAL_MACHINE, "registry_path": r"SOFTWARE\Microsoft\Windows Script Host\Settings", "value_name": "Enabled", "expected_value": 0},
    {"control_id": "CIS-18.9.84.2_E8-M1", "control_name": "VBScript Disabled", "category": "ApplicationControl", "frameworks": "CIS,Essential8", "severity": "High", "description": "Disables VBScript execution", "registry_hive": winreg.HKEY_LOCAL_MACHINE, "registry_path": r"SOFTWARE\Microsoft\Windows Script Host\Settings", "value_name": "DisableVBScript", "expected_value": 1},
    {"control_id": "CIS-18.9.84.3_E8-M1", "control_name": "JScript Disabled", "category": "ApplicationControl", "frameworks": "CIS,Essential8", "severity": "High", "description": "Disables JScript execution", "registry_hive": winreg.HKEY_LOCAL_MACHINE, "registry_path": r"SOFTWARE\Microsoft\Windows Script Host\Settings", "value_name": "DisableJScript", "expected_value": 1},
    {"control_id": "E8-M4-SCRIPT-01", "control_name": "Flash Player Kill Bit", "category": "ApplicationSecurity", "frameworks": "Essential8", "severity": "High", "description": "Disables Flash Player ActiveX", "registry_hive": winreg.HKEY_LOCAL_MACHINE, "registry_path": r"SOFTWARE\Microsoft\Internet Explorer\ActiveX Compatibility\{D27CDB6E-AE6D-11CF-96B8-444553540000}", "value_name": "Compatibility Flags", "expected_value": 1024},
    {"control_id": "E8-M4-SCRIPT-02", "control_name": "Silverlight Kill Bit", "category": "ApplicationSecurity", "frameworks": "Essential8", "severity": "Medium", "description": "Disables Silverlight plugin", "registry_hive": winreg.HKEY_LOCAL_MACHINE, "registry_path": r"SOFTWARE\Microsoft\Internet Explorer\ActiveX Compatibility\{DFEAF541-F3E1-4C24-ACAC-99C30715084A}", "value_name": "Compatibility Flags", "expected_value": 1024},
]

# ============================================================================
# ADDITIONAL OUTLOOK SECURITY (5 controls)
# ============================================================================
ADDITIONAL_OUTLOOK_CONTROLS = [
    {"control_id": "E8-M3-OUTLOOK-01", "control_name": "Outlook Object Model Guard Prompt", "category": "OfficeSecurity", "frameworks": "Essential8", "severity": "High", "description": "Prompts for object model access", "registry_hive": winreg.HKEY_CURRENT_USER, "registry_path": r"SOFTWARE\Policies\Microsoft\Office\16.0\Outlook\Security", "value_name": "PromptOOMAddressBookAccess", "expected_value": 1},
    {"control_id": "E8-M3-OUTLOOK-02", "control_name": "Outlook Block External Content", "category": "OfficeSecurity", "frameworks": "Essential8", "severity": "High", "description": "Blocks external content in emails", "registry_hive": winreg.HKEY_CURRENT_USER, "registry_path": r"SOFTWARE\Policies\Microsoft\Office\16.0\Outlook\Options\Mail", "value_name": "BlockExtContent", "expected_value": 1},
    {"control_id": "E8-M3-OUTLOOK-03", "control_name": "Outlook Level1 File Extensions", "category": "OfficeSecurity", "frameworks": "Essential8", "severity": "High", "description": "Blocks dangerous file types", "registry_hive": winreg.HKEY_CURRENT_USER, "registry_path": r"SOFTWARE\Policies\Microsoft\Office\16.0\Outlook\Security", "value_name": "Level1Remove", "expected_value": ""},
    {"control_id": "E8-M3-OUTLOOK-04", "control_name": "Outlook Disable Hyperlinks", "category": "OfficeSecurity", "frameworks": "Essential8", "severity": "Medium", "description": "Warns before opening hyperlinks", "registry_hive": winreg.HKEY_CURRENT_USER, "registry_path": r"SOFTWARE\Policies\Microsoft\Office\16.0\Common\Security", "value_name": "DisableHyperlinkWarning", "expected_value": 0},
    {"control_id": "E8-M3-OUTLOOK-05", "control_name": "Outlook Junk Email Protection", "category": "OfficeSecurity", "frameworks": "Essential8", "severity": "Medium", "description": "Enables junk email filtering", "registry_hive": winreg.HKEY_CURRENT_USER, "registry_path": r"SOFTWARE\Policies\Microsoft\Office\16.0\Outlook\Options\Mail", "value_name": "JunkMailImportLists", "expected_value": 1},
]

# ============================================================================
# WINDOWS STORE RESTRICTIONS (3 controls)
# ============================================================================
WINDOWS_STORE_CONTROLS = [
    {"control_id": "E8-M1-STORE-01", "control_name": "Windows Store Disabled", "category": "ApplicationControl", "frameworks": "Essential8", "severity": "Medium", "description": "Disables Windows Store for enterprise", "registry_hive": winreg.HKEY_LOCAL_MACHINE, "registry_path": r"SOFTWARE\Policies\Microsoft\WindowsStore", "value_name": "RemoveWindowsStore", "expected_value": 1},
    {"control_id": "E8-M1-STORE-02", "control_name": "Windows Store Auto Download Disabled", "category": "ApplicationControl", "frameworks": "Essential8", "severity": "Medium", "description": "Disables auto app downloads", "registry_hive": winreg.HKEY_LOCAL_MACHINE, "registry_path": r"SOFTWARE\Policies\Microsoft\WindowsStore", "value_name": "AutoDownload", "expected_value": 2},
    {"control_id": "E8-M1-STORE-03", "control_name": "Private Store Only", "category": "ApplicationControl", "frameworks": "Essential8", "severity": "Medium", "description": "Restricts to private store only", "registry_hive": winreg.HKEY_LOCAL_MACHINE, "registry_path": r"SOFTWARE\Policies\Microsoft\WindowsStore", "value_name": "RequirePrivateStoreOnly", "expected_value": 1},
]

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
        SMB_SECURITY_CONTROLS +
        PROTOCOL_ATTACK_CONTROLS +
        INTERACTIVE_LOGON_CONTROLS +
        MSS_CONTROLS +
        PRINT_SERVICES_CONTROLS +
        EDGE_BROWSER_CONTROLS +
        ADDITIONAL_FIREWALL_CONTROLS +
        APP_SECURITY_CONTROLS +
        ADDITIONAL_OUTLOOK_CONTROLS +
        WINDOWS_STORE_CONTROLS +
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
        "SMB Security": len(SMB_SECURITY_CONTROLS),
        "Protocol Attacks": len(PROTOCOL_ATTACK_CONTROLS),
        "Interactive Logon": len(INTERACTIVE_LOGON_CONTROLS),
        "MSS Settings": len(MSS_CONTROLS),
        "Print Services": len(PRINT_SERVICES_CONTROLS),
        "Browser Security": len(EDGE_BROWSER_CONTROLS),
        "Additional Firewall": len(ADDITIONAL_FIREWALL_CONTROLS),
        "Application Security": len(APP_SECURITY_CONTROLS),
        "Additional Outlook": len(ADDITIONAL_OUTLOOK_CONTROLS),
        "Windows Store": len(WINDOWS_STORE_CONTROLS),
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
