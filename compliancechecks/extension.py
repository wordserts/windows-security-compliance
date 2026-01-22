"""
Windows Security Compliance Extension
Monitors Windows security configurations against CIS, Essential 8, and PCI-DSS
"""

import winreg
import logging
from typing import Dict, List, Any, Optional

try:
    from dynatrace_extension import Extension, Status, StatusValue
except ImportError:
    # Fallback for local testing
    class Extension:
        config = {}
        logger = None
        def __init__(self):
            self.config = {}
            self.logger = logging.getLogger(__name__)
        def run(self):
            pass
        def report_metric(self, key, value, dimensions=None):
            pass
    class Status:
        def __init__(self, status, message=""):
            self.status = status
            self.message = message
    class StatusValue:
        OK = "OK"
        ERROR = "ERROR"


class ComplianceExtension(Extension):
    """Extension to monitor Windows security compliance"""

    def initialize(self):
        """Initialize the extension"""
        self.logger.info("Initializing Windows Security Compliance Extension")
        self.logger.info("Monitoring 30 security controls across CIS, Essential 8, and PCI-DSS")

    def query(self):
        """Main query method called by OneAgent"""
        try:
            self.logger.info("Starting compliance check")
            
            controls = self._get_controls()
            results = []
            
            for control in controls:
                result = self._check_compliance(control)
                results.append(result)
                self._report_control_metrics(result)
            
            # Summary
            compliant_count = sum(1 for r in results if r["status"] == 1)
            non_compliant_count = sum(1 for r in results if r["status"] == 0)
            not_configured_count = sum(1 for r in results if r["status"] == -1)
            
            self.logger.info(f"Compliance Check Complete: {compliant_count} compliant, "
                           f"{non_compliant_count} non-compliant, "
                           f"{not_configured_count} not configured")
            
            return Status(StatusValue.OK)
            
        except Exception as e:
            self.logger.error(f"Error in compliance check: {str(e)}", exc_info=True)
            return Status(StatusValue.ERROR, f"Failed to check compliance: {str(e)}")

    def _get_controls(self) -> List[Dict]:
        """Get all compliance control definitions - 30 controls total"""
        return [
            # Authentication & Credentials (3 controls)
            {"control_id": "CIS-18.3.1_E8-H01_PCI-2.2.4", "control_name": "No LM Hash Storage", "category": "Authentication", "frameworks": "CIS,Essential8,PCI-DSS", "severity": "Critical", "description": "Prevents storage of LAN Manager password hashes", "registry_hive": winreg.HKEY_LOCAL_MACHINE, "registry_path": r"SYSTEM\CurrentControlSet\Control\Lsa", "value_name": "NoLMHash", "expected_value": 1, "value_type": "DWORD"},
            {"control_id": "CIS-2.3.11.8_PCI-2.2.4", "control_name": "LAN Manager Authentication Level", "category": "Authentication", "frameworks": "CIS,PCI-DSS", "severity": "High", "description": "Requires NTLMv2 authentication only", "registry_hive": winreg.HKEY_LOCAL_MACHINE, "registry_path": r"SYSTEM\CurrentControlSet\Control\Lsa", "value_name": "LmCompatibilityLevel", "expected_value": 5, "value_type": "DWORD"},
            {"control_id": "CIS-2.3.11.7_PCI-8.2.1", "control_name": "Cached Logons Limit", "category": "Authentication", "frameworks": "CIS,PCI-DSS", "severity": "Medium", "description": "Limits cached domain credentials", "registry_hive": winreg.HKEY_LOCAL_MACHINE, "registry_path": r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", "value_name": "CachedLogonsCount", "expected_value": 4, "value_type": "DWORD"},
            
            # User Account Control & Privileges (4 controls)
            {"control_id": "CIS-2.3.17.1_E8-H02", "control_name": "User Account Control Enabled", "category": "Privileges", "frameworks": "CIS,Essential8", "severity": "Critical", "description": "Enables User Account Control for all users", "registry_hive": winreg.HKEY_LOCAL_MACHINE, "registry_path": r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "value_name": "EnableLUA", "expected_value": 1, "value_type": "DWORD"},
            {"control_id": "CIS-2.3.17.2", "control_name": "UAC Admin Approval Mode", "category": "Privileges", "frameworks": "CIS", "severity": "High", "description": "Requires admin approval mode for built-in Administrator", "registry_hive": winreg.HKEY_LOCAL_MACHINE, "registry_path": r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "value_name": "FilterAdministratorToken", "expected_value": 1, "value_type": "DWORD"},
            {"control_id": "CIS-2.3.17.5", "control_name": "UAC Elevation Prompt for Admins", "category": "Privileges", "frameworks": "CIS", "severity": "High", "description": "Prompts for credentials on elevation", "registry_hive": winreg.HKEY_LOCAL_MACHINE, "registry_path": r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "value_name": "ConsentPromptBehaviorAdmin", "expected_value": 2, "value_type": "DWORD"},
            {"control_id": "CIS-2.3.17.6", "control_name": "UAC Elevation Prompt for Standard Users", "category": "Privileges", "frameworks": "CIS", "severity": "High", "description": "Automatically denies elevation for standard users", "registry_hive": winreg.HKEY_LOCAL_MACHINE, "registry_path": r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "value_name": "ConsentPromptBehaviorUser", "expected_value": 0, "value_type": "DWORD"},
            
            # Network Security (6 controls)
            {"control_id": "CIS-2.3.8.3_PCI-2.2.4", "control_name": "SMB Server Signing Required", "category": "Network", "frameworks": "CIS,PCI-DSS", "severity": "Critical", "description": "Requires SMB packet signing for server", "registry_hive": winreg.HKEY_LOCAL_MACHINE, "registry_path": r"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters", "value_name": "RequireSecuritySignature", "expected_value": 1, "value_type": "DWORD"},
            {"control_id": "CIS-2.3.8.1_PCI-2.2.4", "control_name": "SMB Client Signing Required", "category": "Network", "frameworks": "CIS,PCI-DSS", "severity": "Critical", "description": "Requires SMB packet signing for client", "registry_hive": winreg.HKEY_LOCAL_MACHINE, "registry_path": r"SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters", "value_name": "RequireSecuritySignature", "expected_value": 1, "value_type": "DWORD"},
            {"control_id": "CIS-2.3.11.9_PCI-2.2.4", "control_name": "LDAP Client Signing Required", "category": "Network", "frameworks": "CIS,PCI-DSS", "severity": "High", "description": "Requires LDAP client signing", "registry_hive": winreg.HKEY_LOCAL_MACHINE, "registry_path": r"SYSTEM\CurrentControlSet\Services\LDAP", "value_name": "LDAPClientIntegrity", "expected_value": 2, "value_type": "DWORD"},
            {"control_id": "CIS-2.3.1.4", "control_name": "Anonymous SID Translation Disabled", "category": "Network", "frameworks": "CIS", "severity": "High", "description": "Prevents anonymous users from translating SIDs", "registry_hive": winreg.HKEY_LOCAL_MACHINE, "registry_path": r"SYSTEM\CurrentControlSet\Control\Lsa", "value_name": "TurnOffAnonymousBlock", "expected_value": 1, "value_type": "DWORD"},
            {"control_id": "CIS-2.3.10.12", "control_name": "Anonymous SAM Enumeration Disabled", "category": "Network", "frameworks": "CIS", "severity": "High", "description": "Prevents anonymous enumeration of SAM accounts", "registry_hive": winreg.HKEY_LOCAL_MACHINE, "registry_path": r"SYSTEM\CurrentControlSet\Control\Lsa", "value_name": "RestrictAnonymousSAM", "expected_value": 1, "value_type": "DWORD"},
            {"control_id": "CIS-2.3.10.13", "control_name": "Anonymous Shares Enumeration Disabled", "category": "Network", "frameworks": "CIS", "severity": "High", "description": "Prevents anonymous enumeration of shares", "registry_hive": winreg.HKEY_LOCAL_MACHINE, "registry_path": r"SYSTEM\CurrentControlSet\Control\Lsa", "value_name": "RestrictAnonymous", "expected_value": 1, "value_type": "DWORD"},
            
            # Audit & Logging (3 controls)
            {"control_id": "CIS-17.1.1_E8-L01_PCI-10.2", "control_name": "Audit Policy Subcategory Override", "category": "Audit", "frameworks": "CIS,Essential8,PCI-DSS", "severity": "High", "description": "Allows audit subcategories to override audit categories", "registry_hive": winreg.HKEY_LOCAL_MACHINE, "registry_path": r"SYSTEM\CurrentControlSet\Control\Lsa", "value_name": "SCENoApplyLegacyAuditPolicy", "expected_value": 1, "value_type": "DWORD"},
            {"control_id": "PCI-10.5.1", "control_name": "Security Event Log Retention", "category": "Audit", "frameworks": "PCI-DSS", "severity": "Medium", "description": "Enables security event log retention", "registry_hive": winreg.HKEY_LOCAL_MACHINE, "registry_path": r"SYSTEM\CurrentControlSet\Services\Eventlog\Security", "value_name": "Retention", "expected_value": 0, "value_type": "DWORD"},
            {"control_id": "PCI-10.5.1_CIS-17.2.1", "control_name": "Security Event Log Max Size", "category": "Audit", "frameworks": "PCI-DSS,CIS", "severity": "Medium", "description": "Sets minimum security event log size to 192MB", "registry_hive": winreg.HKEY_LOCAL_MACHINE, "registry_path": r"SYSTEM\CurrentControlSet\Services\Eventlog\Security", "value_name": "MaxSize", "expected_value": 196608, "value_type": "DWORD", "comparison": "greater_equal"},
            
            # Remote Access (4 controls)
            {"control_id": "CIS-18.9.65.2.2_PCI-2.2.4", "control_name": "RDP Encryption Level", "category": "RemoteAccess", "frameworks": "CIS,PCI-DSS", "severity": "High", "description": "Requires high encryption level for RDP", "registry_hive": winreg.HKEY_LOCAL_MACHINE, "registry_path": r"SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services", "value_name": "MinEncryptionLevel", "expected_value": 3, "value_type": "DWORD"},
            {"control_id": "CIS-18.9.65.3.3.1", "control_name": "RDP Network Level Authentication", "category": "RemoteAccess", "frameworks": "CIS", "severity": "High", "description": "Requires Network Level Authentication for RDP", "registry_hive": winreg.HKEY_LOCAL_MACHINE, "registry_path": r"SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services", "value_name": "UserAuthentication", "expected_value": 1, "value_type": "DWORD"},
            {"control_id": "CIS-18.9.65.3.3.2", "control_name": "RDP Security Layer", "category": "RemoteAccess", "frameworks": "CIS", "severity": "High", "description": "Requires SSL/TLS for RDP", "registry_hive": winreg.HKEY_LOCAL_MACHINE, "registry_path": r"SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services", "value_name": "SecurityLayer", "expected_value": 2, "value_type": "DWORD"},
            {"control_id": "CIS-18.9.65.3.9.1", "control_name": "RDP Session Timeout", "category": "RemoteAccess", "frameworks": "CIS", "severity": "Medium", "description": "Sets timeout for disconnected RDP sessions to 1 minute", "registry_hive": winreg.HKEY_LOCAL_MACHINE, "registry_path": r"SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services", "value_name": "MaxDisconnectionTime", "expected_value": 60000, "value_type": "DWORD", "comparison": "less_equal"},
            
            # System Hardening (10 controls)
            {"control_id": "CIS-18.9.8.1_E8-H03", "control_name": "AutoPlay Disabled", "category": "SystemHardening", "frameworks": "CIS,Essential8", "severity": "Medium", "description": "Disables AutoPlay for all drives", "registry_hive": winreg.HKEY_LOCAL_MACHINE, "registry_path": r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer", "value_name": "NoDriveTypeAutoRun", "expected_value": 255, "value_type": "DWORD"},
            {"control_id": "CIS-18.9.8.2_E8-H04", "control_name": "AutoPlay Default Behavior", "category": "SystemHardening", "frameworks": "CIS,Essential8", "severity": "Medium", "description": "Sets AutoPlay to take no action", "registry_hive": winreg.HKEY_LOCAL_MACHINE, "registry_path": r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer", "value_name": "NoAutorun", "expected_value": 1, "value_type": "DWORD"},
            {"control_id": "CIS-18.9.8.3_E8-H05", "control_name": "AutoRun Disabled", "category": "SystemHardening", "frameworks": "CIS,Essential8", "severity": "Medium", "description": "Disables AutoRun for all drives", "registry_hive": winreg.HKEY_LOCAL_MACHINE, "registry_path": r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer", "value_name": "NoDriveTypeAutoRun", "expected_value": 255, "value_type": "DWORD"},
            {"control_id": "CIS-2.3.7.7", "control_name": "Screen Saver Grace Period", "category": "SystemHardening", "frameworks": "CIS", "severity": "Low", "description": "Sets screen saver grace period to 5 seconds or less", "registry_hive": winreg.HKEY_LOCAL_MACHINE, "registry_path": r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", "value_name": "ScreenSaverGracePeriod", "expected_value": 5, "value_type": "DWORD", "comparison": "less_equal"},
            {"control_id": "CIS-18.9.47.5.1", "control_name": "WinRM Client Basic Auth Disabled", "category": "SystemHardening", "frameworks": "CIS", "severity": "High", "description": "Disables basic authentication for WinRM client", "registry_hive": winreg.HKEY_LOCAL_MACHINE, "registry_path": r"SOFTWARE\Policies\Microsoft\Windows\WinRM\Client", "value_name": "AllowBasic", "expected_value": 0, "value_type": "DWORD"},
            {"control_id": "CIS-18.9.47.11.1", "control_name": "WinRM Service Basic Auth Disabled", "category": "SystemHardening", "frameworks": "CIS", "severity": "High", "description": "Disables basic authentication for WinRM service", "registry_hive": winreg.HKEY_LOCAL_MACHINE, "registry_path": r"SOFTWARE\Policies\Microsoft\Windows\WinRM\Service", "value_name": "AllowBasic", "expected_value": 0, "value_type": "DWORD"},
            {"control_id": "CIS-18.5.4.1", "control_name": "NetBIOS Node Type", "category": "SystemHardening", "frameworks": "CIS", "severity": "Medium", "description": "Sets NetBIOS node type to P-node (peer-to-peer)", "registry_hive": winreg.HKEY_LOCAL_MACHINE, "registry_path": r"SYSTEM\CurrentControlSet\Services\NetBT\Parameters", "value_name": "NodeType", "expected_value": 2, "value_type": "DWORD"},
            {"control_id": "CIS-18.9.30.2", "control_name": "Windows Installer Elevated Install Disabled", "category": "SystemHardening", "frameworks": "CIS", "severity": "High", "description": "Prevents users from elevating privileges during installs", "registry_hive": winreg.HKEY_LOCAL_MACHINE, "registry_path": r"SOFTWARE\Policies\Microsoft\Windows\Installer", "value_name": "AlwaysInstallElevated", "expected_value": 0, "value_type": "DWORD"},
            {"control_id": "CIS-18.1.1.1", "control_name": "Removable Storage Driver Installation Prevented", "category": "SystemHardening", "frameworks": "CIS", "severity": "Medium", "description": "Prevents automatic driver installation for removable storage", "registry_hive": winreg.HKEY_LOCAL_MACHINE, "registry_path": r"SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions", "value_name": "DenyRemovableDevices", "expected_value": 1, "value_type": "DWORD"},
            {"control_id": "CIS-2.3.7.8", "control_name": "Machine Inactivity Limit", "category": "SystemHardening", "frameworks": "CIS", "severity": "Medium", "description": "Sets machine inactivity limit to 900 seconds or less", "registry_hive": winreg.HKEY_LOCAL_MACHINE, "registry_path": r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "value_name": "InactivityTimeoutSecs", "expected_value": 900, "value_type": "DWORD", "comparison": "less_equal"},
        ]

    def _read_registry_value(self, hive: int, path: str, value_name: str) -> Optional[Any]:
        """Read a value from Windows Registry"""
        try:
            key = winreg.OpenKey(hive, path, 0, winreg.KEY_READ)
            value, _ = winreg.QueryValueEx(key, value_name)
            winreg.CloseKey(key)
            return value
        except FileNotFoundError:
            self.logger.debug(f"Registry path not found: {path}\\{value_name}")
            return None
        except PermissionError:
            self.logger.error(f"Permission denied reading: {path}\\{value_name}")
            return None
        except Exception as e:
            self.logger.error(f"Error reading registry {path}\\{value_name}: {str(e)}")
            return None

    def _check_compliance(self, control: Dict[str, Any]) -> Dict[str, Any]:
        """Check compliance for a single control"""
        current_value = self._read_registry_value(
            control["registry_hive"],
            control["registry_path"],
            control["value_name"]
        )
        
        result = {
            "control_id": control["control_id"],
            "control_name": control["control_name"],
            "category": control["category"],
            "frameworks": control["frameworks"],
            "severity": control["severity"],
            "description": control["description"],
            "registry_path": f"HKLM\\{control['registry_path']}",
            "registry_value": control["value_name"],
            "expected_value": str(control["expected_value"]),
            "current_value": str(current_value) if current_value is not None else "NOT_CONFIGURED",
            "compliant": False,
            "status": -1
        }
        
        if current_value is None:
            result["status"] = -1
            result["compliant"] = False
        else:
            comparison = control.get("comparison", "equal")
            
            if comparison == "equal":
                result["compliant"] = (current_value == control["expected_value"])
            elif comparison == "greater_equal":
                result["compliant"] = (current_value >= control["expected_value"])
            elif comparison == "less_equal":
                result["compliant"] = (current_value <= control["expected_value"])
            
            result["status"] = 1 if result["compliant"] else 0
        
        return result

    def _report_control_metrics(self, result: Dict[str, Any]):
        """Report metrics for a single control using Extension SDK"""
        try:
            dimensions = {
                'control_id': result['control_id'],
                'control_name': result['control_name'],
                'control_category': result['category'],
                'control_frameworks': result['frameworks'],
                'severity': result['severity'],
                'registry_path': result['registry_path'],
                'registry_value': result['registry_value'],
                'expected_value': result['expected_value'],
                'current_value': result['current_value'],
                'description': result['description']
            }
            
            # Report compliance status
            self.report_metric(
                key="windows.security.compliance.status",
                value=result['status'],
                dimensions=dimensions
            )
            
            # Report actual value (if available)
            value_to_report = -1
            if result['current_value'] != "NOT_CONFIGURED":
                try:
                    value_to_report = int(result['current_value'])
                except (ValueError, TypeError):
                    value_to_report = -1
            
            self.report_metric(
                key="windows.security.compliance.value",
                value=value_to_report,
                dimensions=dimensions
            )
            
        except Exception as e:
            self.logger.error(f"Error reporting metrics: {e}", exc_info=True)


def main():
    """Entry point for the extension"""
    ComplianceExtension().run()


if __name__ == '__main__':
    main()
