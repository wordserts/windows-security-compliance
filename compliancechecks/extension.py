"""
Windows Security Compliance Extension v2.0
Monitors Windows security configurations against CIS, Essential 8, and PCI-DSS
Expanded to ~100 comprehensive security controls
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

# Import controls from controls module
from .controls import get_all_controls, get_control_counts


class ComplianceExtension(Extension):
    """Extension to monitor Windows security compliance"""

    def initialize(self):
        """Initialize the extension"""
        control_counts = get_control_counts()
        self.logger.info("Initializing Windows Security Compliance Extension v2.0")
        self.logger.info(f"Monitoring {control_counts['TOTAL']} security controls across CIS, Essential 8, and PCI-DSS")
        self.logger.info(f"Control breakdown by category:")
        for category, count in control_counts.items():
            if category != 'TOTAL':
                self.logger.info(f"  - {category}: {count} controls")

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
        """Get all compliance control definitions from controls module"""
        return get_all_controls()

    def _read_registry_value(self, hive, path: str, value_name: str) -> Any:
        """Read a value from Windows registry"""
        try:
            with winreg.OpenKey(hive, path, 0, winreg.KEY_READ) as key:
                value, reg_type = winreg.QueryValueEx(key, value_name)
                return value
        except FileNotFoundError:
            return None
        except PermissionError:
            self.logger.warning(f"Permission denied reading {path}\\{value_name}")
            return None
        except Exception as e:
            self.logger.warning(f"Error reading registry {path}\\{value_name}: {str(e)}")
            return None

    def _check_compliance(self, control: Dict) -> Dict:
        """Check a single control for compliance"""
        result = {
            "control_id": control["control_id"],
            "control_name": control["control_name"],
            "category": control["category"],
            "frameworks": control["frameworks"],
            "severity": control["severity"],
            "description": control["description"],
            "registry_hive": str(control["registry_hive"]),
            "registry_path": control["registry_path"],
            "value_name": control["value_name"],
            "expected_value": control["expected_value"],
            "current_value": None,
            "status": -1  # -1 = not configured, 0 = non-compliant, 1 = compliant
        }
        
        # Read current value
        current_value = self._read_registry_value(
            control["registry_hive"],
            control["registry_path"],
            control["value_name"]
        )
        
        result["current_value"] = current_value
        
        # Check if value exists
        if current_value is None:
            result["status"] = -1  # Not configured
            return result
        
        # Determine compliance based on comparison type
        comparison = control.get("comparison", "eq")  # Default to equality
        expected = control["expected_value"]
        
        try:
            # Convert values for comparison if needed
            if isinstance(expected, int) and isinstance(current_value, str):
                try:
                    current_value = int(current_value)
                except ValueError:
                    result["status"] = 0
                    return result
            
            # Perform comparison
            if comparison == "eq":
                is_compliant = current_value == expected
            elif comparison == "ne":
                is_compliant = current_value != expected
            elif comparison == "gte":
                is_compliant = current_value >= expected
            elif comparison == "lte":
                is_compliant = current_value <= expected
            elif comparison == "gt":
                is_compliant = current_value > expected
            elif comparison == "lt":
                is_compliant = current_value < expected
            else:
                self.logger.warning(f"Unknown comparison type: {comparison}, defaulting to equality")
                is_compliant = current_value == expected
            
            result["status"] = 1 if is_compliant else 0
            
        except Exception as e:
            self.logger.error(f"Error comparing values for {control['control_id']}: {str(e)}")
            result["status"] = 0
        
        return result

    def _report_control_metrics(self, result: Dict):
        """Report metrics for a single control using Extension SDK"""
        try:
            # Report compliance status metric
            self.report_metric(
                key="windows.security.compliance.status",
                value=result["status"],
                dimensions={
                    "control_id": result["control_id"],
                    "control_name": result["control_name"],
                    "control_category": result["category"],
                    "severity": result["severity"],
                    "control_frameworks": result["frameworks"],
                    "current_value": str(result["current_value"]) if result["current_value"] is not None else "NOT_CONFIGURED",
                    "expected_value": str(result["expected_value"]),
                    "registry_path": result["registry_path"]
                }
            )
            
            # Also report the raw value as a separate metric if configured
            if result["current_value"] is not None and isinstance(result["current_value"], (int, float)):
                self.report_metric(
                    key="windows.security.compliance.value",
                    value=float(result["current_value"]),
                    dimensions={
                        "control_id": result["control_id"],
                        "control_name": result["control_name"],
                        "control_category": result["category"]
                    }
                )
                
        except Exception as e:
            self.logger.error(f"Error reporting metrics for {result['control_id']}: {str(e)}")
