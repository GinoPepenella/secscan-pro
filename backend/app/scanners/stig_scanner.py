import asyncio
import json
import subprocess
from typing import Dict, List, Optional, Any
from pathlib import Path
from loguru import logger
from app.core.config import settings
from app.scanners.ssh_manager import SSHManager
from datetime import datetime
import re


class STIGScanner:
    """Scanner for STIG compliance checks."""

    def __init__(self, stig_path: str = None):
        self.stig_path = stig_path or settings.STIG_SCANNER_PATH
        self.stig_script = Path(self.stig_path) / "Evaluate-STIG.ps1"
        self.bash_wrapper = Path(self.stig_path) / "Evaluate-STIG_Bash.sh"

    async def scan_local(
        self,
        output_format: str = "JSON",
        select_stig: Optional[List[str]] = None,
        exclude_stig: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Run STIG scan on local system."""
        logger.info("Starting local STIG scan")

        try:
            # Build command
            cmd = ["sudo", str(self.bash_wrapper)]

            # Add output format
            cmd.extend(["--Output", "Console", "--JSON"])

            # Add STIG selection
            if select_stig:
                cmd.extend(["--SelectSTIG", ",".join(select_stig)])
            if exclude_stig:
                cmd.extend(["--ExcludeSTIG", ",".join(exclude_stig)])

            # Set timeout
            cmd.extend(["--VulnTimeout", str(settings.VULN_TIMEOUT)])

            logger.debug(f"Running command: {' '.join(cmd)}")

            # Execute scan
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=self.stig_path
            )

            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=settings.DEFAULT_SCAN_TIMEOUT
            )

            if process.returncode != 0:
                logger.error(f"STIG scan failed: {stderr.decode()}")
                return {
                    "success": False,
                    "error": stderr.decode(),
                    "findings": []
                }

            # Parse JSON output
            output = stdout.decode()
            findings = self._parse_stig_output(output)

            return {
                "success": True,
                "findings": findings,
                "total_checks": len(findings),
                "error": None
            }

        except asyncio.TimeoutError:
            logger.error("STIG scan timed out")
            return {
                "success": False,
                "error": "Scan timed out",
                "findings": []
            }
        except Exception as e:
            logger.error(f"STIG scan failed: {str(e)}")
            return {
                "success": False,
                "error": str(e),
                "findings": []
            }

    async def scan_remote(
        self,
        ssh_manager: SSHManager,
        output_format: str = "JSON",
        select_stig: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Run STIG scan on remote system via SSH."""
        logger.info(f"Starting remote STIG scan on {ssh_manager.host}")

        try:
            # Check if STIG scanner exists on remote system
            check_result = await ssh_manager.execute_command(
                f"test -f {self.stig_path}/Evaluate-STIG_Bash.sh && echo 'exists'"
            )

            if "exists" not in check_result["stdout"]:
                return {
                    "success": False,
                    "error": f"STIG scanner not found on remote system at {self.stig_path}",
                    "findings": []
                }

            # Build command
            cmd_parts = [str(self.bash_wrapper), "--Output", "Console", "--JSON"]

            if select_stig:
                cmd_parts.extend(["--SelectSTIG", ",".join(select_stig)])

            cmd_parts.extend(["--VulnTimeout", str(settings.VULN_TIMEOUT)])

            command = " ".join(cmd_parts)

            # Execute scan with sudo
            result = await ssh_manager.execute_command(
                command,
                use_sudo=True,
                sudo_password=ssh_manager.password
            )

            if not result["success"]:
                logger.error(f"Remote STIG scan failed: {result['stderr']}")
                return {
                    "success": False,
                    "error": result["stderr"],
                    "findings": []
                }

            # Parse output
            findings = self._parse_stig_output(result["stdout"])

            return {
                "success": True,
                "findings": findings,
                "total_checks": len(findings),
                "error": None
            }

        except Exception as e:
            logger.error(f"Remote STIG scan failed: {str(e)}")
            return {
                "success": False,
                "error": str(e),
                "findings": []
            }

    def _parse_stig_output(self, output: str) -> List[Dict[str, Any]]:
        """Parse STIG scan JSON output."""
        findings = []

        try:
            # Try to parse as JSON
            if output.strip().startswith("{") or output.strip().startswith("["):
                data = json.loads(output)

                # Handle different output formats
                if isinstance(data, list):
                    scan_results = data
                elif isinstance(data, dict):
                    scan_results = data.get("Findings", [])
                else:
                    scan_results = []

                for item in scan_results:
                    finding = self._parse_finding(item)
                    if finding:
                        findings.append(finding)

        except json.JSONDecodeError:
            logger.warning("Failed to parse STIG output as JSON, attempting text parsing")
            # Fallback to text parsing if needed
            findings = self._parse_text_output(output)

        return findings

    def _parse_finding(self, item: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Parse individual STIG finding."""
        try:
            # Map severity
            severity_map = {
                "high": "high",
                "medium": "medium",
                "low": "low",
                "cat1": "critical",
                "cat2": "high",
                "cat3": "medium"
            }

            raw_severity = item.get("Severity", "").lower()
            severity = severity_map.get(raw_severity, "medium")

            # Determine status
            status = item.get("Status", "Open")
            finding_status = "open"
            if status.lower() in ["notafinding", "not_a_finding"]:
                finding_status = "closed"
            elif status.lower() in ["notapplicable", "not_applicable"]:
                finding_status = "not_applicable"

            return {
                "finding_type": "stig",
                "vuln_id": item.get("VulnID", ""),
                "stig_id": item.get("STIGID", ""),
                "rule_id": item.get("RuleID", ""),
                "title": item.get("RuleTitle", ""),
                "description": item.get("Discussion", ""),
                "severity": severity,
                "group_title": item.get("GroupTitle", ""),
                "check_content": item.get("CheckText", ""),
                "fix_text": item.get("FixText", ""),
                "finding_details": item.get("FindingDetails", ""),
                "status": finding_status,
                "can_auto_remediate": self._check_auto_remediate(item.get("FixText", ""))
            }

        except Exception as e:
            logger.error(f"Failed to parse finding: {str(e)}")
            return None

    def _parse_text_output(self, output: str) -> List[Dict[str, Any]]:
        """Fallback parser for text output."""
        # Basic text parsing - implement as needed
        return []

    def _check_auto_remediate(self, fix_text: str) -> bool:
        """Determine if a finding can be auto-remediated."""
        if not fix_text:
            return False

        # Simple heuristic: Check if fix involves simple config changes
        auto_remediate_keywords = [
            "set",
            "edit",
            "configure",
            "modify",
            "update",
            "change"
        ]

        manual_keywords = [
            "manual",
            "consult",
            "contact",
            "review",
            "assess",
            "determine"
        ]

        fix_lower = fix_text.lower()

        has_auto = any(keyword in fix_lower for keyword in auto_remediate_keywords)
        has_manual = any(keyword in fix_lower for keyword in manual_keywords)

        return has_auto and not has_manual

    async def get_available_stigs(self) -> List[str]:
        """Get list of available STIG profiles."""
        try:
            cmd = ["sudo", str(self.bash_wrapper), "--ListSupportedProducts"]

            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=self.stig_path
            )

            stdout, stderr = await process.communicate()

            if process.returncode == 0:
                output = stdout.decode()
                # Parse the list of supported products
                stigs = [line.strip() for line in output.split("\n") if line.strip()]
                return stigs
            else:
                logger.error(f"Failed to get STIG list: {stderr.decode()}")
                return []

        except Exception as e:
            logger.error(f"Failed to get STIG list: {str(e)}")
            return []
