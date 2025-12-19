import asyncio
from typing import List, Dict, Optional, Any
from loguru import logger
from app.scanners.ssh_manager import SSHManager
from app.models.scan import Finding, SudoMode
from app.db.base import AsyncSessionLocal
from sqlalchemy import select
from datetime import datetime
import re


class RemediationEngine:
    """Engine for automated remediation of security findings."""

    def __init__(self):
        self.remediation_templates = self._load_remediation_templates()

    def _load_remediation_templates(self) -> Dict[str, Dict[str, Any]]:
        """Load remediation templates for common findings."""
        return {
            # STIG remediations
            "V-230221": {
                "description": "Set password minimum length",
                "script": "sed -i 's/PASS_MIN_LEN.*/PASS_MIN_LEN    15/' /etc/login.defs",
                "requires_reboot": False,
                "risk_level": "low"
            },
            "V-230222": {
                "description": "Set password minimum age",
                "script": "sed -i 's/PASS_MIN_DAYS.*/PASS_MIN_DAYS   1/' /etc/login.defs",
                "requires_reboot": False,
                "risk_level": "low"
            },
            "V-230223": {
                "description": "Set password maximum age",
                "script": "sed -i 's/PASS_MAX_DAYS.*/PASS_MAX_DAYS   60/' /etc/login.defs",
                "requires_reboot": False,
                "risk_level": "low"
            },
            "V-230345": {
                "description": "Enable SELinux",
                "script": "sed -i 's/SELINUX=.*/SELINUX=enforcing/' /etc/selinux/config",
                "requires_reboot": True,
                "risk_level": "high"
            },
            "V-230368": {
                "description": "Configure firewalld to start automatically",
                "script": "systemctl enable firewalld && systemctl start firewalld",
                "requires_reboot": False,
                "risk_level": "medium"
            },
            # Add more templates as needed
        }

    async def remediate_findings(
        self,
        finding_ids: List[int],
        ssh_manager: Optional[SSHManager] = None,
        dry_run: bool = False
    ) -> Dict[str, Any]:
        """
        Remediate multiple findings.

        Args:
            finding_ids: List of finding IDs to remediate
            ssh_manager: SSH connection for remote remediation
            dry_run: If True, only simulate remediation

        Returns:
            Dict with remediation results
        """
        results = {
            "success": [],
            "failed": [],
            "skipped": [],
            "dry_run": dry_run
        }

        async with AsyncSessionLocal() as session:
            for finding_id in finding_ids:
                # Get finding
                result = await session.execute(
                    select(Finding).where(Finding.id == finding_id)
                )
                finding = result.scalar_one_or_none()

                if not finding:
                    results["skipped"].append({
                        "finding_id": finding_id,
                        "reason": "Finding not found"
                    })
                    continue

                if not finding.can_auto_remediate:
                    results["skipped"].append({
                        "finding_id": finding_id,
                        "vuln_id": finding.vuln_id,
                        "reason": "Cannot auto-remediate"
                    })
                    continue

                # Attempt remediation
                try:
                    remediation_result = await self._remediate_finding(
                        finding,
                        ssh_manager,
                        dry_run
                    )

                    if remediation_result["success"]:
                        results["success"].append({
                            "finding_id": finding_id,
                            "vuln_id": finding.vuln_id,
                            "output": remediation_result["output"]
                        })

                        if not dry_run:
                            # Update finding status
                            finding.remediation_status = "remediated"
                            finding.remediated_at = datetime.utcnow()
                            finding.status = "remediated"
                            await session.commit()
                    else:
                        results["failed"].append({
                            "finding_id": finding_id,
                            "vuln_id": finding.vuln_id,
                            "error": remediation_result["error"]
                        })

                except Exception as e:
                    logger.error(f"Remediation failed for finding {finding_id}: {str(e)}")
                    results["failed"].append({
                        "finding_id": finding_id,
                        "vuln_id": finding.vuln_id if finding else None,
                        "error": str(e)
                    })

        return results

    async def _remediate_finding(
        self,
        finding: Finding,
        ssh_manager: Optional[SSHManager],
        dry_run: bool
    ) -> Dict[str, Any]:
        """Remediate a single finding."""

        # Check if we have a template for this finding
        vuln_id = finding.vuln_id
        template = self.remediation_templates.get(vuln_id)

        if not template:
            # Try to generate remediation script from fix_text
            script = self._generate_script_from_fix_text(finding.fix_text)
            if not script:
                return {
                    "success": False,
                    "error": "No remediation template available"
                }
            template = {
                "script": script,
                "requires_reboot": False,
                "risk_level": "medium"
            }

        logger.info(f"Remediating {vuln_id}: {template.get('description', 'Unknown')}")

        if dry_run:
            return {
                "success": True,
                "output": f"[DRY RUN] Would execute: {template['script']}"
            }

        # Execute remediation
        script = template["script"]

        if ssh_manager:
            # Remote remediation
            result = await ssh_manager.execute_command(
                script,
                use_sudo=True
            )

            if result["success"]:
                return {
                    "success": True,
                    "output": result["stdout"],
                    "requires_reboot": template.get("requires_reboot", False)
                }
            else:
                return {
                    "success": False,
                    "error": result["stderr"]
                }
        else:
            # Local remediation
            try:
                process = await asyncio.create_subprocess_shell(
                    f"sudo {script}",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )

                stdout, stderr = await process.communicate()

                if process.returncode == 0:
                    return {
                        "success": True,
                        "output": stdout.decode(),
                        "requires_reboot": template.get("requires_reboot", False)
                    }
                else:
                    return {
                        "success": False,
                        "error": stderr.decode()
                    }

            except Exception as e:
                return {
                    "success": False,
                    "error": str(e)
                }

    def _generate_script_from_fix_text(self, fix_text: str) -> Optional[str]:
        """Attempt to generate remediation script from STIG fix text."""
        if not fix_text:
            return None

        # Look for common patterns in fix text
        patterns = {
            # Config file edits
            r'edit.*?([/\w.-]+).*?set.*?(\w+)\s*=\s*([^\s]+)': lambda m: f"sed -i 's/^{m.group(2)}.*/{m.group(2)}={m.group(3)}/' {m.group(1)}",

            # Service enable/start
            r'enable.*?(\w+).*?service': lambda m: f"systemctl enable {m.group(1)} && systemctl start {m.group(1)}",

            # Service disable/stop
            r'disable.*?(\w+).*?service': lambda m: f"systemctl disable {m.group(1)} && systemctl stop {m.group(1)}",

            # Package installation
            r'install.*?package.*?(\w+)': lambda m: f"yum install -y {m.group(1)} || apt-get install -y {m.group(1)}",

            # Package removal
            r'remove.*?package.*?(\w+)': lambda m: f"yum remove -y {m.group(1)} || apt-get remove -y {m.group(1)}",
        }

        for pattern, script_gen in patterns.items():
            match = re.search(pattern, fix_text, re.IGNORECASE)
            if match:
                try:
                    return script_gen(match)
                except:
                    continue

        return None

    async def get_remediation_preview(self, finding_id: int) -> Dict[str, Any]:
        """Get a preview of what remediation would do."""
        async with AsyncSessionLocal() as session:
            result = await session.execute(
                select(Finding).where(Finding.id == finding_id)
            )
            finding = result.scalar_one_or_none()

            if not finding:
                return {"error": "Finding not found"}

            if not finding.can_auto_remediate:
                return {
                    "can_remediate": False,
                    "reason": "This finding requires manual remediation"
                }

            template = self.remediation_templates.get(finding.vuln_id)

            if not template:
                script = self._generate_script_from_fix_text(finding.fix_text)
                if not script:
                    return {
                        "can_remediate": False,
                        "reason": "No remediation template available"
                    }
                template = {
                    "script": script,
                    "requires_reboot": False,
                    "risk_level": "medium",
                    "description": "Auto-generated from fix text"
                }

            return {
                "can_remediate": True,
                "vuln_id": finding.vuln_id,
                "description": template.get("description", ""),
                "script": template["script"],
                "requires_reboot": template.get("requires_reboot", False),
                "risk_level": template.get("risk_level", "medium")
            }
