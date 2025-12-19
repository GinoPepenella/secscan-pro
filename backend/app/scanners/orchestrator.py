import asyncio
from typing import List, Dict, Optional, Any
from loguru import logger
from app.scanners.ssh_manager import SSHManager
from app.scanners.stig_scanner import STIGScanner
from app.scanners.vuln_scanner import VulnerabilityScanner
from app.models.scan import Scan, Finding, ScanType, ScanStatus, AuthMethod, SudoMode
from app.db.base import AsyncSessionLocal
from sqlalchemy import select, update
from datetime import datetime
import ipaddress
import socket


class ScanOrchestrator:
    """Orchestrates security scans across multiple targets."""

    def __init__(self):
        self.stig_scanner = STIGScanner()
        self.vuln_scanner = VulnerabilityScanner()

    async def execute_scan(self, scan_id: int):
        """Execute a scan and update database with results."""
        async with AsyncSessionLocal() as session:
            # Get scan configuration
            result = await session.execute(select(Scan).where(Scan.id == scan_id))
            scan = result.scalar_one_or_none()

            if not scan:
                logger.error(f"Scan {scan_id} not found")
                return

            try:
                # Update scan status
                scan.status = ScanStatus.RUNNING
                scan.started_at = datetime.utcnow()
                await session.commit()

                logger.info(f"Starting scan {scan_id}: {scan.name}")

                all_findings = []

                # Process each target
                targets = scan.targets or []
                for target in targets:
                    target_findings = await self._scan_target(scan, target)
                    all_findings.extend(target_findings)

                # Save findings to database
                for finding_data in all_findings:
                    finding = Finding(
                        scan_id=scan.id,
                        **finding_data
                    )
                    session.add(finding)

                # Calculate statistics
                scan.total_checks = len(all_findings)
                scan.passed_checks = sum(1 for f in all_findings if f.get("status") == "closed")
                scan.failed_checks = sum(1 for f in all_findings if f.get("status") == "open")
                scan.not_applicable = sum(1 for f in all_findings if f.get("status") == "not_applicable")

                # Calculate risk metrics
                risk_metrics = self._calculate_risk_metrics(all_findings)
                scan.risk_score = risk_metrics["risk_score"]
                scan.critical_findings = risk_metrics["critical"]
                scan.high_findings = risk_metrics["high"]
                scan.medium_findings = risk_metrics["medium"]
                scan.low_findings = risk_metrics["low"]

                # Mark as completed
                scan.status = ScanStatus.COMPLETED
                scan.completed_at = datetime.utcnow()

                await session.commit()

                logger.info(f"Scan {scan_id} completed successfully with {len(all_findings)} findings")

            except Exception as e:
                logger.error(f"Scan {scan_id} failed: {str(e)}")
                scan.status = ScanStatus.FAILED
                scan.error_message = str(e)
                scan.completed_at = datetime.utcnow()
                await session.commit()

    async def _scan_target(self, scan: Scan, target: str) -> List[Dict[str, Any]]:
        """Scan a single target."""
        logger.info(f"Scanning target: {target}")

        findings = []

        try:
            # Resolve target to IP if it's a hostname
            target_ip = self._resolve_target(target)

            if scan.use_ssh:
                # SSH-based scanning
                findings = await self._scan_via_ssh(scan, target, target_ip)
            else:
                # Config file scanning
                findings = await self._scan_config_files(scan, target)

        except Exception as e:
            logger.error(f"Failed to scan target {target}: {str(e)}")
            # Add error as finding
            findings.append({
                "finding_type": "error",
                "vuln_id": "SCAN_ERROR",
                "title": f"Scan Error for {target}",
                "description": str(e),
                "severity": "high",
                "target_host": target,
                "target_ip": target_ip,
                "status": "open",
                "finding_details": f"Failed to scan target: {str(e)}",
                "can_auto_remediate": False
            })

        return findings

    async def _scan_via_ssh(
        self,
        scan: Scan,
        target: str,
        target_ip: Optional[str]
    ) -> List[Dict[str, Any]]:
        """Scan target via SSH connection."""
        findings = []

        # Create SSH manager
        ssh_manager = SSHManager(
            host=target,
            username=scan.ssh_username,
            password=None,  # TODO: Handle password storage securely
            port=scan.ssh_port,
            auth_method=scan.auth_method,
            sudo_mode=scan.sudo_mode
        )

        async with ssh_manager:
            # Run STIG scan if requested
            if scan.scan_type in [ScanType.STIG, ScanType.COMBINED]:
                stig_results = await self.stig_scanner.scan_remote(
                    ssh_manager,
                    select_stig=scan.stig_profiles
                )

                if stig_results["success"]:
                    for finding in stig_results["findings"]:
                        finding["target_host"] = target
                        finding["target_ip"] = target_ip
                        findings.append(finding)

            # Run vulnerability scan if requested
            if scan.scan_type in [ScanType.VULNERABILITY, ScanType.COMBINED]:
                # Get installed packages
                packages = await self.vuln_scanner.get_installed_packages(ssh_manager)

                # Get OS info
                os_result = await ssh_manager.execute_command("cat /etc/os-release")
                os_info = os_result["stdout"] if os_result["success"] else ""

                # Scan for vulnerabilities
                vuln_results = await self.vuln_scanner.scan_packages(packages, os_info)

                if vuln_results["success"]:
                    for finding in vuln_results["findings"]:
                        finding["target_host"] = target
                        finding["target_ip"] = target_ip
                        findings.append(finding)

        return findings

    async def _scan_config_files(
        self,
        scan: Scan,
        target: str
    ) -> List[Dict[str, Any]]:
        """Scan configuration files."""
        # TODO: Implement config file scanning
        logger.warning("Config file scanning not yet implemented")
        return []

    def _resolve_target(self, target: str) -> Optional[str]:
        """Resolve hostname to IP address."""
        try:
            # Check if already an IP
            ipaddress.ip_address(target)
            return target
        except ValueError:
            # Try to resolve hostname
            try:
                ip = socket.gethostbyname(target)
                return ip
            except socket.gaierror:
                logger.warning(f"Failed to resolve {target}")
                return None

    def _calculate_risk_metrics(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Calculate risk score and metrics from findings."""
        severity_counts = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0
        }

        for finding in findings:
            severity = finding.get("severity", "low").lower()
            if severity in severity_counts:
                severity_counts[severity] += 1

        # Calculate weighted risk score (0-100)
        risk_score = (
            severity_counts["critical"] * 10 +
            severity_counts["high"] * 5 +
            severity_counts["medium"] * 2 +
            severity_counts["low"] * 0.5
        )

        # Normalize to 0-100 scale
        max_score = 100
        risk_score = min(risk_score, max_score)

        return {
            "risk_score": round(risk_score, 2),
            "critical": severity_counts["critical"],
            "high": severity_counts["high"],
            "medium": severity_counts["medium"],
            "low": severity_counts["low"]
        }

    async def test_ssh_connection(
        self,
        host: str,
        username: str,
        password: Optional[str] = None,
        private_key_path: Optional[str] = None,
        port: int = 22,
        auth_method: AuthMethod = AuthMethod.PASSWORD
    ) -> Dict[str, Any]:
        """Test SSH connection to target."""
        ssh_manager = SSHManager(
            host=host,
            username=username,
            password=password,
            private_key_path=private_key_path,
            port=port,
            auth_method=auth_method
        )

        return await ssh_manager.test_connection()
