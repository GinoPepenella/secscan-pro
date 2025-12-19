"""
SCC (SCAP Compliance Checker) Scanner

Integrates with DISA's SCAP Compliance Checker tool for automated
compliance scanning using SCAP benchmarks.
"""

import asyncio
import json
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Dict, List, Optional, Any
from loguru import logger
from app.core.config import settings


class SCCScanner:
    """
    Scanner for SCAP Compliance Checker (SCC) integration.
    Supports RHEL, Oracle Linux, SLES, and other SCAP benchmarks.
    """

    def __init__(self, scc_path: str = "/opt/scc"):
        self.scc_path = Path(scc_path)
        self.scc_binary = self.scc_path / "scc"
        self.content_path = self.scc_path / "Resources" / "Content" / "SCAP12_Content"

        if not self.scc_binary.exists():
            raise FileNotFoundError(f"SCC binary not found at {self.scc_binary}")

        logger.info(f"SCC Scanner initialized with path: {self.scc_path}")

    def discover_available_benchmarks(self) -> List[Dict[str, str]]:
        """
        Discover all available SCAP benchmarks in the SCC content directory.

        Returns:
            List of dicts with 'id', 'name', 'path', and 'version' for each benchmark
        """
        benchmarks = []

        if not self.content_path.exists():
            logger.warning(f"SCC content path not found: {self.content_path}")
            return benchmarks

        # Find all SCAP XML files
        for xml_file in self.content_path.glob("*.xml"):
            try:
                benchmark_info = self._parse_benchmark_metadata(xml_file)
                if benchmark_info:
                    benchmarks.append(benchmark_info)
            except Exception as e:
                logger.warning(f"Failed to parse benchmark {xml_file.name}: {str(e)}")

        logger.info(f"Discovered {len(benchmarks)} SCC benchmarks")
        return sorted(benchmarks, key=lambda x: x['name'])

    def _parse_benchmark_metadata(self, xml_path: Path) -> Optional[Dict[str, str]]:
        """Extract metadata from SCAP benchmark XML file."""
        try:
            # Extract info from filename (more reliable than parsing large XML)
            filename = xml_path.name

            # Parse filename like: U_RHEL_9_V2R5_STIG_SCAP_1-4_Benchmark-enhancedV7-signed.xml
            if "RHEL_9" in filename:
                name = "Red Hat Enterprise Linux 9"
                os_type = "rhel9"
            elif "RHEL_8" in filename:
                name = "Red Hat Enterprise Linux 8"
                os_type = "rhel8"
            elif "RHEL_7" in filename:
                name = "Red Hat Enterprise Linux 7"
                os_type = "rhel7"
            elif "Oracle_Linux_8" in filename:
                name = "Oracle Linux 8"
                os_type = "oracle8"
            elif "Oracle_Linux_7" in filename:
                name = "Oracle Linux 7"
                os_type = "oracle7"
            elif "SLES_15" in filename:
                name = "SUSE Linux Enterprise Server 15"
                os_type = "sles15"
            elif "SLES_12" in filename:
                name = "SUSE Linux Enterprise Server 12"
                os_type = "sles12"
            elif "Kubernetes" in filename:
                name = "Kubernetes"
                os_type = "kubernetes"
            elif "Firefox" in filename:
                name = "Mozilla Firefox"
                os_type = "firefox"
            elif "Cisco_IOS" in filename:
                name = "Cisco IOS-XE"
                os_type = "cisco"
            elif "TOSS" in filename:
                name = "Tri-Lab Operating System Stack (TOSS)"
                os_type = "toss"
            else:
                name = filename.replace("U_", "").replace("_STIG_SCAP_1-4_Benchmark-enhancedV", " v").split("-")[0]
                os_type = "unknown"

            # Extract version from filename
            import re
            version_match = re.search(r'V(\d+)R(\d+)', filename)
            version = f"V{version_match.group(1)}R{version_match.group(2)}" if version_match else "Unknown"

            return {
                "id": xml_path.stem,
                "name": name,
                "version": version,
                "path": str(xml_path),
                "os_type": os_type,
                "filename": filename
            }

        except Exception as e:
            logger.error(f"Error parsing benchmark metadata: {str(e)}")
            return None

    async def detect_os_and_select_benchmark(self, os_info: str) -> Optional[Dict[str, str]]:
        """
        Auto-detect the operating system and select appropriate SCAP benchmark.

        Args:
            os_info: Content from /etc/os-release or similar

        Returns:
            Benchmark info dict or None if no match
        """
        os_info_lower = os_info.lower()

        benchmarks = self.discover_available_benchmarks()

        # Detection logic based on os-release content
        if "red hat" in os_info_lower or "rhel" in os_info_lower:
            if "release 9" in os_info_lower or "version 9" in os_info_lower:
                return next((b for b in benchmarks if b['os_type'] == 'rhel9'), None)
            elif "release 8" in os_info_lower or "version 8" in os_info_lower:
                return next((b for b in benchmarks if b['os_type'] == 'rhel8'), None)
            elif "release 7" in os_info_lower or "version 7" in os_info_lower:
                return next((b for b in benchmarks if b['os_type'] == 'rhel7'), None)

        elif "oracle" in os_info_lower:
            if "release 8" in os_info_lower or "version 8" in os_info_lower:
                return next((b for b in benchmarks if b['os_type'] == 'oracle8'), None)
            elif "release 7" in os_info_lower or "version 7" in os_info_lower:
                return next((b for b in benchmarks if b['os_type'] == 'oracle7'), None)

        elif "suse" in os_info_lower or "sles" in os_info_lower:
            if "15" in os_info_lower:
                return next((b for b in benchmarks if b['os_type'] == 'sles15'), None)
            elif "12" in os_info_lower:
                return next((b for b in benchmarks if b['os_type'] == 'sles12'), None)

        logger.warning(f"Could not auto-detect SCAP benchmark for OS: {os_info[:100]}")
        return None

    async def scan_local(
        self,
        benchmark_path: Optional[str] = None,
        output_dir: str = "/tmp/scc_results"
    ) -> Dict[str, Any]:
        """
        Run SCC scan on the local system.

        Args:
            benchmark_path: Path to specific SCAP benchmark XML file
            output_dir: Directory to store scan results

        Returns:
            Dict with scan results and findings
        """
        logger.info(f"Starting local SCC scan")

        # Create output directory
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)

        # Build SCC command
        cmd = [
            "sudo",
            str(self.scc_binary),
            "-o", str(output_path)
        ]

        if benchmark_path:
            cmd.extend(["-c", benchmark_path])

        logger.debug(f"Executing SCC command: {' '.join(cmd)}")

        try:
            # Execute SCC (requires root)
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            stdout, stderr = await process.communicate()

            if process.returncode != 0:
                error_msg = stderr.decode() if stderr else "Unknown error"
                logger.error(f"SCC scan failed: {error_msg}")
                return {
                    "success": False,
                    "error": error_msg,
                    "findings": []
                }

            # Parse results
            results = await self._parse_scc_results(output_path)

            logger.info(f"SCC scan completed successfully with {len(results.get('findings', []))} findings")
            return results

        except Exception as e:
            logger.error(f"SCC scan execution failed: {str(e)}")
            return {
                "success": False,
                "error": str(e),
                "findings": []
            }

    async def _parse_scc_results(self, output_dir: Path) -> Dict[str, Any]:
        """
        Parse SCC output files and extract findings.

        SCC generates multiple output formats: XCCDF XML, HTML, CKL, etc.
        We'll parse the XCCDF results file.
        """
        findings = []

        # Look for XCCDF results file
        xccdf_files = list(output_dir.glob("*Results*.xml")) + list(output_dir.glob("*results*.xml"))

        if not xccdf_files:
            logger.warning(f"No XCCDF results file found in {output_dir}")
            return {
                "success": True,
                "findings": [],
                "summary": {
                    "total": 0,
                    "pass": 0,
                    "fail": 0,
                    "not_applicable": 0,
                    "not_checked": 0
                }
            }

        results_file = xccdf_files[0]
        logger.debug(f"Parsing SCC results from {results_file}")

        try:
            tree = ET.parse(results_file)
            root = tree.getroot()

            # Parse XCCDF namespace
            ns = {'xccdf': 'http://checklists.nist.gov/xccdf/1.2'}

            summary = {
                "total": 0,
                "pass": 0,
                "fail": 0,
                "not_applicable": 0,
                "not_checked": 0
            }

            # Extract rule results
            for rule_result in root.findall('.//xccdf:rule-result', ns):
                rule_id = rule_result.get('idref', '')
                result = rule_result.find('xccdf:result', ns)

                if result is None:
                    continue

                result_text = result.text.lower()
                summary["total"] += 1

                # Map XCCDF result to our finding format
                severity = self._map_severity(rule_id)

                if result_text == "pass":
                    summary["pass"] += 1
                    status = "closed"
                elif result_text == "fail":
                    summary["fail"] += 1
                    status = "open"
                elif result_text == "notapplicable":
                    summary["not_applicable"] += 1
                    status = "not_applicable"
                else:
                    summary["not_checked"] += 1
                    continue

                # Only add findings for failures
                if result_text == "fail":
                    finding = {
                        "finding_type": "scc",
                        "vuln_id": rule_id,
                        "title": f"SCAP Compliance Check: {rule_id}",
                        "description": f"SCAP compliance check failed for rule {rule_id}",
                        "severity": severity,
                        "status": status,
                        "can_auto_remediate": False,
                        "finding_details": f"Rule {rule_id} failed compliance check"
                    }
                    findings.append(finding)

            return {
                "success": True,
                "findings": findings,
                "summary": summary,
                "results_file": str(results_file)
            }

        except Exception as e:
            logger.error(f"Failed to parse SCC results: {str(e)}")
            return {
                "success": False,
                "error": str(e),
                "findings": []
            }

    def _map_severity(self, rule_id: str) -> str:
        """
        Map STIG rule ID to severity level.
        CAT I = Critical, CAT II = High, CAT III = Medium
        """
        # This is a simplified mapping - in production, parse the actual
        # severity from the benchmark XML or results
        if "SV-" in rule_id:
            # Default to high for STIG vulnerabilities
            return "high"
        return "medium"
