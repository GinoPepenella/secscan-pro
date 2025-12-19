import asyncio
import aiohttp
import nvdlib
from typing import Dict, List, Optional, Any
from loguru import logger
from app.core.config import settings
from datetime import datetime, timedelta
import re
from packaging import version as pkg_version


class VulnerabilityScanner:
    """Scanner for CVE vulnerabilities using NVD database."""

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or settings.NVD_API_KEY
        self.rate_limit = settings.NVD_RATE_LIMIT
        self.nvd_base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    async def scan_packages(
        self,
        packages: List[Dict[str, str]],
        os_info: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Scan installed packages for known vulnerabilities.

        Args:
            packages: List of dicts with 'name' and 'version'
            os_info: OS information for context

        Returns:
            Dict with scan results
        """
        logger.info(f"Scanning {len(packages)} packages for vulnerabilities")

        findings = []
        total_vulns = 0

        for package in packages:
            package_name = package.get("name", "")
            package_version = package.get("version", "")

            if not package_name or not package_version:
                continue

            # Search for CVEs related to this package
            vulns = await self._search_cves_for_package(package_name, package_version)

            for vuln in vulns:
                findings.append({
                    **vuln,
                    "affected_software": [{
                        "name": package_name,
                        "version": package_version
                    }]
                })
                total_vulns += 1

            # Rate limiting
            await asyncio.sleep(1.0 / self.rate_limit)

        return {
            "success": True,
            "findings": findings,
            "total_vulnerabilities": total_vulns,
            "packages_scanned": len(packages)
        }

    async def _search_cves_for_package(
        self,
        package_name: str,
        package_version: str
    ) -> List[Dict[str, Any]]:
        """Search NVD for CVEs affecting a specific package version."""
        findings = []

        try:
            # Use nvdlib to search for CVEs
            # Note: This is synchronous, so we run it in executor
            loop = asyncio.get_event_loop()

            def search_nvd():
                try:
                    # Search for recent CVEs (last 2 years)
                    end_date = datetime.now()
                    start_date = end_date - timedelta(days=730)

                    results = nvdlib.searchCVE(
                        keywordSearch=package_name,
                        pubStartDate=start_date,
                        pubEndDate=end_date,
                        key=self.api_key,
                        limit=100
                    )
                    return list(results)
                except Exception as e:
                    logger.error(f"NVD search failed for {package_name}: {str(e)}")
                    return []

            cves = await loop.run_in_executor(None, search_nvd)

            for cve in cves:
                # Check if package version is affected
                if self._is_version_affected(cve, package_name, package_version):
                    finding = self._parse_cve(cve)
                    findings.append(finding)

        except Exception as e:
            logger.error(f"CVE search failed for {package_name}: {str(e)}")

        return findings

    def _is_version_affected(
        self,
        cve: Any,
        package_name: str,
        package_version: str
    ) -> bool:
        """Check if a specific package version is affected by CVE."""
        try:
            # Get CPE configurations from CVE
            if not hasattr(cve, 'configurations'):
                return False

            for config in cve.configurations:
                for node in config.nodes:
                    for cpe_match in node.cpeMatch:
                        cpe = cpe_match.criteria

                        # Parse CPE to check version ranges
                        if package_name.lower() in cpe.lower():
                            # Check version constraints
                            if hasattr(cpe_match, 'versionStartIncluding'):
                                if pkg_version.parse(package_version) < pkg_version.parse(cpe_match.versionStartIncluding):
                                    continue

                            if hasattr(cpe_match, 'versionEndExcluding'):
                                if pkg_version.parse(package_version) >= pkg_version.parse(cpe_match.versionEndExcluding):
                                    continue

                            if hasattr(cpe_match, 'versionEndIncluding'):
                                if pkg_version.parse(package_version) > pkg_version.parse(cpe_match.versionEndIncluding):
                                    continue

                            return cpe_match.vulnerable

        except Exception as e:
            logger.debug(f"Version check failed: {str(e)}")
            # Be conservative - if we can't determine, assume it might be affected
            return True

        return False

    def _parse_cve(self, cve: Any) -> Dict[str, Any]:
        """Parse CVE object into finding format."""
        try:
            # Get CVSS score
            cvss_score = 0.0
            cvss_vector = ""
            severity = "medium"

            if hasattr(cve, 'v31score'):
                cvss_score = cve.v31score
                cvss_vector = cve.v31vector if hasattr(cve, 'v31vector') else ""
            elif hasattr(cve, 'v3score'):
                cvss_score = cve.v3score
                cvss_vector = cve.v3vector if hasattr(cve, 'v3vector') else ""
            elif hasattr(cve, 'v2score'):
                cvss_score = cve.v2score
                cvss_vector = cve.v2vector if hasattr(cve, 'v2vector') else ""

            # Map CVSS score to severity
            if cvss_score >= 9.0:
                severity = "critical"
            elif cvss_score >= 7.0:
                severity = "high"
            elif cvss_score >= 4.0:
                severity = "medium"
            elif cvss_score > 0:
                severity = "low"

            # Get description
            description = ""
            if hasattr(cve, 'descriptions'):
                for desc in cve.descriptions:
                    if desc.lang == 'en':
                        description = desc.value
                        break

            return {
                "finding_type": "cve",
                "vuln_id": cve.id,
                "title": f"CVE: {cve.id}",
                "description": description,
                "severity": severity,
                "cvss_score": cvss_score,
                "cvss_vector": cvss_vector,
                "cve_published_date": cve.published if hasattr(cve, 'published') else None,
                "cve_modified_date": cve.lastModified if hasattr(cve, 'lastModified') else None,
                "status": "open",
                "can_auto_remediate": False  # CVEs typically need manual remediation
            }

        except Exception as e:
            logger.error(f"Failed to parse CVE: {str(e)}")
            return {}

    async def get_installed_packages(self, ssh_manager=None) -> List[Dict[str, str]]:
        """Get list of installed packages from system."""
        packages = []

        try:
            if ssh_manager:
                # Remote system
                # Try different package managers
                commands = [
                    ("rpm -qa --queryformat '%{NAME}|%{VERSION}\\n'", "rpm"),
                    ("dpkg-query -W -f='${Package}|${Version}\\n'", "dpkg"),
                    ("apk info -v", "apk")
                ]

                for cmd, pkg_manager in commands:
                    result = await ssh_manager.execute_command(cmd)
                    if result["success"]:
                        packages = self._parse_package_list(result["stdout"], pkg_manager)
                        break
            else:
                # Local system
                # Detect package manager
                loop = asyncio.get_event_loop()

                def get_packages():
                    import subprocess

                    # Try rpm first
                    try:
                        result = subprocess.run(
                            ["rpm", "-qa", "--queryformat", "%{NAME}|%{VERSION}\\n"],
                            capture_output=True,
                            text=True
                        )
                        if result.returncode == 0:
                            return self._parse_package_list(result.stdout, "rpm")
                    except FileNotFoundError:
                        pass

                    # Try dpkg
                    try:
                        result = subprocess.run(
                            ["dpkg-query", "-W", "-f=${Package}|${Version}\\n"],
                            capture_output=True,
                            text=True
                        )
                        if result.returncode == 0:
                            return self._parse_package_list(result.stdout, "dpkg")
                    except FileNotFoundError:
                        pass

                    return []

                packages = await loop.run_in_executor(None, get_packages)

        except Exception as e:
            logger.error(f"Failed to get installed packages: {str(e)}")

        return packages

    def _parse_package_list(self, output: str, pkg_manager: str) -> List[Dict[str, str]]:
        """Parse package list output."""
        packages = []

        for line in output.split("\n"):
            line = line.strip()
            if not line:
                continue

            if "|" in line:
                name, version = line.split("|", 1)
                packages.append({
                    "name": name.strip(),
                    "version": version.strip(),
                    "package_manager": pkg_manager
                })
            elif pkg_manager == "apk":
                # Alpine format: package-version
                parts = line.rsplit("-", 1)
                if len(parts) == 2:
                    packages.append({
                        "name": parts[0],
                        "version": parts[1],
                        "package_manager": "apk"
                    })

        return packages
