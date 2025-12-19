"""
ClamAV Antivirus Scanner

Integrates with ClamAV for malware and virus detection.
"""

import asyncio
import json
import re
from pathlib import Path
from typing import Dict, List, Optional, Any
from loguru import logger


class ClamAVScanner:
    """
    Scanner for ClamAV antivirus integration.
    Detects malware, viruses, and suspicious files.
    """

    def __init__(self, clamscan_path: str = "/usr/bin/clamscan"):
        self.clamscan_path = clamscan_path
        self.freshclam_path = "/usr/bin/freshclam"

        logger.info(f"ClamAV Scanner initialized")

    async def check_installation(self) -> Dict[str, Any]:
        """
        Check if ClamAV is installed and get version info.

        Returns:
            Dict with installation status and version info
        """
        try:
            process = await asyncio.create_subprocess_exec(
                self.clamscan_path, "--version",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            stdout, stderr = await process.communicate()

            if process.returncode == 0:
                version = stdout.decode().strip()
                return {
                    "installed": True,
                    "version": version,
                    "path": self.clamscan_path
                }
            else:
                return {
                    "installed": False,
                    "error": "ClamAV not found or not executable"
                }

        except FileNotFoundError:
            logger.warning("ClamAV not found on system")
            return {
                "installed": False,
                "error": "ClamAV not installed"
            }
        except Exception as e:
            logger.error(f"Error checking ClamAV installation: {str(e)}")
            return {
                "installed": False,
                "error": str(e)
            }

    async def update_signatures(self) -> Dict[str, Any]:
        """
        Update ClamAV virus signatures using freshclam.

        Returns:
            Dict with update status
        """
        logger.info("Updating ClamAV signatures...")

        try:
            process = await asyncio.create_subprocess_exec(
                "sudo", self.freshclam_path,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            stdout, stderr = await process.communicate()

            if process.returncode == 0:
                logger.info("ClamAV signatures updated successfully")
                return {
                    "success": True,
                    "output": stdout.decode()
                }
            else:
                error_msg = stderr.decode() if stderr else "Unknown error"
                logger.warning(f"ClamAV signature update warning: {error_msg}")
                # Don't fail if already up to date
                return {
                    "success": True,
                    "output": stdout.decode(),
                    "warning": error_msg
                }

        except Exception as e:
            logger.error(f"Failed to update ClamAV signatures: {str(e)}")
            return {
                "success": False,
                "error": str(e)
            }

    async def scan_paths(
        self,
        scan_paths: List[str],
        recursive: bool = True,
        remove_infected: bool = False,
        max_filesize: str = "100M"
    ) -> Dict[str, Any]:
        """
        Scan specified paths for malware.

        Args:
            scan_paths: List of file or directory paths to scan
            recursive: Scan directories recursively
            remove_infected: Automatically remove infected files (dangerous!)
            max_filesize: Maximum file size to scan (e.g., "100M")

        Returns:
            Dict with scan results and findings
        """
        logger.info(f"Starting ClamAV scan of {len(scan_paths)} path(s)")

        # Build clamscan command
        cmd = [self.clamscan_path]

        # Options
        if recursive:
            cmd.append("-r")  # Recursive

        cmd.extend([
            "-i",  # Only show infected files
            "--max-filesize=" + max_filesize,
            "--max-scansize=" + max_filesize,
            "-l", "/tmp/clamav_scan.log"  # Log file
        ])

        if remove_infected:
            cmd.append("--remove")  # Remove infected files

        # Add paths to scan
        cmd.extend(scan_paths)

        logger.debug(f"Executing ClamAV command: {' '.join(cmd)}")

        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            stdout, stderr = await process.communicate()

            # Parse output
            output = stdout.decode()
            results = self._parse_clamscan_output(output)

            # Add scan paths to results
            results["scan_paths"] = scan_paths
            results["recursive"] = recursive

            logger.info(f"ClamAV scan completed: {results['summary']['infected_files']} infected files found")

            return results

        except Exception as e:
            logger.error(f"ClamAV scan execution failed: {str(e)}")
            return {
                "success": False,
                "error": str(e),
                "findings": []
            }

    async def scan_full_system(
        self,
        exclude_paths: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """
        Perform a full system scan.

        Args:
            exclude_paths: List of paths to exclude from scan

        Returns:
            Dict with scan results and findings
        """
        logger.info("Starting full system ClamAV scan")

        # Common paths to scan for a full system scan
        scan_paths = [
            "/home",
            "/var",
            "/opt",
            "/usr/local",
            "/tmp"
        ]

        # Filter out excluded paths
        if exclude_paths:
            scan_paths = [p for p in scan_paths if p not in exclude_paths]

        return await self.scan_paths(scan_paths, recursive=True)

    def _parse_clamscan_output(self, output: str) -> Dict[str, Any]:
        """
        Parse clamscan output and extract findings.

        Args:
            output: Raw clamscan output

        Returns:
            Dict with parsed results
        """
        findings = []
        summary = {
            "scanned_files": 0,
            "scanned_directories": 0,
            "infected_files": 0,
            "data_scanned": "",
            "scan_time": ""
        }

        # Parse infected files
        # Format: /path/to/file: Virus.Name FOUND
        infected_pattern = r"^(.+?):\s+(.+?)\s+FOUND$"

        for line in output.split('\n'):
            line = line.strip()

            # Match infected files
            match = re.match(infected_pattern, line)
            if match:
                file_path = match.group(1)
                virus_name = match.group(2)

                finding = {
                    "finding_type": "malware",
                    "vuln_id": f"MALWARE-{virus_name}",
                    "title": f"Malware Detected: {virus_name}",
                    "description": f"ClamAV detected malware in file: {file_path}",
                    "severity": "critical",  # All malware is critical
                    "status": "open",
                    "can_auto_remediate": True,  # Can delete the file
                    "finding_details": f"Virus/Malware: {virus_name}\nFile: {file_path}",
                    "affected_file": file_path,
                    "malware_signature": virus_name
                }
                findings.append(finding)

            # Parse summary statistics
            if "Scanned files:" in line:
                summary["scanned_files"] = int(line.split(":")[1].strip())
            elif "Scanned directories:" in line:
                summary["scanned_directories"] = int(line.split(":")[1].strip())
            elif "Infected files:" in line:
                summary["infected_files"] = int(line.split(":")[1].strip())
            elif "Data scanned:" in line:
                summary["data_scanned"] = line.split(":")[1].strip()
            elif "Time:" in line:
                summary["scan_time"] = line.split(":")[1].strip()

        return {
            "success": True,
            "findings": findings,
            "summary": summary,
            "raw_output": output
        }

    async def scan_file(self, file_path: str) -> Dict[str, Any]:
        """
        Scan a single file for malware.

        Args:
            file_path: Path to file to scan

        Returns:
            Dict with scan result
        """
        return await self.scan_paths([file_path], recursive=False)

    async def get_database_info(self) -> Dict[str, Any]:
        """
        Get ClamAV virus database information.

        Returns:
            Dict with database version and signature counts
        """
        try:
            process = await asyncio.create_subprocess_exec(
                self.clamscan_path, "--version",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            stdout, stderr = await process.communicate()

            if process.returncode == 0:
                output = stdout.decode()
                # Parse version and signature count from output
                # Format: ClamAV 0.103.x/26xxx/Date
                parts = output.split('/')
                if len(parts) >= 2:
                    signatures = parts[1]
                else:
                    signatures = "Unknown"

                return {
                    "success": True,
                    "version": output.strip(),
                    "signatures": signatures
                }
            else:
                return {
                    "success": False,
                    "error": "Failed to get database info"
                }

        except Exception as e:
            logger.error(f"Error getting ClamAV database info: {str(e)}")
            return {
                "success": False,
                "error": str(e)
            }
