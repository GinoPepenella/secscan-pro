"""
YARA Scanner

Integrates with YARA for pattern-based malware and threat detection.
"""

import asyncio
import json
from pathlib import Path
from typing import Dict, List, Optional, Any
from loguru import logger


class YARAScanner:
    """
    Scanner for YARA pattern matching and threat detection.
    Uses YARA rules to identify malware, suspicious patterns, and indicators of compromise.
    """

    def __init__(self, yara_binary: str = "/usr/bin/yara"):
        self.yara_binary = yara_binary
        self.default_rules_paths = [
            "/var/lib/yara/rules",
            "/usr/share/yara/rules",
            "/opt/yara-rules",
            "./yara-rules"
        ]

        logger.info(f"YARA Scanner initialized")

    async def check_installation(self) -> Dict[str, Any]:
        """
        Check if YARA is installed and get version info.

        Returns:
            Dict with installation status and version info
        """
        try:
            process = await asyncio.create_subprocess_exec(
                self.yara_binary, "--version",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            stdout, stderr = await process.communicate()

            if process.returncode == 0:
                version = stdout.decode().strip()
                return {
                    "installed": True,
                    "version": version,
                    "path": self.yara_binary
                }
            else:
                return {
                    "installed": False,
                    "error": "YARA not found or not executable"
                }

        except FileNotFoundError:
            logger.warning("YARA not found on system")
            return {
                "installed": False,
                "error": "YARA not installed"
            }
        except Exception as e:
            logger.error(f"Error checking YARA installation: {str(e)}")
            return {
                "installed": False,
                "error": str(e)
            }

    def discover_rule_files(self, custom_path: Optional[str] = None) -> List[str]:
        """
        Discover YARA rule files in standard locations.

        Args:
            custom_path: Optional custom path to search for rules

        Returns:
            List of rule file paths found
        """
        rule_files = []
        search_paths = self.default_rules_paths.copy()

        if custom_path:
            search_paths.insert(0, custom_path)

        for rules_dir in search_paths:
            rules_path = Path(rules_dir)
            if rules_path.exists() and rules_path.is_dir():
                # Find .yar and .yara files
                for pattern in ["*.yar", "*.yara"]:
                    rule_files.extend([str(f) for f in rules_path.glob(pattern)])
                    # Also search subdirectories
                    rule_files.extend([str(f) for f in rules_path.glob(f"**/{pattern}")])

        logger.info(f"Discovered {len(rule_files)} YARA rule files")
        return rule_files

    async def scan_with_rules(
        self,
        rules_file: str,
        scan_paths: List[str],
        recursive: bool = True,
        fast_scan: bool = False
    ) -> Dict[str, Any]:
        """
        Scan paths using specified YARA rules.

        Args:
            rules_file: Path to YARA rules file
            scan_paths: List of files or directories to scan
            recursive: Scan directories recursively
            fast_scan: Fast scan mode (less thorough but faster)

        Returns:
            Dict with scan results and findings
        """
        logger.info(f"Starting YARA scan with rules: {rules_file}")

        # Build YARA command
        cmd = [self.yara_binary]

        # Options
        if recursive:
            cmd.append("-r")  # Recursive

        if fast_scan:
            cmd.append("-f")  # Fast matching mode

        # Additional options
        cmd.extend([
            "-s",  # Print matching strings
            "-m",  # Print metadata
            "-g",  # Print tags
        ])

        # Add rules file
        cmd.append(rules_file)

        # Add scan paths
        cmd.extend(scan_paths)

        logger.debug(f"Executing YARA command: {' '.join(cmd)}")

        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            stdout, stderr = await process.communicate()

            # YARA returns non-zero if no matches, which is fine
            output = stdout.decode()
            error_output = stderr.decode()

            if error_output and "error" in error_output.lower():
                logger.warning(f"YARA scan warnings: {error_output}")

            # Parse results
            results = self._parse_yara_output(output)
            results["rules_file"] = rules_file
            results["scan_paths"] = scan_paths

            logger.info(f"YARA scan completed: {len(results['findings'])} matches found")

            return results

        except Exception as e:
            logger.error(f"YARA scan execution failed: {str(e)}")
            return {
                "success": False,
                "error": str(e),
                "findings": []
            }

    async def scan_with_multiple_rules(
        self,
        scan_paths: List[str],
        custom_rules_path: Optional[str] = None,
        recursive: bool = True
    ) -> Dict[str, Any]:
        """
        Scan paths using all available YARA rules.

        Args:
            scan_paths: List of files or directories to scan
            custom_rules_path: Optional custom rules directory
            recursive: Scan directories recursively

        Returns:
            Dict with aggregated scan results
        """
        logger.info(f"Starting multi-rule YARA scan")

        rule_files = self.discover_rule_files(custom_rules_path)

        if not rule_files:
            logger.warning("No YARA rules found")
            return {
                "success": False,
                "error": "No YARA rule files found",
                "findings": []
            }

        all_findings = []
        rules_scanned = 0

        for rules_file in rule_files:
            try:
                result = await self.scan_with_rules(
                    rules_file,
                    scan_paths,
                    recursive=recursive,
                    fast_scan=False
                )

                if result.get("success", False):
                    all_findings.extend(result.get("findings", []))
                    rules_scanned += 1

            except Exception as e:
                logger.warning(f"Failed to scan with rules {rules_file}: {str(e)}")

        return {
            "success": True,
            "findings": all_findings,
            "summary": {
                "total_matches": len(all_findings),
                "rules_used": rules_scanned,
                "total_rules_available": len(rule_files)
            }
        }

    def _parse_yara_output(self, output: str) -> Dict[str, Any]:
        """
        Parse YARA output and extract findings.

        YARA output format:
        rule_name file_path
        0x1234:$string_identifier: matched string

        Args:
            output: Raw YARA output

        Returns:
            Dict with parsed results
        """
        findings = []
        current_finding = None

        for line in output.split('\n'):
            line = line.strip()
            if not line:
                continue

            # Check if this is a rule match line (no indentation, no $)
            if not line.startswith('0x') and not line.startswith('$'):
                parts = line.split()
                if len(parts) >= 2:
                    rule_name = parts[0]
                    file_path = ' '.join(parts[1:])

                    # Save previous finding if exists
                    if current_finding:
                        findings.append(current_finding)

                    # Start new finding
                    current_finding = {
                        "finding_type": "yara_match",
                        "vuln_id": f"YARA-{rule_name}",
                        "title": f"YARA Rule Match: {rule_name}",
                        "description": f"File matched YARA rule indicating potential threat or suspicious pattern",
                        "severity": self._determine_severity(rule_name),
                        "status": "open",
                        "can_auto_remediate": False,  # Manual review needed
                        "finding_details": f"Rule: {rule_name}\nFile: {file_path}",
                        "affected_file": file_path,
                        "yara_rule": rule_name,
                        "matched_strings": []
                    }

            # Parse matched strings
            elif line.startswith('0x') and current_finding:
                # Format: 0x1234:$string_name: matched content
                parts = line.split(':', 2)
                if len(parts) >= 2:
                    matched_str = parts[1].strip() if len(parts) > 1 else ""
                    current_finding["matched_strings"].append(matched_str)

        # Add last finding
        if current_finding:
            findings.append(current_finding)

        return {
            "success": True,
            "findings": findings,
            "summary": {
                "total_matches": len(findings)
            }
        }

    def _determine_severity(self, rule_name: str) -> str:
        """
        Determine severity based on YARA rule name.

        Args:
            rule_name: Name of the YARA rule that matched

        Returns:
            Severity level string
        """
        rule_lower = rule_name.lower()

        # Critical indicators
        if any(term in rule_lower for term in ['ransomware', 'trojan', 'backdoor', 'rootkit', 'exploit']):
            return "critical"

        # High severity indicators
        if any(term in rule_lower for term in ['malware', 'virus', 'worm', 'apt', 'shellcode']):
            return "high"

        # Medium severity indicators
        if any(term in rule_lower for term in ['suspicious', 'packer', 'obfuscated', 'encoded']):
            return "medium"

        # Default to medium for unknown patterns
        return "medium"

    async def compile_rules(self, rules_path: str, output_path: str) -> Dict[str, Any]:
        """
        Compile YARA rules into a compiled rules file for faster scanning.

        Args:
            rules_path: Path to rules file or directory
            output_path: Path to save compiled rules

        Returns:
            Dict with compilation status
        """
        logger.info(f"Compiling YARA rules from {rules_path}")

        try:
            cmd = [
                "yarac",  # YARA compiler
                rules_path,
                output_path
            ]

            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            stdout, stderr = await process.communicate()

            if process.returncode == 0:
                logger.info(f"YARA rules compiled successfully to {output_path}")
                return {
                    "success": True,
                    "output_file": output_path
                }
            else:
                error_msg = stderr.decode() if stderr else "Unknown error"
                logger.error(f"YARA rule compilation failed: {error_msg}")
                return {
                    "success": False,
                    "error": error_msg
                }

        except FileNotFoundError:
            return {
                "success": False,
                "error": "yarac compiler not found"
            }
        except Exception as e:
            logger.error(f"YARA rule compilation failed: {str(e)}")
            return {
                "success": False,
                "error": str(e)
            }
