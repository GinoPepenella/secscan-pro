from sqlalchemy import Column, Integer, String, DateTime, Text, JSON, Enum, ForeignKey, Boolean, Float
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from app.db.base import Base
import enum


class ScanStatus(str, enum.Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ScanType(str, enum.Enum):
    STIG = "stig"
    VULNERABILITY = "vulnerability"
    COMBINED = "combined"
    SCC = "scc"  # SCAP Compliance Checker
    ANTIVIRUS = "antivirus"  # ClamAV + YARA
    FULL = "full"  # All scan types


class AuthMethod(str, enum.Enum):
    PASSWORD = "password"
    PUBLIC_KEY = "public_key"
    PRIVATE_KEY_CONTENT = "private_key_content"  # Paste key content
    LOCAL_SSH_KEYS = "local_ssh_keys"  # Use ~/.ssh/ keys


class SudoMode(str, enum.Enum):
    SUDO = "sudo"
    SUDO_SU = "sudo_su"
    SUDO_SU_DASH = "sudo_su_dash"


class Scan(Base):
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, index=True)
    scan_type = Column(Enum(ScanType), nullable=False)
    status = Column(Enum(ScanStatus), default=ScanStatus.PENDING)

    # Target information
    targets = Column(JSON)  # List of IPs/FQDNs

    # SSH Configuration
    use_ssh = Column(Boolean, default=False)
    auth_method = Column(Enum(AuthMethod), nullable=True)
    ssh_username = Column(String, nullable=True)
    ssh_port = Column(Integer, default=22)
    sudo_mode = Column(Enum(SudoMode), default=SudoMode.SUDO)

    # SSH Credentials (encrypted)
    ssh_password = Column(Text, nullable=True)  # Encrypted password
    ssh_private_key_content = Column(Text, nullable=True)  # Encrypted private key content
    ssh_private_key_path = Column(String, nullable=True)  # Path to key file (e.g., ~/.ssh/id_rsa)
    ssh_key_passphrase = Column(Text, nullable=True)  # Encrypted key passphrase if needed

    # Config file scanning
    config_files = Column(JSON, nullable=True)  # List of config file paths

    # STIG Configuration
    stig_profiles = Column(JSON, nullable=True)  # List of STIG profiles to scan

    # SCC (SCAP Compliance Checker) Configuration
    scc_profiles = Column(JSON, nullable=True)  # List of SCAP profiles to scan
    scc_auto_detect = Column(Boolean, default=True)  # Auto-detect OS and apply appropriate STIG

    # Vulnerability Configuration
    include_cves = Column(Boolean, default=True)

    # Antivirus Configuration
    av_scan_paths = Column(JSON, nullable=True)  # Paths to scan with antivirus
    av_full_scan = Column(Boolean, default=False)  # Full system scan vs targeted
    av_use_clamav = Column(Boolean, default=True)  # Use ClamAV engine
    av_use_yara = Column(Boolean, default=True)  # Use YARA engine
    av_yara_rules_path = Column(String, nullable=True)  # Custom YARA rules path

    # Results
    total_checks = Column(Integer, default=0)
    passed_checks = Column(Integer, default=0)
    failed_checks = Column(Integer, default=0)
    not_applicable = Column(Integer, default=0)

    # Risk scoring
    risk_score = Column(Float, default=0.0)
    critical_findings = Column(Integer, default=0)
    high_findings = Column(Integer, default=0)
    medium_findings = Column(Integer, default=0)
    low_findings = Column(Integer, default=0)

    # Metadata
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    started_at = Column(DateTime(timezone=True), nullable=True)
    completed_at = Column(DateTime(timezone=True), nullable=True)

    error_message = Column(Text, nullable=True)

    # Relationships
    findings = relationship("Finding", back_populates="scan", cascade="all, delete-orphan")
    reports = relationship("Report", back_populates="scan", cascade="all, delete-orphan")


class Finding(Base):
    __tablename__ = "findings"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id", ondelete="CASCADE"), nullable=False)

    # Finding identification
    finding_type = Column(String, index=True)  # "stig", "cve", "config"
    vuln_id = Column(String, index=True)  # V-XXXXX for STIG, CVE-XXXX-XXXX for CVE
    title = Column(String)
    description = Column(Text)

    # Target information
    target_host = Column(String, index=True)
    target_ip = Column(String, nullable=True)

    # Risk information
    severity = Column(String, index=True)  # "critical", "high", "medium", "low", "info"
    cvss_score = Column(Float, nullable=True)
    cvss_vector = Column(String, nullable=True)

    # STIG specific
    stig_id = Column(String, nullable=True)
    rule_id = Column(String, nullable=True)
    group_title = Column(String, nullable=True)
    check_content = Column(Text, nullable=True)
    fix_text = Column(Text, nullable=True)

    # CVE specific
    cve_published_date = Column(DateTime(timezone=True), nullable=True)
    cve_modified_date = Column(DateTime(timezone=True), nullable=True)
    affected_software = Column(JSON, nullable=True)

    # Status
    status = Column(String, default="open")  # "open", "remediated", "accepted", "false_positive"
    finding_details = Column(Text)

    # Remediation
    can_auto_remediate = Column(Boolean, default=False)
    remediation_script = Column(Text, nullable=True)
    remediation_status = Column(String, nullable=True)
    remediated_at = Column(DateTime(timezone=True), nullable=True)

    # Metadata
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    # Relationships
    scan = relationship("Scan", back_populates="findings")


class Report(Base):
    __tablename__ = "reports"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id", ondelete="CASCADE"), nullable=False)

    report_format = Column(String)  # "pdf", "json", "csv", "html"
    file_path = Column(String)
    file_size = Column(Integer)

    created_at = Column(DateTime(timezone=True), server_default=func.now())

    # Relationships
    scan = relationship("Scan", back_populates="reports")
