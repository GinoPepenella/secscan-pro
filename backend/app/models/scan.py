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


class AuthMethod(str, enum.Enum):
    PASSWORD = "password"
    PUBLIC_KEY = "public_key"


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

    # Config file scanning
    config_files = Column(JSON, nullable=True)  # List of config file paths

    # STIG Configuration
    stig_profiles = Column(JSON, nullable=True)  # List of STIG profiles to scan

    # Vulnerability Configuration
    include_cves = Column(Boolean, default=True)

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
