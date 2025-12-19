from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc
from typing import List, Optional
from pydantic import BaseModel
from app.db.base import get_db
from app.models.scan import Scan, Finding, ScanType, ScanStatus, AuthMethod, SudoMode
from app.scanners.orchestrator import ScanOrchestrator
from datetime import datetime

router = APIRouter()


class ScanCreate(BaseModel):
    name: str
    scan_type: ScanType
    targets: List[str]
    use_ssh: bool = False
    auth_method: Optional[AuthMethod] = None
    ssh_username: Optional[str] = None
    ssh_port: int = 22
    sudo_mode: SudoMode = SudoMode.SUDO
    config_files: Optional[List[str]] = None
    stig_profiles: Optional[List[str]] = None
    include_cves: bool = True


class ScanResponse(BaseModel):
    id: int
    name: str
    scan_type: str
    status: str
    total_checks: int
    passed_checks: int
    failed_checks: int
    risk_score: float
    critical_findings: int
    high_findings: int
    medium_findings: int
    low_findings: int
    created_at: datetime
    started_at: Optional[datetime]
    completed_at: Optional[datetime]

    class Config:
        from_attributes = True


class FindingResponse(BaseModel):
    id: int
    finding_type: str
    vuln_id: str
    title: str
    severity: str
    target_host: str
    status: str
    can_auto_remediate: bool
    cvss_score: Optional[float]

    class Config:
        from_attributes = True


@router.post("/", response_model=ScanResponse)
async def create_scan(
    scan_data: ScanCreate,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db)
):
    """Create and start a new security scan."""
    # Create scan record
    scan = Scan(
        name=scan_data.name,
        scan_type=scan_data.scan_type,
        targets=scan_data.targets,
        use_ssh=scan_data.use_ssh,
        auth_method=scan_data.auth_method,
        ssh_username=scan_data.ssh_username,
        ssh_port=scan_data.ssh_port,
        sudo_mode=scan_data.sudo_mode,
        config_files=scan_data.config_files,
        stig_profiles=scan_data.stig_profiles,
        include_cves=scan_data.include_cves,
        status=ScanStatus.PENDING
    )

    db.add(scan)
    await db.commit()
    await db.refresh(scan)

    # Start scan in background
    orchestrator = ScanOrchestrator()
    background_tasks.add_task(orchestrator.execute_scan, scan.id)

    return scan


@router.get("/", response_model=List[ScanResponse])
async def list_scans(
    skip: int = 0,
    limit: int = 100,
    status: Optional[ScanStatus] = None,
    db: AsyncSession = Depends(get_db)
):
    """List all scans."""
    query = select(Scan).order_by(desc(Scan.created_at)).offset(skip).limit(limit)

    if status:
        query = query.where(Scan.status == status)

    result = await db.execute(query)
    scans = result.scalars().all()
    return scans


@router.get("/{scan_id}", response_model=ScanResponse)
async def get_scan(scan_id: int, db: AsyncSession = Depends(get_db)):
    """Get scan details."""
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalar_one_or_none()

    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    return scan


@router.get("/{scan_id}/findings", response_model=List[FindingResponse])
async def get_scan_findings(
    scan_id: int,
    severity: Optional[str] = None,
    finding_type: Optional[str] = None,
    db: AsyncSession = Depends(get_db)
):
    """Get findings for a scan."""
    query = select(Finding).where(Finding.scan_id == scan_id)

    if severity:
        query = query.where(Finding.severity == severity)

    if finding_type:
        query = query.where(Finding.finding_type == finding_type)

    result = await db.execute(query)
    findings = result.scalars().all()
    return findings


@router.delete("/{scan_id}")
async def delete_scan(scan_id: int, db: AsyncSession = Depends(get_db)):
    """Delete a scan and all associated findings."""
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalar_one_or_none()

    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    await db.delete(scan)
    await db.commit()

    return {"message": "Scan deleted successfully"}


@router.post("/{scan_id}/cancel")
async def cancel_scan(scan_id: int, db: AsyncSession = Depends(get_db)):
    """Cancel a running scan."""
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalar_one_or_none()

    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    if scan.status != ScanStatus.RUNNING:
        raise HTTPException(status_code=400, detail="Scan is not running")

    scan.status = ScanStatus.CANCELLED
    scan.completed_at = datetime.utcnow()
    await db.commit()

    return {"message": "Scan cancelled"}
