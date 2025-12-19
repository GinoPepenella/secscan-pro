from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from typing import List, Optional
from pydantic import BaseModel
from app.db.base import get_db
from app.remediation.engine import RemediationEngine

router = APIRouter()


class RemediationRequest(BaseModel):
    finding_ids: List[int]
    dry_run: bool = False


class RemediationResponse(BaseModel):
    success: List[dict]
    failed: List[dict]
    skipped: List[dict]
    dry_run: bool


class RemediationPreview(BaseModel):
    can_remediate: bool
    vuln_id: Optional[str] = None
    description: Optional[str] = None
    script: Optional[str] = None
    requires_reboot: bool = False
    risk_level: Optional[str] = None
    reason: Optional[str] = None


@router.post("/", response_model=RemediationResponse)
async def remediate_findings(
    request: RemediationRequest,
    db: AsyncSession = Depends(get_db)
):
    """Remediate one or more findings."""
    engine = RemediationEngine()

    # For now, we'll do local remediation
    # TODO: Support SSH-based remediation
    results = await engine.remediate_findings(
        finding_ids=request.finding_ids,
        ssh_manager=None,
        dry_run=request.dry_run
    )

    return results


@router.get("/{finding_id}/preview", response_model=RemediationPreview)
async def get_remediation_preview(
    finding_id: int,
    db: AsyncSession = Depends(get_db)
):
    """Get a preview of what remediation would do for a finding."""
    engine = RemediationEngine()
    preview = await engine.get_remediation_preview(finding_id)
    return preview


@router.post("/bulk")
async def bulk_remediate(
    scan_id: int,
    severity: Optional[str] = None,
    auto_only: bool = True,
    dry_run: bool = False,
    db: AsyncSession = Depends(get_db)
):
    """Bulk remediate findings from a scan."""
    from sqlalchemy import select
    from app.models.scan import Finding

    # Build query
    query = select(Finding).where(Finding.scan_id == scan_id)

    if severity:
        query = query.where(Finding.severity == severity)

    if auto_only:
        query = query.where(Finding.can_auto_remediate == True)

    result = await db.execute(query)
    findings = result.scalars().all()

    if not findings:
        return {"message": "No findings to remediate"}

    finding_ids = [f.id for f in findings]

    engine = RemediationEngine()
    results = await engine.remediate_findings(
        finding_ids=finding_ids,
        ssh_manager=None,
        dry_run=dry_run
    )

    return results
