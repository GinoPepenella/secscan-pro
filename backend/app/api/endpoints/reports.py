from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse
from sqlalchemy.ext.asyncio import AsyncSession
from app.db.base import get_db
from app.reporting.pdf_generator import PDFReportGenerator
from app.models.scan import Report
from pathlib import Path

router = APIRouter()


@router.post("/{scan_id}/generate")
async def generate_report(scan_id: int, db: AsyncSession = Depends(get_db)):
    """Generate a PDF report for a scan."""
    generator = PDFReportGenerator()

    report_path = await generator.generate_report(scan_id)

    if not report_path:
        raise HTTPException(status_code=500, detail="Failed to generate report")

    # Save report record
    file_path = Path(report_path)
    report = Report(
        scan_id=scan_id,
        report_format="pdf",
        file_path=report_path,
        file_size=file_path.stat().st_size if file_path.exists() else 0
    )

    db.add(report)
    await db.commit()

    return {
        "message": "Report generated successfully",
        "report_id": report.id,
        "file_path": report_path
    }


@router.get("/{scan_id}/download")
async def download_report(scan_id: int, db: AsyncSession = Depends(get_db)):
    """Download the latest PDF report for a scan."""
    from sqlalchemy import select, desc

    result = await db.execute(
        select(Report)
        .where(Report.scan_id == scan_id)
        .order_by(desc(Report.created_at))
        .limit(1)
    )

    report = result.scalar_one_or_none()

    if not report:
        raise HTTPException(status_code=404, detail="No report found for this scan")

    if not Path(report.file_path).exists():
        raise HTTPException(status_code=404, detail="Report file not found")

    return FileResponse(
        report.file_path,
        media_type="application/pdf",
        filename=f"scan_{scan_id}_report.pdf"
    )
