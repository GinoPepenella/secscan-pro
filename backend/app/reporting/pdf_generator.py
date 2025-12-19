from reportlab.lib import colors
from reportlab.lib.pagesizes import letter, A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, PageBreak, Image
from reportlab.platypus import KeepTogether
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from reportlab.graphics.shapes import Drawing
from reportlab.graphics.charts.piecharts import Pie
from reportlab.graphics.charts.barcharts import VerticalBarChart
import matplotlib.pyplot as plt
import matplotlib
matplotlib.use('Agg')  # Non-interactive backend
from io import BytesIO
from typing import List, Dict, Any, Optional
from datetime import datetime
from pathlib import Path
from loguru import logger
from app.core.config import settings
from app.models.scan import Scan, Finding
from sqlalchemy import select
from app.db.base import AsyncSessionLocal
import tempfile


class PDFReportGenerator:
    """Generates comprehensive PDF reports for security scans."""

    def __init__(self):
        self.output_dir = Path(settings.REPORT_OUTPUT_DIR)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    async def generate_report(self, scan_id: int) -> Optional[str]:
        """Generate PDF report for a scan."""
        async with AsyncSessionLocal() as session:
            # Get scan and findings
            scan_result = await session.execute(
                select(Scan).where(Scan.id == scan_id)
            )
            scan = scan_result.scalar_one_or_none()

            if not scan:
                logger.error(f"Scan {scan_id} not found")
                return None

            findings_result = await session.execute(
                select(Finding).where(Finding.scan_id == scan_id)
            )
            findings = findings_result.scalars().all()

            # Generate report
            report_path = self.output_dir / f"scan_{scan_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"

            try:
                self._create_pdf(scan, findings, str(report_path))
                logger.info(f"Report generated: {report_path}")
                return str(report_path)
            except Exception as e:
                logger.error(f"Failed to generate report: {str(e)}")
                return None

    def _create_pdf(self, scan: Scan, findings: List[Finding], output_path: str):
        """Create PDF document."""
        doc = SimpleDocTemplate(
            output_path,
            pagesize=letter,
            rightMargin=72,
            leftMargin=72,
            topMargin=72,
            bottomMargin=18,
        )

        # Container for the 'Flowable' objects
        elements = []

        # Define styles
        styles = getSampleStyleSheet()
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=24,
            textColor=colors.HexColor('#1a1a1a'),
            spaceAfter=30,
            alignment=TA_CENTER,
            fontName='Helvetica-Bold'
        )

        heading_style = ParagraphStyle(
            'CustomHeading',
            parent=styles['Heading2'],
            fontSize=16,
            textColor=colors.HexColor('#2c3e50'),
            spaceAfter=12,
            spaceBefore=12,
            fontName='Helvetica-Bold'
        )

        # Title
        elements.append(Paragraph("Security Scan Report", title_style))
        elements.append(Paragraph(f"SecScan Pro v{settings.VERSION}", styles['Normal']))
        elements.append(Spacer(1, 12))

        # Executive Summary
        elements.append(Paragraph("Executive Summary", heading_style))
        elements.append(self._create_summary_table(scan))
        elements.append(Spacer(1, 20))

        # Risk Score
        elements.append(Paragraph("Risk Assessment", heading_style))
        risk_color = self._get_risk_color(scan.risk_score)
        risk_level = self._get_risk_level(scan.risk_score)

        risk_data = [
            ['Risk Score', 'Risk Level', 'Scan Status'],
            [
                f'{scan.risk_score:.1f}/100',
                Paragraph(f'<font color="{risk_color}"><b>{risk_level}</b></font>', styles['Normal']),
                scan.status.value.upper()
            ]
        ]
        risk_table = Table(risk_data, colWidths=[2*inch, 2*inch, 2*inch])
        risk_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#34495e')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        elements.append(risk_table)
        elements.append(Spacer(1, 20))

        # Findings Distribution Chart
        elements.append(Paragraph("Findings Distribution", heading_style))
        severity_chart = self._create_severity_chart(scan)
        if severity_chart:
            elements.append(severity_chart)
        elements.append(Spacer(1, 20))

        # Findings by Type
        elements.append(Paragraph("Findings Overview", heading_style))
        findings_overview = self._create_findings_overview(findings)
        elements.append(findings_overview)
        elements.append(PageBreak())

        # Detailed Findings
        elements.append(Paragraph("Detailed Findings", heading_style))

        # Group findings by severity
        findings_by_severity = {
            'critical': [],
            'high': [],
            'medium': [],
            'low': []
        }

        for finding in findings:
            severity = finding.severity.lower()
            if severity in findings_by_severity:
                findings_by_severity[severity].append(finding)

        # Add findings in order of severity
        for severity in ['critical', 'high', 'medium', 'low']:
            severity_findings = findings_by_severity[severity]
            if severity_findings:
                elements.append(Paragraph(
                    f"{severity.upper()} Severity Findings ({len(severity_findings)})",
                    heading_style
                ))

                for finding in severity_findings:
                    finding_elements = self._create_finding_detail(finding, styles)
                    elements.append(KeepTogether(finding_elements))
                    elements.append(Spacer(1, 12))

        # Remediation Summary
        elements.append(PageBreak())
        elements.append(Paragraph("Remediation Summary", heading_style))
        remediation_summary = self._create_remediation_summary(findings)
        elements.append(remediation_summary)
        elements.append(Spacer(1, 20))

        # Recommendations
        elements.append(Paragraph("Recommendations", heading_style))
        recommendations = self._get_recommendations(scan, findings)
        for rec in recommendations:
            elements.append(Paragraph(f"• {rec}", styles['Normal']))
            elements.append(Spacer(1, 6))

        # Build PDF
        doc.build(elements)

    def _create_summary_table(self, scan: Scan) -> Table:
        """Create summary information table."""
        data = [
            ['Scan Name', scan.name],
            ['Scan Type', scan.scan_type.value.upper()],
            ['Started', scan.started_at.strftime('%Y-%m-%d %H:%M:%S') if scan.started_at else 'N/A'],
            ['Completed', scan.completed_at.strftime('%Y-%m-%d %H:%M:%S') if scan.completed_at else 'N/A'],
            ['Total Targets', len(scan.targets) if scan.targets else 0],
            ['Total Checks', scan.total_checks],
            ['Passed', scan.passed_checks],
            ['Failed', scan.failed_checks],
            ['Not Applicable', scan.not_applicable],
        ]

        table = Table(data, colWidths=[2*inch, 4*inch])
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#ecf0f1')),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
            ('GRID', (0, 0), (-1, -1), 1, colors.grey)
        ]))

        return table

    def _create_severity_chart(self, scan: Scan) -> Optional[Drawing]:
        """Create pie chart for severity distribution."""
        data = [
            scan.critical_findings,
            scan.high_findings,
            scan.medium_findings,
            scan.low_findings
        ]

        if sum(data) == 0:
            return None

        drawing = Drawing(400, 200)
        pie = Pie()
        pie.x = 150
        pie.y = 50
        pie.width = 100
        pie.height = 100
        pie.data = data
        pie.labels = ['Critical', 'High', 'Medium', 'Low']
        pie.slices.strokeWidth = 0.5

        pie.slices[0].fillColor = colors.HexColor('#c0392b')
        pie.slices[1].fillColor = colors.HexColor('#e74c3c')
        pie.slices[2].fillColor = colors.HexColor('#f39c12')
        pie.slices[3].fillColor = colors.HexColor('#f1c40f')

        drawing.add(pie)
        return drawing

    def _create_findings_overview(self, findings: List[Finding]) -> Table:
        """Create overview table of findings by type."""
        stig_count = sum(1 for f in findings if f.finding_type == 'stig')
        cve_count = sum(1 for f in findings if f.finding_type == 'cve')
        other_count = len(findings) - stig_count - cve_count

        data = [
            ['Finding Type', 'Count'],
            ['STIG Compliance', stig_count],
            ['CVE Vulnerabilities', cve_count],
            ['Other', other_count],
            ['Total', len(findings)]
        ]

        table = Table(data, colWidths=[3*inch, 2*inch])
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#34495e')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -2), colors.beige),
            ('BACKGROUND', (0, -1), (-1, -1), colors.HexColor('#ecf0f1')),
            ('FONTNAME', (0, -1), (-1, -1), 'Helvetica-Bold'),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))

        return table

    def _create_finding_detail(self, finding: Finding, styles) -> List:
        """Create detailed view of a single finding."""
        elements = []

        # Title with severity color
        severity_color = self._get_severity_color(finding.severity)
        title = Paragraph(
            f'<font color="{severity_color}"><b>[{finding.severity.upper()}]</b></font> {finding.vuln_id}: {finding.title}',
            styles['Heading3']
        )
        elements.append(title)

        # Details table
        details = []

        if finding.target_host:
            details.append(['Target', finding.target_host])

        if finding.cvss_score:
            details.append(['CVSS Score', f'{finding.cvss_score:.1f}'])

        if finding.stig_id:
            details.append(['STIG ID', finding.stig_id])

        details.append(['Status', finding.status.upper()])
        details.append(['Auto-Remediate', 'Yes' if finding.can_auto_remediate else 'No'])

        if details:
            table = Table(details, colWidths=[1.5*inch, 4.5*inch])
            table.setStyle(TableStyle([
                ('FONTSIZE', (0, 0), (-1, -1), 9),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#ecf0f1'))
            ]))
            elements.append(table)

        # Description
        if finding.description:
            elements.append(Spacer(1, 6))
            elements.append(Paragraph(f"<b>Description:</b> {finding.description[:500]}", styles['Normal']))

        return elements

    def _create_remediation_summary(self, findings: List[Finding]) -> Table:
        """Create remediation summary table."""
        auto_remediate = sum(1 for f in findings if f.can_auto_remediate)
        manual_remediate = len(findings) - auto_remediate
        already_remediated = sum(1 for f in findings if f.remediation_status == 'remediated')

        data = [
            ['Remediation Status', 'Count'],
            ['Auto-Remediatable', auto_remediate],
            ['Requires Manual Remediation', manual_remediate],
            ['Already Remediated', already_remediated],
            ['Remaining', len(findings) - already_remediated]
        ]

        table = Table(data, colWidths=[3*inch, 2*inch])
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#34495e')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))

        return table

    def _get_recommendations(self, scan: Scan, findings: List[Finding]) -> List[str]:
        """Generate recommendations based on findings."""
        recommendations = []

        if scan.critical_findings > 0:
            recommendations.append(f"Immediately address {scan.critical_findings} critical findings to reduce security risk.")

        if scan.high_findings > 5:
            recommendations.append(f"Prioritize remediation of {scan.high_findings} high severity findings.")

        auto_remediate = sum(1 for f in findings if f.can_auto_remediate and f.status == 'open')
        if auto_remediate > 0:
            recommendations.append(f"{auto_remediate} findings can be automatically remediated. Consider using the auto-remediation feature.")

        if scan.risk_score > 70:
            recommendations.append("System has a high risk score. Implement a comprehensive remediation plan immediately.")
        elif scan.risk_score > 40:
            recommendations.append("System has a medium risk score. Schedule remediation activities within the next 30 days.")

        recommendations.append("Conduct regular security scans to maintain compliance and identify new vulnerabilities.")
        recommendations.append("Review and update security policies based on these findings.")

        return recommendations

    def _get_risk_color(self, risk_score: float) -> str:
        """Get color based on risk score."""
        if risk_score >= 70:
            return '#c0392b'
        elif risk_score >= 40:
            return '#f39c12'
        elif risk_score >= 20:
            return '#f1c40f'
        else:
            return '#27ae60'

    def _get_risk_level(self, risk_score: float) -> str:
        """Get risk level based on score."""
        if risk_score >= 70:
            return 'CRITICAL'
        elif risk_score >= 40:
            return 'HIGH'
        elif risk_score >= 20:
            return 'MEDIUM'
        else:
            return 'LOW'

    def _get_severity_color(self, severity: str) -> str:
        """Get color for severity level."""
        colors_map = {
            'critical': '#c0392b',
            'high': '#e74c3c',
            'medium': '#f39c12',
            'low': '#f1c40f',
            'info': '#3498db'
        }
        return colors_map.get(severity.lower(), '#7f8c8d')
