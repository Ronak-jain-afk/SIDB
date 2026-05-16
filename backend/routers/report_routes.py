"""
Report export routes for Shadow IT Discovery Bot.
Provides CSV and PDF export of scan results.
"""

import csv
import io
import logging
from datetime import datetime

from fastapi import APIRouter, HTTPException, status
from fastapi.responses import StreamingResponse
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle

from models import ScanStatus
from services import get_scan_service

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/reports", tags=["Reports"])


@router.get(
    "/{scan_id}/csv",
    summary="Export Scan as CSV",
    description="Download scan results as a CSV file."
)
async def export_csv(scan_id: str):
    """Export scan assets as a CSV file."""
    service = get_scan_service()
    scan = await service.get_scan(scan_id)

    if not scan:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")
    if scan.status != ScanStatus.COMPLETED:
        raise HTTPException(status_code=400, detail="Scan not yet completed")

    output = io.StringIO()
    writer = csv.writer(output)

    writer.writerow(["Asset ID", "IP Address", "Port", "Service", "Technology",
                      "Version", "Hostname", "Risk Level", "Risk Score", "Risk Factors"])

    for asset in scan.assets:
        writer.writerow([
            asset.asset_id,
            asset.ip,
            asset.port,
            asset.service,
            asset.technology or "",
            asset.version or "",
            asset.hostname or "",
            asset.risk_level.value,
            asset.risk_score,
            "; ".join(asset.risk_factors)
        ])

    output.seek(0)
    filename = f"shadow-scan-{scan_id}-{datetime.utcnow().strftime('%Y%m%d')}.csv"

    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )


@router.get(
    "/{scan_id}/pdf",
    summary="Export Scan as PDF",
    description="Download scan results as a PDF report."
)
async def export_pdf(scan_id: str):
    """Export scan results as a PDF report."""
    service = get_scan_service()
    scan = await service.get_scan(scan_id)

    if not scan:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")
    if scan.status != ScanStatus.COMPLETED:
        raise HTTPException(status_code=400, detail="Scan not yet completed")

    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=letter)
    styles = getSampleStyleSheet()
    elements = []

    # Title
    elements.append(Paragraph(
        f"Shadow IT Discovery Bot - Scan Report", styles["Title"]
    ))
    elements.append(Spacer(1, 12))

    # Metadata
    elements.append(Paragraph(f"<b>Scan ID:</b> {scan.scan_id}", styles["Normal"]))
    elements.append(Paragraph(f"<b>Domain:</b> {scan.domain}", styles["Normal"]))
    elements.append(Paragraph(
        f"<b>Date:</b> {scan.started_at.strftime('%Y-%m-%d %H:%M UTC')}",
        styles["Normal"]
    ))
    if scan.posture_score:
        elements.append(Paragraph(
            f"<b>Security Posture:</b> {scan.posture_score.score}/100 ({scan.posture_score.rating.value})",
            styles["Normal"]
        ))
    elements.append(Spacer(1, 20))

    # Assets table
    elements.append(Paragraph("<b>Discovered Assets</b>", styles["Heading2"]))
    elements.append(Spacer(1, 8))

    table_data = [["IP", "Port", "Service", "Technology", "Risk"]]
    for asset in scan.assets:
        table_data.append([
            asset.ip,
            str(asset.port),
            asset.service,
            asset.technology or "",
            f"{asset.risk_level.value} ({asset.risk_score})"
        ])

    if len(table_data) > 1:
        col_widths = [1.3*inch, 0.6*inch, 1*inch, 1.5*inch, 1.2*inch]
        t = Table(table_data, colWidths=col_widths)
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1f2937")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("ALIGN", (0, 0), (-1, -1), "LEFT"),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#374151")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#111827"), colors.HexColor("#1a2332")]),
            ("TEXTCOLOR", (0, 1), (-1, -1), colors.HexColor("#d1d5db")),
        ]))
        elements.append(t)
    else:
        elements.append(Paragraph("No assets discovered.", styles["Normal"]))

    elements.append(Spacer(1, 20))

    # Recommendations
    elements.append(Paragraph("<b>Recommendations</b>", styles["Heading2"]))
    elements.append(Spacer(1, 8))

    for rec in scan.recommendations[:10]:
        elements.append(Paragraph(
            f"<b>[{rec.priority.value}]</b> {rec.title}",
            styles["Normal"]
        ))
        elements.append(Paragraph(
            f"<i>{rec.category}</i>",
            styles["Normal"]
        ))
        elements.append(Spacer(1, 4))

    if not scan.recommendations:
        elements.append(Paragraph("No recommendations.", styles["Normal"]))

    doc.build(elements)
    buf.seek(0)

    filename = f"shadow-scan-{scan_id}-{datetime.utcnow().strftime('%Y%m%d')}.pdf"

    return StreamingResponse(
        iter([buf.getvalue()]),
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )
