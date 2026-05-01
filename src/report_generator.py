"""
PDF report generator for Copilot Data Exposure Firewall.
Produces a 3-section executive report: Summary, Findings, Remediation.
"""

from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    HRFlowable, KeepTogether
)
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from datetime import datetime
import io

from src.scanner import ScanResult, ExposureItem, RISK_CRITICAL, RISK_HIGH, RISK_MEDIUM

BRAND_DARK = colors.HexColor("#0F172A")
BRAND_BLUE = colors.HexColor("#2563EB")
BRAND_RED = colors.HexColor("#DC2626")
BRAND_ORANGE = colors.HexColor("#EA580C")
BRAND_YELLOW = colors.HexColor("#CA8A04")
BRAND_GREEN = colors.HexColor("#16A34A")
BRAND_GRAY = colors.HexColor("#64748B")
BRAND_LIGHT = colors.HexColor("#F8FAFC")


def _risk_color(level: str) -> colors.Color:
    return {
        RISK_CRITICAL: BRAND_RED,
        RISK_HIGH: BRAND_ORANGE,
        RISK_MEDIUM: BRAND_YELLOW,
    }.get(level, BRAND_GRAY)


def generate_pdf(result: ScanResult, redact_after: int = 0) -> bytes:
    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=A4,
        leftMargin=2*cm, rightMargin=2*cm,
        topMargin=2*cm, bottomMargin=2*cm
    )

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle("title", parent=styles["Title"],
                                  fontSize=22, textColor=BRAND_DARK, spaceAfter=6)
    h2_style = ParagraphStyle("h2", parent=styles["Heading2"],
                               fontSize=14, textColor=BRAND_BLUE, spaceBefore=18, spaceAfter=8)
    body_style = ParagraphStyle("body", parent=styles["Normal"],
                                 fontSize=10, textColor=BRAND_DARK, spaceAfter=4)
    small_style = ParagraphStyle("small", parent=styles["Normal"],
                                  fontSize=8, textColor=BRAND_GRAY)

    story = []

    story.append(Paragraph("Copilot Data Exposure Report", title_style))
    story.append(Paragraph(
        f"Tenant: {result.tenant_id[:8]}... | Scanned: {result.scanned_at[:10]} | "
        f"Confidential - for IT Admin use only",
        small_style
    ))
    story.append(HRFlowable(width="100%", thickness=1, color=BRAND_BLUE, spaceAfter=14))

    summary_data = [
        ["AI Readiness Score", "Grade", "Critical", "High", "Medium", "Items Scanned"],
        [
            str(result.ai_readiness_score) + "/100",
            result.risk_grade,
            str(len(result.critical_items)),
            str(len(result.high_items)),
            str(len(result.medium_items)),
            str(result.total_items_scanned),
        ]
    ]
    summary_table = Table(summary_data, colWidths=[3.5*cm]*6)
    summary_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), BRAND_DARK),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, 0), 9),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("FONTSIZE", (0, 1), (-1, 1), 14),
        ("FONTNAME", (0, 1), (-1, 1), "Helvetica-Bold"),
        ("TEXTCOLOR", (2, 1), (2, 1), BRAND_RED),
        ("TEXTCOLOR", (3, 1), (3, 1), BRAND_ORANGE),
        ("TEXTCOLOR", (4, 1), (4, 1), BRAND_YELLOW),
        ("ROWBACKGROUNDS", (0, 1), (-1, 1), [BRAND_LIGHT]),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
    ]))
    story.append(summary_table)
    story.append(Spacer(1, 16))

    story.append(Paragraph("Score Breakdown", h2_style))
    for label, detail in result.score_breakdown.items():
        story.append(Paragraph(f"- {label}: {detail}", body_style))
    story.append(Spacer(1, 12))

    story.append(Paragraph("Findings", h2_style))
    story.append(Paragraph(
        f"Copilot can traverse {result.total_items_scanned:,} items across "
        f"{result.total_sites} SharePoint sites.",
        body_style
    ))
    story.append(Spacer(1, 8))

    all_items = result.critical_items + result.high_items + result.medium_items
    shown_items = all_items[:redact_after] if redact_after else all_items

    for item in shown_items:
        rc = _risk_color(item.risk_level)
        item_data = [
            [Paragraph(f"{item.risk_level.upper()}", body_style),
             Paragraph(f"{item.name}", body_style),
             Paragraph(item.site_name, small_style)],
            [Paragraph("Permission", small_style),
             Paragraph(item.permission_type, body_style),
             Paragraph(f"Granted to: {item.granted_to}", small_style)],
            [Paragraph("Risk", small_style),
             Paragraph("; ".join(item.risk_reasons), body_style), ""],
            [Paragraph("Fix", small_style),
             Paragraph(item.remediation, small_style), ""],
        ]
        t = Table(item_data, colWidths=[2.5*cm, 10*cm, 4.5*cm])
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (0, 0), rc),
            ("TEXTCOLOR", (0, 0), (0, 0), colors.white),
            ("FONTNAME", (0, 0), (0, 0), "Helvetica-Bold"),
            ("SPAN", (1, 2), (2, 2)),
            ("SPAN", (1, 3), (2, 3)),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#E2E8F0")),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ]))
        story.append(KeepTogether([t, Spacer(1, 6)]))

    remaining = len(all_items) - len(shown_items)
    if redact_after and remaining > 0:
        story.append(Spacer(1, 10))
        notice_data = [[
            Paragraph(
                f"{remaining} additional findings redacted. "
                "Unlock the full report + PowerShell remediation playbook for $999. "
                "Contact: hello@copilotfirewall.io",
                body_style
            )
        ]]
        nt = Table(notice_data, colWidths=[17*cm])
        nt.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#FEF9C3")),
            ("GRID", (0, 0), (-1, -1), 0.5, BRAND_YELLOW),
            ("TOPPADDING", (0, 0), (-1, -1), 10),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
            ("LEFTPADDING", (0, 0), (-1, -1), 12),
        ]))
        story.append(nt)

    story.append(Spacer(1, 20))
    story.append(HRFlowable(width="100%", thickness=0.5, color=BRAND_GRAY))
    story.append(Spacer(1, 6))
    story.append(Paragraph(
        "Generated by Copilot Firewall - Read-only Graph API scan. No files were accessed or stored.",
        small_style
    ))

    doc.build(story)
    return buf.getvalue()
