import io
from datetime import datetime
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.units import inch
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle

def generate_pdf_report(scan_data: dict) -> io.BytesIO:
    """
    Generates a professional, branded cybersecurity analysis PDF report
    for a URL or email scan using ReportLab.
    """
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        rightMargin=40,
        leftMargin=40,
        topMargin=40,
        bottomMargin=40
    )

    styles = getSampleStyleSheet()

    # Custom styles
    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=20,
        textColor=colors.HexColor("#080E19"),
        leading=24
    )
    subtitle_style = ParagraphStyle(
        'Subtitle',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=10,
        textColor=colors.HexColor("#4B5563"),
        leading=14
    )
    section_heading = ParagraphStyle(
        'SectionHeading',
        parent=styles['Heading2'],
        fontName='Helvetica-Bold',
        fontSize=12,
        textColor=colors.HexColor("#101A2B"),
        spaceBefore=12,
        spaceAfter=6
    )
    body_style = ParagraphStyle(
        'Body',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=9,
        textColor=colors.HexColor("#1F2937"),
        leading=13
    )
    mono_style = ParagraphStyle(
        'Mono',
        parent=styles['Normal'],
        fontName='Courier',
        fontSize=9,
        textColor=colors.HexColor("#111827"),
        leading=12
    )
    disclaimer_style = ParagraphStyle(
        'Disclaimer',
        parent=styles['Normal'],
        fontName='Helvetica-Oblique',
        fontSize=8,
        textColor=colors.HexColor("#6B7280"),
        leading=11
    )

    elements = []

    # Header Bar
    report_id = f"PG-RPT-{scan_data.get('id', 'LIVE'):05d}" if isinstance(scan_data.get('id'), int) else f"PG-RPT-{scan_data.get('id', 'LIVE')}"
    scan_date = scan_data.get("created_at")
    date_str = scan_date.strftime("%Y-%m-%d %H:%M:%S UTC") if isinstance(scan_date, datetime) else str(scan_date or datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"))

    header_table_data = [
        [
            Paragraph("<b>PHISHGUARD</b> &nbsp;|&nbsp; Threat Intelligence & Phishing Analysis", title_style),
            Paragraph(f"<b>Report ID:</b> {report_id}<br/><b>Date:</b> {date_str}", subtitle_style)
        ]
    ]
    header_table = Table(header_table_data, colWidths=[4.2 * inch, 2.8 * inch])
    header_table.setStyle(TableStyle([
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('ALIGN', (1, 0), (1, 0), 'RIGHT'),
    ]))
    elements.append(header_table)
    elements.append(Spacer(1, 10))
    elements.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor("#00D4FF"), spaceBefore=0, spaceAfter=15))

    # Executive Summary Card
    risk_score = scan_data.get("risk_score", 0)
    classification = scan_data.get("classification_label", scan_data.get("classification", "Unknown")).upper()
    scan_type = scan_data.get("scan_type", "url").upper()
    submitted = scan_data.get("submitted_item", "N/A")

    # Score color
    if risk_score >= 70:
        score_color = colors.HexColor("#FF4D67")
        badge_bg = colors.HexColor("#FFE5E8")
    elif risk_score >= 40:
        score_color = colors.HexColor("#FF8C00")
        badge_bg = colors.HexColor("#FFF3E0")
    elif risk_score >= 20:
        score_color = colors.HexColor("#FFB020")
        badge_bg = colors.HexColor("#FFF9C4")
    else:
        score_color = colors.HexColor("#00E6A0")
        badge_bg = colors.HexColor("#E8F8F0")

    summary_data = [
        [
            Paragraph(f"<b>Scan Target Type:</b> {scan_type}<br/><b>Submitted Target:</b><br/>{submitted[:120]}", body_style),
            Paragraph(
                f"<div align='center'><font size='18' color='{score_color.hexval()}'><b>{risk_score}/100</b></font><br/>"
                f"<font size='10' color='{score_color.hexval()}'><b>{classification}</b></font></div>",
                body_style
            )
        ]
    ]
    summary_table = Table(summary_data, colWidths=[5.0 * inch, 2.0 * inch])
    summary_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor("#F8FAFC")),
        ('BOX', (0, 0), (-1, -1), 1, colors.HexColor("#E2E8F0")),
        ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
        ('PADDING', (0, 0), (-1, -1), 10),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
    ]))
    elements.append(summary_table)
    elements.append(Spacer(1, 15))

    # Detected Indicators Table
    elements.append(Paragraph("Detected Security & Threat Indicators", section_heading))
    indicators = scan_data.get("indicators", [])

    if indicators:
        ind_table_data = [
            [
                Paragraph("<b>Indicator Name</b>", body_style),
                Paragraph("<b>Severity</b>", body_style),
                Paragraph("<b>Points</b>", body_style),
                Paragraph("<b>Technical Analysis / Description</b>", body_style)
            ]
        ]
        for ind in indicators:
            sev = ind.get("severity", "medium").upper()
            ind_table_data.append([
                Paragraph(f"<b>{ind.get('name', 'Indicator')}</b>", body_style),
                Paragraph(f"<font color='#B91C1C'><b>{sev}</b></font>" if sev in ("CRITICAL", "HIGH") else f"<b>{sev}</b>", body_style),
                Paragraph(f"+{ind.get('points', 0)}", body_style),
                Paragraph(f"{ind.get('description', '')}", body_style)
            ])
        ind_table = Table(ind_table_data, colWidths=[1.8 * inch, 0.9 * inch, 0.7 * inch, 3.6 * inch])
        ind_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#F1F5F9")),
            ('BOX', (0, 0), (-1, -1), 1, colors.HexColor("#CBD5E1")),
            ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
            ('PADDING', (0, 0), (-1, -1), 6),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ]))
        elements.append(ind_table)
    else:
        elements.append(Paragraph("<i>No suspicious threat indicators were flagged during static evaluation.</i>", body_style))

    elements.append(Spacer(1, 15))

    # Positive Security Observations
    positive_obs = scan_data.get("positive_observations", [])
    if positive_obs:
        elements.append(Paragraph("Positive Security Observations", section_heading))
        for obs in positive_obs:
            elements.append(Paragraph(f"• {obs}", body_style))
        elements.append(Spacer(1, 10))

    # Recommendations
    elements.append(Paragraph("Prescribed Security Recommendations", section_heading))
    recs = scan_data.get("recommendations", [])
    if recs:
        for idx, rec in enumerate(recs, 1):
            elements.append(Paragraph(f"<b>{idx}.</b> {rec}", body_style))
    else:
        elements.append(Paragraph("No specific remediation required for this target.", body_style))

    elements.append(Spacer(1, 20))

    # Disclaimer Footer
    elements.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#CBD5E1"), spaceBefore=5, spaceAfter=8))
    elements.append(Paragraph(
        "<b>PhishGuard Heuristic Disclaimer:</b> This threat assessment report was generated automatically via "
        "static heuristic analysis, brand distance scoring, and local rule matching. No external outbound network "
        "connections were initiated to the target URL to eliminate Server-Side Request Forgery (SSRF) risk. "
        "Scores reflect estimated likelihood based on observed patterns and must be evaluated alongside organizational policies.",
        disclaimer_style
    ))

    doc.build(elements)
    buffer.seek(0)
    return buffer

