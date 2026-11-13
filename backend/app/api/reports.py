import json
from fastapi import APIRouter, Depends, HTTPException, Response
from sqlalchemy.orm import Session
from ..database import get_db
from ..models import Scan
from ..services.report_generator import generate_pdf_report

router = APIRouter(prefix="/reports", tags=["Security Reports"])

@router.get("/{scan_id}/pdf")
def download_scan_pdf(scan_id: int, db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail=f"Scan record {scan_id} not found")

    try:
        analysis_data = json.loads(scan.analysis_json)
    except Exception:
        analysis_data = {}

    indicators = [
        {
            "name": ind.indicator_name,
            "severity": ind.severity,
            "points": ind.risk_points,
            "description": ind.description
        }
        for ind in scan.indicators
    ]

    recommendations = [rec.recommendation_text for rec in scan.recommendations]

    report_payload = {
        "id": scan.id,
        "scan_type": scan.scan_type,
        "submitted_item": scan.submitted_item,
        "risk_score": scan.risk_score,
        "classification": scan.classification,
        "classification_label": analysis_data.get("classification_label", scan.classification.title()),
        "created_at": scan.created_at,
        "indicators": indicators,
        "recommendations": recommendations,
        "positive_observations": analysis_data.get("positive_observations", [])
    }

    pdf_buffer = generate_pdf_report(report_payload)
    pdf_bytes = pdf_buffer.getvalue()

    filename = f"PhishGuard_Report_PG-{scan.id:05d}.pdf"

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"'
        }
    )

