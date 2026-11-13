import json
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from ..database import get_db
from ..models import Scan

router = APIRouter(prefix="/scans", tags=["Scan History"])

@router.get("")
def list_scans(
    search: Optional[str] = None,
    scan_type: Optional[str] = None,
    classification: Optional[str] = None,
    sort_order: str = Query(default="desc", pattern="^(asc|desc)$"),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db)
):
    query = db.query(Scan)

    if scan_type and scan_type.lower() != "all":
        query = query.filter(Scan.scan_type == scan_type.lower())

    if classification and classification.lower() != "all":
        query = query.filter(Scan.classification == classification.lower())

    if search:
        search_filter = f"%{search.strip()}%"
        query = query.filter(Scan.submitted_item.ilike(search_filter))

    total = query.count()

    if sort_order == "desc":
        query = query.order_by(Scan.created_at.desc())
    else:
        query = query.order_by(Scan.created_at.asc())

    records = query.offset(offset).limit(limit).all()

    items = []
    for s in records:
        badge = "red" if s.risk_score >= 70 else ("orange" if s.risk_score >= 40 else ("amber" if s.risk_score >= 20 else "emerald"))
        label = "Critical Risk" if s.risk_score >= 70 else ("High Risk" if s.risk_score >= 40 else ("Suspicious" if s.risk_score >= 20 else "Low Risk"))
        items.append({
            "id": s.id,
            "scan_type": s.scan_type,
            "submitted_item": s.submitted_item,
            "risk_score": s.risk_score,
            "classification": s.classification,
            "classification_label": label,
            "badge_color": badge,
            "created_at": s.created_at,
            "indicator_count": len(s.indicators)
        })

    return {
        "total": total,
        "limit": limit,
        "offset": offset,
        "items": items
    }


@router.get("/{scan_id}")
def get_scan_detail(scan_id: int, db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail=f"Scan with ID {scan_id} not found")

    try:
        analysis_data = json.loads(scan.analysis_json)
    except Exception:
        analysis_data = {}

    indicators = [
        {
            "id": ind.id,
            "name": ind.indicator_name,
            "severity": ind.severity,
            "points": ind.risk_points,
            "description": ind.description
        }
        for ind in scan.indicators
    ]

    recommendations = [rec.recommendation_text for rec in scan.recommendations]

    return {
        "id": scan.id,
        "scan_type": scan.scan_type,
        "submitted_item": scan.submitted_item,
        "risk_score": scan.risk_score,
        "classification": scan.classification,
        "classification_label": analysis_data.get("classification_label", "Risk Evaluation"),
        "badge_color": analysis_data.get("badge_color", "slate"),
        "created_at": scan.created_at,
        "analysis_details": analysis_data,
        "indicators": indicators,
        "recommendations": recommendations,
        "positive_observations": analysis_data.get("positive_observations", [])
    }


@router.delete("/{scan_id}")
def delete_scan(scan_id: int, db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail=f"Scan with ID {scan_id} not found")

    db.delete(scan)
    db.commit()
    return {"message": f"Scan {scan_id} successfully removed", "id": scan_id}


@router.delete("")
def clear_all_scans(confirm: bool = Query(default=False), db: Session = Depends(get_db)):
    if not confirm:
        raise HTTPException(status_code=400, detail="Confirmation required to delete all scan records (confirm=true)")

    deleted_count = db.query(Scan).delete()
    db.commit()
    return {"message": "All scan records deleted successfully", "deleted_count": deleted_count}
