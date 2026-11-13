from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from ..database import get_db
from ..models import ThreatIndicator

router = APIRouter(prefix="/threats", tags=["Threat Intelligence"])

@router.get("")
def list_threats(
    category: Optional[str] = None,
    severity: Optional[str] = None,
    search: Optional[str] = None,
    db: Session = Depends(get_db)
):
    query = db.query(ThreatIndicator)

    if category and category.lower() != "all":
        query = query.filter(ThreatIndicator.category.ilike(f"%{category}%"))

    if severity and severity.lower() != "all":
        query = query.filter(ThreatIndicator.severity.ilike(severity))

    if search:
        search_term = f"%{search.strip()}%"
        query = query.filter(
            (ThreatIndicator.indicator_value.ilike(search_term)) |
            (ThreatIndicator.detection_reason.ilike(search_term))
        )

    records = query.order_by(ThreatIndicator.scan_count.desc(), ThreatIndicator.first_observed.desc()).all()

    # Calculate summary metrics for the SOC threat intel header
    critical_count = sum(1 for r in records if r.severity.lower() == "critical")
    high_count = sum(1 for r in records if r.severity.lower() == "high")
    total_observed_scans = sum(r.scan_count for r in records)

    return {
        "total_threats": len(records),
        "critical_count": critical_count,
        "high_count": high_count,
        "total_observed_scans": total_observed_scans,
        "items": [
            {
                "id": r.id,
                "indicator_value": r.indicator_value,
                "category": r.category,
                "severity": r.severity,
                "detection_reason": r.detection_reason,
                "first_observed": r.first_observed.isoformat(),
                "scan_count": r.scan_count,
                "is_simulated": r.is_simulated,
                "recommended_action": r.recommended_action
            }
            for r in records
        ]
    }


@router.get("/{threat_id}")
def get_threat_detail(threat_id: int, db: Session = Depends(get_db)):
    threat = db.query(ThreatIndicator).filter(ThreatIndicator.id == threat_id).first()
    if not threat:
        raise HTTPException(status_code=404, detail=f"Threat indicator {threat_id} not found")

    return {
        "id": threat.id,
        "indicator_value": threat.indicator_value,
        "category": threat.category,
        "severity": threat.severity,
        "detection_reason": threat.detection_reason,
        "first_observed": threat.first_observed.isoformat(),
        "scan_count": threat.scan_count,
        "is_simulated": threat.is_simulated,
        "recommended_action": threat.recommended_action
    }

