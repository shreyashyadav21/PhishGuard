from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from typing import Optional, List
from ..database import get_db
from ..models import SecurityEvent

router = APIRouter(prefix="/timeline", tags=["Threat Timeline"])

@router.get("")
def get_threat_timeline(
    severity: Optional[str] = None,
    event_type: Optional[str] = None,
    search: Optional[str] = None,
    limit: int = Query(default=50, ge=1, le=200),
    db: Session = Depends(get_db)
):
    """
    Returns Personal Threat Timeline events (emails detected, threats identified,
    quarantined items, user actions, campaign correlations).
    """
    query = db.query(SecurityEvent)

    if severity and severity.lower() != "all":
        query = query.filter(SecurityEvent.severity.ilike(severity))

    if event_type and event_type.lower() != "all":
        query = query.filter(SecurityEvent.event_type == event_type.lower())

    if search:
        search_filter = f"%{search.strip()}%"
        query = query.filter(
            (SecurityEvent.title.ilike(search_filter)) |
            (SecurityEvent.description.ilike(search_filter)) |
            (SecurityEvent.target_item.ilike(search_filter))
        )

    events = query.order_by(SecurityEvent.created_at.desc()).limit(limit).all()

    return [
        {
            "id": ev.id,
            "event_type": ev.event_type,
            "title": ev.title,
            "description": ev.description,
            "severity": ev.severity,
            "target_item": ev.target_item,
            "scan_id": ev.scan_id,
            "created_at": ev.created_at.isoformat() if ev.created_at else None
        }
        for ev in events
    ]

