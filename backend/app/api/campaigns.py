from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from ..database import get_db
from ..models import Campaign
from ..detection.campaign_engine import correlate_campaigns

router = APIRouter(prefix="/campaigns", tags=["Campaign Detection"])

@router.get("")
def list_campaigns(db: Session = Depends(get_db)):
    """Returns detected phishing campaigns with cluster metrics."""
    # Run correlation on demand
    correlate_campaigns(db)
    campaigns = db.query(Campaign).order_by(Campaign.last_observed.desc()).all()

    return [
        {
            "id": c.id,
            "name": c.name,
            "target_brand": c.target_brand,
            "common_domain": c.common_sender_domain or "Multi-Origin",
            "common_subject": c.common_subject_pattern,
            "severity": c.severity,
            "confidence_score": c.confidence_score,
            "email_count": c.email_count,
            "first_observed": c.first_observed.isoformat() if c.first_observed else None,
            "last_observed": c.last_observed.isoformat() if c.last_observed else None
        }
        for c in campaigns
    ]

@router.post("/correlate")
def run_correlation(db: Session = Depends(get_db)):
    """Triggers an active correlation run across all historical email scans."""
    results = correlate_campaigns(db)
    return {"status": "success", "correlated_campaigns_count": len(results), "campaigns": results}

