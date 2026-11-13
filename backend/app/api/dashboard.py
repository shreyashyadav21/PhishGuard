import datetime
import json
from collections import defaultdict
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from sqlalchemy import func
from ..database import get_db
from ..models import Scan, Indicator
from ..schemas import DashboardStatsResponse, ScanSummaryItem

router = APIRouter(prefix="/dashboard", tags=["Dashboard"])

@router.get("/stats")
def get_dashboard_stats(days: int = Query(default=30, ge=7, le=90), db: Session = Depends(get_db)):
    total_scans = db.query(Scan).count()

    safe_count = db.query(Scan).filter(Scan.risk_score < 20).count()
    suspicious_count = db.query(Scan).filter(Scan.risk_score >= 20, Scan.risk_score < 40).count()
    high_count = db.query(Scan).filter(Scan.risk_score >= 40, Scan.risk_score < 70).count()
    critical_count = db.query(Scan).filter(Scan.risk_score >= 70).count()

    high_risk_combined = high_count + critical_count
    threat_scans = suspicious_count + high_risk_combined

    detection_rate = round((threat_scans / total_scans * 100), 1) if total_scans > 0 else 0.0

    threat_distribution = {
        "safe": safe_count,
        "suspicious": suspicious_count,
        "high_risk": high_count,
        "critical": critical_count
    }

    # Threat category frequency by analyzing Indicator records
    category_counts = {
        "Domain Impersonation": 0,
        "Phishing Keywords": 0,
        "URL Obfuscation": 0,
        "Credential Harvesting": 0,
        "Social Engineering": 0,
        "Insecure Protocol / IP": 0,
    }

    indicators = db.query(Indicator).all()
    for ind in indicators:
        name = ind.indicator_name.lower()
        if "impersonation" in name or "typosquatting" in name:
            category_counts["Domain Impersonation"] += 1
        elif "keyword" in name:
            category_counts["Phishing Keywords"] += 1
        elif "percent" in name or "encoding" in name or "redirect" in name or "long url" in name:
            category_counts["URL Obfuscation"] += 1
        elif "credential" in name or "password" in name or "otp" in name:
            category_counts["Credential Harvesting"] += 1
        elif "urgency" in name or "social engineering" in name or "lure" in name:
            category_counts["Social Engineering"] += 1
        elif "http" in name or "ip address" in name or "port" in name:
            category_counts["Insecure Protocol / IP"] += 1

    # Daily scan activity over requested timeline (7, 30, or 90 days)
    cutoff = datetime.datetime.utcnow() - datetime.timedelta(days=days)
    recent_records = db.query(Scan).filter(Scan.created_at >= cutoff).order_by(Scan.created_at.asc()).all()

    daily_map = defaultdict(lambda: {"date": "", "total": 0, "safe": 0, "suspicious": 0, "high_risk": 0})

    # Prepopulate each date in range so chart is continuous
    for i in range(days):
        d = (datetime.datetime.utcnow() - datetime.timedelta(days=days - 1 - i)).strftime("%b %d")
        daily_map[d] = {"date": d, "total": 0, "safe": 0, "suspicious": 0, "high_risk": 0}

    for scan in recent_records:
        day_str = scan.created_at.strftime("%b %d")
        entry = daily_map[day_str]
        entry["total"] += 1
        if scan.risk_score < 20:
            entry["safe"] += 1
        elif scan.risk_score < 40:
            entry["suspicious"] += 1
        else:
            entry["high_risk"] += 1

    activity_timeline = list(daily_map.values())

    # Recent scans list (last 8)
    recent_scans_raw = db.query(Scan).order_by(Scan.created_at.desc()).limit(8).all()
    recent_scans = []
    for s in recent_scans_raw:
        recent_scans.append({
            "id": s.id,
            "scan_type": s.scan_type,
            "submitted_item": s.submitted_item,
            "risk_score": s.risk_score,
            "classification": s.classification,
            "classification_label": "Critical Risk" if s.risk_score >= 70 else ("High Risk" if s.risk_score >= 40 else ("Suspicious" if s.risk_score >= 20 else "Low Risk")),
            "badge_color": "red" if s.risk_score >= 70 else ("orange" if s.risk_score >= 40 else ("amber" if s.risk_score >= 20 else "emerald")),
            "created_at": s.created_at,
            "indicator_count": len(s.indicators)
        })

    return {
        "total_scans": total_scans,
        "safe_scans": safe_count,
        "suspicious_scans": suspicious_count,
        "high_risk_scans": high_count,
        "critical_scans": critical_count,
        "threat_detection_rate": detection_rate,
        "threat_distribution": threat_distribution,
        "category_counts": category_counts,
        "activity_timeline": activity_timeline,
        "recent_scans": recent_scans
    }

