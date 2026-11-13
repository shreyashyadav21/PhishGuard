import json
import datetime
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from ..database import get_db
from ..models import Scan, Indicator, Recommendation, Setting, ThreatIndicator
from ..schemas import URLScanRequest, EmailScanRequest
from ..detection.url_analyzer import analyze_url
from ..detection.email_analyzer import analyze_email

router = APIRouter(prefix="/scan", tags=["Scanning"])

@router.post("/url")
def scan_url_endpoint(payload: URLScanRequest, db: Session = Depends(get_db)):
    url = payload.url.strip()
    if not url:
        raise HTTPException(status_code=400, detail="URL cannot be empty")

    analysis = analyze_url(url)

    # Persist to database
    scan_obj = Scan(
        scan_type="url",
        submitted_item=url,
        risk_score=analysis["risk_score"],
        classification=analysis["classification"],
        created_at=datetime.datetime.utcnow(),
        analysis_json=json.dumps(analysis)
    )
    db.add(scan_obj)
    db.flush()

    for ind in analysis.get("indicators", []):
        db.add(Indicator(
            scan_id=scan_obj.id,
            indicator_name=ind.get("name", "Indicator"),
            severity=ind.get("severity", "medium"),
            risk_points=ind.get("points", 0),
            description=ind.get("description", "")
        ))

    for rec in analysis.get("recommendations", []):
        db.add(Recommendation(
            scan_id=scan_obj.id,
            recommendation_text=rec
        ))

    # If critical / high risk, auto-aggregate into local threat intelligence indicators table
    hostname = analysis.get("parsed_details", {}).get("hostname")
    if hostname and analysis["risk_score"] >= 40:
        existing_threat = db.query(ThreatIndicator).filter(
            ThreatIndicator.indicator_value == hostname
        ).first()

        category = "Domain Impersonation" if any("impersonation" in i["name"].lower() for i in analysis.get("indicators", [])) else "Suspicious URL Structure"
        severity = "Critical" if analysis["risk_score"] >= 70 else "High"
        top_reason = analysis["indicators"][0]["description"] if analysis.get("indicators") else "High-risk URL scan"

        if existing_threat:
            existing_threat.scan_count += 1
            existing_threat.severity = severity
        else:
            db.add(ThreatIndicator(
                indicator_value=hostname,
                category=category,
                severity=severity,
                detection_reason=top_reason,
                first_observed=datetime.datetime.utcnow(),
                scan_count=1,
                is_simulated=False,
                recommended_action="Block domain across network perimeter; warn users against interaction."
            ))

    db.commit()
    db.refresh(scan_obj)

    analysis["id"] = scan_obj.id
    analysis["created_at"] = scan_obj.created_at.isoformat()
    return analysis


@router.post("/email")
def scan_email_endpoint(payload: EmailScanRequest, db: Session = Depends(get_db)):
    # Check privacy setting
    privacy_setting = db.query(Setting).filter(Setting.setting_key == "store_email_body").first()
    store_body = privacy_setting.setting_value.lower() == "true" if privacy_setting else False

    email_dict = payload.model_dump()
    analysis = analyze_email(email_dict)

    # Privacy preservation: sanitize stored payload
    sanitized_analysis = dict(analysis)
    if not store_body:
        sanitized_analysis["email_body_stored"] = False
        # Do not persist the full raw body to the DB
    else:
        sanitized_analysis["email_body_stored"] = True

    submitted_label = payload.subject or payload.sender or "Analyzed Email Content"

    scan_obj = Scan(
        scan_type="email",
        submitted_item=submitted_label,
        risk_score=analysis["risk_score"],
        classification=analysis["classification"],
        created_at=datetime.datetime.utcnow(),
        analysis_json=json.dumps(sanitized_analysis)
    )
    db.add(scan_obj)
    db.flush()

    for ind in analysis.get("indicators", []):
        db.add(Indicator(
            scan_id=scan_obj.id,
            indicator_name=ind.get("name", "Indicator"),
            severity=ind.get("severity", "medium"),
            risk_points=ind.get("points", 0),
            description=ind.get("description", "")
        ))

    for rec in analysis.get("recommendations", []):
        db.add(Recommendation(
            scan_id=scan_obj.id,
            recommendation_text=rec
        ))

    # If email contains malicious domain/sender and high score, add to threats
    sender = payload.sender
    if sender and analysis["risk_score"] >= 40:
        clean_sender = sender.split("<")[-1].replace(">", "").strip()
        existing_threat = db.query(ThreatIndicator).filter(
            ThreatIndicator.indicator_value == clean_sender
        ).first()

        category = "Credential Theft" if any("credential" in i["name"].lower() for i in analysis.get("indicators", [])) else "Social Engineering"
        severity = "Critical" if analysis["risk_score"] >= 70 else "High"
        top_reason = analysis["indicators"][0]["description"] if analysis.get("indicators") else "High-risk email sender"

        if existing_threat:
            existing_threat.scan_count += 1
            existing_threat.severity = severity
        else:
            db.add(ThreatIndicator(
                indicator_value=clean_sender,
                category=category,
                severity=severity,
                detection_reason=top_reason,
                first_observed=datetime.datetime.utcnow(),
                scan_count=1,
                is_simulated=False,
                recommended_action="Quarantine sender address and add to mail gateway blocklist."
            ))

    db.commit()
    db.refresh(scan_obj)

    analysis["id"] = scan_obj.id
    analysis["created_at"] = scan_obj.created_at.isoformat()
    return analysis
