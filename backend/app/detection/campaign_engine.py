import datetime
import json
from typing import List, Dict, Any, Optional
from sqlalchemy.orm import Session
from ..models import Scan, Campaign, CampaignEmail

def correlate_campaigns(db: Session) -> List[Dict[str, Any]]:
    """
    Analyzes historical email scans to detect coordinated phishing campaigns
    based on shared brand targets, sender domains, repeated lure hosts, and subjects.
    Creates or updates Campaign database records with evidence.
    """
    email_scans = db.query(Scan).filter(Scan.scan_type == "email").order_by(Scan.created_at.desc()).all()

    # Clusters grouped by (target_brand, common_domain) or subject keywords
    clusters: Dict[str, List[Scan]] = {}

    for scan in email_scans:
        try:
            data = json.loads(scan.analysis_json)
        except Exception:
            continue

        # Extract cluster keys
        sender = data.get("sender", "")
        domain = sender.split("@")[-1].replace(">", "").strip().lower() if "@" in sender else ""
        
        # Check brand target from indicators
        brand = "Generic Threat"
        for ind in data.get("indicators", []):
            name = ind.get("name", "").lower()
            desc = ind.get("description", "").lower()
            for b in ["paypal", "microsoft", "google", "apple", "amazon", "netflix", "sbi", "hdfc", "icici"]:
                if b in name or b in desc:
                    brand = b.upper()
                    break
            if brand != "Generic Threat":
                break

        cluster_key = f"{brand}::{domain}" if domain else f"{brand}::heuristics"
        clusters.setdefault(cluster_key, []).append(scan)

    detected_campaigns = []

    for cluster_key, group in clusters.items():
        if len(group) >= 2:
            brand_part, domain_part = cluster_key.split("::")
            campaign_name = f"Campaign: {brand_part} Lure via {domain_part or 'Distributed Hosts'}"

            # Calculate metrics
            avg_score = sum(s.risk_score for s in group) / len(group)
            severity = "Critical" if avg_score >= 70 else ("High" if avg_score >= 40 else "Medium")
            first_seen = min(s.created_at for s in group)
            last_seen = max(s.created_at for s in group)
            confidence = min(95, 60 + len(group) * 10)

            # Check if campaign already exists in DB
            existing_camp = db.query(Campaign).filter(Campaign.name == campaign_name).first()
            if existing_camp:
                existing_camp.email_count = len(group)
                existing_camp.last_observed = last_seen
                existing_camp.severity = severity
                existing_camp.confidence_score = confidence
                camp_id = existing_camp.id
            else:
                new_camp = Campaign(
                    name=campaign_name,
                    target_brand=brand_part,
                    common_sender_domain=domain_part,
                    common_subject_pattern=group[0].submitted_item[:200],
                    severity=severity,
                    confidence_score=confidence,
                    email_count=len(group),
                    first_observed=first_seen,
                    last_observed=last_seen
                )
                db.add(new_camp)
                db.flush()
                camp_id = new_camp.id

                # Link emails
                for s in group:
                    db.add(CampaignEmail(campaign_id=camp_id, scan_id=s.id))

            detected_campaigns.append({
                "id": camp_id,
                "name": campaign_name,
                "target_brand": brand_part,
                "common_domain": domain_part or "Multi-Origin",
                "email_count": len(group),
                "severity": severity,
                "confidence_score": confidence,
                "first_observed": first_seen.isoformat(),
                "last_observed": last_seen.isoformat(),
                "related_scan_ids": [s.id for s in group]
            })

    db.commit()
    return detected_campaigns

