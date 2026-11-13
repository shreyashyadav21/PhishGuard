from typing import List, Dict, Any
from .indicators import IndicatorResult

def calculate_risk(indicators: List[IndicatorResult], positive_observations: List[str] = None) -> Dict[str, Any]:
    """
    Calculates weighted risk score (0-100), applies category caps to avoid
    over-penalizing correlated signals, and determines severity classification.
    """
    if positive_observations is None:
        positive_observations = []

    # Category caps to prevent correlated score runaway
    category_caps = {
        "protocol": 10,
        "ip_hostname": 25,
        "url_structure": 25,
        "suspicious_chars": 20,
        "keywords": 20,
        "domain_impersonation": 35,
        "domain": 15,
        "encoding": 15,
        "email_urgency": 20,
        "email_credentials": 30,
        "email_sender_mismatch": 30,
        "email_social_engineering": 20,
        "email_links": 35,
    }

    # Sum points per category with cap
    category_totals: Dict[str, int] = {}
    itemized_indicators = []

    for ind in indicators:
        cat = ind.category
        category_totals[cat] = category_totals.get(cat, 0) + ind.points
        itemized_indicators.append({
            "name": ind.name,
            "severity": ind.severity,
            "points": ind.points,
            "description": ind.description,
            "category": ind.category,
            "evidence": ind.evidence
        })

    # Apply caps
    raw_score = 0
    for cat, total in category_totals.items():
        cap = category_caps.get(cat, 35)
        raw_score += min(total, cap)

    # If domain is verified official, provide safety discount
    for obs in positive_observations:
        if "recognized legitimate infrastructure" in obs.lower():
            raw_score = max(0, raw_score - 20)

    # Cap score at 100
    final_score = min(100, max(0, raw_score))

    # Classify
    if final_score >= 70:
        classification = "critical"
        classification_label = "Critical Risk"
        badge_color = "red"
    elif final_score >= 40:
        classification = "high"
        classification_label = "High Risk"
        badge_color = "orange"
    elif final_score >= 20:
        classification = "suspicious"
        classification_label = "Suspicious"
        badge_color = "amber"
    else:
        classification = "safe"
        classification_label = "Low Risk"
        badge_color = "emerald"

    return {
        "risk_score": final_score,
        "classification": classification,
        "classification_label": classification_label,
        "badge_color": badge_color,
        "indicators": itemized_indicators,
        "positive_observations": positive_observations,
        "indicator_count": len(itemized_indicators)
    }

