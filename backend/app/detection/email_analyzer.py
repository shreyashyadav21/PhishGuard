import re
from typing import Dict, Any, List, Tuple
from .indicators import (
    IndicatorResult,
    CREDENTIAL_REQUEST_TERMS,
    URGENCY_TERMS,
    SOCIAL_ENGINEERING_TERMS,
    KNOWN_BRANDS
)
from .domain_analyzer import check_domain_reputation
from .url_analyzer import analyze_url
from .risk_scoring import calculate_risk
from .recommendations import generate_recommendations

URL_REGEX = re.compile(
    r'(?:https?://|www\.)[a-zA-Z0-9][-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b[-a-zA-Z0-9()@:%_\+.~#?&//=]*',
    re.IGNORECASE
)
EMAIL_ADDR_REGEX = re.compile(r'[\w\.-]+@[\w\.-]+\.\w+')

def parse_email_sender(sender_str: str) -> Tuple[str, str, str]:
    """
    Parses display name, email address, and domain from a sender string.
    e.g. 'PayPal Security <security@paypa1-update.com>' -> ('PayPal Security', 'security@paypa1-update.com', 'paypa1-update.com')
    """
    if not sender_str:
        return "", "", ""

    display_name = ""
    email_addr = ""
    domain = ""

    # Check for 'Display Name <email@domain.com>'
    match = re.match(r'^(.*?)\s*<([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})>$', sender_str.strip())
    if match:
        display_name = match.group(1).strip('"\'' )
        email_addr = match.group(2).lower()
    else:
        # Check if just email address
        emails = EMAIL_ADDR_REGEX.findall(sender_str)
        if emails:
            email_addr = emails[0].lower()
            display_name = sender_str.replace(email_addr, "").strip(' <>\'":')
        else:
            display_name = sender_str

    if '@' in email_addr:
        domain = email_addr.split('@')[1].lower()

    return display_name, email_addr, domain

def extract_urls_from_text(text: str) -> List[str]:
    """Extracts all unique URLs from plain text or HTML body."""
    raw_urls = URL_REGEX.findall(text)
    # Extract href links specifically if HTML
    href_urls = re.findall(r'href=[\'"]?([^\'" >]+)', text, re.IGNORECASE)
    all_urls = list(dict.fromkeys(raw_urls + href_urls))
    clean_urls = []
    for u in all_urls:
        if not u.startswith('http://') and not u.startswith('https://'):
            clean_urls.append('http://' + u)
        else:
            clean_urls.append(u)
    return clean_urls

def analyze_email(email_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Analyzes an email for phishing, social engineering, credential harvesting,
    sender spoofing, and malicious links.
    """
    sender = email_data.get("sender", "").strip()
    subject = email_data.get("subject", "").strip()
    body = email_data.get("body", "").strip()
    reply_to = email_data.get("reply_to", "").strip()

    if not body and not subject:
        return {
            "scan_type": "email",
            "submitted_item": subject or sender or "Empty Email",
            "risk_score": 0,
            "classification": "unknown",
            "classification_label": "Insufficient Evidence",
            "badge_color": "slate",
            "indicators": [],
            "positive_observations": ["No email body or subject provided for evaluation."],
            "recommendations": ["Please supply email content to analyze."],
            "extracted_urls": [],
            "highlighted_spans": [],
            "analysis_status": "insufficient_evidence"
        }

    indicators: List[IndicatorResult] = []
    positive_observations: List[str] = []
    highlighted_spans: List[Dict[str, Any]] = []

    full_text = f"{subject}\n{body}".lower()

    # 1. Sender Analysis & Spoofing Detection
    display_name, sender_addr, sender_dom = parse_email_sender(sender)
    _, reply_addr, reply_dom = parse_email_sender(reply_to)

    if sender_dom:
        # Check if sender domain is impersonating known brands
        dom_inds, dom_obs = check_domain_reputation(sender_dom)
        for d_ind in dom_inds:
            indicators.append(IndicatorResult(
                name=f"Sender Domain: {d_ind.name}",
                severity=d_ind.severity,
                points=d_ind.points,
                description=f"Sender domain '{sender_dom}' exhibits threat markers: {d_ind.description}",
                category="email_sender_mismatch",
                evidence=f"From: {sender}"
            ))

        # Check Display Name Spoofing
        # e.g. Display Name contains "PayPal" or "Google", but domain is not an official domain
        for brand_key, brand_info in KNOWN_BRANDS.items():
            b_name = brand_info["name"].lower()
            if brand_key in display_name.lower() or b_name in display_name.lower():
                is_official = any(sender_dom == off or sender_dom.endswith("." + off) for off in brand_info["official_domains"])
                if not is_official:
                    indicators.append(IndicatorResult(
                        name="Display Name Brand Spoofing",
                        severity="critical",
                        points=30,
                        description=f"The sender claims to be '{brand_info['name']}' in the display name, but the actual sending address domain is '{sender_dom}'.",
                        category="email_sender_mismatch",
                        evidence=f"Display Name: '{display_name}' vs Sender Domain: '{sender_dom}'"
                    ))
                    break

    # Check Reply-To Mismatch
    if reply_dom and sender_dom and reply_dom != sender_dom:
        indicators.append(IndicatorResult(
            name="Sender and Reply-To Domain Mismatch",
            severity="high",
            points=25,
            description=f"Replies are directed to an entirely different domain ('{reply_dom}') than the sender ('{sender_dom}'). This is a hallmark indicator of sender address spoofing.",
            category="email_sender_mismatch",
            evidence=f"Sender: {sender_dom} | Reply-To: {reply_dom}"
        ))

    # 2. Urgency and Threat-Based Language
    found_urgency = []
    for term in URGENCY_TERMS:
        if term in full_text:
            found_urgency.append(term)
            highlighted_spans.append({
                "phrase": term,
                "category": "urgency",
                "severity": "high"
            })

    if found_urgency:
        indicators.append(IndicatorResult(
            name="High-Pressure Urgency Tactics",
            severity="high",
            points=20,
            description=f"Detected urgent psychological coercion triggers ({', '.join(found_urgency[:3])}) designed to bypass critical thinking.",
            category="email_urgency",
            evidence=f"Terms: {', '.join(found_urgency)}"
        ))

    # 3. Credential Harvesting Requests
    found_cred_terms = []
    for term in CREDENTIAL_REQUEST_TERMS:
        if term in full_text:
            found_cred_terms.append(term)
            highlighted_spans.append({
                "phrase": term,
                "category": "credential_request",
                "severity": "critical"
            })

    if found_cred_terms:
        indicators.append(IndicatorResult(
            name="Direct Request for Sensitive Credentials",
            severity="critical",
            points=30,
            description=f"Message explicitly solicits authentication credentials or secrets ({', '.join(found_cred_terms[:3])}). Legitimate entities never ask for these via unauthenticated messages.",
            category="email_credentials",
            evidence=f"Terms: {', '.join(found_cred_terms)}"
        ))

    # 4. Social Engineering & Financial Lures
    found_social = []
    for term in SOCIAL_ENGINEERING_TERMS:
        if term in full_text:
            found_social.append(term)
            highlighted_spans.append({
                "phrase": term,
                "category": "social_engineering",
                "severity": "medium"
            })

    if found_social:
        indicators.append(IndicatorResult(
            name="Social Engineering / Financial Lure",
            severity="medium",
            points=18,
            description=f"Content contains unsolicited lottery, prize, or wire transfer promises ({', '.join(found_social[:2])}).",
            category="email_social_engineering",
            evidence=f"Terms: {', '.join(found_social)}"
        ))

    # 5. Grammar, Formatting, and Excessive Capitalization
    caps_count = sum(1 for c in subject if c.isupper())
    if len(subject) > 10 and (caps_count / len(subject)) > 0.6:
        indicators.append(IndicatorResult(
            name="Excessive Capitalization in Subject Line",
            severity="low",
            points=6,
            description="The subject line is predominantly capitalized, a common tactic in spam and pressure-driven phishing.",
            category="email_social_engineering",
            evidence=f"Subject: {subject}"
        ))

    # 6. Embedded Links Analysis
    extracted_urls = extract_urls_from_text(body)
    analyzed_links = []
    max_link_score = 0

    for link in extracted_urls[:8]:  # analyze up to 8 links
        link_analysis = analyze_url(link)
        link_score = link_analysis.get("risk_score", 0)
        analyzed_links.append({
            "url": link,
            "risk_score": link_score,
            "classification": link_analysis.get("classification"),
            "indicators": [ind["name"] for ind in link_analysis.get("indicators", [])]
        })
        if link_score > max_link_score:
            max_link_score = link_score

    if max_link_score >= 70:
        indicators.append(IndicatorResult(
            name="Critical Phishing Link Embedded in Email",
            severity="critical",
            points=35,
            description="At least one embedded hyperlink was independently analyzed and determined to be a Critical Phishing Risk.",
            category="email_links",
            evidence=f"Max embedded link risk score: {max_link_score}/100"
        ))
    elif max_link_score >= 40:
        indicators.append(IndicatorResult(
            name="Suspicious Hyperlink Detected in Email",
            severity="high",
            points=20,
            description="An embedded link exhibits multiple suspicious phishing indicators.",
            category="email_links",
            evidence=f"Max embedded link risk score: {max_link_score}/100"
        ))
    elif extracted_urls:
        positive_observations.append(f"Analyzed {len(extracted_urls)} embedded link(s); none displayed critical standalone anomalies.")

    # Positive observations
    if not indicators:
        positive_observations.append("No urgent coercion keywords, credential requests, or spoofed headers identified.")

    # Calculate overall risk
    risk_data = calculate_risk(indicators, positive_observations)
    recommendations = generate_recommendations(risk_data["indicators"], risk_data["risk_score"], scan_type="email")

    return {
        "scan_type": "email",
        "submitted_item": subject or sender or "Submitted Email",
        "sender": sender,
        "subject": subject,
        "reply_to": reply_to,
        "risk_score": risk_data["risk_score"],
        "classification": risk_data["classification"],
        "classification_label": risk_data["classification_label"],
        "badge_color": risk_data["badge_color"],
        "indicators": risk_data["indicators"],
        "positive_observations": risk_data["positive_observations"],
        "recommendations": recommendations,
        "extracted_urls": analyzed_links,
        "highlighted_spans": highlighted_spans,
        "analysis_status": "completed"
    }

