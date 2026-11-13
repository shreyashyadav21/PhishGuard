import re
import urllib.parse
from typing import Dict, Any, List
from .indicators import IndicatorResult, SUSPICIOUS_KEYWORDS
from .domain_analyzer import check_domain_reputation
from .risk_scoring import calculate_risk
from .recommendations import generate_recommendations

IP_V4_PATTERN = re.compile(
    r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(?::\d+)?$"
)
IP_V6_PATTERN = re.compile(r"^\[?[a-fA-F0-9:]+\]?(?::\d+)?$")

def is_ip_address(hostname: str) -> bool:
    """Checks if the given hostname is a raw IPv4 or IPv6 address."""
    clean_host = hostname.split(':')[0].strip('[]')
    if IP_V4_PATTERN.match(clean_host):
        return True
    # Basic check for IPv6 containing at least 2 colons
    if clean_host.count(':') >= 2:
        return True
    return False

def analyze_url(raw_url: str) -> Dict[str, Any]:
    """
    Analyzes a URL for phishing and security indicators using static heuristics.
    Never initiates outbound network connections (SSRF protection).
    """
    if not raw_url or not isinstance(raw_url, str) or not raw_url.strip():
        return {
            "scan_type": "url",
            "submitted_item": raw_url or "",
            "risk_score": 0,
            "classification": "unknown",
            "classification_label": "Insufficient Evidence",
            "badge_color": "slate",
            "indicators": [],
            "positive_observations": ["No URL content provided for heuristic evaluation."],
            "recommendations": ["Please provide a valid URL string to evaluate."],
            "parsed_details": {},
            "analysis_status": "insufficient_evidence"
        }

    url_str = raw_url.strip()
    if len(url_str) > 4096:
        url_str = url_str[:4096]

    # Prepend scheme if absent for uniform parsing
    has_explicit_scheme = bool(re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url_str))
    parse_target = url_str if has_explicit_scheme else f"http://{url_str}"

    try:
        parsed = urllib.parse.urlsplit(parse_target)
    except Exception as e:
        return {
            "scan_type": "url",
            "submitted_item": raw_url,
            "risk_score": 50,
            "classification": "suspicious",
            "classification_label": "Malformed URL",
            "badge_color": "amber",
            "indicators": [{
                "name": "Malformed URL Structure",
                "severity": "medium",
                "points": 20,
                "description": f"The URL cannot be parsed by RFC standard parsers: {str(e)}",
                "category": "url_structure",
                "evidence": url_str
            }],
            "positive_observations": [],
            "recommendations": ["Do not click or load syntactically invalid URLs as they may exploit browser parser differentials."],
            "parsed_details": {},
            "analysis_status": "completed"
        }

    scheme = parsed.scheme.lower()
    netloc = parsed.netloc
    path = parsed.path
    query = parsed.query

    # Extract hostname and port
    hostname = parsed.hostname or ""
    port = parsed.port

    indicators: List[IndicatorResult] = []
    positive_observations: List[str] = []

    # 1. Protocol / HTTPS Verification
    if scheme == "https":
        positive_observations.append("URL uses HTTPS transport encryption (Note: HTTPS encrypts transit but does not guarantee the site is benign).")
    elif scheme == "http":
        indicators.append(IndicatorResult(
            name="Insecure HTTP Connection",
            severity="low",
            points=5,
            description="The URL uses unencrypted HTTP. Data sent over this connection can be intercepted or altered by man-in-the-middle attackers.",
            category="protocol",
            evidence="Scheme: http://"
        ))
    else:
        indicators.append(IndicatorResult(
            name=f"Non-Standard Protocol ({scheme})",
            severity="medium",
            points=15,
            description=f"The URL specifies a non-standard protocol '{scheme}://' which may trigger local handler execution.",
            category="protocol",
            evidence=f"Scheme: {scheme}"
        ))

    # 2. Raw IP Address Hostname
    if hostname and is_ip_address(hostname):
        indicators.append(IndicatorResult(
            name="Raw IP Address as Hostname",
            severity="high",
            points=20,
            description=f"The hostname '{hostname}' is a raw IP address instead of a registered domain name. Phishers frequently use raw IPs to bypass domain reputation blocklists.",
            category="ip_hostname",
            evidence=f"Host: {hostname}"
        ))
    elif hostname:
        positive_observations.append(f"Domain '{hostname}' uses standard named domain resolution rather than a raw IP address.")

    # 3. URL Length
    total_len = len(url_str)
    if total_len > 120:
        indicators.append(IndicatorResult(
            name="Excessively Long URL (>120 chars)",
            severity="medium",
            points=12,
            description=f"The URL length ({total_len} characters) is unusually long, commonly used to hide malicious domains or pass obfuscated tracking payloads.",
            category="url_structure",
            evidence=f"Length: {total_len} characters"
        ))
    elif total_len > 75:
        indicators.append(IndicatorResult(
            name="Long URL Structure (>75 chars)",
            severity="low",
            points=6,
            description=f"The URL is longer than typical landing links ({total_len} characters).",
            category="url_structure",
            evidence=f"Length: {total_len} characters"
        ))
    else:
        positive_observations.append("URL length is concise and within normal bounds.")

    # 4. Suspicious Characters (@ symbol, unusual ports)
    if "@" in netloc or "@" in url_str:
        indicators.append(IndicatorResult(
            name="Deceptive '@' Character in URL",
            severity="critical",
            points=25,
            description="The '@' symbol treats preceding text as userinfo, causing browsers to ignore the fake domain and connect exclusively to the host following the '@'.",
            category="suspicious_chars",
            evidence=f"Detected '@' in URL: {url_str}"
        ))

    if port and port not in (80, 443, 8080, 8443):
        indicators.append(IndicatorResult(
            name=f"Unusual Non-Standard Port (:{port})",
            severity="medium",
            points=10,
            description=f"The URL connects to non-standard TCP port {port}. Standard secure web services rarely operate on atypical ports for end users.",
            category="suspicious_chars",
            evidence=f"Port: {port}"
        ))

    # 5. Suspicious Keywords (Contextual)
    found_keywords = []
    lower_target = url_str.lower()
    for kw in SUSPICIOUS_KEYWORDS:
        if kw in lower_target:
            found_keywords.append(kw)

    if found_keywords:
        # Contextual analysis: check where the keywords are
        kw_in_host = [k for k in found_keywords if k in hostname.lower()]
        kw_in_path = [k for k in found_keywords if k in path.lower() or k in query.lower()]

        if len(kw_in_host) >= 2 or (kw_in_host and kw_in_path):
            indicators.append(IndicatorResult(
                name="High-Risk Security Keyword Combinations",
                severity="high",
                points=15,
                description=f"Multiple high-value security/banking lure terms ({', '.join(found_keywords[:4])}) identified in domain and path.",
                category="keywords",
                evidence=f"Keywords: {', '.join(found_keywords)}"
            ))
        elif len(found_keywords) >= 1:
            indicators.append(IndicatorResult(
                name="Suspicious Authentication / Account Keywords",
                severity="low",
                points=6,
                description=f"URL contains sensitive action keywords ({', '.join(found_keywords[:3])}) often used in phishing lures.",
                category="keywords",
                evidence=f"Keywords: {', '.join(found_keywords)}"
            ))

    # 6. Domain Reputation and Impersonation Analysis
    if hostname:
        domain_indicators, domain_observations = check_domain_reputation(hostname)
        indicators.extend(domain_indicators)
        positive_observations.extend(domain_observations)

    # 7. URL Encoding & Obfuscation
    percent_count = url_str.count("%")
    if percent_count >= 4:
        indicators.append(IndicatorResult(
            name="Excessive Percent-Encoding Obfuscation",
            severity="medium",
            points=10,
            description=f"Detected {percent_count} percent-encoded tokens in URL. Phishers use URL-encoding to evade keyword filters and hide target strings.",
            category="encoding",
            evidence=f"Percent signs count: {percent_count}"
        ))

    # 8. Open Redirect Pattern in Query
    open_redirect_params = ["redirect", "url", "next", "return", "dest", "target", "link"]
    query_params = urllib.parse.parse_qs(query)
    for param in open_redirect_params:
        if param in query_params:
            val = query_params[param][0]
            if val.startswith("http://") or val.startswith("https://") or "//" in val:
                indicators.append(IndicatorResult(
                    name="Potential Open Redirection Parameter",
                    severity="medium",
                    points=12,
                    description=f"Query parameter '{param}' contains an embedded target URL. Attackers use open redirects on trusted sites to forward victims to malicious pages.",
                    category="url_structure",
                    evidence=f"{param}={val}"
                ))
                break

    # Calculate overall risk score and classify
    risk_data = calculate_risk(indicators, positive_observations)
    recommendations = generate_recommendations(risk_data["indicators"], risk_data["risk_score"], scan_type="url")

    parsed_details = {
        "scheme": scheme,
        "hostname": hostname,
        "port": port or (443 if scheme == "https" else 80),
        "path": path,
        "query": query,
        "is_ip": is_ip_address(hostname) if hostname else False,
        "length": total_len
    }

    return {
        "scan_type": "url",
        "submitted_item": raw_url,
        "risk_score": risk_data["risk_score"],
        "classification": risk_data["classification"],
        "classification_label": risk_data["classification_label"],
        "badge_color": risk_data["badge_color"],
        "indicators": risk_data["indicators"],
        "positive_observations": risk_data["positive_observations"],
        "recommendations": recommendations,
        "parsed_details": parsed_details,
        "analysis_status": "completed"
    }

