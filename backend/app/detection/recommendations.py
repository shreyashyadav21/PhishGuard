from typing import List, Dict, Any

def generate_recommendations(indicators: List[Dict[str, Any]], risk_score: int, scan_type: str = "url") -> List[str]:
    """
    Generates actionable, context-aware cybersecurity recommendations
    based on the specific indicators identified during analysis.
    """
    recommendations: List[str] = []

    # Safe scan recommendations
    if risk_score < 20:
        if scan_type == "url":
            recommendations.append("This URL displays standard domain and structural indicators with no known phishing flags.")
            recommendations.append("Always verify you are on the intended page before entering passwords or confidential data.")
            recommendations.append("Keep your web browser updated to benefit from the latest anti-malware and certificate revocation protections.")
        else:
            recommendations.append("No immediate signs of deceptive language, credential harvesting, or spoofing detected.")
            recommendations.append("Follow standard security hygiene: confirm unanticipated attachments or wire requests through out-of-band channels.")
        return recommendations

    # Collect categories present in indicators
    categories = {ind.get("category", "") for ind in indicators}
    names = [ind.get("name", "").lower() for ind in indicators]

    # Critical brand impersonation
    if "domain_impersonation" in categories:
        recommendations.append("DO NOT submit passwords, credit card numbers, or personal credentials on this domain.")
        recommendations.append("Navigate to the legitimate service provider manually by typing their official web address into your browser.")
        recommendations.append("Report this domain as an impersonation attempt to your organization's security team or Anti-Phishing Working Group (APWG).")

    # Raw IP address
    if "ip_hostname" in categories:
        recommendations.append("Legitimate commercial web applications rarely host login portals on raw IP addresses. Treat this link as untrusted.")
        recommendations.append("Do not bypass any browser warnings or security prompts attempting to connect to this IP.")

    # Insecure HTTP
    if any("http" in name for name in names):
        recommendations.append("The link uses plain HTTP; communications are unencrypted and vulnerable to eavesdropping and credential sniffing.")

    # Credential requests in email
    if "email_credentials" in categories:
        recommendations.append("Reputable organizations and financial institutions will NEVER ask for passwords, OTPs, or PINs via email.")
        recommendations.append("Delete or quarantine this email immediately without responding or providing any verification codes.")

    # Email urgency / fear
    if "email_urgency" in categories:
        recommendations.append("High-pressure urgency ('account suspended in 24 hours') is the #1 social engineering tactic to compel hasty decisions.")
        recommendations.append("Contact the supposed sender using a known, trusted phone number or application rather than responding to this message.")

    # Sender mismatch
    if "email_sender_mismatch" in categories:
        recommendations.append("The sender's apparent display identity does not match the actual transmitting domain, indicating an impersonation attempt.")

    # Suspicious extracted links
    if "email_links" in categories:
        recommendations.append("The email body contains hyperlinks flagged as high risk. Do not click or interact with embedded buttons or URLs.")

    # Suspicious @ symbol or encoding in URL
    if "suspicious_chars" in categories or "encoding" in categories:
        recommendations.append("The URL utilizes character masking or obfuscated encoding designed to mislead automated filters. Avoid loading this link.")

    # Generic fallback if specific conditions didn't generate enough advice
    if len(recommendations) < 2:
        recommendations.append("Exercise extreme caution before proceeding. Inspect the full URL and certificate details.")
        recommendations.append("Do not download attachments or enter sensitive information.")

    return recommendations

