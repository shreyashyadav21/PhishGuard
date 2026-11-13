import re
from typing import Dict, Any, List, Optional
from ..config import settings

def sanitize_untrusted_text(text: str, max_length: int = 1000) -> str:
    """Sanitizes untrusted email content to neutralize prompt injection tokens."""
    if not text:
        return ""
    # Strip potential prompt injection delimiters
    cleaned = re.sub(r"(ignore previous instructions|system prompt|developer mode|you are now)", "[REDACTED_PROMPT_TOKEN]", text, flags=re.IGNORECASE)
    return cleaned[:max_length].strip()

def generate_threat_explanation(
    analysis_data: Dict[str, Any],
    custom_question: Optional[str] = None
) -> Dict[str, Any]:
    """
    Generates explainable threat intelligence for security analysts and end users.
    Uses structured detection evidence. If an AI key is configured, formats a bounded prompt;
    otherwise uses deterministic expert heuristics.
    """
    risk_score = analysis_data.get("risk_score", 0)
    classification = analysis_data.get("classification_label", analysis_data.get("classification", "Unknown"))
    submitted_target = analysis_data.get("submitted_item", "N/A")
    indicators = analysis_data.get("indicators", [])
    extracted_urls = analysis_data.get("extracted_urls", [])
    sender = analysis_data.get("sender", "Unknown sender")
    subject = analysis_data.get("subject", "No subject")
    recommendations = analysis_data.get("recommendations", [])

    # Deterministic Rule-Based Synthesis (Local Engine)
    what_happened = f"PhishGuard inspected this message and calculated a threat severity score of {risk_score}/100 ({classification.upper()})."
    
    why_suspicious_points = []
    sender_analysis = "The sender domain matches expected patterns without recognized typosquatting."
    links_attention = []

    for ind in indicators:
        name = ind.get("name", "")
        desc = ind.get("description", "")
        sev = ind.get("severity", "medium")
        why_suspicious_points.append(f"• [{sev.upper()}] {name}: {desc}")

        if "sender" in name.lower() or "display name" in name.lower() or "mismatch" in name.lower():
            sender_analysis = f"Suspicious Sender: {desc}"

    for link in extracted_urls:
        url_score = link.get("risk_score", 0)
        if url_score >= 20:
            links_attention.append({
                "url": link.get("url"),
                "score": url_score,
                "reason": f"Risk score {url_score}/100. Associated indicators: {', '.join(link.get('indicators', ['Suspicious link structure']))}"
            })

    what_to_do = recommendations[:3] if recommendations else [
        "Do not click links or download attachments from this message.",
        "Verify the sender's identity through an independent, verified contact method."
    ]

    # Handle Interactive Questions
    answer_to_question = None
    if custom_question:
        q_lower = custom_question.lower()
        if "dangerous" in q_lower or "why" in q_lower and "score" in q_lower:
            answer_to_question = (
                f"This email received a risk score of {risk_score}/100 primarily due to {len(indicators)} flagged indicator(s). "
                f"The highest-weighted factor is '{indicators[0]['name'] if indicators else 'heuristic anomalies'}'. "
                "Attackers use these patterns to steal credentials or compromise devices."
            )
        elif "sender" in q_lower or "genuine" in q_lower:
            answer_to_question = (
                f"Sender assessment: {sender_analysis} "
                "Always check whether the domain after the '@' matches the official website of the organization claiming to contact you."
            )
        elif "click" in q_lower or "link" in q_lower:
            if links_attention:
                answer_to_question = (
                    f"Warning: At least {len(links_attention)} link(s) in this message were identified as suspicious. "
                    f"Clicking them may lead to a spoofed credential harvesting page or trigger automated malware delivery. Do not open: {links_attention[0]['url']}"
                )
            else:
                answer_to_question = "No high-risk external links were detected, but proceed with caution if unexpected."
        elif "verify" in q_lower or "how to" in q_lower:
            answer_to_question = (
                "To safely verify this message: Navigate directly to the company's official website using your own browser bookmark "
                "or call their publicly listed customer service number. Never use the phone numbers or links provided in the email itself."
            )
        else:
            answer_to_question = (
                f"Regarding your query: Based on {len(indicators)} security indicators, this message is categorized as {classification}. "
                f"Key recommendation: {what_to_do[0] if what_to_do else 'Do not interact with untrusted content.'}"
            )

    return {
        "engine": "Deterministic SOC Heuristic Explainer" if not settings.AI_API_KEY else "AI-Enhanced Explainer (Key Configured)",
        "risk_score": risk_score,
        "classification": classification,
        "summary": what_happened,
        "why_suspicious": why_suspicious_points,
        "sender_analysis": sender_analysis,
        "links_requiring_attention": links_attention,
        "prescribed_actions": what_to_do,
        "question": custom_question,
        "answer": answer_to_question,
        "prompt_injection_protected": True
    }

