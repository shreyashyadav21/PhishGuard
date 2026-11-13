from typing import List, Dict, Any
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from ..database import get_db
from ..models import QuizAttempt
from ..schemas import QuizSubmitRequest, QuizResultResponse

router = APIRouter(prefix="/quiz", tags=["Cybersecurity Quiz"])

QUIZ_QUESTIONS = [
    {
        "id": 1,
        "question": "What is the primary objective of a phishing attack?",
        "options": [
            "To physically overheat the target's computer hardware.",
            "To trick individuals into revealing passwords, credit cards, or confidential information through social engineering.",
            "To speed up internet connection latency across corporate networks.",
            "To automatically renew expired software licenses."
        ],
        "correct_index": 1,
        "explanation": "Phishing is a social engineering attack where attackers impersonate trusted entities to deceive individuals into divulging sensitive data such as login credentials or financial information."
    },
    {
        "id": 2,
        "question": "If a website has a valid padlock icon and uses 'HTTPS', does that guarantee it is safe and legitimate?",
        "options": [
            "Yes, attackers cannot obtain HTTPS certificates under any circumstances.",
            "No, HTTPS only encrypts data in transit. Attackers can obtain free SSL/TLS certificates for malicious phishing websites.",
            "Yes, HTTPS certificates are only granted after thorough police background verification.",
            "No, but it guarantees the website is hosted directly by Google."
        ],
        "correct_index": 1,
        "explanation": "HTTPS ensures an encrypted connection between your browser and the web server, protecting traffic from eavesdropping. However, modern threat actors readily obtain free TLS certificates for phishing sites. HTTPS does NOT verify that the site owner is trustworthy."
    },
    {
        "id": 3,
        "question": "Which of the following domains represents a homoglyph typosquatting attack against PayPal?",
        "options": [
            "https://www.paypal.com/signin",
            "https://paypa1-security-verification.example.com/login",
            "https://developer.paypal.com/docs",
            "https://community.paypal.com"
        ],
        "correct_index": 1,
        "explanation": "'paypa1-security-verification.example.com' replaces the letter 'l' with the numeral '1' (homoglyph) and appends banking keywords under an unrelated registered domain ('example.com')."
    },
    {
        "id": 4,
        "question": "How does Display Name Spoofing deceive email recipients?",
        "options": [
            "The attacker modifies the recipient's computer monitor brightness.",
            "The attacker sets the email sender's human-readable name to a trusted executive or brand, while the actual sender email address belongs to an external attacker.",
            "The attacker encrypts the email subject with an uncrackable cipher.",
            "The email automatically converts all text into an unreadable foreign language."
        ],
        "correct_index": 1,
        "explanation": "Many email clients display only the friendly sender name (e.g. 'IT Support') prominently. Attackers leverage this by naming their sender profile after a trusted authority while transmitting from an untrusted address."
    },
    {
        "id": 5,
        "question": "What is the purpose of the '@' symbol in a deceptive URL like 'http://google.com@evil-site.com'?",
        "options": [
            "It automatically sends an email to Google upon loading.",
            "It treats everything before the '@' as authentication credentials/userinfo, causing the browser to ignore 'google.com' and connect directly to 'evil-site.com'.",
            "It enforces end-to-end PGP email encryption.",
            "It speeds up DNS queries using Google's 8.8.8.8 resolver."
        ],
        "correct_index": 1,
        "explanation": "In URI specification RFC 3986, characters preceding an '@' symbol in the authority component denote userinfo (username:password). Attackers exploit this to visually deceive users into thinking they are visiting the brand name before the '@'."
    },
    {
        "id": 6,
        "question": "Why do phishing emails frequently use urgent deadlines like 'Your account will be suspended within 24 hours'?",
        "options": [
            "Because cyber insurance policies require quick resolution.",
            "To trigger panic and urgency, causing victims to bypass critical reasoning and act impulsively without verifying.",
            "Because email servers automatically delete unread messages after 24 hours.",
            "To comply with federal privacy disclosure laws."
        ],
        "correct_index": 1,
        "explanation": "Urgency is a core psychological lever in social engineering. Creating high stakes and artificial time pressure induces fear, reducing the likelihood that the target will stop to check the sender's authenticity."
    },
    {
        "id": 7,
        "question": "If you receive an email from your bank asking you to reply with your One-Time Password (OTP) or PIN to prevent fraud, what should you do?",
        "options": [
            "Immediately reply with the OTP to ensure your account is protected.",
            "Never share OTPs or PINs. Legitimate banks and financial institutions will never solicit these secrets via email or text.",
            "Forward the OTP to your friends to see if they got the same message.",
            "Click all links in the email to verify their authenticity."
        ],
        "correct_index": 1,
        "explanation": "Legitimate financial institutions and service providers will NEVER request passwords, OTPs, or debit card PINs over email or text messages. These requests are guaranteed signs of a credential harvesting attack."
    },
    {
        "id": 8,
        "question": "What is the most effective immediate action if you suspect you just submitted credentials on a phishing website?",
        "options": [
            "Turn off your computer and leave it unplugged for a week.",
            "Immediately change your password on the genuine official website, invalidate active sessions, and report the incident to your security team or IT helpdesk.",
            "Email the phishing site administrator asking them to delete your record.",
            "Clear your browser history and do nothing else."
        ],
        "correct_index": 1,
        "explanation": "Time is critical. Immediately reset passwords on the legitimate service, revoke active login sessions, enable multi-factor authentication (MFA), and inform your organization's IT/security response team."
    },
    {
        "id": 9,
        "question": "How does Multi-Factor Authentication (MFA) defend against phishing?",
        "options": [
            "It permanently removes all spam from the global internet.",
            "Even if attackers steal your primary password, they cannot access your account without the secondary independent verification factor (authenticator app, security key).",
            "It disables your web browser from visiting HTTP websites.",
            "It replaces passwords with biometric scans stored on public cloud servers."
        ],
        "correct_index": 1,
        "explanation": "MFA requires two or more verification factors to gain access. Even if an attacker captures a victim's password via phishing, they are blocked without the dynamic time-based token or hardware security key (especially FIDO2/WebAuthn)."
    },
    {
        "id": 10,
        "question": "Which of the following top-level domain (TLD) practices represents a high-risk security pattern in URLs?",
        "options": [
            "Using .gov for authorized government agencies.",
            "Hosting corporate services on .edu university networks.",
            "Abusing cheap or free disposable TLDs (e.g. .xyz, .top, .buzz) with multi-hyphenated brand impersonations to quickly stand up phishing infrastructure.",
            "Using .org for non-profit entities."
        ],
        "correct_index": 2,
        "explanation": "Threat actors frequently register disposable, low-cost generic TLDs (.top, .xyz, .buzz, etc.) in high volumes to host automated short-lived phishing campaigns before domain registrars or blocklists can shut them down."
    }
]

@router.get("/questions")
def get_quiz_questions():
    """Returns the 10 quiz questions without exposing the answers."""
    sanitized = []
    for q in QUIZ_QUESTIONS:
        sanitized.append({
            "id": q["id"],
            "question": q["question"],
            "options": q["options"]
        })
    return {"questions": sanitized}

@router.post("/submit")
def submit_quiz_answers(payload: QuizSubmitRequest, db: Session = Depends(get_db)):
    """Scores submitted quiz answers, returns detailed feedback and persists the attempt."""
    user_answers = payload.answers
    total = len(QUIZ_QUESTIONS)
    correct_count = 0
    feedback = []

    for q in QUIZ_QUESTIONS:
        qid = q["id"]
        selected = user_answers.get(qid)
        is_correct = (selected == q["correct_index"])
        if is_correct:
            correct_count += 1

        feedback.append({
            "question_id": qid,
            "question": q["question"],
            "selected_index": selected,
            "correct_index": q["correct_index"],
            "is_correct": is_correct,
            "explanation": q["explanation"]
        })

    score_percentage = int(round((correct_count / total) * 100))

    if score_percentage >= 90:
        knowledge_level = "SOC Master Defender"
    elif score_percentage >= 70:
        knowledge_level = "Security Guardian"
    elif score_percentage >= 50:
        knowledge_level = "Cyber Aware"
    else:
        knowledge_level = "Novice Cadet"

    # Persist attempt to DB
    attempt = QuizAttempt(
        total_questions=total,
        correct_answers=correct_count,
        score=score_percentage
    )
    db.add(attempt)
    db.commit()

    return {
        "total_questions": total,
        "correct_answers": correct_count,
        "score_percentage": score_percentage,
        "knowledge_level": knowledge_level,
        "feedback": feedback
    }

