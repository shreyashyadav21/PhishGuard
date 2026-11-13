import pytest
from app.detection.email_analyzer import analyze_email

def test_safe_email():
    payload = {
        "sender": "Alice Smith <alice@company.com>",
        "subject": "Team Lunch on Friday",
        "body": "Hey team, let's meet at noon for our weekly lunch catch-up. See you there!"
    }
    res = analyze_email(payload)
    assert res["analysis_status"] == "completed"
    assert res["risk_score"] < 20
    assert res["classification"] == "safe"

def test_credential_harvesting_email():
    payload = {
        "sender": "Security Team <security@bank-alert.xyz>",
        "subject": "Urgent: Your account is suspended",
        "body": "Your bank account has been suspended! Please immediately provide your password and OTP code to unlock your account.",
        "reply_to": "hacker@evil-inbox.xyz"
    }
    res = analyze_email(payload)
    assert res["risk_score"] >= 60
    assert any("credential" in ind["name"].lower() for ind in res["indicators"])
    assert any("urgency" in ind["name"].lower() for ind in res["indicators"])

def test_display_name_spoofing():
    payload = {
        "sender": "PayPal Support <service@unrelated-hacker.com>",
        "subject": "Unauthorized Transaction Flagged",
        "body": "We detected an unauthorized charge. Click here to reverse the charges."
    }
    res = analyze_email(payload)
    assert any("display name" in ind["name"].lower() for ind in res["indicators"])

def test_reply_to_mismatch():
    payload = {
        "sender": "Help Desk <support@legit-corp.com>",
        "subject": "System Upgrade",
        "body": "Please confirm your user credentials.",
        "reply_to": "collector@attacker-domain.xyz"
    }
    res = analyze_email(payload)
    assert any("mismatch" in ind["name"].lower() for ind in res["indicators"])

