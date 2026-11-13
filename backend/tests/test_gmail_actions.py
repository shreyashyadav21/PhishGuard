import pytest
import datetime
from fastapi.testclient import TestClient
from app.main import app
from app.database import SessionLocal
from app.models import ConnectedAccount, Scan
from app.services.gmail_service import encrypt_token

client = TestClient(app)

def test_gmail_actions_flow():
    db = SessionLocal()
    # Create test connected account
    test_email = "test-security-analyst@example.com"
    existing = db.query(ConnectedAccount).filter(ConnectedAccount.email == test_email).first()
    if not existing:
        acc = ConnectedAccount(
            email=test_email,
            encrypted_access_token=encrypt_token("mock_access_token"),
            encrypted_refresh_token=encrypt_token("mock_refresh_token"),
            is_active=True
        )
        db.add(acc)
        db.commit()
    db.close()

    # 1. Test KEEP Action
    keep_resp = client.post("/api/gmail/actions", json={
        "account_email": test_email,
        "gmail_message_id": "msg_keep_101",
        "action_type": "keep",
        "notes": "Verified authentic internal notification"
    })
    assert keep_resp.status_code == 200
    assert keep_resp.json()["status"] == "success"
    assert keep_resp.json()["action"] == "keep"

    # 2. Test QUARANTINE Action
    quarantine_resp = client.post("/api/gmail/actions", json={
        "account_email": test_email,
        "gmail_message_id": "msg_quar_102",
        "action_type": "quarantine"
    })
    assert quarantine_resp.status_code == 200
    assert quarantine_resp.json()["action"] == "quarantine"

    # 3. Test TRASH Action
    trash_resp = client.post("/api/gmail/actions", json={
        "account_email": test_email,
        "gmail_message_id": "msg_trash_103",
        "action_type": "trash"
    })
    assert trash_resp.status_code == 200
    assert trash_resp.json()["action"] == "trash"

    # 4. Test REPORT Action
    report_resp = client.post("/api/gmail/actions", json={
        "account_email": test_email,
        "gmail_message_id": "msg_rep_104",
        "action_type": "report"
    })
    assert report_resp.status_code == 200
    assert report_resp.json()["action"] == "report"

def test_campaign_correlation_api():
    resp = client.post("/api/campaigns/correlate")
    assert resp.status_code == 200
    data = resp.json()
    assert "correlated_campaigns_count" in data

    list_resp = client.get("/api/campaigns")
    assert list_resp.status_code == 200
    assert isinstance(list_resp.json(), list)

def test_timeline_api():
    resp = client.get("/api/timeline?limit=10")
    assert resp.status_code == 200
    events = resp.json()
    assert isinstance(events, list)
    assert len(events) > 0
    assert "event_type" in events[0]

