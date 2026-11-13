import pytest
import uuid
import httpx
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from app.database import Base, get_db
from app.models import ConnectedAccount
from app.main import app
from app.config import settings
from app.services.gmail_service import _gmail_api_error, encrypt_token

client = TestClient(app)

def test_health_endpoint():
    response = client.get("/api/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert "detection_engine_version" in data

def test_url_scan_endpoint():
    response = client.post("/api/scan/url", json={"url": "http://paypa1-verify-account.top/login"})
    assert response.status_code == 200
    data = response.json()
    assert "risk_score" in data
    assert "classification" in data
    assert data["risk_score"] > 40
    assert "id" in data

def test_email_scan_endpoint():
    response = client.post("/api/scan/email", json={
        "sender": "Apple Security <security@app1e-support.xyz>",
        "subject": "CRITICAL: Account Suspended within 24 hours",
        "body": "Please provide your Apple ID password and verification code immediately."
    })
    assert response.status_code == 200
    data = response.json()
    assert data["risk_score"] >= 60

def test_dashboard_stats_endpoint():
    response = client.get("/api/dashboard/stats?days=30")
    assert response.status_code == 200
    data = response.json()
    assert "total_scans" in data
    assert "threat_detection_rate" in data
    assert "activity_timeline" in data
    assert "category_counts" in data

def test_quiz_endpoints():
    # Test questions
    resp_q = client.get("/api/quiz/questions")
    assert resp_q.status_code == 200
    questions = resp_q.json()["questions"]
    assert len(questions) == 10

    # Test submit
    resp_sub = client.post("/api/quiz/submit", json={"answers": {1: 1, 2: 1, 3: 1}})
    assert resp_sub.status_code == 200
    result = resp_sub.json()
    assert "score_percentage" in result
    assert "knowledge_level" in result

def test_pdf_report_download():
    # First make a scan
    scan_resp = client.post("/api/scan/url", json={"url": "http://suspicious-test.com/login"})
    scan_id = scan_resp.json()["id"]

    pdf_resp = client.get(f"/api/reports/{scan_id}/pdf")
    assert pdf_resp.status_code == 200
    assert pdf_resp.headers["content-type"] == "application/pdf"
    assert len(pdf_resp.content) > 1000

def test_gmail_status_and_demo_connect():
    # Test status endpoint
    status_resp = client.get("/api/gmail/status")
    assert status_resp.status_code == 200
    data = status_resp.json()
    assert "is_configured" in data

    # Test demo mailbox connect
    demo_resp = client.post("/api/gmail/demo-connect")
    assert demo_resp.status_code == 200
    demo_data = demo_resp.json()
    assert demo_data["status"] == "connected"
    assert "phishguard-soc.org" in demo_data["email"]

    # Test accounts list includes the demo account
    accounts_resp = client.get("/api/gmail/accounts")
    assert accounts_resp.status_code == 200
    accounts = accounts_resp.json()
    assert any(a["email"] == demo_data["email"] for a in accounts)

def test_gmail_api_disabled_error_explains_project_and_fix():
    response = httpx.Response(403, json={
        "error": {
            "code": 403,
            "message": "Gmail API has not been used in project 123456789 before or it is disabled.",
            "errors": [{"reason": "accessNotConfigured"}],
            "status": "PERMISSION_DENIED"
        }
    })

    message = str(_gmail_api_error(response, "Gmail message-list request"))

    assert "accessNotConfigured" in message
    assert "Google Cloud project 123456789" in message
    assert "Enable Gmail API" in message

def test_gmail_credentials_save():
    save_resp = client.post("/api/gmail/credentials", json={
        "client_id": "123456789-mock.apps.googleusercontent.com",
        "client_secret": "GOCSPX-mocksecret123456",
        "redirect_uri": "http://localhost:5173/gmail-connect"
    })
    assert save_resp.status_code == 200
    assert save_resp.json()["status"] == "success"

    # Status should now report configured
    status_resp = client.get("/api/gmail/status")
    assert status_resp.status_code == 200
    assert status_resp.json()["is_configured"] is True

def test_gmail_extension_scan_returns_and_caches_verdict():
    message_id = f"extension-test-{uuid.uuid4().hex}"
    thread_id = f"extension-thread-{uuid.uuid4().hex}"
    payload = {
        "gmail_message_id": message_id,
        "gmail_thread_id": thread_id,
        "account_email": "extension-test@example.com",
        "sender": "Account Security <security@paypa1-update.xyz>",
        "subject": "URGENT: Verify your password immediately",
        "body": "Your account will be suspended. Verify your password at http://paypa1-verify.top/login"
    }

    first_response = client.post("/api/gmail/extension/scan", json=payload)
    second_response = client.post("/api/gmail/extension/scan", json=payload)
    other_account_response = client.post(
        "/api/gmail/extension/scan",
        json={**payload, "account_email": "another-account@example.com"}
    )

    assert first_response.status_code == 200
    assert first_response.json()["risk_score"] >= 40
    assert first_response.json()["status"] == "completed"
    assert first_response.json()["thread_id"] == thread_id
    assert second_response.status_code == 200
    assert second_response.json()["scan_id"] == first_response.json()["scan_id"]
    assert second_response.json()["thread_id"] == thread_id
    assert other_account_response.status_code == 200
    assert other_account_response.json()["scan_id"] != first_response.json()["scan_id"]

def test_gmail_sync_scans_paginated_inbox_and_returns_thread_ids(monkeypatch):
    import app.api.gmail as gmail_api

    test_engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool
    )
    Base.metadata.create_all(bind=test_engine)
    test_session = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)

    def override_get_db():
        db = test_session()
        try:
            yield db
        finally:
            db.close()

    original_overrides = app.dependency_overrides.copy()
    app.dependency_overrides[get_db] = override_get_db
    account_email = f"sync-test-{uuid.uuid4().hex}@unit.test"
    db = test_session()
    db.add(ConnectedAccount(
        email=account_email,
        encrypted_access_token=encrypt_token("unit-test-access-token"),
        encrypted_refresh_token="",
        is_active=True
    ))
    db.commit()
    account_id = db.query(ConnectedAccount).filter_by(email=account_email).one().id
    db.close()

    requested_tokens = []

    async def fake_fetch_page(_access_token, max_results, page_token=None):
        requested_tokens.append(page_token)
        assert max_results == 25
        if page_token is None:
            return {
                "messages": [{"id": "sync-message-1", "threadId": "sync-thread-1"}],
                "next_page_token": "next-page"
            }
        return {"messages": [], "next_page_token": None}

    async def fake_fetch_detail(_access_token, message_id):
        assert message_id == "sync-message-1"
        return {
            "id": message_id,
            "threadId": "sync-thread-1",
            "snippet": "Please review this routine notice.",
            "payload": {
                "headers": [
                    {"name": "From", "value": "Updates <updates@example.com>"},
                    {"name": "Subject", "value": "Routine notice"}
                ],
                "parts": []
            }
        }

    monkeypatch.setattr(gmail_api, "fetch_gmail_messages_page", fake_fetch_page)
    monkeypatch.setattr(gmail_api, "fetch_gmail_message_detail", fake_fetch_detail)
    try:
        first = client.post(f"/api/gmail/sync/{account_id}?max_results=25")
        second = client.post(f"/api/gmail/sync/{account_id}?max_results=25&page_token=next-page")
    finally:
        app.dependency_overrides.clear()
        app.dependency_overrides.update(original_overrides)
        test_engine.dispose()

    assert first.status_code == 200
    assert first.json()["processed_new_messages"] == 1
    assert first.json()["verdicts"][0]["thread_id"] == "sync-thread-1"
    assert first.json()["next_page_token"] == "next-page"
    assert second.status_code == 200
    assert second.json()["page_count"] == 0
    assert requested_tokens == [None, "next-page"]

def test_gmail_addon_scan_requires_api_key(monkeypatch):
    payload = {
        "gmail_message_id": f"addon-test-{uuid.uuid4().hex}",
        "sender": "Security <security@example.com>",
        "subject": "Message for add-on scan",
        "body": "Please review this account notice."
    }

    monkeypatch.setattr(settings, "GMAIL_ADDON_API_KEY", "")
    unconfigured = client.post("/api/gmail/addon/scan", json=payload)
    assert unconfigured.status_code == 503

    api_key = "test-addon-key-" + uuid.uuid4().hex
    monkeypatch.setattr(settings, "GMAIL_ADDON_API_KEY", api_key)
    unauthorized = client.post("/api/gmail/addon/scan", json=payload)
    assert unauthorized.status_code == 401

    authorized = client.post(
        "/api/gmail/addon/scan",
        json=payload,
        headers={"Authorization": f"Bearer {api_key}"}
    )
    assert authorized.status_code == 200
    assert authorized.json()["status"] == "completed"

def test_gmail_overview_contains_only_gmail_linked_scans():
    message_id = f"overview-test-{uuid.uuid4().hex}"
    gmail_response = client.post("/api/gmail/extension/scan", json={
        "gmail_message_id": message_id,
        "account_email": "overview-test@example.com",
        "sender": "Updates <updates@example.com>",
        "subject": "Inbox overview test",
        "body": "A routine message."
    })
    manual_response = client.post("/api/scan/email", json={
        "sender": "updates@example.com",
        "subject": "Manual scan should not appear",
        "body": "This was submitted through the manual scanner."
    })

    overview_response = client.get("/api/gmail/overview")

    assert gmail_response.status_code == 200
    assert manual_response.status_code == 200
    assert overview_response.status_code == 200
    overview = overview_response.json()
    assert overview["gmail_messages_scanned"] >= 1
    assert any(message["gmail_message_id"] == message_id for message in overview["recent_messages"])
    assert all(message["scan_id"] != manual_response.json()["id"] for message in overview["recent_messages"])
    assert all(account["email"] != "analyst.demo@phishguard-soc.org" for account in overview["connected_accounts"])


