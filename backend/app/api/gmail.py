import json
import base64
import asyncio
import datetime
import secrets
import urllib.parse
from typing import Optional, Dict, Any, List
import httpx
from fastapi import APIRouter, Depends, Header, HTTPException, Query, Body, Request
from fastapi.responses import RedirectResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session
from sqlalchemy import or_
from ..database import get_db
from ..models import (
    ConnectedAccount,
    Scan,
    Attachment,
    SecurityEvent,
    Indicator,
    Recommendation,
    ThreatIndicator,
    Setting
)
from ..schemas import GmailExtensionScanRequest
from ..config import settings
from ..services.gmail_service import (
    get_google_auth_url,
    exchange_code_for_tokens,
    encrypt_token,
    decrypt_token,
    refresh_access_token,
    fetch_google_user_profile,
    register_gmail_watch,
    fetch_gmail_messages_page,
    fetch_gmail_message_detail,
    parse_gmail_payload
)
from ..services.gmail_actions import (
    execute_keep_email,
    execute_quarantine_email,
    execute_trash_email,
    execute_report_phishing
)
from ..detection.email_analyzer import analyze_email
from ..detection.attachment_scanner import analyze_attachment

router = APIRouter(prefix="/gmail", tags=["Gmail Integration"])

class OAuthCallbackPayload(BaseModel):
    code: str
    redirect_uri: Optional[str] = None

class ActionPayload(BaseModel):
    account_email: str
    gmail_message_id: str
    action_type: str  # "keep", "quarantine", "trash", "report"
    scan_id: Optional[int] = None
    notes: Optional[str] = None

class CredentialsPayload(BaseModel):
    client_id: str
    client_secret: str
    redirect_uri: Optional[str] = None
    pubsub_topic: Optional[str] = None

def get_effective_client_id(db: Session) -> str:
    """Returns Client ID from env or database setting."""
    if settings.GOOGLE_CLIENT_ID and settings.GOOGLE_CLIENT_ID != "CONFIGURE_IN_SETTINGS":
        return settings.GOOGLE_CLIENT_ID
    db_setting = db.query(Setting).filter(Setting.setting_key == "google_client_id").first()
    return db_setting.setting_value if db_setting and db_setting.setting_value else ""

def get_effective_client_secret(db: Session) -> str:
    """Returns Client Secret from env or database setting."""
    if settings.GOOGLE_CLIENT_SECRET:
        return settings.GOOGLE_CLIENT_SECRET
    db_setting = db.query(Setting).filter(Setting.setting_key == "google_client_secret").first()
    return db_setting.setting_value if db_setting and db_setting.setting_value else ""

def get_effective_redirect_uri(db: Session) -> str:
    """Returns Redirect URI from database setting or default."""
    db_setting = db.query(Setting).filter(Setting.setting_key == "google_redirect_uri").first()
    if db_setting and db_setting.setting_value:
        return db_setting.setting_value
    return settings.GOOGLE_REDIRECT_URI

@router.get("/status")
def get_oauth_status(db: Session = Depends(get_db)):
    """Returns Google OAuth configuration readiness status."""
    cid = get_effective_client_id(db)
    csec = get_effective_client_secret(db)
    is_configured = bool(cid and not cid.startswith("CONFIGURE_") and csec)
    return {
        "is_configured": is_configured,
        "client_id_preview": f"{cid[:15]}...apps.googleusercontent.com" if is_configured else None,
        "has_client_secret": bool(csec),
        "redirect_uri": get_effective_redirect_uri(db)
    }

@router.post("/credentials")
def save_google_credentials(payload: CredentialsPayload, db: Session = Depends(get_db)):
    """Saves Google OAuth credentials into database settings."""
    cid = payload.client_id.strip()
    csecret = payload.client_secret.strip()
    if not cid or not csecret:
        raise HTTPException(status_code=400, detail="Client ID and Client Secret cannot be empty")

    # Save to database
    def upsert(k, v):
        item = db.query(Setting).filter(Setting.setting_key == k).first()
        if item:
            item.setting_value = v
        else:
            db.add(Setting(setting_key=k, setting_value=v))

    upsert("google_client_id", cid)
    upsert("google_client_secret", csecret)
    if payload.redirect_uri:
        upsert("google_redirect_uri", payload.redirect_uri.strip())
        settings.GOOGLE_REDIRECT_URI = payload.redirect_uri.strip()
    if payload.pubsub_topic:
        upsert("google_pubsub_topic", payload.pubsub_topic.strip())
        settings.GOOGLE_PUBSUB_TOPIC = payload.pubsub_topic.strip()

    # Update in-memory settings
    settings.GOOGLE_CLIENT_ID = cid
    settings.GOOGLE_CLIENT_SECRET = csecret
    db.commit()

    return {"status": "success", "message": "Google OAuth credentials saved successfully."}

@router.get("/oauth/url")
def get_auth_url(redirect_uri: Optional[str] = None, db: Session = Depends(get_db)):
    """Returns Google OAuth 2.0 authorization URL or configuration notice."""
    cid = get_effective_client_id(db)
    if not cid or cid == "CONFIGURE_IN_SETTINGS":
        raise HTTPException(
            status_code=400,
            detail="Google Client ID is not configured yet. Please configure your Google Cloud OAuth Client ID and Secret in the setup panel below, or activate the instant Demonstration Mailbox."
        )
    eff_redirect = redirect_uri or get_effective_redirect_uri(db)
    return {"auth_url": get_google_auth_url(client_id=cid, redirect_uri=eff_redirect)}

@router.get("/oauth/callback")
def oauth_callback_get(code: Optional[str] = None, error: Optional[str] = None):
    """
    Handles browser redirects when Google Cloud Authorized Redirect URI
    is configured to backend URL (http://127.0.0.1:8000/api/gmail/oauth/callback).
    Redirects back to React frontend (/gmail-connect).
    """
    if error:
        return RedirectResponse(url=f"http://localhost:5173/gmail-connect?error={urllib.parse.quote(error)}")
    if code:
        return RedirectResponse(url=f"http://localhost:5173/gmail-connect?code={urllib.parse.quote(code)}")
    return RedirectResponse(url="http://localhost:5173/gmail-connect")

@router.post("/demo-connect")
def connect_demo_mailbox(db: Session = Depends(get_db)):
    """
    Connects an authorized Demonstration Mailbox (analyst.demo@phishguard-soc.org)
    with realistic incoming phishing and legitimate messages, enabling instant testing
    of the entire Live Surveillance, Quarantine, and Chrome Extension workflows without GCP setup.
    """
    demo_email = "analyst.demo@phishguard-soc.org"
    existing = db.query(ConnectedAccount).filter(ConnectedAccount.email == demo_email).first()

    if existing:
        existing.is_active = True
        existing.last_synced_at = datetime.datetime.utcnow()
        account_obj = existing
    else:
        account_obj = ConnectedAccount(
            email=demo_email,
            google_user_id="demo_user_102938475",
            display_name="SOC Demo Analyst",
            profile_picture="https://lh3.googleusercontent.com/a/default-user=s96-c",
            encrypted_access_token=encrypt_token("demo_access_token_phishguard"),
            encrypted_refresh_token=encrypt_token("demo_refresh_token_phishguard"),
            token_expiry=datetime.datetime.utcnow() + datetime.timedelta(days=365),
            last_history_id="1092837",
            watch_expiry=datetime.datetime.utcnow() + datetime.timedelta(days=7),
            is_active=True
        )
        db.add(account_obj)

    # Seed 3 sample live messages for this account
    sample_messages = [
        (
            "msg_live_001",
            "PayPal Security <security@paypa1-update.xyz>",
            "URGENT: Unauthorized login attempt - Verify your PayPal account now",
            "Dear customer,\nWe detected an unauthorized transaction. Please verify your password and OTP immediately at http://paypa1-verify-security.top/login within 24 hours.",
            "collector@darkinbox.xyz"
        ),
        (
            "msg_live_002",
            "Microsoft 365 Admin <admin@micros0ft-support.top>",
            "Action Needed: Your password expires in 2 hours",
            "Your corporate password will expire today. Renew your credentials at http://login-microsoft365-auth.buzz/renew to maintain email access.",
            "admin@micros0ft-support.top"
        ),
        (
            "msg_live_003",
            "Google Calendar <calendar-notification@google.com>",
            "Meeting Invitation: Weekly SOC Incident Review",
            "Hi team,\nPlease join the weekly incident response synchronization meeting.\nAgenda: https://calendar.google.com/event?id=sample",
            ""
        )
    ]

    for mid, sender, subject, body, reply_to in sample_messages:
        existing_scan = db.query(Scan).filter(Scan.gmail_message_id == mid).first()
        if not existing_scan:
            analysis = analyze_email({
                "sender": sender,
                "subject": subject,
                "body": body,
                "reply_to": reply_to
            })
            scan_obj = Scan(
                scan_type="email",
                submitted_item=subject,
                risk_score=analysis["risk_score"],
                classification=analysis["classification"],
                created_at=datetime.datetime.utcnow(),
                analysis_json=json.dumps(analysis),
                gmail_message_id=mid,
                account_email=demo_email
            )
            db.add(scan_obj)
            db.flush()

            for ind in analysis.get("indicators", []):
                db.add(Indicator(
                    scan_id=scan_obj.id,
                    indicator_name=ind.get("name", ""),
                    severity=ind.get("severity", "medium"),
                    risk_points=ind.get("points", 0),
                    description=ind.get("description", "")
                ))
            for rec in analysis.get("recommendations", []):
                db.add(Recommendation(
                    scan_id=scan_obj.id,
                    recommendation_text=rec
                ))

    # Add security event
    db.add(SecurityEvent(
        event_type="account_connected",
        title="Demonstration Mailbox Connected",
        description=f"Connected demonstration test mailbox {demo_email} with active heuristic surveillance.",
        severity="info",
        target_item=demo_email
    ))

    db.commit()
    db.refresh(account_obj)

    return {
        "status": "connected",
        "email": account_obj.email,
        "display_name": account_obj.display_name,
        "mode": "Demonstration Test Mailbox",
        "watch_registered": True
    }

@router.post("/oauth/callback")
async def oauth_callback(payload: OAuthCallbackPayload, db: Session = Depends(get_db)):
    """Exchanges code, encrypts tokens, registers watch, and saves connected account."""
    cid = get_effective_client_id(db)
    csec = get_effective_client_secret(db)
    eff_redirect = payload.redirect_uri or get_effective_redirect_uri(db)
    try:
        tokens = await exchange_code_for_tokens(
            payload.code,
            client_id=cid,
            client_secret=csec,
            redirect_uri=eff_redirect
        )
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"OAuth code exchange failed: {str(e)}")

    access_token = tokens.get("access_token")
    refresh_token = tokens.get("refresh_token")
    expires_in = tokens.get("expires_in", 3600)

    try:
        profile = await fetch_google_user_profile(access_token)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Profile retrieval failed: {str(e)}")

    email = profile.get("email")
    if not email:
        raise HTTPException(status_code=400, detail="Google account email not found in profile.")

    existing = db.query(ConnectedAccount).filter(ConnectedAccount.email == email).first()
    expiry_dt = datetime.datetime.utcnow() + datetime.timedelta(seconds=expires_in)

    if existing:
        existing.encrypted_access_token = encrypt_token(access_token)
        if refresh_token:
            existing.encrypted_refresh_token = encrypt_token(refresh_token)
        existing.token_expiry = expiry_dt
        existing.is_active = True
        existing.display_name = profile.get("name")
        existing.profile_picture = profile.get("picture")
        account_obj = existing
    else:
        account_obj = ConnectedAccount(
            email=email,
            google_user_id=profile.get("id"),
            display_name=profile.get("name"),
            profile_picture=profile.get("picture"),
            encrypted_access_token=encrypt_token(access_token),
            encrypted_refresh_token=encrypt_token(refresh_token or ""),
            token_expiry=expiry_dt,
            is_active=True
        )
        db.add(account_obj)

    # Register watch with Google Cloud Pub/Sub
    watch_res = await register_gmail_watch(access_token)
    if "historyId" in watch_res:
        account_obj.last_history_id = str(watch_res["historyId"])
        account_obj.watch_expiry = datetime.datetime.utcnow() + datetime.timedelta(days=7)

    # Log security event
    db.add(SecurityEvent(
        event_type="account_connected",
        title="Gmail Account Connected",
        description=f"Successfully authenticated and connected Gmail account {email} via OAuth 2.0.",
        severity="info",
        target_item=email
    ))

    db.commit()
    db.refresh(account_obj)

    return {
        "status": "connected",
        "email": account_obj.email,
        "display_name": account_obj.display_name,
        "watch_registered": bool(account_obj.last_history_id)
    }

@router.get("/accounts")
def list_accounts(db: Session = Depends(get_db)):
    """Lists all connected accounts without exposing secret tokens."""
    accounts = db.query(ConnectedAccount).filter(ConnectedAccount.is_active == True).all()
    return [
        {
            "id": a.id,
            "email": a.email,
            "display_name": a.display_name,
            "profile_picture": a.profile_picture,
            "connected_at": a.connected_at.isoformat() if a.connected_at else None,
            "last_synced_at": a.last_synced_at.isoformat() if a.last_synced_at else None,
            "is_active": a.is_active,
            "watch_active": bool(a.watch_expiry and a.watch_expiry > datetime.datetime.utcnow())
        }
        for a in accounts
    ]

@router.get("/overview")
def get_gmail_overview(db: Session = Depends(get_db)):
    """Returns real connected mailboxes and Gmail-linked scan verdicts for the dashboard."""
    demo_email = "analyst.demo@phishguard-soc.org"
    scans_query = db.query(Scan).filter(
        Scan.gmail_message_id.isnot(None),
        or_(Scan.account_email.is_(None), Scan.account_email != demo_email)
    )
    risk_buckets = {
        "safe": scans_query.filter(Scan.risk_score < 20).count(),
        "suspicious": scans_query.filter(Scan.risk_score >= 20, Scan.risk_score < 40).count(),
        "high_risk": scans_query.filter(Scan.risk_score >= 40, Scan.risk_score < 70).count(),
        "critical": scans_query.filter(Scan.risk_score >= 70).count()
    }
    recent_scans = scans_query.order_by(Scan.created_at.desc()).limit(12).all()
    accounts = db.query(ConnectedAccount).filter(
        ConnectedAccount.is_active.is_(True),
        ConnectedAccount.email != demo_email
    ).order_by(ConnectedAccount.connected_at.desc()).all()

    messages = []
    for scan in recent_scans:
        try:
            analysis = json.loads(scan.analysis_json)
        except (TypeError, json.JSONDecodeError):
            analysis = {}
        messages.append({
            "scan_id": scan.id,
            "gmail_message_id": scan.gmail_message_id,
            "account_email": scan.account_email,
            "subject": scan.submitted_item,
            "sender": analysis.get("sender", ""),
            "risk_score": scan.risk_score,
            "classification": scan.classification,
            "classification_label": (
                "Critical risk" if scan.risk_score >= 70 else
                "High risk" if scan.risk_score >= 40 else
                "Suspicious" if scan.risk_score >= 20 else
                "No high-risk signals"
            ),
            "created_at": scan.created_at.isoformat() if scan.created_at else None,
            "indicator_count": len(scan.indicators)
        })

    return {
        "connected_accounts": [
            {
                "email": account.email,
                "display_name": account.display_name,
                "connected_at": account.connected_at.isoformat() if account.connected_at else None,
                "last_synced_at": account.last_synced_at.isoformat() if account.last_synced_at else None
            }
            for account in accounts
        ],
        "gmail_messages_scanned": sum(risk_buckets.values()),
        "threats_detected": risk_buckets["suspicious"] + risk_buckets["high_risk"] + risk_buckets["critical"],
        "risk_buckets": risk_buckets,
        "recent_messages": messages
    }

@router.delete("/accounts/{account_id}")
def disconnect_account(account_id: int, db: Session = Depends(get_db)):
    """Disconnects and deactivates a Gmail account."""
    acc = db.query(ConnectedAccount).filter(ConnectedAccount.id == account_id).first()
    if not acc:
        raise HTTPException(status_code=404, detail="Connected account not found")

    email = acc.email
    db.delete(acc)

    db.add(SecurityEvent(
        event_type="account_disconnected",
        title="Gmail Account Disconnected",
        description=f"Account {email} disconnected by user. Mailbox monitoring terminated.",
        severity="info",
        target_item=email
    ))
    db.commit()

    return {"message": f"Account {email} disconnected successfully."}

@router.post("/sync/{account_id}")
async def sync_mailbox(
    account_id: int,
    max_results: int = Query(default=50, ge=1, le=100),
    page_token: Optional[str] = Query(default=None, max_length=4096),
    db: Session = Depends(get_db)
):
    """Analyzes one paginated batch of the authorized account's Inbox."""
    acc = db.query(ConnectedAccount).filter(
        ConnectedAccount.id == account_id,
        ConnectedAccount.is_active.is_(True)
    ).first()
    if not acc:
        raise HTTPException(status_code=404, detail="Active connected account not found")
    if "demo" in acc.email.lower():
        raise HTTPException(status_code=400, detail="Demonstration mailboxes cannot be background-scanned.")

    access_token = decrypt_token(acc.encrypted_access_token)
    if not access_token:
        raise HTTPException(status_code=400, detail="Invalid token; please reconnect account.")

    if acc.token_expiry and acc.token_expiry <= datetime.datetime.utcnow():
        try:
            access_token = await refresh_access_token(acc, db)
        except (ValueError, httpx.HTTPError) as error:
            raise HTTPException(status_code=400, detail=f"Gmail authorization expired; reconnect the account: {error}") from error

    try:
        page = await fetch_gmail_messages_page(
            access_token,
            max_results=max_results,
            page_token=page_token
        )
    except (ValueError, httpx.HTTPError) as error:
        message = str(error)
        if "accessNotConfigured" in message:
            raise HTTPException(status_code=503, detail=message) from error
        if "insufficientPermissions" in message:
            raise HTTPException(status_code=403, detail=message) from error
        raise HTTPException(status_code=502, detail=f"Failed to list Gmail Inbox messages: {message}") from error

    messages = page["messages"]
    message_ids = [message.get("id") for message in messages if message.get("id")]
    existing_scans = db.query(Scan).filter(
        Scan.account_email == acc.email,
        Scan.gmail_message_id.in_(message_ids)
    ).all() if message_ids else []
    scans_by_message_id = {
        scan.gmail_message_id: scan
        for scan in sorted(existing_scans, key=lambda item: item.created_at or datetime.datetime.min)
    }

    async def fetch_message_detail(message_id: str) -> Dict[str, Any]:
        async with semaphore:
            return await fetch_gmail_message_detail(access_token, message_id)

    semaphore = asyncio.Semaphore(8)
    details = await asyncio.gather(
        *(fetch_message_detail(message_id) for message_id in message_ids),
        return_exceptions=True
    )
    details_by_message_id = dict(zip(message_ids, details))

    failures = []
    verdicts = []
    processed_count = 0

    for message in messages:
        message_id = message.get("id")
        thread_id = message.get("threadId")
        if not message_id:
            failures.append({"message_id": None, "error": "Gmail returned a message without an ID."})
            continue

        existing_scan = scans_by_message_id.get(message_id)
        if existing_scan:
            if thread_id and not existing_scan.gmail_thread_id:
                existing_scan.gmail_thread_id = thread_id
            scan = existing_scan
        else:
            full_message = details_by_message_id.get(message_id)
            if isinstance(full_message, Exception):
                failures.append({"message_id": message_id, "error": str(full_message)})
                continue

            parsed = parse_gmail_payload(full_message)
            analysis = analyze_email({
                "sender": parsed["sender"],
                "subject": parsed["subject"],
                "body": parsed["body"],
                "reply_to": parsed["reply_to"]
            })
            scan = Scan(
                scan_type="email",
                submitted_item=parsed["subject"] or parsed["sender"] or "Gmail Message",
                risk_score=analysis["risk_score"],
                classification=analysis["classification"],
                created_at=datetime.datetime.utcnow(),
                analysis_json=json.dumps(analysis),
                gmail_message_id=message_id,
                gmail_thread_id=parsed["thread_id"] or thread_id,
                account_email=acc.email
            )
            db.add(scan)
            db.flush()

            for indicator in analysis.get("indicators", []):
                db.add(Indicator(
                    scan_id=scan.id,
                    indicator_name=indicator.get("name", ""),
                    severity=indicator.get("severity", "medium"),
                    risk_points=indicator.get("points", 0),
                    description=indicator.get("description", "")
                ))
            for recommendation in analysis.get("recommendations", []):
                db.add(Recommendation(
                    scan_id=scan.id,
                    recommendation_text=recommendation
                ))
            for attachment in parsed.get("attachments", []):
                attachment_analysis = analyze_attachment(
                    filename=attachment.get("filename", ""),
                    file_size=attachment.get("size", 0),
                    declared_mime=attachment.get("mimeType")
                )
                db.add(Attachment(
                    scan_id=scan.id,
                    filename=attachment_analysis["filename"],
                    file_size=attachment_analysis["file_size"],
                    mime_type=attachment_analysis["mime_type"],
                    sha256_hash=attachment_analysis["sha256_hash"],
                    is_dangerous=attachment_analysis["is_dangerous"],
                    threat_score=attachment_analysis["threat_score"],
                    threat_reasons=json.dumps(attachment_analysis["threat_reasons"])
                ))
            db.add(SecurityEvent(
                event_type="email_detected",
                title=f"New Email Evaluated ({analysis['classification_label']})",
                description=f"Analyzed message '{parsed['subject'][:80]}' from {parsed['sender']}. Risk Score: {analysis['risk_score']}/100.",
                severity="critical" if analysis["risk_score"] >= 70 else ("high" if analysis["risk_score"] >= 40 else "info"),
                target_item=parsed["subject"],
                scan_id=scan.id
            ))
            scans_by_message_id[message_id] = scan
            processed_count += 1

        formatted_scan = _format_message_scan(scan, scan.gmail_message_id)
        verdicts.append({
            "scan_id": scan.id,
            "message_id": scan.gmail_message_id,
            "thread_id": scan.gmail_thread_id or thread_id,
            "subject": scan.submitted_item,
            "sender": formatted_scan["sender"],
            "risk_score": scan.risk_score,
            "classification": scan.classification,
            "classification_label": formatted_scan["classification_label"],
            "indicator_count": len(formatted_scan["indicators"]),
            "scanned_at": scan.created_at.isoformat() if scan.created_at else None
        })

    acc.last_synced_at = datetime.datetime.utcnow()
    db.commit()

    return {
        "status": "success",
        "account_email": acc.email,
        "processed_new_messages": processed_count,
        "page_count": len(messages),
        "next_page_token": page["next_page_token"],
        "failed_messages": failures,
        "verdicts": verdicts
    }

@router.post("/pubsub")
async def pubsub_webhook(request: Request, db: Session = Depends(get_db)):
    """Receives Google Cloud Pub/Sub push notifications for mailbox changes."""
    body = await request.json()
    message = body.get("message", {})
    data_b64 = message.get("data")
    if not data_b64:
        return {"status": "ignored", "reason": "No data payload"}

    try:
        decoded_json = json.loads(base64.b64decode(data_b64).decode("utf-8"))
        email_address = decoded_json.get("emailAddress")
        history_id = decoded_json.get("historyId")
    except Exception:
        return {"status": "error", "reason": "Malformed Pub/Sub payload"}

    acc = db.query(ConnectedAccount).filter(ConnectedAccount.email == email_address).first()
    if not acc:
        return {"status": "ignored", "reason": "Account not recognized"}

    acc.last_history_id = str(history_id)
    db.add(SecurityEvent(
        event_type="pubsub_notification",
        title="Pub/Sub Mailbox Notification Received",
        description=f"Received mailbox state change notification for {email_address} (History ID: {history_id}).",
        severity="info",
        target_item=email_address
    ))
    db.commit()

    return {"status": "processed", "historyId": history_id}

@router.post("/actions")
async def execute_action(payload: ActionPayload, db: Session = Depends(get_db)):
    """Executes a confirmed user action (keep, quarantine, trash, report)."""
    acc = db.query(ConnectedAccount).filter(ConnectedAccount.email == payload.account_email).first()
    if not acc:
        # Check if any active account exists to associate with the action
        acc = db.query(ConnectedAccount).filter(ConnectedAccount.is_active == True).first()
        if not acc:
            raise HTTPException(status_code=404, detail="No connected account found for this action")

    act_type = payload.action_type.lower()
    if act_type == "keep":
        res = await execute_keep_email(acc, payload.gmail_message_id, payload.scan_id, db, payload.notes)
    elif act_type == "quarantine":
        res = await execute_quarantine_email(acc, payload.gmail_message_id, payload.scan_id, db)
    elif act_type == "trash":
        res = await execute_trash_email(acc, payload.gmail_message_id, payload.scan_id, db)
    elif act_type == "report":
        res = await execute_report_phishing(acc, payload.gmail_message_id, payload.scan_id, db)
    else:
        raise HTTPException(status_code=400, detail=f"Unknown action type: {act_type}")

    return res

@router.get("/message/{message_id}")
def get_message_scan(
    message_id: str,
    account_email: Optional[str] = Query(None),
    db: Session = Depends(get_db)
):
    """Chrome Extension endpoint: Retrieves scan for a Gmail message ID."""
    query = db.query(Scan).filter(Scan.gmail_message_id == message_id)
    if account_email:
        query = query.filter(Scan.account_email == account_email)
    scan = query.order_by(Scan.created_at.desc()).first()
    if not scan:
        return {"status": "pending", "message_id": message_id}

    return _format_message_scan(scan, message_id)

def _format_message_scan(scan: Scan, message_id: str) -> Dict[str, Any]:
    try:
        data = json.loads(scan.analysis_json)
    except (TypeError, json.JSONDecodeError):
        data = {}

    return {
        "status": "completed",
        "scan_id": scan.id,
        "message_id": message_id,
        "thread_id": scan.gmail_thread_id,
        "account_email": scan.account_email,
        "sender": data.get("sender", ""),
        "risk_score": scan.risk_score,
        "classification": scan.classification,
        "classification_label": data.get("classification_label", scan.classification.title()),
        "badge_color": data.get("badge_color", "slate"),
        "indicators": [
            {"name": ind.indicator_name, "severity": ind.severity, "description": ind.description}
            for ind in scan.indicators
        ],
        "recommendations": [rec.recommendation_text for rec in scan.recommendations],
        "positive_observations": data.get("positive_observations", []),
        "extracted_urls": data.get("extracted_urls", [])
    }

@router.post("/extension/scan")
def scan_open_gmail_message(payload: GmailExtensionScanRequest, db: Session = Depends(get_db)):
    """Analyzes and caches an opened Gmail message for the browser extension."""
    return _scan_open_gmail_message(payload, db)

@router.post("/addon/scan")
def scan_gmail_addon_message(
    payload: GmailExtensionScanRequest,
    authorization: Optional[str] = Header(None),
    db: Session = Depends(get_db)
):
    """Authenticates and analyzes a message from the Gmail Workspace add-on."""
    expected_key = settings.GMAIL_ADDON_API_KEY
    if len(expected_key) < 32:
        raise HTTPException(status_code=503, detail="Gmail add-on API access is not configured.")

    parts = authorization.split(None, 1) if authorization else []
    supplied_key = parts[1].strip() if len(parts) == 2 and parts[0].lower() == "bearer" else ""
    if not secrets.compare_digest(supplied_key, expected_key):
        raise HTTPException(status_code=401, detail="Gmail add-on authorization failed.")

    return _scan_open_gmail_message(payload, db)

def _scan_open_gmail_message(payload: GmailExtensionScanRequest, db: Session) -> Dict[str, Any]:
    query = db.query(Scan).filter(Scan.gmail_message_id == payload.gmail_message_id)
    if payload.account_email:
        query = query.filter(Scan.account_email == payload.account_email)
    else:
        query = query.filter(Scan.account_email.is_(None))
    existing_scan = query.order_by(Scan.created_at.desc()).first()
    if existing_scan:
        if payload.gmail_thread_id and not existing_scan.gmail_thread_id:
            existing_scan.gmail_thread_id = payload.gmail_thread_id
            db.commit()
        return _format_message_scan(existing_scan, payload.gmail_message_id)

    analysis = analyze_email({
        "sender": payload.sender,
        "subject": payload.subject,
        "body": payload.body,
        "reply_to": payload.reply_to or ""
    })
    scan = Scan(
        scan_type="email",
        submitted_item=payload.subject or payload.sender or "Gmail Message",
        risk_score=analysis["risk_score"],
        classification=analysis["classification"],
        created_at=datetime.datetime.utcnow(),
        analysis_json=json.dumps(analysis),
        gmail_message_id=payload.gmail_message_id,
        gmail_thread_id=payload.gmail_thread_id,
        account_email=payload.account_email
    )
    db.add(scan)
    db.flush()

    for indicator in analysis.get("indicators", []):
        db.add(Indicator(
            scan_id=scan.id,
            indicator_name=indicator.get("name", "Indicator"),
            severity=indicator.get("severity", "medium"),
            risk_points=indicator.get("points", 0),
            description=indicator.get("description", "")
        ))
    for recommendation in analysis.get("recommendations", []):
        db.add(Recommendation(
            scan_id=scan.id,
            recommendation_text=recommendation
        ))

    db.commit()
    db.refresh(scan)
    return _format_message_scan(scan, payload.gmail_message_id)
