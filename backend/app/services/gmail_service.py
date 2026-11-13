import base64
import json
import datetime
import re
import urllib.parse
from typing import Dict, Any, List, Optional, Tuple
from cryptography.fernet import Fernet
import httpx
from sqlalchemy.orm import Session
from ..config import settings
from ..models import ConnectedAccount, Scan, SecurityEvent
from ..detection.email_analyzer import analyze_email
from ..detection.attachment_scanner import analyze_attachment

# Minimum required Gmail scopes
GMAIL_SCOPES = [
    "https://www.googleapis.com/auth/userinfo.email",
    "https://www.googleapis.com/auth/userinfo.profile",
    "https://www.googleapis.com/auth/gmail.readonly",
    "https://www.googleapis.com/auth/gmail.modify",   # For user-controlled Quarantine label & trash
    "https://www.googleapis.com/auth/gmail.labels",
]

def get_fernet() -> Fernet:
    return Fernet(settings.get_fernet_key())

def encrypt_token(token: str) -> str:
    if not token:
        return ""
    return get_fernet().encrypt(token.encode()).decode()

def decrypt_token(encrypted_token: str) -> str:
    if not encrypted_token:
        return ""
    try:
        return get_fernet().decrypt(encrypted_token.encode()).decode()
    except Exception:
        return ""

def get_google_auth_url(client_id: Optional[str] = None, redirect_uri: Optional[str] = None, state: str = "phishguard_login") -> str:
    """Generates the Google OAuth 2.0 authorization URL."""
    base_url = "https://accounts.google.com/o/oauth2/v2/auth"
    eff_client_id = client_id or settings.GOOGLE_CLIENT_ID
    eff_redirect = redirect_uri or settings.GOOGLE_REDIRECT_URI
    params = {
        "client_id": eff_client_id or "CONFIGURE_IN_SETTINGS",
        "redirect_uri": eff_redirect,
        "response_type": "code",
        "scope": " ".join(GMAIL_SCOPES),
        "access_type": "offline",
        "prompt": "consent",
        "state": state
    }
    return f"{base_url}?{urllib.parse.urlencode(params)}"

async def exchange_code_for_tokens(
    code: str,
    client_id: Optional[str] = None,
    client_secret: Optional[str] = None,
    redirect_uri: Optional[str] = None
) -> Dict[str, Any]:
    """Exchanges authorization code for Google access and refresh tokens."""
    token_url = "https://oauth2.googleapis.com/token"
    eff_client_id = client_id or settings.GOOGLE_CLIENT_ID
    eff_client_secret = client_secret or settings.GOOGLE_CLIENT_SECRET
    eff_redirect = redirect_uri or settings.GOOGLE_REDIRECT_URI
    data = {
        "client_id": eff_client_id,
        "client_secret": eff_client_secret,
        "code": code,
        "grant_type": "authorization_code",
        "redirect_uri": eff_redirect
    }
    async with httpx.AsyncClient(timeout=15.0) as client:
        resp = await client.post(token_url, data=data)
        if resp.status_code != 200:
            raise ValueError(f"Google token exchange failed ({resp.status_code}): {resp.text}")
        return resp.json()

async def refresh_access_token(account: ConnectedAccount, db: Session) -> str:
    """Refreshes expired access token using stored refresh token."""
    refresh_token = decrypt_token(account.encrypted_refresh_token)
    if not refresh_token:
        raise ValueError("No refresh token available for this account.")

    token_url = "https://oauth2.googleapis.com/token"
    data = {
        "client_id": settings.GOOGLE_CLIENT_ID,
        "client_secret": settings.GOOGLE_CLIENT_SECRET,
        "refresh_token": refresh_token,
        "grant_type": "refresh_token"
    }
    async with httpx.AsyncClient(timeout=15.0) as client:
        resp = await client.post(token_url, data=data)
        if resp.status_code != 200:
            raise ValueError(f"Failed to refresh Google token: {resp.text}")
        token_data = resp.json()
        new_access = token_data.get("access_token")
        expires_in = token_data.get("expires_in", 3600)

        account.encrypted_access_token = encrypt_token(new_access)
        account.token_expiry = datetime.datetime.utcnow() + datetime.timedelta(seconds=expires_in)
        db.commit()
        return new_access

async def fetch_google_user_profile(access_token: str) -> Dict[str, Any]:
    """Fetches Google user profile (email, name, picture)."""
    userinfo_url = "https://www.googleapis.com/oauth2/v2/userinfo"
    headers = {"Authorization": f"Bearer {access_token}"}
    async with httpx.AsyncClient(timeout=15.0) as client:
        resp = await client.get(userinfo_url, headers=headers)
        if resp.status_code != 200:
            raise ValueError(f"Failed to fetch user profile: {resp.text}")
        return resp.json()

async def register_gmail_watch(access_token: str, topic_name: Optional[str] = None) -> Dict[str, Any]:
    """Registers Gmail users.watch with Google Cloud Pub/Sub."""
    watch_url = "https://gmail.googleapis.com/gmail/v1/users/me/watch"
    target_topic = topic_name or settings.GOOGLE_PUBSUB_TOPIC
    if not target_topic:
        return {"status": "skipped", "reason": "No Google Pub/Sub topic configured"}

    headers = {"Authorization": f"Bearer {access_token}", "Content-Type": "application/json"}
    payload = {
        "topicName": target_topic,
        "labelIds": ["INBOX"]
    }
    async with httpx.AsyncClient(timeout=15.0) as client:
        resp = await client.post(watch_url, headers=headers, json=payload)
        if resp.status_code == 200:
            return resp.json()
        return {"status": "error", "error": resp.text}

async def fetch_gmail_messages_page(
    access_token: str,
    max_results: int = 50,
    page_token: Optional[str] = None
) -> Dict[str, Any]:
    """Fetches one page of message IDs from the user's INBOX."""
    list_url = "https://gmail.googleapis.com/gmail/v1/users/me/messages"
    headers = {"Authorization": f"Bearer {access_token}"}
    params = {"maxResults": max_results, "q": "label:INBOX"}
    if page_token:
        params["pageToken"] = page_token
    async with httpx.AsyncClient(timeout=15.0) as client:
        resp = await client.get(list_url, headers=headers, params=params)
        if resp.status_code == 200:
            data = resp.json()
            return {
                "messages": data.get("messages", []),
                "next_page_token": data.get("nextPageToken")
            }
        raise _gmail_api_error(resp, "Gmail message-list request")

async def fetch_gmail_messages_list(access_token: str, max_results: int = 10) -> List[Dict[str, Any]]:
    """Fetches the first page of recent message IDs from the user's INBOX."""
    page = await fetch_gmail_messages_page(access_token, max_results=max_results)
    return page["messages"]

def _gmail_api_error(response: httpx.Response, operation: str) -> ValueError:
    """Preserves Google's actionable error reason without returning an unbounded body."""
    try:
        payload = response.json()
    except ValueError:
        payload = {}

    error = payload.get("error", {}) if isinstance(payload, dict) else {}
    if isinstance(error, dict):
        message = " ".join(str(error.get("message", "")).split())[:300]
        reasons = [
            str(item.get("reason"))
            for item in error.get("errors", [])
            if isinstance(item, dict) and item.get("reason")
        ]
        if error.get("status"):
            reasons.append(str(error["status"]))
        details = "; ".join(dict.fromkeys(reasons))
        if "accessNotConfigured" in reasons:
            project = re.search(r"\bproject\s+(\d+)\b", message, re.IGNORECASE)
            project_detail = f" Google Cloud project {project.group(1)}." if project else " this Google Cloud project."
            return ValueError(
                f"{operation} failed (HTTP {response.status_code}, accessNotConfigured): "
                f"Gmail API is not enabled for{project_detail} Enable Gmail API under "
                "Google Cloud Console > APIs & Services > Library, then retry."
            )
        if "insufficientPermissions" in reasons:
            return ValueError(
                f"{operation} failed (HTTP {response.status_code}, insufficientPermissions): "
                "Reconnect Gmail after granting the gmail.readonly scope."
            )
        if details and message:
            return ValueError(f"{operation} failed (HTTP {response.status_code}, {details}): {message}")
        if details:
            return ValueError(f"{operation} failed (HTTP {response.status_code}, {details}).")
        if message:
            return ValueError(f"{operation} failed (HTTP {response.status_code}): {message}")

    return ValueError(f"{operation} failed (HTTP {response.status_code}).")

async def fetch_gmail_message_detail(access_token: str, message_id: str) -> Dict[str, Any]:
    """Fetches complete message structure, headers, body, and attachment metadata."""
    msg_url = f"https://gmail.googleapis.com/gmail/v1/users/me/messages/{message_id}?format=full"
    headers = {"Authorization": f"Bearer {access_token}"}
    async with httpx.AsyncClient(timeout=15.0) as client:
        resp = await client.get(msg_url, headers=headers)
        if resp.status_code != 200:
            raise _gmail_api_error(resp, f"Failed to retrieve Gmail message {message_id}")
        return resp.json()

def parse_gmail_payload(message_json: Dict[str, Any]) -> Dict[str, Any]:
    """Extracts sender, subject, snippet, body text, and attachments from Gmail full format."""
    payload = message_json.get("payload", {})
    headers = payload.get("headers", [])
    
    sender = ""
    subject = ""
    reply_to = ""

    for h in headers:
        name = h.get("name", "").lower()
        if name == "from":
            sender = h.get("value", "")
        elif name == "subject":
            subject = h.get("value", "")
        elif name == "reply-to":
            reply_to = h.get("value", "")

    # Extract body text
    body_text = message_json.get("snippet", "")
    parts = payload.get("parts", [])
    attachments = []

    def extract_parts(parts_list):
        nonlocal body_text
        for part in parts_list:
            mime = part.get("mimeType", "")
            filename = part.get("filename", "")
            body = part.get("body", {})

            if filename:
                attachments.append({
                    "filename": filename,
                    "mimeType": mime,
                    "size": body.get("size", 0),
                    "attachmentId": body.get("attachmentId")
                })
            elif mime == "text/plain" and "data" in body:
                try:
                    decoded = base64.urlsafe_b64decode(body["data"]).decode("utf-8", errors="ignore")
                    if decoded:
                        body_text = decoded
                except Exception:
                    pass
            if "parts" in part:
                extract_parts(part["parts"])

    if parts:
        extract_parts(parts)

    return {
        "message_id": message_json.get("id"),
        "thread_id": message_json.get("threadId"),
        "sender": sender,
        "subject": subject,
        "reply_to": reply_to,
        "body": body_text,
        "attachments": attachments
    }

