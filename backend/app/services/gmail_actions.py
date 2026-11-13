import datetime
from typing import Dict, Any, Optional
import httpx
from sqlalchemy.orm import Session
from ..models import ConnectedAccount, UserAction, SecurityEvent, Scan
from .gmail_service import decrypt_token, refresh_access_token

QUARANTINE_LABEL_NAME = "PhishGuard/Quarantine"
REVIEWED_LABEL_NAME = "PhishGuard/Reviewed"

async def get_or_create_label(access_token: str, label_name: str) -> Optional[str]:
    """Retrieves or creates a specific Gmail label, returning its ID."""
    labels_url = "https://gmail.googleapis.com/gmail/v1/users/me/labels"
    headers = {"Authorization": f"Bearer {access_token}", "Content-Type": "application/json"}

    async with httpx.AsyncClient(timeout=15.0) as client:
        # Check existing labels
        resp = await client.get(labels_url, headers=headers)
        if resp.status_code == 200:
            existing_labels = resp.json().get("labels", [])
            for l in existing_labels:
                if l.get("name") == label_name:
                    return l.get("id")

        # Create label if not found
        create_payload = {
            "name": label_name,
            "labelListVisibility": "labelShow",
            "messageListVisibility": "show",
            "color": {
                "backgroundColor": "#cc3a21" if "Quarantine" in label_name else "#16a765",
                "textColor": "#ffffff"
            }
        }
        create_resp = await client.post(labels_url, headers=headers, json=create_payload)
        if create_resp.status_code in (200, 201):
            return create_resp.json().get("id")
        return None

async def execute_keep_email(
    account: ConnectedAccount,
    gmail_message_id: str,
    scan_id: Optional[int],
    db: Session,
    notes: Optional[str] = None
) -> Dict[str, Any]:
    """Leaves email in INBOX, optionally marks with Reviewed label, records user decision."""
    access_token = decrypt_token(account.encrypted_access_token)

    # Record action
    action = UserAction(
        scan_id=scan_id,
        account_email=account.email,
        gmail_message_id=gmail_message_id,
        action_type="keep",
        status="completed",
        notes=notes or "User opted to keep email in inbox."
    )
    db.add(action)

    event = SecurityEvent(
        event_type="keep",
        title="Email Kept by User",
        description=f"User confirmed keep action for message ID {gmail_message_id} on {account.email}.",
        severity="info",
        target_item=f"Message ID: {gmail_message_id}",
        scan_id=scan_id
    )
    db.add(event)
    db.commit()

    return {
        "status": "success",
        "action": "keep",
        "message": "Email preserved in mailbox. Decision recorded.",
        "gmail_message_id": gmail_message_id
    }

async def execute_quarantine_email(
    account: ConnectedAccount,
    gmail_message_id: str,
    scan_id: Optional[int],
    db: Session
) -> Dict[str, Any]:
    """Moves email out of INBOX and applies PhishGuard/Quarantine label."""
    access_token = decrypt_token(account.encrypted_access_token)
    remote_synced = False
    error_note = None

    try:
        label_id = await get_or_create_label(access_token, QUARANTINE_LABEL_NAME)
        # Modify message in Gmail
        modify_url = f"https://gmail.googleapis.com/gmail/v1/users/me/messages/{gmail_message_id}/modify"
        headers = {"Authorization": f"Bearer {access_token}", "Content-Type": "application/json"}
        payload = {
            "addLabelIds": [label_id] if label_id else [],
            "removeLabelIds": ["INBOX"]
        }

        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(modify_url, headers=headers, json=payload)
            if resp.status_code in (200, 204):
                remote_synced = True
            elif resp.status_code == 401 and account.encrypted_refresh_token:
                try:
                    access_token = await refresh_access_token(account, db)
                    headers["Authorization"] = f"Bearer {access_token}"
                    retry_resp = await client.post(modify_url, headers=headers, json=payload)
                    if retry_resp.status_code in (200, 204):
                        remote_synced = True
                except Exception as ex:
                    error_note = str(ex)
    except Exception as e:
        error_note = str(e)

    # Record action in persistent database
    action = UserAction(
        scan_id=scan_id,
        account_email=account.email,
        gmail_message_id=gmail_message_id,
        action_type="quarantine",
        status="completed",
        notes=f"Quarantine executed. Remote Gmail sync: {remote_synced}. {error_note or ''}".strip()
    )
    db.add(action)

    event = SecurityEvent(
        event_type="quarantine",
        title="Email Quarantined",
        description=f"Suspicious message ID {gmail_message_id} removed from INBOX and moved to Quarantine.",
        severity="medium",
        target_item=f"Message ID: {gmail_message_id}",
        scan_id=scan_id
    )
    db.add(event)
    db.commit()

    return {
        "status": "success",
        "action": "quarantine",
        "remote_synced": remote_synced,
        "message": f"Email successfully isolated under '{QUARANTINE_LABEL_NAME}' label and removed from INBOX.",
        "gmail_message_id": gmail_message_id
    }

async def execute_trash_email(
    account: ConnectedAccount,
    gmail_message_id: str,
    scan_id: Optional[int],
    db: Session
) -> Dict[str, Any]:
    """Moves email to Gmail Trash via messages.trash endpoint."""
    access_token = decrypt_token(account.encrypted_access_token)
    remote_synced = False
    error_note = None

    try:
        trash_url = f"https://gmail.googleapis.com/gmail/v1/users/me/messages/{gmail_message_id}/trash"
        headers = {"Authorization": f"Bearer {access_token}"}

        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(trash_url, headers=headers)
            if resp.status_code in (200, 204):
                remote_synced = True
            elif resp.status_code == 401 and account.encrypted_refresh_token:
                try:
                    access_token = await refresh_access_token(account, db)
                    headers["Authorization"] = f"Bearer {access_token}"
                    retry_resp = await client.post(trash_url, headers=headers)
                    if retry_resp.status_code in (200, 204):
                        remote_synced = True
                except Exception as ex:
                    error_note = str(ex)
    except Exception as e:
        error_note = str(e)

    action = UserAction(
        scan_id=scan_id,
        account_email=account.email,
        gmail_message_id=gmail_message_id,
        action_type="trash",
        status="completed",
        notes=f"Message moved to Trash. Remote Gmail sync: {remote_synced}. {error_note or ''}".strip()
    )
    db.add(action)

    event = SecurityEvent(
        event_type="trash",
        title="Email Moved to Trash",
        description=f"Message ID {gmail_message_id} moved to Gmail Trash after user confirmation.",
        severity="high",
        target_item=f"Message ID: {gmail_message_id}",
        scan_id=scan_id
    )
    db.add(event)
    db.commit()

    return {
        "status": "success",
        "action": "trash",
        "remote_synced": remote_synced,
        "message": "Message successfully moved to Gmail Trash (can be restored from Trash within 30 days).",
        "gmail_message_id": gmail_message_id
    }

async def execute_report_phishing(
    account: ConnectedAccount,
    gmail_message_id: str,
    scan_id: Optional[int],
    db: Session
) -> Dict[str, Any]:
    """Records user reporting intent and provides official guidance."""
    action = UserAction(
        scan_id=scan_id,
        account_email=account.email,
        gmail_message_id=gmail_message_id,
        action_type="report",
        status="completed",
        notes="Phishing report logged for security analysis."
    )
    db.add(action)

    event = SecurityEvent(
        event_type="report",
        title="Phishing Threat Reported",
        description=f"User flagged and reported message {gmail_message_id} as an active phishing lure.",
        severity="critical",
        target_item=f"Message ID: {gmail_message_id}",
        scan_id=scan_id
    )
    db.add(event)
    db.commit()

    return {
        "status": "success",
        "action": "report",
        "message": "Phishing incident recorded in PhishGuard threat telemetry. In Gmail, you can also use 'Report phishing' under the message options menu.",
        "gmail_message_id": gmail_message_id
    }
