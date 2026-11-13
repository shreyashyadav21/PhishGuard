from fastapi import APIRouter, Depends, UploadFile, File, Form, HTTPException
from sqlalchemy.orm import Session
from typing import Optional, List
import json
from ..database import get_db
from ..models import Attachment, Scan
from ..detection.attachment_scanner import analyze_attachment

router = APIRouter(prefix="/attachments", tags=["Attachment Security"])

@router.post("/scan")
async def scan_attachment_file(
    file: UploadFile = File(...),
    db: Session = Depends(get_db)
):
    """
    Performs safe static inspection of an uploaded attachment file.
    Inspects magic bytes, hashes, extensions without code execution.
    """
    content = await file.read()
    analysis = analyze_attachment(
        filename=file.filename or "unknown_file",
        content_bytes=content,
        file_size=len(content),
        declared_mime=file.content_type
    )
    return analysis

@router.get("")
def list_attachments(db: Session = Depends(get_db)):
    """Lists scanned attachments across all emails."""
    attachments = db.query(Attachment).order_by(Attachment.id.desc()).limit(50).all()
    results = []
    for att in attachments:
        try:
            reasons = json.loads(att.threat_reasons)
        except Exception:
            reasons = []

        results.append({
            "id": att.id,
            "scan_id": att.scan_id,
            "filename": att.filename,
            "file_size": att.file_size,
            "mime_type": att.mime_type,
            "sha256_hash": att.sha256_hash,
            "is_dangerous": att.is_dangerous,
            "threat_score": att.threat_score,
            "threat_reasons": reasons
        })
    return results

