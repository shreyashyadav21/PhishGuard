from fastapi import APIRouter, Depends, HTTPException, Body
from sqlalchemy.orm import Session
from pydantic import BaseModel
from typing import Optional, Dict, Any
import json
from ..database import get_db
from ..models import Scan
from ..detection.ai_explainer import generate_threat_explanation

router = APIRouter(prefix="/ai", tags=["AI Threat Explanations"])

class ExplainRequest(BaseModel):
    scan_id: int
    question: Optional[str] = None

@router.post("/explain")
def explain_threat(payload: ExplainRequest, db: Session = Depends(get_db)):
    """
    Returns AI / heuristic explainability for a scan report.
    Answers user questions with prompt injection protections.
    """
    scan = db.query(Scan).filter(Scan.id == payload.scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail=f"Scan record {payload.scan_id} not found")

    try:
        data = json.loads(scan.analysis_json)
    except Exception:
        data = {}

    explanation = generate_threat_explanation(data, custom_question=payload.question)
    return explanation

