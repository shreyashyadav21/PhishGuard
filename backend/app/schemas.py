from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from datetime import datetime

class URLScanRequest(BaseModel):
    url: str = Field(..., max_length=4096, description="URL string to analyze")

class EmailScanRequest(BaseModel):
    sender: str = Field(default="", max_length=500, description="Email sender address or display name")
    subject: str = Field(default="", max_length=1000, description="Email subject line")
    body: str = Field(default="", max_length=100000, description="Email content/body")
    reply_to: Optional[str] = Field(default="", max_length=500, description="Optional Reply-To header")

class GmailExtensionScanRequest(EmailScanRequest):
    gmail_message_id: str = Field(..., min_length=1, max_length=100)
    gmail_thread_id: Optional[str] = Field(default=None, max_length=100)
    account_email: Optional[str] = Field(default=None, max_length=255)

class IndicatorSchema(BaseModel):
    name: str
    severity: str
    points: int
    description: str
    category: Optional[str] = None
    evidence: Optional[str] = None

class ScanSummaryItem(BaseModel):
    id: int
    scan_type: str
    submitted_item: str
    risk_score: int
    classification: str
    classification_label: Optional[str] = None
    badge_color: Optional[str] = None
    created_at: datetime
    indicator_count: Optional[int] = 0

class ScanDetailResponse(BaseModel):
    id: int
    scan_type: str
    submitted_item: str
    risk_score: int
    classification: str
    classification_label: Optional[str] = None
    badge_color: Optional[str] = None
    created_at: datetime
    analysis_details: Dict[str, Any]
    indicators: List[Dict[str, Any]]
    recommendations: List[str]
    positive_observations: List[str]

class DashboardStatsResponse(BaseModel):
    total_scans: int
    safe_scans: int
    suspicious_scans: int
    high_risk_scans: int
    critical_scans: int
    threat_detection_rate: float
    threat_distribution: Dict[str, int]
    category_counts: Dict[str, int]
    activity_timeline: List[Dict[str, Any]]
    recent_scans: List[ScanSummaryItem]

class ThreatIndicatorItem(BaseModel):
    id: int
    indicator_value: str
    category: str
    severity: str
    detection_reason: str
    first_observed: datetime
    scan_count: int
    is_simulated: bool
    recommended_action: str

class QuizQuestion(BaseModel):
    id: int
    question: str
    options: List[str]
    explanation: str

class QuizSubmitRequest(BaseModel):
    answers: Dict[int, int]  # question_id -> selected_option_index

class QuizResultResponse(BaseModel):
    total_questions: int
    correct_answers: int
    score_percentage: int
    knowledge_level: str
    feedback: List[Dict[str, Any]]

class SettingItem(BaseModel):
    key: str
    value: str

class SettingsUpdate(BaseModel):
    settings: Dict[str, str]

