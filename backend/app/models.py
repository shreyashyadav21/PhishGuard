import datetime
from sqlalchemy import Column, Integer, String, Text, DateTime, ForeignKey, Boolean
from sqlalchemy.orm import relationship
from .database import Base

class Scan(Base):
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, index=True)
    scan_type = Column(String(50), nullable=False, index=True)  # "url" or "email"
    submitted_item = Column(Text, nullable=False)               # URL or Email Subject
    risk_score = Column(Integer, nullable=False, index=True)    # 0 - 100
    classification = Column(String(50), nullable=False, index=True)  # "safe", "suspicious", "high_risk", "critical"
    created_at = Column(DateTime, default=datetime.datetime.utcnow, index=True)
    analysis_json = Column(Text, nullable=False)                # JSON serialized result
    gmail_message_id = Column(String(100), nullable=True, index=True) # Gmail Message ID if from mailbox
    gmail_thread_id = Column(String(100), nullable=True, index=True) # Gmail thread containing the message
    account_email = Column(String(255), nullable=True, index=True)   # Associated monitored account

    indicators = relationship("Indicator", back_populates="scan", cascade="all, delete-orphan")
    recommendations = relationship("Recommendation", back_populates="scan", cascade="all, delete-orphan")
    attachments = relationship("Attachment", back_populates="scan", cascade="all, delete-orphan")
    actions = relationship("UserAction", back_populates="scan", cascade="all, delete-orphan")


class Indicator(Base):
    __tablename__ = "indicators"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)
    indicator_name = Column(String(200), nullable=False)
    severity = Column(String(50), nullable=False)              # "low", "medium", "high", "critical"
    risk_points = Column(Integer, nullable=False)
    description = Column(Text, nullable=False)

    scan = relationship("Scan", back_populates="indicators")


class Recommendation(Base):
    __tablename__ = "recommendations"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)
    recommendation_text = Column(Text, nullable=False)

    scan = relationship("Scan", back_populates="recommendations")


class Setting(Base):
    __tablename__ = "settings"

    id = Column(Integer, primary_key=True, index=True)
    setting_key = Column(String(100), unique=True, nullable=False, index=True)
    setting_value = Column(Text, nullable=False)


class QuizAttempt(Base):
    __tablename__ = "quiz_attempts"

    id = Column(Integer, primary_key=True, index=True)
    total_questions = Column(Integer, nullable=False)
    correct_answers = Column(Integer, nullable=False)
    score = Column(Integer, nullable=False)  # Percentage 0-100
    created_at = Column(DateTime, default=datetime.datetime.utcnow, index=True)


class ThreatIndicator(Base):
    __tablename__ = "threat_indicators"

    id = Column(Integer, primary_key=True, index=True)
    indicator_value = Column(String(255), nullable=False, index=True)
    category = Column(String(100), nullable=False, index=True)
    severity = Column(String(50), nullable=False, index=True)
    detection_reason = Column(Text, nullable=False)
    first_observed = Column(DateTime, default=datetime.datetime.utcnow)
    scan_count = Column(Integer, default=1)
    is_simulated = Column(Boolean, default=False)
    recommended_action = Column(Text, nullable=False)


# --- Phase 4 & 5: Gmail Connected Accounts & Mailbox Watches ---
class ConnectedAccount(Base):
    __tablename__ = "connected_accounts"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(255), unique=True, nullable=False, index=True)
    google_user_id = Column(String(255), nullable=True, index=True)
    display_name = Column(String(255), nullable=True)
    profile_picture = Column(Text, nullable=True)
    encrypted_access_token = Column(Text, nullable=False)
    encrypted_refresh_token = Column(Text, nullable=True)
    token_expiry = Column(DateTime, nullable=True)
    last_history_id = Column(String(100), nullable=True)
    watch_expiry = Column(DateTime, nullable=True)
    is_active = Column(Boolean, default=True)
    connected_at = Column(DateTime, default=datetime.datetime.utcnow)
    last_synced_at = Column(DateTime, default=datetime.datetime.utcnow)


# --- Phase 7: Attachment Security Scanner ---
class Attachment(Base):
    __tablename__ = "attachments"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)
    filename = Column(String(255), nullable=False)
    file_size = Column(Integer, default=0)
    mime_type = Column(String(100), default="application/octet-stream")
    sha256_hash = Column(String(64), index=True)
    is_dangerous = Column(Boolean, default=False)
    threat_score = Column(Integer, default=0)
    threat_reasons = Column(Text, default="[]")  # JSON list of flags

    scan = relationship("Scan", back_populates="attachments")


# --- Phase 9: Phishing Campaign Correlation ---
class Campaign(Base):
    __tablename__ = "campaigns"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), nullable=False, index=True)
    target_brand = Column(String(100), nullable=True, index=True)
    common_sender_domain = Column(String(255), nullable=True, index=True)
    common_subject_pattern = Column(String(255), nullable=True)
    severity = Column(String(50), default="High")
    confidence_score = Column(Integer, default=80)
    email_count = Column(Integer, default=1)
    first_observed = Column(DateTime, default=datetime.datetime.utcnow)
    last_observed = Column(DateTime, default=datetime.datetime.utcnow)

    emails = relationship("CampaignEmail", back_populates="campaign", cascade="all, delete-orphan")


class CampaignEmail(Base):
    __tablename__ = "campaign_emails"

    id = Column(Integer, primary_key=True, index=True)
    campaign_id = Column(Integer, ForeignKey("campaigns.id", ondelete="CASCADE"), nullable=False, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)

    campaign = relationship("Campaign", back_populates="emails")


# --- Phase 10: Gmail User-Controlled Actions ---
class UserAction(Base):
    __tablename__ = "user_actions"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id", ondelete="CASCADE"), nullable=True, index=True)
    account_email = Column(String(255), nullable=False, index=True)
    gmail_message_id = Column(String(100), nullable=False, index=True)
    action_type = Column(String(50), nullable=False)  # "keep", "quarantine", "trash", "report"
    action_timestamp = Column(DateTime, default=datetime.datetime.utcnow)
    status = Column(String(50), default="completed")  # "completed", "reverted"
    notes = Column(Text, nullable=True)

    scan = relationship("Scan", back_populates="actions")


# --- Phase 13: Personal Threat Timeline ---
class SecurityEvent(Base):
    __tablename__ = "security_events"

    id = Column(Integer, primary_key=True, index=True)
    event_type = Column(String(50), nullable=False, index=True)  # "email_detected", "threat_identified", "quarantine", "trash", "keep", "report"
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=False)
    severity = Column(String(50), default="info", index=True)  # "low", "medium", "high", "critical", "info"
    target_item = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow, index=True)
    scan_id = Column(Integer, nullable=True)
