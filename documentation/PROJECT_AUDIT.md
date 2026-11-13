# PhishGuard – Project Audit & Gap Analysis

**Date:** November 2026  
**Auditor:** Senior Full-Stack & Cybersecurity Systems Architect  
**Project State:** Operational Prototype transitioning to Complete SOC & Gmail Monitoring Ecosystem

---

## 1. Executive Summary

PhishGuard currently possesses a solid, working core foundation:
- A high-performance, Zero-SSRF Python FastAPI detection engine (`url_analyzer.py`, `email_analyzer.py`, `domain_analyzer.py`, `risk_scoring.py`, `recommendations.py`).
- 20 comprehensive backend tests passing with 100% success rate.
- SQLite database with SQLAlchemy ORM (`scans`, `indicators`, `recommendations`, `threat_indicators`, `quiz_attempts`, `settings`).
- A React 19 + Vite + Tailwind CSS frontend dashboard with Overview, URL Scanner, Email Scanner, Threat Intelligence, Scan History, Security Reports, Academy, and Settings.

However, several advanced enterprise capabilities specified in the intended architecture remain unbuilt or partially implemented, specifically:
1. Google OAuth 2.0 & Gmail API direct mailbox synchronization.
2. Google Cloud Pub/Sub real-time webhook ingestion (`users.watch`).
3. Static attachment security scanner (SHA-256, magic bytes, archive inspection).
4. AI Threat Explanation Engine with prompt injection immunity and local fallback.
5. Cross-email Phishing Campaign correlation engine.
6. Gmail User-Controlled Actions (Keep, Quarantine Labeling, Trash, Reporting).
7. Manifest V3 Chrome Extension for inline Gmail warning banners.
8. Personal Threat Timeline and specialized SOC views.

---

## 2. Component-by-Component Audit Matrix

| Component / Feature | Current Status | Notes & Verification Findings |
|---|---|---|
| **FastAPI Core (`backend/app/main.py`)** | **COMPLETE** | CORS enabled, lifespan table initialization, router aggregation. |
| **URL Analysis Engine (`url_analyzer.py`)** | **COMPLETE** | 100% Zero-SSRF, RFC 3986 syntax, IP check, length, `@` trick, percent encoding. |
| **Domain Impersonation (`domain_analyzer.py`)** | **COMPLETE** | 13 brand matrices, Levenshtein distance, homoglyph normalization, TLD checks. |
| **Manual Email Scanner (`email_analyzer.py`)** | **COMPLETE** | Urgency triggers, credential solicitation, reply-to mismatch, link extraction. |
| **Risk Scoring (`risk_scoring.py`)** | **COMPLETE** | Weighted scoring 0–100, category caps, classification bands. |
| **ReportLab PDF Generator (`report_generator.py`)**| **COMPLETE** | Produces branded PDF reports for URL and email scans. |
| **Overview Dashboard (`Overview.jsx`)** | **COMPLETE** | Real stats from SQLite, Recharts activity and distribution charts. |
| **URL Scanner Page (`UrlScanner.jsx`)** | **COMPLETE** | Interactive input, quick samples, risk meter, itemized indicators. |
| **Email Scanner Page (`EmailScanner.jsx`)** | **COMPLETE** | Interactive phrase highlighter, extracted links audit table. |
| **Threat Intelligence (`ThreatIntel.jsx`)** | **COMPLETE** | Searchable IOCs, severity/category filters, simulated vs live tags. |
| **Scan History (`ScanHistory.jsx`)** | **COMPLETE** | DB-backed search, sort, filter, delete, purge with confirmation. |
| **Security Reports (`SecurityReports.jsx`)** | **COMPLETE** | Downloadable PDF audits. |
| **Defense Academy & Quiz (`LearnCybersecurity.jsx`)**| **COMPLETE** | 10 knowledge modules, 10-question quiz with scoring and confetti. |
| **System Settings (`SettingsPage.jsx`)** | **COMPLETE** | Persistent database-backed configuration. |
| **Gmail OAuth 2.0 Integration** | **NOT IMPLEMENTED** | Needs Google Auth credentials, token exchange, refresh token handling. |
| **Automatic Email Monitoring & Pub/Sub** | **NOT IMPLEMENTED** | Needs `users.watch`, webhook endpoint, and Gmail History API sync. |
| **Attachment Security Scanner** | **NOT IMPLEMENTED** | Needs static inspection (mime, magic bytes, hash, double extension). |
| **AI Threat Explanation Engine** | **NOT IMPLEMENTED** | Needs natural language synthesis, prompt injection barrier & local fallback. |
| **Phishing Campaign Detection** | **NOT IMPLEMENTED** | Needs correlation on senders, subjects, URLs, attachment hashes. |
| **Gmail User-Controlled Actions** | **NOT IMPLEMENTED** | Needs Keep, Quarantine (`INBOX` removal + label), Trash (`messages.trash`). |
| **Chrome Extension (Manifest V3)** | **NOT IMPLEMENTED** | Needs content scripts, MutationObserver, inline Gmail warning banners. |
| **Personal Threat Timeline** | **NOT IMPLEMENTED** | Needs security events database table & timeline visualizer. |
| **Connected Accounts & OAuth Storage** | **NOT IMPLEMENTED** | Needs `connected_accounts` table with AES/Fernet token encryption. |

---

## 3. Required Enhancements & Implementation Plan

### Step 1: Database Model & Schema Expansion
Expand `backend/app/models.py` and `schemas.py` without breaking existing tables:
- `ConnectedAccount`: Stores Google account credentials securely (tokens encrypted).
- `Attachment`: Metadata for scanned email attachments.
- `Campaign` & `CampaignEmail`: Tracks coordinated multi-message campaigns.
- `UserAction`: Tracks user mitigation decisions (Keep, Quarantine, Trash).
- `SecurityEvent`: Real-time timeline telemetry entries.

### Step 2: Static Attachment Scanner Engine
Create `backend/app/detection/attachment_scanner.py`:
- Safe static inspection of filenames, extensions, MIME types, file sizes, SHA-256 hashes.
- Magic signature byte inspection.
- Detection of dangerous extensions (`.exe`, `.scr`, `.bat`, `.vbs`, `.js`, `.hta`, `.docm`, `.xlsm`, `.iso`).
- Detection of double extension deception (e.g. `invoice.pdf.exe`).

### Step 3: AI Threat Explainer with Deterministic Fallback
Create `backend/app/detection/ai_explainer.py`:
- Generates natural-language analysis for non-technical users.
- Built-in prompt injection immunity (treats email body strictly as unexecuted text data).
- Robust deterministic local heuristic fallback if no external LLM API key is present.
- Support for common analyst questions ("Why is this dangerous?", "Is the sender genuine?").

### Step 4: Campaign Correlation Engine
Create `backend/app/detection/campaign_engine.py`:
- Groups emails sharing common infrastructure, identical extracted lure domains, subject regexes, or attachment hashes.
- Quantifies campaign severity, first/last seen timestamps, and affected user metrics.

### Step 5: Gmail OAuth 2.0 & Cloud Pub/Sub Integration
Create `backend/app/services/gmail_service.py` & `backend/app/services/gmail_actions.py`:
- Google OAuth 2.0 URL generation, callback exchange, and Fernet token encryption.
- Account profile retrieval and disconnection.
- Mailbox watch registration (`users.watch`) and Pub/Sub webhook endpoint (`/api/gmail/pubsub`).
- Gmail History API retrieval (`users.history.list`) to catch incoming messages in real-time.
- User actions: Keep (apply label), Quarantine (apply `PhishGuard/Quarantine`, remove `INBOX`), Move to Trash (`users.messages.trash`), and Phishing report recording.

### Step 6: Manifest V3 Chrome Extension
Create `extension/` directory:
- `manifest.json`: Manifest V3 specification with host permissions for `mail.google.com` and `http://127.0.0.1:8000/*`.
- `background.js`: Service worker communicating with PhishGuard API.
- `content.js`: Injected into Gmail with a MutationObserver to detect opened emails, extract message IDs, query the backend, and inject non-intrusive, color-coded warning banners (Green, Yellow, Orange, Red) with Keep/Quarantine/Trash buttons.
- `popup.html` & `popup.js`: Quick extension status and backend health indicator.

### Step 7: Web Dashboard Enhancements
Extend the React dashboard with the remaining specialized SOC views:
- **Gmail Connection & Live Monitoring** (`GmailMonitor.jsx`).
- **Campaign Detection** (`CampaignView.jsx`).
- **Attachment Security** (`AttachmentScannerView.jsx`).
- **Personal Threat Timeline** (`ThreatTimelineView.jsx`).
- Update Sidebar navigation to access all modules smoothly.

### Step 8: Comprehensive Verification & Pytest Suite
Add test suites for all new modules:
- `test_attachment_scanner.py`
- `test_campaign_engine.py`
- `test_ai_explainer.py`
- `test_gmail_actions.py`
Verify 100% test pass rate and update documentation.

