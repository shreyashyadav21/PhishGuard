# PhishGuard Complete REST API Documentation

The PhishGuard backend service is built using FastAPI with OpenAPI 3.0 schema definitions. Interactive Swagger UI is available at `/docs` and ReDoc at `/redoc`.

**Base URL:** `http://localhost:8000/api`

---

## 1. System Health & Diagnostics
- **`GET /api/health`**
  - Returns backend status, detection engine version, and mode.
  - Response:
    ```json
    {
      "status": "healthy",
      "app_name": "PhishGuard",
      "app_version": "2.5.0",
      "detection_engine_version": "3.2.0-ENTERPRISE",
      "ssrf_protection": "enabled",
      "mode": "standalone-soc"
    }
    ```

---

## 2. Detection & Heuristic Scanning

- **`POST /api/scan/url`**
  - **Body:** `{"url": "http://paypa1-security.example.com/verify"}`
  - Returns calculated risk score (0-100), classification, itemized indicators, positive observations, and recommendations.

- **`POST /api/scan/email`**
  - **Body:** `{"sender": "...", "subject": "...", "body": "...", "reply_to": "..."}`
  - Evaluates message body, highlights urgency/credential phrases, extracts links and runs URL analyzer recursively.

- **`POST /api/attachments/scan`**
  - **Multipart Form:** `file: <binary>`
  - Static file inspection: Double extensions, magic bytes, SHA-256 hash. Returns `is_dangerous` and `threat_score`.

---

## 3. Gmail Integration & Mailbox Protection

- **`GET /api/gmail/oauth/url`**
  - Generates the Google OAuth 2.0 authorization URL.

- **`POST /api/gmail/oauth/callback`**
  - **Body:** `{"code": "4/0A..."}`
  - Exchanges code for tokens, encrypts tokens with Fernet AES, registers `users.watch`, returns account profile.

- **`GET /api/gmail/accounts`**
  - Lists connected mailboxes with watch status.

- **`GET /api/gmail/overview`**
  - Returns active non-demo Gmail accounts, Gmail-linked scan totals, risk buckets, and recent message verdicts for the dashboard.
  - Excludes manual scans and seeded demonstration-mailbox records.

- **`DELETE /api/gmail/accounts/{id}`**
  - Disconnects mailbox and terminates monitoring.

- **`POST /api/gmail/sync/{id}`**
  - Scans one paginated batch from the connected account's INBOX. Optional query parameters: `max_results` (1-100, default 50) and `page_token`.
  - Returns per-message verdicts, Gmail thread IDs, `next_page_token`, and any messages that could not be fetched. The extension advances the page token across scheduled runs.

- **`POST /api/gmail/extension/scan`**
  - Accepts the opened message's `gmail_message_id`, optional `gmail_thread_id` and `account_email`, sender, subject, and body.
  - Returns the cached or newly calculated verdict, including its Gmail thread ID for the extension's row badge.

- **`POST /api/gmail/pubsub`**
  - Google Cloud Pub/Sub push webhook endpoint for incoming mailbox notifications.

- **`POST /api/gmail/actions`**
  - **Body:**
    ```json
    {
      "account_email": "user@gmail.com",
      "gmail_message_id": "18f921a8c0",
      "action_type": "quarantine", // "keep" | "quarantine" | "trash" | "report"
      "scan_id": 14
    }
    ```
  - Executes confirmed action in Gmail (e.g. removes INBOX label and applies `PhishGuard/Quarantine`).

- **`GET /api/gmail/message/{message_id}`**
  - Dedicated endpoint for Chrome Extension: returns risk score, indicators, account email, and Gmail thread ID for a Gmail message ID.

- **`POST /api/gmail/addon/scan`**
  - Gmail Workspace add-on endpoint. Requires `Authorization: Bearer <GMAIL_ADDON_API_KEY>`.
  - Accepts the currently opened Gmail message fields and returns a cached verdict, risk score, indicators, link analysis, and recommendations.
  - Configure the same random key in the backend environment and Apps Script project properties. The backend must be publicly reachable over HTTPS for Apps Script.

---

## 4. SOC Analytics, History & Reports

- **`GET /api/dashboard/stats?days=30`**
  - Aggregated metrics, 7d/30d/90d scan activity timeline, threat distribution, and category frequency.

- **`GET /api/scans`**
  - Search, filter by classification/type, and sort history records.

- **`GET /api/reports/{scan_id}/pdf`**
  - Generates downloadable ReportLab PDF report.

- **`GET /api/timeline`**
  - Personal Threat Timeline event stream.

- **`GET /api/campaigns`**
  - Lists correlated phishing campaigns and clusters.

- **`POST /api/campaigns/correlate`**
  - Triggers active campaign correlation across historical scans.

---

## 5. AI Threat Explainer & Defense Academy

- **`POST /api/ai/explain`**
  - **Body:** `{"scan_id": 14, "question": "Why is this email dangerous?"}`
  - Returns grounded threat explanation with prompt injection protection.

- **`GET /api/quiz/questions`**
  - Returns 10 multiple-choice cybersecurity awareness questions.

- **`POST /api/quiz/submit`**
  - **Body:** `{"answers": {"1": 1, "2": 1, ...}}`
  - Grades submission, returns feedback, explanations, and knowledge level badge.

