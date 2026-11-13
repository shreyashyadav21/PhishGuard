# PhishGuard Complete Ecosystem Architecture

## 1. System Topology

PhishGuard is an integrated, explainable cybersecurity command center and threat intelligence platform designed to protect users across both the web dashboard and native email clients (Gmail).

```
+-----------------------------------------------------------------------------------+
|                            USER SURVEILLANCE SURFACES                             |
|                                                                                   |
|  +---------------------------------------+   +---------------------------------+  |
|  |     REACT 19 SOC WEB COMMAND CENTER   |   |   MANIFEST V3 CHROME EXTENSION  |  |
|  |   - Overview Dashboard & KPI Trends   |   |   - Gmail MutationObserver      |  |
|  |   - URL Scanner & Zero-SSRF Sandbox   |   |   - In-Gmail Warning Banners    |  |
|  |   - Email Phrase Highlighter          |   |   - Risk Meter (Green/Red)      |  |
|  |   - Impersonation Guardian Matrix     |   |   - User Actions (Keep/Quar)    |  |
|  |   - Attachment Security Inspector     |   |   - Zero-Token Client Sandbox   |  |
|  |   - Phishing Campaign Correlator      |   +----------------+----------------+  |
|  |   - Personal Threat Timeline          |                    |                   |
|  |   - Defense Academy & 10-Q Quiz       |                    |                   |
|  +-------------------+-------------------+                    |                   |
+----------------------|----------------------------------------|-------------------+
                       |                                        |
                       | REST API (JSON / HTTP)                 |
                       v                                        v
+-----------------------------------------------------------------------------------+
|                        FASTAPI ENTERPRISE BACKEND SERVICE                         |
|                                                                                   |
|  +-----------------------------------------------------------------------------+  |
|  |                              API ROUTERS LAYER                              |  |
|  |  /api/health       /api/scan/url        /api/scan/email    /api/dashboard   |  |
|  |  /api/gmail/*      /api/attachments/*   /api/campaigns/*   /api/timeline    |  |
|  |  /api/reports/*    /api/quiz/*          /api/settings      /api/ai/explain  |  |
|  +-----------------------------------------------------------------------------+  |
|                                        |                                          |
|  +-------------------------------------+---------------------------------------+  |
|  |                           DETECTION & AUDIT CORE                            |  |
|  |  [url_analyzer.py]       [email_analyzer.py]       [domain_analyzer.py]     |  |
|  |  - RFC 3986 Parsing      - Urgency / Lures         - 13 Brand Matrices      |  |
|  |  - Raw IP Detection      - Credential Solicit      - Levenshtein & Homoglyph|  |
|  |  - Character Masking     - Reply-To Divergence     - Abused TLDs (.xyz,top) |  |
|  |                                                                             |  |
|  |  [attachment_scanner.py] [campaign_engine.py]      [ai_explainer.py]        |  |
|  |  - Double Extensions     - Shared Target Clusters  - Grounded Heuristics    |  |
|  |  - Magic Signatures (MZ) - Infrastructure Waves    - Prompt Injection Proof |  |
|  |  - SHA-256 Hashes        - Confidence Scoring      - Local Fallback Engine  |  |
|  +-----------------------------------------------------------------------------+  |
|                                        |                                          |
|  +-------------------------------------+---------------------------------------+  |
|  |                       SERVICES & INTEGRATION LAYER                          |  |
|  |  [gmail_service.py]      [gmail_actions.py]        [report_generator.py]    |  |
|  |  - Google OAuth 2.0      - User-Controlled Keep    - ReportLab PDF Engine   |  |
|  |  - Fernet AES Encryption - Quarantine Isolation   - Publication Reports    |  |
|  |  - Pub/Sub Webhook       - Non-destructive Trash   - Executive Audits       |  |
|  +-----------------------------------------------------------------------------+  |
+----------------------------------------+------------------------------------------+
                                         |
                                         v
+-----------------------------------------------------------------------------------+
|                              DATA & STORAGE LAYER                                 |
|   SQLite 3 / PostgreSQL with SQLAlchemy ORM                                       |
|   Tables: scans, indicators, recommendations, connected_accounts, attachments,    |
|   campaigns, campaign_emails, user_actions, security_events, settings, quiz       |
+-----------------------------------------------------------------------------------+
```

---

## 2. Ingestion & Communication Lifecycles

### 2.1 Web Ingestion Lifecycle
1. User enters URL or Email in React frontend.
2. Frontend submits JSON payload to `/api/scan/url` or `/api/scan/email`.
3. Backend performs pure in-memory static parsing without initiating external HTTP connections (**Zero-SSRF guarantee**).
4. Weighted scoring engine caps correlated signals and assigns severity (0–100).
5. Data is committed transactionally to `scans`, `indicators`, and `recommendations`.
6. Associated security event logged in `security_events` table for Threat Timeline.
7. Structured JSON response returned to frontend; Recharts components and gauges animate.

### 2.2 Gmail Ingestion & Chrome Extension Lifecycle
1. User connects mailbox via OAuth 2.0 (`/api/gmail/oauth/url`); tokens are encrypted using 256-bit Fernet AES.
2. Webhook registered with Google Cloud Pub/Sub (`users.watch`).
3. When new email arrives:
   - Pub/Sub pushes webhook event containing `historyId` to `/api/gmail/pubsub`.
   - Backend queries Gmail History API for new messages.
   - Message body, headers, links, and attachments are statically evaluated.
4. When user opens email in Gmail web client:
   - Chrome Extension `MutationObserver` detects message view container.
   - Queries `/api/gmail/message/{id}` to fetch existing evaluation.
   - Extension injects non-intrusive color-coded warning banner (Green/Yellow/Orange/Red).
   - User reviews indicators and selects **Keep**, **Quarantine**, or **Move to Trash**.
   - Backend executes authorized Gmail action via `gmail_actions.py`.
