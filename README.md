# PhishGuard – AI-Powered Phishing Detection & Threat Intelligence Platform

PhishGuard is an integrated, enterprise-grade cybersecurity command center and threat intelligence platform designed to protect organizations, SOC analysts, and everyday users from phishing attacks across web URLs and native Gmail mailboxes.

Operating on a **Zero-SSRF static analysis model**, PhishGuard inspects payloads without initiating outbound network connections, delivers explainable risk scores (0–100), provides user-controlled email quarantine actions, and includes a Manifest V3 extension for Chromium browsers such as Brave and Chrome, plus a Gmail Workspace add-on for contextual verdicts on desktop and mobile.

## Website working 
https://phishguard-h88c.onrender.com

---

## 🏛️ Complete System Architecture

```
Cyber/
├── frontend/                     # React 19 + Vite 8 + Tailwind CSS v4 + Recharts
│   ├── src/
│   │   ├── api/client.js        # Axios instance configured with API proxy
│   │   ├── components/          # RiskMeter, Sidebar, Navbar, ReportViewModal
│   │   ├── pages/               # User-facing Gmail protection and threat views
├── backend/                      # Python 3.11+ / FastAPI + SQLAlchemy 2.0 + ReportLab
│   ├── app/
│   │   ├── detection/           # Modular detection engine:
│   │   │                        # - url_analyzer.py (Zero-SSRF, RFC 3986, @ trick, IP checks)
│   │   │                        # - email_analyzer.py (Urgency, credential solicitation, spoofing)
│   │   │                        # - domain_analyzer.py (13 brands, Levenshtein, homoglyphs)
│   │   │                        # - attachment_scanner.py (Magic bytes, double extensions, SHA-256)
│   │   │                        # - campaign_engine.py (Cross-message correlation clusters)
│   │   │                        # - ai_explainer.py (Prompt injection proof threat explainer)
│   │   │                        # - risk_scoring.py & recommendations.py
│   │   ├── api/                 # REST endpoints (health, scan, gmail, campaigns, attachments,
│   │   │                        #                  timeline, ai, dashboard, history, threats, reports, quiz)
│   │   ├── services/            # OAuth token encryption (Fernet), Gmail actions (Keep, Quarantine, Trash),
│   │   │                        # ReportLab PDF engine, and demonstration seed data
│   │   ├── database.py          # SQLite engine with in-place safe schema migrations
│   │   ├── models.py            # Complete relational schema (10 tables)
│   │   └── main.py              # Application lifecycle & CORS configuration
│   └── tests/                   # 30 Pytest unit & integration tests (100% pass)
├── extension/                   # Manifest V3 Chromium extension for Gmail (Brave/Chrome)
│   ├── manifest.json            # Manifest V3 configuration with mail.google.com permissions
│   ├── content.js               # MutationObserver, message ID extraction & on-open verdict overlay
│   ├── background.js            # Background service worker API bridge
│   ├── popup.html & popup.js    # Quick sensor status & SOC dashboard launcher
│   └── styles.css               # Verdict overlay and Inbox badge styles
├── gmail-addon/                 # Gmail Workspace add-on for desktop and mobile
│   ├── Code.gs                  # On-open message analysis and contextual verdict card
│   └── appsscript.json          # Gmail trigger and least-privilege scopes
├── documentation/               # Comprehensive technical manuals:
│   ├── PROJECT_AUDIT.md         # Component-by-component audit matrix & gap analysis
│   ├── ARCHITECTURE.md          # Complete ecosystem topology & data lifecycles
│   ├── DATABASE.md              # Relational schema, tables, foreign keys & migrations
│   ├── GMAIL_SETUP.md           # Step-by-step Google Cloud OAuth 2.0 guide
│   ├── PUBSUB_SETUP.md          # Google Cloud Pub/Sub real-time webhook ingestion guide
│   ├── EXTENSION_SETUP.md       # Brave/Chrome extension installation & testing instructions
│   ├── GMAIL_ADDON_SETUP.md     # Gmail add-on HTTPS setup and test deployment
│   ├── API_DOCUMENTATION.md     # OpenAPI / REST endpoint specifications
│   ├── SECURITY.md              # Threat modeling, Zero-SSRF, Fernet AES, and prompt protection
│   ├── TESTING_REPORT.md        # Pytest test execution logs & environment verification
│   └── DEMO_GUIDE.md            # 5-minute live hackathon presentation guide
├── .env.example                 # Environment variables template
├── run_dev.ps1                  # Windows PowerShell launcher
└── run_dev.bat                  # Windows CMD launcher
```

---

## ⚡ Core Capabilities

1. **Zero-SSRF Heuristic Scanner**: Evaluates URLs without contacting destination servers. Detects IP hostnames, deceptive `@` masking, excessive length, percent encoding, and open redirects.
2. **Impersonation Guardian**: 13 corporate profiles (Google, Microsoft, Apple, Amazon, PayPal, Netflix, SBI, HDFC, ICICI, etc.) with safe Levenshtein edit distance and homoglyph normalization matrices (`0` $\to$ `o`, `1` $\to$ `l`, `rn` $\to$ `m`).
3. **Gmail Integration & Pub/Sub Monitoring**: Google OAuth 2.0 authorization, AES/Fernet token encryption, `users.watch` push webhooks, and Gmail History API synchronization.
4. **User-Controlled Email Actions**:
   - **Keep Email**: Preserves message and records decision.
   - **Quarantine**: Removes message from `INBOX` and applies the `PhishGuard/Quarantine` label.
   - **Move to Trash**: Safely moves message to Gmail Trash (`messages.trash`).
   - **Report Phishing**: Records threat telemetry with Gmail guidance.
5. **Static Attachment Security Sandbox**: Detects double extensions (`invoice.pdf.exe`), Windows executable magic headers (`MZ`) disguised as photos or documents, macro containers (`.docm`, `.xlsm`), and computes cryptographic SHA-256 hashes.
6. **AI Threat Explainer with Injection Protection**: Explains technical indicators in plain English, answers user questions, enforces prompt injection sanitization, and defaults to deterministic local heuristics.
7. **Phishing Campaign Correlation**: Automatically clusters recurring attacks sharing sender domains, subject regexes, brand targets, or attachment hashes.
8. **Gmail protection surfaces**: The Brave/Chrome extension shows a fixed desktop verdict overlay when a message is opened and per-message Inbox badges; the Gmail Workspace add-on shows a contextual verdict card on desktop and mobile when opened for the current message. Extension verdicts are heuristic estimates, not guarantees.
9. **Gmail-first dashboard**: Shows real Gmail-linked verdicts and flagged messages only; manual email and URL submission pages are not part of the user-facing app.
10. **Personal Threat Timeline**: Chronological stream auditing every detected threat, user action, and quarantine isolation.
11. **Defense Academy & Quiz**: 10 educational modules and an interactive 10-question awareness quiz with live grading, confetti animations, and knowledge level badges.

---

## 🚀 Quickstart Guide

### 1. Start the Backend API
```bash
cd backend
py -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```
- API Health Status: `http://127.0.0.1:8000/api/health`
- Interactive Swagger Documentation: `http://127.0.0.1:8000/docs`

### 2. Start the Frontend SOC Console
```bash
cd frontend
npm.cmd run dev
```
- Open your browser to `http://localhost:5173`.

### 3. Install the Brave or Chrome Extension
1. In Brave, open `brave://extensions/` (in Chrome, open `chrome://extensions/`).
2. Enable **Developer mode** in the top-right.
3. Click **Load unpacked** and select the `Cyber/extension` directory. The same Manifest V3 extension works in Brave; a separate Brave-specific build is not needed.
4. Open [Gmail](https://mail.google.com/) and open a message to see its fixed PhishGuard verdict overlay. Inbox scans require a connected Gmail account; both Inbox and opened-message scans require the backend to be running.

After changing extension files, open the browser's extensions page, reload PhishGuard, then refresh Gmail. See [EXTENSION_SETUP.md](documentation/EXTENSION_SETUP.md) for Brave setup and troubleshooting.

**Accuracy note:** PhishGuard does not currently have a validated detection-accuracy percentage. Measure precision, recall, and false-positive/false-negative rates against a labeled dataset before relying on its verdicts.

### 4. Add cross-device Gmail verdict cards

Follow [GMAIL_ADDON_SETUP.md](documentation/GMAIL_ADDON_SETUP.md) to deploy the backend over public HTTPS, configure the add-on API key, and test-install the Gmail Workspace add-on. Gmail requires opening the add-on panel to display its card; it cannot force an automatic popup.

## ☁️ Deploy to Render

Deploy the backend and frontend together as one Render Web Service:

1. Create a **Web Service** from this repository. Leave **Root Directory** blank (repository root).
2. Set **Build Command** to `pip install -r backend/requirements.txt && npm --prefix frontend ci && npm --prefix frontend run build`.
3. Set **Start Command** to `cd backend && uvicorn app.main:app --host 0.0.0.0 --port $PORT`.
4. Set `ENCRYPTION_SECRET` to a long, unique secret. Add Google OAuth and other integration variables only if those features are needed; set the Google OAuth authorized redirect URI to `https://<your-service>.onrender.com/gmail-connect`.
5. To persist SQLite data, configure a disk mounted at `/var/data` and set `DATABASE_URL` to `sqlite:////var/data/phishguard.db`. Render persistent disks require a paid web service; without one, SQLite data can be lost when the service restarts or redeploys.

The backend serves the built frontend at `/` and continues to expose the API at `/api` and Swagger docs at `/docs`. The free web service may spin down while idle, so the first request can take longer.

## Deploy to Vercel with Neon

Vercel runs the FastAPI backend as a Python Function and serves the React frontend from the same domain. Neon PostgreSQL provides persistent storage; SQLite is not suitable for Vercel Functions.

1. Create a Neon PostgreSQL database and copy its pooled connection string.
2. Import this repository into Vercel with the repository root as the project root. The root `pyproject.toml` selects the FastAPI entrypoint and runs the frontend build. Vercel installs Python packages from the root `requirements.txt`, which mirrors `backend/requirements.txt`.
3. Add these Vercel Environment Variables for Production and Preview:
   - `DATABASE_URL`: Neon pooled URL (`postgresql://...`). The app converts it to the psycopg SQLAlchemy driver.
   - `ENCRYPTION_SECRET`: a long, unique secret. Keep this value stable so stored Gmail tokens remain decryptable.
   - `GOOGLE_CLIENT_ID` and `GOOGLE_CLIENT_SECRET`: your Google Cloud Web application OAuth credentials.
   - `GOOGLE_REDIRECT_URI`: `https://<your-vercel-domain>/gmail-connect`.
4. In Google Cloud Console, add `https://<your-vercel-domain>` as an Authorized JavaScript origin and `https://<your-vercel-domain>/gmail-connect` as an Authorized redirect URI. Enable the Gmail API and add your account as an OAuth test user if the consent screen is in Testing mode.
5. Deploy from Vercel. The frontend uses same-origin `/api` requests; no `VITE_API_BASE_URL` is needed. The API remains available at `/api` and Swagger at `/docs`.

Optional integration variables include `GOOGLE_PUBSUB_TOPIC`, `GMAIL_ADDON_API_KEY`, and `AI_API_KEY`. A new Neon database is initialized on first startup; existing Render SQLite records are not automatically copied.

---

## 🧪 Automated Pytest Verification

Run the complete 30-test automated verification suite:
```bash
cd backend
py -m pytest -v
```
**Test Result:** `30 passed in 4.75s` (100% pass rate).

---

## ⚖️ Security Notice
PhishGuard is designed to operate safely in secure environments. URL and email evaluations are performed statically without initiating outbound connections (Zero-SSRF). Email bodies are purged by default after processing to respect confidentiality, and passwords or secrets are never logged.
