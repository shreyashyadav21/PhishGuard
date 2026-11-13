# PhishGuard Live Demonstration & Hackathon Presentation Guide

This guide provides a structured 5-minute walkthrough to demonstrate all capabilities of **PhishGuard** to judges, clients, and security teams.

---

## ⏱️ 5-Minute Demonstration Script

### Minute 1: SOC Command Center & Overview Dashboard
- Open `http://localhost:5173`.
- Show the **Overview Dashboard**:
  - Point out that **Total Scans, Safe Results, Suspicious Results, High-Risk Detections, and Detection Rate** are computed live from SQLite.
  - Demonstrate the **Scan Activity Timeline** (toggle between 7-day, 30-day, and 90-day surveillance windows).
  - Highlight the **Threat Distribution Donut** and **Category Frequency** chart.

### Minute 2: URL Scanner & Zero-SSRF Phishing Detection
- Navigate to **URL Scanner** (`/url-scanner`).
- Click on one of the quick test scenarios:
  - Select **Homoglyph Phishing**: `http://paypa1-login-security.example.com/verify`.
- Click **Analyze URL**.
- Highlight:
  - The circular **Risk Meter** jumping to Critical Risk.
  - The itemized indicators: Insecure HTTP (+5 pts), Homoglyph Typosquatting (+30 pts), Deceptive Brand Subdomain (+30 pts), Security Keywords (+15 pts).
  - The **Positive Security Observations** confirming RFC parsing.
  - The **Zero-SSRF guarantee**: Explain that no outbound requests were initiated to the attacker's server.
- Click **Export PDF Report** to show the ReportLab generated audit document.

### Minute 3: Email Scanner with Interactive Phrase Highlighter
- Navigate to **Email Scanner** (`/email-scanner`).
- Click the **PayPal Account Suspended** quick scenario.
- Click **Analyze Email**.
- Showcase:
  - The **Interactive Phishing Phrase Highlighter**: Flagged urgency cues (`"account suspended within 24 hours"`, `"immediate action required"`) and credential solicitation tokens (`"password"`, `"otp"`, `"card details"`) are highlighted in amber and red.
  - The **Extracted Hyperlinks Table**: Show how links are recursively parsed and rated.
  - The **Sender Spoofing Alert**: Point out the discrepancy between display name and untrusted `.xyz` domain.

### Minute 4: Gmail Protection & Chrome Extension In Action
- Open Google Chrome with the PhishGuard extension loaded from `Cyber/extension`.
- Show the extension popup: Confirms `Backend Sensor: Online (8000)`.
- Open a Gmail message:
  - Demonstrate the **in-Gmail PhishGuard security banner** appearing dynamically above the email.
  - Point out the color-coded warning (Green / Yellow / Orange / Red).
  - Demonstrate the user-controlled action buttons:
    - Click **Quarantine**: Demonstrates the prompt, applies the `PhishGuard/Quarantine` label, and removes the message from the inbox.
    - Click **Move to Trash**: Demonstrates non-destructive trashing.
- Navigate back to the Web Dashboard:
  - Open **Live Surveillance** (`/live-monitoring`) to show the real-time stream.
  - Open **Personal Threat Timeline** (`/timeline`) to show the logged Quarantine event.

### Minute 5: Attachment Security, Campaigns & Cybersecurity Academy
- Open **Attachment Security** (`/attachments`):
  - Upload a test file (e.g. `Statement.pdf.exe`).
  - Demonstrate magic byte signature verification and double extension detection without code execution.
- Open **Phishing Campaigns** (`/campaigns`):
  - Click **Run Correlation Analysis** to group multi-email waves targeting brands like PayPal or Microsoft.
- Open **Defense Academy** (`/learn`):
  - Show the 10 learning cards.
  - Open the **Interactive 10-Question Awareness Quiz**, submit answers, and display the knowledge level badge and celebration confetti!

