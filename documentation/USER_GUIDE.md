# PhishGuard User & Security Analyst Guide

Welcome to **PhishGuard**, an AI-powered phishing detection and threat intelligence platform designed for SOC analysts, cybersecurity students, and everyday users.

---

## 1. Getting Started

### 1.1 Overview Dashboard
Upon opening the application, the SOC command center displays:
- **Total Scans, Safe Results, Suspicious Results, High-Risk Detections**, and **Detection Rate**.
- An interactive **Scan Activity Timeline** (toggle between 7-day, 30-day, and 90-day surveillance windows).
- A **Threat Distribution Donut** visualizer and **Threat Category Frequency** breakdown.
- **Recent Scans** with one-click "View Report" actions.

---

## 2. Analyzing a Suspicious Link (URL Scanner)

1. Navigate to **URL Scanner** from the sidebar or click **New Scan**.
2. Paste the target link into the address field or click one of the pre-loaded **Quick Test Cases** (e.g. *Homoglyph Phishing*, *Raw IP Hostname*, or *Deceptive @ Masking*).
3. Click **Analyze URL**.
4. The system evaluates the URL structure without contacting the destination server (Zero-SSRF):
   - View the **Risk Meter** gauge (0 - 100).
   - Review each **Detected Indicator** with point weight and technical explanation.
   - Read **Positive Security Observations** confirming safe parameters.
   - Follow the **Prescribed Remediation Actions**.
5. Click **Export PDF Report** to download an audit file.

---

## 3. Analyzing an Email Message (Email Scanner)

1. Navigate to **Email Scanner**.
2. Fill in the **From / Sender Address**, **Subject Line**, and **Email Content**. You can also test with pre-configured scenarios (*PayPal Account Suspended*, *Microsoft Display Name Spoofing*, or *Benign Meeting*).
3. Click **Analyze Email**.
4. Explore the interactive results:
   - **Interactive Phishing Phrase Highlighter**: Flagged urgency cues and credential requests are highlighted in amber and red.
   - **Extracted Hyperlinks Table**: Every link embedded in the message is independently parsed and assigned its own risk score.
   - **Sender Spoofing Warnings**: Alerts if the friendly name claims a brand but the sending domain is unregistered.

---

## 4. Threat Intelligence Center

- Access the **Threat Intelligence** module to inspect persistent Indicators of Compromise (IOCs).
- Filter by threat categories such as *Domain Impersonation*, *Credential Theft*, or *Social Engineering*.
- Filter by severity levels: *Critical*, *High*, *Medium*, *Low*.
- Click **Inspect Details** on any indicator to view historical hit counts, observation timestamps, and firewall blocking advice. Demonstration records are clearly marked with a `Simulated Seed` tag.

---

## 5. Security Reports & Compliance

- Access **Security Reports** to review all historical assessments.
- Download branded, publication-ready PDF reports formatted for incident response teams and executive leadership.

---

## 6. Cybersecurity Defense Academy & Awareness Quiz

- Study the **10 Core Learning Modules** explaining phishing anatomy, SMTP spoofing, HTTPS myths, and MFA best practices.
- Take the **10-Question Awareness Quiz** to test your phishing detection reflexes.
- Receive instant grading, detailed explanations for every option, and earn your knowledge badge (*SOC Master Defender*, *Security Guardian*, or *Cyber Aware*).

