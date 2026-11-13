# PhishGuard REST API Specification

The PhishGuard backend exposes a comprehensive RESTful API built on FastAPI with OpenAPI 3.0 documentation available interactively at `/docs`.

## Base URL
```
http://localhost:8000/api
```

---

## Endpoints Summary

### 1. Health & Status
- **`GET /api/health`**
  - **Description**: Returns engine operational health and version metadata.
  - **Response 200**:
    ```json
    {
      "status": "healthy",
      "app_name": "PhishGuard",
      "app_version": "2.4.0",
      "detection_engine_version": "3.1.0-SOC",
      "ssrf_protection": "enabled",
      "mode": "standalone-soc"
    }
    ```

---

### 2. URL Scanner
- **`POST /api/scan/url`**
  - **Description**: Evaluates a URL string for phishing, homoglyphs, and structural anomalies.
  - **Request Body**:
    ```json
    {
      "url": "http://paypa1-security.example.com/verify"
    }
    ```
  - **Response 200**:
    ```json
    {
      "id": 14,
      "scan_type": "url",
      "submitted_item": "http://paypa1-security.example.com/verify",
      "risk_score": 85,
      "classification": "critical",
      "classification_label": "Critical Risk",
      "badge_color": "red",
      "indicators": [
        {
          "name": "Brand Impersonation in Subdomain",
          "severity": "critical",
          "points": 30,
          "description": "Brand name 'PayPal' appears in subdomain 'paypa1-security'...",
          "category": "domain_impersonation",
          "evidence": "Subdomain: paypa1-security, Root Domain: example.com"
        }
      ],
      "positive_observations": [],
      "recommendations": [
        "DO NOT submit passwords or credit card numbers on this domain.",
        "Navigate to the official service manually."
      ],
      "created_at": "2026-11-12T18:00:00"
    }
    ```

---

### 3. Email Scanner
- **`POST /api/scan/email`**
  - **Description**: Evaluates an email message for social engineering, urgency, credential harvesting, and spoofing.
  - **Request Body**:
    ```json
    {
      "sender": "Security <support@paypa1.xyz>",
      "subject": "Urgent: Your account is suspended",
      "body": "Please confirm your password at http://paypa1.xyz/login immediately.",
      "reply_to": "attacker@darkmail.xyz"
    }
    ```
  - **Response 200**: Returns score, indicators, extracted links with individual scores, and highlighted phrase spans.

---

### 4. SOC Overview Dashboard
- **`GET /api/dashboard/stats?days=30`**
  - **Parameters**: `days` (7, 30, 90)
  - **Response 200**: Aggregated counts, detection rates, category frequencies, timeline arrays, and recent scans.

---

### 5. Scan History
- **`GET /api/scans`**
  - **Parameters**: `search`, `scan_type`, `classification`, `sort_order`, `limit`, `offset`
- **`GET /api/scans/{scan_id}`**
  - **Description**: Full technical scan detail.
- **`DELETE /api/scans/{scan_id}`**
  - **Description**: Delete individual scan record.
- **`DELETE /api/scans?confirm=true`**
  - **Description**: Purge all scan records from database.

---

### 6. Threat Intelligence
- **`GET /api/threats`**
  - **Parameters**: `category`, `severity`, `search`
- **`GET /api/threats/{threat_id}`**
  - **Description**: In-depth threat IOC details and mitigation advice.

---

### 7. PDF Security Reports
- **`GET /api/reports/{scan_id}/pdf`**
  - **Description**: Generates downloadable branded PDF report.
  - **Response 200**: Binary stream with header `Content-Type: application/pdf`.

---

### 8. Cybersecurity Academy & Quiz
- **`GET /api/quiz/questions`**
  - **Description**: Fetches 10 cybersecurity awareness multiple choice questions.
- **`POST /api/quiz/submit`**
  - **Request Body**: `{"answers": {1: 1, 2: 1, ...}}`
  - **Response 200**: Knowledge level badge, final score percentage, and detailed answer explanations.

---

### 9. Settings
- **`GET /api/settings`**
- **`PUT /api/settings`**
  - **Request Body**: `{"settings": {"store_email_body": "false", "theme": "dark"}}`

