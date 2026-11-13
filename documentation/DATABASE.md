# PhishGuard Database Architecture & Schema Specification

**Database Engine:** SQLite 3 (Default local zero-config) / PostgreSQL (Enterprise production)  
**ORM:** SQLAlchemy 2.0  
**Migration Strategy:** In-place metadata reflection and safe non-destructive `ALTER TABLE` column additions.

---

## 1. Relational Entity Diagram

```
+------------------------------------+          +------------------------------------+
|               scans                |          |         connected_accounts         |
+------------------------------------+          +------------------------------------+
| id (PK)                            |          | id (PK)                            |
| scan_type ("url" | "email")        |          | email (UNIQUE)                     |
| submitted_item                     |          | google_user_id                     |
| risk_score (0 - 100)               |          | display_name, profile_picture      |
| classification                     |          | encrypted_access_token (Fernet)    |
| created_at (TIMESTAMP)             |          | encrypted_refresh_token (Fernet)   |
| analysis_json (TEXT)               |          | token_expiry, last_history_id      |
| gmail_message_id (INDEX)           |          | watch_expiry, is_active            |
| account_email                      |          | connected_at, last_synced_at       |
+-----------------+------------------+          +------------------------------------+
                  |
         +--------+--------+-----------------------+
         |                 |                       |
         v                 v                       v
+-----------------+ +--------------------+ +--------------------+
|   indicators    | |  recommendations   | |    attachments     |
+-----------------+ +--------------------+ +--------------------+
| id (PK)         | | id (PK)            | | id (PK)            |
| scan_id (FK)    | | scan_id (FK)       | | scan_id (FK)       |
| indicator_name  | | recommendation_text| | filename, file_size|
| severity        | +--------------------+ | mime_type          |
| risk_points     |                        | sha256_hash (INDEX)|
| description     |                        | is_dangerous (BOOL)|
+-----------------+                        | threat_score       |
                                           | threat_reasons     |
                                           +--------------------+

+------------------------------------+          +------------------------------------+
|             campaigns              |          |          security_events           |
+------------------------------------+          +------------------------------------+
| id (PK)                            |          | id (PK)                            |
| name, target_brand                 |          | event_type (INDEX)                 |
| common_sender_domain               |          | title, description                 |
| common_subject_pattern             |          | severity (INDEX)                   |
| severity, confidence_score         |          | target_item, scan_id               |
| email_count                        |          | created_at (TIMESTAMP)             |
| first_observed, last_observed      |          +------------------------------------+
+-----------------+------------------+
                  |
                  v
+------------------------------------+          +------------------------------------+
|          campaign_emails           |          |            user_actions            |
+------------------------------------+          +------------------------------------+
| id (PK)                            |          | id (PK)                            |
| campaign_id (FK)                   |          | scan_id (FK)                       |
| scan_id (FK)                       |          | account_email, gmail_message_id    |
+------------------------------------+          | action_type ("keep"|"quarantine"|  |
                                                |              "trash"|"report")     |
                                                | action_timestamp, status, notes    |
                                                +------------------------------------+
```

---

## 2. Table Specifications

### 2.1 `scans`
Stores top-level metadata for URL and Email scans.
- `id` (INTEGER, PK): Unique scan identifier.
- `scan_type` (VARCHAR(50)): `url` or `email`.
- `submitted_item` (TEXT): Normalized URL or Email Subject line.
- `risk_score` (INTEGER): Weighted score from 0 to 100.
- `classification` (VARCHAR(50)): `safe`, `suspicious`, `high`, `critical`.
- `created_at` (DATETIME): UTC timestamp of the evaluation.
- `analysis_json` (TEXT): Full structured JSON evaluation result.
- `gmail_message_id` (VARCHAR(100), INDEX): Gmail Message ID if ingested from monitored mailbox.
- `account_email` (VARCHAR(255), INDEX): Monitored account address.

### 2.2 `connected_accounts`
Stores authorized Gmail mailboxes. Secret tokens are encrypted with Fernet AES before storage.
- `encrypted_access_token` (TEXT): AES encrypted OAuth access token.
- `encrypted_refresh_token` (TEXT): AES encrypted OAuth refresh token.
- `last_history_id` (VARCHAR(100)): State cursor for Gmail History API synchronization.
- `watch_expiry` (DATETIME): Expiration of active Pub/Sub watch.

### 2.3 `attachments`
Stores safe static metadata of email attachments. Never executes binaries.
- `sha256_hash` (VARCHAR(64), INDEX): SHA-256 fingerprint for campaign correlation.
- `is_dangerous` (BOOLEAN): Flagged if double extension or executable signature detected.
- `threat_reasons` (TEXT): JSON array of specific threat flags.

### 2.4 `security_events` (Personal Threat Timeline)
Maintains an immutable audit log of incoming detections and user decisions (`keep`, `quarantine`, `trash`, `report`).

