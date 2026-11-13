# Google Cloud OAuth 2.0 & Gmail Integration Setup Guide

This guide walks you through configuring Google Cloud Platform (GCP) credentials for **PhishGuard** mailbox surveillance and user-controlled email quarantine.

---

## 1. Create a Google Cloud Project

1. Navigate to the [Google Cloud Console](https://console.cloud.google.com/).
2. Click **Select a Project** $\to$ **New Project**.
3. Name your project (e.g. `PhishGuard-SOC`) and click **Create**.

---

## 2. Enable Gmail API

1. In the Google Cloud Console, navigate to **APIs & Services** $\to$ **Library**.
2. Search for `Gmail API`.
3. Select it and click **Enable**.

---

## 3. Configure OAuth Consent Screen

1. Navigate to **APIs & Services** $\to$ **OAuth consent screen**.
2. Select User Type: **External** (or Internal if using Google Workspace organization). Click **Create**.
3. Fill in the App Information:
   - **App name:** `PhishGuard Threat Intelligence`
   - **User support email:** Select your Google account.
   - **Developer contact information:** Your email.
4. Click **Save and Continue**.
5. **Scopes**: Click **Add or Remove Scopes** and add:
   - `.../auth/userinfo.email`
   - `.../auth/userinfo.profile`
   - `https://www.googleapis.com/auth/gmail.readonly`
   - `https://www.googleapis.com/auth/gmail.modify` *(required for Quarantine labeling & Moving to Trash)*
   - `https://www.googleapis.com/auth/gmail.labels` *(required for creating PhishGuard/Quarantine)*
6. Click **Save and Continue**.
7. **Test Users**: While in Testing mode, add your personal Gmail address to the authorized test users list.

---

## 4. Create OAuth 2.0 Credentials

1. Navigate to **APIs & Services** $\to$ **Credentials**.
2. Click **Create Credentials** $\to$ **OAuth client ID**.
3. Application type: Select **Web application**.
4. Name: `PhishGuard Web Client`.
5. **Authorized JavaScript origins**:
   - `http://localhost:5173`
   - `http://127.0.0.1:5173`
   - `http://localhost:8000`
   - `http://127.0.0.1:8000`
6. **Authorized redirect URIs**:
   - `http://127.0.0.1:8000/api/gmail/oauth/callback`
   - `http://localhost:8000/api/gmail/oauth/callback`
   - `http://localhost:5173/gmail-connect`
7. Click **Create**.
8. Copy your **Client ID** and **Client Secret**.

---

## 5. Configure PhishGuard Environment

Create or edit your `.env` file in `Cyber/backend/`:

```bash
# PhishGuard Environment Variables
GOOGLE_CLIENT_ID="YOUR_GOOGLE_CLIENT_ID.apps.googleusercontent.com"
GOOGLE_CLIENT_SECRET="GOCSPX-YOUR_CLIENT_SECRET"
GOOGLE_REDIRECT_URI="http://localhost:5173/gmail-connect"

# Optional Cloud Pub/Sub Topic for Push Notifications
GOOGLE_PUBSUB_TOPIC="projects/YOUR_PROJECT_ID/topics/gmail-notifications"

# Fernet Encryption Key for Access & Refresh Tokens
ENCRYPTION_SECRET="generate-a-random-secure-string-here"
```

Restart the FastAPI backend after updating `.env`.

---

## 6. Testing the Connection in PhishGuard

1. Open `http://localhost:5173/gmail-connect`.
2. Click **Connect Gmail Account** (or click **⚡ Enable Demo Mailbox** for immediate zero-config testing).
3. Choose your Google account on the consent screen.
4. Once granted, PhishGuard stores the encrypted credentials, initiates the mailbox watch, and appears in the **Monitored Mailboxes** list.

---

## 7. Troubleshooting Common Errors

### Error 401: `invalid_client - The OAuth client was not found`
- **Cause**: Google rejects the authorization request because the OAuth Client ID is either missing, contains placeholders, or was not created under an active Google Cloud Project.
- **Resolution**:
  1. Open PhishGuard at `http://localhost:5173/gmail-connect`.
  2. Click **Configure Google Client ID & Secret** in the banner.
  3. Paste your real Web Application Client ID (`...apps.googleusercontent.com`) and Client Secret (`GOCSPX-...`) from Google Cloud Console.
  4. Ensure your **Authorized redirect URIs** in Google Cloud Console includes `http://localhost:5173/gmail-connect` and `http://127.0.0.1:8000/api/gmail/oauth/callback`.
  5. Alternatively, click **⚡ Enable Demo Mailbox** (`analyst.demo@phishguard-soc.org`) to test mailbox surveillance, quarantine, and live threat streams immediately with zero GCP setup.

### Error 403: `access_denied` / App is not verified
- **Cause**: If your OAuth consent screen is in "Testing" mode, only users explicitly added to the "Test users" list in Google Cloud Console can sign in.
- **Resolution**: In Google Cloud Console $\to$ **APIs & Services** $\to$ **OAuth consent screen**, scroll to **Test users** and click **Add Users** to add your Gmail address.

