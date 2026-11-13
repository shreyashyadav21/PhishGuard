# Brave and Chrome Extension Installation & Verification

PhishGuard's Manifest V3 extension checks the message you open and scans the connected Gmail account's Inbox in the background. Inbox results are cached by Gmail account and thread, then shown beside each Gmail row as **Low risk**, **Suspicious**, **High risk**, **Critical risk**, or **Not scanned**. A low-risk result is not a guarantee that a message is safe.

## Requirements and coverage

- Brave or Chrome must be running with the PhishGuard extension enabled.
- The PhishGuard backend must be running at `http://127.0.0.1:8000`.
- A real Gmail account must be connected to PhishGuard with Gmail read access. Google OAuth testing-mode accounts must also be listed as test users.
- **Gmail API must be enabled** in the Google Cloud project that owns the OAuth client.
- The extension reads Gmail Inbox messages through the backend. The backend stores OAuth tokens; the extension does not store Google tokens.
- Only messages in **Inbox** are included. Archived mail, Sent, Spam, and Trash are not scanned by this background feature.
- Inbox scans process up to 100 messages per run and continue through paginated batches. The browser schedules recurring checks approximately once a minute while it is running; it may delay scheduled work.
- The extension sends message content to the configured local PhishGuard backend for analysis. Treat the results as heuristic signals, not proof of safety.

## Load the extension in Brave or Chrome

1. In Brave, open `brave://extensions/`. In Chrome, open `chrome://extensions/`.
2. Enable **Developer mode**.
3. Select **Load unpacked** and choose the `extension` folder:
   `C:\Users\yadav\OneDrive\Desktop\Cyber\extension`
4. Confirm **PhishGuard – AI Phishing Protection for Gmail** is enabled.
5. Start the backend and connect your Gmail account in the PhishGuard dashboard.
6. Reload the extension from the extensions page, then refresh the Gmail tab.

## Verify it

1. Open the PhishGuard toolbar popup and confirm the backend is online.
2. Select **Scan Inbox Now** to start a batch immediately, or leave Chrome running for scheduled batches.
3. In Gmail, Inbox rows receive a per-thread verdict badge as their messages are scanned. **Not scanned** means no result is available yet; it does not mean safe.
4. Open a message to show its fixed on-screen verdict overlay. The extension reuses the saved per-message scan when one is already available.

After changing extension files, reload PhishGuard from the browser's extensions page and refresh Gmail. A connected account and reachable backend are required for background Inbox results; the on-open scan also requires the backend. The extension's Manifest V3 APIs are supported by Brave, so no separate Brave build is needed.
