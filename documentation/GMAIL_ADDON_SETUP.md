# PhishGuard Gmail add-on

The Gmail Workspace add-on shows PhishGuard's risk verdict, score, and top indicators in Gmail's contextual side panel on web and mobile. The existing Chrome extension remains available for an inline desktop banner.

## Important Gmail behavior

Gmail does not let add-ons force themselves open as a popup. To see the card, open PhishGuard from Gmail's add-ons panel while viewing a message. On desktop, keep the panel open while moving between messages; Gmail reruns the contextual trigger. On mobile, open the installed PhishGuard add-on from the current message. Gmail's interface placement can vary by device.

## 1. Deploy the backend over HTTPS

Apps Script runs on Google's servers, so it cannot call `localhost`, `127.0.0.1`, or a private development machine. Deploy the FastAPI backend at a publicly reachable HTTPS URL first.

Generate a random add-on API key locally:

```powershell
py -c "import secrets; print(secrets.token_urlsafe(48))"
```

Set that same value as `GMAIL_ADDON_API_KEY` in `backend/.env`, then restart FastAPI. Keep the key private and do not commit or share it. The add-on endpoint returns an error until a key of at least 32 characters is configured.

## 2. Create the Apps Script project

1. Visit [script.google.com](https://script.google.com/) and create a standalone project named **PhishGuard Gmail Protection**.
2. In **Project Settings**, enable **Show `appsscript.json` manifest file in editor**.
3. Replace the generated `Code.gs` with [`gmail-addon/Code.gs`](../gmail-addon/Code.gs).
4. Replace the project manifest with [`gmail-addon/appsscript.json`](../gmail-addon/appsscript.json).
5. In **Project Settings → Script Properties**, add:
   - `PHISHGUARD_BACKEND_URL`: the public HTTPS backend origin, for example `https://phishguard.example.com` (no `/api` suffix).
   - `PHISHGUARD_API_KEY`: the same random key configured as `GMAIL_ADDON_API_KEY` in the backend.

The manifest uses a public Gmail icon as a placeholder. Before wider distribution, change `addOns.common.logoUrl` to a publicly hosted PhishGuard icon.

## 3. Test-install in Gmail

1. In Apps Script, choose **Deploy → Test deployments** and select the add-on test deployment.
2. Install the test add-on and authorize the requested Gmail current-message and external-request scopes.
3. If the OAuth consent screen is in **Testing** mode, add your account under the Google Cloud project's **Test users**.
4. Open Gmail on desktop or mobile, open a message, then open **PhishGuard Gmail Protection** from the add-ons panel.
5. The card should show the verdict, risk score, and up to five detection indicators.

If you edit the Apps Script code, save it and update/reload the test deployment before testing again. For a published deployment, set the manifest's top-level `urlFetchWhitelist` to the exact HTTPS prefix of your backend, and complete any Google OAuth/Marketplace verification required for the Gmail scopes.

## Data flow and limits

The add-on reads the message currently open in Gmail and sends its sender, subject, plain-text body (up to 10,000 characters), and reply-to value to the configured backend over HTTPS. The backend caches the analysis by Gmail message ID; it does not store the full raw body in the scan result. Anyone with access to the Apps Script project can view its Script Properties, so restrict project editors and rotate the API key if exposed.

The current-message scope is narrower than full mailbox access. This feature analyzes messages when the add-on is opened for them; it does not auto-open a popup or scan all incoming mail in the background. Automatic scan-on-arrival requires separate Gmail Pub/Sub infrastructure and a public webhook.

Official references:

- [Extend Gmail message UI](https://developers.google.com/workspace/add-ons/gmail/extending-message-ui)
- [Gmail add-on event objects](https://developers.google.com/workspace/add-ons/concepts/event-objects#gmail-event-object)
- [Google Workspace add-on scopes](https://developers.google.com/workspace/add-ons/concepts/workspace-scopes)
