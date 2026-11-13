const BACKEND_URL = "http://127.0.0.1:8000/api";

document.addEventListener("DOMContentLoaded", () => {
  const backendStatusEl = document.getElementById("backend-status");
  const inboxStatusEl = document.getElementById("inbox-scan-status");
  const scanButton = document.getElementById("btn-scan-inbox");

  function showSyncStatus(summary) {
    if (!summary) {
      inboxStatusEl.textContent = "Connect a Gmail account to start Inbox checks.";
      return;
    }
    if (summary.status === "error") {
      inboxStatusEl.textContent = `Inbox scan unavailable: ${summary.error || "Check the backend."}`;
      return;
    }
    if (summary.status === "not_connected") {
      inboxStatusEl.textContent = "No connected Gmail account. Connect one in the PhishGuard dashboard.";
      return;
    }

    const accounts = summary.accounts || [];
    const checked = accounts.reduce((count, account) => count + (account.messages_checked || 0), 0);
    const pending = accounts.some((account) => account.more_pages);
    const failed = accounts.reduce((count, account) => count + (account.failed_messages || 0), 0);
    const when = summary.checked_at ? new Date(summary.checked_at).toLocaleTimeString() : "recently";
    inboxStatusEl.textContent = `Last check ${when}: ${checked} messages${pending ? " checked; more are queued" : ""}${failed ? `; ${failed} could not be read` : ""}.`;
  }

  function loadSavedStatus() {
    chrome.storage.local.get("lastInboxSync").then((stored) => {
      showSyncStatus(stored.lastInboxSync);
    }).catch((error) => {
      inboxStatusEl.textContent = `Could not read scan status: ${error.message}`;
    });
  }

  Promise.all([
    fetch(`${BACKEND_URL}/health`).then((response) => {
      if (!response.ok) throw new Error("Backend health check failed.");
      return response.json();
    }),
    fetch(`${BACKEND_URL}/gmail/accounts`).then((response) => {
      if (!response.ok) throw new Error("Gmail account check failed.");
      return response.json();
    })
  ]).then(([health, accounts]) => {
    if (health.status === "healthy") {
      backendStatusEl.textContent = "Online (8000)";
      backendStatusEl.style.color = "#00E6A0";
      const hasRealAccount = accounts.some((account) => {
        const email = String(account.email || "").toLowerCase();
        return account.is_active
          && email
          && email !== "analyst.demo@phishguard-soc.org"
          && !email.endsWith("@example.com");
      });
      if (!hasRealAccount) {
        inboxStatusEl.textContent = "Connect a real Gmail account in the PhishGuard dashboard to scan the Inbox.";
      } else {
        loadSavedStatus();
      }
    } else {
      backendStatusEl.textContent = "Degraded";
      backendStatusEl.style.color = "#FFB020";
      inboxStatusEl.textContent = "The backend is responding but not healthy.";
    }
  }).catch(() => {
    backendStatusEl.textContent = "Offline (Start API)";
    backendStatusEl.style.color = "#FF4D67";
    inboxStatusEl.textContent = "Start the PhishGuard backend before scanning.";
  });

  scanButton.addEventListener("click", () => {
    scanButton.disabled = true;
    scanButton.textContent = "Scanning Inbox…";
    chrome.runtime.sendMessage({ type: "SYNC_GMAIL_NOW" }, (response) => {
      scanButton.disabled = false;
      scanButton.textContent = "Scan Inbox Now";
      if (chrome.runtime.lastError) {
        inboxStatusEl.textContent = chrome.runtime.lastError.message;
      } else if (!response?.success) {
        inboxStatusEl.textContent = response?.error || "Inbox scan could not start.";
      } else {
        showSyncStatus(response.data);
      }
    });
  });
});
