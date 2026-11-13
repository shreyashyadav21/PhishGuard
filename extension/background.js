const BACKEND_URL = "http://127.0.0.1:8000/api";
const VERDICTS_KEY = "gmailInboxVerdicts";
const CURSOR_PREFIX = "gmailInboxCursor_";
const SYNC_ALARM = "gmail-inbox-sync";
const PAGE_SIZE = 50;
const PAGES_PER_RUN = 2;
const MAX_CACHED_THREADS = 20000;

let syncPromise = null;

function requestBackend(path, options = {}) {
  return fetch(`${BACKEND_URL}${path}`, {
    ...options,
    headers: {
      "Content-Type": "application/json",
      ...(options.headers || {})
    }
  }).then(async (response) => {
    const data = await response.json();
    if (!response.ok) {
      throw new Error(data.detail || `Backend request failed (${response.status}).`);
    }
    return data;
  });
}

function isRealAccount(account) {
  const email = String(account.email || "").toLowerCase();
  return Boolean(account.is_active
    && email
    && email !== "analyst.demo@phishguard-soc.org"
    && !email.endsWith("@example.com"));
}

async function saveVerdicts(accountEmail, verdicts) {
  if (!accountEmail || !Array.isArray(verdicts) || !verdicts.length) return;

  const stored = await chrome.storage.local.get(VERDICTS_KEY);
  const allAccounts = stored[VERDICTS_KEY] || {};
  const accountVerdicts = allAccounts[accountEmail] || {};

  for (const verdict of verdicts) {
    if (!verdict.thread_id) continue;
    const previous = accountVerdicts[verdict.thread_id];
    const next = {
      thread_id: verdict.thread_id,
      risk_score: verdict.risk_score,
      classification: verdict.classification,
      classification_label: verdict.classification_label,
      indicator_count: verdict.indicator_count || 0,
      scan_id: verdict.scan_id,
      scanned_at: verdict.scanned_at || new Date().toISOString()
    };
    if (previous && Number(previous.risk_score) > Number(next.risk_score)) {
      next.risk_score = previous.risk_score;
      next.classification = previous.classification;
      next.classification_label = previous.classification_label;
      next.indicator_count = previous.indicator_count;
      next.scan_id = previous.scan_id;
    }
    accountVerdicts[verdict.thread_id] = next;
  }

  const retained = Object.entries(accountVerdicts)
    .sort((left, right) => String(right[1].scanned_at).localeCompare(String(left[1].scanned_at)))
    .slice(0, MAX_CACHED_THREADS);
  allAccounts[accountEmail] = Object.fromEntries(retained);
  await chrome.storage.local.set({ [VERDICTS_KEY]: allAccounts });
}

async function syncAccount(account) {
  const cursorKey = `${CURSOR_PREFIX}${account.id}`;
  const stored = await chrome.storage.local.get(cursorKey);
  let pageToken = stored[cursorKey] || null;
  let cursorReset = false;
  let messagesChecked = 0;
  let newScans = 0;
  let failedMessages = 0;
  let morePages = false;

  for (let pageIndex = 0; pageIndex < PAGES_PER_RUN; pageIndex += 1) {
    const query = new URLSearchParams({ max_results: String(PAGE_SIZE) });
    if (pageToken) query.set("page_token", pageToken);

    let result;
    try {
      result = await requestBackend(`/gmail/sync/${account.id}?${query.toString()}`, {
        method: "POST"
      });
    } catch (error) {
      if (pageToken && !cursorReset) {
        await chrome.storage.local.remove(cursorKey);
        pageToken = null;
        cursorReset = true;
        pageIndex -= 1;
        continue;
      }
      throw error;
    }

    const verdicts = Array.isArray(result.verdicts) ? result.verdicts : [];
    await saveVerdicts(account.email, verdicts);
    messagesChecked += Number(result.page_count) || 0;
    newScans += Number(result.processed_new_messages) || 0;
    failedMessages += Array.isArray(result.failed_messages) ? result.failed_messages.length : 0;
    pageToken = result.next_page_token || null;
    morePages = Boolean(pageToken);

    if (pageToken) {
      await chrome.storage.local.set({ [cursorKey]: pageToken });
    } else {
      await chrome.storage.local.remove(cursorKey);
      break;
    }
  }

  return {
    account_email: account.email,
    messages_checked: messagesChecked,
    new_scans: newScans,
    failed_messages: failedMessages,
    more_pages: morePages
  };
}

function syncConnectedAccounts(accountEmail) {
  if (syncPromise) return syncPromise;

  const task = (async () => {
    const accounts = await requestBackend("/gmail/accounts");
    const requestedEmail = String(accountEmail || "").toLowerCase();
    const targets = accounts.filter((account) => (
      isRealAccount(account)
      && (!requestedEmail || account.email.toLowerCase() === requestedEmail)
    ));
    const results = [];

    for (const account of targets) {
      results.push(await syncAccount(account));
    }

    const summary = {
      status: results.length ? "completed" : "not_connected",
      checked_at: new Date().toISOString(),
      accounts: results
    };
    await chrome.storage.local.set({ lastInboxSync: summary });
    return summary;
  })();

  syncPromise = task.finally(() => {
    syncPromise = null;
  });
  return syncPromise;
}

async function runScheduledSync(accountEmail) {
  try {
    await syncConnectedAccounts(accountEmail);
  } catch (error) {
    await chrome.storage.local.set({
      lastInboxSync: {
        status: "error",
        checked_at: new Date().toISOString(),
        error: error.message
      }
    });
    console.error("[PhishGuard] Inbox sync failed:", error);
  }
}

chrome.runtime.onInstalled.addListener(() => {
  chrome.alarms.create(SYNC_ALARM, { delayInMinutes: 1, periodInMinutes: 1 });
  void runScheduledSync();
});

chrome.runtime.onStartup.addListener(() => {
  chrome.alarms.create(SYNC_ALARM, { delayInMinutes: 1, periodInMinutes: 1 });
  void runScheduledSync();
});

chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === SYNC_ALARM) void runScheduledSync();
});

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  if (message.type === "ANALYZE_GMAIL_MESSAGE") {
    requestBackend("/gmail/extension/scan", {
      method: "POST",
      body: JSON.stringify({
        gmail_message_id: message.payload.messageId,
        gmail_thread_id: message.payload.threadId || null,
        account_email: message.payload.accountEmail || null,
        sender: message.payload.sender,
        subject: message.payload.subject,
        body: message.payload.body
      })
    }).then(async (result) => {
      if (message.payload.accountEmail && result.thread_id) {
        await saveVerdicts(message.payload.accountEmail, [{
          ...result,
          scanned_at: new Date().toISOString()
        }]);
      }
      sendResponse({ success: true, data: result });
    }).catch((error) => {
      sendResponse({ success: false, error: error.message });
    });
    return true;
  }

  if (message.type === "GET_GMAIL_VERDICTS") {
    chrome.storage.local.get([VERDICTS_KEY, "lastInboxSync"]).then((stored) => {
      sendResponse({
        success: true,
        data: {
          verdicts: stored[VERDICTS_KEY] || {},
          last_sync: stored.lastInboxSync || null
        }
      });
    }).catch((error) => {
      sendResponse({ success: false, error: error.message });
    });
    return true;
  }

  if (message.type === "SYNC_GMAIL_NOW") {
    runScheduledSync(message.payload?.accountEmail).then(() => {
      chrome.storage.local.get("lastInboxSync").then((stored) => {
        const summary = stored.lastInboxSync;
        sendResponse({
          success: summary?.status !== "error",
          data: summary,
          error: summary?.error
        });
      });
    }).catch((error) => {
      sendResponse({ success: false, error: error.message });
    });
    return true;
  }

  return false;
});
