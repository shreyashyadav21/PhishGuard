// PhishGuard Gmail Content Script (Manifest V3)
console.log("[PhishGuard] Gmail Security Content Script loaded.");

const BANNER_ID = "phishguard-banner-injected";
const INBOX_MONITOR_ID = "phishguard-inbox-monitor";
const MAX_EMAIL_BODY_LENGTH = 10000;
let scanTimer = null;
let activeScanKey = null;
let inboxTimer = null;
let lastVerdictRefresh = 0;
let lastSyncRequest = 0;
let inboxVerdicts = {};

function getBannerTheme(score, status) {
  if (status === "insufficient_evidence") {
    return { cssClass: "phishguard-banner-muted", label: "NOT ENOUGH EMAIL CONTENT", icon: "ℹ️" };
  }
  if (score >= 70) {
    return { cssClass: "phishguard-banner-red", label: "CRITICAL PHISHING RISK", icon: "🚨" };
  }
  if (score >= 40) {
    return { cssClass: "phishguard-banner-orange", label: "HIGH THREAT SUSPICION", icon: "⚠️" };
  }
  if (score >= 20) {
    return { cssClass: "phishguard-banner-yellow", label: "SUSPICIOUS INDICATORS", icon: "🔍" };
  }
  return { cssClass: "phishguard-banner-green", label: "NO HIGH-RISK SIGNALS FOUND", icon: "🛡️" };
}

function addTextElement(parent, tagName, className, text) {
  const element = document.createElement(tagName);
  element.className = className;
  element.textContent = text;
  parent.appendChild(element);
  return element;
}

function renderBanner(analysis, hasMessageId) {
  document.getElementById(BANNER_ID)?.remove();

  const score = Number.isFinite(Number(analysis.risk_score))
    ? Math.max(0, Math.min(100, Number(analysis.risk_score)))
    : null;
  const theme = getBannerTheme(score ?? 0, analysis.analysis_status);
  const banner = document.createElement("section");
  banner.id = BANNER_ID;
  banner.className = `phishguard-banner-container ${theme.cssClass}`;
  banner.setAttribute("aria-live", "polite");
  banner.setAttribute("role", score >= 40 ? "alert" : "status");

  const header = document.createElement("div");
  header.className = "phishguard-header";
  const brand = document.createElement("div");
  brand.className = "phishguard-logo";
  addTextElement(brand, "span", "", theme.icon);
  addTextElement(brand, "span", "", `PHISHGUARD DEFENSE · ${theme.label}`);
  header.appendChild(brand);
  if (score !== null) {
    addTextElement(header, "span", "phishguard-score-badge", `RISK ${score} / 100`);
  }
  banner.appendChild(header);

  const body = document.createElement("div");
  body.className = "phishguard-body";
  const summary = analysis.classification_label || theme.label;
  addTextElement(body, "p", "phishguard-verdict", summary);

  const indicators = Array.isArray(analysis.indicators) ? analysis.indicators.slice(0, 3) : [];
  if (indicators.length) {
    const list = document.createElement("ul");
    list.className = "phishguard-indicators-list";
    for (const indicator of indicators) {
      const item = document.createElement("li");
      const name = document.createElement("strong");
      name.textContent = `${indicator.name || "Signal"}: `;
      item.append(name, document.createTextNode(indicator.description || ""));
      list.appendChild(item);
    }
    body.appendChild(list);
  } else {
    addTextElement(
      body,
      "p",
      "phishguard-summary",
      analysis.analysis_status === "insufficient_evidence"
        ? "Open the full message and try again. PhishGuard could not assess enough content."
        : "No high-risk signals were detected by this scan. This is not a guarantee that the message is safe."
    );
  }

  addTextElement(
    body,
    "p",
    "phishguard-disclaimer",
    hasMessageId
      ? "Automated heuristic assessment; no scan can guarantee absolute safety."
      : "Gmail message ID unavailable. This result is associated with its thread; no scan can guarantee absolute safety."
  );
  banner.appendChild(body);
  document.body.appendChild(banner);
}

function renderNotice(label, description, className = "phishguard-banner-muted") {
  const existing = document.getElementById(BANNER_ID);
  const noticeKey = `${label}\n${description}`;
  if (existing?.dataset.phishguardNotice === noticeKey) return;
  existing?.remove();
  const banner = document.createElement("section");
  banner.id = BANNER_ID;
  banner.dataset.phishguardNotice = noticeKey;
  banner.className = `phishguard-banner-container ${className}`;
  banner.setAttribute("role", "status");
  banner.setAttribute("aria-live", "polite");
  const header = document.createElement("div");
  header.className = "phishguard-header";
  addTextElement(header, "div", "phishguard-logo", `PHISHGUARD DEFENSE · ${label}`);
  banner.appendChild(header);
  const body = document.createElement("div");
  body.className = "phishguard-body";
  addTextElement(body, "p", "phishguard-summary", description);
  banner.appendChild(body);
  document.body.appendChild(banner);
}

function getVisibleMessageContainer() {
  const visible = (element) => {
    const rect = element.getBoundingClientRect();
    return rect.width > 0 && rect.height > 0;
  };
  const bodies = Array.from(document.querySelectorAll(".a3s, .ii.gt, [data-legacy-message-id]"))
    .filter((element) => visible(element) && element.innerText?.trim());
  const messageBody = bodies.pop();
  if (!messageBody) return null;
  return messageBody.closest(".adn.ads, .gs, [data-legacy-message-id], [data-message-id]")
    || messageBody;
}

function getGmailMessageId(container) {
  for (let element = container; element && element !== document.body; element = element.parentElement) {
    const id = element.getAttribute("data-legacy-message-id") || element.getAttribute("data-message-id");
    if (id) return id;
  }
  const nestedMessage = container.querySelector("[data-legacy-message-id], [data-message-id]");
  return nestedMessage?.getAttribute("data-legacy-message-id")
    || nestedMessage?.getAttribute("data-message-id")
    || null;
}

function getThreadIdFromUrl(value) {
  try {
    const hash = new URL(value, window.location.href).hash.replace(/^#/, "");
    const segments = hash.split("/").filter(Boolean);
    const supportedRoutes = ["inbox", "all", "sent", "drafts", "starred", "important", "spam", "trash", "label"];
    if (segments.length < 2 || !supportedRoutes.includes(segments[0])) return null;
    return decodeURIComponent(segments[segments.length - 1]);
  } catch {
    return null;
  }
}

function getGmailThreadId(element) {
  for (let current = element; current && current !== document.body; current = current.parentElement) {
    const id = current.getAttribute("data-legacy-thread-id")
      || current.getAttribute("data-thread-id");
    if (id) return id;
  }
  const row = element.closest("tr.zA");
  if (row) {
    const nestedThread = row.querySelector("[data-legacy-thread-id], [data-thread-id]");
    const nestedId = nestedThread?.getAttribute("data-legacy-thread-id")
      || nestedThread?.getAttribute("data-thread-id");
    if (nestedId) return nestedId;
    for (const link of row.querySelectorAll("a[href]")) {
      const linkedId = getThreadIdFromUrl(link.getAttribute("href"));
      if (linkedId) return linkedId;
    }
  }
  return getThreadIdFromUrl(window.location.href);
}

function getAccountEmail() {
  const accountButton = document.querySelector('[aria-label^="Google Account:"]');
  const label = accountButton?.getAttribute("aria-label") || "";
  return label.match(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/i)?.[0] || null;
}

function getOpenedEmail(container) {
  const messageBody = container.querySelector(".a3s, .ii.gt") || container;
  const subject = container.querySelector("h2.hP")?.innerText
    || document.querySelector("h2.hP")?.innerText
    || "Email Message";
  const senderElement = container.querySelector(".gD, span[email]")
    || document.querySelector(".gD, span[email]");
  const sender = senderElement?.getAttribute("email") || senderElement?.innerText || "";
  const visibleBody = messageBody.innerText || "";
  const links = Array.from(messageBody.querySelectorAll("a[href]"))
    .map((link) => link.href)
    .filter((href) => href.startsWith("http://") || href.startsWith("https://"));
  const body = `${visibleBody}\n${links.map((url) => `Link: ${url}`).join("\n")}`
    .slice(0, MAX_EMAIL_BODY_LENGTH);
  const messageId = getGmailMessageId(container);
  const threadId = getGmailThreadId(container);

  return {
    messageId: messageId || threadId,
    hasMessageId: Boolean(messageId),
    threadId,
    accountEmail: getAccountEmail(),
    sender,
    subject: subject.trim(),
    body
  };
}

function renderInboxMonitor(lastSync) {
  let monitor = document.getElementById(INBOX_MONITOR_ID);
  if (!monitor) {
    monitor = document.createElement("div");
    monitor.id = INBOX_MONITOR_ID;
    monitor.className = "phishguard-inbox-monitor";
    monitor.setAttribute("role", "status");
    monitor.setAttribute("aria-live", "polite");
    document.body.appendChild(monitor);
  }

  if (lastSync?.status === "error") {
    monitor.textContent = `PhishGuard Inbox scan unavailable: ${lastSync.error || "Check the backend."}`;
    monitor.classList.add("phishguard-inbox-monitor-error");
    return;
  }

  monitor.classList.remove("phishguard-inbox-monitor-error");
  if (!lastSync || lastSync.status === "not_connected") {
    monitor.textContent = "PhishGuard is ready. Connect Gmail to start Inbox checks.";
    return;
  }

  const accounts = Array.isArray(lastSync.accounts) ? lastSync.accounts : [];
  const checked = accounts.reduce((count, account) => count + (Number(account.messages_checked) || 0), 0);
  const pending = accounts.some((account) => account.more_pages);
  monitor.textContent = `PhishGuard Inbox monitor · ${checked} messages checked${pending ? " · more queued" : ""}`;
}

function getInboxBadgeTheme(verdict) {
  const score = Number(verdict?.risk_score);
  if (!Number.isFinite(score)) {
    return { className: "phishguard-inbox-unscanned", label: "NOT SCANNED" };
  }
  if (score >= 70) return { className: "phishguard-inbox-critical", label: "CRITICAL RISK" };
  if (score >= 40) return { className: "phishguard-inbox-high", label: "HIGH RISK" };
  if (score >= 20) return { className: "phishguard-inbox-suspicious", label: "SUSPICIOUS" };
  return { className: "phishguard-inbox-low", label: "LOW RISK" };
}

function renderInboxBadges() {
  const accountEmail = getAccountEmail();
  const matchingAccountVerdicts = accountEmail
    ? Object.entries(inboxVerdicts).find(([email]) => email.toLowerCase() === accountEmail.toLowerCase())?.[1]
    : null;
  const accountVerdicts = (accountEmail && inboxVerdicts[accountEmail])
    || matchingAccountVerdicts
    || (Object.keys(inboxVerdicts).length === 1 ? Object.values(inboxVerdicts)[0] : null)
    || {};

  const rows = new Set(document.querySelectorAll("tr.zA"));
  for (const node of document.querySelectorAll("[data-legacy-thread-id], [data-thread-id]")) {
    const row = node.closest("tr");
    if (row) rows.add(row);
  }

  for (const row of rows) {
    const threadId = getGmailThreadId(row);
    if (!threadId) continue;

    const verdict = accountVerdicts[threadId];
    let badge = row.querySelector(".phishguard-inbox-verdict");
    if (!badge) {
      badge = document.createElement("span");
      badge.className = "phishguard-inbox-verdict";
      const subject = row.querySelector(".y6 span") || row.querySelector(".bog");
      if (subject) subject.appendChild(badge);
      else {
        const subjectCell = row.querySelector("td.xY, td.yX");
        if (subjectCell) subjectCell.appendChild(badge);
      }
    }

    const theme = getInboxBadgeTheme(verdict);
    const className = `phishguard-inbox-verdict ${theme.className}`;
    const label = verdict && Number.isFinite(Number(verdict.risk_score))
      ? `${theme.label} · ${verdict.risk_score}/100`
      : theme.label;
    const title = verdict
      ? `PhishGuard estimate: ${verdict.risk_score}/100. Automated checks cannot guarantee safety.`
      : "This message has not been scanned yet. Inbox scanning requires a connected Gmail account and running backend.";
    if (badge.className !== className) badge.className = className;
    if (badge.textContent !== label) badge.textContent = label;
    if (badge.title !== title) badge.title = title;
  }
}

async function refreshInboxVerdicts(force = false) {
  const now = Date.now();
  if (!force && now - lastVerdictRefresh < 15000) {
    renderInboxBadges();
    return;
  }
  lastVerdictRefresh = now;
  try {
    const result = await sendRuntimeMessage({ type: "GET_GMAIL_VERDICTS" });
    inboxVerdicts = result.verdicts || {};
    renderInboxMonitor(result.last_sync);
    renderInboxBadges();
  } catch (error) {
    console.warn("[PhishGuard] Could not load cached Inbox verdicts:", error.message);
  }
}

function scheduleInboxRefresh() {
  clearTimeout(inboxTimer);
  inboxTimer = setTimeout(async () => {
    await refreshInboxVerdicts();
    if (!document.querySelector("tr.zA")) return;
    const now = Date.now();
    const accountEmail = getAccountEmail();
    if (accountEmail && now - lastSyncRequest > 60000) {
      lastSyncRequest = now;
      try {
        await sendRuntimeMessage({
          type: "SYNC_GMAIL_NOW",
          payload: { accountEmail }
        });
        await refreshInboxVerdicts(true);
      } catch (error) {
        console.warn("[PhishGuard] Background Inbox scan unavailable:", error.message);
      }
    }
  }, 800);
}

function sendRuntimeMessage(message) {
  return new Promise((resolve, reject) => {
    chrome.runtime.sendMessage(message, (response) => {
      if (chrome.runtime.lastError) {
        reject(new Error(chrome.runtime.lastError.message));
      } else if (!response?.success) {
        reject(new Error(response?.error || "The PhishGuard backend could not analyze this message."));
      } else {
        resolve(response.data);
      }
    });
  });
}

function getEmailScanKey(email) {
  return [email.threadId || window.location.hash, email.messageId, email.sender, email.subject, email.body].join("|");
}

function isCurrentScan(scanKey) {
  if (activeScanKey !== scanKey || !getThreadIdFromUrl(window.location.href)) return false;
  const container = getVisibleMessageContainer();
  return Boolean(container && getEmailScanKey(getOpenedEmail(container)) === scanKey);
}

async function analyzeMessage(email, scanKey) {
  renderNotice("ANALYZING MESSAGE", "Checking sender, message content, and visible links…");
  try {
    const analysis = await sendRuntimeMessage({
      type: "ANALYZE_GMAIL_MESSAGE",
      payload: email
    });
    if (!isCurrentScan(scanKey)) return;
    renderBanner(analysis, email.hasMessageId);
  } catch (error) {
    if (!isCurrentScan(scanKey)) return;
    renderNotice(
      "SCAN UNAVAILABLE",
      `${error.message} Keep treating unexpected links and requests with caution.`
    );
  }
}

function inspectOpenedEmail() {
  const threadId = getThreadIdFromUrl(window.location.href);
  if (!threadId) {
    activeScanKey = null;
    document.getElementById(BANNER_ID)?.remove();
    return;
  }

  const container = getVisibleMessageContainer();
  if (!container) {
    activeScanKey = null;
    renderNotice(
      "MESSAGE NOT SCANNED",
      "PhishGuard cannot read this open message yet. Refresh Gmail and open it again."
    );
    return;
  }

  const email = getOpenedEmail(container);
  if (!email.body.trim()) {
    activeScanKey = null;
    renderNotice("MESSAGE NOT SCANNED", "No readable message body was found. Expand the message and try again.");
    return;
  }
  if (!email.messageId) {
    activeScanKey = null;
    renderNotice("MESSAGE NOT SCANNED", "Gmail did not expose a message or thread ID, so this message could not be matched to a scan.");
    return;
  }
  const key = getEmailScanKey(email);
  if (key === activeScanKey) return;

  activeScanKey = key;
  analyzeMessage(email, key);
}

const observer = new MutationObserver(() => {
  clearTimeout(scanTimer);
  scanTimer = setTimeout(inspectOpenedEmail, 250);
  scheduleInboxRefresh();
});

chrome.storage.onChanged.addListener((changes, areaName) => {
  if (areaName !== "local") return;
  if (changes.gmailInboxVerdicts) {
    inboxVerdicts = changes.gmailInboxVerdicts.newValue || {};
    renderInboxBadges();
  }
  if (changes.lastInboxSync) renderInboxMonitor(changes.lastInboxSync.newValue);
});

observer.observe(document.body, {
  childList: true,
  subtree: true
});

window.addEventListener("hashchange", () => {
  activeScanKey = null;
  inspectOpenedEmail();
  scheduleInboxRefresh();
});

inspectOpenedEmail();
scheduleInboxRefresh();
