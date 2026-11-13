const PHISHGUARD_ADDON_API_PATH = "/api/gmail/addon/scan";
const MAX_MESSAGE_BODY_LENGTH = 10000;

function onGmailMessageOpen(e) {
  const gmailEvent = e && e.gmail;
  if (!gmailEvent || !gmailEvent.messageId || !gmailEvent.accessToken) {
    return [buildNoticeCard_(
      "Message unavailable",
      "Open a Gmail message and start PhishGuard again to scan it."
    )];
  }

  try {
    GmailApp.setCurrentMessageAccessToken(gmailEvent.accessToken);
    const message = GmailApp.getMessageById(gmailEvent.messageId);
    const result = scanMessage_(message, gmailEvent.messageId);
    return [buildVerdictCard_(result)];
  } catch (error) {
    console.error("PhishGuard Gmail scan failed: " + error.message);
    return [buildNoticeCard_(
      "Scan unavailable",
      error.message || "PhishGuard could not analyze this message."
    )];
  }
}

function buildHomepageCard() {
  return CardService.newCardBuilder()
    .setHeader(CardService.newCardHeader()
      .setTitle("PhishGuard")
      .setSubtitle("Open a message to check its phishing risk."))
    .addSection(CardService.newCardSection()
      .addWidget(CardService.newTextParagraph()
        .setText("Keep this panel open while reviewing messages. PhishGuard will refresh the verdict as you switch messages.")))
    .build();
}

function scanMessage_(message, messageId) {
  const properties = PropertiesService.getScriptProperties();
  const backendUrl = (properties.getProperty("PHISHGUARD_BACKEND_URL") || "").trim();
  const apiKey = (properties.getProperty("PHISHGUARD_API_KEY") || "").trim();

  if (!backendUrl || !apiKey) {
    throw new Error("Configure PHISHGUARD_BACKEND_URL and PHISHGUARD_API_KEY in this Apps Script project's Script Properties.");
  }
  if (!/^https:\/\/[^/?#]+(?:\/[^?#]*)?$/i.test(backendUrl) || /localhost|127\.0\.0\.1/i.test(backendUrl)) {
    throw new Error("PHISHGUARD_BACKEND_URL must be a publicly reachable HTTPS backend URL. Google cannot reach localhost.");
  }
  if (apiKey.length < 32) {
    throw new Error("PHISHGUARD_API_KEY must contain at least 32 characters.");
  }

  const payload = {
    gmail_message_id: messageId,
    sender: message.getFrom() || "",
    subject: message.getSubject() || "",
    body: (message.getPlainBody() || "").slice(0, MAX_MESSAGE_BODY_LENGTH),
    reply_to: message.getReplyTo() || ""
  };
  const response = UrlFetchApp.fetch(
    backendUrl.replace(/\/+$/, "") + PHISHGUARD_ADDON_API_PATH,
    {
      method: "post",
      contentType: "application/json",
      headers: { Authorization: "Bearer " + apiKey },
      payload: JSON.stringify(payload),
      muteHttpExceptions: true
    }
  );
  const status = response.getResponseCode();
  if (status < 200 || status >= 300) {
    const responseBody = response.getContentText();
    let detail = "The PhishGuard backend could not analyze this message.";
    try {
      detail = JSON.parse(responseBody).detail || detail;
    } catch (error) {
      console.error("PhishGuard backend returned a non-JSON error.");
    }
    throw new Error(detail);
  }
  return JSON.parse(response.getContentText());
}

function buildVerdictCard_(result) {
  const riskScore = Number(result.risk_score);
  const scoreText = Number.isFinite(riskScore)
    ? Math.max(0, Math.min(100, riskScore)) + " / 100"
    : "Unavailable";
  const verdict = result.classification_label || "Assessment complete";
  const section = CardService.newCardSection()
    .addWidget(CardService.newDecoratedText()
      .setTopLabel("Verdict")
      .setText(verdict))
    .addWidget(CardService.newDecoratedText()
      .setTopLabel("Phishing risk score")
      .setText(scoreText));

  const indicators = Array.isArray(result.indicators) ? result.indicators.slice(0, 5) : [];
  const links = Array.isArray(result.extracted_urls) ? result.extracted_urls : [];
  if (indicators.length) {
    section.addWidget(CardService.newTextParagraph().setText("<b>Why it was flagged</b>"));
    indicators.forEach((indicator) => {
      section.addWidget(CardService.newDecoratedText()
        .setTopLabel(indicator.name || "Risk signal")
        .setText(indicator.description || "A suspicious signal was detected."));
    });
  } else {
    section.addWidget(CardService.newTextParagraph()
      .setText("No high-risk signals were detected by this scan. This does not guarantee that the message is safe."));
  }

  if (links.length) {
    const highestLinkRisk = Math.max(...links.map((link) => Number(link.risk_score) || 0));
    section.addWidget(CardService.newDecoratedText()
      .setTopLabel("Links analyzed")
      .setText(links.length + " link(s); highest link score " + highestLinkRisk + " / 100"));
  }

  const recommendations = Array.isArray(result.recommendations)
    ? result.recommendations.slice(0, 3)
    : [];
  if (recommendations.length) {
    section.addWidget(CardService.newTextParagraph().setText("<b>Recommended next steps</b>"));
    recommendations.forEach((recommendation) => {
      section.addWidget(CardService.newTextParagraph().setText(recommendation));
    });
  }

  section.addWidget(CardService.newTextParagraph()
    .setText("PhishGuard uses automated heuristics. Verify unexpected requests independently and avoid opening suspicious links."));

  return CardService.newCardBuilder()
    .setHeader(CardService.newCardHeader()
      .setTitle("PhishGuard")
      .setSubtitle("Gmail message analysis"))
    .addSection(section)
    .build();
}

function buildNoticeCard_(title, message) {
  return CardService.newCardBuilder()
    .setHeader(CardService.newCardHeader()
      .setTitle("PhishGuard")
      .setSubtitle(title))
    .addSection(CardService.newCardSection()
      .addWidget(CardService.newTextParagraph().setText(message)))
    .build();
}
