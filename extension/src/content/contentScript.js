/**
 * SafeInbox AI webmail email-text and URL threat scanner.
 * 
 * Automatically activates on webmail (Gmail, Outlook, Yahoo) whenever an email is opened:
 * 1. Automatically extracts Sender, Receiver, Subject, Body, and URLs.
 * 2. Injects TWO DISTINCT Security Banners:
 *    - BANNER 1 (Top): URL & Hyperlink Security Scan ONLY.
 *      Audits each hyperlink, displays risk score, evidence, and Safe / Threat feedback buttons.
 *      Contains ZERO email text, NO body, NO sender, NO receiver, NO subject.
 *    - BANNER 2 (Bottom): Email Content Security Scan (Text Only).
 *      Audits sender authenticity, recipient routing, subject, and clean body text with browser heuristics.
 *      Contains ZERO URLs, NO hyperlinks, NO clickable external links.
 */

// Pre-compiled module-level constants (avoids recompiling on every call)
const _RE_WEBMAIL = /mail\.google\.com|outlook\.live\.com|outlook\.office\.com|mail\.yahoo\.com/;

// In-memory URL scan cache (session-scoped, avoids scanning same URL twice)
const _urlScanCache = new Map();

// =============================================================================
// Message listeners for the Side Panel and background service worker.
// =============================================================================
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === "highlight_threat_links") {
    highlightSuspiciousLinks(request.threatUrls || []);
    sendResponse({ status: "ok" });
    return true;
  }
});

// =============================================================================
// Automatic Webmail Email Detection & In-Page Scanner
// =============================================================================
function isWebmailDomain() {
  return _RE_WEBMAIL.test(window.location.hostname);
}

// =============================================================================
// Webmail URL Click Audit Tracking (Strictly Mail Only)
// =============================================================================
const WEBMAIL_CLICKS_KEY = "webmail_url_clicks";
const MAX_RECORDED_CLICKS = 500;

function defangUrlForLog(url) {
  return String(url || "")
    .replace(/\./g, "[.]")
    .replace(/http:\/\//gi, "hxxp://")
    .replace(/https:\/\//gi, "hxxps://");
}

function recordWebmailUrlClick(entry) {
  if (typeof chrome === "undefined" || !chrome.storage || !chrome.storage.local) {
    return Promise.resolve(false);
  }
  if (!isWebmailDomain()) {
    // Strict webmail boundary: clicks on other websites must NEVER be recorded
    return Promise.resolve(false);
  }
  if (!entry || !entry.url) return Promise.resolve(false);

  const cleanUrl = String(entry.url).trim();
  const clickRecord = {
    id: `click_${Date.now()}_${Math.random().toString(36).slice(2, 7)}`,
    url: cleanUrl,
    defanged: defangUrlForLog(cleanUrl),
    timestamp: Date.now(),
    date_iso: new Date().toISOString(),
    email_subject: String(entry.emailSubject || "").slice(0, 150),
    sender: String(entry.sender || "").slice(0, 150),
    risk_score: typeof entry.riskScore === "number" ? entry.riskScore : 0,
    risk_level: String(entry.riskLevel || "AUDITED"),
    proceeded: entry.proceeded !== false,
    source: String(entry.source || "email_body_link")
  };

  return new Promise((resolve) => {
    try {
      chrome.storage.local.get([WEBMAIL_CLICKS_KEY], (res) => {
        if (chrome.runtime.lastError) {
          console.warn("SafeInbox AI failed to read webmail clicks:", chrome.runtime.lastError);
          resolve(false);
          return;
        }
        const clicks = Array.isArray(res && res[WEBMAIL_CLICKS_KEY]) ? res[WEBMAIL_CLICKS_KEY] : [];
        clicks.push(clickRecord);
        const trimmed = clicks.length > MAX_RECORDED_CLICKS ? clicks.slice(-MAX_RECORDED_CLICKS) : clicks;
        chrome.storage.local.set({ [WEBMAIL_CLICKS_KEY]: trimmed }, () => {
          if (chrome.runtime.lastError) {
            console.warn("SafeInbox AI failed to write webmail click:", chrome.runtime.lastError);
            resolve(false);
          } else {
            resolve(true);
          }
        });
      });
    } catch (err) {
      console.warn("SafeInbox AI recordWebmailUrlClick error:", err);
      resolve(false);
    }
  });
}

function attachSafeLinkClickListener(aEl, urlVerdict, emailData) {
  if (aEl.dataset.safeinboxClickTracked === "true") return;
  aEl.dataset.safeinboxClickTracked = "true";

  aEl.addEventListener("click", () => {
    recordWebmailUrlClick({
      url: aEl.href,
      emailSubject: emailData ? emailData.subject : "",
      sender: emailData ? (emailData.senderName ? `${emailData.senderName} <${emailData.senderEmail}>` : emailData.senderEmail) : "",
      riskScore: (urlVerdict && urlVerdict.risk_score) || 0,
      riskLevel: (urlVerdict && urlVerdict.risk_level) || "SAFE",
      proceeded: true,
      source: "email_body_link"
    });
  });
}

function getEmailScanFingerprint(emailData, emailUrls) {
  return JSON.stringify([
    emailData.senderEmail,
    emailData.receiverEmail,
    emailData.cc,
    emailData.bcc,
    emailData.subject,
    emailData.cleanBodyText,
    emailUrls
  ]);
}

let scanDebounceTimer = null;

function startAutoEmailObserver() {
  if (!isWebmailDomain()) return;

  const observer = new MutationObserver(() => {
    if (scanDebounceTimer) clearTimeout(scanDebounceTimer);
    scanDebounceTimer = setTimeout(detectAndScanOpenEmails, 600);
  });

  observer.observe(document.body, { childList: true, characterData: true, subtree: true });
  // Initial check
  detectAndScanOpenEmails();
}

/**
 * Searches the DOM for active open email containers in Gmail or Outlook.
 * The scan fingerprint prevents duplicate work while allowing a reused reading pane
 * to be reprocessed when the selected email changes.
 */
function detectAndScanOpenEmails() {
  if (window.location.hostname.includes("mail.google.com")) {
    const activeMessage = getActiveGmailMessage();
    if (activeMessage) processSingleEmailContainer(activeMessage, "gmail");
    return;
  }

  // 2. Outlook Web Message Reading Pane
  const outlookPane = document.querySelector(".ReadingPaneContainer, [aria-label='Message body']");
  if (outlookPane) {
    const container = outlookPane.closest(".customScrollBar") || outlookPane.parentElement;
    if (container) {
      processSingleEmailContainer(container, "outlook");
    }
    return;
  }

  // 3. Generic / Standalone fallback message view
  const genericBody = document.querySelector(
    ".a3s.aiL, [data-test-id='message-view'], [data-test-id='message-body'], [data-testid='message-body']"
  );
  if (genericBody) {
    const container = genericBody.parentElement || genericBody;
    processSingleEmailContainer(container, "generic");
  }
}

function getActiveGmailMessage() {
  const expandedMessages = Array.from(document.querySelectorAll(".adn.ads"))
    .filter((message) => message.querySelector(".a3s.aiL"));
  return expandedMessages[expandedMessages.length - 1] ||
    document.querySelector(".a3s.aiL")?.closest(".adn.ads") ||
    null;
}

/**
 * Executes full threat inspection on an open email container:
 * Injects TWO DISTINCT BANNERS:
 *  - Banner 1: URL & Hyperlink Security Scan (URLs only, Safe/Threat feedback)
 *  - Banner 2: Email Content Analysis (Sender, Receiver, Subject, Body text only)
 */
async function processSingleEmailContainer(containerEl, clientType) {
  const emailData = extractStructuredEmailFromElement(containerEl, clientType);
  if (!emailData || (!emailData.bodyText && !emailData.subject)) {
    containerEl.dataset.aegisaiScanned = "empty";
    return;
  }
  const emailUrls = EmailThreatUtils.extractUrlsFromEmail(
    emailData.bodyText,
    emailData.linkElements.map((anchor) => anchor.href)
  );
  const fingerprint = getEmailScanFingerprint(emailData, emailUrls);
  if (containerEl.dataset.aegisaiScanned === "in-progress") {
    if (containerEl.dataset.aegisaiScanFingerprint !== fingerprint) {
      containerEl.dataset.aegisaiPendingRescan = "true";
    }
    return;
  }
  if (containerEl.dataset.aegisaiScanFingerprint === fingerprint &&
      containerEl.dataset.aegisaiScanned === "done") return;
  containerEl.dataset.aegisaiScanned = "in-progress";
  containerEl.dataset.aegisaiScanFingerprint = fingerprint;
  notifySidePanelOfEmail(emailData, emailUrls);

  // Ensure clean wrapper exists at top of email view
  let bannerContainer = containerEl.querySelector(".aegisai-banner-container");
  if (!bannerContainer) {
    bannerContainer = document.createElement("div");
    bannerContainer.className = "aegisai-banner-container";
    insertBannerAtTop(containerEl, bannerContainer);
  }

  // BANNER 1: URL & HYPERLINK SECURITY SCAN (Initial progress state)
  const banner1El = document.createElement("div");
  banner1El.className = "aegisai-auto-banner medium aegisai-url-banner";
  banner1El.innerHTML = `
    <div class="aegisai-banner-main">
      <div class="aegisai-banner-icon">🔗</div>
      <div class="aegisai-banner-info">
        <div class="aegisai-banner-title">
          <span id="aegisBanner1Title">SafeInbox AI — Auditing Hyperlinks &amp; URLs…</span>
          <span class="aegisai-banner-score-pill" id="aegisBanner1Pill">Scanning</span>
        </div>
        <div class="aegisai-banner-summary" id="aegisBanner1Summary">Extracting and auditing destination hyperlinks…</div>
        <div style="margin-top:6px; height:2px; background:rgba(255,255,255,0.08); border-radius:3px; overflow:hidden;">
          <div id="aegisBanner1Bar" style="height:100%;width:0%;background:linear-gradient(90deg,#FFA586,#B51A2B);transition:width 0.4s ease;border-radius:3px;"></div>
        </div>
      </div>
    </div>
  `;

  // BANNER 2: EMAIL CONTENT ANALYSIS (Initial progress state)
  const banner2El = document.createElement("div");
  banner2El.className = "aegisai-auto-banner medium aegisai-content-banner";
  banner2El.innerHTML = `
    <div class="aegisai-banner-main">
      <div class="aegisai-banner-icon">📧</div>
      <div class="aegisai-banner-info">
        <div class="aegisai-banner-title">
          <span>SafeInbox AI — Analyzing Email Content &amp; Sender…</span>
          <span class="aegisai-banner-score-pill">Analyzing</span>
        </div>
        <div class="aegisai-banner-summary">Auditing sender authenticity, recipient routing, and body text…</div>
      </div>
    </div>
  `;

  bannerContainer.innerHTML = "";
  bannerContainer.appendChild(banner1El);
  bannerContainer.appendChild(banner2El);

  // STEP 1: SCAN ALL URLS FOR BANNER 1
  const urlScanMap = new Map();
  const urlElements = emailData.linkElements;
  const urlCandidates = emailUrls;
  const totalUrls = urlCandidates.length;

  const b1Title   = banner1El.querySelector("#aegisBanner1Title");
  const b1Pill    = banner1El.querySelector("#aegisBanner1Pill");
  const b1Summary = banner1El.querySelector("#aegisBanner1Summary");
  const b1Bar     = banner1El.querySelector("#aegisBanner1Bar");

  let urlIndex = 0;
  for (const url of urlCandidates) {
    try {
      if (b1Title)   b1Title.textContent   = `Scanning URL ${urlIndex + 1} of ${totalUrls}…`;
      if (b1Pill)    b1Pill.textContent    = `${urlIndex + 1}/${totalUrls}`;
      if (b1Summary) {
        const defanged = url.replace(/https?:\/\//gi, "hxxps://").replace(/\./g, "[.]");
        b1Summary.textContent = defanged.substring(0, 72) + (url.length > 72 ? "…" : "");
      }
      if (b1Bar) b1Bar.style.width = `${Math.round(((urlIndex + 1) / totalUrls) * 100)}%`;

      const uRes = await scanSingleUrl(url);
      urlScanMap.set(url, uRes);

      // Highlight and track email DOM links
      const isHighThreat = (uRes.risk_score >= 50) || (uRes.evidence && uRes.evidence.length > 0);
      const matchingAnchors = urlElements.filter(a => a.href === url || (a.href && a.href.replace(/\/$/, '') === url.replace(/\/$/, '')));
      matchingAnchors.forEach(aEl => {
        if (isHighThreat) {
          flagSuspiciousLinkElement(aEl, uRes, emailData);
        } else {
          attachSafeLinkClickListener(aEl, uRes, emailData);
        }
      });
    } catch (error) {
      urlScanMap.set(url, {
        target: url,
        risk_score: 0,
        risk_level: "UNKNOWN",
        scanError: error.message || "URL analysis failed.",
        evidence: [{
          severity: "HIGH",
          rule_id: "URL_SCAN_ERROR",
          evidence: `This URL could not be fully analyzed: ${error.message || "unknown error"}`
        }]
      });
    }
    urlIndex++;
  }

  // RENDER PERMANENT BANNER 1 (URLs ONLY)
  renderUrlSecurityBanner(banner1El, urlScanMap, emailData);

  // STEP 2: SCAN EMAIL CONTENT FOR BANNER 2 (TEXT ONLY)
  let emailVerdict = null;
  try {
    emailVerdict = await scanEmailPayload({
      text: emailData.cleanPayloadText,     // URL-free body for analysis
      sender: emailData.senderName ? `${emailData.senderName} <${emailData.senderEmail}>` : emailData.senderEmail,
      receiver: emailData.receiverEmail,
      cc: emailData.cc,
      bcc: emailData.bcc,
      subject: emailData.subject,
      body: emailData.cleanBodyText,
      body_preview: emailData.cleanBodyText.substring(0, 500)
    });
  } catch (err) {
    console.error("SafeInbox AI email text analysis failed:", err);
    emailVerdict = {
      risk_level: "UNKNOWN",
      risk_score: 25,
      summary: "Email text analysis could not be completed.",
      recommended_action: "Treat this message as unverified and independently verify the sender before acting.",
      evidence: [{
        severity: "HIGH",
        rule_id: "EMAIL_TEXT_ANALYSIS_ERROR",
        evidence: `The local email analyzer failed: ${err.message || "unknown error"}`
      }]
    };
  }

  // RENDER PERMANENT BANNER 2 (CONTENT & TEXT ONLY)
  renderContentSecurityBanner(banner2El, emailVerdict, emailData);
  highlightSuspiciousSentences(emailData.bodyEl, emailVerdict.threat_vectors || []);

  containerEl.dataset.aegisaiScanned = "done";
  if (containerEl.dataset.aegisaiPendingRescan === "true") {
    delete containerEl.dataset.aegisaiPendingRescan;
    containerEl.dataset.aegisaiScanFingerprint = "";
    queueMicrotask(() => processSingleEmailContainer(containerEl, clientType));
  }
}

/**
 * Extracts sender, receiver, subject, body, and DOM link elements.
 */
function extractStructuredEmailFromElement(containerEl, clientType) {
  let senderName = "";
  let senderEmail = "";
  let receiverEmail = "";
  let receiverName = "";
  let cc = "";
  let bcc = "";
  let subject = "";
  let bodyEl = null;

  if (clientType === "gmail") {
    const senderEl = containerEl.querySelector(".gD");
    senderEmail = senderEl?.getAttribute("email") || senderEl?.textContent || "";
    senderName = senderEl?.textContent?.replace(/<[^>]+>/, "").trim() || senderEmail;

    const receiverEl = containerEl.querySelector(".g2") || containerEl.querySelector("span[email]");
    receiverEmail = receiverEl?.getAttribute("email") || receiverEl?.textContent || "";
    receiverName = receiverEl?.textContent?.trim() || receiverEmail;

    subject = document.querySelector("h2.hP")?.textContent?.trim() || "";
    bodyEl = containerEl.querySelector(".a3s.aiL") || containerEl;
  } else if (clientType === "outlook") {
    const senderEl = document.querySelector(".PersonaCard-anchor, [data-hovercard-id]");
    senderEmail = senderEl?.textContent?.match(/[\w\.-]+@[\w\.-]+\.\w+/)?.[0] || senderEl?.textContent || "";
    senderName = senderEl?.textContent?.trim() || "";

    const receiverEl = document.querySelector("[aria-label*='To:']");
    receiverEmail = receiverEl?.textContent?.match(/[\w\.-]+@[\w\.-]+\.\w+/)?.[0] || "";
    receiverName = receiverEl?.textContent?.trim() || "";

    subject = document.querySelector("[role='heading'][aria-level='1']")?.textContent?.trim() || "";
    bodyEl = containerEl.querySelector("[aria-label='Message body']") || containerEl;
  } else {
    // Generic fallback
    bodyEl = containerEl.querySelector(
      ".a3s.aiL, [data-test-id='message-view'], [data-test-id='message-body'], [data-testid='message-body']"
    ) || containerEl;
    subject = document.title || "";
    const mailMatches = document.body.innerText.match(/[\w\.-]+@[\w\.-]+\.\w+/g) || [];
    senderEmail = mailMatches[0] || "";
    receiverEmail = mailMatches[1] || "";
  }

  const ccElement = containerEl.querySelector("[aria-label*='Cc'], [data-hovercard-id*='cc']");
  const bccElement = containerEl.querySelector("[aria-label*='Bcc'], [data-hovercard-id*='bcc']");
  if (ccElement) cc = ccElement.innerText || ccElement.textContent || "";
  if (bccElement) bcc = bccElement.innerText || bccElement.textContent || "";
  const bodyText = bodyEl ? bodyEl.innerText : containerEl.innerText;
  const linkElements = bodyEl ? Array.from(bodyEl.querySelectorAll("a[href]")).filter(a => a.href.startsWith("http")) : [];

  // Strip bare URLs (http/https/www tokens) from the text for NLP analysis
  const cleanBodyText = bodyText
    .replace(/https?:\/\/[^\s\"\'>]+/gi, "")
    .replace(/www\.[^\s\"\'>]{3,}/gi, "")
    .replace(/[ \t]{2,}/g, " ")
    .replace(/\n{3,}/g, "\n\n")
    .trim();

  // Full raw text (kept for reference)
  const fullRawText = `From: ${senderName} <${senderEmail}>\nTo: ${receiverName} <${receiverEmail}>\nSubject: ${subject}\n\n${bodyText}`;

  // Keep the clean email text separate from URLs for local analysis.
  const cleanPayloadText = `From: ${senderEmail}\nTo: ${receiverEmail}\nSubject: ${subject}\n\n${cleanBodyText}`;

  return {
    senderName,
    senderEmail,
    receiverName,
    receiverEmail,
    cc,
    bcc,
    subject,
    bodyText,
    cleanBodyText,
    linkElements,
    fullRawText,
    cleanPayloadText,
    bodyEl
  };
}

/**
 * Highlights a suspicious link inside the email and intercepts clicks with a warning.
 * Clicks are recorded into webmail_url_clicks log.
 */
function flagSuspiciousLinkElement(aEl, urlVerdict, emailData) {
  if (aEl.dataset.safeinboxFlagged === "true") return;
  aEl.dataset.safeinboxFlagged = "true";
  aEl.classList.add("aegisai-threat-flagged");
  aEl.title = `⚠️ SafeInbox AI Warning: Suspicious Link (Risk Score: ${urlVerdict.risk_score || 80}/100)`;

  // Add inline warning tag if not already attached
  if (!aEl.nextElementSibling || !aEl.nextElementSibling.classList.contains("aegisai-threat-tag")) {
    const tag = document.createElement("span");
    tag.className = "aegisai-threat-tag";
    tag.textContent = "⚠️ PHISHING LINK";
    aEl.parentNode.insertBefore(tag, aEl.nextSibling);
  }

  // Intercept click to prevent accidental navigation and log click
  aEl.addEventListener("click", e => {
    e.preventDefault();
    e.stopPropagation();
    const proceed = confirm(
      `🛡️ SafeInbox AI Security Warning:\n` +
      `This link was flagged as a potential phishing or security risk!\n\n` +
      `Target URL: ${aEl.href}\n` +
      `Risk Level: ${urlVerdict.risk_level || 'HIGH'} (${urlVerdict.risk_score || 80}/100)\n\n` +
      `Do you still want to proceed to this external destination?`
    );
    recordWebmailUrlClick({
      url: aEl.href,
      emailSubject: emailData ? emailData.subject : "",
      sender: emailData ? (emailData.senderName ? `${emailData.senderName} <${emailData.senderEmail}>` : emailData.senderEmail) : "",
      riskScore: urlVerdict.risk_score || 80,
      riskLevel: urlVerdict.risk_level || "HIGH",
      proceeded: Boolean(proceed),
      source: "flagged_email_link"
    });
    if (proceed) {
      window.open(aEl.href, "_blank", "noopener,noreferrer");
    }
  }, true);
}

/**
 * Injects banner at the appropriate top location of the email view.
 */
function insertBannerAtTop(containerEl, bannerEl) {
  const bodyEl = containerEl.querySelector(".a3s.aiL, [aria-label='Message body']") || containerEl.firstElementChild;
  if (bodyEl && bodyEl.parentNode) {
    bodyEl.parentNode.insertBefore(bannerEl, bodyEl);
  } else {
    containerEl.insertBefore(bannerEl, containerEl.firstChild);
  }
}

/**
 * =============================================================================
 * BANNER 1: URL & HYPERLINK SECURITY SCAN ONLY
 * Contains ONLY:
 * - URL safety status and risk score
 * - List of audited hyperlinks with defanged URLs
 * - Safe / Threat feedback buttons to save a browser-local assessment
 * 
 * NO text, NO body, NO sender, NO receiver, NO subject line!
 * =============================================================================
 */
function renderUrlSecurityBanner(bannerEl, urlScanMap, emailData) {
  let totalScore = 0;
  let threatLinksCount = 0;
  urlScanMap.forEach(v => {
    const s = v.risk_score || 0;
    totalScore += s;
    if (s >= 50 || (v.evidence && v.evidence.length > 0)) threatLinksCount++;
  });

  const totalUrls = urlScanMap.size;
  const avgScore = totalUrls > 0 ? Math.round(totalScore / totalUrls) : 0;
  const failedScans = Array.from(urlScanMap.values()).filter((result) => result.scanError).length;

  let themeClass = "medium";
  let icon = "🔎";
  let title = "NO CONFIGURED THREAT SIGNALS — NOT VERIFIED SAFE";
  let pillText = `Score: ${avgScore}/100 (Avg)`;
  let summaryText = "";

  if (failedScans > 0) {
    themeClass = "medium";
    icon = "🔎";
    title = "INCOMPLETE — SOME LINKS COULD NOT BE VERIFIED";
    pillText = `${failedScans} Scan Error${failedScans === 1 ? "" : "s"}`;
    summaryText = `${failedScans} of ${totalUrls} URL/domain candidates could not be fully analyzed. Do not treat those destinations as verified safe.`;
  } else if (totalUrls === 0) {
    themeClass = "medium";
    icon = "🔎";
    title = "NO HYPERLINKS DETECTED";
    pillText = "0 Links";
    summaryText = "No external links or hyperlinks were detected. This does not verify the email itself as safe.";
  } else if (avgScore >= 60 || (totalUrls > 0 && threatLinksCount >= Math.ceil(totalUrls / 2))) {
    themeClass = "critical";
    icon = "🚨";
    title = "CRITICAL THREAT — HIGH RISK HYPERLINKS DETECTED";
    pillText = `Score: ${avgScore}/100 (Avg)`;
    summaryText = `Average URL risk score across all ${totalUrls} hyperlinks: ${avgScore}/100. ${threatLinksCount} flagged as malicious or phishing destinations.`;
  } else if (avgScore >= 35 || threatLinksCount > 0) {
    themeClass = "high";
    icon = "⚠️";
    title = "SUSPICIOUS HYPERLINK SIGNALS DETECTED";
    pillText = `Score: ${avgScore}/100 (Avg)`;
    summaryText = `Average URL risk score across all ${totalUrls} hyperlinks: ${avgScore}/100. ${threatLinksCount} of ${totalUrls} flagged as suspicious. Verify destination before clicking.`;
  } else {
    themeClass = "medium";
    icon = "🔎";
    title = "NO CONFIGURED THREAT SIGNALS — NOT VERIFIED SAFE";
    pillText = `Score: ${avgScore}/100 (Avg)`;
    summaryText = `Average URL risk score across all ${totalUrls} hyperlinks: ${avgScore}/100. Heuristic checks found no configured indicators; they do not prove the destinations are safe.`;
  }

  bannerEl.className = `aegisai-auto-banner ${themeClass} aegisai-url-banner`;

  // Build URL cards for Banner 1
  let cardsHtml = "";
  if (totalUrls === 0) {
    cardsHtml = `<div class="aegisai-scan-no-items safe">No hyperlinks found. This does not verify the email itself as safe.</div>`;
  } else {
    let idx = 0;
    urlScanMap.forEach((uRes, u) => {
      const uScore  = uRes.risk_score || 0;
      const hasSignals = (uRes.evidence || []).length > 0;
      const uClass  = uRes.scanError ? "warning" : uScore >= 80 ? "threat" : uScore >= 50 || hasSignals ? "warning" : "safe";
      const uBadge  = uRes.scanError ? "UNVERIFIED"
                    : uScore >= 80 ? `THREAT • ${uScore}/100`
                    : uScore >= 50 ? `SUSPICIOUS • ${uScore}/100`
                    : hasSignals ? `SIGNAL • ${uScore}/100`
                    : `NO SIGNALS • ${uScore}/100`;
      const defanged = u.replace(/\./g, "[.]")
                        .replace(/http:\/\//gi, "hxxp://")
                        .replace(/https:\/\//gi, "hxxps://");
      const evidenceHtml = (uRes.evidence && uRes.evidence.length > 0)
        ? `<div class="aegisai-url-evidence">⚠️ ${escapeHtml(uRes.evidence[0].evidence || "Suspicious indicators detected")}</div>`
        : `<div class="aegisai-url-evidence" style="color:#34d399;">✓ No threat indicators found</div>`;
      cardsHtml += `
        <div class="aegisai-url-card ${uClass}" id="aegisaiUrlCard_${idx}" style="max-width:100% !important; box-sizing:border-box !important; overflow:hidden !important; background:rgba(16,21,47,0.9) !important; border:1px solid #384358 !important;">
          <div class="aegisai-url-card-top" style="display:flex !important; align-items:flex-start !important; justify-content:space-between !important; gap:10px !important; width:100% !important; box-sizing:border-box !important;">
            <a href="${escapeHtml(u)}" class="aegisai-url-text aegisai-banner-url-link" data-url="${escapeHtml(u)}" target="_blank" rel="noopener noreferrer" title="Click to visit destination: ${escapeHtml(u)}" style="font-family:'JetBrains Mono',Consolas,monospace !important; font-size:11.5px !important; color:#FFA586 !important; word-break:break-all !important; overflow-wrap:anywhere !important; white-space:normal !important; min-width:0 !important; flex:1 1 auto !important; text-decoration:underline !important; cursor:pointer !important;">${escapeHtml(defanged)}</a>
            <span class="aegisai-url-score-pill ${uClass}" style="flex-shrink:0 !important; background:#242F40 !important; border:1px solid #384358 !important; color:#FFA586 !important;">${uBadge}</span>
          </div>
          ${evidenceHtml}
          <div class="aegisai-url-feedback-bar" style="display:flex !important; flex-wrap:wrap !important; align-items:center !important; justify-content:flex-start !important; background:#242F40 !important; border:1px solid #384358 !important; border-radius:8px !important; padding:8px 12px !important; margin-top:8px !important; gap:12px !important; width:100% !important; box-sizing:border-box !important;">
            <span class="aegisai-feedback-prompt" style="font-size:12px !important; font-weight:700 !important; color:#f8fafc !important; white-space:nowrap !important;">Was this URL safe?</span>
            <div class="aegisai-feedback-buttons" id="aegisaiFbBtns_${idx}" style="display:inline-flex !important; align-items:center !important; gap:8px !important;">
              <span class="aegisai-fb-btn safe" data-url="${escapeHtml(u)}" data-safe="true" data-idx="${idx}" role="button" tabindex="0" style="display:inline-flex !important; align-items:center !important; justify-content:center !important; gap:5px !important; padding:5px 14px !important; border-radius:6px !important; font-size:12px !important; font-weight:700 !important; cursor:pointer !important; background:rgba(255,165,134,0.12) !important; color:#FFA586 !important; border:1px solid #FFA586 !important; box-shadow:0 2px 5px rgba(16,21,47,0.4) !important; user-select:none !important; visibility:visible !important; opacity:1 !important;">✅ Safe</span>
              <span class="aegisai-fb-btn threat" data-url="${escapeHtml(u)}" data-safe="false" data-idx="${idx}" role="button" tabindex="0" style="display:inline-flex !important; align-items:center !important; justify-content:center !important; gap:5px !important; padding:5px 14px !important; border-radius:6px !important; font-size:12px !important; font-weight:700 !important; cursor:pointer !important; background:#B51A2B !important; color:#ffffff !important; border:1px solid #B51A2B !important; box-shadow:0 2px 5px rgba(16,21,47,0.4) !important; user-select:none !important; visibility:visible !important; opacity:1 !important;">❌ Threat</span>
            </div>
          </div>
        </div>`;
      idx++;
    });
  }

  bannerEl.innerHTML = `
    <div class="aegisai-banner-main">
      <div class="aegisai-banner-icon">${icon}</div>
      <div class="aegisai-banner-info">
        <div class="aegisai-banner-title">
          <span>${title}</span>
          <span class="aegisai-banner-score-pill">${pillText}</span>
        </div>
        <div class="aegisai-banner-summary">${escapeHtml(summaryText)}</div>
        <div class="aegisai-banner-urls-section">
          <div class="aegisai-banner-urls-header">
            <span>Audited Hyperlinks (${totalUrls})</span>
            <span class="aegisai-ml-badge">Browser Feedback</span>
          </div>
          ${cardsHtml}
        </div>
      </div>
    </div>
  `;

  // Wire up URL clicks from banner cards (strictly mail only)
  bannerEl.querySelectorAll(".aegisai-banner-url-link").forEach(linkEl => {
    linkEl.addEventListener("click", (e) => {
      e.preventDefault();
      e.stopPropagation();
      const targetUrl = linkEl.getAttribute("data-url");
      const uRes = urlScanMap.get(targetUrl) || {};
      const isHigh = (uRes.risk_score >= 50) || (uRes.evidence && uRes.evidence.length > 0);
      let proceed = true;
      if (isHigh) {
        proceed = confirm(
          `🛡️ SafeInbox AI Warning:\n` +
          `This audited URL was flagged with risk score ${uRes.risk_score || 0}/100.\n\n` +
          `Target: ${targetUrl}\n\n` +
          `Do you still want to proceed to this external destination?`
        );
      }
      recordWebmailUrlClick({
        url: targetUrl,
        emailSubject: emailData ? emailData.subject : "",
        sender: emailData ? (emailData.senderName ? `${emailData.senderName} <${emailData.senderEmail}>` : emailData.senderEmail) : "",
        riskScore: uRes.risk_score || 0,
        riskLevel: uRes.risk_level || (isHigh ? "HIGH" : "SAFE"),
        proceeded: Boolean(proceed),
        source: "url_security_banner"
      });
      if (proceed) {
        window.open(targetUrl, "_blank", "noopener,noreferrer");
      }
    });
  });

  // Wire up feedback buttons (Banner 1 only)
  bannerEl.querySelectorAll(".aegisai-fb-btn").forEach(btn => {
    btn.addEventListener("click", async (e) => {
      e.preventDefault();
      e.stopPropagation();
      const url    = btn.getAttribute("data-url");
      const isSafe = btn.getAttribute("data-safe") === "true";
      const idx    = btn.getAttribute("data-idx");
      const uRes   = urlScanMap.get(url) || {};
      const box    = bannerEl.querySelector(`#aegisaiFbBtns_${idx}`);
      if (box) box.innerHTML = `<span style="font-size:10.5px;color:#94a3b8;">Recording…</span>`;
      const feedbackResult = await sendUrlBooleanFeedback(url, isSafe);
      if (box) box.innerHTML = `
        <span class="aegisai-fb-confirmed ${isSafe ? "safe" : "threat"}" style="font-size:11.5px !important; font-weight:700 !important; padding:4px 10px !important; border-radius:6px !important; display:inline-block !important; background:${isSafe ? "rgba(255,165,134,0.18)" : "rgba(84,26,46,0.45)"} !important; color:${isSafe ? "#FFA586" : "#ff6b7d"} !important; border:1px solid ${isSafe ? "#FFA586" : "#B51A2B"} !important;">
          ${feedbackResult.status === "saved_locally"
            ? "✓ Saved in this browser only; not used for model training"
              : `Feedback not saved: ${escapeHtml(feedbackResult.message || "Unknown error.")}`}
        </span>`;
    });
  });
}

/**
 * =============================================================================
 * BANNER 2: EMAIL CONTENT ANALYSIS (TEXT ONLY)
 * Contains ONLY:
 * - Sender, receiver, subject line, and body text excerpt (clean of URLs)
 * - Text analysis findings / NLP evidence (brand spoofing, urgency, suspicious text)
 * - Recommended action
 * - Safe / Threat feedback buttons to save a browser-local assessment
 * 
 * NO URLs, NO hyperlinks, NO clickable external links!
 * =============================================================================
 */
function renderContentSecurityBanner(bannerEl, verdict, emailData) {
  const isCritical = verdict.risk_level === "CRITICAL" || verdict.risk_score >= 80;
  const isHigh     = verdict.risk_level === "HIGH" || (verdict.risk_score >= 50 && verdict.risk_score < 80);
  const isSafe     = verdict.risk_level === "SAFE" || verdict.risk_score < 25;

  const themeClass = isCritical ? "critical" : (isHigh ? "high" : (isSafe ? "safe" : "medium"));
  const icon       = isCritical ? "🚨" : (isHigh ? "⚠️" : (isSafe ? "🛡️" : "🔎"));
  const title      = isCritical ? "CRITICAL PHISHING THREAT DETECTED"
                   : isHigh     ? "SUSPICIOUS EMAIL SIGNALS DETECTED"
                   : isSafe     ? "NO CONFIGURED THREAT SIGNALS — NOT A GUARANTEE OF SAFETY"
                   :              "CAUTION ADVISED — MODERATE RISK";

  bannerEl.className = `aegisai-auto-banner ${themeClass} aegisai-content-banner`;

  // Body excerpt (pure clean text, URLs already stripped)
  const bodyExcerpt = (emailData.cleanBodyText || emailData.bodyText || "")
    .substring(0, 320).replace(/\n+/g, " ").trim();

  // Findings list (text only)
  const evidenceList = verdict.evidence || [];
  const findingsHtml = evidenceList.length === 0
    ? `<div class="aegisai-scan-no-items safe">No configured text indicators detected in sender, receiver, subject, or body. This is not a safety guarantee.</div>`
    : evidenceList.map(ev => `
        <div class="aegisai-content-finding-item ${(ev.severity || "info").toLowerCase()}">
          <div class="aegisai-cfi-top">
            <span class="aegisai-cfi-rule">${escapeHtml(ev.rule_id || "RULE")}</span>
            <span class="aegisai-cfi-sev ${(ev.severity || "info").toLowerCase()}">${ev.severity || "INFO"}</span>
          </div>
          <div class="aegisai-cfi-text">${escapeHtml(ev.evidence || "")}</div>
          ${ev.remediation ? `<div class="aegisai-cfi-remediation">${escapeHtml(ev.remediation)}</div>` : ""}
        </div>`
      ).join("");

  bannerEl.innerHTML = `
    <div class="aegisai-banner-main">
      <div class="aegisai-banner-icon">${icon}</div>
      <div class="aegisai-banner-info">
        <div class="aegisai-banner-title">
          <span>${title}</span>
          <span class="aegisai-banner-score-pill">Score: ${verdict.risk_score}/100 · ${verdict.model_available ? "NLP model" : "Heuristics"}</span>
        </div>
        <div class="aegisai-banner-summary">${escapeHtml(verdict.summary || (isSafe ? "No configured email text indicators were detected. This is not a safety guarantee." : "Deceptive indicators or sender domain mismatch detected in text."))}</div>

        <div class="aegisai-email-fields-card">
          <div class="aegisai-email-fields-title">📧 Scanned Email Fields (Text Only)</div>
          <div class="aegisai-email-field-row">
            <span class="aegisai-ef-label">Sender</span>
            <span class="aegisai-ef-value">
              ${escapeHtml(emailData.senderName || emailData.senderEmail || "—")}
              ${emailData.senderEmail && emailData.senderName && emailData.senderName !== emailData.senderEmail
                ? `<span class="aegisai-ef-addr">&lt;${escapeHtml(emailData.senderEmail)}&gt;</span>` : ""}
            </span>
          </div>
          <div class="aegisai-email-field-row">
            <span class="aegisai-ef-label">Receiver</span>
            <span class="aegisai-ef-value">${escapeHtml(emailData.receiverEmail || "Current User")}</span>
          </div>
          <div class="aegisai-email-field-row">
            <span class="aegisai-ef-label">Subject</span>
            <span class="aegisai-ef-value">${escapeHtml(emailData.subject || "(no subject)")}</span>
          </div>
          <div class="aegisai-email-field-row body-row">
            <span class="aegisai-ef-label">Body</span>
            <span class="aegisai-ef-value body-text">
              ${escapeHtml(bodyExcerpt || "(empty body)")}${bodyExcerpt.length >= 320 ? "…" : ""}
            </span>
          </div>
          ${verdict.claimed_company ? `
          <div class="aegisai-email-field-row">
            <span class="aegisai-ef-label">Brand</span>
            <span class="aegisai-ef-value" style="color:#fbbf24;">${escapeHtml(verdict.claimed_company)} (claimed)</span>
          </div>` : ""}
        </div>

        <div class="aegisai-content-findings">
          <div class="aegisai-content-findings-title">
            🔍 Text Analysis Findings
            <span class="aegisai-findings-count">${evidenceList.length}</span>
          </div>
          ${findingsHtml}
        </div>

        ${verdict.recommended_action ? `
          <div class="aegisai-content-action ${isSafe ? "safe" : "warn"}">
            <strong>Action:</strong> ${escapeHtml(verdict.recommended_action)}
          </div>` : ""}

        <!-- Text / Email Content Feedback Bar (Banner 2) -->
        <div class="aegisai-content-feedback-bar" style="display:flex !important; flex-wrap:wrap !important; align-items:center !important; justify-content:flex-start !important; background:#242F40 !important; border:1px solid #384358 !important; border-radius:8px !important; padding:10px 14px !important; margin-top:12px !important; gap:12px !important; width:100% !important; box-sizing:border-box !important;">
          <span class="aegisai-feedback-prompt" style="font-size:12px !important; font-weight:700 !important; color:#f8fafc !important;">Was this email text / sender safe?</span>
          <div class="aegisai-feedback-buttons" id="aegisaiContentFbBtns" style="display:inline-flex !important; align-items:center !important; gap:8px !important;">
            <span class="aegisai-fb-btn safe" id="aegisaiContentFbSafe" role="button" tabindex="0" style="display:inline-flex !important; align-items:center !important; justify-content:center !important; gap:5px !important; padding:5px 14px !important; border-radius:6px !important; font-size:12px !important; font-weight:700 !important; cursor:pointer !important; background:rgba(255,165,134,0.12) !important; color:#FFA586 !important; border:1px solid #FFA586 !important; box-shadow:0 2px 5px rgba(16,21,47,0.4) !important; user-select:none !important; visibility:visible !important; opacity:1 !important;">✅ Safe</span>
            <span class="aegisai-fb-btn threat" id="aegisaiContentFbThreat" role="button" tabindex="0" style="display:inline-flex !important; align-items:center !important; justify-content:center !important; gap:5px !important; padding:5px 14px !important; border-radius:6px !important; font-size:12px !important; font-weight:700 !important; cursor:pointer !important; background:#B51A2B !important; color:#ffffff !important; border:1px solid #B51A2B !important; box-shadow:0 2px 5px rgba(16,21,47,0.4) !important; user-select:none !important; visibility:visible !important; opacity:1 !important;">❌ Threat</span>
          </div>
        </div>
      </div>
      <button class="aegisai-banner-toggle-btn" id="aegisaiToggleDetails">Details</button>
    </div>

    <div class="aegisai-banner-details" style="display:none;" id="aegisaiDetailsSection">
      <div style="font-size:11.5px;font-weight:700;color:#cbd5e1;margin-bottom:4px;">Security Evidence:</div>
      ${evidenceList.map(ev => `
        <div class="aegisai-banner-evidence-item ${isSafe ? "safe" : ""}">
          <strong>[${ev.severity || "INFO"}]</strong> ${escapeHtml(ev.evidence)}
        </div>`).join("")}
      ${verdict.recommended_action ? `
        <div style="margin-top:6px;font-size:12px;color:#f8fafc;background:rgba(0,0,0,0.3);padding:8px;border-radius:6px;">
          <strong>Action:</strong> ${escapeHtml(verdict.recommended_action)}
        </div>` : ""}
    </div>
  `;

  // Wire up email text feedback buttons (Banner 2 only)
  const fbSafeBtn   = bannerEl.querySelector("#aegisaiContentFbSafe");
  const fbThreatBtn = bannerEl.querySelector("#aegisaiContentFbThreat");
  const fbBox       = bannerEl.querySelector("#aegisaiContentFbBtns");

  const handleEmailFeedback = async (isSafeFeedback) => {
    if (fbBox) fbBox.innerHTML = `<span style="font-size:10.5px;color:#94a3b8;">Recording…</span>`;
    const feedbackResult = await sendEmailBooleanFeedback(emailData, isSafeFeedback);
    if (fbBox) fbBox.innerHTML = `
      <span class="aegisai-fb-confirmed ${isSafeFeedback ? "safe" : "threat"}" style="font-size:11.5px !important; font-weight:700 !important; padding:4px 10px !important; border-radius:6px !important; display:inline-block !important; background:${isSafeFeedback ? "rgba(255,165,134,0.18)" : "rgba(84,26,46,0.45)"} !important; color:${isSafeFeedback ? "#FFA586" : "#ff6b7d"} !important; border:1px solid ${isSafeFeedback ? "#FFA586" : "#B51A2B"} !important;">
        ${feedbackResult.status === "saved_locally"
          ? "✓ Saved in this browser only; not used for model training"
            : `Feedback not saved: ${escapeHtml(feedbackResult.message || "Unknown error.")}`}
      </span>`;
  };

  if (fbSafeBtn) {
    fbSafeBtn.addEventListener("click", (e) => {
      e.preventDefault();
      e.stopPropagation();
      handleEmailFeedback(true);
    });
  }
  if (fbThreatBtn) {
    fbThreatBtn.addEventListener("click", (e) => {
      e.preventDefault();
      e.stopPropagation();
      handleEmailFeedback(false);
    });
  }

  // Toggle raw details panel
  const toggleBtn  = bannerEl.querySelector("#aegisaiToggleDetails");
  const detailsSec = bannerEl.querySelector("#aegisaiDetailsSection");
  if (toggleBtn && detailsSec) {
    toggleBtn.addEventListener("click", () => {
      const vis = detailsSec.style.display !== "none";
      detailsSec.style.display = vis ? "none" : "flex";
      toggleBtn.textContent    = vis ? "Details" : "Hide";
    });
  }
}

/**
 * Saves bounded feedback in local browser storage (max 100 entries per type).
 */
function saveBrowserFeedback(target, isSafe, targetType) {
  if (typeof chrome === "undefined" || !chrome.storage || !chrome.storage.local || typeof target !== "string" || !target.trim()) {
    return Promise.resolve({
      status: "error",
      message: typeof target !== "string" || !target.trim()
        ? "No feedback sample was available to save."
        : "Browser storage is unavailable; feedback could not be saved."
    });
  }
  const storageKey = targetType === "EMAIL" ? "offline_text_feedback" : "offline_url_feedback";
  const maxTargetLength = targetType === "EMAIL" ? 20000 : 4096;
  return new Promise((resolve) => {
    try {
      chrome.storage.local.get([storageKey], (data) => {
        if (chrome.runtime.lastError) {
          resolve({ status: "error", message: chrome.runtime.lastError.message });
          return;
        }
        const list = Array.isArray(data[storageKey]) ? data[storageKey] : [];
        list.push({
          target: target.trim().slice(0, maxTargetLength),
          target_truncated: target.trim().length > maxTargetLength,
          target_type: targetType === "EMAIL" ? "TEXT" : "URL",
          is_safe: isSafe,
          source: "webmail_banner",
          timestamp: Date.now()
        });
        chrome.storage.local.set({ [storageKey]: list.slice(-100) }, () => {
          if (chrome.runtime.lastError) {
            resolve({ status: "error", message: chrome.runtime.lastError.message });
            return;
          }
          resolve({ status: "saved_locally", is_safe: isSafe });
        });
      });
    } catch (error) {
      resolve({ status: "error", message: error.message || "Browser storage is unavailable." });
    }
  });
}

/**
 * Saves email-content feedback in browser storage.
 */
function sendEmailBooleanFeedback(emailData, isSafe) {
  const target = (emailData && (emailData.cleanBodyText || emailData.bodyText)) || "";
  return saveBrowserFeedback(target, isSafe, "EMAIL");
}

/**
 * Saves URL feedback in browser storage.
 */
function sendUrlBooleanFeedback(url, isSafe) {
  return saveBrowserFeedback(url, isSafe, "URL");
}

// =============================================================================
// Browser-Side Threat Inspection
// =============================================================================
async function scanSingleUrl(url) {
  if (_urlScanCache.has(url)) return _urlScanCache.get(url);
  const result = await analyzeEmailUrl(url);
  _urlScanCache.set(url, result);
  return result;
}

async function analyzeEmailUrl(url) {
  if (typeof chrome !== "undefined" && chrome.runtime && chrome.runtime.sendMessage) {
    const response = await new Promise((resolve, reject) => {
      chrome.runtime.sendMessage({ type: "ANALYZE_URL", url }, (result) => {
        if (chrome.runtime.lastError) {
          reject(new Error(chrome.runtime.lastError.message));
          return;
        }
        resolve(result);
      });
    });
    if (!response || !response.ok) {
      throw new Error(response && response.error ? response.error : "URL analysis failed.");
    }
    return adaptEmailUrlResult(response.result);
  }
  const parsed = UrlThreatParser.analyzeUrl(url);
  return adaptEmailUrlResult({ ...parsed, riskScore: parsed.heuristicRisk, modelAvailable: false });
}

function adaptEmailUrlResult(result) {
  return {
    target: result.inputUrl,
    risk_score: Math.round(result.riskScore * 100),
    risk_level: result.riskScore >= 0.8 ? "CRITICAL" : result.riskScore >= 0.6 ? "HIGH" : result.riskScore >= 0.35 ? "MEDIUM" : "SAFE",
    model_available: Boolean(result.modelAvailable),
    analysisWarning: result.analysisWarning || "",
    evidence: (result.findings || []).map((finding) => ({
      severity: finding.penalty >= 0.5 ? "CRITICAL" : finding.penalty >= 0.3 ? "HIGH" : "MEDIUM",
      rule_id: finding.attackType,
      evidence: `${finding.title}: ${finding.detail}`
    }))
  };
}

function notifySidePanelOfEmail(emailData, urls) {
  chrome.runtime.sendMessage({
    type: "EMAIL_SCAN_OPENED",
    email: {
      sender: emailData.senderName ? `${emailData.senderName} <${emailData.senderEmail}>` : emailData.senderEmail,
      senderName: emailData.senderName,
      senderEmail: emailData.senderEmail,
      receiver: emailData.receiverEmail,
      cc: emailData.cc,
      bcc: emailData.bcc,
      subject: emailData.subject,
      text: emailData.cleanPayloadText,
      bodyText: emailData.cleanBodyText,
      urls
    }
  }, (response) => {
    if (chrome.runtime.lastError) {
      console.warn("SafeInbox AI could not hand the email scan to the side panel:", chrome.runtime.lastError.message);
    } else if (response && !response.ok) {
      console.warn("SafeInbox AI could not hand the email scan to the side panel:", response.error);
    }
  });
}

async function scanEmailPayload(payload) {
  const email = {
    text: payload.text || "",
    body: payload.body || payload.text || "",
    sender: payload.sender || "",
    receiver: payload.receiver || "",
    cc: payload.cc || "",
    subject: payload.subject || "",
    bcc: payload.bcc || ""
  };
  try {
    const response = await new Promise((resolve, reject) => {
      chrome.runtime.sendMessage({ type: "ANALYZE_EMAIL_TEXT", email }, (result) => {
        if (chrome.runtime.lastError) {
          reject(new Error(chrome.runtime.lastError.message));
        } else if (!result || !result.ok) {
          reject(new Error(result && result.error ? result.error : "Email text analysis service did not respond."));
        } else {
          resolve(result);
        }
      });
    });
    return response.result;
  } catch (error) {
    console.warn("SafeInbox AI webmail analysis used local heuristics:", error.message);
    const result = EmailTextAnalyzer.analyzeEmailText(email);
    result.analysis_note = `Background text inference was unavailable; local heuristics were used: ${error.message}`;
    return result;
  }
}

function highlightSuspiciousSentences(bodyEl, threatVectors) {
  if (!bodyEl || !Array.isArray(threatVectors) || !threatVectors.length) return;
  const cues = [];
  if (threatVectors.includes("ARTIFICIAL_URGENCY")) cues.push(/\b(?:urgent(?:ly)?|immediate(?:ly)?|action required|within\s+\d+\s+hours?|account (?:is )?(?:suspended|locked|terminated)|final warning|expires? today)\b/gi);
  if (threatVectors.includes("FINANCIAL_SCAM")) cues.push(/\b(?:unclaimed refund|refund pending|payment overdue|invoice|wire transfer|gift card|prize(?: money)?|claim your reward|tax refund)\b/gi);
  if (threatVectors.includes("CREDENTIAL_HARVESTING")) cues.push(/\b(?:password|passcode|pin|one[- ]time code|2fa|multi[- ]factor|verification code|security code|login credentials|sign[ -]?in details)\b/gi);
  if (threatVectors.includes("BEHAVIORAL_MANIPULATION")) cues.push(/\b(?:legal action|police report|law enforcement|account termination|permanently deleted|arrest warrant|immediately or else|avoid prosecution)\b/gi);
  if (!cues.length) return;

  const walker = document.createTreeWalker(bodyEl, NodeFilter.SHOW_TEXT, {
    acceptNode(node) {
      if (!node.nodeValue || !node.nodeValue.trim()) return NodeFilter.FILTER_REJECT;
      const parent = node.parentElement;
      if (!parent || parent.closest("a,script,style,mark,.aegisai-banner-container")) return NodeFilter.FILTER_REJECT;
      return NodeFilter.FILTER_ACCEPT;
    }
  });
  const nodes = [];
  while (walker.nextNode()) nodes.push(walker.currentNode);

  for (const node of nodes) {
    const text = node.nodeValue;
    const ranges = [];
    for (const cue of cues) {
      cue.lastIndex = 0;
      for (const match of text.matchAll(cue)) {
        let start = match.index;
        let end = start + match[0].length;
        while (start > 0 && !/[.!?\n]/.test(text[start - 1])) start -= 1;
        while (end < text.length && !/[.!?\n]/.test(text[end])) end += 1;
        if (end < text.length && /[.!?]/.test(text[end])) end += 1;
        ranges.push([start, end]);
      }
    }
    ranges.sort((left, right) => left[0] - right[0]);
    const merged = [];
    for (const range of ranges) {
      const previous = merged[merged.length - 1];
      if (previous && range[0] <= previous[1]) previous[1] = Math.max(previous[1], range[1]);
      else merged.push(range);
    }
    for (const [start, end] of merged.reverse()) {
      node.splitText(end);
      const markedNode = node.splitText(start);
      const mark = document.createElement("mark");
      mark.className = "aegisai-text-threat-highlight";
      mark.title = "Suspicious or manipulative language identified by local email analysis.";
      mark.textContent = markedNode.nodeValue;
      markedNode.parentNode.replaceChild(mark, markedNode);
    }
  }
}

function escapeHtml(str) {
  return String(str ?? "").replace(/[&<>"']/g, m => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
  }[m]));
}

function extractActiveEmailData() {
  if (!isWebmailDomain()) return null;
  const hostname = window.location.hostname.toLowerCase();
  const clientType = hostname.includes("outlook") ? "outlook" : hostname.includes("mail.yahoo") ? "generic" : "gmail";
  let container = null;

  if (clientType === "gmail") {
    container = getActiveGmailMessage();
  } else if (clientType === "outlook") {
    container = document.querySelector(".ReadingPaneContainer, [aria-label='Message body']");
  } else {
    container = document.querySelector(
      ".a3s.aiL, [data-test-id='message-view'], [data-test-id='message-body'], [data-testid='message-body']"
    );
  }

  if (!container) return null;
  return extractStructuredEmailFromElement(container, clientType);
}

function highlightSuspiciousLinks(threatUrls) {
  if (!threatUrls || threatUrls.length === 0) return;
  const threatSet = new Set(threatUrls.map(u => u.toLowerCase()));
  const activeMessage = getActiveGmailMessage() || document.querySelector(".ReadingPaneContainer, [aria-label='Message body'], .a3s.aiL");
  if (!activeMessage) return;

  activeMessage.querySelectorAll("a[href]").forEach(a => {
    if (threatSet.has(a.href.toLowerCase())) {
      a.classList.add("aegisai-threat-flagged");
      a.title = "⚠️ SafeInbox AI Warning: Suspicious or high-risk destination link";
    }
  });
}

// =============================================================================
// Message listener for Side Panel operations (extract email, scan links).
// =============================================================================
if (typeof chrome !== "undefined" && chrome.runtime && chrome.runtime.onMessage) {
  chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === "extract_email_content") {
      try {
        const emailData = extractActiveEmailData();
        if (!emailData || (!emailData.bodyText && !emailData.subject)) {
          sendResponse({ status: "error", message: "No active email message detected." });
          return true;
        }
        sendResponse({
          status: "ok",
          sender: emailData.senderName ? `${emailData.senderName} <${emailData.senderEmail}>` : emailData.senderEmail,
          senderEmail: emailData.senderEmail,
          senderName: emailData.senderName,
          receiver: emailData.receiverEmail,
          cc: emailData.cc,
          bcc: emailData.bcc,
          subject: emailData.subject,
          bodyText: emailData.cleanBodyText,
          text: emailData.cleanPayloadText,
          cleanBody: emailData.cleanBodyText,
          clean_body: emailData.cleanBodyText,
          urls: EmailThreatUtils.extractUrlsFromEmail(
            emailData.bodyText,
            emailData.linkElements.map((anchor) => anchor.href)
          )
        });
      } catch (err) {
        sendResponse({ status: "error", message: err.message });
      }
      return true;
    }

    if (request.action === "extract_page_links") {
      try {
        const activeMessage = getActiveGmailMessage() || document.querySelector(".ReadingPaneContainer, [aria-label='Message body'], .a3s.aiL");
        const scope = activeMessage || document;
        const links = Array.from(scope.querySelectorAll("a[href]"))
          .map(a => a.href)
          .filter(h => h.startsWith("http://") || h.startsWith("https://"));
        sendResponse({ status: "ok", links: links });
      } catch (err) {
        sendResponse({ status: "error", message: err.message });
      }
      return true;
    }
  });
}

// Initialize on page load
if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", startAutoEmailObserver);
} else {
  startAutoEmailObserver();
}
