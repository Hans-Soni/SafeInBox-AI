/**
 * AegisAI Threat Inspector - Browser Extension Side Panel Controller
 * Runs client-side brand intelligence and heuristic checks.
 */

let lastScanResult = null;
let inferenceWorker = null;
let inferencePort = null;
let lastAutoEmailScanKey = "";

// DOM element cache — populated once on DOMContentLoaded
const el = {};

// =============================================================================
// Initialization & Local Engine Status
// =============================================================================
document.addEventListener("DOMContentLoaded", async () => {
  // Cache frequently-used elements once to avoid repeated DOM lookups
  el.urlInput            = document.getElementById("urlInput");
  el.emailInput          = document.getElementById("emailInput");
  el.scanUrlBtn          = document.getElementById("scanUrlBtn");
  el.scanEmailBtn        = document.getElementById("scanEmailBtn");
  el.tabEmailBtn         = document.getElementById("tabEmailBtn");
  el.tabSummaryBtn       = document.getElementById("tabSummaryBtn");
  el.engineStatusBadge   = document.getElementById("engineStatusBadge");
  el.engineStatusText    = document.getElementById("engineStatusText");
  el.statusDot           = el.engineStatusBadge.querySelector(".status-dot");
  el.loadingOverlay      = document.getElementById("loadingOverlay");
  el.resultsContainer    = document.getElementById("resultsContainer");
  el.riskScoreValue      = document.getElementById("riskScoreValue");
  el.riskLevelBadge      = document.getElementById("riskLevelBadge");
  el.latencyBadge        = document.getElementById("latencyBadge");
  el.verdictTitle        = document.getElementById("verdictTitle");
  el.verdictSummary      = document.getElementById("verdictSummary");
  el.gaugeBar            = document.getElementById("gaugeBar");
  el.auditReportBox      = document.getElementById("auditReportBox");
  el.evidenceList        = document.getElementById("evidenceList");
  el.evidenceCount       = document.getElementById("evidenceCount");
  el.remediationCard     = document.getElementById("remediationCard");
  el.remediationText     = document.getElementById("remediationText");
  el.companyIntelCard    = document.getElementById("companyIntelCard");
  el.intelClaimedBrand   = document.getElementById("intelClaimedBrand");
  el.intelSenderDomain   = document.getElementById("intelSenderDomain");
  el.companyStatusBadge  = document.getElementById("companyStatusBadge");
  el.intelDomainVerdict  = document.getElementById("intelDomainVerdict");
  el.directFeedbackCard  = document.getElementById("directFeedbackCard");
  el.directFeedbackBtns  = document.getElementById("directFeedbackBtns");
  el.directFeedbackMsg   = document.getElementById("directFeedbackMsg");
  el.btnFeedbackSafe     = document.getElementById("btnFeedbackSafe");
  el.btnFeedbackThreat   = document.getElementById("btnFeedbackThreat");
  el.feedbackTargetLabel = document.getElementById("feedbackTargetLabel");
  el.linksCard           = document.getElementById("linksCard");
  el.linksList           = document.getElementById("linksList");
  el.linksCount          = document.getElementById("linksCount");
  el.linksTitle          = document.getElementById("linksTitle");
  el.scanProgressContainer = document.getElementById("scanProgressContainer");
  el.scanProgressFill    = document.getElementById("scanProgressFill");
  el.scanProgressText    = document.getElementById("scanProgressText");
  el.activeEmailNotice  = document.getElementById("activeEmailNotice");
  el.summaryTextScore = document.getElementById("summaryTextScore");
  el.summaryUrlScore = document.getElementById("summaryUrlScore");
  el.summaryCombinedScore = document.getElementById("summaryCombinedScore");
  el.summaryAnalysis = document.getElementById("summaryAnalysis");
  el.emailUrlAverage = document.getElementById("emailUrlAverage");
  el.contextTextLevel = document.getElementById("contextTextLevel");
  el.contextTextScore = document.getElementById("contextTextScore");
  el.contextTextSummary = document.getElementById("contextTextSummary");
  el.contextSignals = document.getElementById("contextSignals");
  el.contextResultCard = document.getElementById("contextResultCard");
  el.cloudPanel = document.getElementById("cloudPanel");
  el.cloudPanelHeader = document.getElementById("cloudPanelHeader");
  el.cloudPanelBody = document.getElementById("cloudPanelBody");
  el.cloudBadge = document.getElementById("cloudBadge");
  el.cloudBackendUrlInput = document.getElementById("cloudBackendUrlInput");
  el.btnConnectCloud = document.getElementById("btnConnectCloud");
  el.cloudStatusMsg = document.getElementById("cloudStatusMsg");
  el.mailClicksPanel = document.getElementById("mailClicksPanel");
  el.mailClicksHeader = document.getElementById("mailClicksHeader");
  el.mailClicksBody = document.getElementById("mailClicksBody");
  el.mailClicksCountBadge = document.getElementById("mailClicksCountBadge");
  el.mailClicksList = document.getElementById("mailClicksList");
  el.btnClearMailClicks = document.getElementById("btnClearMailClicks");
  el.accountPillBtn = document.getElementById("accountPillBtn");
  el.accountPillLabel = document.getElementById("accountPillLabel");
  el.cloudAccountStatus = document.getElementById("cloudAccountStatus");
  el.btnCloudAccountAction = document.getElementById("btnCloudAccountAction");
  el.authModalBackdrop = document.getElementById("authModalBackdrop");
  el.authModalClose = document.getElementById("authModalClose");
  el.authSignedOutView = document.getElementById("authSignedOutView");
  el.authSignedInView = document.getElementById("authSignedInView");
  el.authTabSignInBtn = document.getElementById("authTabSignInBtn");
  el.authTabSignUpBtn = document.getElementById("authTabSignUpBtn");
  el.authSignInForm = document.getElementById("authSignInForm");
  el.authSignInEmail = document.getElementById("authSignInEmail");
  el.authSignInPassword = document.getElementById("authSignInPassword");
  el.authSignInStatus = document.getElementById("authSignInStatus");
  el.btnSubmitSignIn = document.getElementById("btnSubmitSignIn");
  el.authLinkToSignUp = document.getElementById("authLinkToSignUp");
  el.authSignUpForm = document.getElementById("authSignUpForm");
  el.authSignUpName = document.getElementById("authSignUpName");
  el.authSignUpEmail = document.getElementById("authSignUpEmail");
  el.authSignUpPassword = document.getElementById("authSignUpPassword");
  el.authSignUpConfirmPassword = document.getElementById("authSignUpConfirmPassword");
  el.authSignUpStatus = document.getElementById("authSignUpStatus");
  el.btnSubmitSignUp = document.getElementById("btnSubmitSignUp");
  el.authLinkToSignIn = document.getElementById("authLinkToSignIn");
  el.authProfileName = document.getElementById("authProfileName");
  el.authProfileEmail = document.getElementById("authProfileEmail");
  el.btnSubmitSignOut = document.getElementById("btnSubmitSignOut");
  el.linkOpenWelcome = document.getElementById("linkOpenWelcome");

  const summaryTab = document.getElementById("tab-summary");
  const urlTab = document.getElementById("tab-url");
  const contextTab = document.getElementById("tab-context");
  el.urlTab = urlTab;
  el.contextTab = contextTab;
  summaryTab.appendChild(el.resultsContainer);
  urlTab.appendChild(el.linksCard);
  contextTab.appendChild(el.directFeedbackCard);
  const pageLinkCard = document.querySelector("#tab-page .input-card");
  if (pageLinkCard) {
    urlTab.appendChild(pageLinkCard);
    document.getElementById("tab-page").remove();
  }
  const evidenceCard = document.querySelector(".evidence-card");
  if (evidenceCard) evidenceCard.style.display = "none";

  el.emailInput.addEventListener("input", () => {
    delete el.emailInput.dataset.cleanBody;
    delete el.emailInput.dataset.sender;
    delete el.emailInput.dataset.receiver;
    delete el.emailInput.dataset.cc;
    delete el.emailInput.dataset.bcc;
    delete el.emailInput.dataset.subject;
  });

  // Status badge re-check on click (moved here so el cache is ready)
  el.engineStatusBadge.addEventListener("click", checkBackendStatus);

  initTabs();
  initPresetButtons();
  initActions();
  initFeedbackActions();
  initCloudPanel();
  initMailClicksTracker();
  initAuthManager();
  checkBackendStatus();
  initializeInferenceWorker();
  initializeEmailModelStatus();
  void initializeEmailScanBridge().catch(showEmailScanError);

  if (typeof chrome !== "undefined" && chrome.storage && chrome.storage.local) {
    chrome.storage.local.get(["pendingScanUrl", "pendingScanEmail"], (items) => {
      if (items && items.pendingScanUrl) {
        el.urlInput.value = items.pendingScanUrl;
        chrome.storage.local.remove("pendingScanUrl");
        el.scanUrlBtn.click();
      } else if (items && items.pendingScanEmail) {
        el.tabEmailBtn.click();
        el.emailInput.value = items.pendingScanEmail;
        chrome.storage.local.remove("pendingScanEmail");
        el.scanEmailBtn.click();
      } else {
        autoFillCurrentTabUrl();
      }
    });
  } else {
    autoFillCurrentTabUrl();
  }
});

async function initializeEmailScanBridge() {
  if (typeof chrome === "undefined" || !chrome.tabs || !chrome.tabs.query) return;
  if (chrome.storage && chrome.storage.session && chrome.storage.onChanged) {
    chrome.storage.onChanged.addListener((changes, areaName) => {
      if (areaName === "session" && changes.activeEmailScan && changes.activeEmailScan.newValue) {
        void loadEmailScanForActiveTab(changes.activeEmailScan.newValue).catch(showEmailScanError);
      }
    });
  }
  if (chrome.tabs.onActivated) {
    chrome.tabs.onActivated.addListener(({ tabId }) => {
      void refreshEmailForTab(tabId).catch(showEmailScanError);
    });
  }
  const [activeTab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!activeTab) return;
  if (!isSupportedEmailTab(activeTab.url)) {
    el.activeEmailNotice.textContent = "Open Gmail, Outlook, or Yahoo Mail to scan the current email.";
    return;
  }
  if (chrome.storage && chrome.storage.session) {
    const items = await chrome.storage.session.get("activeEmailScan");
    if (items.activeEmailScan && items.activeEmailScan.tabId === activeTab.id) {
      await loadEmailScanForActiveTab(items.activeEmailScan);
      return;
    }
  }
  const email = await requestEmailFromTab(activeTab.id);
  if (email) {
    email.tabId = activeTab.id;
    email.updatedAt = Date.now();
    await loadEmailScanForActiveTab(email);
  } else if (el.activeEmailNotice) {
    el.activeEmailNotice.textContent = "Open a message in Gmail, Outlook, or Yahoo Mail to scan its text and links.";
  }
}

function requestEmailFromTab(tabId) {
  return new Promise((resolve) => {
    chrome.tabs.sendMessage(tabId, { action: "extract_email_content" }, (response) => {
      if (chrome.runtime.lastError) {
        el.activeEmailNotice.textContent = "Extension updated. Refresh the email page once so its scanner can reconnect, then open the message again.";
        resolve(null);
        return;
      }
      if (!response || response.status !== "ok") {
        el.activeEmailNotice.textContent = response && response.message
          ? response.message
          : "No open email was found in the active tab.";
        resolve(null);
        return;
      }
      resolve(response);
    });
  });
}

async function refreshEmailForTab(tabId) {
  const activeTab = await chrome.tabs.get(tabId);
  if (!activeTab || !isSupportedEmailTab(activeTab.url)) {
    el.activeEmailNotice.textContent = "Open Gmail, Outlook, or Yahoo Mail to scan the current email.";
    return;
  }
  if (chrome.storage && chrome.storage.session) {
    const stored = await chrome.storage.session.get("activeEmailScan");
    if (stored.activeEmailScan && stored.activeEmailScan.tabId === tabId) {
      await loadEmailScanForActiveTab(stored.activeEmailScan);
      return;
    }
  }
  const email = await requestEmailFromTab(tabId);
  if (email) {
    email.tabId = tabId;
    email.updatedAt = Date.now();
    await loadEmailScanForActiveTab(email);
  }
}

function isSupportedEmailTab(url) {
  if (typeof url !== "string") return false;
  try {
    const hostname = new URL(url).hostname.toLowerCase();
    return hostname === "mail.google.com" ||
      hostname === "outlook.live.com" ||
      hostname === "outlook.office.com" ||
      hostname === "mail.yahoo.com";
  } catch {
    return false;
  }
}

function showEmailScanError(error) {
  if (el.activeEmailNotice) {
    el.activeEmailNotice.textContent = `Email scan could not be completed: ${error.message || "Unknown error."}`;
  }
}

async function loadEmailScanForActiveTab(email) {
  const [activeTab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!activeTab || activeTab.id !== email.tabId) return;
  const scanKey = JSON.stringify([email.tabId, email.sender, email.subject, email.text, email.urls]);
  if (scanKey === lastAutoEmailScanKey) {
    await clearEmailSessionIfCurrent(email);
    return;
  }
  lastAutoEmailScanKey = scanKey;
  try {
    await runEmailScan(email.text, email.urls, email);
  } finally {
    await clearEmailSessionIfCurrent(email);
  }
}

async function clearEmailSessionIfCurrent(email) {
  const stored = await chrome.storage.session.get("activeEmailScan");
  if (stored.activeEmailScan &&
      stored.activeEmailScan.tabId === email.tabId &&
      stored.activeEmailScan.updatedAt === email.updatedAt) {
    await chrome.storage.session.remove("activeEmailScan");
  }
}

async function runEmailScan(text, suppliedUrls, metadata = {}) {
  const emailText = (text || "").trim();
  if (!emailText) throw new Error("No email content was available to scan.");
  el.emailInput.value = emailText;
  el.emailInput.dataset.sender = metadata.sender || "";
  el.emailInput.dataset.receiver = metadata.receiver || "";
  el.emailInput.dataset.cc = metadata.cc || "";
  el.emailInput.dataset.bcc = metadata.bcc || "";
  el.emailInput.dataset.subject = metadata.subject || "";
  el.emailInput.dataset.cleanBody = metadata.bodyText || "";
  if (el.activeEmailNotice) {
    el.activeEmailNotice.textContent = metadata.subject
      ? `Scanning open email: ${metadata.subject}`
      : "Scanning the email opened in this tab.";
  }

  showLoading(true);
  try {
    const textResult = await executeEmailScan(emailText);
    const urls = EmailThreatUtils.extractUrlsFromEmail(emailText, suppliedUrls || []);
    if (!urls.length) {
      el.linksTitle.textContent = "Current Email URLs";
      renderResults({
        ...textResult,
        target_type: "EMAIL",
        email_text_score: textResult.risk_score,
        email_text_summary: textResult.summary,
        email_text_evidence: textResult.evidence || [],
        email_url_average: null,
        email_url_highest: null
      });
      if (metadata.tabId !== undefined) el.tabSummaryBtn.click();
      return;
    }
    el.linksTitle.textContent = "Current Email URLs";
    const urlResult = await scanBatchLinks(urls);
    const urlScores = urlResult.urls_analyzed.map((item) => Math.round((Number.parseFloat(item.risk_score) || 0) * 100));
    const averages = calculateEmailRiskAverage(textResult.risk_score, urlScores);
    const { textScore: textRisk, urlAverage: averageUrlRisk, urlHighest: highestUrlRisk, combined: riskScore } = averages;
    const urlEvidence = urlResult.urls_analyzed.flatMap((item) =>
      (item.evidence || []).map((finding) => ({
        ...finding,
        evidence: `${item.defanged}: ${finding.evidence}`
      }))
    );
    const combined = {
      ...textResult,
      target_type: "EMAIL",
      risk_score: riskScore,
      risk_level: riskScore >= 80 ? "CRITICAL" : riskScore >= 60 ? "HIGH" : riskScore >= 35 ? "MEDIUM" : riskScore >= 15 ? "LOW" : "SAFE",
      summary: `Combined email risk is the arithmetic mean of text risk (${textRisk}/100) and the average of ${urls.length} URL risk score${urls.length === 1 ? "" : "s"} (${averageUrlRisk}/100). Highest individual URL risk: ${highestUrlRisk}/100. ${textResult.summary} ${urlResult.urls_analyzed.some((item) => item.model_available) ? "ONNX inference was available for URL analysis." : "URL assessments used heuristics; no trained model was available."}`,
      recommended_action: riskScore >= 50
        ? "Do not click suspicious links or provide credentials. Verify the sender through a separate trusted channel."
        : textResult.recommended_action,
      urls_analyzed: urlResult.urls_analyzed,
      email_text_score: textRisk,
      email_text_summary: textResult.summary,
      email_text_evidence: textResult.evidence || [],
      email_url_average: averageUrlRisk,
      email_url_highest: highestUrlRisk,
      extracted_urls_count: urls.length,
      evidence: [...(textResult.evidence || []), ...urlEvidence],
      latency_ms: Number(textResult.latency_ms || 0) + Number(urlResult.latency_ms || 0)
    };
    renderResults(combined);
    if (metadata.tabId !== undefined) el.tabSummaryBtn.click();
  } finally {
    showLoading(false);
  }
}

function checkBackendStatus() {
  el.statusDot.className = "status-dot online";
  if (!inferenceWorker) el.engineStatusText.textContent = "Browser Heuristics";
  el.engineStatusBadge.title = "Heuristics are always available; ONNX inference is optional.";
}

function initializeInferenceWorker() {
  if (typeof chrome === "undefined" || !chrome.runtime || !chrome.runtime.connect || typeof Worker === "undefined") return;
  try {
    inferencePort = chrome.runtime.connect({ name: "url-analysis-worker" });
    inferenceWorker = new Worker(chrome.runtime.getURL("src/ml/workers/urlInferenceWorker.js"));
    inferenceWorker.onmessage = ({ data }) => {
      if (data.type === "READY") {
        inferencePort.postMessage({ type: "WORKER_STATUS", modelAvailable: data.modelAvailable });
        el.engineStatusText.textContent = data.modelAvailable ? "ONNX + Heuristics" : "Heuristics Ready";
        el.engineStatusBadge.title = data.modelAvailable
          ? "URL risk uses the packaged ONNX model and local threat heuristics."
          : "No trained ONNX model is installed; browser-side threat heuristics remain active.";
        return;
      }
      inferencePort.postMessage({
        type: "INFERENCE_RESULT",
        requestId: data.requestId,
        result: data.result,
        error: data.error
      });
    };
    inferenceWorker.onerror = () => {
      el.engineStatusText.textContent = "Heuristics Ready";
      el.engineStatusBadge.title = "ONNX worker is unavailable; browser-side threat heuristics remain active.";
      inferenceWorker.terminate();
      inferenceWorker = null;
      if (inferencePort) inferencePort.disconnect();
      inferencePort = null;
    };
    inferencePort.onDisconnect.addListener(() => {
      if (inferenceWorker) inferenceWorker.terminate();
      inferenceWorker = null;
      inferencePort = null;
    });
    inferencePort.onMessage.addListener((message) => {
      if (message.type === "INFER_URL" && inferenceWorker) inferenceWorker.postMessage(message);
    });
  } catch (error) {
    el.engineStatusText.textContent = "Heuristics Ready";
    el.engineStatusBadge.title = `ONNX worker could not start: ${error.message}`;
  }
}

function initializeEmailModelStatus() {
  if (typeof chrome === "undefined" || !chrome.runtime || !chrome.runtime.onMessage) return;
  chrome.runtime.onMessage.addListener((message) => {
    if (message.type !== "EMAIL_TEXT_MODEL_STATUS") return;
    el.engineStatusText.textContent = message.modelAvailable ? "URL + Email ONNX" : "Browser Heuristics";
    el.engineStatusBadge.title = message.modelAvailable
      ? "Email text classification uses the local ONNX model and deterministic email indicators."
      : `${message.error || "No trained email model is installed"}; email heuristics remain active.`;
  });
}

// =============================================================================
// Tab Switching
// =============================================================================
function initTabs() {
  const tabButtons  = document.querySelectorAll(".tab-btn");
  const tabContents = document.querySelectorAll(".tab-content");
  tabButtons.forEach(btn => {
    btn.addEventListener("click", () => {
      const targetId = btn.dataset.tab;
      tabButtons.forEach(b => b.classList.remove("active"));
      tabContents.forEach(c => c.classList.remove("active"));
      btn.classList.add("active");
      const target = document.getElementById(targetId);
      if (target) target.classList.add("active");
    });
  });
}

// =============================================================================
// Active Tab URL Auto-Fill
// =============================================================================
function autoFillCurrentTabUrl() {
  if (typeof chrome !== "undefined" && chrome.tabs && chrome.tabs.query) {
    chrome.tabs.query({ active: true, currentWindow: true }, tabs => {
      const url = tabs && tabs[0] && tabs[0].url;
      if (url && (url.startsWith("http://") || url.startsWith("https://"))) {
        el.urlInput.value = url;
      } else {
        el.activeEmailNotice.textContent = "The active browser tab does not have a scannable HTTP(S) URL.";
      }
    });
    return;
  }
  el.activeEmailNotice.textContent = "Current Tab requires the extension to run in Chrome.";
}

// =============================================================================
// Preset Samples
// =============================================================================
function clearEmailPageMetadata() {
  delete el.emailInput.dataset.cleanBody;
  delete el.emailInput.dataset.sender;
  delete el.emailInput.dataset.receiver;
  delete el.emailInput.dataset.cc;
  delete el.emailInput.dataset.bcc;
  delete el.emailInput.dataset.subject;
}

function initPresetButtons() {
  document.getElementById("useCurrentTabBtn").addEventListener("click", autoFillCurrentTabUrl);

  // Quick URL chip buttons
  document.querySelectorAll(".chip-btn[data-sample]").forEach(chip => {
    chip.addEventListener("click", () => {
      el.urlInput.value = chip.getAttribute("data-sample");
      el.scanUrlBtn.click();
    });
  });

  // Email presets
  // Static email samples (defined once, not re-allocated per click)
  const NETFLIX_PHISH =
`From: Netflix Billing Support <billing-notice@netflx-update-alert.xyz>
Subject: URGENT: Your Netflix membership is temporarily suspended!
To: customer@domain.com
Date: Sat, 17 Oct 2026 05:00:00

Dear Member,
We were unable to validate your billing information for the current cycle.
Your account access has been restricted.

To restore your service immediately, please verify your credentials and update your payment method within 24 hours at our secure portal:
http://netflix-billing-update.top/login.php

Failure to update your details will result in permanent cancellation of your membership.

Netflix Customer Security Team`;
  const PAYPAL_PHISH =
`From: "PayPal Service" <security-alerts@gmail.com>
Reply-To: refund-desk@paypal-dispute-resolve.com
Subject: Unauthorized transaction of $649.99 detected on your PayPal wallet

Dear Customer,
An unauthorized transaction was authorized on your account from an unrecognized IP address (192.168.1.100).
If you did not authorize this payment, you must verify your password and identity immediately:
http://paypal-verification-center.xyz/signin

PayPal Fraud Prevention Department`;
  const BENIGN_EMAIL =
`From: Sarah Jenkins <s.jenkins@trusted-enterprise.com>
Subject: Finalized Project Roadmap & Discussion Points
To: team@trusted-enterprise.com

Hi Everyone,
Following up on our sprint review, please find the updated project milestones documented on our internal wiki:
https://wiki.trusted-enterprise.com/projects/q4-roadmap

Let me know if you'd like to schedule any 1-on-1 walk-throughs before Thursday.
Best regards,
Sarah`;

  document.getElementById("loadNetflixPhishBtn").addEventListener("click", () => {
    clearEmailPageMetadata();
    el.emailInput.value = NETFLIX_PHISH;
    el.scanEmailBtn.click();
  });
  document.getElementById("loadPayPalPhishBtn").addEventListener("click", () => {
    clearEmailPageMetadata();
    el.emailInput.value = PAYPAL_PHISH;
    el.scanEmailBtn.click();
  });
  document.getElementById("loadBenignEmailBtn").addEventListener("click", () => {
    clearEmailPageMetadata();
    el.emailInput.value = BENIGN_EMAIL;
    el.scanEmailBtn.click();
  });

  // Extract from current page — captures sender, receiver, subject, clean body separately
  document.getElementById("extractFromPageBtn").addEventListener("click", () => {
    if (typeof chrome !== "undefined" && chrome.tabs && chrome.tabs.query) {
      chrome.tabs.query({ active: true, currentWindow: true }, tabs => {
        if (!tabs || !tabs[0]) {
          el.activeEmailNotice.textContent = "No active tab is available to read.";
          return;
        }

        chrome.tabs.sendMessage(tabs[0].id, { action: "extract_email_content" }, response => {
          if (chrome.runtime.lastError || !response || !response.text) {
            el.activeEmailNotice.textContent = "No email could be extracted. Open a supported webmail message and refresh the tab if the extension was just reloaded.";
            return;
          }
          const preview = [
            `From:    ${response.sender    || "(unknown)"}`,
            `To:      ${response.receiver  || "(unknown)"}`,
            `Subject: ${response.subject   || "(no subject)"}`,
            ``,
            `--- Body (URLs stripped) ---`,
            response.clean_body || response.text || "(empty)"
          ].join("\n");

          el.emailInput.value = preview;
          el.emailInput.dataset.sender    = response.sender    || "";
          el.emailInput.dataset.receiver  = response.receiver  || "";
          el.emailInput.dataset.cc        = response.cc        || "";
          el.emailInput.dataset.bcc       = response.bcc       || "";
          el.emailInput.dataset.subject   = response.subject   || "";
          el.emailInput.dataset.cleanBody = response.clean_body || "";
          el.scanEmailBtn.click();
        });
      });
    } else {
      el.activeEmailNotice.textContent = "Grab from Page requires the extension and a supported webmail tab.";
    }
  });

  // Page links scan
  document.getElementById("scanPageLinksBtn").addEventListener("click", async () => {
    // 1. Live Chrome / Edge Extension Mode
    if (typeof chrome !== "undefined" && chrome.tabs && chrome.tabs.query) {
      chrome.tabs.query({ active: true, currentWindow: true }, tabs => {
        if (!tabs || !tabs[0]) {
          runSandboxPageLinksScan();
          return;
        }

        const activeTab = tabs[0];
        const tabUrl = activeTab.url || "";

        // Check for browser-restricted system pages (chrome://, edge://, about:)
        if (tabUrl.startsWith("chrome://") || tabUrl.startsWith("edge://") || tabUrl.startsWith("about:") || tabUrl.startsWith("chrome-extension://")) {
          showLoading(false);
          alert("Browser security restricts extensions from reading internal pages (" + tabUrl.split("/")[0] + "//). Please navigate to any standard website (like GitHub, a news site, or webmail) and click scan again.");
          return;
        }

        showLoading(true);

        // Ask the page-link scanner for links before using the scripting fallback.
        chrome.tabs.sendMessage(activeTab.id, { action: "extract_page_links" }, async response => {
          if (chrome.runtime.lastError || !response || !response.links) {
            // The extension may have been installed after this tab was loaded.
            if (chrome.scripting && chrome.scripting.executeScript) {
              chrome.scripting.executeScript({
                target: { tabId: activeTab.id },
                func: () => Array.from(document.querySelectorAll("a[href]"))
                  .map(a => a.href)
                  .filter(h => h.startsWith("http://") || h.startsWith("https://"))
              }, async results => {
                showLoading(false);
                if (results && results[0] && results[0].result && results[0].result.length > 0) {
                  const uniqueLinks = [...new Set(results[0].result)].slice(0, 20);
                  showLoading(true);
                  await scanBatchLinks(uniqueLinks);
                } else {
                  alert("No HTTP(S) links detected on the active webpage: " + tabUrl);
                }
              });
            } else {
              showLoading(false);
              alert("Unable to inspect links on this tab. Please refresh the web page once and click scan again.");
            }
            return;
          }

          if (response.links && response.links.length > 0) {
            const uniqueLinks = [...new Set(response.links)].slice(0, 20);
            await scanBatchLinks(uniqueLinks);
          } else {
            showLoading(false);
            alert("No external links found on the active page.");
          }
        });
      });
    } else {
      showLoading(false);
      alert("This action requires the SafeInbox browser extension.");
    }
  });
}

// =============================================================================
// Action Button Listeners
// =============================================================================
function initActions() {
  el.scanUrlBtn.addEventListener("click", async () => {
    const rawUrl = el.urlInput.value.trim();
    if (!rawUrl) { alert("Please enter or paste a valid URL to analyze."); return; }
    showLoading(true);
    try { renderResults(await executeUrlScan(rawUrl)); }
    catch (err) { alert("Scan failed: " + err.message); }
    finally { showLoading(false); }
  });

  el.scanEmailBtn.addEventListener("click", async () => {
    const emailText = el.emailInput.value.trim();
    if (!emailText) { alert("Please paste the email content or message text to analyze."); return; }
    const urls = EmailThreatUtils.extractUrlsFromEmail(emailText);
    try { await runEmailScan(emailText, urls, {
      sender: el.emailInput.dataset.sender || "",
      receiver: el.emailInput.dataset.receiver || "",
      subject: el.emailInput.dataset.subject || "",
      bodyText: el.emailInput.dataset.cleanBody || ""
    }); }
    catch (err) { alert("Scan failed: " + err.message); }
  });
}

// =============================================================================
// Browser-Local Feedback Operations
// =============================================================================
function escapeHtml(str) {
  return String(str ?? "").replace(/[&<>"']/g, m => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
  }[m]));
}

function initFeedbackActions() {
  const btnSafe   = document.getElementById("btnFeedbackSafe");
  const btnThreat = document.getElementById("btnFeedbackThreat");

  if (btnSafe) {
    btnSafe.addEventListener("click", async () => {
      if (!lastScanResult) return;
      const targetType = lastScanResult.target_type || "URL";
      const target = targetType === "EMAIL"
        ? getEmailTrainingSample()
        : (lastScanResult.target || lastScanResult.target_raw || el.urlInput.value.trim());

      el.directFeedbackBtns.style.display = "none";
      el.directFeedbackMsg.style.display = "flex";
      el.directFeedbackMsg.className = "feedback-status-msg safe";
      el.directFeedbackMsg.textContent = "Saving your assessment in this browser...";
      const result = await submitTargetFeedback(target, true, "popup_direct", targetType);
      el.directFeedbackMsg.textContent = feedbackResultMessage(result, true);
    });
  }

  if (btnThreat) {
    btnThreat.addEventListener("click", async () => {
      if (!lastScanResult) return;
      const targetType = lastScanResult.target_type || "URL";
      const target = targetType === "EMAIL"
        ? getEmailTrainingSample()
        : (lastScanResult.target || lastScanResult.target_raw || el.urlInput.value.trim());

      el.directFeedbackBtns.style.display = "none";
      el.directFeedbackMsg.style.display = "flex";
      el.directFeedbackMsg.className = "feedback-status-msg threat";
      el.directFeedbackMsg.textContent = "Saving your assessment in this browser...";
      const result = await submitTargetFeedback(target, false, "popup_direct", targetType);
      el.directFeedbackMsg.textContent = feedbackResultMessage(result, false);
    });
  }
}

function submitTargetFeedback(target, isSafe, source, targetType = "URL") {
  if (typeof chrome !== "undefined" && chrome.storage && chrome.storage.local && typeof target === "string" && target.trim()) {
    const storageKey = targetType === "EMAIL" ? "offline_text_feedback" : "offline_url_feedback";
    return new Promise((resolve) => {
      try {
        chrome.storage.local.get([storageKey], (data) => {
          if (chrome.runtime.lastError) {
            resolve({ status: "error", message: chrome.runtime.lastError.message });
            return;
          }
          const list = Array.isArray(data[storageKey]) ? data[storageKey] : [];
          const maxTargetLength = targetType === "EMAIL" ? 20000 : 4096;
          list.push({
            target: target.trim().slice(0, maxTargetLength),
            target_truncated: target.trim().length > maxTargetLength,
            target_type: targetType === "EMAIL" ? "TEXT" : "URL",
            is_safe: isSafe,
            source,
            timestamp: Date.now()
          });
          chrome.storage.local.set({ [storageKey]: list.slice(-100) }, () => {
            if (chrome.runtime.lastError) {
              resolve({ status: "error", message: chrome.runtime.lastError.message });
              return;
            }
            // Asynchronously sync feedback to Cloud API if configured
            try {
              chrome.storage.local.get(["cloudBackendUrl", "cloudBackendEnabled", "safeinbox_auth"], (cloudSettings) => {
                if (cloudSettings && cloudSettings.cloudBackendEnabled && cloudSettings.cloudBackendUrl && typeof fetch === "function") {
                  const cloudUrl = String(cloudSettings.cloudBackendUrl).trim().replace(/\/+$/, "");
                  const isLocalhost = /^https?:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/i.test(cloudUrl);
                  if (!cloudUrl.startsWith("https://") && !isLocalhost) return;
                  const reqHeaders = { "Content-Type": "application/json" };
                  if (cloudSettings.safeinbox_auth && cloudSettings.safeinbox_auth.token) {
                    reqHeaders["Authorization"] = `Bearer ${cloudSettings.safeinbox_auth.token}`;
                  }
                  fetch(`${cloudUrl}/api/v1/feedback`, {
                    method: "POST",
                    headers: reqHeaders,
                    body: JSON.stringify({
                      target: target.trim().slice(0, 4096),
                      target_type: targetType === "EMAIL" ? "TEXT" : "URL",
                      is_safe: isSafe,
                      source: source || "sidepanel"
                    })
                  }).catch(() => {});
                }
              });
            } catch {
              // Non-blocking
            }
            resolve({ status: "saved_locally", is_safe: isSafe });
          });
        });
      } catch (error) {
        resolve({ status: "error", message: error.message || "Browser storage is unavailable." });
      }
    });
  }
  return Promise.resolve({
    status: "error",
    message: typeof target !== "string" || !target.trim()
      ? "No feedback sample was available to save."
      : "Browser storage is unavailable; feedback could not be saved."
  });
}

function feedbackResultMessage(result, isSafe) {
  const label = isSafe ? "Confirmed Safe" : "Flagged as Threat";
  if (result.status === "saved_locally") {
    return `✓ ${label} (Saved in this browser for future training; the current model was not retrained)`;
  }
  return `Feedback not saved: ${result.message || "Unknown error."}`;
}

function initCloudPanel() {
  if (!el.cloudPanelHeader || !el.cloudPanelBody) return;

  el.cloudPanelHeader.addEventListener("click", () => {
    const isHidden = el.cloudPanelBody.style.display === "none";
    el.cloudPanelBody.style.display = isHidden ? "block" : "none";
    el.cloudPanelHeader.setAttribute("aria-expanded", isHidden ? "true" : "false");
  });

  if (typeof chrome !== "undefined" && chrome.storage && chrome.storage.local) {
    chrome.storage.local.get(["cloudBackendUrl", "cloudBackendEnabled"], (data) => {
      if (data && data.cloudBackendUrl) {
        if (el.cloudBackendUrlInput) el.cloudBackendUrlInput.value = data.cloudBackendUrl;
        if (data.cloudBackendEnabled) {
          if (el.cloudBadge) {
            el.cloudBadge.textContent = "Cloud Active";
            el.cloudBadge.className = "cloud-badge online";
          }
          if (el.cloudStatusMsg) {
            el.cloudStatusMsg.textContent = "Global IOC sync active with " + data.cloudBackendUrl;
          }
        }
      }
    });
  }

  if (el.btnConnectCloud && el.cloudBackendUrlInput) {
    el.btnConnectCloud.addEventListener("click", async () => {
      const url = el.cloudBackendUrlInput.value.trim();
      if (!url) {
        if (typeof chrome !== "undefined" && chrome.storage && chrome.storage.local) {
          chrome.storage.local.set({ cloudBackendEnabled: false, cloudBackendUrl: "" });
        }
        if (el.cloudBadge) {
          el.cloudBadge.textContent = "Local Only";
          el.cloudBadge.className = "cloud-badge";
        }
        if (el.cloudStatusMsg) {
          el.cloudStatusMsg.textContent = "Operating in local heuristics mode.";
        }
        return;
      }

      if (!/^https?:\/\//i.test(url)) {
        if (el.cloudStatusMsg) el.cloudStatusMsg.textContent = "URL must start with http:// or https://";
        return;
      }

      const isLocalhost = /^https?:\/\/(localhost|127\.0\.0\.1)(:\d+)?(\/|$)/i.test(url);
      if (!url.startsWith("https://") && !isLocalhost) {
        if (el.cloudStatusMsg) el.cloudStatusMsg.textContent = "Security violation: Remote backend must use HTTPS over TCP. Unencrypted HTTP is blocked.";
        if (el.cloudBadge) {
          el.cloudBadge.textContent = "HTTPS Required";
          el.cloudBadge.className = "cloud-badge error";
        }
        return;
      }

      if (el.cloudStatusMsg) el.cloudStatusMsg.textContent = "Connecting to backend...";
      try {
        let status = null;
        if (typeof chrome !== "undefined" && chrome.runtime && chrome.runtime.sendMessage) {
          const resp = await chrome.runtime.sendMessage({ type: "TEST_CLOUD_BACKEND", url });
          if (!resp || !resp.ok) throw new Error(resp && resp.error ? resp.error : "Failed to connect.");
          status = resp.status;
        } else if (typeof fetch === "function") {
          const resp = await fetch(`${url.replace(/\/+$/, "")}/health`);
          if (!resp.ok) throw new Error("Server returned HTTP " + resp.status);
          const data = await resp.json();
          status = { online: true, latencyMs: 50, version: data.version, project: data.project };
        } else {
          throw new Error("Network capability unavailable.");
        }

        if (typeof chrome !== "undefined" && chrome.storage && chrome.storage.local) {
          chrome.storage.local.set({ cloudBackendEnabled: true, cloudBackendUrl: url });
        }
        if (el.cloudBadge) {
          el.cloudBadge.textContent = `Online (${status.latencyMs}ms)`;
          el.cloudBadge.className = "cloud-badge online";
        }
        if (el.cloudStatusMsg) {
          el.cloudStatusMsg.textContent = `✓ Connected to ${status.project || "SafeInbox API"} (v${status.version || "1.0.0"}). Global IOC intelligence enabled.`;
        }
      } catch (err) {
        if (el.cloudBadge) {
          el.cloudBadge.textContent = "Offline";
          el.cloudBadge.className = "cloud-badge error";
        }
        if (el.cloudStatusMsg) {
          el.cloudStatusMsg.textContent = `Connection failed: ${err.message}. Local heuristics remain active.`;
        }
      }
    });
  }
}

function initMailClicksTracker() {
  if (!el.mailClicksPanel || !el.mailClicksHeader || !el.mailClicksBody) return;

  el.mailClicksHeader.addEventListener("click", () => {
    const isHidden = el.mailClicksBody.style.display === "none";
    el.mailClicksBody.style.display = isHidden ? "block" : "none";
    el.mailClicksHeader.setAttribute("aria-expanded", String(isHidden));
    if (isHidden) refreshMailClicks();
  });

  if (el.btnClearMailClicks) {
    el.btnClearMailClicks.addEventListener("click", () => {
      if (typeof chrome !== "undefined" && chrome.storage && chrome.storage.local) {
        chrome.storage.local.set({ webmail_url_clicks: [] }, () => {
          renderMailClicks([]);
        });
      }
    });
  }

  if (typeof chrome !== "undefined" && chrome.storage && chrome.storage.onChanged) {
    chrome.storage.onChanged.addListener((changes, area) => {
      if (area === "local" && changes.webmail_url_clicks) {
        renderMailClicks(changes.webmail_url_clicks.newValue || []);
      }
    });
  }

  refreshMailClicks();
}

function refreshMailClicks() {
  if (typeof chrome === "undefined" || !chrome.storage || !chrome.storage.local) {
    renderMailClicks([]);
    return;
  }
  try {
    chrome.storage.local.get(["webmail_url_clicks"], (res) => {
      const list = Array.isArray(res && res.webmail_url_clicks) ? res.webmail_url_clicks : [];
      renderMailClicks(list);
    });
  } catch {
    renderMailClicks([]);
  }
}

function renderMailClicks(clicks) {
  if (!el.mailClicksCountBadge || !el.mailClicksList) return;
  const list = Array.isArray(clicks) ? clicks : [];
  const count = list.length;
  el.mailClicksCountBadge.textContent = `${count} Click${count === 1 ? "" : "s"}`;

  if (count === 0) {
    el.mailClicksList.innerHTML = `<div class="mail-clicks-empty">No email link clicks recorded yet.</div>`;
    return;
  }

  const fragment = document.createDocumentFragment();
  const reversed = list.slice().reverse();
  reversed.forEach(c => {
    const item = document.createElement("div");
    const isThreat = (c.risk_score >= 50) || c.risk_level === "CRITICAL" || c.risk_level === "HIGH";
    item.className = `mail-click-item ${isThreat ? "threat" : "safe"}`;

    const dateStr = c.timestamp ? new Date(c.timestamp).toLocaleString() : (c.date_iso || "--");
    const badgeText = `${c.risk_level || "AUDITED"} • ${c.risk_score || 0}/100`;
    const actionStatus = c.proceeded ? "Navigated" : "Blocked / Aborted";
    const srcTag = c.source === "url_security_banner" ? "Banner Link" : c.source === "flagged_email_link" ? "Flagged Link" : "Email Link";

    item.innerHTML = `
      <div class="mail-click-top">
        <span class="mail-click-url" title="${escapeHtml(c.url)}">${escapeHtml(c.defanged || c.url)}</span>
        <span class="mail-click-badge ${isThreat ? "threat" : "safe"}">${escapeHtml(badgeText)}</span>
      </div>
      <div class="mail-click-meta">
        <span>${escapeHtml(srcTag)} • ${escapeHtml(actionStatus)}</span>
        <span>${escapeHtml(dateStr)}</span>
      </div>
      ${c.email_subject ? `<div class="mail-click-meta" style="margin-top:3px;font-style:italic;"><span>Subject: ${escapeHtml(c.email_subject.slice(0, 60))}</span></div>` : ""}
    `;
    fragment.appendChild(item);
  });

  el.mailClicksList.innerHTML = "";
  el.mailClicksList.appendChild(fragment);
}

// =============================================================================
// User Account & Authentication Manager (Sign In / Sign Up)
// =============================================================================
function getBackendBaseUrl() {
  const fromInput = el.cloudBackendUrlInput && el.cloudBackendUrlInput.value ? el.cloudBackendUrlInput.value.trim() : "";
  if (fromInput) return fromInput.replace(/\/+$/, "");
  return "http://localhost:8080";
}

function showAuthModal(initialTab) {
  if (!el.authModalBackdrop) return;
  el.authModalBackdrop.style.display = "flex";
  if (initialTab === "signup") {
    switchAuthTab("signup");
  } else {
    switchAuthTab("signin");
  }
}

function closeAuthModal() {
  if (!el.authModalBackdrop) return;
  el.authModalBackdrop.style.display = "none";
  if (el.authSignInStatus) {
    el.authSignInStatus.style.display = "none";
    el.authSignInStatus.textContent = "";
  }
  if (el.authSignUpStatus) {
    el.authSignUpStatus.style.display = "none";
    el.authSignUpStatus.textContent = "";
  }
}

function switchAuthTab(tab) {
  if (tab === "signup") {
    if (el.authTabSignUpBtn) el.authTabSignUpBtn.classList.add("active");
    if (el.authTabSignInBtn) el.authTabSignInBtn.classList.remove("active");
    if (el.authSignUpForm) el.authSignUpForm.style.display = "flex";
    if (el.authSignInForm) el.authSignInForm.style.display = "none";
  } else {
    if (el.authTabSignInBtn) el.authTabSignInBtn.classList.add("active");
    if (el.authTabSignUpBtn) el.authTabSignUpBtn.classList.remove("active");
    if (el.authSignInForm) el.authSignInForm.style.display = "flex";
    if (el.authSignUpForm) el.authSignUpForm.style.display = "none";
  }
}

function setAuthStatus(targetEl, msg, type) {
  if (!targetEl) return;
  targetEl.textContent = msg;
  targetEl.className = `auth-status-msg ${type}`;
  targetEl.style.display = "block";
}

async function saveAuthSession(token, user) {
  if (typeof chrome !== "undefined" && chrome.storage && chrome.storage.local) {
    await chrome.storage.local.set({
      safeinbox_auth: { token, user, saved_at: Date.now() },
      cloudBackendEnabled: true
    });
  }
  refreshAuthState();
}

async function clearAuthSession() {
  if (typeof chrome !== "undefined" && chrome.storage && chrome.storage.local) {
    await chrome.storage.local.remove(["safeinbox_auth"]);
  }
  if (el.authSignInForm) el.authSignInForm.reset();
  if (el.authSignUpForm) el.authSignUpForm.reset();
  if (el.authSignInEmail) el.authSignInEmail.value = "";
  if (el.authSignInPassword) el.authSignInPassword.value = "";
  if (el.authSignUpName) el.authSignUpName.value = "";
  if (el.authSignUpEmail) el.authSignUpEmail.value = "";
  if (el.authSignUpPassword) el.authSignUpPassword.value = "";
  if (el.authSignUpConfirmPassword) el.authSignUpConfirmPassword.value = "";
  if (el.authSignInStatus) el.authSignInStatus.style.display = "none";
  if (el.authSignUpStatus) el.authSignUpStatus.style.display = "none";
  refreshAuthState();
}


function refreshAuthState() {
  if (typeof chrome === "undefined" || !chrome.storage || !chrome.storage.local) {
    renderAuthUI(null);
    return;
  }
  try {
    chrome.storage.local.get(["safeinbox_auth"], (res) => {
      const auth = res && res.safeinbox_auth;
      renderAuthUI(auth);
    });
  } catch {
    renderAuthUI(null);
  }
}

function renderAuthUI(auth) {
  const isSignedIn = Boolean(auth && auth.token && auth.user);
  const user = isSignedIn ? auth.user : null;

  if (isSignedIn && user) {
    const displayName = user.full_name || (user.email ? user.email.split("@")[0] : "Analyst");
    if (el.accountPillLabel) el.accountPillLabel.textContent = displayName;
    if (el.accountPillBtn) {
      el.accountPillBtn.classList.add("signed-in");
      el.accountPillBtn.title = `Signed in as ${user.email}`;
    }
    if (el.cloudAccountStatus) el.cloudAccountStatus.textContent = `Signed in: ${user.email}`;
    if (el.btnCloudAccountAction) el.btnCloudAccountAction.textContent = "Account Profile";

    if (el.authSignedOutView) el.authSignedOutView.style.display = "none";
    if (el.authSignedInView) el.authSignedInView.style.display = "block";
    if (el.authProfileName) el.authProfileName.textContent = user.full_name || "Analyst";
    if (el.authProfileEmail) el.authProfileEmail.textContent = user.email;
  } else {
    if (el.accountPillLabel) el.accountPillLabel.textContent = "Sign In";
    if (el.accountPillBtn) {
      el.accountPillBtn.classList.remove("signed-in");
      el.accountPillBtn.title = "Sign In or Sign Up";
    }
    if (el.cloudAccountStatus) el.cloudAccountStatus.textContent = "Guest Mode (Local Only)";
    if (el.btnCloudAccountAction) el.btnCloudAccountAction.textContent = "Sign In / Sign Up";

    if (el.authSignedOutView) el.authSignedOutView.style.display = "block";
    if (el.authSignedInView) el.authSignedInView.style.display = "none";
  }
}

function initAuthManager() {
  if (!el.authModalBackdrop) return;

  // Header pill opens modal
  if (el.accountPillBtn) {
    el.accountPillBtn.addEventListener("click", () => showAuthModal("signin"));
  }

  // Cloud panel button opens modal
  if (el.btnCloudAccountAction) {
    el.btnCloudAccountAction.addEventListener("click", () => showAuthModal("signin"));
  }

  // Modal close button
  if (el.authModalClose) {
    el.authModalClose.addEventListener("click", closeAuthModal);
  }

  // Open Welcome & Guide page
  if (el.linkOpenWelcome) {
    el.linkOpenWelcome.addEventListener("click", (e) => {
      e.preventDefault();
      if (typeof chrome !== "undefined" && chrome.tabs && chrome.tabs.create) {
        chrome.tabs.create({ url: chrome.runtime.getURL("welcome.html") });
      } else {
        window.open("welcome.html", "_blank");
      }
    });
  }

  // Close on clicking backdrop
  el.authModalBackdrop.addEventListener("click", (e) => {
    if (e.target === el.authModalBackdrop) closeAuthModal();
  });

  // Tab buttons
  if (el.authTabSignInBtn) {
    el.authTabSignInBtn.addEventListener("click", () => switchAuthTab("signin"));
  }
  if (el.authTabSignUpBtn) {
    el.authTabSignUpBtn.addEventListener("click", () => switchAuthTab("signup"));
  }
  if (el.authLinkToSignUp) {
    el.authLinkToSignUp.addEventListener("click", (e) => {
      e.preventDefault();
      switchAuthTab("signup");
    });
  }
  if (el.authLinkToSignIn) {
    el.authLinkToSignIn.addEventListener("click", (e) => {
      e.preventDefault();
      switchAuthTab("signin");
    });
  }

  // Sign In Form submission
  if (el.authSignInForm) {
    el.authSignInForm.addEventListener("submit", async (e) => {
      e.preventDefault();
      const email = el.authSignInEmail ? el.authSignInEmail.value.trim().toLowerCase() : "";
      const password = el.authSignInPassword ? el.authSignInPassword.value : "";
      if (!email || !password) return;

      setAuthStatus(el.authSignInStatus, "Signing in...", "info");
      if (el.btnSubmitSignIn) el.btnSubmitSignIn.disabled = true;

      try {
        const baseUrl = getBackendBaseUrl();
        const resp = await fetch(`${baseUrl}/api/v1/auth/signin`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ email, password })
        });

        const data = await resp.json().catch(() => ({}));
        if (!resp.ok) {
          throw new Error(data.detail || `Invalid email or password.`);
        }

        await saveAuthSession(data.access_token, data.user);

        // Wipe inputs immediately so no data lingers in login section
        el.authSignInForm.reset();
        if (el.authSignInEmail) el.authSignInEmail.value = "";
        if (el.authSignInPassword) el.authSignInPassword.value = "";

        setAuthStatus(el.authSignInStatus, "✓ Signed in successfully!", "success");
        setTimeout(closeAuthModal, 600);
      } catch (err) {
        setAuthStatus(el.authSignInStatus, err.message || "Invalid email or password.", "error");
      } finally {
        if (el.btnSubmitSignIn) el.btnSubmitSignIn.disabled = false;
      }
    });
  }

  // Sign Up Form submission
  if (el.authSignUpForm) {
    el.authSignUpForm.addEventListener("submit", async (e) => {
      e.preventDefault();
      const fullName = el.authSignUpName ? el.authSignUpName.value.trim() : "";
      const email = el.authSignUpEmail ? el.authSignUpEmail.value.trim().toLowerCase() : "";
      const password = el.authSignUpPassword ? el.authSignUpPassword.value : "";
      const confirmPassword = el.authSignUpConfirmPassword ? el.authSignUpConfirmPassword.value : "";

      if (!email || !password) return;
      if (password.length < 8) {
        setAuthStatus(el.authSignUpStatus, "Password must be at least 8 characters long.", "error");
        return;
      }
      if (password !== confirmPassword) {
        setAuthStatus(el.authSignUpStatus, "Passwords do not match.", "error");
        return;
      }

      setAuthStatus(el.authSignUpStatus, "Creating account...", "info");
      if (el.btnSubmitSignUp) el.btnSubmitSignUp.disabled = true;

      try {
        const baseUrl = getBackendBaseUrl();
        const resp = await fetch(`${baseUrl}/api/v1/auth/signup`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ email, password, full_name: fullName || null })
        });

        const data = await resp.json().catch(() => ({}));
        if (!resp.ok) {
          throw new Error(data.detail || `Sign up failed (HTTP ${resp.status})`);
        }

        await saveAuthSession(data.access_token, data.user);

        // Wipe inputs immediately so no data lingers in signup section
        el.authSignUpForm.reset();
        if (el.authSignUpName) el.authSignUpName.value = "";
        if (el.authSignUpEmail) el.authSignUpEmail.value = "";
        if (el.authSignUpPassword) el.authSignUpPassword.value = "";
        if (el.authSignUpConfirmPassword) el.authSignUpConfirmPassword.value = "";

        setAuthStatus(el.authSignUpStatus, "✓ Account created successfully!", "success");
        setTimeout(closeAuthModal, 600);
      } catch (err) {
        setAuthStatus(el.authSignUpStatus, err.message || "Failed to create account.", "error");
      } finally {
        if (el.btnSubmitSignUp) el.btnSubmitSignUp.disabled = false;
      }
    });
  }


  // Sign Out button
  if (el.btnSubmitSignOut) {
    el.btnSubmitSignOut.addEventListener("click", async () => {
      await clearAuthSession();
      closeAuthModal();
    });
  }

  // Sync across tabs
  if (typeof chrome !== "undefined" && chrome.storage && chrome.storage.onChanged) {
    chrome.storage.onChanged.addListener((changes, area) => {
      if (area === "local" && changes.safeinbox_auth) {
        refreshAuthState();
      }
    });
  }

  // Initial load
  refreshAuthState();
}

function calculateEmailRiskAverage(textRisk, urlScores) {
  const textScore = Math.max(0, Math.min(100, Math.round(Number(textRisk) || 0)));
  const scores = (Array.isArray(urlScores) ? urlScores : [])
    .map((score) => Math.max(0, Math.min(100, Math.round(Number(score) || 0))))
    .filter(Number.isFinite);
  if (!scores.length) return { textScore, urlAverage: null, urlHighest: null, combined: textScore };
  const urlAverage = Math.round(scores.reduce((sum, score) => sum + score, 0) / scores.length);
  return {
    textScore,
    urlAverage,
    urlHighest: Math.max(...scores),
    combined: Math.round((textScore + urlAverage) / 2)
  };
}

function getEmailTrainingSample() {
  const emailInput = el.emailInput;
  const cleanBody = emailInput.dataset.cleanBody;
  if (cleanBody) return cleanBody.trim();

  const rawText = emailInput.value.trim();
  const headerBlock = rawText.match(/^(?:(?:from|to|subject|date|reply-to|cc|delivered-to|mime-[^:]+):[^\r\n]*[\r\n]+)+/i);
  const body = headerBlock ? rawText.slice(headerBlock[0].length).trim() : rawText;
  return body
    .replace(/https?:\/\/[^\s"'<>]+/gi, " ")
    .replace(/www\.[^\s"'<>]{3,}/gi, " ")
    .replace(/[ \t]{2,}/g, " ")
    .trim();
}


// =============================================================================
// Client-Side Scan Execution
// =============================================================================
async function executeUrlScan(url) {
  if (typeof chrome !== "undefined" && chrome.runtime && chrome.runtime.sendMessage) {
    try {
      const response = await chrome.runtime.sendMessage({ type: "ANALYZE_URL", url });
      if (!response || !response.ok) {
        throw new Error(response && response.error ? response.error : "URL analysis failed.");
      }
      return adaptUrlThreatResult(response.result);
    } catch (error) {
      if (/Only HTTP and HTTPS|Enter a URL|could not be parsed/.test(error.message)) throw error;
      el.engineStatusText.textContent = "Local Heuristic Fallback";
      el.engineStatusBadge.title = `Background scan unavailable; using local heuristics: ${error.message}`;
      const localResult = clientScanUrl(url);
      localResult.summary += " The background worker was unavailable; local heuristic scanning was used.";
      return localResult;
    }
  }
  return clientScanUrl(url);
}

function adaptUrlThreatResult(result) {
  const score = Math.round(result.riskScore * 100);
  return {
    target_type: "URL",
    target: result.inputUrl,
    defanged_target: defangUrl(result.inputUrl),
    hostname: result.hostname,
    risk_level: score >= 80 ? "CRITICAL" : score >= 60 ? "HIGH" : score >= 35 ? "MEDIUM" : score >= 15 ? "LOW" : "SAFE",
    risk_score: score,
    summary: result.attackTypes.length
      ? `Detected indicators: ${result.attackTypes.join(", ")}.`
      : "No configured URL threat indicators were detected.",
    analysis_note: result.modelAvailable
      ? "ONNX inference and heuristic signals were used."
      : result.analysisWarning || result.modelError || "Heuristic-only result; no trained ONNX model was available.",
    recommended_action: score >= 60
      ? "Do not open this URL or enter credentials unless you can independently verify its destination."
      : "Treat this heuristic assessment as one signal, not a guarantee of safety.",
    claimed_brand: result.matchedBrand,
    model_available: result.modelAvailable,
    attack_types: result.attackTypes,
    evidence: result.findings.map((finding) => ({
      rule_id: finding.attackType,
      severity: finding.penalty >= 0.5 ? "CRITICAL" : finding.penalty >= 0.3 ? "HIGH" : "MEDIUM",
      evidence: `${finding.title}: ${finding.detail}`,
      remediation: "Verify the destination independently before continuing."
    })),
    latency_ms: 0
  };
}

async function executeEmailScan(text) {
  const inp       = el.emailInput;
  let sender    = inp ? (inp.dataset.sender    || "") : "";
  let receiver  = inp ? (inp.dataset.receiver  || "") : "";
  let cc        = inp ? (inp.dataset.cc        || "") : "";
  let bcc       = inp ? (inp.dataset.bcc       || "") : "";
  let subject   = inp ? (inp.dataset.subject   || "") : "";
  const cleanBody = inp ? (inp.dataset.cleanBody || "") : "";

  // Automatically extract From/To/Subject if headers are in raw text
  if (!sender) {
    const fromMatch = text.match(/From:\s*([^\n\r]+)/i);
    if (fromMatch) sender = fromMatch[1].trim();
  }
  if (!receiver) {
    const toMatch = text.match(/To:\s*([^\n\r]+)/i);
    if (toMatch) receiver = toMatch[1].trim();
  }
  if (!subject) {
    const subMatch = text.match(/Subject:\s*([^\n\r]+)/i);
    if (subMatch) subject = subMatch[1].trim();
  }
  if (!bcc) {
    const bccMatch = text.match(/Bcc:\s*([^\n\r]+)/i);
    if (bccMatch) bcc = bccMatch[1].trim();
  }
  if (!cc) {
    const ccMatch = text.match(/^Cc:\s*([^\n\r]+)/im);
    if (ccMatch) cc = ccMatch[1].trim();
  }

  // Strip URLs from manually pasted text before analyzing the message body.
  const cleanedText = (cleanBody || text)
    .replace(/https?:\/\/[^\s"'>]+/gi, "")
    .replace(/www\.[^\s"'>]{3,}/gi, "")
    .replace(/[ \t]{2,}/g, " ")
    .replace(/\n{3,}/g, "\n\n")
    .trim();

  const analysisInput = {
    text: text || cleanedText,
    body: cleanBody || text,
    sender,
    receiver,
    cc,
    bcc,
    subject
  };
  let result;
  try {
    const response = await chrome.runtime.sendMessage({ type: "ANALYZE_EMAIL_TEXT", email: analysisInput });
    if (!response || !response.ok) throw new Error(response && response.error ? response.error : "Email analysis service did not respond.");
    result = response.result;
  } catch (error) {
    console.warn("SafeInbox AI email analysis used local heuristics:", error.message);
    result = clientScanEmail([sender, receiver, subject, cleanedText || text].filter(Boolean).join("\n"));
    result.analysis_note = `Background text inference was unavailable; local heuristics were used: ${error.message}`;
  }
  return result;
}

// =============================================================================
// Batch Page-Link Scanner (sequential with live progress)
// =============================================================================
async function scanBatchLinks(links) {
  showLoading(false);
  el.linksTitle.textContent = "Current Page URLs";
  el.resultsContainer.style.display = "flex";

  el.linksCard.style.display = "flex";
  el.linksList.innerHTML = "";
  el.linksCount.textContent = links.length;

  el.directFeedbackCard.style.display = "none";
  el.companyIntelCard.style.display   = "none";

  el.scanProgressContainer.style.display = "flex";
  el.scanProgressFill.style.width = "0%";

  el.riskScoreValue.textContent = "–";
  el.riskLevelBadge.textContent = "SCANNING";
  el.riskLevelBadge.className   = "risk-badge medium";
  el.verdictTitle.textContent   = `Scanning ${links.length} Link${links.length !== 1 ? "s" : ""}…`;
  el.verdictSummary.textContent = "Inspecting every destination URL one by one; ONNX inference is used when a trained model is available…";
  el.latencyBadge.textContent   = `0 / ${links.length}`;

  const CIRCUMFERENCE = GAUGE_CIRCUMFERENCE;

  let maxScore = 0;
  let totalScore = 0;
  const linkCards = [];

  for (let i = 0; i < links.length; i++) {
    const url = links[i];

    const pct = Math.round((i / links.length) * 100);
    el.scanProgressFill.style.width = `${pct}%`;
    el.scanProgressText.textContent = `Scanning URL ${i + 1} of ${links.length} …`;
    el.latencyBadge.textContent     = `${i} / ${links.length}`;

    const placeholder = document.createElement("div");
    placeholder.className = "link-item scanning";
    placeholder.id        = `linkCard_${i}`;
    const shortUrl = defangUrl(url).substring(0, 65) + (url.length > 65 ? "…" : "");
    placeholder.innerHTML = `
      <div class="link-item-top">
        <span class="link-defanged" style="color:var(--text-muted);">
          <span class="link-spinner-dot"></span>${escapeHtml(shortUrl)}
        </span>
        <span class="link-score-badge" style="background:rgba(6,182,212,0.12);color:#06b6d4;">Scanning…</span>
      </div>`;
    el.linksList.appendChild(placeholder);
    placeholder.scrollIntoView({ behavior: "smooth", block: "nearest" });

    // ── (C) Perform the actual scan (awaited) ────────────────────────────
    const res        = await executeUrlScan(url);
    const riskScore  = res.risk_score || 0;
    totalScore += riskScore;
    if (riskScore > maxScore) maxScore = riskScore;
    const avgScoreSoFar = Math.round(totalScore / (i + 1));

    const defanged   = defangUrl(url);
    const evidences  = res.evidence || [];
    const isHigh     = riskScore >= 50;
    const isMedium   = riskScore >= 25 && riskScore < 50;
    const hasSignals = evidences.length > 0;
    const badgeClass = isHigh ? "high" : (isMedium || hasSignals ? "warning" : "safe");
    const badgeLabel = isHigh ? "THREAT" : (isMedium ? "SUSPICIOUS" : (hasSignals ? "SIGNAL" : "NO SIGNALS"));

    linkCards.push({
      url, defanged,
      risk_score: (riskScore / 100).toFixed(2),
      risk_level: res.risk_level,
      rule_triggers: evidences.length,
      evidence: evidences,
      model_available: Boolean(res.model_available),
      analysis_note: res.analysis_note || ""
    });

    // ── (D) Replace placeholder with full result + feedback card ─────────
    const card = document.getElementById(`linkCard_${i}`);
    if (card) {
      card.className   = `link-item ${badgeClass}`;
      card.style.animation = "none";               // stop the pulse
      const topEvidence = evidences[0];
      card.innerHTML = `
        <div class="link-item-top">
          <span class="link-defanged" title="${escapeHtml(url)}">${escapeHtml(defanged)}</span>
          <span class="link-score-badge ${badgeClass}">${badgeLabel} · ${riskScore}/100</span>
        </div>
          <div class="link-evidence-text">${res.model_available ? "ONNX + heuristic analysis" : "Heuristic-only analysis; no trained model available"}</div>
        ${topEvidence
          ? `<div class="link-evidence-text">⚠ ${escapeHtml(topEvidence.evidence || "Threat indicators detected")}</div>`
          : `<div class="link-evidence-text safe-ev">✓ No threat indicators found</div>`}
        <div class="link-feedback-row">
          <span class="link-fb-prompt">Was this URL safe?</span>
          <div class="link-fb-buttons" id="popupLinkFb_${i}">
            <button class="link-fb-btn safe"
              data-url="${escapeHtml(url)}" data-safe="true" data-idx="${i}">✅ Safe</button>
            <button class="link-fb-btn threat"
              data-url="${escapeHtml(url)}" data-safe="false" data-idx="${i}">❌ Threat</button>
          </div>
        </div>`;

      // Wire up feedback buttons immediately for this card
      card.querySelectorAll(".link-fb-btn").forEach(btn => {
        btn.addEventListener("click", async (e) => {
          e.preventDefault();
          const u      = btn.getAttribute("data-url");
          const isSafe = btn.getAttribute("data-safe") === "true";
          const idx    = btn.getAttribute("data-idx");
          const box    = document.getElementById(`popupLinkFb_${idx}`);
          if (box) box.innerHTML = `<span style="font-size:9.5px;color:var(--text-muted);">Saving locally…</span>`;
          const feedback = await submitTargetFeedback(u, isSafe, "popup_batch_links");
          if (box) box.innerHTML = `<span class="link-fb-confirmed ${isSafe ? "safe" : "threat"}">${escapeHtml(feedbackResultMessage(feedback, isSafe))}</span>`;
        });
      });
    }

    const curLevel = avgScoreSoFar >= 80 ? "CRITICAL" : (avgScoreSoFar >= 50 ? "HIGH" : (avgScoreSoFar >= 25 ? "MEDIUM" : "SAFE"));
    el.riskScoreValue.textContent = avgScoreSoFar;
    el.riskLevelBadge.textContent = curLevel;
    el.riskLevelBadge.className   = `risk-badge ${curLevel.toLowerCase()}`;
    el.latencyBadge.textContent   = `${i + 1} / ${links.length}`;
    el.verdictTitle.textContent   = `Scanned ${i + 1} of ${links.length} links…`;
    el.gaugeBar.style.strokeDashoffset = CIRCUMFERENCE - (avgScoreSoFar / 100) * CIRCUMFERENCE;
    el.gaugeBar.style.stroke = avgScoreSoFar >= 80 ? "var(--danger-crimson)"
                             : avgScoreSoFar >= 50 ? "#ea580c"
                             : avgScoreSoFar >= 25 ? "var(--warning-amber)"
                             : "var(--safe-green)";
  }

  el.scanProgressFill.style.width = "100%";
  el.scanProgressText.textContent = `✓ All ${links.length} links scanned`;
  setTimeout(() => { el.scanProgressContainer.style.display = "none"; }, 2800);

  // ── Build composite result for the audit log with AVERAGE score ────────
  const avgScore = links.length > 0 ? Math.round(totalScore / links.length) : 0;
  const flagged = linkCards.filter(l => parseFloat(l.risk_score) >= 0.5);
  const compositeResult = {
    target_type: "WEBPAGE_LINKS",
    risk_level: avgScore >= 80 ? "CRITICAL" : (avgScore >= 50 ? "HIGH" : (avgScore >= 25 ? "MEDIUM" : "SAFE")),
    risk_score: avgScore,
    summary: `${links.length} links scanned one-by-one. Average risk score: ${avgScore}/100. ${flagged.length} suspicious.`,
    recommended_action: avgScore >= 50 || flagged.length > 0
      ? "Suspicious links detected — do NOT click highlighted destinations."
      : `No configured indicators were detected in ${links.length} scanned link${links.length === 1 ? "" : "s"}. Heuristic checks do not verify a destination as safe.`,
    urls_analyzed: linkCards,
    extracted_urls_count: links.length,
    evidence: flagged.map(l => ({
      rule_id: "PAGE_LINK_ALERT", severity: "HIGH",
      indicator: "suspicious_destination",
      evidence: `'${l.defanged}' flagged at score ${(parseFloat(l.risk_score)*100).toFixed(0)}/100`
    })),
    latency_ms: (links.length * 12).toFixed(1)
  };
  lastScanResult = compositeResult;

  const finalLevel = compositeResult.risk_level;
  el.verdictTitle.textContent = finalLevel === "CRITICAL" ? "Severe Threat Detected"
                              : finalLevel === "HIGH" ? "High Risk Detected"
                              : finalLevel === "MEDIUM" ? "Suspicious Signals"
                              : `All ${links.length} Links Verified Safe`;
  el.verdictSummary.textContent = compositeResult.summary;
  el.latencyBadge.textContent   = `${links.length} links`;
  el.remediationText.textContent = compositeResult.recommended_action;
  el.remediationCard.className   = avgScore >= 50 ? "remediation-card critical" : "remediation-card";

  const evs = compositeResult.evidence || [];
  el.evidenceCount.textContent = evs.length;
  el.evidenceList.innerHTML = "";
  if (evs.length === 0) {
    el.evidenceList.innerHTML = `<div class="evidence-item" style="border-left-color:var(--safe-green);">
      <div class="evidence-text">No threat patterns triggered across all ${links.length} scanned links.</div></div>`;
  } else {
    const frag = document.createDocumentFragment();
    evs.forEach(f => {
      const div = document.createElement("div");
      div.className = "evidence-item high";
      div.innerHTML = `
        <div class="evidence-item-top">
          <span class="evidence-rule-id">${f.rule_id}</span>
          <span class="evidence-severity high">HIGH</span>
        </div>
        <div class="evidence-text">${escapeHtml(f.evidence)}</div>`;
      frag.appendChild(div);
    });
    el.evidenceList.appendChild(frag);
  }

  if (el.auditReportBox) el.auditReportBox.textContent = JSON.stringify(compositeResult, null, 2);
  return compositeResult;
}


// =============================================================================
// Pre-compiled RegExps & constants (module-level — compiled once, reused on every scan)
// =============================================================================
const GAUGE_CIRCUMFERENCE = 2 * Math.PI * 42; // 263.89 — computed once

// =============================================================================
// Client-Side Fallback Engine
// =============================================================================
function defangUrl(url) {
  return url.replace(/\./g, "[.]").replace(/http:\/\//gi, "hxxp://").replace(/https:\/\//gi, "hxxps://");
}

function clientScanUrl(rawUrl) {
  const t0 = performance.now();
  const parsed = UrlThreatParser.analyzeUrl(rawUrl);
  const result = adaptUrlThreatResult({
    ...parsed,
    riskScore: parsed.heuristicRisk,
    modelAvailable: false
  });
  result.latency_ms = Math.round(performance.now() - t0);
  return result;
}

function clientScanEmail(text) {
  const t0 = performance.now();
  const result = EmailTextAnalyzer.analyzeEmailText({ text });
  result.latency_ms = Math.round(performance.now() - t0);
  return result;
}

// =============================================================================
// UI Rendering Functions
// =============================================================================
function showLoading(show) {
  el.loadingOverlay.style.display = show ? "flex" : "none";
  if (show) el.resultsContainer.style.display = "none";
}

function renderResults(res) {
  lastScanResult = res;
  el.resultsContainer.style.display = "flex";

  const score = res.risk_score || 0;
  const level = (res.risk_level || "SAFE").toLowerCase();
  const CIRCUMFERENCE = GAUGE_CIRCUMFERENCE;
  const isEmailResult = res.target_type === "EMAIL";
  const modelAvailable = Boolean(res.model_available) ||
    (Array.isArray(res.urls_analyzed) && res.urls_analyzed.some((item) => item.model_available));
  const hasFindings = Array.isArray(res.evidence) && res.evidence.length > 0;
  const noSignalsOnly = score === 0 && !hasFindings && !modelAvailable;
  el.summaryTextScore.textContent = isEmailResult ? `${res.email_text_score ?? score}/100` : "--";
  el.summaryUrlScore.textContent = isEmailResult
    ? (res.email_url_average === null ? "No URLs" : `${res.email_url_average}/100`)
    : "--";
  el.summaryCombinedScore.textContent = `${score}/100`;
  el.summaryAnalysis.textContent = noSignalsOnly
    ? `${res.summary || "No configured threat indicators were detected."} No trained model is installed; this heuristic-only result does not verify the message or URL as safe.`
    : res.summary || "Scan complete.";
  if (isEmailResult) el.linksTitle.textContent = "Current Email URLs";
  el.emailUrlAverage.textContent = isEmailResult
    ? (res.email_url_average === null ? "No URLs found" : `Average: ${res.email_url_average}/100`)
    : "Average: --";
  el.contextResultCard.style.display = isEmailResult ? "flex" : "none";
  if (isEmailResult) {
    const textScore = Number(res.email_text_score ?? score);
    el.contextTextScore.textContent = textScore;
    const textHasSignals = Array.isArray(res.email_text_evidence) && res.email_text_evidence.length > 0;
    el.contextTextLevel.textContent = textScore === 0 && !textHasSignals && !res.model_available ? "NO SIGNALS"
      : textScore >= 80 ? "CRITICAL"
      : textScore >= 60 ? "HIGH"
      : textScore >= 35 ? "MEDIUM"
      : textScore >= 15 ? "LOW"
      : "LOW";
    el.contextTextLevel.className = `intel-badge ${textScore >= 60 ? "mismatch" : textScore === 0 && !textHasSignals && !res.model_available ? "unverified" : textScore < 15 ? "verified" : ""}`;
    el.contextTextSummary.textContent = res.email_text_summary || res.summary || "Email text assessment complete.";
    if (textScore === 0 && !textHasSignals && !res.model_available) {
      el.contextTextSummary.textContent += " No trained model is installed; this is not a safety verdict.";
    }
    el.contextSignals.replaceChildren();
    const signals = res.email_text_evidence || res.evidence || [];
    if (!signals.length) {
      el.contextSignals.textContent = "No configured email text indicators were detected.";
    } else {
      signals.slice(0, 8).forEach((finding) => {
        const signal = document.createElement("div");
        signal.className = "context-signal";
        signal.textContent = finding.evidence || finding.rule_id || "Email indicator detected.";
        el.contextSignals.appendChild(signal);
      });
    }
  }

  el.riskScoreValue.textContent = score;
  el.riskLevelBadge.textContent = noSignalsOnly ? "NO SIGNALS" : (res.risk_level || "SAFE");
  el.riskLevelBadge.className   = `risk-badge ${noSignalsOnly ? "unverified" : level}`;
  el.latencyBadge.textContent   = res.cached ? `⚡ ${res.latency_ms || 0.5} ms (Cached)` : `${res.latency_ms || 1.2} ms`;
  el.verdictTitle.textContent   = noSignalsOnly ? "No Configured Indicators Found"
                                : level === "critical" ? "Severe Security Threat"
                                : level === "high"     ? "High Risk Detected"
                                : level === "medium"   ? "Suspicious Signals" : "Low Risk Content";
  el.verdictSummary.textContent = res.summary || "Scan complete.";

  el.gaugeBar.style.strokeDashoffset = CIRCUMFERENCE - (score / 100) * CIRCUMFERENCE;
  el.gaugeBar.style.stroke = score >= 80 ? "var(--danger-crimson)"
                           : score >= 60 ? "#ea580c"
                           : score >= 35 ? "var(--warning-amber)"
                           : "var(--safe-green)";

  if (isEmailResult) {
    el.contextTab.insertBefore(el.directFeedbackCard, el.contextResultCard);
    el.directFeedbackCard.style.display = "flex";
    el.directFeedbackBtns.style.display = "flex";
    el.directFeedbackMsg.style.display  = "none";
    el.feedbackTargetLabel.textContent  = `Subject: "${res.subject || "Email Message"}". Saved locally as a future training label; the current model is not retrained.`;
    const btnSafeText = el.btnFeedbackSafe.querySelector("span") || el.btnFeedbackSafe;
    const btnThreatText = el.btnFeedbackThreat.querySelector("span") || el.btnFeedbackThreat;
    btnSafeText.textContent = "✅ Safe Email";
    btnThreatText.textContent = "❌ Threat / Phishing";
  } else if (res.target_type === "URL" && res.target) {
    el.urlTab.insertBefore(el.directFeedbackCard, el.linksCard);
    el.directFeedbackCard.style.display = "flex";
    el.directFeedbackBtns.style.display = "flex";
    el.directFeedbackMsg.style.display = "none";
    el.feedbackTargetLabel.textContent = `Target: ${res.defanged_target || defangUrl(res.target)}. Saved locally as a future training label; the current model is not retrained.`;
    const btnSafeText = el.btnFeedbackSafe.querySelector("span") || el.btnFeedbackSafe;
    const btnThreatText = el.btnFeedbackThreat.querySelector("span") || el.btnFeedbackThreat;
    btnSafeText.textContent = "✅ Safe URL";
    btnThreatText.textContent = "❌ Threat / Malicious";
  } else {
    el.directFeedbackCard.style.display = "none";
  }

  // Company Intel Card
  const brandName   = res.claimed_company || (res.company_intelligence ? res.company_intelligence.claimed_brand : null) || res.claimed_brand;
  const intelStatus = res.company_intelligence ? res.company_intelligence.status : (brandName ? "ANALYZED" : "NONE_DETECTED");

  const fallbackSenderDomain = el.emailInput && el.emailInput.dataset && el.emailInput.dataset.sender
    ? (el.emailInput.dataset.sender.match(/@([\w.-]+)/)?.[1] || "")
    : "";
  const displaySenderDomain = res.sender_domain || fallbackSenderDomain;

  if (brandName || displaySenderDomain) {
    el.companyIntelCard.style.display = "flex";
    el.intelClaimedBrand.textContent  = brandName || "None Detected";
    el.intelSenderDomain.textContent  = displaySenderDomain ? `@${displaySenderDomain}` : (res.hostname || "N/A");
    if (intelStatus === "IMPERSONATION_MISMATCH") {
      el.companyStatusBadge.textContent = "IMPERSONATION MISMATCH";
      el.companyStatusBadge.className   = "intel-badge mismatch";
      el.intelDomainVerdict.textContent = `ALERT: Sender domain does not match official ${brandName} infrastructure!`;
      el.intelDomainVerdict.style.color = "#ff6b7d";
    } else if (intelStatus === "VERIFIED_DOMAIN_MATCH") {
      el.companyStatusBadge.textContent = "VERIFIED DOMAIN";
      el.companyStatusBadge.className   = "intel-badge verified";
      el.intelDomainVerdict.textContent = `Sender domain matches recognized official domains for ${brandName}.`;
      el.intelDomainVerdict.style.color = "var(--safe-green)";
    } else {
      el.companyStatusBadge.textContent = "GENERIC";
      el.companyStatusBadge.className   = "intel-badge";
      el.intelDomainVerdict.textContent = "No specific corporate brand claims identified.";
      el.intelDomainVerdict.style.color = "var(--text-muted)";
    }
  } else {
    el.companyIntelCard.style.display = "none";
  }

  // Remediation Card
  el.remediationText.textContent = res.recommended_action || "Standard security scrutiny applies.";
  el.remediationCard.className   = (level === "critical" || level === "high") ? "remediation-card critical" : "remediation-card";

  // Evidence Findings — use DocumentFragment to minimise reflows
  const findings = res.evidence || [];
  el.evidenceCount.textContent = findings.length;
  el.evidenceList.innerHTML = "";
  if (findings.length === 0) {
    el.evidenceList.innerHTML = `<div class="evidence-item" style="border-left-color:var(--safe-green);"><div class="evidence-text">No threat rules or malicious heuristics triggered.</div></div>`;
  } else {
    const evFrag = document.createDocumentFragment();
    findings.forEach(f => {
      const sev = (f.severity || "MEDIUM").toLowerCase();
      const div = document.createElement("div");
      div.className = `evidence-item ${sev}`;
      div.innerHTML = `
        <div class="evidence-item-top">
          <span class="evidence-rule-id">${f.rule_id || "THREAT_RULE"}</span>
          <span class="evidence-severity ${sev}">${f.severity || "INFO"}</span>
        </div>
        <div class="evidence-text">${escapeHtml(f.evidence || "")}</div>
        ${f.remediation ? `<div class="evidence-remediation">${escapeHtml(f.remediation)}</div>` : ""}`;
      evFrag.appendChild(div);
    });
    el.evidenceList.appendChild(evFrag);
  }

  // Embedded Links Card (Strictly omitted for pure Email Text Inspection per contract)
  const links = res.urls_analyzed || [];
  el.linksCount.textContent = links.length;

  if (links.length > 0) {
    el.linksCard.style.display = "flex";
    el.linksList.innerHTML = "";
    const linkFrag = document.createDocumentFragment();
    links.forEach((l, idx) => {
      const riskScore = parseFloat(l.risk_score) || 0;
      const hasSignals = (l.evidence || []).length > 0;
      const isHigh = riskScore >= 0.5;
      const isMedium = riskScore >= 0.25 && riskScore < 0.5;
      const badgeClass = isHigh ? 'high' : (isMedium || hasSignals ? 'warning' : 'safe');
      const badgeText = isHigh ? `THREAT • ${(riskScore * 100).toFixed(0)}/100`
        : isMedium ? `SUSPICIOUS • ${(riskScore * 100).toFixed(0)}/100`
        : hasSignals ? `SIGNAL • ${(riskScore * 100).toFixed(0)}/100`
        : `SAFE • ${(riskScore * 100).toFixed(0)}/100`;
      const evidenceSummary = hasSignals
        ? l.evidence.slice(0, 3).map((finding) => escapeHtml(finding.evidence || finding.rule_id || "Indicator detected")).join(" · ")
        : "No configured URL threat indicators detected.";

      const div = document.createElement("div");
      div.className = `link-item ${badgeClass}`;
      div.innerHTML = `
        <div class="link-item-top">
          <span class="link-defanged" title="${escapeHtml(l.url)}">${escapeHtml(l.defanged || defangUrl(l.url))}</span>
          <span class="link-score-badge ${badgeClass}">${badgeText}</span>
        </div>
        <div class="link-evidence-text">${l.model_available ? "ONNX + heuristic analysis" : "Heuristic-only analysis; no trained model available"}</div>
        <div class="link-evidence-text">${evidenceSummary}</div>
        <div class="link-feedback-row">
          <span class="link-fb-prompt">Was this URL safe?</span>
          <div class="link-fb-buttons" id="popupLinkFb_${idx}">
            <button class="link-fb-btn safe" data-url="${escapeHtml(l.url)}" data-safe="true" data-idx="${idx}" title="Save this assessment in browser storage">✅ Safe</button>
            <button class="link-fb-btn threat" data-url="${escapeHtml(l.url)}" data-safe="false" data-idx="${idx}" title="Save this assessment in browser storage">❌ Threat</button>
          </div>
        </div>
      `;
      linkFrag.appendChild(div);
    });
    el.linksList.appendChild(linkFrag);

    // Event delegation — one listener on the container instead of N per button
    el.linksList.onclick = async (e) => {
      const btn = e.target.closest(".link-fb-btn");
      if (!btn) return;
      e.preventDefault();
      const url    = btn.getAttribute("data-url");
      const isSafe = btn.getAttribute("data-safe") === "true";
      const idx    = btn.getAttribute("data-idx");
      const btnBox = el.linksList.querySelector(`#popupLinkFb_${idx}`);
      if (btnBox) btnBox.innerHTML = `<span style="font-size:9.5px;color:var(--text-muted);">Saving locally...</span>`;
      const feedback = await submitTargetFeedback(url, isSafe, "popup_batch_links");
      if (btnBox) btnBox.innerHTML = `<span class="link-fb-confirmed ${isSafe ? "safe" : "threat"}">${escapeHtml(feedbackResultMessage(feedback, isSafe))}</span>`;
    };
  } else {
    el.linksCard.style.display = "none";
  }

  if (el.auditReportBox) el.auditReportBox.textContent = JSON.stringify(res, null, 2);
}

function generateTextReport(res) {
  return `================================================================================
SAFEINBOX AI THREAT INTELLIGENCE ANALYSIS REPORT
Target: ${res.target || res.target_type}
Date: ${new Date().toISOString()}
================================================================================
RISK LEVEL:        ${res.risk_level} (${res.risk_score}/100)
CLAIMED COMPANY:   ${res.claimed_company || res.claimed_brand || "None"}
SUMMARY:           ${res.summary}
RECOMMENDED ACTION: ${res.recommended_action}

FINDINGS & EVIDENCE (${(res.evidence || []).length}):
${(res.evidence || []).map(e => `[${e.severity}] ${e.rule_id}: ${e.evidence}`).join("\n")}

LINKS ANALYZED (${(res.urls_analyzed || []).length}):
${(res.urls_analyzed || []).map(l => ` - ${l.defanged}`).join("\n")}

SafeInbox AI v1.0.0 - Intelligent Email Protection
================================================================================`;
}
