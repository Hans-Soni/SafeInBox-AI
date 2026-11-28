"use strict";

importScripts("../url/urlThreatParser.js");
importScripts("../utils/textParser.js");
importScripts("../utils/cryptoUtils.js");

const CACHE_PREFIX = "urlThreatScan:";
const CACHE_TTL_MS = 7 * 24 * 60 * 60 * 1000;
const MAX_CACHE_ENTRIES = 500;
const EMAIL_CACHE_PREFIX = "emailThreatScan:";
const EMAIL_CACHE_TTL_MS = 24 * 60 * 60 * 1000;
const MAX_EMAIL_CACHE_ENTRIES = 200;
const MODEL_RESPONSE_TIMEOUT_MS = 15000;
const EMAIL_MODEL_RESPONSE_TIMEOUT_MS = 30000;
const MAX_EMAIL_HANDOFF_CHARACTERS = 1000000;
const MAX_EMAIL_HANDOFF_URLS = 100;
const MAX_EMAIL_HANDOFF_URL_LENGTH = 4096;
const SUPPORTED_WEBMAIL_HOSTS = new Set([
  "mail.google.com",
  "outlook.live.com",
  "outlook.office.com",
  "mail.yahoo.com"
]);
const DIGEST_ALARM_NAME = "safeinbox_15day_digest_check";
const DIGEST_INTERVAL_MS = 15 * 24 * 60 * 60 * 1000; // 15 days in milliseconds
const DIGEST_RECORDS_KEY = "safeinbox_15day_email_records";
const DIGEST_LAST_SENT_KEY = "safeinbox_15day_last_dispatch";
const DIGEST_HISTORY_KEY = "safeinbox_15day_history";

const pendingInferences = new Map();
const inFlightScans = new Map();
const inFlightEmailScans = new Map();
let inferencePort = null;
let nextRequestId = 0;
let modelAvailable = false;
let emailModelAvailable = false;
let emailModelStatusKnown = false;
let inferenceWorkerReady = false;
let textInferenceDocumentPromise = null;

function configureSidePanelBehavior() {
  if (!chrome.sidePanel || typeof chrome.sidePanel.setPanelBehavior !== "function") {
    console.error("The SafeInbox side panel API is unavailable. Use a recent Chrome version with Side Panel support.");
    return;
  }
  chrome.sidePanel.setPanelBehavior({ openPanelOnActionClick: true }).catch((error) => {
    console.error("Could not configure the SafeInbox side panel:", error);
  });
}

async function purgeStaleHeuristicCaches() {
  if (typeof chrome === "undefined" || !chrome.storage || !chrome.storage.local) return;
  try {
    const items = await chrome.storage.local.get(null);
    const keysToRemove = Object.keys(items).filter((key) => {
      if (!key.startsWith(CACHE_PREFIX) && !key.startsWith(EMAIL_CACHE_PREFIX)) return false;
      const entry = items[key];
      return entry && entry.result && (!entry.result.model_available && !entry.result.modelAvailable);
    });
    if (keysToRemove.length) {
      await chrome.storage.local.remove(keysToRemove);
    }
  } catch {}
}

configureSidePanelBehavior();
setupDigestAlarm();
purgeStaleHeuristicCaches();
flushAllPendingCloudData().catch(() => {});

// Ensure default backend configuration exists in storage
if (typeof chrome !== "undefined" && chrome.storage && chrome.storage.local && typeof chrome.storage.local.get === "function") {
  chrome.storage.local.get(["cloudBackendUrl", "cloudBackendEnabled"], (stored) => {
    if (!stored || !stored.cloudBackendUrl) {
      if (typeof chrome.storage.local.set === "function") {
        chrome.storage.local.set({
          cloudBackendUrl: "https://safeinbox-ai.onrender.com",
          cloudBackendEnabled: true
        });
      }
    }
  });
}

chrome.runtime.onInstalled.addListener((details) => {
  configureSidePanelBehavior();
  setupDigestAlarm();
  purgeStaleHeuristicCaches();
  flushAllPendingCloudData().catch(() => {});
  if (typeof chrome !== "undefined" && chrome.storage && chrome.storage.local) {
    chrome.storage.local.set({
      cloudBackendUrl: "https://safeinbox-ai.onrender.com",
      cloudBackendEnabled: true
    });
  }
  if (details && details.reason === "install") {
    if (typeof chrome !== "undefined" && chrome.tabs && chrome.tabs.create) {
      chrome.tabs.create({ url: chrome.runtime.getURL("welcome.html") });
    }
  }
  chrome.contextMenus.removeAll(() => {
    chrome.contextMenus.create({
      id: "aegisai-scan-link",
      title: "SafeInbox AI: Inspect Link Safety",
      contexts: ["link"]
    });
    chrome.contextMenus.create({
      id: "aegisai-scan-page",
      title: "SafeInbox AI: Inspect Current URL",
      contexts: ["page"]
    });
    chrome.contextMenus.create({
      id: "aegisai-scan-selection",
      title: "SafeInbox AI: Scan Selected Text as Email",
      contexts: ["selection"]
    });
  });
});

chrome.contextMenus.onClicked.addListener((info) => {
  if (info.menuItemId === "aegisai-scan-selection" && typeof info.selectionText === "string" && info.selectionText.trim()) {
    const boundedText = info.selectionText.slice(0, 100000);
    chrome.storage.local.set({ pendingScanEmail: boundedText });
    chrome.sidePanel.open({ tabId: info.tabId }).catch((error) => {
      console.error("Could not open the SafeInbox side panel:", error);
    });
    return;
  }
  const rawUrl = info.menuItemId === "aegisai-scan-link" ? info.linkUrl : info.pageUrl;
  if (typeof rawUrl === "string" && /^https?:\/\//i.test(rawUrl)) {
    const boundedUrl = rawUrl.slice(0, 4096);
    chrome.storage.local.set({ pendingScanUrl: boundedUrl });
    chrome.sidePanel.open({ tabId: info.tabId }).catch((error) => {
      console.error("Could not open the SafeInbox side panel:", error);
    });
  }
});

if (typeof chrome !== "undefined" && chrome.tabs && chrome.tabs.onRemoved) {
  chrome.tabs.onRemoved.addListener((tabId) => {
    if (!chrome.storage || !chrome.storage.session) return;
    chrome.storage.session.get("activeEmailScan").then((stored) => {
      if (stored && stored.activeEmailScan && stored.activeEmailScan.tabId === tabId) {
        chrome.storage.session.remove("activeEmailScan");
      }
    }).catch(() => {});
  });
}

if (typeof chrome !== "undefined" && chrome.tabs && chrome.tabs.onUpdated) {
  chrome.tabs.onUpdated.addListener((tabId, changeInfo) => {
    if (!chrome.storage || !chrome.storage.session) return;
    if (changeInfo.url && !isSupportedWebmailUrl(changeInfo.url)) {
      chrome.storage.session.get("activeEmailScan").then((stored) => {
        if (stored && stored.activeEmailScan && stored.activeEmailScan.tabId === tabId) {
          chrome.storage.session.remove("activeEmailScan");
        }
      }).catch(() => {});
    }
  });
}

if (typeof chrome !== "undefined" && chrome.storage && chrome.storage.onChanged) {
  chrome.storage.onChanged.addListener((changes, area) => {
    if (area === "local" && (changes.safeinbox_auth || changes.safeinbox_user_session)) {
      if (typeof SafeInboxCrypto !== "undefined" && typeof SafeInboxCrypto.clearKeyCache === "function") {
        SafeInboxCrypto.clearKeyCache();
      }
    }
  });
}

chrome.runtime.onConnect.addListener((port) => {
  if (port.name !== "url-analysis-worker") return;
  inferencePort = port;
  port.onMessage.addListener((message) => {
    if (message.type === "WORKER_STATUS") {
      inferenceWorkerReady = true;
      modelAvailable = Boolean(message.modelAvailable);
      return;
    }
    if (message.type !== "INFERENCE_RESULT") return;
    const pending = pendingInferences.get(message.requestId);
    if (!pending) return;
    clearTimeout(pending.timeout);
    pendingInferences.delete(message.requestId);
    if (message.error) pending.reject(new Error(message.error));
    else {
      modelAvailable = Boolean(message.result && message.result.modelAvailable);
      pending.resolve(message.result);
    }
  });
  port.onDisconnect.addListener(() => {
    if (inferencePort === port) inferencePort = null;
    inferenceWorkerReady = false;
    modelAvailable = false;
    for (const [requestId, pending] of pendingInferences) {
      clearTimeout(pending.timeout);
      pending.reject(new Error("The URL inference worker disconnected."));
      pendingInferences.delete(requestId);
    }
  });
});

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message && message.type === "EMAIL_TEXT_MODEL_STATUS") {
    emailModelAvailable = Boolean(message.modelAvailable);
    emailModelStatusKnown = true;
    sendResponse({ ok: true });
    return false;
  }

  if (message && message.type === "EMAIL_SCAN_OPENED") {
    const sourceUrl = sender.url || (sender.tab && sender.tab.url) || "";
    const payload = message.email;
    if (!sender.tab || !Number.isInteger(sender.tab.id) ||
        !isSupportedWebmailUrl(sourceUrl) ||
        !isValidEmailHandoff(payload)) {
      sendResponse({ ok: false, error: "Email scan payload or source tab is invalid." });
      return false;
    }

    const email = {
      sender: payload.sender || "",
      senderName: payload.senderName || "",
      senderEmail: payload.senderEmail || "",
      receiver: payload.receiver || "",
      cc: payload.cc || "",
      bcc: payload.bcc || "",
      subject: payload.subject,
      text: payload.text,
      bodyText: payload.bodyText || "",
      urls: payload.urls,
      tabId: sender.tab.id,
      updatedAt: Date.now()
    };
    chrome.storage.session.set({ activeEmailScan: email }).then(
      () => sendResponse({ ok: true }),
      (error) => sendResponse({ ok: false, error: error.message || "Could not share email scan with the side panel." })
    );
    return true;
  }

  if (message && message.type === "ANALYZE_EMAIL_TEXT") {
    if (!message.email || typeof message.email !== "object") {
      sendResponse({ ok: false, error: "Email text payload is invalid." });
      return false;
    }
    analyzeEmailAndRespond(message.email).then(
      (result) => sendResponse({ ok: true, result }),
      (error) => sendResponse({ ok: false, error: error.message || "Email text analysis failed." })
    );
    return true;
  }

  if (message && message.type === "URL_MODEL_STATUS") {
    modelAvailable = Boolean(message.modelAvailable);
    return false;
  }

  if (message && message.type === "TEST_CLOUD_BACKEND") {
    testCloudBackend(message.url).then(
      (status) => sendResponse({ ok: true, status }),
      (error) => sendResponse({ ok: false, error: error.message || "Failed to reach cloud backend." })
    );
    return true;
  }

  if (message && message.type === "GET_15DAY_DIGEST_DATA") {
    get15DayDigestData().then(
      (data) => sendResponse({ ok: true, data }),
      (error) => sendResponse({ ok: false, error: error.message || "Failed to load 15-day digest data." })
    );
    return true;
  }

  if (message && message.type === "DISPATCH_15DAY_DIGEST_NOW") {
    dispatch15DayDigestNow({ force: true, targetEmail: message.targetEmail }).then(
      (result) => sendResponse({ ok: true, result }),
      (error) => sendResponse({ ok: false, error: error.message || "Failed to dispatch 15-day digest." })
    );
    return true;
  }

  if (message && message.type === "PREVIEW_15DAY_DIGEST") {
    preview15DayDigest(message.targetEmail).then(
      (result) => sendResponse({ ok: true, result }),
      (error) => sendResponse({ ok: false, error: error.message || "Failed to generate digest preview." })
    );
    return true;
  }

  if (message && message.type === "RECORD_WEBMAIL_CLICK") {
    syncClickWithBackend(message.clickRecord).then(
      (saved) => sendResponse({ ok: true, saved }),
      (err) => sendResponse({ ok: false, error: err.message })
    );
    return true;
  }

  if (message && message.type === "RECORD_FEEDBACK") {
    syncFeedbackWithBackend(message.feedback).then(
      (saved) => sendResponse({ ok: true, saved }),
      (err) => sendResponse({ ok: false, error: err.message })
    );
    return true;
  }

  if (message && message.type === "RECORD_EMAIL_AUDIT") {
    syncAuditWithBackend(message.auditRecord).then(
      (saved) => sendResponse({ ok: true, saved }),
      (err) => sendResponse({ ok: false, error: err.message })
    );
    return true;
  }

  if (message && message.type === "OPEN_WELCOME_PAGE") {
    const welcomeUrl = chrome.runtime.getURL("welcome.html");
    if (chrome.tabs && chrome.tabs.create) {
      chrome.tabs.create({ url: welcomeUrl });
    }
    sendResponse({ ok: true });
    return true;
  }

  if (message && message.type === "CLEAR_AUTH_CACHE") {
    if (typeof SafeInboxCrypto !== "undefined" && typeof SafeInboxCrypto.clearKeyCache === "function") {
      SafeInboxCrypto.clearKeyCache();
    }
    sendResponse({ ok: true });
    return true;
  }

  if (message && message.type === "FLUSH_PENDING_SYNC") {
    flushAllPendingCloudData().then(
      () => sendResponse({ ok: true }),
      (err) => sendResponse({ ok: false, error: err.message })
    );
    return true;
  }

  if (!message || message.type !== "ANALYZE_URL") return false;
  analyzeAndRespond(message.url).then(
    (result) => sendResponse({ ok: true, result }),
    (error) => sendResponse({ ok: false, error: error.message || "URL analysis failed." })
  );
  return true;
});

async function testCloudBackend(rawUrl) {
  if (typeof rawUrl !== "string" || !rawUrl.trim()) throw new TypeError("Backend URL is required.");
  const baseUrl = rawUrl.trim().replace(/\/+$/, "");
  if (!/^https?:\/\//i.test(baseUrl)) throw new TypeError("Backend URL must start with http:// or https://");
  const isLocalhost = /^https?:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/i.test(baseUrl);
  if (!baseUrl.startsWith("https://") && !isLocalhost) {
    throw new TypeError("Protocol violation: Remote backend must use HTTPS over TCP. Unencrypted HTTP is blocked.");
  }
  if (typeof fetch !== "function") throw new Error("Fetch API is unavailable in this environment.");
  const controller = typeof AbortController === "function" ? new AbortController() : null;
  const timeoutId = controller ? setTimeout(() => controller.abort(), 4000) : null;
  const start = Date.now();
  try {
    const resp = await fetch(`${baseUrl}/health`, controller ? { signal: controller.signal } : {});
    if (timeoutId) clearTimeout(timeoutId);
    if (!resp.ok) throw new Error(`Server returned HTTP ${resp.status}`);
    const data = await resp.json();
    if (resp.ok) {
      flushAllPendingCloudData(baseUrl).catch(() => {});
    }
    return {
      online: true,
      latencyMs: Date.now() - start,
      version: data.version || "1.0.0",
      project: data.project || "SafeInbox API"
    };
  } catch (err) {
    if (timeoutId) clearTimeout(timeoutId);
    throw new Error(`Could not connect to ${baseUrl}: ${err.message}`);
  }
}

// =============================================================================
// Cloud & Local Database Live Action Synchronization (Clicks, Feedback, Audits)
// =============================================================================
const PENDING_CLICKS_KEY = "safeinbox_pending_clicks";
const PENDING_FEEDBACK_KEY = "safeinbox_pending_feedback";
const PENDING_AUDITS_KEY = "safeinbox_pending_audits";
const MAX_PENDING_QUEUE = 500;
const DEFAULT_CLOUD_BACKEND_URL = "https://safeinbox-ai.onrender.com";

async function getEffectiveBackendUrl() {
  if (typeof chrome === "undefined" || !chrome.storage || !chrome.storage.local) {
    return DEFAULT_CLOUD_BACKEND_URL;
  }
  return new Promise((resolve) => {
    try {
      chrome.storage.local.get(["cloudBackendUrl", "cloudBackendEnabled", "cloud_backend_url"], (stored) => {
        if (chrome.runtime.lastError) {
          resolve(DEFAULT_CLOUD_BACKEND_URL);
          return;
        }
        let url = "";
        if (stored && stored.cloudBackendUrl && (stored.cloudBackendEnabled || stored.cloudBackendEnabled === undefined)) {
          url = String(stored.cloudBackendUrl).trim().replace(/\/+$/, "");
        } else if (stored && stored.cloud_backend_url) {
          url = String(stored.cloud_backend_url).trim().replace(/\/+$/, "");
        } else {
          url = DEFAULT_CLOUD_BACKEND_URL;
        }

        const isLocalhost = /^https?:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/i.test(url);
        if (!isLocalhost && !url.startsWith("https://")) {
          // Protocol enforcement: Remote cloud backend must use HTTPS
          resolve("");
          return;
        }
        resolve(url);
      });
    } catch {
      resolve(DEFAULT_CLOUD_BACKEND_URL);
    }
  });
}

async function getAuthHeader() {
  if (typeof chrome === "undefined" || !chrome.storage || !chrome.storage.local) return {};
  return new Promise((resolve) => {
    try {
      chrome.storage.local.get(["safeinbox_auth"], async (res) => {
        const auth = res && res.safeinbox_auth;
        if (!auth || !auth.token) {
          resolve({});
          return;
        }

        // Proactive Refresh Token Rotation (RTR):
        // If access token is older than 25 minutes and we have a valid refresh token,
        // transparently rotate it with the backend.
        const now = Date.now();
        const tokenAge = now - (auth.token_saved_at || auth.saved_at || 0);
        const ACCESS_TOKEN_TTL_MS = 25 * 60 * 1000; // 25 minutes

        if (tokenAge > ACCESS_TOKEN_TTL_MS && auth.refresh_token) {
          try {
            const backendUrl = await getEffectiveBackendUrl();
            if (backendUrl) {
              const refreshResp = await fetch(`${backendUrl}/api/v1/auth/refresh`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ refresh_token: auth.refresh_token })
              });
              if (refreshResp.ok) {
                const refreshed = await refreshResp.json();
                auth.token = refreshed.access_token;
                auth.refresh_token = refreshed.refresh_token;
                auth.token_saved_at = Date.now();
                await chrome.storage.local.set({ safeinbox_auth: auth });
                resolve({ "Authorization": `Bearer ${auth.token}` });
                return;
              }
            }
          } catch (e) {
            console.warn("Background auto-refresh failed, using current token:", e);
          }
        }

        resolve({ "Authorization": `Bearer ${auth.token}` });
      });
    } catch {
      resolve({});
    }
  });
}

async function syncClickWithBackend(clickRecord) {
  if (!clickRecord || !clickRecord.url) return false;
  const backendUrl = await getEffectiveBackendUrl();
  if (!backendUrl) return false;

  const authHeaders = await getAuthHeader();
  let userEmail = null;
  let userIndexId = null;
  let userToken = null;
  try {
    const sessionRes = await new Promise((r) => {
      chrome.storage.local.get(["safeinbox_auth", "safeinbox_user_session"], r);
    });
    const authObj = (sessionRes && sessionRes.safeinbox_auth) || (sessionRes && sessionRes.safeinbox_user_session) || null;
    userEmail = (authObj && authObj.email) ||
                (authObj && authObj.user && authObj.user.email) ||
                null;
    userIndexId = (authObj && authObj.index_id) ||
                  (authObj && authObj.user && authObj.user.index_id) ||
                  null;
    userToken = (authObj && authObj.token) ||
                (authObj && authObj.accessToken) ||
                null;
  } catch {}

  const rawUrl = clickRecord.url;
  const defangedUrl = clickRecord.defanged || String(rawUrl).replace(/\./g, "[.]");
  let isEncrypted = false;
  let encryptedPayload = null;

  // Zero-Knowledge Client-Side Encryption (AES-256-GCM)
  if (typeof SafeInboxCrypto !== "undefined" && (userToken || userEmail)) {
    try {
      const zkKey = await SafeInboxCrypto.deriveZeroKnowledgeKey(
        userToken || userEmail,
        userIndexId || userEmail
      );
      const sensitiveData = {
        url: rawUrl,
        defanged_url: defangedUrl,
        email_subject: clickRecord.email_subject || null,
        sender: clickRecord.sender || null
      };
      encryptedPayload = await SafeInboxCrypto.encryptZeroKnowledge(sensitiveData, zkKey);
      isEncrypted = true;
    } catch (cryptoErr) {
      console.warn("Client-side zero-knowledge encryption fallback:", cryptoErr);
    }
  }

  const payload = {
    url: isEncrypted ? "[ENCRYPTED]" : rawUrl,
    defanged_url: isEncrypted ? "[ENCRYPTED]" : defangedUrl,
    email_subject: isEncrypted ? "[ENCRYPTED]" : (clickRecord.email_subject || null),
    sender: isEncrypted ? "[ENCRYPTED]" : (clickRecord.sender || null),
    risk_score: typeof clickRecord.risk_score === "number" ? clickRecord.risk_score : 0,
    risk_level: String(clickRecord.risk_level || "AUDITED"),
    proceeded: clickRecord.proceeded !== false,
    source: String(clickRecord.source || "email_body_link"),
    user_email: userEmail,
    user_index_id: userIndexId,
    is_encrypted: isEncrypted,
    encrypted_payload: encryptedPayload
  };

  if (typeof fetch !== "function") {
    await queuePendingCloudItem(PENDING_CLICKS_KEY, payload);
    return false;
  }

  try {
    const controller = typeof AbortController === "function" ? new AbortController() : null;
    const timeoutId = controller ? setTimeout(() => controller.abort(), 2500) : null;
    const resp = await fetch(`${backendUrl}/api/v1/scan/click`, {
      method: "POST",
      headers: { "Content-Type": "application/json", ...authHeaders },
      body: JSON.stringify(payload),
      signal: controller ? controller.signal : undefined
    });
    if (timeoutId) clearTimeout(timeoutId);

    if (resp.ok) {
      flushAllPendingCloudData(backendUrl).catch(() => {});
      return true;
    } else {
      await queuePendingCloudItem(PENDING_CLICKS_KEY, payload);
      return false;
    }
  } catch (err) {
    await queuePendingCloudItem(PENDING_CLICKS_KEY, payload);
    return false;
  }
}

async function syncFeedbackWithBackend(feedback) {
  if (!feedback || !feedback.target) return false;
  const backendUrl = await getEffectiveBackendUrl();
  if (!backendUrl) return false;

  const authHeaders = await getAuthHeader();
  const payload = {
    target: feedback.target,
    target_type: feedback.target_type === "EMAIL" ? "TEXT" : (feedback.target_type || "URL"),
    is_safe: Boolean(feedback.is_safe),
    source: feedback.source || "webmail_banner"
  };

  if (typeof fetch !== "function") {
    await queuePendingCloudItem(PENDING_FEEDBACK_KEY, payload);
    return false;
  }

  try {
    const controller = typeof AbortController === "function" ? new AbortController() : null;
    const timeoutId = controller ? setTimeout(() => controller.abort(), 2500) : null;
    const resp = await fetch(`${backendUrl}/api/v1/feedback`, {
      method: "POST",
      headers: { "Content-Type": "application/json", ...authHeaders },
      body: JSON.stringify(payload),
      signal: controller ? controller.signal : undefined
    });
    if (timeoutId) clearTimeout(timeoutId);

    if (resp.ok) {
      const responseData = await resp.json().catch(() => null);
      flushAllPendingCloudData(backendUrl).catch(() => {});
      return { ok: true, data: responseData };
    } else {
      await queuePendingCloudItem(PENDING_FEEDBACK_KEY, payload);
      return false;
    }
  } catch (err) {
    await queuePendingCloudItem(PENDING_FEEDBACK_KEY, payload);
    return false;
  }
}

async function syncAuditWithBackend(auditRecord) {
  if (!auditRecord) return false;
  const backendUrl = await getEffectiveBackendUrl();
  if (!backendUrl || typeof fetch !== "function") return false;

  const authHeaders = await getAuthHeader();
  let userEmail = null;
  let userIndexId = null;
  try {
    const sessionRes = await new Promise((r) => {
      chrome.storage.local.get(["safeinbox_auth", "safeinbox_user_session"], r);
    });
    userEmail = (sessionRes && sessionRes.safeinbox_auth && sessionRes.safeinbox_auth.email) ||
                (sessionRes && sessionRes.safeinbox_auth && sessionRes.safeinbox_auth.user && sessionRes.safeinbox_auth.user.email) ||
                null;
    userIndexId = (sessionRes && sessionRes.safeinbox_auth && sessionRes.safeinbox_auth.index_id) ||
                  (sessionRes && sessionRes.safeinbox_auth && sessionRes.safeinbox_auth.user && sessionRes.safeinbox_auth.user.index_id) ||
                  null;
  } catch {}

  const rawId = `${auditRecord.sender || ""}|${auditRecord.subject || ""}|${Date.now()}`;
  const contentHash = await hashUrl(rawId);

  const payload = {
    scan_type: "EMAIL",
    content_hash: contentHash,
    risk_score: Math.round(auditRecord.risk_score || 0),
    risk_level: String(auditRecord.risk_level || "SAFE"),
    threat_vectors: Array.isArray(auditRecord.threat_vectors) ? auditRecord.threat_vectors : [],
    user_email: userEmail,
    user_index_id: userIndexId
  };

  try {
    const controller = typeof AbortController === "function" ? new AbortController() : null;
    const timeoutId = controller ? setTimeout(() => controller.abort(), 2500) : null;
    const resp = await fetch(`${backendUrl}/api/v1/scan/audit`, {
      method: "POST",
      headers: { "Content-Type": "application/json", ...authHeaders },
      body: JSON.stringify(payload),
      signal: controller ? controller.signal : undefined
    });
    if (timeoutId) clearTimeout(timeoutId);

    if (resp.ok) {
      flushAllPendingCloudData(backendUrl).catch(() => {});
      return true;
    } else {
      await queuePendingCloudItem(PENDING_AUDITS_KEY, payload);
      return false;
    }
  } catch (err) {
    await queuePendingCloudItem(PENDING_AUDITS_KEY, payload);
    return false;
  }
}

async function queuePendingCloudItem(storageKey, item) {
  if (typeof chrome === "undefined" || !chrome.storage || !chrome.storage.local) return;
  return new Promise((resolve) => {
    try {
      chrome.storage.local.get([storageKey], (res) => {
        if (chrome.runtime.lastError) {
          resolve();
          return;
        }
        const list = Array.isArray(res && res[storageKey]) ? res[storageKey] : [];
        list.push(item);
        const trimmed = list.slice(-MAX_PENDING_QUEUE);
        chrome.storage.local.set({ [storageKey]: trimmed }, () => resolve());
      });
    } catch {
      resolve();
    }
  });
}

async function flushAllPendingCloudData(targetBackendUrl = null) {
  const backendUrl = targetBackendUrl || await getEffectiveBackendUrl();
  if (!backendUrl || typeof fetch !== "function") return;
  const authHeaders = await getAuthHeader();

  // Flush pending clicks
  try {
    const clickRes = await new Promise((r) => chrome.storage.local.get([PENDING_CLICKS_KEY], r));
    const pendingClicks = Array.isArray(clickRes && clickRes[PENDING_CLICKS_KEY]) ? clickRes[PENDING_CLICKS_KEY] : [];
    if (pendingClicks.length > 0) {
      const remainingClicks = [];
      for (let i = 0; i < pendingClicks.length; i++) {
        const item = pendingClicks[i];
        try {
          const resp = await fetch(`${backendUrl}/api/v1/scan/click`, {
            method: "POST",
            headers: { "Content-Type": "application/json", ...authHeaders },
            body: JSON.stringify(item)
          });
          if (!resp.ok) remainingClicks.push(item);
        } catch {
          remainingClicks.push(...pendingClicks.slice(i));
          break;
        }
      }
      await new Promise((r) => chrome.storage.local.set({ [PENDING_CLICKS_KEY]: remainingClicks }, r));
    }
  } catch {}

  // Flush pending feedback
  try {
    const fbRes = await new Promise((r) => chrome.storage.local.get([PENDING_FEEDBACK_KEY], r));
    const pendingFb = Array.isArray(fbRes && fbRes[PENDING_FEEDBACK_KEY]) ? fbRes[PENDING_FEEDBACK_KEY] : [];
    if (pendingFb.length > 0) {
      const remainingFb = [];
      for (let i = 0; i < pendingFb.length; i++) {
        const item = pendingFb[i];
        try {
          const resp = await fetch(`${backendUrl}/api/v1/feedback`, {
            method: "POST",
            headers: { "Content-Type": "application/json", ...authHeaders },
            body: JSON.stringify(item)
          });
          if (!resp.ok) remainingFb.push(item);
        } catch {
          remainingFb.push(...pendingFb.slice(i));
          break;
        }
      }
      await new Promise((r) => chrome.storage.local.set({ [PENDING_FEEDBACK_KEY]: remainingFb }, r));
    }
  } catch {}

  // Flush pending audits
  try {
    const auditRes = await new Promise((r) => chrome.storage.local.get([PENDING_AUDITS_KEY], r));
    const pendingAudits = Array.isArray(auditRes && auditRes[PENDING_AUDITS_KEY]) ? auditRes[PENDING_AUDITS_KEY] : [];
    if (pendingAudits.length > 0) {
      const remainingAudits = [];
      for (let i = 0; i < pendingAudits.length; i++) {
        const item = pendingAudits[i];
        try {
          const resp = await fetch(`${backendUrl}/api/v1/scan/audit`, {
            method: "POST",
            headers: { "Content-Type": "application/json", ...authHeaders },
            body: JSON.stringify(item)
          });
          if (!resp.ok) remainingAudits.push(item);
        } catch {
          remainingAudits.push(...pendingAudits.slice(i));
          break;
        }
      }
      await new Promise((r) => chrome.storage.local.set({ [PENDING_AUDITS_KEY]: remainingAudits }, r));
    }
  } catch {}
}

function isSupportedWebmailUrl(value) {
  try {
    const url = new URL(value);
    return url.protocol === "https:" && SUPPORTED_WEBMAIL_HOSTS.has(url.hostname.toLowerCase());
  } catch {
    return false;
  }
}

function isValidEmailHandoff(email) {
  if (!email || typeof email !== "object" ||
      typeof email.subject !== "string" ||
      typeof email.text !== "string" ||
      !Array.isArray(email.urls) ||
      email.urls.length > MAX_EMAIL_HANDOFF_URLS) return false;

  const textFields = ["sender", "senderName", "senderEmail", "receiver", "cc", "bcc", "bodyText"];
  if (textFields.some((field) => email[field] !== undefined && typeof email[field] !== "string")) return false;
  const characterCount = [...textFields, "subject", "text"]
    .reduce((sum, field) => sum + (email[field] || "").length, 0);
  if (characterCount > MAX_EMAIL_HANDOFF_CHARACTERS) return false;
  return email.urls.every((url) =>
    typeof url === "string" &&
    url.length <= MAX_EMAIL_HANDOFF_URL_LENGTH &&
    /^https?:\/\//i.test(url)
  );
}

async function hashEmail(email) {
  const canonical = JSON.stringify({
    subject: email.subject || "",
    sender: email.sender || "",
    receiver: email.receiver || "",
    cc: email.cc || "",
    bcc: email.bcc || "",
    text: email.text || "",
    body: email.body || ""
  });
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(canonical));
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("");
}

async function ensureTextInferenceDocument() {
  if (!chrome.offscreen || !chrome.offscreen.createDocument) {
    throw new Error("Chrome offscreen documents are unavailable; email ONNX inference is disabled.");
  }
  if (textInferenceDocumentPromise) return textInferenceDocumentPromise;

  textInferenceDocumentPromise = (async () => {
    if (chrome.offscreen.hasDocument && await chrome.offscreen.hasDocument()) return;
    if (chrome.runtime.getContexts) {
      const contexts = await chrome.runtime.getContexts({
        contextTypes: ["OFFSCREEN_DOCUMENT"],
        documentUrls: [chrome.runtime.getURL("offscreen.html")]
      });
      if (contexts.length) return;
    }
    try {
      await chrome.offscreen.createDocument({
        url: "offscreen.html",
        reasons: ["WORKERS"],
        justification: "Run local email ONNX inference in a Web Worker outside the page UI."
      });
    } catch (error) {
      if (/single offscreen document|already exists/i.test(error.message || "")) return;
      throw error;
    }
  })();
  try {
    await textInferenceDocumentPromise;
  } finally {
    textInferenceDocumentPromise = null;
  }
}

function removeEmailIdentity(result) {
  const cachedResult = {
    ...result,
    company_intelligence: result.company_intelligence
      ? { ...result.company_intelligence, sender_domain: "" }
      : result.company_intelligence
  };
  delete cachedResult.sender_name;
  delete cachedResult.sender_email;
  delete cachedResult.sender_domain;
  delete cachedResult.receiver;
  delete cachedResult.cc;
  delete cachedResult.subject;
  delete cachedResult.body_text;
  delete cachedResult.normalized_text;
  return cachedResult;
}

async function requestEmailInference(email) {
  await ensureTextInferenceDocument();
  const requestId = `email-${Date.now()}-${++nextRequestId}`;
  let timeoutId;
  const timeout = new Promise((resolve, reject) => {
    timeoutId = setTimeout(() => reject(new Error("Email text inference timed out.")), EMAIL_MODEL_RESPONSE_TIMEOUT_MS);
  });
  try {
    const response = await Promise.race([
      chrome.runtime.sendMessage({ type: "RUN_EMAIL_TEXT_INFERENCE", requestId, email }),
      timeout
    ]);
    if (!response || !response.ok) {
      throw new Error(response && response.error ? response.error : "Offscreen email inference did not respond.");
    }
    return response.result;
  } finally {
    clearTimeout(timeoutId);
  }
}

async function analyzeEmailAndRespond(input) {
  const fields = ["text", "body", "sender", "receiver", "cc", "bcc", "subject"];
  const email = {};
  for (const field of fields) {
    if (input[field] !== undefined && typeof input[field] !== "string") {
      throw new TypeError(`Email ${field} must be text.`);
    }
    email[field] = input[field] || "";
  }
  const totalCharacters = fields.reduce((sum, field) => sum + email[field].length, 0);
  if (!totalCharacters) throw new TypeError("Email content was empty.");
  if (totalCharacters > 1000000) throw new RangeError("Email content exceeds the 1 MB analysis limit.");

  let inferenceUnavailable = "";
  try {
    await ensureTextInferenceDocument();
  } catch (error) {
    inferenceUnavailable = error.message || "Offscreen email inference is unavailable.";
    console.error(inferenceUnavailable);
    emailModelAvailable = false;
    emailModelStatusKnown = true;
  }

  const hash = await hashEmail(email);
  const cacheKey = `${EMAIL_CACHE_PREFIX}${hash}`;
  const cached = (await chrome.storage.local.get(cacheKey))[cacheKey];
  if (cached && emailModelStatusKnown && Date.now() - cached.createdAt <= EMAIL_CACHE_TTL_MS &&
      cached.result.model_available === emailModelAvailable) {
    return cached.result;
  }
  if (cached) await chrome.storage.local.remove(cacheKey);
  if (inFlightEmailScans.has(hash)) return inFlightEmailScans.get(hash);

  const analysis = (async () => {
    // Concurrent early-dispatch for cloud community threat intelligence
    const cloudEmailPromise = (async () => {
      try {
        if (typeof chrome === "undefined" || typeof fetch !== "function") return null;
        const cloudUrl = await getEffectiveBackendUrl();
        if (!cloudUrl) return null;
        const isLocalhost = /^https?:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/i.test(cloudUrl);
        if (!cloudUrl.startsWith("https://") && !isLocalhost) return null;

        const controller = typeof AbortController === "function" ? new AbortController() : null;
        const timeoutId = controller ? setTimeout(() => controller.abort(), 2000) : null;
        const stored = await chrome.storage.local.get(["safeinbox_auth"]);
        const authHeaders = await getAuthHeader();
        const fetchHeaders = { "Content-Type": "application/json", ...authHeaders };
        if (stored && stored.safeinbox_auth && stored.safeinbox_auth.token) {
          fetchHeaders["Authorization"] = `Bearer ${stored.safeinbox_auth.token}`;
        }
        const resp = await fetch(`${cloudUrl}/api/v1/scan/email`, {
          method: "POST",
          headers: fetchHeaders,
          body: JSON.stringify({
            subject: email.subject || "",
            body: email.body || email.text || "",
            sender: email.sender || ""
          }),
          signal: controller ? controller.signal : undefined
        });
        if (timeoutId) clearTimeout(timeoutId);
        if (resp.ok) return await resp.json();
        return null;
      } catch {
        return null;
      }
    })();

    let result = null;
    let analysisWarning = "";
    try {
      if (!inferenceUnavailable) result = await requestEmailInference(email);
      if (result) {
        emailModelAvailable = Boolean(result.model_available);
        emailModelStatusKnown = true;
      }
    } catch (error) {
      analysisWarning = `ONNX email inference failed; heuristic analysis was used: ${error.message}`;
      console.error(analysisWarning);
    }
    if (!result) {
      const parsed = EmailTextParser.analyzeEmailText(email);
      const { normalized_text, body_text, ...publicResult } = parsed;
      result = publicResult;
      if (analysisWarning || inferenceUnavailable) {
        result.analysis_note = analysisWarning || `Heuristic-only result; ${inferenceUnavailable}`;
      }
    }

    // Await the concurrently dispatched cloud community threat intelligence
    try {
      const cloudData = await cloudEmailPromise;
      if (cloudData) {
        if (cloudData.community_intel) {
          result.community_intel = cloudData.community_intel;
        }
        if (cloudData.community_intel && cloudData.community_intel.flagged) {
          result.risk_score = Math.max(result.risk_score || 0, 75);
          if (result.risk_level === "SAFE" || result.risk_level === "LOW") {
            result.risk_level = "HIGH";
          }
          if (!Array.isArray(result.threat_vectors)) result.threat_vectors = [];
          if (!result.threat_vectors.includes("COMMUNITY_CROWD_THREAT")) {
            result.threat_vectors.push("COMMUNITY_CROWD_THREAT");
          }
          if (!Array.isArray(result.evidence)) result.evidence = [];
          const alreadyHasCrowdEv = result.evidence.some(e => e.rule_id === "COMMUNITY_CROWD_THREAT");
          if (!alreadyHasCrowdEv) {
            result.evidence.unshift({
              rule_id: "COMMUNITY_CROWD_THREAT",
              severity: "HIGH",
              indicator: "community_threat_consensus",
              evidence: cloudData.community_intel.message || `${cloudData.community_intel.threat_count} users reported this email template as a threat.`
            });
          }
        }
      }
    } catch {
      // Non-blocking: local heuristics and models remain completely reliable offline
    }

    result = removeEmailIdentity(result);
    await chrome.storage.local.set({ [cacheKey]: { createdAt: Date.now(), result } });
    const items = await chrome.storage.local.get(null);
    const entries = Object.entries(items)
      .filter(([key, value]) => key.startsWith(EMAIL_CACHE_PREFIX) && value && value.createdAt)
      .sort((left, right) => left[1].createdAt - right[1].createdAt);
    const removeKeys = entries
      .filter(([, value]) => Date.now() - value.createdAt > EMAIL_CACHE_TTL_MS)
      .map(([key]) => key);
    removeKeys.push(...entries.slice(0, Math.max(entries.length - MAX_EMAIL_CACHE_ENTRIES, 0)).map(([key]) => key));
    if (removeKeys.length) await chrome.storage.local.remove(Array.from(new Set(removeKeys)));
    return result;
  })();
  inFlightEmailScans.set(hash, analysis);
  try {
    return await analysis;
  } finally {
    inFlightEmailScans.delete(hash);
  }
}

async function hashUrl(url) {
  const bytes = new TextEncoder().encode(url);
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("");
}

async function readCachedResult(key) {
  const entry = (await chrome.storage.local.get(key))[key];
  if (!entry || Date.now() - entry.createdAt > CACHE_TTL_MS) {
    if (entry) await chrome.storage.local.remove(key);
    return null;
  }
  if (modelAvailable && !entry.result.modelAvailable) return null;
  if (inferencePort && !inferenceWorkerReady && !entry.result.modelAvailable) return null;
  return entry.result;
}

async function writeCachedResult(key, result) {
  await chrome.storage.local.set({ [key]: { createdAt: Date.now(), result } });
  const allItems = await chrome.storage.local.get(null);
  const cacheEntries = Object.entries(allItems)
    .filter(([entryKey, value]) => entryKey.startsWith(CACHE_PREFIX) && value && value.createdAt)
    .sort((left, right) => left[1].createdAt - right[1].createdAt);
  const expiredOrExcess = cacheEntries.slice(0, Math.max(cacheEntries.length - MAX_CACHE_ENTRIES, 0));
  const expiredKeys = cacheEntries
    .filter(([, value]) => Date.now() - value.createdAt > CACHE_TTL_MS)
    .map(([entryKey]) => entryKey);
  const removeKeys = Array.from(new Set([...expiredOrExcess.map(([entryKey]) => entryKey), ...expiredKeys]));
  if (removeKeys.length) await chrome.storage.local.remove(removeKeys);
}

async function requestInference(parsed) {
  if (inferencePort && inferenceWorkerReady) {
    const requestId = `url-${Date.now()}-${++nextRequestId}`;
    return new Promise((resolve, reject) => {
      const timeout = setTimeout(() => {
        pendingInferences.delete(requestId);
        resolve(null);
      }, MODEL_RESPONSE_TIMEOUT_MS);
      pendingInferences.set(requestId, { resolve, reject, timeout });
      inferencePort.postMessage({ type: "INFER_URL", requestId, parsed });
    });
  }

  // Use offscreen document host when sidepanel port is not connected
  try {
    await ensureTextInferenceDocument();
    const requestId = `url-offscreen-${Date.now()}-${++nextRequestId}`;
    let timeoutId = null;
    const timeoutPromise = new Promise((resolve) => {
      timeoutId = setTimeout(() => resolve(null), MODEL_RESPONSE_TIMEOUT_MS);
    });
    const responsePromise = chrome.runtime.sendMessage({
      type: "RUN_URL_INFERENCE",
      requestId,
      parsed
    });
    const resp = await Promise.race([responsePromise, timeoutPromise]);
    if (timeoutId) clearTimeout(timeoutId);
    if (resp && resp.ok && resp.result) {
      modelAvailable = true;
      return resp.result;
    }
  } catch (err) {
    console.warn("Offscreen URL inference attempt:", err.message);
  }
  return null;
}

async function analyzeAndRespond(inputUrl) {
  if (typeof inputUrl !== "string" || !inputUrl.trim()) throw new TypeError("Enter a URL to analyze.");
  const parsed = UrlThreatParser.analyzeUrl(inputUrl);
  const hash = await hashUrl(parsed.canonicalUrl);
  const cacheKey = `${CACHE_PREFIX}${hash}`;
  const cached = await readCachedResult(cacheKey);
  if (cached) return cached;

  if (inFlightScans.has(hash)) return inFlightScans.get(hash);
  const analysis = (async () => {
    // Concurrent early-dispatch for cloud threat intelligence and community consensus
    const cloudUrlPromise = (async () => {
      try {
        if (typeof chrome === "undefined" || typeof fetch !== "function") return null;
        const cloudUrl = await getEffectiveBackendUrl();
        if (!cloudUrl) return null;
        const isLocalhost = /^https?:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/i.test(cloudUrl);
        if (!cloudUrl.startsWith("https://") && !isLocalhost) {
          throw new Error("Protocol violation: Remote backend must use HTTPS.");
        }
        const controller = typeof AbortController === "function" ? new AbortController() : null;
        const timeoutId = controller ? setTimeout(() => controller.abort(), 2000) : null;
        const stored = await chrome.storage.local.get(["safeinbox_auth"]);
        const authHeaders = await getAuthHeader();
        const fetchHeaders = { "Content-Type": "application/json", ...authHeaders };
        if (stored && stored.safeinbox_auth && stored.safeinbox_auth.token) {
          fetchHeaders["Authorization"] = `Bearer ${stored.safeinbox_auth.token}`;
        }
        const resp = await fetch(`${cloudUrl}/api/v1/scan/url`, {
          method: "POST",
          headers: fetchHeaders,
          body: JSON.stringify({ url: parsed.canonicalUrl }),
          signal: controller ? controller.signal : undefined
        });
        if (timeoutId) clearTimeout(timeoutId);
        if (resp.ok) return await resp.json();
        return null;
      } catch (err) {
        if (err && err.message && err.message.includes("Protocol violation")) throw err;
        return null;
      }
    })();

    let inferenceResult = null;
    let analysisWarning = "";
    try {
      inferenceResult = await requestInference(parsed);
    } catch (error) {
      analysisWarning = `ONNX inference was unavailable; heuristic analysis was used: ${error.message}`;
      console.error(analysisWarning);
    }
    const result = inferenceResult || {
      inputUrl: parsed.inputUrl,
      canonicalUrl: parsed.canonicalUrl,
      hostname: parsed.hostname,
      unicodeHostname: parsed.unicodeHostname,
      matchedBrand: parsed.matchedBrand,
      riskScore: parsed.heuristicRisk,
      heuristicRisk: parsed.heuristicRisk,
      modelRisk: null,
      modelAvailable: false,
      analysisWarning: analysisWarning || "No trained ONNX model inference was available; this result uses heuristic checks only.",
      attackTypes: parsed.attackTypes,
      findings: parsed.findings,
      metrics: parsed.metrics
    };

    // Await the concurrently dispatched cloud scan
    try {
      const cloudData = await cloudUrlPromise;
      if (cloudData) {
        result.cloudEnriched = true;
        result.cloudIntelligence = {
          source: "SafeInbox Cloud API",
          cached: Boolean(cloudData.cached),
          riskScore: cloudData.riskScore,
          riskLevel: cloudData.riskLevel,
          attackTypes: cloudData.attackTypes || []
        };
        if (typeof cloudData.riskScore === "number" && cloudData.riskScore > result.riskScore) {
          result.riskScore = cloudData.riskScore;
        }
        if (Array.isArray(cloudData.attackTypes)) {
          for (const at of cloudData.attackTypes) {
            if (!result.attackTypes.includes(at)) result.attackTypes.push(at);
          }
        }
        if (cloudData.community_intel) {
          result.community_intel = cloudData.community_intel;
        }
        if (Array.isArray(cloudData.findings)) {
          for (const f of cloudData.findings) {
            if (!result.findings.includes(f)) result.findings.push(f);
          }
        }
      }
    } catch (err) {
      if (err && err.message && err.message.includes("Protocol violation")) throw err;
    }

    await writeCachedResult(cacheKey, result);
    return result;
  })();
  inFlightScans.set(hash, analysis);
  try {
    return await analysis;
  } finally {
    inFlightScans.delete(hash);
  }
}

// =============================================================================
// 15-Day Security Digest Delivery & Scheduling System
// =============================================================================
function setupDigestAlarm() {
  if (typeof chrome !== "undefined" && chrome.alarms) {
    chrome.alarms.get(DIGEST_ALARM_NAME, (alarm) => {
      if (!alarm) {
        chrome.alarms.create(DIGEST_ALARM_NAME, { periodInMinutes: 360 }); // Check every 6 hours
      }
    });
  }
}

if (typeof chrome !== "undefined" && chrome.alarms && chrome.alarms.onAlarm) {
  chrome.alarms.onAlarm.addListener((alarm) => {
    if (alarm && alarm.name === DIGEST_ALARM_NAME) {
      dispatch15DayDigestNow({ force: false, isAutomatic: true }).catch((err) => {
        console.warn("SafeInbox automated 15-day digest dispatch check:", err);
      });
    }
  });
}

function escapeHtmlDigest(str) {
  return String(str ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function generateLocalDigestHtml(userEmail, userName, periodStart, periodEnd, records, urlClicks = [], userIndexId = null) {
  const safeEmail = escapeHtmlDigest(userEmail || "user@safeinbox.local");
  const safeName = escapeHtmlDigest(userName || "SafeInbox User");
  const safeIndexId = escapeHtmlDigest(userIndexId || ("SAFE-IDX-" + (safeEmail.replace(/[^a-zA-Z0-9]/g, "").slice(0, 12).toUpperCase().padEnd(12, "0"))));
  const totalEmails = records.length;
  const threats = records.filter(r => (r.composite_risk >= 35) || ["HIGH", "CRITICAL", "MEDIUM"].includes(r.risk_level));
  const threatCount = threats.length;
  const safeCount = totalEmails - threatCount;

  // Aggregate all URL clicks from explicit urlClicks and individual email clicked_urls
  const seenClickKeys = new Set();
  const aggregatedClicks = [];

  (Array.isArray(urlClicks) ? urlClicks : []).forEach(c => {
    const key = `${c.url}|${c.timestamp}`;
    if (!seenClickKeys.has(key)) {
      seenClickKeys.add(key);
      aggregatedClicks.push(c);
    }
  });

  records.forEach(r => {
    if (Array.isArray(r.clicked_urls)) {
      r.clicked_urls.forEach(c => {
        const key = `${c.url}|${c.timestamp}`;
        if (!seenClickKeys.has(key)) {
          seenClickKeys.add(key);
          aggregatedClicks.push({
            url: c.url,
            defanged: c.defanged,
            risk_score: c.risk_score,
            risk_level: c.risk_level,
            timestamp: c.timestamp,
            proceeded: c.proceeded !== false,
            email_subject: r.subject || "(Email Link)",
            sender: r.sender || "Webmail Sender"
          });
        }
      });
    }
  });

  const totalClicks = aggregatedClicks.length;

  let cardsHtml = "";
  if (records.length === 0) {
    cardsHtml = `
      <div style="background:#0f172a;border:1px solid #1e293b;border-radius:10px;padding:24px;text-align:center;color:#94a3b8;font-size:14px;">
        No webmail scan activity recorded during this 15-day time-slab.
      </div>
    `;
  } else {
    records.forEach((rec, idx) => {
      const isThreat = (rec.composite_risk >= 35) || ["HIGH", "CRITICAL", "MEDIUM"].includes(rec.risk_level);
      const badgeColor = rec.composite_risk >= 60 ? "#ef4444" : (rec.composite_risk >= 35 ? "#f59e0b" : "#10b981");
      const badgeBg = rec.composite_risk >= 60 ? "#450a0a" : (rec.composite_risk >= 35 ? "#451a03" : "#064e3b");

      let clicksHtml = "";
      if (Array.isArray(rec.clicked_urls) && rec.clicked_urls.length > 0) {
        let items = "";
        rec.clicked_urls.forEach(c => {
          const cThreat = (c.risk_score >= 35) || ["SUSPICIOUS", "MALICIOUS", "THREAT", "HIGH", "CRITICAL"].includes(c.risk_level);
          const cColor = cThreat ? "#ef4444" : "#10b981";
          const cDefanged = c.defanged || String(c.url || "").replace(/\./g, "[.]");
          items += `
            <div style="background:#090d16;border:1px solid #1e293b;border-radius:6px;padding:8px 12px;margin-top:6px;font-size:12px;display:flex;justify-content:space-between;align-items:center;">
              <span style="font-family:monospace;color:#38bdf8;word-break:break-all;">${escapeHtmlDigest(cDefanged)}</span>
              <span style="color:${cColor};font-weight:bold;margin-left:10px;white-space:nowrap;">Risk: ${Math.round(c.risk_score || 0)}/100</span>
            </div>
          `;
        });
        clicksHtml = `
          <div style="margin-top:12px;padding-top:10px;border-top:1px dashed #334155;">
            <div style="font-size:12px;font-weight:bold;color:#f8fafc;margin-bottom:4px;">
              🔗 URL Clicks in this email (${rec.clicked_urls.length}):
            </div>
            ${items}
          </div>
        `;
      } else {
        clicksHtml = `
          <div style="margin-top:10px;font-size:12px;color:#64748b;font-style:italic;">
            No links were clicked in this email.
          </div>
        `;
      }

      let vectorsBadge = "";
      if (Array.isArray(rec.threat_vectors) && rec.threat_vectors.length > 0) {
        vectorsBadge = `
          <div style="margin-top:8px;">
            <span style="font-size:11px;color:#cbd5e1;">Vectors: </span>
            ${rec.threat_vectors.map(v => `<span style="background:#1e293b;color:#fca5a5;padding:2px 6px;border-radius:4px;font-size:11px;margin-right:4px;">${escapeHtmlDigest(v)}</span>`).join(" ")}
          </div>
        `;
      }

      cardsHtml += `
        <div style="background:#0f172a;border:1px solid ${isThreat ? '#991b1b' : '#1e293b'};border-radius:10px;padding:18px;margin-bottom:16px;">
          <div style="display:flex;justify-content:space-between;align-items:flex-start;border-bottom:1px solid #1e293b;padding-bottom:10px;margin-bottom:10px;">
            <div>
              <span style="font-size:15px;font-weight:bold;color:#f8fafc;">#${idx + 1}. ${escapeHtmlDigest(rec.subject || '(No Subject)')}</span>
            </div>
            <span style="background:${badgeBg};color:${badgeColor};border:1px solid {badgeColor};padding:3px 10px;border-radius:12px;font-size:12px;font-weight:bold;white-space:nowrap;">
              ML Score: ${Math.round(rec.composite_risk || 0)}/100 (${escapeHtmlDigest(rec.risk_level || 'SAFE')})
            </span>
          </div>
          <table style="width:100%;font-size:13px;color:#cbd5e1;border-collapse:collapse;margin-bottom:8px;">
            <tr>
              <td style="padding:3px 0;width:110px;color:#94a3b8;font-weight:600;">Sender:</td>
              <td style="padding:3px 0;color:#f1f5f9;font-weight:500;">${escapeHtmlDigest(rec.sender || 'Unknown')}</td>
            </tr>
            <tr>
              <td style="padding:3px 0;color:#94a3b8;font-weight:600;">Receiver:</td>
              <td style="padding:3px 0;color:#f1f5f9;font-weight:500;">${escapeHtmlDigest(rec.receiver || 'Current User')}</td>
            </tr>
            <tr>
              <td style="padding:3px 0;color:#94a3b8;font-weight:600;">Time-Slab:</td>
              <td style="padding:3px 0;color:#94a3b8;">${escapeHtmlDigest(rec.time_slab || rec.date_iso || 'Recorded')}</td>
            </tr>
            <tr>
              <td style="padding:3px 0;color:#94a3b8;font-weight:600;">ML Breakdown:</td>
              <td style="padding:3px 0;color:#94a3b8;">Text Threat: <strong style="color:#f8fafc;">${Math.round(rec.text_threat_score || 0)}%</strong> | URL Threat: <strong style="color:#f8fafc;">${Math.round(rec.url_threat_score || 0)}%</strong></td>
            </tr>
          </table>
          ${vectorsBadge}
          ${clicksHtml}
        </div>
      `;
    });
  }

  // Render dedicated 15-day URL click history section
  let urlClicksHtml = "";
  if (aggregatedClicks.length === 0) {
    urlClicksHtml = `
      <div style="background:#0f172a;border:1px solid #1e293b;border-radius:10px;padding:20px;text-align:center;color:#94a3b8;font-size:13px;">
        No hyperlink clicks were performed in webmail during this 15-day audit period.
      </div>
    `;
  } else {
    aggregatedClicks.forEach((click, cIdx) => {
      const cThreat = (click.risk_score >= 35) || ["SUSPICIOUS", "MALICIOUS", "THREAT", "HIGH", "CRITICAL"].includes(click.risk_level);
      const cBadgeColor = click.risk_score >= 60 ? "#ef4444" : (click.risk_score >= 35 ? "#f59e0b" : "#10b981");
      const cBadgeBg = click.risk_score >= 60 ? "#450a0a" : (click.risk_score >= 35 ? "#451a03" : "#064e3b");
      const cBorder = cThreat ? "#991b1b" : "#1e293b";
      const cDefanged = click.defanged || escapeHtmlDigest(String(click.url || "").replace(/\./g, "[.]"));
      const cTime = click.timestamp ? String(click.timestamp) : "Recorded";
      const cContext = click.email_subject || click.sender || "(Webmail Link)";
      const cActionText = click.proceeded !== false ? "✓ Proceeded" : "✋ Blocked/Aborted";
      const cActionColor = click.proceeded !== false ? "#10b981" : "#ef4444";

      urlClicksHtml += `
        <div style="background:#0f172a;border:1px solid ${cBorder};border-radius:8px;padding:12px 16px;margin-bottom:10px;">
          <div style="display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:6px;">
            <div>
              <span style="font-size:11px;color:#94a3b8;font-weight:bold;margin-right:6px;">#${cIdx + 1}</span>
              <span style="font-family:monospace;color:#38bdf8;font-size:13px;word-break:break-all;">${escapeHtmlDigest(cDefanged)}</span>
            </div>
            <span style="background:${cBadgeBg};color:${cBadgeColor};border:1px solid ${cBadgeColor};padding:2px 8px;border-radius:10px;font-size:11px;font-weight:bold;white-space:nowrap;margin-left:10px;">
              ${Math.round(click.risk_score || 0)}/100 (${escapeHtmlDigest(click.risk_level || 'AUDITED')})
            </span>
          </div>
          <div style="display:flex;justify-content:space-between;align-items:center;font-size:12px;color:#94a3b8;flex-wrap:wrap;gap:6px;">
            <div>
              <span style="color:#64748b;">Email Context:</span> <strong style="color:#e2e8f0;">${escapeHtmlDigest(cContext)}</strong>
            </div>
            <div>
              <span style="color:#64748b;">Clicked At:</span> <span style="color:#cbd5e1;">${escapeHtmlDigest(cTime)}</span>
              <span style="margin-left:8px;padding:2px 6px;border-radius:4px;font-size:10px;background:#1e293b;color:${cActionColor};font-weight:600;">
                ${cActionText}
              </span>
            </div>
          </div>
        </div>
      `;
    });
  }

  return `<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>SafeInbox AI: 15-Day Security Audit Digest</title>
</head>
<body style="margin:0;padding:0;background:#030712;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;color:#f8fafc;">
  <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="background:#030712;padding:24px 0;">
    <tr>
      <td align="center">
        <table role="presentation" width="640" cellspacing="0" cellpadding="0" style="max-width:640px;width:100%;background:#090d16;border:1px solid #1e293b;border-radius:12px;overflow:hidden;">
          <tr>
            <td style="background:linear-gradient(135deg, #0284c7 0%, #0369a1 50%, #0f172a 100%);padding:28px 24px;text-align:left;">
              <div style="display:inline-block;background:rgba(255,255,255,0.15);padding:4px 10px;border-radius:20px;font-size:12px;font-weight:bold;color:#e0f2fe;margin-bottom:8px;">
                🛡️ 15-Day Security & Threat Audit
              </div>
              <h1 style="margin:0;font-size:22px;color:#ffffff;font-weight:800;letter-spacing:-0.5px;">
                SafeInbox AI Security Digest
              </h1>
              <p style="margin:6px 0 0 0;font-size:13px;color:#bae6fd;">
                Audit Window: <strong>${escapeHtmlDigest(periodStart)}</strong> &mdash; <strong>${escapeHtmlDigest(periodEnd)}</strong>
              </p>
            </td>
          </tr>
          <tr>
            <td style="background:#0f172a;border-bottom:1px solid #1e293b;padding:12px 24px;font-size:13px;color:#94a3b8;">
              Prepared exclusively for: <strong style="color:#f8fafc;">${safeName}</strong> (&lt;${safeEmail}&gt;)
              &nbsp;&bull;&nbsp; Index ID: <strong style="color:#FFA586;font-family:monospace;">${safeIndexId}</strong>
            </td>
          </tr>
          <tr>
            <td style="padding:24px;">
              <table width="100%" cellspacing="0" cellpadding="0" style="margin-bottom:24px;">
                <tr>
                  <td width="24%" style="background:#0f172a;border:1px solid #1e293b;border-radius:8px;padding:14px;text-align:center;">
                    <div style="font-size:20px;font-weight:bold;color:#f8fafc;">${totalEmails}</div>
                    <div style="font-size:11px;color:#94a3b8;margin-top:2px;">Emails Audited</div>
                  </td>
                  <td width="3%"></td>
                  <td width="23%" style="background:#0f172a;border:1px solid #065f46;border-radius:8px;padding:14px;text-align:center;">
                    <div style="font-size:20px;font-weight:bold;color:#10b981;">${safeCount}</div>
                    <div style="font-size:11px;color:#94a3b8;margin-top:2px;">Safe Emails</div>
                  </td>
                  <td width="3%"></td>
                  <td width="23%" style="background:#0f172a;border:1px solid #991b1b;border-radius:8px;padding:14px;text-align:center;">
                    <div style="font-size:20px;font-weight:bold;color:#ef4444;">${threatCount}</div>
                    <div style="font-size:11px;color:#94a3b8;margin-top:2px;">Threats Flagged</div>
                  </td>
                  <td width="3%"></td>
                  <td width="24%" style="background:#0f172a;border:1px solid #1e293b;border-radius:8px;padding:14px;text-align:center;">
                    <div style="font-size:20px;font-weight:bold;color:#38bdf8;">${totalClicks}</div>
                    <div style="font-size:11px;color:#94a3b8;margin-top:2px;">URL Clicks</div>
                  </td>
                </tr>
              </table>

              <!-- Section 1: Email Threat Reports -->
              <div style="font-size:16px;font-weight:bold;color:#f8fafc;margin-bottom:14px;display:flex;align-items:center;">
                📋 15-Day Email Security Reports (Sender, Receiver &amp; ML Threat Scores)
              </div>
              ${cardsHtml}

              <!-- Section 2: Comprehensive URL Click History -->
              <div style="font-size:16px;font-weight:bold;color:#f8fafc;margin-top:24px;margin-bottom:14px;display:flex;align-items:center;">
                🔗 15-Day Webmail URL Click Audit Trail (${totalClicks})
              </div>
              ${urlClicksHtml}

              <!-- Guidance Box -->
              <div style="background:#0c192c;border:1px solid #1e3a8a;border-radius:8px;padding:16px;margin-top:24px;">
                <div style="font-size:13px;font-weight:bold;color:#60a5fa;margin-bottom:4px;">
                  💡 Autonomous Security Recommendation:
                </div>
                <div style="font-size:12px;color:#93c5fd;line-height:1.5;">
                  SafeInbox AI inspects all incoming emails and link destinations using local ONNX neural networks. If you see high ML risk scores or unrecognized sender domains above, avoid entering credentials or running file attachments.
                </div>
              </div>
            </td>
          </tr>
          <tr>
            <td style="background:#030712;border-top:1px solid #1e293b;padding:20px 24px;text-align:center;font-size:11px;color:#64748b;">
              <p style="margin:0 0 4px 0;">SafeInbox AI &bull; Autonomous Client-Side Threat Intelligence</p>
              <p style="margin:0 0 4px 0;">This scheduled report is automatically generated every 15 days for your account. Confidential &amp; Encrypted.</p>
              <p style="margin:4px 0 0 0;color:#94a3b8;font-size:11px;">
                ⏳ <strong>15-Day Privacy Lifecycle:</strong> Scanned email audit records and URL click history are retained for 15 days, after which they are permanently cleared from our database.
              </p>
            </td>
          </tr>
        </table>
      </td>
    </tr>
  </table>
</body>
</html>`;
}

async function get15DayDigestData() {
  if (typeof chrome === "undefined" || !chrome.storage || !chrome.storage.local) {
    return {
      userEmail: "guest@safeinbox.local",
      userName: "Guest Analyst",
      periodStart: new Date(Date.now() - DIGEST_INTERVAL_MS).toISOString().slice(0, 10),
      periodEnd: new Date().toISOString().slice(0, 10),
      totalEmails: 0,
      threatCount: 0,
      clickCount: 0,
      records: [],
      urlClicks: []
    };
  }

  return new Promise((resolve) => {
    chrome.storage.local.get([
      DIGEST_RECORDS_KEY,
      DIGEST_LAST_SENT_KEY,
      "webmail_url_clicks",
      "safeinbox_auth",
      "safeinbox_user_session"
    ], (res) => {
      const now = Date.now();
      const cutoff = now - DIGEST_INTERVAL_MS;

      const rawRecords = Array.isArray(res && res[DIGEST_RECORDS_KEY]) ? res[DIGEST_RECORDS_KEY] : [];
      // Rolling 15-day window: filter email records within past 15 days
      const records = rawRecords.filter(r => (r.timestamp || now) >= cutoff);

      const auth = res && res.safeinbox_auth;
      const session = res && res.safeinbox_user_session;
      const userEmail = (auth && auth.user && auth.user.email) ||
                        (session && session.email) ||
                        (auth && auth.email) ||
                        "guest@safeinbox.local";
      const userIndexId = (auth && auth.user && auth.user.index_id) ||
                          (auth && auth.index_id) ||
                          null;
      const userToken = (auth && auth.token) ||
                        (session && session.token) ||
                        null;
      const userName = (auth && auth.user && auth.user.full_name) ||
                       (session && session.name) ||
                       "SafeInbox User";
      const lastSent = (res && res[DIGEST_LAST_SENT_KEY]) || cutoff;
      const periodStart = new Date(lastSent).toISOString().slice(0, 10);
      const periodEnd = new Date(now).toISOString().slice(0, 10);

      const threatCount = records.filter(r => (r.composite_risk >= 35) || ["HIGH", "CRITICAL", "MEDIUM"].includes(r.risk_level)).length;

      // Aggregate all URL clicks within the 15-day window
      const storedClicks = Array.isArray(res && res["webmail_url_clicks"]) ? res["webmail_url_clicks"] : [];
      const validStoredClicks = storedClicks.filter(c => (c.timestamp || now) >= cutoff);

      const seenClickKeys = new Set();
      const unifiedClicks = [];

      // 1. From webmail_url_clicks store
      validStoredClicks.forEach(c => {
        const key = `${c.url}|${c.timestamp || c.date_iso}`;
        if (!seenClickKeys.has(key)) {
          seenClickKeys.add(key);
          unifiedClicks.push({
            url: c.url,
            defanged: c.defanged || escapeHtmlDigest(String(c.url || "").replace(/\./g, "[.]")),
            risk_score: typeof c.risk_score === "number" ? c.risk_score : (c.riskScore || 0),
            risk_level: c.risk_level || c.riskLevel || "AUDITED",
            timestamp: c.date_iso || (c.timestamp ? new Date(c.timestamp).toISOString() : new Date().toISOString()),
            proceeded: c.proceeded !== false,
            email_subject: c.email_subject || c.emailSubject || "(Webmail Link)",
            sender: c.sender || "Webmail Sender",
            source: c.source || "email_body_link"
          });
        }
      });

      // 2. From individual email records' clicked_urls
      records.forEach(r => {
        if (Array.isArray(r.clicked_urls)) {
          r.clicked_urls.forEach(c => {
            const key = `${c.url}|${c.timestamp}`;
            if (!seenClickKeys.has(key)) {
              seenClickKeys.add(key);
              unifiedClicks.push({
                url: c.url,
                defanged: c.defanged || escapeHtmlDigest(String(c.url || "").replace(/\./g, "[.]")),
                risk_score: typeof c.risk_score === "number" ? c.risk_score : 0,
                risk_level: c.risk_level || "AUDITED",
                timestamp: c.timestamp || r.date_iso || new Date().toISOString(),
                proceeded: c.proceeded !== false,
                email_subject: r.subject || "(Email Link)",
                sender: r.sender || "Webmail Sender",
                source: "email_body_link"
              });
            }
          });
        }
      });

      const clickCount = unifiedClicks.length;

      resolve({
        userEmail,
        userIndexId,
        userToken,
        userName,
        periodStart,
        periodEnd,
        totalEmails: records.length,
        threatCount,
        clickCount,
        nextDispatchDue: lastSent + DIGEST_INTERVAL_MS,
        records,
        urlClicks: unifiedClicks
      });
    });
  });
}

async function preview15DayDigest(targetEmail = null) {
  const data = await get15DayDigestData();
  const effectiveEmail = targetEmail || data.userEmail;
  const html = generateLocalDigestHtml(
    effectiveEmail,
    data.userName,
    data.periodStart,
    data.periodEnd,
    data.records,
    data.urlClicks,
    data.userIndexId
  );
  return {
    userEmail: effectiveEmail,
    periodStart: data.periodStart,
    periodEnd: data.periodEnd,
    totalEmails: data.totalEmails,
    threatCount: data.threatCount,
    clickCount: data.clickCount,
    html
  };
}

async function dispatch15DayDigestNow({ force = false, targetEmail = null, isAutomatic = false } = {}) {
  const data = await get15DayDigestData();
  const effectiveEmail = targetEmail || data.userEmail;

  // If automatic and 15 days haven't passed, skip
  if (isAutomatic && !force && Date.now() < data.nextDispatchDue) {
    return {
      success: true,
      skipped: true,
      reason: "15-day interval has not elapsed yet.",
      nextDue: data.nextDispatchDue
    };
  }

  // Get active backend URL
  const cloudUrl = await getEffectiveBackendUrl();

  // Zero-Knowledge Client-Side Encryption of Digest Data
  let isEncrypted = false;
  let encryptedDigestPayload = null;
  if (typeof SafeInboxCrypto !== "undefined" && (data.userToken || effectiveEmail)) {
    try {
      const zkKey = await SafeInboxCrypto.deriveZeroKnowledgeKey(
        data.userToken || effectiveEmail,
        data.userIndexId || effectiveEmail
      );
      const auditSummary = {
        records: data.records,
        url_clicks: data.urlClicks
      };
      encryptedDigestPayload = await SafeInboxCrypto.encryptZeroKnowledge(auditSummary, zkKey);
      isEncrypted = true;
    } catch (cryptoErr) {
      console.warn("Client-side digest zero-knowledge encryption fallback:", cryptoErr);
    }
  }

  const payload = {
    user_email: effectiveEmail,
    user_index_id: data.userIndexId,
    user_name: data.userName,
    period_start: data.periodStart,
    period_end: data.periodEnd,
    records: data.records,
    url_clicks: data.urlClicks,
    is_encrypted: isEncrypted,
    encrypted_payload: encryptedDigestPayload
  };

  let dispatchMode = "local_autonomous";
  let deliveryNote = "Compiled and generated locally (autonomous extension mode).";
  let renderedHtml = "";
  let purgedCount = 0;

  if (cloudUrl && typeof fetch === "function") {
    try {
      const authHeaders = await getAuthHeader();
      const reqHeaders = { "Content-Type": "application/json", ...authHeaders };

      const resp = await fetch(`${cloudUrl}/api/v1/digest/send`, {
        method: "POST",
        headers: reqHeaders,
        body: JSON.stringify(payload)
      });
      if (resp.ok) {
        const json = await resp.json();
        dispatchMode = json.dispatch_mode || "apps_script";
        deliveryNote = json.message || "Delivered via cloud backend";
        renderedHtml = json.preview_html || "";
        purgedCount = json.purged_records || 0;
      }
    } catch (e) {
      console.warn("Backend digest send failed, falling back to local digest generation:", e);
    }
  }

  if (!renderedHtml) {
    renderedHtml = generateLocalDigestHtml(
      effectiveEmail,
      data.userName,
      data.periodStart,
      data.periodEnd,
      data.records,
      data.urlClicks,
      data.userIndexId
    );
  }

  // 15-Day Local Storage Retention Purge: remove records and clicks older than 15 days from local storage
  const cutoff = Date.now() - DIGEST_INTERVAL_MS;
  const prunedRecords = data.records.filter(r => (r.timestamp || Date.now()) >= cutoff);
  const prunedClicks = (data.urlClicks || []).filter(c => {
    const ts = typeof c.timestamp === "number" ? c.timestamp : Date.parse(c.timestamp);
    return isNaN(ts) || ts >= cutoff;
  });

  // Update last sent time and dispatch history
  await new Promise(r => {
    chrome.storage.local.get([DIGEST_HISTORY_KEY], (histRes) => {
      const history = Array.isArray(histRes && histRes[DIGEST_HISTORY_KEY]) ? histRes[DIGEST_HISTORY_KEY] : [];
      history.push({
        timestamp: Date.now(),
        user_email: effectiveEmail,
        period_start: data.periodStart,
        period_end: data.periodEnd,
        total_emails: data.totalEmails,
        threat_count: data.threatCount,
        click_count: data.clickCount,
        purged_records: purgedCount,
        dispatch_mode: dispatchMode,
        delivery_note: deliveryNote
      });
      const trimmedHistory = history.slice(-20);
      chrome.storage.local.set({
        [DIGEST_LAST_SENT_KEY]: Date.now(),
        [DIGEST_HISTORY_KEY]: trimmedHistory,
        [DIGEST_RECORDS_KEY]: prunedRecords,
        "webmail_url_clicks": prunedClicks
      }, r);
    });
  });

  return {
    success: true,
    user_email: effectiveEmail,
    period: `${data.periodStart} to ${data.periodEnd}`,
    total_emails: data.totalEmails,
    threats_detected: data.threatCount,
    total_clicks: data.clickCount,
    purged_records: purgedCount,
    dispatch_mode: dispatchMode,
    delivery_note: deliveryNote,
    preview_html: renderedHtml
  };
}
