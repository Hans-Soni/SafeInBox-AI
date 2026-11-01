"use strict";

importScripts("../url/urlThreatParser.js");
importScripts("../utils/textParser.js");

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

configureSidePanelBehavior();

chrome.runtime.onInstalled.addListener((details) => {
  configureSidePanelBehavior();
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

  if (message && message.type === "TEST_CLOUD_BACKEND") {
    testCloudBackend(message.url).then(
      (status) => sendResponse({ ok: true, status }),
      (error) => sendResponse({ ok: false, error: error.message || "Failed to reach cloud backend." })
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

function requestInference(parsed) {
  if (!inferencePort) return Promise.resolve(null);
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

async function analyzeAndRespond(inputUrl) {
  if (typeof inputUrl !== "string" || !inputUrl.trim()) throw new TypeError("Enter a URL to analyze.");
  const parsed = UrlThreatParser.analyzeUrl(inputUrl);
  const hash = await hashUrl(parsed.canonicalUrl);
  const cacheKey = `${CACHE_PREFIX}${hash}`;
  const cached = await readCachedResult(cacheKey);
  if (cached) return cached;

  if (inFlightScans.has(hash)) return inFlightScans.get(hash);
  const analysis = (async () => {
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

    // Optional Cloud Intelligence check if configured and enabled
    try {
      if (typeof chrome !== "undefined" && chrome.storage && chrome.storage.local && typeof fetch === "function") {
        const stored = await chrome.storage.local.get(["cloudBackendUrl", "cloudBackendEnabled", "safeinbox_auth"]);
        if (stored && stored.cloudBackendEnabled && typeof stored.cloudBackendUrl === "string" && stored.cloudBackendUrl.trim()) {
          const cloudUrl = stored.cloudBackendUrl.trim().replace(/\/+$/, "");
          const isLocalhost = /^https?:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/i.test(cloudUrl);
          if (!cloudUrl.startsWith("https://") && !isLocalhost) {
            // Reject non-HTTPS remote URL to prevent unencrypted traffic over the internet
            throw new Error("Protocol violation: Remote backend must use HTTPS.");
          }
          const controller = typeof AbortController === "function" ? new AbortController() : null;
          const timeoutId = controller ? setTimeout(() => controller.abort(), 2500) : null;
          const fetchHeaders = { "Content-Type": "application/json" };
          if (stored.safeinbox_auth && stored.safeinbox_auth.token) {
            fetchHeaders["Authorization"] = `Bearer ${stored.safeinbox_auth.token}`;
          }
          const resp = await fetch(`${cloudUrl}/api/v1/scan/url`, {
            method: "POST",
            headers: fetchHeaders,
            body: JSON.stringify({ url: parsed.canonicalUrl }),
            signal: controller ? controller.signal : undefined
          });
          if (timeoutId) clearTimeout(timeoutId);
          if (resp.ok) {
            const cloudData = await resp.json();
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
            if (Array.isArray(cloudData.findings)) {
              for (const f of cloudData.findings) {
                if (!result.findings.includes(f)) result.findings.push(f);
              }
            }
          }
        }
      }
    } catch {
      // Non-blocking: local heuristics and models remain completely reliable
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
