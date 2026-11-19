"use strict";

const pendingRequests = new Map();
let workerReadyResolve;
let workerFailure = null;
const workerReady = new Promise((resolve) => {
  workerReadyResolve = resolve;
});

const worker = new Worker(chrome.runtime.getURL("src/ml/textMlWorker.js"));

worker.onmessage = ({ data }) => {
  if (data.type === "READY") {
    chrome.runtime.sendMessage({
      type: "EMAIL_TEXT_MODEL_STATUS",
      modelAvailable: Boolean(data.modelAvailable),
      error: data.error || ""
    }, () => {
      if (chrome.runtime.lastError) {
        console.warn("SafeInbox AI could not report email model status:", chrome.runtime.lastError.message);
      }
    });
    workerReadyResolve({ ok: true, modelAvailable: Boolean(data.modelAvailable) });
    return;
  }
  if (data.type !== "EMAIL_TEXT_RESULT") return;
  const respond = pendingRequests.get(data.requestId);
  if (!respond) return;
  pendingRequests.delete(data.requestId);
  respond(data.error
    ? { ok: false, error: data.error }
    : { ok: true, result: data.result });
};

worker.onerror = (error) => {
  const message = error.message || "Email ONNX worker failed to start.";
  workerFailure = message;
  workerReadyResolve({ ok: false, error: message });
  for (const respond of pendingRequests.values()) respond({ ok: false, error: message });
  pendingRequests.clear();
  console.error("SafeInbox AI email ONNX worker error:", message);
};

// URL ONNX worker management in offscreen host
const pendingUrlRequests = new Map();
let urlWorkerReadyResolve;
let urlWorkerFailure = null;
const urlWorkerReady = new Promise((resolve) => {
  urlWorkerReadyResolve = resolve;
});

let urlWorker = null;
try {
  urlWorker = new Worker(chrome.runtime.getURL("src/ml/workers/urlInferenceWorker.js"));
  urlWorker.onmessage = ({ data }) => {
    if (data.type === "READY") {
      chrome.runtime.sendMessage({
        type: "URL_MODEL_STATUS",
        modelAvailable: Boolean(data.modelAvailable),
        error: data.modelError || ""
      }, () => {
        if (chrome.runtime.lastError) {}
      });
      urlWorkerReadyResolve({ ok: true, modelAvailable: Boolean(data.modelAvailable) });
      return;
    }
    const respond = pendingUrlRequests.get(data.requestId);
    if (!respond) return;
    pendingUrlRequests.delete(data.requestId);
    respond(data.error ? { ok: false, error: data.error } : { ok: true, result: data.result });
  };
  urlWorker.onerror = (error) => {
    const message = error.message || "URL ONNX worker failed to start.";
    urlWorkerFailure = message;
    urlWorkerReadyResolve({ ok: false, error: message });
    for (const respond of pendingUrlRequests.values()) respond({ ok: false, error: message });
    pendingUrlRequests.clear();
    console.error("SafeInbox AI URL ONNX worker error:", message);
  };
} catch (e) {
  urlWorkerFailure = e.message;
  urlWorkerReadyResolve({ ok: false, error: e.message });
}

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (!message || typeof message !== "object") return false;

  if (message.type === "RUN_EMAIL_TEXT_INFERENCE") {
    if (typeof message.requestId !== "string" || !message.email) {
      sendResponse({ ok: false, error: "Invalid email text inference payload." });
      return false;
    }
    let timeoutId = null;
    workerReady.then((ready) => {
      if (!ready.ok || workerFailure) {
        sendResponse({ ok: false, error: workerFailure || ready.error || "Email text worker unavailable." });
        return;
      }
      timeoutId = setTimeout(() => {
        if (pendingRequests.has(message.requestId)) {
          pendingRequests.delete(message.requestId);
          try {
            sendResponse({ ok: false, error: "Email text inference timed out in host." });
          } catch (_) {}
        }
      }, 35000);
      pendingRequests.set(message.requestId, (response) => {
        if (timeoutId) clearTimeout(timeoutId);
        sendResponse(response);
      });
      worker.postMessage({
        type: "INFER_EMAIL_TEXT",
        requestId: message.requestId,
        email: message.email
      });
    }).catch((error) => {
      if (timeoutId) clearTimeout(timeoutId);
      pendingRequests.delete(message.requestId);
      sendResponse({ ok: false, error: error.message || "Email inference host failed." });
    });
    return true;
  }

  if (message.type === "RUN_URL_INFERENCE") {
    if (typeof message.requestId !== "string" || !message.parsed) {
      sendResponse({ ok: false, error: "Invalid URL inference payload." });
      return false;
    }
    let timeoutId = null;
    urlWorkerReady.then((ready) => {
      if (!ready.ok || urlWorkerFailure || !urlWorker) {
        sendResponse({ ok: false, error: urlWorkerFailure || ready.error || "URL inference worker unavailable." });
        return;
      }
      timeoutId = setTimeout(() => {
        if (pendingUrlRequests.has(message.requestId)) {
          pendingUrlRequests.delete(message.requestId);
          try {
            sendResponse({ ok: false, error: "URL inference timed out in host." });
          } catch (_) {}
        }
      }, 15000);
      pendingUrlRequests.set(message.requestId, (response) => {
        if (timeoutId) clearTimeout(timeoutId);
        sendResponse(response);
      });
      urlWorker.postMessage({
        requestId: message.requestId,
        parsed: message.parsed
      });
    }).catch((error) => {
      if (timeoutId) clearTimeout(timeoutId);
      pendingUrlRequests.delete(message.requestId);
      sendResponse({ ok: false, error: error.message || "URL inference host failed." });
    });
    return true;
  }
  return false;
});
