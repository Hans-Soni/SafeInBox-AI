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

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (!message || message.type !== "RUN_EMAIL_TEXT_INFERENCE" ||
      typeof message.requestId !== "string" || !message.email) return false;

  let timeoutId = null;
  workerReady.then((ready) => {
    if (!ready.ok || workerFailure) {
      sendResponse({ ok: false, error: workerFailure || ready.error });
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
});
