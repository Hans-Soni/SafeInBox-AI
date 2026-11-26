"use strict";

function getResourceUrl(relativePath) {
  if (typeof chrome !== "undefined" && chrome && chrome.runtime && typeof chrome.runtime.getURL === "function") {
    try {
      return chrome.runtime.getURL(relativePath);
    } catch (_) {}
  }
  const cleanPath = String(relativePath || "").replace(/^\/+/, "");
  if (typeof self !== "undefined" && self.location) {
    if (self.location.origin && self.location.origin !== "null" && self.location.origin !== "undefined") {
      return `${self.location.origin.replace(/\/+$/, "")}/${cleanPath}`;
    }
    if (self.location.href) {
      try {
        return new URL(cleanPath, self.location.href).href;
      } catch (_) {}
    }
  }
  return cleanPath;
}

try {
  try {
    importScripts(getResourceUrl("src/url/urlThreatParser.js"));
  } catch (_) {
    importScripts("../../url/urlThreatParser.js");
  }
} catch (e) {
  // parser load error
}

let sessionPromise = null;
let session = null;
let modelError = null;

try {
  try {
    importScripts(getResourceUrl("vendor/ort.min.js"));
  } catch (_) {
    importScripts("../../../vendor/ort.min.js");
  }
  const activeOrt = (typeof self !== "undefined" && self.ort) || (typeof ort !== "undefined" ? ort : null);
  if (activeOrt) {
    if (typeof self !== "undefined" && !self.ort) self.ort = activeOrt;
    activeOrt.env.wasm.wasmPaths = getResourceUrl("vendor/");
    activeOrt.env.wasm.numThreads = 1;
    activeOrt.env.wasm.proxy = false;
  }
} catch (error) {
  modelError = `ONNX Runtime Web is not installed: ${error.message}`;
}

const TEMPERATURE_URL = 1.0586;

async function loadModel() {
  if (session) return session;
  if (sessionPromise) return sessionPromise;
  sessionPromise = (async () => {
    const activeOrt = (typeof self !== "undefined" && self.ort) || (typeof ort !== "undefined" ? ort : null);
    if (!activeOrt) return null;
    const modelUrl = getResourceUrl("models/url-threat.onnx");
    const response = await fetch(modelUrl);
    if (!response.ok) throw new Error("No trained ONNX model found at models/url-threat.onnx.");
    const modelBuffer = typeof response.arrayBuffer === "function" ? await response.arrayBuffer() : modelUrl;
    const sessionInput = modelBuffer instanceof ArrayBuffer ? new Uint8Array(modelBuffer) : modelBuffer;
    session = await activeOrt.InferenceSession.create(sessionInput, {
      executionProviders: ["wasm"],
      graphOptimizationLevel: "all"
    });
    if (session.inputNames.length < 2) {
      session = null;
      throw new Error("The ONNX model must accept separate feature and character tensors.");
    }
    return session;
  })().catch((error) => {
    modelError = error.message;
    return null;
  });
  return sessionPromise;
}

function sigmoid(value) {
  return 1 / (1 + Math.exp(-value));
}

function extractModelProbability(output, outputName) {
  const data = output[outputName] && output[outputName].data;
  if (!data || !data.length) throw new Error("The ONNX model returned an empty output tensor.");
  if (data.length === 1) {
    const value = Number(data[0]);
    return value >= 0 && value <= 1 ? value : 1 / (1 + Math.exp(-value / TEMPERATURE_URL));
  }
  const len = data.length;
  // Apply calibrated temperature scaling on logits with zero-allocation softmax
  const l0 = Number(data[len - 2]) / TEMPERATURE_URL;
  const l1 = Number(data[len - 1]) / TEMPERATURE_URL;
  const maxL = l0 > l1 ? l0 : l1;
  const exp0 = Math.exp(l0 - maxL);
  const exp1 = Math.exp(l1 - maxL);
  return exp1 / (exp0 + exp1);
}

async function infer(parsed) {
  const activeSession = await loadModel();
  let modelRisk = null;
  if (activeSession) {
    try {
      const featureInput = activeSession.inputNames.find((name) => /feature/i.test(name)) || activeSession.inputNames[0];
      const characterInput = activeSession.inputNames.find((name) => /char|token/i.test(name)) ||
        activeSession.inputNames.find((name) => name !== featureInput);
      const activeOrt = (typeof self !== "undefined" && self.ort) || (typeof ort !== "undefined" ? ort : null);
      if (!activeOrt) throw new Error("ONNX Runtime is not available.");
      // Reuse existing TypedArrays directly to avoid garbage-collection overhead
      const featData = parsed.featureVector instanceof Float32Array ? parsed.featureVector : Float32Array.from(parsed.featureVector);
      const charData = parsed.charTensor instanceof Int32Array ? parsed.charTensor : Int32Array.from(parsed.charTensor);
      const feeds = {
        [featureInput]: new activeOrt.Tensor("float32", featData, [1, featData.length]),
        [characterInput]: new activeOrt.Tensor("int32", charData, [1, charData.length])
      };
      const output = await activeSession.run(feeds);
      modelRisk = extractModelProbability(output, activeSession.outputNames[0]);
    } catch (error) {
      session = null;
      sessionPromise = null;
      modelError = `ONNX inference failed; using heuristic scoring: ${error.message}`;
    }
  }

  const riskScore = modelRisk === null
    ? parsed.heuristicRisk
    : Math.max(parsed.heuristicRisk * 0.85, modelRisk * 0.65 + parsed.heuristicRisk * 0.35);
  const attackTypes = new Set(parsed.attackTypes);
  if (riskScore >= 0.45) attackTypes.add("PHISHING_SUSPECT");

  return {
    inputUrl: parsed.inputUrl,
    canonicalUrl: parsed.canonicalUrl,
    hostname: parsed.hostname,
    unicodeHostname: parsed.unicodeHostname,
    matchedBrand: parsed.matchedBrand,
    riskScore: Math.max(0, Math.min(1, riskScore)),
    heuristicRisk: parsed.heuristicRisk,
    modelRisk,
    modelAvailable: Boolean(session),
    modelError: modelError || undefined,
    attackTypes: Array.from(attackTypes),
    findings: parsed.findings,
    metrics: parsed.metrics
  };
}

self.onmessage = async (event) => {
  const { requestId, parsed } = event.data || {};
  if (!requestId || !parsed) return;
  try {
    self.postMessage({ requestId, result: await infer(parsed) });
  } catch (error) {
    self.postMessage({ requestId, error: error.message || "URL inference failed." });
  }
};

loadModel().then((activeSession) => {
  const activeOrt = (typeof self !== "undefined" && self.ort) || (typeof ort !== "undefined" ? ort : null);
  self.postMessage({
    type: "READY",
    modelAvailable: Boolean(activeSession),
    modelError,
    runtimeAvailable: Boolean(activeOrt)
  });
});
