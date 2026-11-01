"use strict";

importScripts("../../url/urlThreatParser.js");

let ort = null;
let sessionPromise = null;
let session = null;
let modelError = null;

try {
  importScripts("../../../vendor/ort.min.js");
  ort = self.ort || null;
  if (ort) {
    ort.env.wasm.wasmPaths = chrome.runtime.getURL("vendor/");
    ort.env.wasm.numThreads = 1;
  }
} catch (error) {
  modelError = `ONNX Runtime Web is not installed: ${error.message}`;
}

async function loadModel() {
  if (session) return session;
  if (sessionPromise) return sessionPromise;
  sessionPromise = (async () => {
    if (!ort) return null;
    const modelUrl = chrome.runtime.getURL("models/url-threat.onnx");
    const response = await fetch(modelUrl);
    if (!response.ok) throw new Error("No trained ONNX model found at models/url-threat.onnx.");
    session = await ort.InferenceSession.create(modelUrl, {
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
  const data = Array.from(output[outputName].data);
  if (!data.length) throw new Error("The ONNX model returned an empty output tensor.");
  if (data.length === 1) {
    const value = Number(data[0]);
    return value >= 0 && value <= 1 ? value : sigmoid(value);
  }
  const values = data.slice(-2).map(Number);
  if (values.every((value) => value >= 0 && value <= 1) && Math.abs(values[0] + values[1] - 1) < 0.02) {
    return values[1];
  }
  const max = Math.max(...values);
  const exponents = values.map((value) => Math.exp(value - max));
  return exponents[1] / exponents.reduce((sum, value) => sum + value, 0);
}

async function infer(parsed) {
  const activeSession = await loadModel();
  let modelRisk = null;
  if (activeSession) {
    try {
      const featureInput = activeSession.inputNames.find((name) => /feature/i.test(name)) || activeSession.inputNames[0];
      const characterInput = activeSession.inputNames.find((name) => /char|token/i.test(name)) ||
        activeSession.inputNames.find((name) => name !== featureInput);
      const feeds = {
        [featureInput]: new ort.Tensor("float32", Float32Array.from(parsed.featureVector), [1, parsed.featureVector.length]),
        [characterInput]: new ort.Tensor("int32", Int32Array.from(parsed.charTensor), [1, parsed.charTensor.length])
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
  self.postMessage({
    type: "READY",
    modelAvailable: Boolean(activeSession),
    modelError,
    runtimeAvailable: Boolean(ort)
  });
});
