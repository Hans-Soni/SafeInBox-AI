"use strict";

const MODEL_PATH = "models/email-threat.onnx";
const VOCAB_PATH = "models/email-vocab.json";
const MAX_LENGTH = 512;
const MAX_EMAIL_CHUNKS = 8;
let session = null;
let sessionPromise = null;
let modelError = "No trained email text model is installed.";
let vocabularyPromise = null;

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
    importScripts(getResourceUrl("src/utils/textParser.js"));
  } catch (_) {
    importScripts("../utils/textParser.js");
  }
} catch (e) {
  // parser load error
}

try {
  try {
    importScripts(getResourceUrl("vendor/ort.min.js"));
  } catch (_) {
    importScripts("../../vendor/ort.min.js");
  }
  const activeOrt = (typeof self !== "undefined" && self.ort) || (typeof ort !== "undefined" ? ort : null);
  if (activeOrt) {
    if (typeof self !== "undefined" && !self.ort) self.ort = activeOrt;
    activeOrt.env.wasm.wasmPaths = getResourceUrl("vendor/");
    activeOrt.env.wasm.numThreads = 1;
    activeOrt.env.wasm.proxy = false;
  }
} catch (error) {
  modelError = `ONNX Runtime Web could not be loaded: ${error.message}`;
}

async function loadVocabulary() {
  if (!vocabularyPromise) {
    vocabularyPromise = fetch(getResourceUrl(VOCAB_PATH)).then(async (response) => {
      if (!response.ok) throw new Error(`Could not load ${VOCAB_PATH}.`);
      const file = await response.json();
      const vocabulary = file.vocab || file;
      const maxLength = file.max_length === undefined ? MAX_LENGTH : file.max_length;
      if (!Number.isInteger(maxLength)) throw new Error("email-vocab.json max_length must be an integer.");
      const outputType = file.output_type || "logits";
      if (outputType !== "logits" && outputType !== "probabilities") {
        throw new Error("email-vocab.json output_type must be 'logits' or 'probabilities'.");
      }
      EmailTextParser.wordPieceTokenize("", vocabulary, maxLength);
      return { vocabulary, maxLength, outputType };
    });
  }
  return vocabularyPromise;
}

const TEMPERATURE_TEXT = 1.0656;

async function loadModel() {
  const activeOrt = (typeof self !== "undefined" && self.ort) || (typeof ort !== "undefined" ? ort : null);
  if (!activeOrt) return null;
  if (!sessionPromise) {
    sessionPromise = (async () => {
      const modelUrl = getResourceUrl(MODEL_PATH);
      const response = await fetch(modelUrl);
      if (!response.ok) throw new Error(`No trained model found at ${MODEL_PATH}.`);
      const modelBuffer = typeof response.arrayBuffer === "function" ? await response.arrayBuffer() : modelUrl;
      const sessionInput = modelBuffer instanceof ArrayBuffer ? new Uint8Array(modelBuffer) : modelBuffer;
      const created = await activeOrt.InferenceSession.create(sessionInput, {
        executionProviders: ["wasm"],
        graphOptimizationLevel: "all"
      });
      if (created.inputNames.length < 2) throw new Error("Email model must accept input_ids and attention_mask tensors.");
      return created;
    })().catch((error) => {
      modelError = error.message;
      return null;
    });
  }
  return sessionPromise;
}

function findInputName(names, pattern, fallback) {
  return names.find((name) => pattern.test(name)) || names[fallback];
}

function makeTensor(values, name) {
  const activeOrt = (typeof self !== "undefined" && self.ort) || (typeof ort !== "undefined" ? ort : null);
  if (!activeOrt) throw new Error("ONNX Runtime Web is not available to create tensors.");
  const metadata = session && session.inputMetadata && session.inputMetadata[name];
  const len = values.length;
  if (metadata && metadata.type === "int64") {
    // Fast tight loop avoids iterator and callback overhead
    const bigArr = new BigInt64Array(len);
    for (let i = 0; i < len; i++) {
      bigArr[i] = BigInt(values[i]);
    }
    return new activeOrt.Tensor("int64", bigArr, [1, len]);
  }
  const intArr = values instanceof Int32Array ? values : Int32Array.from(values);
  return new activeOrt.Tensor("int32", intArr, [1, len]);
}

function probabilityFromOutput(output, outputType) {
  const data = output.data;
  if (!data || data.length === 0) return 0;
  if (data.length >= 2) {
    if (outputType === "probabilities") return Math.max(0, Math.min(1, Number(data[1])));
    // Calibrated temperature scaling on logits with zero-allocation softmax
    const v0 = Number(data[0]) / TEMPERATURE_TEXT;
    const v1 = Number(data[1]) / TEMPERATURE_TEXT;
    const maxV = v0 > v1 ? v0 : v1;
    const first = Math.exp(v0 - maxV);
    const second = Math.exp(v1 - maxV);
    return second / (first + second);
  }
  const value = Number(data[0]) || 0;
  if (outputType === "probabilities") return Math.max(0, Math.min(1, value));
  return 1 / (1 + Math.exp(-Math.max(-30, Math.min(30, value / TEMPERATURE_TEXT))));
}

function riskLevel(score) {
  if (score >= 80) return "CRITICAL";
  if (score >= 60) return "HIGH";
  if (score >= 35) return "MEDIUM";
  if (score >= 15) return "LOW";
  return "SAFE";
}

async function analyzeEmail(input) {
  const analysis = EmailTextParser.analyzeEmailText(input || {});
  const { normalized_text: normalizedText, body_text, ...result } = analysis;
  result.model_available = false;
  result.model_risk = null;
  result.analysis_note = modelError;

  const [loadedSession, vocabConfig] = await Promise.all([loadModel(), loadVocabulary().catch(() => null)]);
  if (!loadedSession || !vocabConfig) {
    if (loadedSession && !vocabConfig) result.analysis_note = `ONNX model was present, but ${VOCAB_PATH} is unavailable.`;
    return result;
  }

  try {
    session = loadedSession;
    const tokenChunks = EmailTextParser.wordPieceTokenizeChunks(
      normalizedText,
      vocabConfig.vocabulary,
      Math.min(MAX_LENGTH, vocabConfig.maxLength),
      MAX_EMAIL_CHUNKS + 1
    );
    const idsName = findInputName(loadedSession.inputNames, /input.?ids/i, 0);
    const maskName = findInputName(loadedSession.inputNames, /attention.?mask/i, 1);
    const typeName = loadedSession.inputNames.find((name) => /token.?type.?ids/i.test(name));
    let modelRisk = 0;
    let totalTokenCount = 0;
    const chunksToScan = tokenChunks.slice(0, MAX_EMAIL_CHUNKS);
    for (const tokens of chunksToScan) {
      const feeds = {
        [idsName]: makeTensor(tokens.input_ids, idsName),
        [maskName]: makeTensor(tokens.attention_mask, maskName)
      };
      if (typeName) feeds[typeName] = makeTensor(new Int32Array(tokens.max_length), typeName);
      const output = await loadedSession.run(feeds);
      const prediction = output[loadedSession.outputNames[0]];
      if (!prediction || !prediction.data || prediction.data.length === 0) {
        throw new Error("Email text model returned no classification output.");
      }
      modelRisk = Math.max(modelRisk, probabilityFromOutput(prediction, vocabConfig.outputType));
      totalTokenCount += tokens.token_count;
    }

    const combinedRisk = Math.max(analysis.heuristicRisk, modelRisk * 0.7 + analysis.heuristicRisk * 0.3);
    const score = Math.round(combinedRisk * 100);
    result.model_available = true;
    result.model_risk = modelRisk;
    result.riskScore = combinedRisk;
    result.risk_score = score;
    result.risk_level = riskLevel(score);
    result.analysis_note = "Local ONNX text-model probability is combined with deterministic email indicators.";
    result.model_token_count = totalTokenCount;
    result.model_chunks = chunksToScan.length;
    if (tokenChunks.truncated || tokenChunks.length > MAX_EMAIL_CHUNKS) {
      result.truncated = true;
      result.analysis_note += ` Only the first ${MAX_EMAIL_CHUNKS} text chunks were classified.`;
    }
    result.summary = `${result.summary} Local text-model threat probability: ${Math.round(modelRisk * 100)}%.`;
    return result;
  } catch (error) {
    result.analysis_note = `ONNX email inference failed; local heuristics were used: ${error.message}`;
    return result;
  }
}

Promise.all([loadModel(), loadVocabulary().catch(() => null)]).then(([loaded, vocabConfig]) => {
  self.postMessage({
    type: "READY",
    modelAvailable: Boolean(loaded && vocabConfig),
    error: loaded && !vocabConfig ? `The model vocabulary ${VOCAB_PATH} is missing.` : loaded ? "" : modelError
  });
});

self.onmessage = async ({ data }) => {
  if (!data || data.type !== "INFER_EMAIL_TEXT" || typeof data.requestId !== "string") return;
  try {
    const result = await analyzeEmail(data.email);
    self.postMessage({ type: "EMAIL_TEXT_RESULT", requestId: data.requestId, result });
  } catch (error) {
    self.postMessage({ type: "EMAIL_TEXT_RESULT", requestId: data.requestId, error: error.message || "Email text inference failed." });
  }
};
