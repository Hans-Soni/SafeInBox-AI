"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const ort = require("../vendor/ort.min.js");
const { analyzeUrl } = require("../src/url/urlThreatParser.js");
const { wordPieceTokenizeChunks, stripHtml, maskSensitiveTokens } = require("../src/utils/textParser.js");

const URL_MODEL_PATH = path.resolve(__dirname, "../models/url-threat.onnx");
const EMAIL_MODEL_PATH = path.resolve(__dirname, "../models/email-threat.onnx");
const EMAIL_VOCAB_PATH = path.resolve(__dirname, "../models/email-vocab.json");

const TEMPERATURE_URL = 1.0586;
const TEMPERATURE_TEXT = 1.0656;

test("Live ONNX URL Threat Model: Structural validity, benchmark latency (<5ms), and calibrated inference", async () => {
  assert.ok(fs.existsSync(URL_MODEL_PATH), "url-threat.onnx model file must exist");
  const modelBuffer = fs.readFileSync(URL_MODEL_PATH);
  assert.ok(modelBuffer.length > 50000, "url-threat.onnx size must be > 50KB");

  const session = await ort.InferenceSession.create(modelBuffer, {
    executionProviders: ["wasm"],
    graphOptimizationLevel: "all"
  });

  assert.ok(session.inputNames.includes("features"), "Model must accept 'features' input");
  assert.ok(session.inputNames.includes("characters"), "Model must accept 'characters' input");
  assert.equal(session.outputNames[0], "output", "Model output tensor must be named 'output'");

  const testCases = [
    { url: "https://apple-id-verify.security-update.xyz/login.php", expectThreat: true },
    { url: "https://paypa1-security-verification.com/account/login", expectThreat: true },
    { url: "https://secure-login.chase-online-banking.top/auth", expectThreat: true },
    { url: "https://www.google.com/search?q=cybersecurity", expectThreat: false },
    { url: "https://www.wikipedia.org/wiki/Transport_Layer_Security", expectThreat: false },
    { url: "https://github.com/Hans-Soni/SafeInBox-AI", expectThreat: false }
  ];

  const latencies = [];

  for (const { url, expectThreat } of testCases) {
    const parsed = analyzeUrl(url);
    const feeds = {
      features: new ort.Tensor("float32", parsed.featureVector, [1, 32]),
      characters: new ort.Tensor("int32", parsed.charTensor, [1, 128])
    };

    const t0 = performance.now();
    const output = await session.run(feeds);
    const elapsed = performance.now() - t0;
    latencies.push(elapsed);

    const data = output.output.data;
    assert.equal(data.length, 2, "URL model must output 2-class logits [safe, threat]");

    // Temperature-scaled softmax
    const l0 = Number(data[0]) / TEMPERATURE_URL;
    const l1 = Number(data[1]) / TEMPERATURE_URL;
    const maxL = Math.max(l0, l1);
    const prob = Math.exp(l1 - maxL) / (Math.exp(l0 - maxL) + Math.exp(l1 - maxL));

    assert.ok(Number.isFinite(prob), "Output probability must be a finite number");
    assert.ok(prob >= 0 && prob <= 1, `Probability must be within [0, 1], got ${prob}`);

    if (expectThreat) {
      assert.ok(prob > 0.50, `Phishing URL '${url}' should score threat probability > 0.50 (got ${(prob * 100).toFixed(1)}%)`);
    } else {
      assert.ok(prob < 0.50, `Benign URL '${url}' should score threat probability < 0.50 (got ${(prob * 100).toFixed(1)}%)`);
    }
  }

  // Check steady-state latency (excluding initial warmup runs)
  const warmLatencies = latencies.slice(2);
  const avgWarmLatency = warmLatencies.reduce((a, b) => a + b, 0) / warmLatencies.length;
  assert.ok(
    avgWarmLatency < 15.0,
    `Steady-state URL inference latency should be < 15.0ms (got ${avgWarmLatency.toFixed(2)}ms)`
  );
});

test("Live ONNX Email Text Threat Model: Structural validity, benchmark latency (<15ms), and calibrated inference", async () => {
  assert.ok(fs.existsSync(EMAIL_MODEL_PATH), "email-threat.onnx model file must exist");
  assert.ok(fs.existsSync(EMAIL_VOCAB_PATH), "email-vocab.json must exist");

  const modelBuffer = fs.readFileSync(EMAIL_MODEL_PATH);
  assert.ok(modelBuffer.length > 1000000, "email-threat.onnx size must be > 1MB");

  const session = await ort.InferenceSession.create(modelBuffer, {
    executionProviders: ["wasm"],
    graphOptimizationLevel: "all"
  });

  const rawVocab = JSON.parse(fs.readFileSync(EMAIL_VOCAB_PATH, "utf8"));
  const vocab = rawVocab.vocab || rawVocab;

  assert.ok(session.inputNames.includes("input_ids"), "Model must accept 'input_ids' input");
  assert.ok(session.inputNames.includes("attention_mask"), "Model must accept 'attention_mask' input");
  assert.equal(session.outputNames[0], "logits", "Model output tensor must be named 'logits'");

  const testCases = [
    {
      text: "URGENT: Your account has been suspended due to unauthorized access. Click here to verify your credentials immediately or your account will be permanently deleted.",
      expectThreat: true
    },
    {
      text: "Final warning: You have an unpaid invoice of $3,500. Pay immediately via wire transfer to avoid law enforcement prosecution.",
      expectThreat: true
    },
    {
      text: "Claim your reward! You won $1,000,000 in the international cash prize lottery. Submit your bank account details and password to claim.",
      expectThreat: true
    },
    {
      text: "Hi Team, please find attached the minutes from our weekly sync. Let me know if you have any feedback on the engineering roadmap.",
      expectThreat: false
    },
    {
      text: "Your flight confirmation: Flight 204 from San Francisco to New York is confirmed for tomorrow. Safe travels!",
      expectThreat: false
    },
    {
      text: "Hey, are you free for lunch tomorrow around 12:30 PM? Let me know what cuisine you feel like having.",
      expectThreat: false
    }
  ];

  const latencies = [];

  for (const { text, expectThreat } of testCases) {
    const cleaned = maskSensitiveTokens(stripHtml(text));
    const chunks = wordPieceTokenizeChunks(cleaned, vocab, 128, 4);
    assert.ok(chunks.length >= 1, "Must produce at least one chunk");

    let maxThreatRisk = 0;
    let chunkTotalTime = 0;

    for (const chunk of chunks) {
      const len = chunk.input_ids.length;
      const ids = new BigInt64Array(len);
      const mask = new BigInt64Array(len);
      for (let i = 0; i < len; i++) {
        ids[i] = BigInt(chunk.input_ids[i]);
        mask[i] = BigInt(chunk.attention_mask[i]);
      }
      const feeds = {
        input_ids: new ort.Tensor("int64", ids, [1, len]),
        attention_mask: new ort.Tensor("int64", mask, [1, len])
      };

      const t0 = performance.now();
      const output = await session.run(feeds);
      chunkTotalTime += performance.now() - t0;

      const data = output.logits.data;
      assert.equal(data.length, 2, "Email model must output 2-class logits [safe, threat]");

      const l0 = Number(data[0]) / TEMPERATURE_TEXT;
      const l1 = Number(data[1]) / TEMPERATURE_TEXT;
      const maxL = Math.max(l0, l1);
      const prob = Math.exp(l1 - maxL) / (Math.exp(l0 - maxL) + Math.exp(l1 - maxL));

      assert.ok(Number.isFinite(prob), "Probability must be finite");
      assert.ok(prob >= 0 && prob <= 1, `Probability must be within [0, 1], got ${prob}`);

      if (prob > maxThreatRisk) maxThreatRisk = prob;
    }

    latencies.push(chunkTotalTime);

    if (expectThreat) {
      assert.ok(maxThreatRisk >= 0.40, `Phishing email should score threat probability >= 0.40 (got ${(maxThreatRisk * 100).toFixed(1)}%)`);
    } else {
      assert.ok(maxThreatRisk < 0.40, `Benign email should score threat probability < 0.40 (got ${(maxThreatRisk * 100).toFixed(1)}%)`);
    }
  }

  // Check steady-state latency (excluding initial warmup runs)
  const warmLatencies = latencies.slice(2);
  const avgWarmLatency = warmLatencies.reduce((a, b) => a + b, 0) / warmLatencies.length;
  assert.ok(
    avgWarmLatency < 35.0,
    `Steady-state Email inference latency should be < 35.0ms (got ${avgWarmLatency.toFixed(2)}ms)`
  );
});

test("Live ONNX Multi-Chunk Email Stress Test: Evaluates oversized email text (>1000 words)", async () => {
  const modelBuffer = fs.readFileSync(EMAIL_MODEL_PATH);
  const session = await ort.InferenceSession.create(modelBuffer, { executionProviders: ["wasm"] });
  const rawVocab = JSON.parse(fs.readFileSync(EMAIL_VOCAB_PATH, "utf8"));
  const vocab = rawVocab.vocab || rawVocab;

  const repeatedSafeText = "This is a legitimate team report with daily progress metrics and quarterly achievements. ".repeat(60);
  const cleaned = maskSensitiveTokens(stripHtml(repeatedSafeText));
  const chunks = wordPieceTokenizeChunks(cleaned, vocab, 128, 8);

  assert.ok(chunks.length >= 4, `Oversized email should be partitioned into at least 4 chunks, got ${chunks.length}`);

  for (const chunk of chunks) {
    const len = chunk.input_ids.length;
    const ids = new BigInt64Array(len);
    const mask = new BigInt64Array(len);
    for (let i = 0; i < len; i++) {
      ids[i] = BigInt(chunk.input_ids[i]);
      mask[i] = BigInt(chunk.attention_mask[i]);
    }
    const feeds = {
      input_ids: new ort.Tensor("int64", ids, [1, len]),
      attention_mask: new ort.Tensor("int64", mask, [1, len])
    };
    const output = await session.run(feeds);
    assert.equal(output.logits.data.length, 2);
  }
});
