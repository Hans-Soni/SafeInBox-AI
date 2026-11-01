"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const textParser = require("../src/utils/textParser.js");

test("text worker runs local ONNX inference with WordPiece tensors and returns combined risk", async () => {
  const messages = [];
  const feedsSeen = [];
  const vocabulary = {
    "[PAD]": 0, "[UNK]": 1, "[CLS]": 2, "[SEP]": 3,
    subject: 4, sender: 5, recipient: 6, body: 7, ":": 8, hello: 9
  };
  class Tensor {
    constructor(type, data, dims) {
      this.type = type;
      this.data = data;
      this.dims = dims;
    }
  }
  const ort = {
    env: { wasm: {} },
    Tensor,
    InferenceSession: {
      async create() {
        return {
          inputNames: ["input_ids", "attention_mask"],
          outputNames: ["logits"],
          inputMetadata: {
            input_ids: { type: "int64" },
            attention_mask: { type: "int64" }
          },
          async run(feeds) {
            feedsSeen.push(feeds);
            return { logits: { data: Float32Array.from([-2, 2]) } };
          }
        };
      }
    }
  };
  const self = { postMessage(message) { messages.push(message); } };
  const context = {
    self,
    chrome: { runtime: { getURL: (file) => `chrome-extension://test/${file}` } },
    console,
    performance,
    TextEncoder,
    URL,
    fetch: async (url) => url.endsWith("email-vocab.json")
      ? { ok: true, json: async () => ({ max_length: 8, output_type: "logits", vocab: vocabulary }) }
      : { ok: true },
    importScripts(...files) {
      if (files.some((file) => file.includes("textParser.js"))) context.EmailTextParser = textParser;
      if (files.some((file) => file.includes("ort.min.js"))) self.ort = ort;
    }
  };
  vm.createContext(context);
  const source = fs.readFileSync(path.join(__dirname, "../src/ml/textMlWorker.js"), "utf8");
  vm.runInContext(source, context);

  for (let attempt = 0; attempt < 20 && !messages.some((message) => message.type === "READY"); attempt += 1) {
    await new Promise((resolve) => setTimeout(resolve, 0));
  }
  assert.equal(messages.find((message) => message.type === "READY").modelAvailable, true);

  await self.onmessage({
    data: {
      type: "INFER_EMAIL_TEXT",
      requestId: "test-request",
      email: {
        sender: "sender@example.test",
        receiver: "recipient@example.test",
        subject: "hello",
        body: "hello",
        text: "hello"
      }
    }
  });

  const response = messages.find((message) => message.type === "EMAIL_TEXT_RESULT");
  assert.equal(response.requestId, "test-request");
  assert.equal(response.result.model_available, true);
  assert.ok(response.result.model_risk > 0.9);
  assert.ok(response.result.risk_score >= 15);
  assert.equal(feedsSeen.length, response.result.model_chunks);
  assert.ok(feedsSeen.length > 1);
  assert.equal(feedsSeen[0].input_ids.type, "int64");
  assert.deepEqual(Array.from(feedsSeen[0].input_ids.dims), [1, 8]);
  assert.equal(feedsSeen[0].input_ids.data[0], 2n);
  assert.equal(feedsSeen[0].attention_mask.data[0], 1n);
  assert.ok(!Object.hasOwn(response.result, "body_text"));
});
