"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const { webcrypto } = require("node:crypto");
const parser = require("../src/url/urlThreatParser.js");
const textParser = require("../src/utils/textParser.js");

function createEvent() {
  const listeners = [];
  return {
    addListener(listener) { listeners.push(listener); },
    dispatch(...args) { return listeners.map((listener) => listener(...args)); }
  };
}

function createHarness() {
  const values = {};
  const runtimeOnConnect = createEvent();
  const runtimeOnMessage = createEvent();
  const contextMenusOnClicked = createEvent();
  const contextMenusOnInstalled = createEvent();
  const workerPortMessages = [];
  const sessionValues = {};
  const sidePanelCalls = [];
  const workerPort = {
    name: "url-analysis-worker",
    onMessage: createEvent(),
    onDisconnect: createEvent(),
    postMessage(message) {
      workerPortMessages.push(message);
      if (message.type === "INFER_URL") {
        const parsed = message.parsed;
        queueMicrotask(() => this.onMessage.dispatch({
          type: "INFERENCE_RESULT",
          requestId: message.requestId,
          result: {
            inputUrl: parsed.inputUrl,
            canonicalUrl: parsed.canonicalUrl,
            hostname: parsed.hostname,
            unicodeHostname: parsed.unicodeHostname,
            matchedBrand: parsed.matchedBrand,
            riskScore: parsed.heuristicRisk,
            heuristicRisk: parsed.heuristicRisk,
            modelAvailable: true,
            attackTypes: parsed.attackTypes,
            findings: parsed.findings,
            metrics: parsed.metrics
          }
        }));
      }
    }
  };
  const chrome = {
    runtime: {
      onInstalled: contextMenusOnInstalled,
      onConnect: runtimeOnConnect,
      onMessage: runtimeOnMessage,
      async sendMessage(message) {
        if (message.type !== "RUN_EMAIL_TEXT_INFERENCE") return null;
        const { normalized_text, body_text, ...result } = textParser.analyzeEmailText(message.email);
        return { ok: true, result };
      }
    },
    offscreen: { async hasDocument() { return true; } },
    contextMenus: {
      onClicked: contextMenusOnClicked,
      onInstalled: contextMenusOnInstalled,
      removeAll(callback) { callback(); },
      create() {}
    },
    sidePanel: {
      setPanelBehavior: async (behavior) => sidePanelCalls.push({ type: "behavior", behavior }),
      open: async (options) => sidePanelCalls.push({ type: "open", options })
    },
    storage: {
      local: {
        async get(keys) {
          if (keys === null) return { ...values };
          if (typeof keys === "string") return Object.hasOwn(values, keys) ? { [keys]: values[keys] } : {};
          return Object.fromEntries(keys.filter((key) => Object.hasOwn(values, key)).map((key) => [key, values[key]]));
        },
        async set(items) { Object.assign(values, items); },
        async remove(keys) { for (const key of Array.isArray(keys) ? keys : [keys]) delete values[key]; }
      },
      session: {
        async get(key) { return Object.hasOwn(sessionValues, key) ? { [key]: sessionValues[key] } : {}; },
        async set(items) { Object.assign(sessionValues, items); }
      }
    }
  };
  const context = {
    chrome,
    crypto: webcrypto,
    TextEncoder,
    URL,
    Date,
    Map,
    Set,
    Promise,
    Math,
    Array,
    Object,
    Error,
    TypeError,
    setTimeout,
    clearTimeout,
    importScripts(...paths) {
      if (paths.some((file) => file.includes("textParser.js"))) context.EmailTextParser = textParser;
      else context.UrlThreatParser = parser;
    }
  };
  vm.createContext(context);
  const source = fs.readFileSync(path.join(__dirname, "../src/background/serviceWorker.js"), "utf8");
  vm.runInContext(source, context);
  runtimeOnConnect.dispatch(workerPort);
  workerPort.onMessage.dispatch({ type: "WORKER_STATUS", modelAvailable: true });

  return { runtimeOnMessage, workerPortMessages, values, sessionValues, sidePanelCalls, contextMenusOnInstalled };
}

function analyze(runtimeOnMessage, url) {
  return new Promise((resolve) => {
    const [keepChannelOpen] = runtimeOnMessage.dispatch({ type: "ANALYZE_URL", url }, {}, resolve);
    assert.equal(keepChannelOpen, true);
  });
}

function analyzeEmail(runtimeOnMessage, email) {
  return new Promise((resolve) => {
    const [keepChannelOpen] = runtimeOnMessage.dispatch({ type: "ANALYZE_EMAIL_TEXT", email }, {}, resolve);
    assert.equal(keepChannelOpen, true);
  });
}

test("service worker relays URL analysis and caches results by SHA-256 URL key", async () => {
  const { runtimeOnMessage, workerPortMessages, values } = createHarness();
  const url = "https://example.com/continue?next=https%3A%2F%2Foutside.example";
  const [first, concurrent] = await Promise.all([
    analyze(runtimeOnMessage, url),
    analyze(runtimeOnMessage, url)
  ]);
  assert.equal(first.ok, true);
  assert.equal(concurrent.ok, true);
  assert.ok(first.result.attackTypes.includes("OPEN_REDIRECT"));
  assert.equal(workerPortMessages.filter((message) => message.type === "INFER_URL").length, 1);

  const cacheKeys = Object.keys(values).filter((key) => key.startsWith("urlThreatScan:"));
  assert.equal(cacheKeys.length, 1);
  assert.match(cacheKeys[0], /^urlThreatScan:[a-f0-9]{64}$/);

  const second = await analyze(runtimeOnMessage, url);
  assert.equal(second.ok, true);
  assert.equal(workerPortMessages.filter((message) => message.type === "INFER_URL").length, 1);
});

test("service worker returns parser validation errors rather than caching them", async () => {
  const { runtimeOnMessage, values } = createHarness();
  const result = await analyze(runtimeOnMessage, "javascript:alert(1)");
  assert.equal(result.ok, false);
  assert.match(result.error, /Only HTTP and HTTPS/);
  assert.equal(Object.keys(values).length, 0);
});

test("service worker syncs opened email data to session storage without persistent email retention", async () => {
  const { runtimeOnMessage, sessionValues } = createHarness();
  const email = {
    subject: "Verify account",
    text: "From: sender@example.test\nSubject: Verify account",
    urls: ["https://example.test/"]
  };
  const response = await new Promise((resolve) => {
    const [keepChannelOpen] = runtimeOnMessage.dispatch(
      { type: "EMAIL_SCAN_OPENED", email },
      { tab: { id: 17 }, url: "https://mail.google.com/mail/u/0/#inbox" },
      resolve
    );
    assert.equal(keepChannelOpen, true);
  });
  assert.equal(response.ok, true);
  assert.equal(sessionValues.activeEmailScan.tabId, 17);
  assert.deepEqual(sessionValues.activeEmailScan.urls, email.urls);
});

test("service worker rejects email handoffs from non-webmail tabs and oversized payloads", async () => {
  const { runtimeOnMessage, sessionValues } = createHarness();
  const email = {
    subject: "Verify account",
    text: "Message body",
    urls: ["https://example.test/"]
  };
  const dispatchHandoff = (payload, url) => new Promise((resolve) => {
    const [keepChannelOpen] = runtimeOnMessage.dispatch(
      { type: "EMAIL_SCAN_OPENED", email: payload },
      { tab: { id: 17 }, url },
      resolve
    );
    assert.equal(keepChannelOpen, false);
  });

  const wrongOrigin = await dispatchHandoff(email, "https://mail.google.com.attacker.test/");
  const insecureOrigin = await dispatchHandoff(email, "http://mail.google.com/");
  const oversized = await dispatchHandoff({ ...email, text: "x".repeat(1000001) }, "https://mail.google.com/");
  assert.equal(wrongOrigin.ok, false);
  assert.equal(insecureOrigin.ok, false);
  assert.equal(oversized.ok, false);
  assert.equal(sessionValues.activeEmailScan, undefined);
});

test("service worker configures action clicks to open the native side panel", () => {
  const { sidePanelCalls, contextMenusOnInstalled } = createHarness();
  contextMenusOnInstalled.dispatch();
  assert.equal(sidePanelCalls[0].type, "behavior");
  assert.equal(sidePanelCalls[0].behavior.openPanelOnActionClick, true);
});

test("service worker analyzes and caches email text by SHA-256 without retaining message text", async () => {
  const { runtimeOnMessage, values } = createHarness();
  const email = {
    sender: "PayPal Security <alert@gmail.com>",
    subject: "URGENT ACTION REQUIRED",
    body: "Verify your password within 24 hours.",
    text: "Verify your password within 24 hours."
  };
  const result = await analyzeEmail(runtimeOnMessage, email);
  assert.equal(result.ok, true);
  assert.ok(result.result.threat_vectors.includes("SENDER_SPOOFING"));
  const cacheKeys = Object.keys(values).filter((key) => key.startsWith("emailThreatScan:"));
  assert.equal(cacheKeys.length, 1);
  assert.match(cacheKeys[0], /^emailThreatScan:[a-f0-9]{64}$/);
  assert.ok(!JSON.stringify(values[cacheKeys[0]]).includes("Verify your password"));
  assert.ok(!JSON.stringify(values[cacheKeys[0]]).includes("URGENT ACTION REQUIRED"));

  const second = await analyzeEmail(runtimeOnMessage, email);
  assert.equal(second.ok, true);
  assert.equal(second.result.risk_score, result.result.risk_score);
});


test("service worker enforces HTTPS protocol for remote cloud backend connections", async () => {
  const { runtimeOnMessage } = createHarness();

  const testBackend = (url) => new Promise((resolve) => {
    const [keepOpen] = runtimeOnMessage.dispatch({ type: "TEST_CLOUD_BACKEND", url }, {}, resolve);
    assert.equal(keepOpen, true);
  });

  // 1. Insecure remote HTTP must be rejected
  const insecureRemote = await testBackend("http://remote-server.com/api");
  assert.equal(insecureRemote.ok, false);
  assert.match(insecureRemote.error, /HTTPS/);

  // 2. Unsupported protocol (e.g. ftp, ws, etc.) must be rejected
  const invalidProto = await testBackend("ftp://remote-server.com");
  assert.equal(invalidProto.ok, false);
  assert.match(invalidProto.error, /http:\/\/ or https:\/\//);

  // 3. Empty or null URL must be rejected
  const emptyUrl = await testBackend("");
  assert.equal(emptyUrl.ok, false);
  assert.match(emptyUrl.error, /Backend URL is required/);
});
