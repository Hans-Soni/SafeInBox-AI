"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const parser = require("../src/url/urlThreatParser.js");
const textParser = require("../src/utils/textParser.js");
const emailTextAnalyzer = require("../src/email/emailTextAnalyzer.js");

test("side panel URL input uses the shared parser and scans email links sequentially", async () => {
  const sidepanelSource = fs.readFileSync(path.join(__dirname, "../src/ui/sidepanelController.js"), "utf8");
  const webmailSource = fs.readFileSync(path.join(__dirname, "../src/content/contentScript.js"), "utf8");
  const textWorkerSource = fs.readFileSync(path.join(__dirname, "../src/ml/textMlWorker.js"), "utf8");
  const textWorkerHostSource = fs.readFileSync(path.join(__dirname, "../src/ml/textWorkerHost.js"), "utf8");
  const html = fs.readFileSync(path.join(__dirname, "../sidepanel.html"), "utf8");
  const nav = html.match(/<nav class="nav-tabs">[\s\S]*?<\/nav>/)[0];
  const manifest = JSON.parse(fs.readFileSync(path.join(__dirname, "../manifest.json"), "utf8"));
  assert.ok(html.indexOf('src/url/urlThreatParser.js') < html.indexOf('src="src/ui/sidepanelController.js"'));
  assert.ok(html.includes('src/email/emailTextAnalyzer.js'));
  assert.equal(manifest.side_panel.default_path, "sidepanel.html");
  assert.equal((nav.match(/class="tab-btn/g) || []).length, 3);
  assert.match(nav, /Summary[\s\S]*URL Scanner[\s\S]*Context Scanning/);
  assert.doesNotMatch(nav, /Evidence|Page Links|Email Inspector/);
  assert.ok(manifest.permissions.includes("offscreen"));
  assert.ok(manifest.permissions.includes("sidePanel"));
  assert.doesNotMatch(JSON.stringify(manifest.action), /default_popup/);
  assert.ok(manifest.content_scripts.some((entry) => entry.matches.includes("*://mail.google.com/*")
    && entry.js.includes("src/content/contentScript.js")));
  assert.ok(manifest.content_scripts.some((entry) => entry.matches.includes("<all_urls>")
    && entry.js.includes("src/content/urlLinkScanner.js")));

  const context = {
    document: { addEventListener() {} },
    URL,
    performance,
    Map,
    Set,
    Math,
    Date,
    console
  };
  vm.createContext(context);
  context.UrlThreatParser = parser;
  context.EmailTextParser = textParser;
  context.EmailTextAnalyzer = emailTextAnalyzer;
  vm.runInContext(sidepanelSource, context);

  const result = await context.executeUrlScan("https://paypa1-login.example.xyz/login");
  assert.equal(result.target_type, "URL");
  assert.ok(result.attack_types.includes("TYPOSQUATTING"));
  assert.ok(result.risk_score > 0);
  assert.match(sidepanelSource, /initializeEmailScanBridge/);
  assert.match(sidepanelSource, /storage\.session\.get\("activeEmailScan"\)/);
  assert.match(sidepanelSource, /scanBatchLinks\(urls\)/);
  assert.match(sidepanelSource, /calculateEmailRiskAverage\(textResult\.risk_score, urlScores\)/);
  assert.match(sidepanelSource, /chrome\.tabs\.onActivated\.addListener/);
  assert.match(sidepanelSource, /EmailTextAnalyzer\.analyzeEmailText/);
  assert.doesNotMatch(sidepanelSource, /const CLIENT_BRANDS|_RE_URGENCY|_RE_CREDENTIAL_E/);
  assert.match(webmailSource, /EmailTextAnalyzer\.analyzeEmailText/);
  assert.doesNotMatch(webmailSource, /clientFallbackEmailScan|const CLIENT_BRANDS/);
  assert.match(textWorkerSource, /executionProviders: \["wasm"\]/);
  assert.match(textWorkerHostSource, /RUN_EMAIL_TEXT_INFERENCE/);
  assert.ok(fs.existsSync(path.join(__dirname, "../offscreen.html")));
});

test("email composite risk averages text and URL risk without hiding the highest URL", () => {
  const source = fs.readFileSync(path.join(__dirname, "../src/ui/sidepanelController.js"), "utf8");
  const context = {
    document: { addEventListener() {} },
    URL,
    performance,
    Map,
    Set,
    Math,
    Date,
    console
  };
  vm.createContext(context);
  vm.runInContext(source, context);

  assert.deepEqual(
    JSON.parse(JSON.stringify(context.calculateEmailRiskAverage(80, [20, 80, 40]))),
    { textScore: 80, urlAverage: 47, urlHighest: 80, combined: 64 }
  );
  assert.deepEqual(
    JSON.parse(JSON.stringify(context.calculateEmailRiskAverage(33, []))),
    { textScore: 33, urlAverage: null, urlHighest: null, combined: 33 }
  );
});

test("URL and email feedback are saved locally as bounded labels", async () => {
  const source = fs.readFileSync(path.join(__dirname, "../src/ui/sidepanelController.js"), "utf8");
  const stored = {};
  const context = {
    document: { addEventListener() {} },
    chrome: {
      runtime: {},
      storage: {
        local: {
          get(keys, callback) {
            callback(Object.fromEntries(keys.filter((key) => Object.hasOwn(stored, key)).map((key) => [key, stored[key]])));
          },
          set(items, callback) {
            Object.assign(stored, items);
            callback();
          }
        }
      }
    },
    URL,
    performance,
    Map,
    Set,
    Math,
    Date,
    console
  };
  vm.createContext(context);
  vm.runInContext(source, context);

  for (let index = 0; index < 102; index += 1) {
    await context.submitTargetFeedback(`https://sample-${index}.example`, false, "test");
  }
  const urlLabels = stored.offline_url_feedback;
  assert.equal(urlLabels.length, 100);
  assert.equal(urlLabels[99].target, "https://sample-101.example");

  const textFeedback = await context.submitTargetFeedback("x".repeat(20001), true, "test", "EMAIL");
  assert.equal(textFeedback.status, "saved_locally");
  assert.equal(stored.offline_text_feedback[0].target.length, 20000);
  assert.equal(stored.offline_text_feedback[0].target_truncated, true);
});

test("webmail scan fingerprint changes when the selected email changes", () => {
  const source = fs.readFileSync(path.join(__dirname, "../src/content/contentScript.js"), "utf8");
  const context = {
    document: { readyState: "loading", addEventListener() {} },
    window: { location: { hostname: "mail.google.com" } },
    chrome: { runtime: { onMessage: { addListener() {} } } },
    URL,
    Map,
    Set,
    Math,
    Date,
    console
  };
  vm.createContext(context);
  vm.runInContext(source, context);

  const emailA = { senderEmail: "one@example.com", receiverEmail: "", cc: "", bcc: "", subject: "First", cleanBodyText: "body one" };
  const emailB = { ...emailA, subject: "Second", cleanBodyText: "body two" };
  assert.notEqual(
    context.getEmailScanFingerprint(emailA, ["https://first.example"]),
    context.getEmailScanFingerprint(emailB, ["https://second.example"])
  );
});

test("Gmail scan routing selects only the last expanded message in an open thread", () => {
  const source = fs.readFileSync(path.join(__dirname, "../src/content/contentScript.js"), "utf8");
  const firstMessage = { id: "older", querySelector: () => ({}) };
  const collapsedMessage = { id: "collapsed", querySelector: () => null };
  const activeMessage = { id: "active", querySelector: () => ({}) };
  const context = {
    document: {
      readyState: "loading",
      addEventListener() {},
      querySelectorAll: () => [firstMessage, collapsedMessage, activeMessage],
      querySelector: () => null
    },
    window: { location: { hostname: "mail.google.com" } },
    chrome: { runtime: { onMessage: { addListener() {} } } },
    URL,
    Map,
    Set,
    Math,
    Date,
    console
  };
  vm.createContext(context);
  vm.runInContext(source, context);

  assert.equal(context.getActiveGmailMessage().id, "active");
});
