"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

const contentScriptPath = path.resolve("extension/src/content/contentScript.js");
const contentScriptSource = fs.readFileSync(contentScriptPath, "utf8");
const sidepanelHtmlPath = path.resolve("extension/sidepanel.html");
const sidepanelHtml = fs.readFileSync(sidepanelHtmlPath, "utf8");

test("15-Day Security Digest: sidepanel HTML contains panel, actions, and preview modal", () => {
  assert.ok(sidepanelHtml.includes('id="digestPanel"'), "Must contain #digestPanel");
  assert.ok(sidepanelHtml.includes('id="digestHeader"'), "Must contain #digestHeader");
  assert.ok(sidepanelHtml.includes('id="digestBody"'), "Must contain #digestBody");
  assert.ok(sidepanelHtml.includes('id="digestUserEmail"'), "Must contain #digestUserEmail");
  assert.ok(sidepanelHtml.includes('id="digestTimeSlab"'), "Must contain #digestTimeSlab");
  assert.ok(sidepanelHtml.includes('id="digestRecordsCount"'), "Must contain #digestRecordsCount");
  assert.ok(sidepanelHtml.includes('id="btnSendDigestNow"'), "Must contain #btnSendDigestNow");
  assert.ok(sidepanelHtml.includes('id="btnPreviewDigest"'), "Must contain #btnPreviewDigest");
  assert.ok(sidepanelHtml.includes('id="digestPreviewModal"'), "Must contain #digestPreviewModal");
  assert.ok(sidepanelHtml.includes('id="digestPreviewIframe"'), "Must contain #digestPreviewIframe");
});

test("15-Day Security Digest: contentScript records sender, receiver, time-slab, and ML score", async () => {
  const stored = {};
  const context = {
    document: { readyState: "loading", addEventListener() {} },
    window: { location: { hostname: "mail.google.com" } },
    MutationObserver: class { observe() {} },
    chrome: {
      runtime: { onMessage: { addListener() {} } },
      storage: {
        local: {
          get(keys, cb) {
            cb(Object.fromEntries(keys.filter(k => Object.hasOwn(stored, k)).map(k => [k, stored[k]])));
          },
          set(items, cb) {
            Object.assign(stored, items);
            if (cb) cb();
          }
        }
      }
    },
    URL, Map, Set, Math, Date, console
  };

  vm.createContext(context);
  vm.runInContext(contentScriptSource, context);

  // 1. Record an email audit
  const emailData = {
    senderName: "Security Desk",
    senderEmail: "alerts@corp-bank.com",
    receiverEmail: "employee@company.com",
    subject: "Action Required: Verify Account"
  };
  const emailVerdict = {
    risk_score: 85,
    threat_vectors: ["ARTIFICIAL_URGENCY", "CREDENTIAL_HARVESTING"]
  };
  const avgUrlRisk = 90;
  const compositeRisk = 88;
  const compLevel = "CRITICAL";

  await context.record15DayEmailAudit(emailData, emailVerdict, avgUrlRisk, compositeRisk, compLevel);

  const records = stored.safeinbox_15day_email_records;
  assert.ok(Array.isArray(records), "Records should be an array");
  assert.equal(records.length, 1);
  assert.equal(records[0].sender, "Security Desk <alerts@corp-bank.com>");
  assert.equal(records[0].receiver, "employee@company.com");
  assert.equal(records[0].subject, "Action Required: Verify Account");
  assert.equal(records[0].composite_risk, 88);
  assert.equal(records[0].risk_level, "CRITICAL");
  assert.equal(records[0].text_threat_score, 85);
  assert.equal(records[0].url_threat_score, 90);
  assert.deepEqual(records[0].threat_vectors, ["ARTIFICIAL_URGENCY", "CREDENTIAL_HARVESTING"]);
  assert.ok(records[0].time_slab.includes(" to "));
  assert.equal(records[0].clicked_urls.length, 0);

  // 2. Click a link in that email
  await context.recordWebmailUrlClick({
    url: "https://corp-bank.com.scam-verify.net/login",
    emailSubject: "Action Required: Verify Account",
    sender: "Security Desk <alerts@corp-bank.com>",
    riskScore: 95,
    riskLevel: "CRITICAL",
    proceeded: false,
    source: "flagged_email_link"
  });

  // Verify the clicked URL is appended directly to the matching email record
  const updatedRecords = stored.safeinbox_15day_email_records;
  assert.equal(updatedRecords.length, 1);
  assert.equal(updatedRecords[0].clicked_urls.length, 1);
  assert.equal(updatedRecords[0].clicked_urls[0].url, "https://corp-bank.com.scam-verify.net/login");
  assert.equal(updatedRecords[0].clicked_urls[0].defanged, "hxxps://corp-bank[.]com[.]scam-verify[.]net/login");
  assert.equal(updatedRecords[0].clicked_urls[0].risk_score, 95);
  assert.equal(updatedRecords[0].clicked_urls[0].risk_level, "CRITICAL");
  assert.ok(updatedRecords[0].clicked_urls[0].timestamp);

  // 3. FIFO bounding to 500 items
  for (let i = 0; i < 510; i++) {
    await context.record15DayEmailAudit(
      {
        senderName: `Sender ${i}`,
        senderEmail: `sender${i}@example.com`,
        receiverEmail: "employee@company.com",
        subject: `Distinct Subject ${i}`
      },
      { risk_score: 10, threat_vectors: [] },
      0, 5, "SAFE"
    );
  }
  assert.equal(stored.safeinbox_15day_email_records.length, 500, "Must be bounded to 500 records max");
});

test("15-Day Security Digest: HTML generator produces all required fields", () => {
  const swPath = path.resolve("extension/src/background/serviceWorker.js");
  const swSource = fs.readFileSync(swPath, "utf8");

  function createEvent() {
    return { addListener() {}, dispatch() {} };
  }

  const context = {
    self: {},
    importScripts() {},
    chrome: {
      sidePanel: { setPanelBehavior() { return Promise.resolve(); } },
      alarms: { get(name, cb) { if (cb) cb(null); }, create() {}, onAlarm: createEvent() },
      runtime: {
        onInstalled: createEvent(),
        onMessage: createEvent(),
        onConnect: createEvent()
      },
      contextMenus: { removeAll(cb) { cb(); }, create() {}, onClicked: createEvent() },
      storage: {
        local: { get() {}, set() {} },
        session: { get() { return Promise.resolve({}); }, set() { return Promise.resolve(); } }
      }
    },
    Map, Set, URL, Math, Date, console
  };

  vm.createContext(context);
  vm.runInContext(swSource, context);

  const sampleRecords = [
    {
      id: "rec_1",
      sender: "Financial Dept <billing@fake-bank.org>",
      receiver: "target.user@domain.com",
      subject: "Overdue Invoice Notice",
      timestamp: 1730500000000,
      date_iso: "2026-11-01T10:00:00Z",
      time_slab: "2026-10-18 to 2026-11-02",
      composite_risk: 82,
      risk_level: "HIGH",
      text_threat_score: 85,
      url_threat_score: 79,
      threat_vectors: ["FINANCIAL_SCAM"],
      clicked_urls: [
        {
          url: "http://fake-bank.org/pay.php",
          defanged: "hxxp://fake-bank[.]org/pay[.]php",
          risk_score: 90,
          risk_level: "HIGH",
          timestamp: "2026-11-01T10:05:00Z"
        }
      ]
    }
  ];

  const html = context.generateLocalDigestHtml(
    "target.user@domain.com",
    "Target User",
    "2026-10-18",
    "2026-11-02",
    sampleRecords
  );

  assert.ok(html.includes("target.user@domain.com"), "Must contain user email");
  assert.ok(html.includes("Target User"), "Must contain user name");
  assert.ok(html.includes("billing@fake-bank.org"), "Must contain sender");
  assert.ok(html.includes("target.user@domain.com"), "Must contain receiver");
  assert.ok(html.includes("2026-10-18"), "Must contain period start");
  assert.ok(html.includes("2026-11-02"), "Must contain period end");
  assert.ok(html.includes("ML Score: 82/100 (HIGH)"), "Must contain ML composite score");
  assert.ok(html.includes("Text Threat: <strong style=\"color:#f8fafc;\">85%</strong>"), "Must contain text score");
  assert.ok(html.includes("URL Threat: <strong style=\"color:#f8fafc;\">79%</strong>"), "Must contain url score");
  assert.ok(html.includes("hxxp://fake-bank[.]org/pay[.]php"), "Must contain defanged clicked URL");
  assert.ok(html.includes("Risk: 90/100"), "Must contain click risk score");
  assert.ok(html.includes("FINANCIAL_SCAM"), "Must contain threat vector");
});
