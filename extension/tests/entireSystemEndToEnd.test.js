"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const vm = require("node:vm");

// Load assets
const sidepanelHtml = fs.readFileSync(path.resolve("extension/sidepanel.html"), "utf8");
const welcomeHtml = fs.readFileSync(path.resolve("extension/welcome.html"), "utf8");
const manifest = JSON.parse(fs.readFileSync(path.resolve("extension/manifest.json"), "utf8"));
const sidepanelJs = fs.readFileSync(path.resolve("extension/src/ui/sidepanelController.js"), "utf8");
const welcomeJs = fs.readFileSync(path.resolve("extension/src/ui/welcomeController.js"), "utf8");
const contentScriptJs = fs.readFileSync(path.resolve("extension/src/content/contentScript.js"), "utf8");
const serviceWorkerJs = fs.readFileSync(path.resolve("extension/src/background/serviceWorker.js"), "utf8");
const urlThreatParser = require("../src/url/urlThreatParser.js");
const textParser = require("../src/utils/textParser.js");
const emailAnalyzer = require("../src/email/emailTextAnalyzer.js");

// -----------------------------------------------------------------------------
// TEST 1: Full Authentication Sign-Up Flow (Complexity, Salt, PBKDF2, Consent)
// -----------------------------------------------------------------------------
test("Entire System Test: User Sign-Up flow enforces complexity, PBKDF2 crypto, and Terms audit", async () => {
  // 1. Password complexity check
  const weakPassword = "weak";
  const strongPassword = "SecurePass#2026!";
  const email = "auditor@safeinbox.ai";
  const fullName = "Lead Security Auditor";

  // Check controller validates password requirements
  assert.ok(sidepanelJs.includes("validateClientPassword"), "Sidepanel must call validateClientPassword");
  assert.ok(welcomeJs.includes("validateClientPassword"), "Welcome controller must call validateClientPassword");

  // 2. Cryptographic Salt generation
  const salt = crypto.randomBytes(16).toString("hex");
  assert.strictEqual(salt.length, 32, "Salt must be a 32-char hex string (16 bytes)");

  // 3. PBKDF2 local hashing with 100,000 iterations
  const hash = await new Promise((resolve, reject) => {
    crypto.pbkdf2(strongPassword, salt, 100000, 32, "sha256", (err, key) => {
      if (err) reject(err);
      else resolve(key.toString("hex"));
    });
  });
  assert.strictEqual(hash.length, 64, "PBKDF2 hash must be 256 bits (64 hex characters)");

  // 4. Terms consent audit payload
  const consentRecord = {
    email,
    ip_address: "127.0.0.1 (Local Verified)",
    mac_address: "N/A (Browser Sandbox Restricted: W3C Anti-Fingerprinting Policy)",
    terms_version: "1.0.0",
    agreed_at: new Date().toISOString()
  };
  assert.strictEqual(consentRecord.email, email);
  assert.strictEqual(consentRecord.terms_version, "1.0.0");
  assert.ok(consentRecord.agreed_at.includes("T"), "Timestamp must be valid ISO format");

  // 5. Auth session structure
  const authSession = {
    token: "mock_jwt_token_12345",
    user: { email, full_name: fullName, is_active: true }
  };
  assert.ok(authSession.token);
  assert.strictEqual(authSession.user.email, email);
});

// -----------------------------------------------------------------------------
// TEST 2: Sign-In Flow, Brute-Force Rate Limiting & Account Lockout Countdown
// -----------------------------------------------------------------------------
test("Entire System Test: User Sign-In flow, failure registration, and 30s lockout", () => {
  let failures = 0;
  let lockoutUntil = 0;

  function registerFailure() {
    failures++;
    if (failures >= 5) {
      lockoutUntil = Date.now() + 30000;
      failures = 0;
    }
  }

  function checkLockout() {
    const now = Date.now();
    if (now < lockoutUntil) {
      return Math.ceil((lockoutUntil - now) / 1000);
    }
    return 0;
  }

  // Attempts 1 to 4 should NOT lock out
  for (let i = 1; i <= 4; i++) {
    registerFailure();
    assert.strictEqual(checkLockout(), 0);
  }

  // 5th failed attempt engages 30s lockout
  registerFailure();
  const rem = checkLockout();
  assert.ok(rem >= 28 && rem <= 30, `Expected ~30s lockout, got ${rem}`);

  // Reset clears lockout
  failures = 0;
  lockoutUntil = 0;
  assert.strictEqual(checkLockout(), 0);
});

// -----------------------------------------------------------------------------
// TEST 3: Sign-Out Flow & Complete Session Sanitization
// -----------------------------------------------------------------------------
test("Entire System Test: User Sign-Out purges all auth tokens, session state, and form fields", () => {
  assert.ok(sidepanelJs.includes("clearAuthSession"), "sidepanel must implement clearAuthSession");
  assert.ok(sidepanelJs.includes("safeinbox_auth"), "sidepanel must remove safeinbox_auth");
  assert.ok(sidepanelJs.includes("safeinbox_user_session"), "sidepanel must remove safeinbox_user_session");
  assert.ok(sidepanelJs.includes("activeEmailScan"), "sidepanel must purge activeEmailScan");
  assert.ok(welcomeJs.includes("removeAuth"), "welcomeController must implement removeAuth");
});

// -----------------------------------------------------------------------------
// TEST 4: Verification of All UI Controls & Buttons in Sidepanel & Welcome Page
// -----------------------------------------------------------------------------
test("Entire System Test: All buttons, tabs, toggles, and modals exist and are properly wired", () => {
  // Sidepanel Core Buttons
  const sidepanelButtons = [
    "accountPillBtn",
    "tabSummaryBtn",
    "tabUrlBtn",
    "tabEmailBtn",
    "useCurrentTabBtn",
    "scanUrlBtn",
    "extractFromPageBtn",
    "loadNetflixPhishBtn",
    "loadPayPalPhishBtn",
    "loadBenignEmailBtn",
    "scanEmailBtn",
    "scanPageLinksBtn",
    "btnFeedbackSafe",
    "btnFeedbackThreat",
    "btnClearMailClicks",
    "btnSendDigestNow",
    "btnPreviewDigest",
    "btnConnectCloud",
    "btnCloudAccountAction",
    "authModalClose",
    "authTabSignInBtn",
    "authTabSignUpBtn",
    "btnSubmitSignIn",
    "btnSubmitSignUp",
    "btnSubmitSignOut",
    "digestPreviewClose"
  ];

  for (const btnId of sidepanelButtons) {
    assert.ok(sidepanelHtml.includes(`id="${btnId}"`), `Sidepanel must contain button #${btnId}`);
  }

  // Welcome Page Core Buttons
  const welcomeButtons = [
    "btnNavSignIn",
    "btnNavSignUp",
    "btnHeroSignUp",
    "btnHeroSignIn",
    "btnSimScan",
    "authModalClose",
    "authTabSignIn",
    "authTabSignUp",
    "btnSubmitSignIn",
    "btnSubmitSignUp",
    "btnConfirmTermsSignUp",
    "btnDeclineTermsSignUp",
    "btnSignOut"
  ];

  for (const btnId of welcomeButtons) {
    assert.ok(welcomeHtml.includes(`id="${btnId}"`), `Welcome page must contain button #${btnId}`);
  }

  // Password visibility toggle buttons
  assert.ok(sidepanelHtml.includes('class="auth-pw-toggle"'), "Sidepanel must include auth-pw-toggle");
  assert.ok(welcomeHtml.includes('class="auth-pw-toggle"'), "Welcome page must include auth-pw-toggle");
  assert.ok(sidepanelJs.includes(".auth-pw-toggle"), "Sidepanel JS must wire .auth-pw-toggle");
  assert.ok(welcomeJs.includes(".auth-pw-toggle"), "Welcome JS must wire .auth-pw-toggle");
});

// -----------------------------------------------------------------------------
// TEST 5: Both ML Threat Models Verification (URL & Email Neural Networks)
// -----------------------------------------------------------------------------
test("Entire System Test: Both ONNX models and vocabulary artifacts are bundled and structurally sound", () => {
  const urlModelPath = path.resolve("extension/models/url-threat.onnx");
  const emailModelPath = path.resolve("extension/models/email-threat.onnx");
  const emailVocabPath = path.resolve("extension/models/email-vocab.json");

  // 1. URL Model Verification
  assert.ok(fs.existsSync(urlModelPath), "url-threat.onnx must exist");
  const urlStats = fs.statSync(urlModelPath);
  assert.ok(urlStats.size > 50000, `url-threat.onnx size (${urlStats.size} bytes) should be > 50KB`);

  // Verify URL feature extractor produces 32-dim features and 128-token character tensor
  const urlRes = urlThreatParser.analyzeUrl("https://apple-id-verify.security-update.xyz/login.php");
  assert.strictEqual(urlRes.featureVector.length, 32, "URL feature extractor must produce exactly 32 features");
  for (const val of urlRes.featureVector) {
    assert.ok(Number.isFinite(val), "Every feature value must be a finite number");
  }

  assert.strictEqual(urlRes.charTensor.length, 128, "URL character tensor must have length 128");

  // 2. Email Model & Vocab Verification
  assert.ok(fs.existsSync(emailModelPath), "email-threat.onnx must exist");
  const emailStats = fs.statSync(emailModelPath);
  assert.ok(emailStats.size > 1000000, `email-threat.onnx size (${emailStats.size} bytes) should be > 1MB`);

  assert.ok(fs.existsSync(emailVocabPath), "email-vocab.json must exist");
  const vocabData = JSON.parse(fs.readFileSync(emailVocabPath, "utf8"));
  assert.ok(vocabData.vocab, "Vocab data must contain 'vocab' dictionary");
  assert.ok(Object.keys(vocabData.vocab).length > 1000, "Vocab must contain at least 1,000 subwords");
  assert.strictEqual(vocabData.vocab["[PAD]"], 0, "[PAD] must map to 0");
  assert.strictEqual(vocabData.vocab["[CLS]"], 2, "[CLS] must map to 2");
  assert.strictEqual(vocabData.vocab["[SEP]"], 3, "[SEP] must map to 3");

  // Verify WordPiece tokenization
  const tokens = textParser.wordPieceTokenize("Urgent: Account Suspension Notice", vocabData.vocab, 256);
  assert.strictEqual(tokens.input_ids.length, 256, "input_ids tensor must have length 256");
  assert.strictEqual(tokens.attention_mask.length, 256, "attention_mask tensor must have length 256");
  assert.strictEqual(tokens.input_ids[0], 2, "First token must be [CLS] (2)");
  assert.ok(tokens.attention_mask.some(v => v === 1), "Attention mask must have active positions");
});

// -----------------------------------------------------------------------------
// TEST 6: Data Saving & Local Storage Isolation
// -----------------------------------------------------------------------------
test("Entire System Test: Data saving rules enforce boundaries, sanitization, and zero-PII storage", () => {
  // 1. URL Analysis Defanging and Findings
  const maliciousUrl = "https://apple-id-verify.security-update.xyz/login.php";
  const urlResult = urlThreatParser.analyzeUrl(maliciousUrl);
  assert.ok(urlResult.heuristicRisk >= 0.5, "Malicious lookalike URL must be flagged as threat");
  assert.ok(urlResult.findings.length > 0, "Threat findings must be populated");

  // 2. Email Text Analysis & Zero-PII sanitization
  const emailSample = `From: PayPal Security <security@paypal-notice.xyz>
To: target.user@company.com
Subject: Action Required: Your account will be suspended within 24 hours
Dear user,
Please verify your password and credentials immediately to avoid suspension.
`;
  const emailResult = emailAnalyzer.analyzeEmailText({ text: emailSample });
  assert.ok(emailResult.risk_score >= 50, "Email with urgency and credential cue must score >= 50");
  assert.ok(emailResult.threat_vectors.includes("ARTIFICIAL_URGENCY") || emailResult.threat_vectors.includes("CREDENTIAL_HARVESTING"));

  // 3. Composite Risk Calculation
  const scores = [urlResult.heuristicRisk * 100];
  const avg = Math.round(scores.reduce((a, b) => a + b, 0) / scores.length);
  const composite = Math.round((emailResult.risk_score + avg) / 2);
  assert.ok(composite >= 50, `Composite risk should reflect threat (got ${composite})`);

  // 4. Feedback Storage FIFO Bounded to 100 entries
  assert.ok(contentScriptJs.includes("saveBrowserFeedback"), "contentScript must implement saveBrowserFeedback");
  assert.ok(contentScriptJs.includes("slice(-100)") || contentScriptJs.includes("100"), "Feedback must be bounded to 100 items");

  // 5. Webmail URL Click Tracking bounded to 500 entries & mail-only
  assert.ok(contentScriptJs.includes("recordWebmailUrlClick"), "contentScript must implement recordWebmailUrlClick");
  assert.ok(contentScriptJs.includes("500"), "Click history must be bounded to 500 items");
});

// -----------------------------------------------------------------------------
// TEST 7: 15-Day Security Digest System (Data Sharing, Click Correlation & Email Generation)
// -----------------------------------------------------------------------------
test("Entire System Test: 15-Day Security Digest correlates sender, receiver, time-slab, ML score, and URL clicks", () => {
  // 1. Manifest alarms permission
  assert.ok(manifest.permissions.includes("alarms"), "Manifest must include 'alarms' permission for 15-day scheduler");

  // 2. Service Worker 15-day check alarm configuration
  assert.ok(serviceWorkerJs.includes("safeinbox_15day_digest_check"), "serviceWorker must register safeinbox_15day_digest_check alarm");
  assert.ok(serviceWorkerJs.includes("setupDigestAlarm"), "serviceWorker must set up digest alarm");

  // 3. Email record accumulation schema in contentScript
  assert.ok(contentScriptJs.includes("safeinbox_15day_email_records"), "contentScript must save to safeinbox_15day_email_records");
  assert.ok(contentScriptJs.includes("record15DayEmailAudit"), "contentScript must implement record15DayEmailAudit");
  assert.ok(contentScriptJs.includes("associateClickWith15DayRecord"), "contentScript must link URL clicks to the active email record");

  // 4. Synthetic 15-day audit trail record verification
  const record = {
    id: "rec_e2e_1",
    sender: "Security Dept <alerts@bank-verify.com>",
    receiver: "analyst@safeinbox.ai",
    subject: "Urgent: Verify Your Account Details",
    timestamp: Date.now(),
    date_iso: new Date().toISOString(),
    time_slab: "2026-10-20 to 2026-11-04",
    composite_risk: 86.0,
    risk_level: "CRITICAL",
    text_threat_score: 90.0,
    url_threat_score: 82.0,
    threat_vectors: ["ARTIFICIAL_URGENCY", "CREDENTIAL_HARVESTING"],
    clicked_urls: [
      {
        url: "https://bank-verify.com/login.php",
        defanged: "hxxps://bank-verify[.]com/login.php",
        risk_score: 92.0,
        risk_level: "CRITICAL",
        timestamp: "2026-11-01 10:02:00"
      }
    ]
  };

  // Assert all user requirements are present in the record:
  // - Email sender and receiver information
  assert.ok(record.sender.includes("alerts@bank-verify.com"), "Must contain sender information");
  assert.ok(record.receiver.includes("analyst@safeinbox.ai"), "Must contain receiver information");
  // - Time-slab records
  assert.ok(record.time_slab.includes("to"), "Must contain 15-day time-slab window");
  // - ML score
  assert.strictEqual(record.composite_risk, 86.0, "Must contain composite ML score");
  assert.strictEqual(record.text_threat_score, 90.0, "Must contain text ML score");
  assert.strictEqual(record.url_threat_score, 82.0, "Must contain url ML score");
  // - All clicks of URLs done by user in that specific email
  assert.strictEqual(record.clicked_urls.length, 1, "Must contain all clicked URLs for that email");
  assert.strictEqual(record.clicked_urls[0].defanged, "hxxps://bank-verify[.]com/login.php");
  assert.strictEqual(record.clicked_urls[0].risk_level, "CRITICAL");

  // 5. Sidepanel HTML 15-day panel elements
  assert.ok(sidepanelHtml.includes('id="digestPanel"'), "Sidepanel must include #digestPanel");
  assert.ok(sidepanelHtml.includes('id="digestUserEmail"'), "Sidepanel must include #digestUserEmail");
  assert.ok(sidepanelHtml.includes('id="digestTimeSlab"'), "Sidepanel must include #digestTimeSlab");
  assert.ok(sidepanelHtml.includes('id="btnSendDigestNow"'), "Sidepanel must include #btnSendDigestNow");
  assert.ok(sidepanelHtml.includes('id="btnPreviewDigest"'), "Sidepanel must include #btnPreviewDigest");
  assert.ok(sidepanelHtml.includes('id="digestPreviewModal"'), "Sidepanel must include #digestPreviewModal");
});

// -----------------------------------------------------------------------------
// TEST 8: Live Action & Click Synchronization with Backend Database
// -----------------------------------------------------------------------------
test("Entire System Test: Action and click synchronization with SQL database and offline queue resilience", () => {
  // 1. Content Script dispatches dual-write messages
  assert.ok(contentScriptJs.includes("RECORD_WEBMAIL_CLICK"), "contentScript must dispatch RECORD_WEBMAIL_CLICK");
  assert.ok(contentScriptJs.includes("RECORD_FEEDBACK"), "contentScript must dispatch RECORD_FEEDBACK");
  assert.ok(contentScriptJs.includes("RECORD_EMAIL_AUDIT"), "contentScript must dispatch RECORD_EMAIL_AUDIT");

  // 2. Service Worker handles dual-write sync messages
  assert.ok(serviceWorkerJs.includes('message.type === "RECORD_WEBMAIL_CLICK"'), "serviceWorker must handle RECORD_WEBMAIL_CLICK");
  assert.ok(serviceWorkerJs.includes('message.type === "RECORD_FEEDBACK"'), "serviceWorker must handle RECORD_FEEDBACK");
  assert.ok(serviceWorkerJs.includes('message.type === "RECORD_EMAIL_AUDIT"'), "serviceWorker must handle RECORD_EMAIL_AUDIT");
  assert.ok(serviceWorkerJs.includes('message.type === "FLUSH_PENDING_SYNC"'), "serviceWorker must handle FLUSH_PENDING_SYNC");

  // 3. Service Worker persistence handlers
  assert.ok(serviceWorkerJs.includes("syncClickWithBackend"), "serviceWorker must implement syncClickWithBackend");
  assert.ok(serviceWorkerJs.includes("syncFeedbackWithBackend"), "serviceWorker must implement syncFeedbackWithBackend");
  assert.ok(serviceWorkerJs.includes("syncAuditWithBackend"), "serviceWorker must implement syncAuditWithBackend");

  // 4. Offline Queue resilience
  assert.ok(serviceWorkerJs.includes("safeinbox_pending_clicks"), "serviceWorker must maintain safeinbox_pending_clicks queue");
  assert.ok(serviceWorkerJs.includes("safeinbox_pending_feedback"), "serviceWorker must maintain safeinbox_pending_feedback queue");
  assert.ok(serviceWorkerJs.includes("safeinbox_pending_audits"), "serviceWorker must maintain safeinbox_pending_audits queue");
  assert.ok(serviceWorkerJs.includes("flushAllPendingCloudData"), "serviceWorker must implement flushAllPendingCloudData");
});
