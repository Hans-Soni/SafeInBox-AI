"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const { webcrypto } = require("node:crypto");

const urlParser = require("../src/url/urlThreatParser.js");
const textParser = require("../src/utils/textParser.js");
const emailAnalyzer = require("../src/email/emailTextAnalyzer.js");
const { extractUrlsFromEmail } = require("../src/email/urlCandidateExtractor.js");

// =============================================================================
// PIPELINE 1: URL THREAT ENGINE - COMPREHENSIVE INPUTS & EXPECTED OUTPUTS
// =============================================================================

test("URL Pipeline: Rejects invalid, empty, or non-HTTP inputs with precise errors", () => {
  const invalidInputs = [
    { input: null, error: /Enter a URL to analyze/ },
    { input: undefined, error: /Enter a URL to analyze/ },
    { input: "", error: /Enter a URL to analyze/ },
    { input: "   ", error: /Enter a URL to analyze/ },
    { input: 12345, error: /Enter a URL to analyze/ },
    { input: {}, error: /Enter a URL to analyze/ },
    { input: "javascript:alert('xss')", error: /Only HTTP and HTTPS/ },
    { input: "data:text/html,<h1>test</h1>", error: /Only HTTP and HTTPS/ },
    { input: "file:///etc/passwd", error: /Only HTTP and HTTPS/ },
    { input: "ftp://files.example.com", error: /Only HTTP and HTTPS/ },
    { input: "chrome://extensions", error: /Only HTTP and HTTPS/ },
    { input: "about:blank", error: /Only HTTP and HTTPS/ },
    { input: "blob:https://example.com/uuid", error: /Only HTTP and HTTPS/ },
    { input: "https://bad host name/path", error: /could not be parsed/ }
  ];

  for (const { input, error } of invalidInputs) {
    assert.throws(() => urlParser.analyzeUrl(input), error, `Failed for input: ${input}`);
  }
});

test("URL Pipeline: Normal benign URLs produce zero heuristic risk and no threat findings", () => {
  const benignSamples = [
    "https://www.google.com/search?q=cybersecurity",
    "https://en.wikipedia.org/wiki/Transport_Layer_Security",
    "https://github.com/nodejs/node",
    "http://example.com/",
    "https://news.ycombinator.com/item?id=123456"
  ];

  for (const url of benignSamples) {
    const result = urlParser.analyzeUrl(url);
    assert.equal(result.heuristicRisk, 0, `Expected 0 risk for ${url}`);
    assert.equal(result.findings.length, 0, `Expected 0 findings for ${url}`);
    assert.equal(result.attackTypes.length, 0);
    assert.ok(result.canonicalUrl.startsWith("http"));
    assert.equal(result.featureVector.length, 32);
    assert.equal(result.charTensor.length, 128);
    assert.ok(result.featureVector.every(Number.isFinite));
  }
});

test("URL Pipeline: Detects IDN Homograph and Mixed-Script Attacks across scripts", () => {
  // Cyrillic homoglyphs
  const cyrillicSpoof = urlParser.analyzeUrl("https://\u0440\u0430ypal.com/signin");
  assert.ok(cyrillicSpoof.attackTypes.includes("HOMOGRAPH_ATTACK"));
  assert.ok(cyrillicSpoof.findings.some(f => f.signal === "homograph"));

  // Punycode representation of homograph
  const punycodeSpoof = urlParser.analyzeUrl("https://xn--e1aybc.xn--p1ai/"); // Cyrillic
  assert.ok(punycodeSpoof.metrics.hasPunycode);
  assert.ok(punycodeSpoof.metrics.punycodeLabels >= 1);

  // Greek homoglyphs
  const greekSpoof = urlParser.analyzeUrl("https://\u03bffficial-apple.com/login");
  assert.ok(greekSpoof.metrics.mixedScripts || greekSpoof.metrics.hasUnicode);
});

test("URL Pipeline: Detects Typosquatting and Brand Lookalikes with Levenshtein metrics", () => {
  const brands = [
    { url: "https://paypa1-security.com/update", brand: "paypal" },
    { url: "https://g00gle-accounts.net/auth", brand: "google" },
    { url: "https://micros0ft-support.xyz/verify", brand: "microsoft" },
    { url: "https://app1e-id-verify.com/portal", brand: "apple" },
    { url: "https://bankofamer1ca-login.org/secure", brand: "bankofamerica" }
  ];

  for (const { url, brand } of brands) {
    const result = urlParser.analyzeUrl(url);
    assert.ok(
      result.attackTypes.includes("TYPOSQUATTING") || result.matchedBrand === brand,
      `Failed to match brand ${brand} for ${url}`
    );
    assert.ok(result.heuristicRisk > 0, `Expected elevated risk for ${url}`);
    assert.ok(result.metrics.brandDistance <= 3);
  }
});

test("URL Pipeline: Detects DGA (Domain Generation Algorithm) high-entropy domains", () => {
  const dgaSamples = [
    "https://qzxvnmkjhgfdsa129847.top/download",
    "https://98b7c6d5e4f3a210.xyz/",
    "https://xkjf9823mndf9823.click/gate"
  ];

  for (const url of dgaSamples) {
    const result = urlParser.analyzeUrl(url);
    assert.ok(
      result.attackTypes.includes("DGA_SUSPECT") || result.metrics.highEntropy || result.metrics.entropy >= 3.0,
      `Expected DGA or entropy trigger for ${url}`
    );
    assert.ok(result.metrics.entropy > 0);
  }
});

test("URL Pipeline: Detects Open Redirect parameters and distinguishes external targets", () => {
  // External destination
  const external = urlParser.analyzeUrl("https://safe.example.com/login?redirect_uri=https://malicious-destination.test/steal");
  assert.ok(external.attackTypes.includes("OPEN_REDIRECT"));
  assert.equal(external.metrics.redirectParameter, true);
  assert.equal(external.metrics.externalRedirect, true);

  // Same-origin relative path redirect
  const internal = urlParser.analyzeUrl("https://safe.example.com/login?next=/dashboard");
  assert.equal(internal.metrics.redirectParameter, true);
  assert.equal(internal.metrics.externalRedirect, false);
});

test("URL Pipeline: Detects Internal / Private IP addresses, localhost, and nonstandard encodings", () => {
  const internalTargets = [
    "http://127.0.0.1/admin",
    "http://127.0.1.50/status",
    "http://10.0.0.1/router",
    "http://192.168.1.1/setup",
    "http://172.16.0.1/internal",
    "http://169.254.169.254/latest/meta-data/", // AWS metadata service
    "http://localhost:8080/dashboard",
    "http://sub.localhost/api",
    "http://printer.local/jobs",
    "http://app.internal/config",
    "http://0.0.0.0/",
    "http://[::1]/",
    "http://[::ffff:127.0.0.1]/",
    "http://[::ffff:7f00:1]/",
    "http://0177.0.0.1/",    // Octal IP for 127.0.0.1
    "http://0x7f000001/"    // Hex IP for 127.0.0.1
  ];

  for (const url of internalTargets) {
    const result = urlParser.analyzeUrl(url);
    assert.ok(
      result.attackTypes.includes("INTERNAL_IP_TARGET"),
      `Expected INTERNAL_IP_TARGET for ${url}`
    );
    assert.equal(result.metrics.isInternal, true, `Expected isInternal=true for ${url}`);
  }
});

test("URL Pipeline: Detects injection payloads (Path traversal, XSS, SQLi, LFI, Double encoding)", () => {
  const injections = [
    { url: "https://example.com/download?file=../../../../etc/passwd", attack: "INJECTION_PAYLOAD", signal: "pathTraversal" },
    { url: "https://example.com/view?file=%2e%2e%2f%2e%2e%2fwin.ini", attack: "INJECTION_PAYLOAD", signal: "pathTraversal" },
    { url: "https://example.com/search?q=%3Cscript%3Ealert(document.cookie)%3C/script%3E", attack: "INJECTION_PAYLOAD", signal: "xss" },
    { url: "https://example.com/profile?name=test%22%3E%3Csvg%20onload=alert(1)%3E", attack: "INJECTION_PAYLOAD", signal: "xss" },
    { url: "https://example.com/items?id=1%20UNION%20ALL%20SELECT%20username,password%20FROM%20users", attack: "INJECTION_PAYLOAD", signal: "sqli" },
    { url: "https://example.com/action?id=1;%20DROP%20TABLE%20members;", attack: "INJECTION_PAYLOAD", signal: "sqli" },
    { url: "https://example.com/page?include=php://filter/read=convert.base64-encode/resource=index.php", attack: "INJECTION_PAYLOAD", signal: "lfi" },
    { url: "https://example.com/lookup?file=/proc/self/environ", attack: "INJECTION_PAYLOAD", signal: "lfi" },
    { url: "https://example.com/%252e%252e%252fsecret", attack: "INJECTION_PAYLOAD", signal: "doubleEncoding" }
  ];

  for (const { url, attack, signal } of injections) {
    const result = urlParser.analyzeUrl(url);
    assert.ok(result.attackTypes.includes(attack), `Expected attack ${attack} for ${url}`);
    assert.ok(result.findings.some(f => f.signal === signal), `Expected signal ${signal} for ${url}`);
  }
});

test("URL Pipeline: Detects embedded URL credentials and executable extensions", () => {
  const credentialsUrl = urlParser.analyzeUrl("https://admin:SuperSecret123@portal.example.com/login");
  assert.equal(credentialsUrl.metrics.hasCredentials, true);
  assert.ok(credentialsUrl.findings.some(f => f.signal === "credentials"));

  const executableUrls = [
    "https://update-center.example.com/setup.exe",
    "https://update-center.example.com/installer.msi",
    "https://update-center.example.com/app.apk",
    "https://update-center.example.com/patch.dmg",
    "https://update-center.example.com/script.bat",
    "https://update-center.example.com/command.cmd"
  ];
  for (const url of executableUrls) {
    const res = urlParser.analyzeUrl(url);
    assert.equal(res.metrics.executablePath, true, `Expected executablePath=true for ${url}`);
  }
});

// =============================================================================
// PIPELINE 2: EMAIL TEXT ANALYSIS - SENSITIVE DATA SCRUBBING & DETECTION
// =============================================================================

test("Email Text Pipeline: HTML strip, entity decode, and sensitive data masking", () => {
  const htmlSample = `
    <html>
      <head><title>Phish</title><style>.hidden { display:none; }</style></head>
      <body>
        <script>alert('malicious')</script>
        <p>Dear Customer &amp; Partner,</p>
        <div>Please transfer $1,250.00 USD immediately to account at 192.168.1.50 or visit https://pay-portal.xyz/pay.</div>
        <br/>
        <span>Bare link: auth.portal.net/login</span>
      </body>
    </html>
  `;
  const stripped = textParser.stripHtml(htmlSample);
  assert.doesNotMatch(stripped, /<script>|<style>|<html>|<title>/);
  assert.match(stripped, /Dear Customer & Partner,/);

  const masked = textParser.maskSensitiveTokens(stripped);
  assert.doesNotMatch(masked, /https:\/\/pay-portal\.xyz\/pay/);
  assert.doesNotMatch(masked, /192\.168\.1\.50/);
  assert.doesNotMatch(masked, /\$1,250\.00 USD/);
  assert.match(masked, /\[MONEY\]/);
  assert.match(masked, /\[IP\]/);
  assert.match(masked, /\[URL\]/);
});

test("Email Text Pipeline: Brand mismatch and free-mail impersonation rules", () => {
  const brands = [
    { name: "PayPal", terms: ["paypal"], badEmail: "alert@gmail.com", goodEmail: "service@paypal.com" },
    { name: "Netflix", terms: ["netflix"], badEmail: "billing@yahoo.com", goodEmail: "info@mailer.netflix.com" },
    { name: "Microsoft", terms: ["microsoft"], badEmail: "support@hotmail.com", goodEmail: "account-security-noreply@accountprotection.microsoft.com" },
    { name: "Apple", terms: ["apple"], badEmail: "security@proton.me", goodEmail: "appleid@id.apple.com" },
    { name: "Amazon", terms: ["amazon"], badEmail: "prime-refund@aol.com", goodEmail: "auto-confirm@amazon.com" }
  ];

  for (const { name, terms, badEmail, goodEmail } of brands) {
    // Bad case: free-mail / mismatch
    const badResult = textParser.analyzeEmailText({
      sender: `${name} Security <${badEmail}>`,
      subject: "Security Notification",
      body: `This is an official notice from ${name}.`
    });
    assert.equal(badResult.claimed_company, name);
    assert.ok(badResult.threat_vectors.includes("SENDER_SPOOFING"), `Expected SENDER_SPOOFING for ${name} with ${badEmail}`);
    assert.equal(badResult.company_intelligence.status, "IMPERSONATION_MISMATCH");

    // Good case: verified canonical domain
    const goodResult = textParser.analyzeEmailText({
      sender: `${name} Verified <${goodEmail}>`,
      subject: "Monthly Statement",
      body: `Your statement from ${name} is ready.`
    });
    assert.equal(goodResult.company_intelligence.status, "VERIFIED_DOMAIN_MATCH");
    assert.ok(!goodResult.threat_vectors.includes("SENDER_SPOOFING"));
  }
});

test("Email Text Pipeline: Urgency, Credential Harvesting, Financial Scams, and Coercion vectors", () => {
  const multiThreatEmail = {
    sender: "Finance Desk <finance@accounting-dept.test>",
    receiver: "employee@company.test",
    subject: "FINAL WARNING: Payment overdue - Account suspension imminent",
    body: `
      URGENT ACTION REQUIRED: An unclaimed refund of $4,500.00 is pending.
      Your invoice #99218 is severely past due.
      You must confirm your login credentials, password, and 2FA verification code within 12 hours.
      Failure to comply will result in immediate legal action and a formal police report.
    `
  };

  const result = textParser.analyzeEmailText(multiThreatEmail);
  assert.ok(result.threat_vectors.includes("ARTIFICIAL_URGENCY"));
  assert.ok(result.threat_vectors.includes("FINANCIAL_SCAM"));
  assert.ok(result.threat_vectors.includes("CREDENTIAL_HARVESTING"));
  assert.ok(result.threat_vectors.includes("BEHAVIORAL_MANIPULATION"));
  assert.equal(result.risk_level, "CRITICAL");
  assert.ok(result.risk_score >= 80);
});

test("Email Text Facade (`emailTextAnalyzer.js`) strips sensitive email text from public output", () => {
  const secretBody = "Super secret employee private data that should never be exported";
  const result = emailAnalyzer.analyzeEmailText({
    sender: "CEO <ceo@company.test>",
    subject: "Private memo",
    body: secretBody
  });

  assert.equal(result.body_text, undefined, "body_text must be stripped");
  assert.equal(result.normalized_text, undefined, "normalized_text must be stripped");
  assert.ok(!JSON.stringify(result).includes(secretBody));
});

test("WordPiece Tokenizer: Tensor constraints, special tokens, and vocabulary checks", () => {
  const vocab = {
    "[PAD]": 0, "[UNK]": 1, "[CLS]": 2, "[SEP]": 3,
    account: 4, security: 5, alert: 6, ":": 7, "[URL]": 8, "[MONEY]": 9
  };

  const tokens = textParser.wordPieceTokenize("account security [URL] [MONEY]", vocab, 8);
  assert.equal(tokens.input_ids.length, 8);
  assert.equal(tokens.attention_mask.length, 8);
  // [CLS] at pos 0, [SEP] after tokens, [PAD] at end
  assert.equal(tokens.input_ids[0], 2); // [CLS]
  assert.equal(tokens.input_ids[1], 4); // account
  assert.equal(tokens.input_ids[2], 5); // security
  assert.equal(tokens.input_ids[3], 8); // [URL]
  assert.equal(tokens.input_ids[4], 9); // [MONEY]
  assert.equal(tokens.input_ids[5], 3); // [SEP]
  assert.equal(tokens.input_ids[6], 0); // [PAD]
  assert.equal(tokens.input_ids[7], 0); // [PAD]

  assert.deepEqual(Array.from(tokens.attention_mask), [1, 1, 1, 1, 1, 1, 0, 0]);

  // Error handling: missing special tokens
  assert.throws(() => textParser.wordPieceTokenize("test", { token: 1 }), /must define integer IDs/);
  // Error handling: invalid length
  assert.throws(() => textParser.wordPieceTokenize("test", vocab, 2), /Token sequence length must be between 3 and 4096/);
});

// =============================================================================
// PIPELINE 3: URL CANDIDATE EXTRACTOR - INPUTS, PUNCTUATION, DEDUPLICATION
// =============================================================================

test("URL Candidate Extractor: Normalizes bare domains, www, and trims complex punctuation", () => {
  const sampleText = `
    Check out these resources:
    1. Visit https://portal.example.com/login?token=abc.
    2. Fallback to www.backup-portal.com/help, or portal.internal-service.org/test!
    3. Contact support at support@legit-domain.com (this should NOT be extracted as a URL).
    4. Trailing braces: (https://nested.example.com/path) and [https://bracket.example.com/item].
    5. Duplicate mention: https://portal.example.com/login?token=abc
  `;
  const rawHrefs = [
    "https://portal.example.com/login?token=abc",
    "https://external-link.example.com/target"
  ];

  const extracted = extractUrlsFromEmail(sampleText, rawHrefs);
  assert.ok(extracted.includes("https://portal.example.com/login?token=abc"));
  assert.ok(extracted.includes("https://www.backup-portal.com/help"));
  assert.ok(extracted.includes("https://portal.internal-service.org/test"));
  assert.ok(extracted.includes("https://nested.example.com/path"));
  assert.ok(extracted.includes("https://bracket.example.com/item"));
  assert.ok(extracted.includes("https://external-link.example.com/target"));

  // Ensure email address is not extracted as URL
  assert.ok(!extracted.some(u => u.includes("support@legit-domain.com")));
  // Ensure deduplication
  const occurrences = extracted.filter(u => u === "https://portal.example.com/login?token=abc").length;
  assert.equal(occurrences, 1);
});

// =============================================================================
// PIPELINE 4: SERVICE WORKER - CACHING, DEDUPLICATION, REJECTION & TTL
// =============================================================================

test("Service Worker Pipeline: Cache eviction, TTL, concurrency, and validation", async () => {
  const values = {};
  const sessionValues = {};
  const runtimeOnMessageListeners = [];
  const runtimeOnConnectListeners = [];

  const harness = {
    chrome: {
      runtime: {
        onInstalled: { addListener() {} },
        onConnect: { addListener(cb) { runtimeOnConnectListeners.push(cb); } },
        onMessage: { addListener(cb) { runtimeOnMessageListeners.push(cb); } },
        async sendMessage(message) {
          if (message.type === "RUN_EMAIL_TEXT_INFERENCE") {
            const { normalized_text, body_text, ...res } = textParser.analyzeEmailText(message.email);
            return { ok: true, result: res };
          }
          return null;
        }
      },
      offscreen: { async hasDocument() { return true; } },
      contextMenus: {
        removeAll(cb) { cb(); },
        create() {},
        onClicked: { addListener() {} }
      },
      sidePanel: {
        setPanelBehavior: async () => {},
        open: async () => {}
      },
      storage: {
        local: {
          async get(keys) {
            if (keys === null) return { ...values };
            if (typeof keys === "string") return Object.hasOwn(values, keys) ? { [keys]: values[keys] } : {};
            return Object.fromEntries(keys.filter(k => Object.hasOwn(values, k)).map(k => [k, values[k]]));
          },
          async set(items) { Object.assign(values, items); },
          async remove(keys) { for (const k of Array.isArray(keys) ? keys : [keys]) delete values[k]; }
        },
        session: {
          async get(key) { return Object.hasOwn(sessionValues, key) ? { [key]: sessionValues[key] } : {}; },
          async set(items) { Object.assign(sessionValues, items); }
        }
      }
    },
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
    RangeError,
    setTimeout,
    clearTimeout,
    importScripts(...paths) {
      if (paths.some(f => f.includes("textParser.js"))) harness.EmailTextParser = textParser;
      else harness.UrlThreatParser = urlParser;
    }
  };

  const context = vm.createContext(harness);
  const swCode = fs.readFileSync(path.join(__dirname, "../src/background/serviceWorker.js"), "utf8");
  vm.runInContext(swCode, context);

  const dispatch = (msg, sender = {}) => new Promise((resolve) => {
    let handled = false;
    for (const listener of runtimeOnMessageListeners) {
      const keepOpen = listener(msg, sender, resolve);
      if (keepOpen) handled = true;
    }
    if (!handled) resolve({ ok: false, error: "Not handled" });
  });

  // 1. Invalid email payload: non-string fields
  const typeErrorRes = await dispatch({ type: "ANALYZE_EMAIL_TEXT", email: { text: 12345 } });
  assert.equal(typeErrorRes.ok, false);
  assert.match(typeErrorRes.error, /must be text/);

  // 2. Empty email content
  const emptyRes = await dispatch({ type: "ANALYZE_EMAIL_TEXT", email: { text: "" } });
  assert.equal(emptyRes.ok, false);
  assert.match(emptyRes.error, /Email content was empty/);

  // 3. Oversized email content (> 1,000,000 characters)
  const hugeRes = await dispatch({ type: "ANALYZE_EMAIL_TEXT", email: { text: "A".repeat(1000005) } });
  assert.equal(hugeRes.ok, false);
  assert.match(hugeRes.error, /limit/);

  // 4. Valid email scan with caching & sensitive scrub
  const validRes = await dispatch({
    type: "ANALYZE_EMAIL_TEXT",
    email: {
      sender: "PayPal Security <fake@gmail.com>",
      subject: "Action Required",
      body: "Please verify credentials."
    }
  });
  assert.equal(validRes.ok, true);
  assert.equal(validRes.result.sender_email, undefined);
  assert.equal(validRes.result.body_text, undefined);

  // 5. Cache check
  const emailCacheKeys = Object.keys(values).filter(k => k.startsWith("emailThreatScan:"));
  assert.equal(emailCacheKeys.length, 1);

  // 6. Security check on EMAIL_SCAN_OPENED: reject non-webmail, HTTP origins, and malicious oversized URLs
  const rejectInsecureOrigin = await dispatch(
    { type: "EMAIL_SCAN_OPENED", email: { subject: "Test", text: "Test", urls: [] } },
    { tab: { id: 1 }, url: "http://mail.google.com/" } // HTTP instead of HTTPS
  );
  assert.equal(rejectInsecureOrigin.ok, false);

  const rejectUntrustedOrigin = await dispatch(
    { type: "EMAIL_SCAN_OPENED", email: { subject: "Test", text: "Test", urls: [] } },
    { tab: { id: 1 }, url: "https://evil-phishing-site.com/" }
  );
  assert.equal(rejectUntrustedOrigin.ok, false);

  const rejectTooManyUrls = await dispatch(
    { type: "EMAIL_SCAN_OPENED", email: { subject: "Test", text: "Test", urls: Array(105).fill("https://example.com") } },
    { tab: { id: 1 }, url: "https://mail.google.com/" }
  );
  assert.equal(rejectTooManyUrls.ok, false);

  // 7. Accept legitimate handoff from supported webmail
  const acceptValidHandoff = await dispatch(
    {
      type: "EMAIL_SCAN_OPENED",
      email: {
        sender: "Trusted <trusted@example.com>",
        subject: "Meeting",
        text: "Meeting at 3 PM",
        urls: ["https://meet.google.com/abc-defg-hij"]
      }
    },
    { tab: { id: 99 }, url: "https://mail.google.com/mail/u/0/#inbox" }
  );
  assert.equal(acceptValidHandoff.ok, true);
  assert.equal(sessionValues.activeEmailScan.tabId, 99);
  assert.equal(sessionValues.activeEmailScan.urls.length, 1);
});

// =============================================================================
// PIPELINE 5: SIDE PANEL CALCULATIONS & FEEDBACK BOUNDS
// =============================================================================

test("Side Panel Pipeline: Composite Risk Arithmetic Mean & Clamping", () => {
  const source = fs.readFileSync(path.join(__dirname, "../src/ui/sidepanelController.js"), "utf8");
  const context = {
    document: { addEventListener() {} },
    URL, performance, Map, Set, Math, Date, console
  };
  vm.createContext(context);
  vm.runInContext(source, context);

  // Test zero URLs: combined equals text score
  const zeroUrls = JSON.parse(JSON.stringify(context.calculateEmailRiskAverage(75, [])));
  assert.deepEqual(zeroUrls, { textScore: 75, urlAverage: null, urlHighest: null, combined: 75 });

  // Test single URL: arithmetic mean of text and single URL score
  const singleUrl = JSON.parse(JSON.stringify(context.calculateEmailRiskAverage(80, [40])));
  assert.deepEqual(singleUrl, { textScore: 80, urlAverage: 40, urlHighest: 40, combined: 60 });

  // Test multiple URLs: average URL score + highest URL tracking
  const multipleUrls = JSON.parse(JSON.stringify(context.calculateEmailRiskAverage(30, [10, 90, 50])));
  // URL average = (10 + 90 + 50) / 3 = 50. Combined = (30 + 50) / 2 = 40.
  assert.deepEqual(multipleUrls, { textScore: 30, urlAverage: 50, urlHighest: 90, combined: 40 });

  // Test clamping on negative or out-of-range inputs
  const clamped = JSON.parse(JSON.stringify(context.calculateEmailRiskAverage(-10, [150, -50])));
  assert.deepEqual(clamped, { textScore: 0, urlAverage: 50, urlHighest: 100, combined: 25 });
});

test("Side Panel Pipeline: Defanging URLs for safe presentation", () => {
  const source = fs.readFileSync(path.join(__dirname, "../src/ui/sidepanelController.js"), "utf8");
  const context = {
    document: { addEventListener() {} },
    URL, performance, Map, Set, Math, Date, console
  };
  vm.createContext(context);
  vm.runInContext(source, context);

  assert.equal(context.defangUrl("http://evil.com/malware"), "hxxp://evil[.]com/malware");
  assert.equal(context.defangUrl("https://sub.evil.com/path?a=1&b=2"), "hxxps://sub[.]evil[.]com/path?a=1&b=2");
});

// =============================================================================
// PIPELINE 6: SECURITY, ZERO-LEAK LIFECYCLE & DATA TRANSFER VALIDATION
// =============================================================================

test("Security & ReDoS: SQLi regular expression defends against catastrophic backtracking", () => {
  const benignLongQuery = "https://example.com/search?query=select%20" + "a".repeat(10000);
  const start = performance.now();
  const res = urlParser.analyzeUrl(benignLongQuery);
  const duration = performance.now() - start;

  assert.ok(duration < 100, `ReDoS check took too long: ${duration}ms`);
  assert.equal(res.findings.some(f => f.signal === "sqli"), false);

  const realSqli = urlParser.analyzeUrl("https://example.com/search?q=select%20user,pass%20from%20accounts");
  assert.equal(realSqli.findings.some(f => f.signal === "sqli"), true);
});

test("Security: escapeHtml safely processes numbers, booleans, and null values without throwing", () => {
  const source = fs.readFileSync(path.join(__dirname, "../src/content/contentScript.js"), "utf8");
  const context = {
    document: { readyState: "loading", addEventListener() {} },
    window: { location: { hostname: "mail.google.com" } },
    chrome: { runtime: { onMessage: { addListener() {} } } },
    MutationObserver: class { observe() {} },
    URL, Map, Set, Math, Date, console
  };
  vm.createContext(context);
  vm.runInContext(source, context);

  assert.equal(context.escapeHtml(0), "0");
  assert.equal(context.escapeHtml(404), "404");
  assert.equal(context.escapeHtml(null), "");
  assert.equal(context.escapeHtml(undefined), "");
  assert.equal(context.escapeHtml("<script>alert(1)</script>"), "&lt;script&gt;alert(1)&lt;/script&gt;");
  assert.equal(context.escapeHtml(' "hello" & \'world\' '), ' &quot;hello&quot; &amp; &#39;world&#39; ');
});

test("Zero-Leak Lifecycle: Tab removal and navigation purges ephemeral email session data", async () => {
  const sessionValues = {
    activeEmailScan: { tabId: 42, subject: "Sensitive Financial Statement", urls: [] }
  };
  const tabRemovedListeners = [];
  const tabUpdatedListeners = [];

  const harness = {
    chrome: {
      runtime: {
        onInstalled: { addListener() {} },
        onConnect: { addListener() {} },
        onMessage: { addListener() {} }
      },
      tabs: {
        onRemoved: { addListener(cb) { tabRemovedListeners.push(cb); } },
        onUpdated: { addListener(cb) { tabUpdatedListeners.push(cb); } }
      },
      sidePanel: { setPanelBehavior: async () => {} },
      contextMenus: { removeAll(cb) { cb(); }, create() {}, onClicked: { addListener() {} } },
      storage: {
        session: {
          async get(key) { return Object.hasOwn(sessionValues, key) ? { [key]: sessionValues[key] } : {}; },
          async remove(key) { delete sessionValues[key]; }
        },
        local: {
          async get() { return {}; },
          async set() {},
          async remove() {}
        }
      }
    },
    crypto: webcrypto,
    TextEncoder, URL, Date, Map, Set, Promise, Math, Array, Object, Error, TypeError, setTimeout, clearTimeout,
    importScripts() {}
  };

  const context = vm.createContext(harness);
  const swCode = fs.readFileSync(path.join(__dirname, "../src/background/serviceWorker.js"), "utf8");
  vm.runInContext(swCode, context);

  // 1. Another tab is closed - tab 42 data remains intact
  for (const listener of tabRemovedListeners) listener(999);
  await new Promise(r => setTimeout(r, 10));
  assert.ok(sessionValues.activeEmailScan !== undefined);

  // 2. Tab 42 is closed - session storage is immediately purged!
  for (const listener of tabRemovedListeners) listener(42);
  await new Promise(r => setTimeout(r, 10));
  assert.equal(sessionValues.activeEmailScan, undefined, "Ephemeral session data must be deleted on tab close");

  // 3. Tab navigates away from webmail
  sessionValues.activeEmailScan = { tabId: 43, subject: "Confidential Email", urls: [] };
  for (const listener of tabUpdatedListeners) listener(43, { url: "https://news.ycombinator.com/" });
  await new Promise(r => setTimeout(r, 10));
  assert.equal(sessionValues.activeEmailScan, undefined, "Ephemeral session data must be deleted on navigation away from webmail");
});

test("Security & Context Menu: Rejects javascript: URLs and bounds oversized selections", async () => {
  const localValues = {};
  const contextMenuListeners = [];

  const harness = {
    chrome: {
      runtime: {
        onInstalled: { addListener() {} },
        onConnect: { addListener() {} },
        onMessage: { addListener() {} }
      },
      tabs: { onRemoved: { addListener() {} }, onUpdated: { addListener() {} } },
      sidePanel: {
        setPanelBehavior: async () => {},
        open: async () => {}
      },
      contextMenus: {
        removeAll(cb) { cb(); },
        create() {},
        onClicked: { addListener(cb) { contextMenuListeners.push(cb); } }
      },
      storage: {
        local: {
          async set(items) { Object.assign(localValues, items); }
        },
        session: { async get() { return {}; } }
      }
    },
    crypto: webcrypto,
    TextEncoder, URL, Date, Map, Set, Promise, Math, Array, Object, Error, TypeError, setTimeout, clearTimeout,
    importScripts() {}
  };

  const context = vm.createContext(harness);
  const swCode = fs.readFileSync(path.join(__dirname, "../src/background/serviceWorker.js"), "utf8");
  vm.runInContext(swCode, context);

  // Malicious javascript: URL clicked in context menu
  for (const listener of contextMenuListeners) {
    listener({ menuItemId: "aegisai-scan-link", linkUrl: "javascript:alert('malicious')", tabId: 1 });
  }
  assert.equal(localValues.pendingScanUrl, undefined, "Must NOT store javascript: protocol URLs");

  // Oversized text selection (e.g. 500,000 chars)
  for (const listener of contextMenuListeners) {
    listener({ menuItemId: "aegisai-scan-selection", selectionText: "A".repeat(500000), tabId: 1 });
  }
  assert.equal(localValues.pendingScanEmail.length, 100000, "Selection text must be bounded to 100,000 characters");
});

test("Webmail In-Page Banners: Feedback storage is bounded to 100 items with truncation", async () => {
  const source = fs.readFileSync(path.join(__dirname, "../src/content/contentScript.js"), "utf8");
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
  vm.runInContext(source, context);

  // Push 105 URL feedbacks from banner
  for (let i = 0; i < 105; i++) {
    await context.sendUrlBooleanFeedback(`https://banner-test-${i}.example.com/`, true);
  }
  assert.equal(stored.offline_url_feedback.length, 100, "Must be bounded to 100 items");
  assert.equal(stored.offline_url_feedback[99].target, "https://banner-test-104.example.com/");
  assert.equal(stored.offline_url_feedback[99].source, "webmail_banner");

  // Push 25KB email text from banner
  const hugeEmail = { cleanBodyText: "W".repeat(25000) };
  await context.sendEmailBooleanFeedback(hugeEmail, false);
  assert.equal(stored.offline_text_feedback[0].target.length, 20000, "Must be truncated to 20,000 characters");
  assert.equal(stored.offline_text_feedback[0].target_truncated, true);
});

test("Data Transfer & Memory: Text parser truncates > 1 MB bodies and handles large inputs", () => {
  const hugeBody = "Normal text content. " + "X".repeat(1200000);
  const result = textParser.analyzeEmailText({
    sender: "Support <support@example.com>",
    subject: "Large Message",
    body: hugeBody
  });

  assert.equal(result.truncated, true);
  assert.ok(result.body_text.length <= 1000000);
});

test("Webmail URL Click Tracking: strictly mail only, bounded to 500 items, and excluded from general sites", async () => {
  const source = fs.readFileSync(path.join(__dirname, "../src/content/contentScript.js"), "utf8");
  const stored = {};
  const webmailContext = {
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
  vm.createContext(webmailContext);
  vm.runInContext(source, webmailContext);

  // 1. Record clicks inside mail
  const recorded = await webmailContext.recordWebmailUrlClick({
    url: "https://paypa1-security.com/verify",
    emailSubject: "Urgent Security Alert",
    sender: "security@paypa1-security.com",
    riskScore: 90,
    riskLevel: "CRITICAL",
    proceeded: false,
    source: "flagged_email_link"
  });
  assert.equal(recorded, true);
  assert.equal(stored.webmail_url_clicks.length, 1);
  assert.equal(stored.webmail_url_clicks[0].url, "https://paypa1-security.com/verify");
  assert.equal(stored.webmail_url_clicks[0].defanged, "hxxps://paypa1-security[.]com/verify");
  assert.equal(stored.webmail_url_clicks[0].email_subject, "Urgent Security Alert");
  assert.equal(stored.webmail_url_clicks[0].sender, "security@paypa1-security.com");
  assert.equal(stored.webmail_url_clicks[0].risk_score, 90);
  assert.equal(stored.webmail_url_clicks[0].risk_level, "CRITICAL");
  assert.equal(stored.webmail_url_clicks[0].proceeded, false);
  assert.equal(stored.webmail_url_clicks[0].source, "flagged_email_link");
  assert.ok(stored.webmail_url_clicks[0].id.startsWith("click_"));
  assert.ok(stored.webmail_url_clicks[0].timestamp > 0);

  // 2. Bound to 500 items FIFO
  for (let i = 0; i < 510; i++) {
    await webmailContext.recordWebmailUrlClick({
      url: `https://click-item-${i}.example.com/`,
      emailSubject: `Subject ${i}`,
      sender: "sender@example.com",
      riskScore: 10,
      riskLevel: "SAFE",
      proceeded: true,
      source: "email_body_link"
    });
  }
  assert.equal(stored.webmail_url_clicks.length, 500, "Must be bounded to 500 items maximum");
  assert.equal(stored.webmail_url_clicks[499].url, "https://click-item-509.example.com/");

  // 3. Strict Mail Boundary: Non-webmail domains must NEVER record clicks
  const generalSiteContext = {
    document: { readyState: "loading", addEventListener() {} },
    window: { location: { hostname: "www.google.com" } },
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
  vm.createContext(generalSiteContext);
  vm.runInContext(source, generalSiteContext);

  const clicksBefore = stored.webmail_url_clicks.length;
  const outsideResult = await generalSiteContext.recordWebmailUrlClick({
    url: "https://wikipedia.org/wiki/Security",
    emailSubject: "",
    sender: "",
    riskScore: 0,
    riskLevel: "SAFE",
    proceeded: true,
    source: "web_search"
  });
  assert.equal(outsideResult, false, "Must reject click tracking outside webmail");
  assert.equal(stored.webmail_url_clicks.length, clicksBefore, "No click must be recorded from general websites");
});

test("Side Panel: Export Current Analysis removed and Mail URL Click History present", () => {
  const html = fs.readFileSync(path.join(__dirname, "../sidepanel.html"), "utf8");
  const controller = fs.readFileSync(path.join(__dirname, "../src/ui/sidepanelController.js"), "utf8");

  // Export controls removed
  assert.doesNotMatch(html, /id="copyReportBtn"/);
  assert.doesNotMatch(html, /id="exportJsonBtn"/);
  assert.doesNotMatch(html, /Export Current Analysis/);
  assert.doesNotMatch(controller, /el\.copyReportBtn\.addEventListener/);
  assert.doesNotMatch(controller, /el\.exportJsonBtn\.addEventListener/);

  // Mail URL Click History present
  assert.match(html, /id="mailClicksPanel"/);
  assert.match(html, /id="mailClicksHeader"/);
  assert.match(html, /id="mailClicksCountBadge"/);
  assert.match(html, /id="mailClicksList"/);
  assert.match(html, /id="btnClearMailClicks"/);
  assert.match(controller, /initMailClicksTracker/);
  assert.match(controller, /renderMailClicks/);
});

test("General Web Search Link Scanner: Prompts user for inspection preference and respects site choice", () => {
  const scannerSource = fs.readFileSync(path.join(__dirname, "../src/content/urlLinkScanner.js"), "utf8");
  assert.match(scannerSource, /site_inspection_preferences/);
  assert.match(scannerSource, /checkSiteInspectionPermission/);
  assert.match(scannerSource, /showSiteInspectionPrompt/);
  assert.match(scannerSource, /Always Inspect/);
  assert.match(scannerSource, /Leave It/);
  // Ensure scanner NEVER writes to webmail click tracking
  assert.doesNotMatch(scannerSource, /webmail_url_clicks/);
});

test("User Authentication: Side panel includes Sign In / Sign Up modal and auth management", () => {
  const html = fs.readFileSync(path.join(__dirname, "../sidepanel.html"), "utf8");
  const controller = fs.readFileSync(path.join(__dirname, "../src/ui/sidepanelController.js"), "utf8");
  const serviceWorker = fs.readFileSync(path.join(__dirname, "../src/background/serviceWorker.js"), "utf8");

  // HTML controls
  assert.match(html, /id="accountPillBtn"/);
  assert.match(html, /id="accountPillLabel"/);
  assert.match(html, /id="authModalBackdrop"/);
  assert.match(html, /id="authTabSignInBtn"/);
  assert.match(html, /id="authTabSignUpBtn"/);
  assert.match(html, /id="authSignInForm"/);
  assert.match(html, /id="authSignUpForm"/);
  assert.match(html, /id="btnSubmitSignIn"/);
  assert.match(html, /id="btnSubmitSignUp"/);
  assert.match(html, /id="btnSubmitSignOut"/);
  assert.match(html, /id="cloudAccountRow"/);

  // Controller wiring
  assert.match(controller, /initAuthManager/);
  assert.match(controller, /saveAuthSession/);
  assert.match(controller, /clearAuthSession/);
  assert.match(controller, /refreshAuthState/);
  assert.match(controller, /renderAuthUI/);
  assert.match(controller, /\/api\/v1\/auth\/signin/);
  assert.match(controller, /\/api\/v1\/auth\/signup/);
  assert.match(controller, /safeinbox_auth/);

  // Service Worker auth header injection
  assert.match(serviceWorker, /stored\.safeinbox_auth\.token/);
  assert.match(serviceWorker, /Authorization/);
});

test("Welcome & Onboarding Page: Features, Guidance, Live Threat Simulator, and Sign In / Sign Up", () => {
  const welcomeHtml = fs.readFileSync(path.join(__dirname, "../welcome.html"), "utf8");
  const welcomeCtrl = fs.readFileSync(path.join(__dirname, "../src/ui/welcomeController.js"), "utf8");
  const serviceWorker = fs.readFileSync(path.join(__dirname, "../src/background/serviceWorker.js"), "utf8");
  const sidepanelHtml = fs.readFileSync(path.join(__dirname, "../sidepanel.html"), "utf8");

  // Welcome page structure & components
  assert.match(welcomeHtml, /SAFEINBOX<span class="brand-accent">AI<\/span>/);
  assert.match(welcomeHtml, /id="guidance"/);
  assert.match(welcomeHtml, /How SafeInbox AI Protects You/);
  assert.match(welcomeHtml, /id="features"/);
  assert.match(welcomeHtml, /Core Capabilities/);
  assert.match(welcomeHtml, /id="simulator"/);
  assert.match(welcomeHtml, /Try The Live Threat Engine/);
  assert.match(welcomeHtml, /id="privacy"/);
  assert.match(welcomeHtml, /Zero-Leak Privacy Guarantees/);

  // Sign In and Sign Up buttons and modals
  assert.match(welcomeHtml, /id="btnNavSignIn"/);
  assert.match(welcomeHtml, /id="btnNavSignUp"/);
  assert.match(welcomeHtml, /id="btnHeroSignIn"/);
  assert.match(welcomeHtml, /id="btnHeroSignUp"/);
  assert.match(welcomeHtml, /id="formSignIn"/);
  assert.match(welcomeHtml, /id="formSignUp"/);
  assert.match(welcomeHtml, /id="btnSubmitSignIn"/);
  assert.match(welcomeHtml, /id="btnSubmitSignUp"/);

  // Welcome controller functionality
  assert.match(welcomeCtrl, /UrlThreatParser\.analyzeUrl/);
  assert.match(welcomeCtrl, /\/api\/v1\/auth\/signin/);
  assert.match(welcomeCtrl, /\/api\/v1\/auth\/signup/);
  assert.match(welcomeCtrl, /safeinbox_auth/);
  assert.match(welcomeCtrl, /runSimulator/);

  // Service worker opens welcome.html on first install
  assert.match(serviceWorker, /details\.reason === "install"/);
  assert.match(serviceWorker, /welcome\.html/);

  // Side panel links to welcome.html
  assert.match(sidepanelHtml, /welcome\.html/);
  assert.match(sidepanelHtml, /id="linkOpenWelcome"/);
});

test("Terms and Conditions: Document structure, consent logging, and sign-in allowance enforcement", () => {
  const termsHtml = fs.readFileSync(path.join(__dirname, "../terms.html"), "utf8");
  const termsCtrl = fs.readFileSync(path.join(__dirname, "../src/ui/termsController.js"), "utf8");
  const welcomeHtml = fs.readFileSync(path.join(__dirname, "../welcome.html"), "utf8");
  const welcomeCtrl = fs.readFileSync(path.join(__dirname, "../src/ui/welcomeController.js"), "utf8");
  const sidepanelHtml = fs.readFileSync(path.join(__dirname, "../sidepanel.html"), "utf8");

  // 1. Terms page structure & legal compliance sections
  assert.match(termsHtml, /Terms and Conditions of Use/);
  assert.match(termsHtml, /Version 1\.0\.0/);
  assert.match(termsHtml, /Local-First Processing &amp; Autonomous Operation/);
  assert.match(termsHtml, /Scoped Webmail Isolation/);
  assert.match(termsHtml, /General Web Search &amp; External Website Inspection Opt-In/);
  assert.match(termsHtml, /Zero-PII &amp; Zero-Retention Privacy Commitment/);
  assert.match(termsHtml, /Strict URL vs\. Text Storage Partitioning/);
  assert.match(termsHtml, /Network Transport Lockdown: HTTPS over TCP Only/);
  assert.match(termsHtml, /Terms Consent Logging &amp; Telemetry Audit Record/);
  assert.match(termsHtml, /User Email ID/);
  assert.match(termsHtml, /Client IP Address/);
  assert.match(termsHtml, /MAC \/ Device Hardware Identifier/);
  assert.match(termsHtml, /Advisory Security Heuristics &amp; Limitation of Liability/);

  // 2. Terms page is clean legal document (Consent Status card removed per user specification)
  assert.equal(termsHtml.includes('id="consentCard"'), false, "Consent Status card must be removed from terms.html");
  assert.equal(termsHtml.includes("Action Required"), false);

  // 3. Welcome page Terms integration & Sign Up Terms Review View (Terms verified once at SignUp; not asked again in SignIn)
  assert.match(welcomeHtml, /terms\.html/);
  assert.equal(welcomeHtml.includes('id="checkTermsSignIn"'), false, "SignIn form must not prompt for Terms again once verified at SignUp");
  assert.match(welcomeHtml, /id="authTermsReviewView"/);
  assert.match(welcomeHtml, /id="termsReviewScrollbox"/);
  assert.match(welcomeHtml, /id="btnConfirmTermsSignUp"/);
  assert.match(welcomeHtml, /id="btnDeclineTermsSignUp"/);

  // 4. Welcome controller: SignUp Terms review step, refresh if declined, and telemetry saving
  assert.match(welcomeCtrl, /authTermsReviewView/);
  assert.match(welcomeCtrl, /btnConfirmTermsSignUp/);
  assert.match(welcomeCtrl, /btnDeclineTermsSignUp/);
  assert.match(welcomeCtrl, /window\.location\.reload\(\)/);
  assert.match(welcomeCtrl, /saveTermsConsent/);
  assert.match(welcomeCtrl, /safeinbox_terms_consent/);
  assert.match(welcomeCtrl, /detectHardwareMac/);


  // 5. Terms controller functionality
  assert.match(termsCtrl, /TERMS_VERSION = "1.0.0"/);
  assert.match(termsCtrl, /safeinbox_terms_consent/);
  assert.match(termsCtrl, /\/api\/v1\/auth\/terms-consent/);

  // 6. Side panel links to terms
  assert.match(sidepanelHtml, /terms\.html/);
  assert.match(sidepanelHtml, /id="linkOpenTerms"/);
});



