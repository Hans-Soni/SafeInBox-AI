"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const {
  analyzeUrl,
  FEATURE_COUNT,
  CHAR_TENSOR_LENGTH,
  CHAR_VOCAB_SIZE
} = require("../src/url/urlThreatParser.js");

test("keeps a normal HTTPS URL free of heuristic threat findings", () => {
  const result = analyzeUrl("https://www.wikipedia.org/wiki/Security");
  assert.equal(result.heuristicRisk, 0);
  assert.deepEqual(result.attackTypes, []);
});

test("detects mixed-script IDN homographs and brand-like spellings", () => {
  const homograph = analyzeUrl("https://\u0440\u0430ypal.com/login");
  assert.ok(homograph.attackTypes.includes("HOMOGRAPH_ATTACK"));
  assert.match(homograph.unicodeHostname, /\u0440/);

  const typo = analyzeUrl("https://paypa1-login.example.xyz/login");
  assert.ok(typo.attackTypes.includes("TYPOSQUATTING"));
  assert.ok(typo.findings.some((finding) => finding.detail.includes("paypal")));

  const brandSpoof = analyzeUrl("https://paypal.example.net/login");
  assert.ok(brandSpoof.attackTypes.includes("TYPOSQUATTING"));
});

test("measures high-entropy domain characteristics", () => {
  const result = analyzeUrl("https://xj3m9q2v8b4n.top/");
  assert.ok(result.findings.some((finding) => finding.signal === "dga"));
  assert.ok(result.metrics.vowelConsonantRatio >= 0);
  assert.ok(result.metrics.keyboardSwaps >= 0);
});

test("detects external redirect parameters without making a network request", () => {
  const result = analyzeUrl("https://example.com/out?next=https%3A%2F%2Foutside.example");
  assert.ok(result.attackTypes.includes("OPEN_REDIRECT"));
  assert.ok(result.findings.some((finding) => finding.detail.includes("not fetched")));
});

test("detects canonicalized private IPs and local hosts", () => {
  for (const url of ["http://127.0.0.1/admin", "http://0x7f000001/admin", "http://localhost/"]) {
    assert.ok(analyzeUrl(url).attackTypes.includes("INTERNAL_IP_TARGET"), url);
  }
  assert.ok(analyzeUrl("http://[::ffff:7f00:1]/").attackTypes.includes("INTERNAL_IP_TARGET"));
});

test("detects encoded injection and repeated URL encoding", () => {
  const result = analyzeUrl("https://example.com/%252e%252e%252fetc%252fpasswd?q=%3Cscript%3E");
  assert.ok(result.attackTypes.includes("INJECTION_PAYLOAD"));
  assert.ok(result.findings.some((finding) => finding.title === "Repeated URL encoding"));
});

test("detects SQLi, open URL credentials, and nonstandard IP encodings", () => {
  const sql = analyzeUrl("https://example.com/search?q=1%20UNION%20SELECT%20name%20FROM%20users");
  assert.ok(sql.findings.some((finding) => finding.title === "SQL injection marker"));

  const credentials = analyzeUrl("https://admin:secret@example.com/");
  assert.ok(credentials.findings.some((finding) => finding.title === "Embedded URL credentials"));

  const octalIp = analyzeUrl("http://0177.0.0.1/");
  assert.ok(octalIp.attackTypes.includes("INTERNAL_IP_TARGET"));
});

test("creates finite model features and fixed-length character tensors", () => {
  const result = analyzeUrl("https://\u0440\u0430ypal.com/login?next=https://example.net");
  assert.equal(result.featureVector.length, FEATURE_COUNT);
  assert.equal(result.charTensor.length, CHAR_TENSOR_LENGTH);
  assert.ok(result.featureVector.every(Number.isFinite));
  assert.ok(result.charTensor.every((token) => token >= 0 && token < CHAR_VOCAB_SIZE));
});

test("rejects non-HTTP schemes and malformed URLs explicitly", () => {
  assert.throws(() => analyzeUrl("javascript:alert(1)"), /Only HTTP and HTTPS/);
  assert.throws(() => analyzeUrl("https://bad host/"), /could not be parsed/);
});
