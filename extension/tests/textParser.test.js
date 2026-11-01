"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const {
  analyzeEmailText,
  maskSensitiveTokens,
  splitIntoChunks,
  stripHtml,
  wordPieceTokenize,
  wordPieceTokenizeChunks
} = require("../src/utils/textParser.js");

test("cleans HTML and masks links, IP addresses, and money amounts", () => {
  const cleaned = stripHtml("<p>Pay&nbsp;now &amp; verify</p><style>.x { color:red }</style><script>ignore()</script>");
  assert.match(cleaned, /Pay now & verify/);
  assert.doesNotMatch(cleaned, /color:red|ignore/);
  assert.equal(
    maskSensitiveTokens("Visit https://example.test/a, address 192.0.2.9 and pay $649.99. See bare.example.test."),
    "Visit [URL], address [IP] and pay [MONEY]. See [URL]."
  );
});

test("detects sender impersonation, recipient spread, subject pressure, financial hooks, and credential cues", () => {
  const result = analyzeEmailText({
    sender: "PayPal Security <alert@gmail.com>",
    receiver: "one@example.test, two@example.test",
    cc: "copy@example.test",
    bcc: "a@example.test, b@example.test, c@example.test, d@example.test, e@example.test",
    subject: "URGENT ACTION REQUIRED: unclaimed refund",
    body: "Verify your password and one-time code to keep the account."
  });

  assert.ok(result.threat_vectors.includes("SENDER_SPOOFING"));
  assert.ok(result.threat_vectors.includes("ARTIFICIAL_URGENCY"));
  assert.ok(result.threat_vectors.includes("FINANCIAL_SCAM"));
  assert.ok(result.threat_vectors.includes("CREDENTIAL_HARVESTING"));
  assert.ok(result.threat_vectors.includes("BEHAVIORAL_MANIPULATION"));
  assert.equal(result.bcc_count, 5);
  assert.equal(result.recipient_count, 8);
  assert.equal(result.risk_level, "CRITICAL");
  assert.ok(result.evidence.every((finding) => !finding.evidence.includes("alert@gmail.com")));
});

test("WordPiece creates fixed-size transformer tensors and respects padding masks", () => {
  const vocabulary = {
    "[PAD]": 0, "[UNK]": 1, "[CLS]": 2, "[SEP]": 3,
    subject: 4, ":": 5, "urgent": 6, "##ly": 7, "[URL]": 8
  };
  const result = wordPieceTokenize("subject: urgently [URL]", vocabulary, 8);
  assert.ok(result.input_ids instanceof Int32Array);
  assert.ok(result.attention_mask instanceof Int32Array);
  assert.deepEqual(Array.from(result.input_ids), [2, 4, 5, 6, 7, 8, 3, 0]);
  assert.deepEqual(Array.from(result.attention_mask), [1, 1, 1, 1, 1, 1, 1, 0]);
});

test("WordPiece requires the model special tokens and chunks long messages", () => {
  assert.throws(() => wordPieceTokenize("test", {}), /must define integer IDs/);
  assert.throws(() => wordPieceTokenize("test", {
    "[PAD]": 0, "[UNK]": 1, "[CLS]": 2, "[SEP]": -1
  }), /non-negative integer ID/);
  assert.deepEqual(splitIntoChunks("a b c d e", 2), ["a b", "c d", "e"]);
  const vocabulary = {
    "[PAD]": 0, "[UNK]": 1, "[CLS]": 2, "[SEP]": 3,
    one: 4, two: 5, three: 6, four: 7
  };
  const chunks = wordPieceTokenizeChunks("one two three four", vocabulary, 4);
  assert.equal(chunks.length, 2);
  assert.deepEqual(Array.from(chunks[0].input_ids), [2, 4, 5, 3]);
  assert.deepEqual(Array.from(chunks[1].input_ids), [2, 6, 7, 3]);
});

test("recognizes verified sender domains without flagging a brand mismatch", () => {
  const result = analyzeEmailText({
    sender: "PayPal Notifications <notice@accounts.paypal.com>",
    subject: "Monthly activity",
    body: "Your monthly summary is ready."
  });
  assert.equal(result.company_intelligence.status, "VERIFIED_DOMAIN_MATCH");
  assert.ok(!result.threat_vectors.includes("SENDER_SPOOFING"));
});

test("treats a consumer mailbox as an impersonation risk even when its domain is a brand service", () => {
  const result = analyzeEmailText({
    sender: "Google Account Team <notice@gmail.com>",
    subject: "Account update",
    body: "Review your account settings."
  });
  assert.ok(result.threat_vectors.includes("SENDER_SPOOFING"));
  assert.ok(result.evidence.some((finding) => finding.rule_id === "RULE_EMAIL_FREE_MAIL_IMPERSONATION"));
});
