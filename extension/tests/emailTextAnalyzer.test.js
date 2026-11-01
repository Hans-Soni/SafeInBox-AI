"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { analyzeEmailText } = require("../src/email/emailTextAnalyzer.js");

test("flags claimed-brand mismatch, urgency, and credential solicitation", () => {
  const result = analyzeEmailText({
    sender: "PayPal Support <alert@gmail.com>",
    subject: "Urgent account notice",
    text: "Your PayPal account is suspended. Verify your password within 24 hours."
  });

  assert.equal(result.target_type, "EMAIL");
  assert.equal(result.sender_domain, "gmail.com");
  assert.equal(result.claimed_company, "PayPal");
  assert.equal(result.company_intelligence.status, "IMPERSONATION_MISMATCH");
  assert.equal(result.risk_level, "CRITICAL");
  assert.ok(result.evidence.some((finding) => finding.rule_id === "RULE_EMAIL_SENDER_DOMAIN_MISMATCH"));
  assert.ok(result.evidence.some((finding) => finding.rule_id === "RULE_EMAIL_SUBJECT_URGENCY"));
  assert.ok(result.evidence.some((finding) => finding.rule_id === "RULE_EMAIL_CREDENTIAL_REQUEST"));
  assert.ok(result.evidence.some((finding) => finding.rule_id === "RULE_EMAIL_FREE_MAIL_IMPERSONATION"));
});

test("recognizes canonical sender domains and returns a stable heuristic result", () => {
  const result = analyzeEmailText({
    sender: "PayPal Security <security@accounts.paypal.com>",
    subject: "Service update",
    text: "We have updated our service information."
  });

  assert.equal(result.company_intelligence.status, "VERIFIED_DOMAIN_MATCH");
  assert.equal(result.risk_level, "LOW");
  assert.equal(result.model_available, false);
  assert.ok(Number.isFinite(result.latency_ms));
  assert.deepEqual(result.urls_analyzed, []);
});

test("extracts headers and raw URLs from pasted email text", () => {
  const result = analyzeEmailText({
    text: "From: Alex <alex@example.test>\nTo: user@example.test\nSubject: Hello\nSee https://example.test/"
  });

  assert.equal(result.sender_email, "alex@example.test");
  assert.equal(result.sender_name, "Alex");
  assert.equal(result.receiver, "user@example.test");
  assert.equal(result.subject, "Hello");
  assert.equal(result.extracted_urls_count, 1);
});
