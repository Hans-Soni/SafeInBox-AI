"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");

const { analyzeEmailText, computeManipulationRadar } = require("../src/utils/textParser.js");

test("Manipulation Radar: Urgency Pressure detection and scoring", () => {
  const result = analyzeEmailText({
    subject: "URGENT: Your account will be suspended within 24 hours!",
    body: "Immediate action required. Final warning: your services expire today. Do not delay, act now."
  });

  assert.ok(result.manipulation_radar, "manipulation_radar must be present in output");
  const radar = result.manipulation_radar;
  assert.ok(radar.urgency_score >= 70, `Expected urgency_score >= 70, got ${radar.urgency_score}`);
  assert.equal(radar.dominant_tactic, "URGENCY");
  assert.ok(["HIGH", "SEVERE"].includes(radar.cognitive_load_level));
  assert.ok(radar.detected_tactics.some(t => t.includes("Urgency Pressure")));
});

test("Manipulation Radar: Authority Coercion and Intimidation detection", () => {
  const result = analyzeEmailText({
    subject: "Executive Directive: Internal Security Investigation",
    body: "By order of the Chief Executive Officer, this compliance inquiry is strictly confidential. Legal action and police report will follow for non-compliance. Do not discuss with colleagues."
  });

  const radar = result.manipulation_radar;
  assert.ok(radar, "manipulation_radar must be present");
  assert.ok(radar.authority_score >= 65, `Expected authority_score >= 65, got ${radar.authority_score}`);
  assert.equal(radar.dominant_tactic, "AUTHORITY");
  assert.ok(["HIGH", "SEVERE"].includes(radar.cognitive_load_level));
  assert.ok(radar.detected_tactics.some(t => t.includes("Authority Coercion")));
});

test("Manipulation Radar: Financial Scam and Transaction Hook detection", () => {
  const result = analyzeEmailText({
    subject: "Unclaimed Tax Refund & Overdue Invoice Notification",
    body: "You have an unclaimed refund of $4,500. Payment is overdue on invoice #8821. Process wire transfer or direct deposit immediately to claim your reward."
  });

  const radar = result.manipulation_radar;
  assert.ok(radar, "manipulation_radar must be present");
  assert.ok(radar.financial_score >= 65, `Expected financial_score >= 65, got ${radar.financial_score}`);
  assert.equal(radar.dominant_tactic, "FINANCIAL");
  assert.ok(radar.detected_tactics.some(t => t.includes("Financial Hook")));
});

test("Manipulation Radar: Credential Harvest Cue detection", () => {
  const result = analyzeEmailText({
    subject: "Security Alert: Verify Login Credentials & 2FA Code",
    body: "Please confirm your password and one-time verification code to prevent sign-in lockout. Update login credentials immediately."
  });

  const radar = result.manipulation_radar;
  assert.ok(radar, "manipulation_radar must be present");
  assert.ok(radar.credential_score >= 70, `Expected credential_score >= 70, got ${radar.credential_score}`);
  assert.equal(radar.dominant_tactic, "CREDENTIAL");
  assert.ok(radar.detected_tactics.some(t => t.includes("Credential Harvest")));
});

test("Manipulation Radar: Benign text produces low cognitive load and zero coercive pressure", () => {
  const result = analyzeEmailText({
    subject: "Team Lunch Next Tuesday",
    body: "Hi folks, let's meet at the terrace cafeteria next Tuesday at 12:30 PM for lunch. Feel free to bring your favorite dessert. See you all then!"
  });

  const radar = result.manipulation_radar;
  assert.ok(radar, "manipulation_radar must be present");
  assert.ok(radar.urgency_score < 25, `Expected low urgency, got ${radar.urgency_score}`);
  assert.ok(radar.authority_score < 25, `Expected low authority, got ${radar.authority_score}`);
  assert.ok(radar.financial_score < 25, `Expected low financial, got ${radar.financial_score}`);
  assert.ok(radar.credential_score < 25, `Expected low credential, got ${radar.credential_score}`);
  assert.equal(radar.dominant_tactic, "NONE");
  assert.equal(radar.cognitive_load_level, "LOW");
  assert.equal(radar.detected_tactics.length, 0);
});
