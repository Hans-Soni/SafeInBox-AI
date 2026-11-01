"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { extractUrlsFromEmail } = require("../src/email/urlCandidateExtractor.js");

test("extracts and deduplicates hyperlink, raw URL, www, and bare-domain candidates", () => {
  const emailText = [
    "Please visit https://bad.example/login?next=https://other.example.",
    "The fallback is www.safe.example/help and the account portal is portal.example.net/login.",
    "Sender contact: security@trusted.example"
  ].join("\n");
  const urls = extractUrlsFromEmail(emailText, [
    "https://bad.example/login?next=https://other.example",
    "https://linked.example/account"
  ]);
  assert.ok(urls.includes("https://bad.example/login?next=https://other.example"));
  assert.ok(urls.includes("https://other.example/"));
  assert.ok(urls.includes("https://www.safe.example/help"));
  assert.ok(urls.includes("https://portal.example.net/login"));
  assert.ok(urls.includes("https://linked.example/account"));
  assert.equal(urls.length, 5);
  assert.ok(!urls.some((url) => url.includes("trusted.example")));
});

test("ignores unsupported schemes and malformed link targets", () => {
  assert.deepEqual(extractUrlsFromEmail("", ["javascript:alert(1)", "https://bad host/path"]), []);
});
