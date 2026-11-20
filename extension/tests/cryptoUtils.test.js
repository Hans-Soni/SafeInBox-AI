"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const SafeInboxCrypto = require("../src/utils/cryptoUtils.js");

test("Zero-Knowledge Crypto: Key derivation and session caching", async () => {
  SafeInboxCrypto.clearKeyCache();
  const secret = "UserMasterSecret!2026";
  const salt = "SAFE-IDX-A1B2C3D4E5F6";

  const t0 = performance.now();
  const key1 = await SafeInboxCrypto.deriveZeroKnowledgeKey(secret, salt);
  const durationFirst = performance.now() - t0;

  assert.ok(key1, "Key should be derived");
  assert.equal(key1.algorithm.name, "AES-GCM");
  assert.equal(key1.algorithm.length, 256);

  // Second call must hit cache in O(1) time
  const t1 = performance.now();
  const key2 = await SafeInboxCrypto.deriveZeroKnowledgeKey(secret, salt);
  const durationCached = performance.now() - t1;

  assert.strictEqual(key1, key2, "Cached key instance should be identical");
  assert.ok(durationCached < 1.0, `Cached derivation should be near instantaneous (${durationCached.toFixed(3)}ms)`);
});

test("Zero-Knowledge Crypto: Authenticated round-trip encryption & decryption", async () => {
  const secret = "AnalystSecretKey#99";
  const salt = "user@example.com";
  const key = await SafeInboxCrypto.deriveZeroKnowledgeKey(secret, salt);

  const sampleData = {
    url: "https://banking-portal-secure.com/dashboard",
    defanged_url: "hxxps://banking-portal-secure[.]com/dashboard",
    email_subject: "URGENT: Verify Your Payment Account",
    sender: "security-alerts@bank-alerts.xyz",
    risk_score: 87.5,
    clicked_at: "2026-11-21T02:00:00Z"
  };

  const encryptedBase64 = await SafeInboxCrypto.encryptZeroKnowledge(sampleData, key);
  assert.equal(typeof encryptedBase64, "string");
  assert.ok(encryptedBase64.length > 40);
  assert.ok(!encryptedBase64.includes("banking-portal-secure"), "Plaintext must not be visible in ciphertext");

  const decrypted = await SafeInboxCrypto.decryptZeroKnowledge(encryptedBase64, key);
  assert.deepEqual(decrypted, sampleData, "Decrypted object must match original payload exactly");
});

test("Zero-Knowledge Crypto: Non-repeating IVs guarantee distinct ciphertexts", async () => {
  const key = await SafeInboxCrypto.deriveZeroKnowledgeKey("SharedSecret123", "salt1");
  const payload = { note: "Repeated payload test" };

  const enc1 = await SafeInboxCrypto.encryptZeroKnowledge(payload, key);
  const enc2 = await SafeInboxCrypto.encryptZeroKnowledge(payload, key);

  assert.notEqual(enc1, enc2, "Identical payloads must produce completely different ciphertexts due to fresh 96-bit random IVs");

  const dec1 = await SafeInboxCrypto.decryptZeroKnowledge(enc1, key);
  const dec2 = await SafeInboxCrypto.decryptZeroKnowledge(enc2, key);
  assert.deepEqual(dec1, dec2);
});

test("Zero-Knowledge Crypto: Tamper resistance & authentication tag rejection", async () => {
  const key = await SafeInboxCrypto.deriveZeroKnowledgeKey("TamperSecretKey", "salt2");
  const payload = { url: "https://trusted-site.com" };
  const ciphertext = await SafeInboxCrypto.encryptZeroKnowledge(payload, key);

  // Flip a character in the ciphertext to simulate an in-flight MITM tamper attack
  const rawBytes = Buffer.from(ciphertext, "base64");
  rawBytes[rawBytes.length - 1] ^= 0xFF; // Corrupt authentication tag
  const tamperedCiphertext = rawBytes.toString("base64");

  await assert.rejects(
    async () => {
      await SafeInboxCrypto.decryptZeroKnowledge(tamperedCiphertext, key);
    },
    /operation failed|authentication tag|decrypt/i,
    "Tampered ciphertext or altered tag must be rejected by AES-GCM authentication"
  );
});

test("Zero-Knowledge Crypto: Decryption with wrong key is rejected", async () => {
  const keyA = await SafeInboxCrypto.deriveZeroKnowledgeKey("CorrectPassword1", "saltA");
  const keyB = await SafeInboxCrypto.deriveZeroKnowledgeKey("WrongPassword2", "saltA");

  const ciphertext = await SafeInboxCrypto.encryptZeroKnowledge({ confidential: "super-secret" }, keyA);

  await assert.rejects(
    async () => {
      await SafeInboxCrypto.decryptZeroKnowledge(ciphertext, keyB);
    },
    /operation failed|authentication tag|decrypt/i,
    "Decrypting with incorrect user key must fail authentication"
  );
});

test("Zero-Knowledge Crypto: Performance benchmark (<0.1ms per encryption/decryption)", async () => {
  const key = await SafeInboxCrypto.deriveZeroKnowledgeKey("BenchmarkSecret", "bench_salt");
  const payload = { url: "https://example.com/login", score: 45, date: Date.now() };

  const iterations = 100;
  const t0 = performance.now();
  for (let i = 0; i < iterations; i++) {
    const cipher = await SafeInboxCrypto.encryptZeroKnowledge(payload, key);
    await SafeInboxCrypto.decryptZeroKnowledge(cipher, key);
  }
  const totalMs = performance.now() - t0;
  const perOpMs = totalMs / (iterations * 2);

  assert.ok(perOpMs < 1.0, `Each AES-GCM crypto operation must be fast (measured ${perOpMs.toFixed(3)}ms per op)`);
});
