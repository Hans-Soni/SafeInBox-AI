/**
 * SafeInbox AI - Zero-Knowledge Cryptographic Utilities
 *
 * Provides hardware-accelerated, authenticated client-side encryption (AES-256-GCM)
 * using the browser-native W3C Web Crypto API (`crypto.subtle`).
 *
 * Time Complexity:
 * - Key Derivation: PBKDF2-SHA256 (100,000 iterations), cached in-memory in O(1) for session reuse.
 * - Encryption / Decryption: AES-256-GCM with 96-bit random IV, O(N) where N = payload byte length (<0.1ms).
 */

(function (root, factory) {
  if (typeof module === "object" && module.exports) {
    module.exports = factory();
  } else {
    root.SafeInboxCrypto = factory();
  }
})(typeof globalThis !== "undefined" ? globalThis : typeof self !== "undefined" ? self : this, function () {
  "use strict";

  // In-memory key derivation cache for O(1) amortized session performance
  const _derivedKeyCache = new Map();

  function getCrypto() {
    if (typeof globalThis !== "undefined" && globalThis.crypto) {
      return globalThis.crypto;
    }
    if (typeof window !== "undefined" && window.crypto) {
      return window.crypto;
    }
    if (typeof self !== "undefined" && self.crypto) {
      return self.crypto;
    }
    throw new Error("W3C Web Crypto API (crypto.subtle) is not available in this environment.");
  }

  /**
   * Derive a 256-bit AES-GCM CryptoKey from a secret passphrase and salt string.
   * Caches derived key instances to avoid redundant PBKDF2 iterations.
   *
   * @param {string} secret - User password, token, or private device secret.
   * @param {string} [saltStr] - Unique salt (e.g. user index_id or email).
   * @returns {Promise<CryptoKey>} Derived AES-256-GCM CryptoKey.
   */
  async function deriveZeroKnowledgeKey(secret, saltStr = "safeinbox_zk_default_salt") {
    if (!secret || typeof secret !== "string") {
      throw new TypeError("Encryption secret must be a non-empty string.");
    }

    const cacheKey = `${saltStr}::${secret}`;
    if (_derivedKeyCache.has(cacheKey)) {
      return _derivedKeyCache.get(cacheKey);
    }

    const cryptoObj = getCrypto();
    const enc = new TextEncoder();
    const keyMaterial = await cryptoObj.subtle.importKey(
      "raw",
      enc.encode(secret),
      "PBKDF2",
      false,
      ["deriveKey"]
    );

    const derivedKey = await cryptoObj.subtle.deriveKey(
      {
        name: "PBKDF2",
        salt: enc.encode(saltStr),
        iterations: 100000,
        hash: "SHA-256"
      },
      keyMaterial,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"]
    );

    // Bound cache size to prevent memory bloat
    if (_derivedKeyCache.size >= 50) {
      const oldestKey = _derivedKeyCache.keys().next().value;
      _derivedKeyCache.delete(oldestKey);
    }
    _derivedKeyCache.set(cacheKey, derivedKey);
    return derivedKey;
  }

  /**
   * Encrypt an arbitrary object or string with AES-256-GCM.
   * Generates a fresh, non-repeating 96-bit (12-byte) initialization vector (IV) per call.
   *
   * @param {object|string} data - Payload to encrypt.
   * @param {CryptoKey} cryptoKey - AES-256-GCM CryptoKey.
   * @returns {Promise<string>} Base64-encoded string: [12-byte IV][Ciphertext + 16-byte GCM Tag].
   */
  async function encryptZeroKnowledge(data, cryptoKey) {
    if (!data) throw new TypeError("Data to encrypt cannot be null or undefined.");
    if (!cryptoKey) throw new TypeError("AES-256-GCM CryptoKey is required.");

    const cryptoObj = getCrypto();
    const enc = new TextEncoder();
    const plaintextBytes = enc.encode(typeof data === "string" ? data : JSON.stringify(data));

    // 96-bit (12-byte) standard IV for AES-GCM
    const iv = cryptoObj.getRandomValues(new Uint8Array(12));

    const ciphertextBuffer = await cryptoObj.subtle.encrypt(
      { name: "AES-GCM", iv },
      cryptoKey,
      plaintextBytes
    );

    // Pack [12-byte IV] + [Ciphertext + Tag]
    const combined = new Uint8Array(iv.length + ciphertextBuffer.byteLength);
    combined.set(iv, 0);
    combined.set(new Uint8Array(ciphertextBuffer), iv.length);

    return bytesToBase64(combined);
  }

  /**
   * Decrypt a base64-encoded AES-256-GCM payload.
   * Authenticates the tag and returns the parsed original object or string.
   *
   * @param {string} base64Payload - Base64-encoded [12-byte IV][Ciphertext + Tag].
   * @param {CryptoKey} cryptoKey - AES-256-GCM CryptoKey.
   * @returns {Promise<any>} Decrypted object or string.
   */
  async function decryptZeroKnowledge(base64Payload, cryptoKey) {
    if (!base64Payload || typeof base64Payload !== "string") {
      throw new TypeError("Ciphertext payload must be a non-empty string.");
    }
    if (!cryptoKey) throw new TypeError("AES-256-GCM CryptoKey is required.");

    const cryptoObj = getCrypto();
    const combined = base64ToBytes(base64Payload.trim());
    if (combined.length < 28) { // 12-byte IV + 16-byte GCM auth tag minimum
      throw new Error("Invalid ciphertext payload: insufficient byte length.");
    }

    const iv = combined.subarray(0, 12);
    const ciphertext = combined.subarray(12);

    const decryptedBuffer = await cryptoObj.subtle.decrypt(
      { name: "AES-GCM", iv },
      cryptoKey,
      ciphertext
    );

    const text = new TextDecoder().decode(decryptedBuffer);
    try {
      return JSON.parse(text);
    } catch {
      return text;
    }
  }

  /**
   * Clear in-memory derived key cache (e.g. on user sign-out).
   */
  function clearKeyCache() {
    _derivedKeyCache.clear();
  }

  // --- Fast Standard Base64 Encoding & Decoding ---

  function bytesToBase64(bytes) {
    if (typeof Buffer !== "undefined") {
      return Buffer.from(bytes).toString("base64");
    }
    let binary = "";
    const len = bytes.byteLength;
    for (let i = 0; i < len; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
  }

  function base64ToBytes(b64) {
    if (typeof Buffer !== "undefined") {
      return new Uint8Array(Buffer.from(b64, "base64"));
    }
    const binary = atob(b64);
    const len = binary.length;
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
  }

  return {
    deriveZeroKnowledgeKey,
    encryptZeroKnowledge,
    decryptZeroKnowledge,
    clearKeyCache
  };
});
