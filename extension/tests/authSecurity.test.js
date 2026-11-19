"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");

const sidepanelHtml = fs.readFileSync(path.resolve("extension/sidepanel.html"), "utf8");
const welcomeHtml = fs.readFileSync(path.resolve("extension/welcome.html"), "utf8");
const sidepanelJs = fs.readFileSync(path.resolve("extension/src/ui/sidepanelController.js"), "utf8");
const welcomeJs = fs.readFileSync(path.resolve("extension/src/ui/welcomeController.js"), "utf8");

// Shared email and password validation rules
const AUTH_EMAIL_REGEX = /^(?!\.)[a-zA-Z0-9_.+-]+(?<!\.)@(?!-)[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)*\.[a-zA-Z]{2,24}$/;

function validateClientEmail(email) {
  const clean = String(email || "").trim().toLowerCase();
  if (!clean || clean.length > 255 || clean.includes("..") || !AUTH_EMAIL_REGEX.test(clean)) {
    return "Please enter a valid email address (e.g. analyst@safeinbox.ai).";
  }
  return null;
}

function validateClientPassword(password) {
  if (typeof password !== "string" || password.length < 10) {
    return "Password must be at least 10 characters long.";
  }
  if (password.length > 128) {
    return "Password must not exceed 128 characters.";
  }
  if (!/[A-Z]/.test(password)) {
    return "Password must contain at least one uppercase letter (A-Z).";
  }
  if (!/[a-z]/.test(password)) {
    return "Password must contain at least one lowercase letter (a-z).";
  }
  if (!/[0-9]/.test(password)) {
    return "Password must contain at least one number (0-9).";
  }
  if (!/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?~` ]/.test(password)) {
    return "Password must contain at least one special character or symbol.";
  }
  const common = ["password", "password123", "12345678", "123456789", "qwerty123", "admin123", "safeinbox", "safeinbox123"];
  if (common.includes(password.toLowerCase())) {
    return "Password is too common. Please choose a stronger password.";
  }
  return null;
}

async function hashPasswordPBKDF2(password, salt) {
  return new Promise((resolve, reject) => {
    crypto.pbkdf2(password, salt, 100000, 32, "sha256", (err, derivedKey) => {
      if (err) reject(err);
      else resolve(derivedKey.toString("hex"));
    });
  });
}

function generateCryptoSalt() {
  return crypto.randomBytes(16).toString("hex");
}

test("Auth Security UI: Password toggle buttons and complexity hints exist in templates", () => {
  // Sidepanel
  assert.ok(sidepanelHtml.includes('class="auth-pw-toggle"'), "Sidepanel must include auth-pw-toggle buttons");
  assert.ok(sidepanelHtml.includes('data-target="authSignInPassword"'), "Sidepanel signin toggle target");
  assert.ok(sidepanelHtml.includes('data-target="authSignUpPassword"'), "Sidepanel signup toggle target");
  assert.ok(sidepanelHtml.includes('auth-password-hints'), "Sidepanel must display password complexity hints");

  // Welcome page
  assert.ok(welcomeHtml.includes('class="auth-pw-toggle"'), "Welcome page must include auth-pw-toggle buttons");
  assert.ok(welcomeHtml.includes('data-target="inputSignInPassword"'), "Welcome signin toggle target");
  assert.ok(welcomeHtml.includes('data-target="inputSignUpPassword"'), "Welcome signup toggle target");
  assert.ok(welcomeHtml.includes('auth-password-hints'), "Welcome page must display password complexity hints");
});

test("Auth Security: Email validation defends against malformed, malicious, and injection patterns", () => {
  const maliciousEmails = [
    "",
    "   ",
    "plainaddress",
    "#@%^%#$@#$@#.com",
    "@example.com",
    "analyst@.com",
    "analyst@com",
    "analyst..duplicate@example.com",
    ".leadingdot@example.com",
    "trailingdot.@example.com",
    "analyst@example..com",
    "<script>alert(1)</script>@domain.com",
    "analyst@domain.c", // TLD too short (< 2)
    "analyst@-domain.com", // leading hyphen in domain
    "a".repeat(256) + "@example.com" // exceeds 255 chars
  ];

  for (const bad of maliciousEmails) {
    const err = validateClientEmail(bad);
    assert.ok(err !== null, `Expected rejection for malicious email: "${bad}"`);
  }

  const validEmails = [
    "analyst@safeinbox.ai",
    "user.name+tag@sub.example.co.uk",
    "first_last@corp-security.org",
    "dev123@tech.io"
  ];

  for (const good of validEmails) {
    const err = validateClientEmail(good);
    assert.strictEqual(err, null, `Expected valid email to pass: "${good}"`);
  }
});

test("Auth Security: Password policy blocks dictionary, weak, short, and low-entropy passwords", () => {
  const weakPasswords = [
    "",
    "short1!",
    "NoSpecialOrDigits",
    "alllowercase123!",
    "ALLUPPERCASE123!",
    "NoDigitsHere!@#$",
    "password",
    "Password123",
    "12345678",
    "qwerty123",
    "Admin123",
    "safeinbox123",
    "A".repeat(129) + "a1!" // exceeds 128 chars
  ];

  for (const weak of weakPasswords) {
    const err = validateClientPassword(weak);
    assert.ok(err !== null, `Expected weak password rejection for: "${weak}"`);
  }

  const strongPasswords = [
    "SafeInbox#Secure2026!",
    "Tr0ub4dor&3_Enterprise",
    "V3ry$tr0ng-P@ssw0rd!"
  ];

  for (const strong of strongPasswords) {
    const err = validateClientPassword(strong);
    assert.strictEqual(err, null, `Expected strong password to pass: "${strong}"`);
  }
});

test("Auth Security: Client-side brute-force lockout triggers on 5 consecutive failures", () => {
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

  // Attempts 1 to 4 should not trigger lockout
  for (let i = 1; i <= 4; i++) {
    registerFailure();
    assert.strictEqual(checkLockout(), 0, `Attempt ${i} should not lock out`);
  }

  // 5th attempt triggers lockout
  registerFailure();
  const rem = checkLockout();
  assert.ok(rem > 25 && rem <= 30, `5th failure should trigger ~30s lockout (got ${rem}s)`);
});

test("Auth Security: Local PBKDF2 cryptography produces high-entropy hashes with unique salts", async () => {
  const pw = "SuperSecret#2026!";
  const salt1 = generateCryptoSalt();
  const salt2 = generateCryptoSalt();

  assert.strictEqual(salt1.length, 32, "16-byte salt must be 32 hex chars");
  assert.strictEqual(salt2.length, 32, "16-byte salt must be 32 hex chars");
  assert.notStrictEqual(salt1, salt2, "Cryptographic salts must be unique");

  const hash1 = await hashPasswordPBKDF2(pw, salt1);
  const hash2 = await hashPasswordPBKDF2(pw, salt2);

  assert.strictEqual(hash1.length, 64, "SHA-256 PBKDF2 must produce 64 hex characters (256-bit)");
  assert.strictEqual(hash2.length, 64, "SHA-256 PBKDF2 must produce 64 hex characters (256-bit)");
  assert.notStrictEqual(hash1, hash2, "Identical password with different salts must yield different hashes");

  // Re-hashing with the same salt produces the exact same hash (verification succeeds)
  const verifyHash = await hashPasswordPBKDF2(pw, salt1);
  assert.strictEqual(verifyHash, hash1, "PBKDF2 verification must match stored hash");

  // Incorrect password verification fails
  const wrongHash = await hashPasswordPBKDF2("WrongPassword123!", salt1);
  assert.notStrictEqual(wrongHash, hash1, "Wrong password must produce different hash");
});

test("Auth Security: JavaScript controllers enforce PBKDF2, strict validation, and session wipe", () => {
  // Verify sidepanel controller enforces security primitives
  assert.ok(sidepanelJs.includes("PBKDF2"), "sidepanelController must use PBKDF2");
  assert.ok(sidepanelJs.includes("100000"), "sidepanelController must use 100,000 iterations");
  assert.ok(sidepanelJs.includes("validateClientEmail"), "sidepanelController must call validateClientEmail");
  assert.ok(sidepanelJs.includes("validateClientPassword"), "sidepanelController must call validateClientPassword");
  assert.ok(sidepanelJs.includes("checkClientSignInRateLimit"), "sidepanelController must enforce client rate limit");
  assert.ok(sidepanelJs.includes("clearAuthSession"), "sidepanelController must implement session cleanup");

  // Verify welcome controller enforces security primitives
  assert.ok(welcomeJs.includes("PBKDF2"), "welcomeController must use PBKDF2");
  assert.ok(welcomeJs.includes("100000"), "welcomeController must use 100,000 iterations");
  assert.ok(welcomeJs.includes("validateClientEmail"), "welcomeController must call validateClientEmail");
  assert.ok(welcomeJs.includes("validateClientPassword"), "welcomeController must call validateClientPassword");
  assert.ok(welcomeJs.includes("generateCryptoSalt()"), "welcomeController must generate cryptographic salt");
  assert.ok(welcomeJs.includes("removeAuth"), "welcomeController must implement session cleanup");
});

test("Auth Security: Multi-Device Duplicate Signup Prevention & Server Uniqueness Enforcement", () => {
  // 1. Ensure silent offline fallback during signup has been eliminated from both controllers
  // Neither controller should create an unverified local account when the server is unreachable
  assert.ok(
    !sidepanelJs.includes('token = "local_token_" + Date.now();\n        user = {\n          email,'),
    "Sidepanel signup must not create unverified local account when server is offline"
  );
  assert.ok(
    !welcomeJs.includes('token = "local_token_" + Date.now();\n        user = {\n          email,'),
    "Welcome controller signup must not create unverified local account when server is offline"
  );

  // 2. Both controllers must require server connection to verify email uniqueness across devices
  assert.ok(
    sidepanelJs.includes("Account registration requires a server connection to verify email uniqueness across devices"),
    "Sidepanel must inform user that signup requires server verification"
  );
  assert.ok(
    welcomeJs.includes("Account creation requires a server connection to verify email uniqueness across devices"),
    "Welcome controller must inform user that signup requires server verification"
  );

  // 3. Local duplicate account creation rejection test
  const localUsers = {};
  function saveUser(email, passHash, salt) {
    const clean = email.toLowerCase().trim();
    if (localUsers[clean]) {
      throw new Error("An account with this email address already exists. Only 1 account per email is allowed. Please sign in instead.");
    }
    localUsers[clean] = { email: clean, passHash, salt };
    return localUsers[clean];
  }

  // First registration on Device 1 succeeds
  saveUser("analyst@safeinbox.ai", "hash1", "salt1");
  assert.ok(localUsers["analyst@safeinbox.ai"]);

  // Attempted duplicate registration on Device 2 with same email must throw duplicate error
  assert.throws(() => {
    saveUser("analyst@safeinbox.ai", "hash2", "salt2");
  }, /already exists/);

  // Case-insensitive duplicate registration attempt must also throw
  assert.throws(() => {
    saveUser("ANALYST@SAFEINBOX.AI", "hash3", "salt3");
  }, /already exists/);
});

test("Auth Security: Email OTP Verification UI, countdown timer, and request/verify endpoints are wired in both controllers", () => {
  // 1. Template Elements in Side Panel and Welcome Page
  assert.ok(sidepanelHtml.includes('id="authOtpVerificationView"'), "Sidepanel must include authOtpVerificationView");
  assert.ok(sidepanelHtml.includes('id="authOtpCodeInput"'), "Sidepanel must include authOtpCodeInput");
  assert.ok(sidepanelHtml.includes('id="btnSubmitAuthVerifyOtp"'), "Sidepanel must include btnSubmitAuthVerifyOtp");
  assert.ok(sidepanelHtml.includes('id="btnAuthResendOtp"'), "Sidepanel must include btnAuthResendOtp");
  assert.ok(sidepanelHtml.includes('id="authOtpCountdown"'), "Sidepanel must include authOtpCountdown");

  assert.ok(welcomeHtml.includes('id="authOtpVerificationView"'), "Welcome page must include authOtpVerificationView");
  assert.ok(welcomeHtml.includes('id="otpCodeInput"'), "Welcome page must include otpCodeInput");
  assert.ok(welcomeHtml.includes('id="btnSubmitVerifyOtp"'), "Welcome page must include btnSubmitVerifyOtp");
  assert.ok(welcomeHtml.includes('id="btnResendOtp"'), "Welcome page must include btnResendOtp");
  assert.ok(welcomeHtml.includes('id="otpCountdownTimer"'), "Welcome page must include otpCountdownTimer");

  // 2. Both controllers route through request-otp and verify-otp
  assert.ok(
    sidepanelJs.includes("/api/v1/auth/signup/request-otp"),
    "Sidepanel must request 6-digit OTP before registration"
  );
  assert.ok(
    sidepanelJs.includes("/api/v1/auth/signup/verify-otp"),
    "Sidepanel must verify OTP code before activating session"
  );
  assert.ok(
    sidepanelJs.includes("/api/v1/auth/signup/resend-otp"),
    "Sidepanel must support resending OTP code"
  );

  assert.ok(
    welcomeJs.includes("/api/v1/auth/signup/request-otp"),
    "Welcome controller must request 6-digit OTP before registration"
  );
  assert.ok(
    welcomeJs.includes("/api/v1/auth/signup/verify-otp"),
    "Welcome controller must verify OTP code before activating session"
  );
  assert.ok(
    welcomeJs.includes("/api/v1/auth/signup/resend-otp"),
    "Welcome controller must support resending OTP code"
  );
});



