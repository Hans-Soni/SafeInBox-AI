"use strict";

(() => {
  // DOM element references
  const el = {
    btnNavSignIn: document.getElementById("btnNavSignIn"),
    btnNavSignUp: document.getElementById("btnNavSignUp"),
    btnHeroSignIn: document.getElementById("btnHeroSignIn"),
    btnHeroSignUp: document.getElementById("btnHeroSignUp"),
    userNavPill: document.getElementById("userNavPill"),
    userNavName: document.getElementById("userNavName"),

    // Auth modal
    authModal: document.getElementById("authModal"),
    authModalClose: document.getElementById("authModalClose"),
    authSignedOutView: document.getElementById("authSignedOutView"),
    authSignedInView: document.getElementById("authSignedInView"),
    authTermsReviewView: document.getElementById("authTermsReviewView"),
    authTabSignIn: document.getElementById("authTabSignIn"),
    authTabSignUp: document.getElementById("authTabSignUp"),

    // Sign in form
    formSignIn: document.getElementById("formSignIn"),
    inputSignInEmail: document.getElementById("inputSignInEmail"),
    inputSignInPassword: document.getElementById("inputSignInPassword"),
    statusSignIn: document.getElementById("statusSignIn"),
    btnSubmitSignIn: document.getElementById("btnSubmitSignIn"),
    linkToSignUp: document.getElementById("linkToSignUp"),

    // Sign up form
    formSignUp: document.getElementById("formSignUp"),
    inputSignUpName: document.getElementById("inputSignUpName"),
    inputSignUpEmail: document.getElementById("inputSignUpEmail"),
    inputSignUpPassword: document.getElementById("inputSignUpPassword"),
    inputSignUpConfirm: document.getElementById("inputSignUpConfirm"),
    statusSignUp: document.getElementById("statusSignUp"),
    btnSubmitSignUp: document.getElementById("btnSubmitSignUp"),
    linkToSignIn: document.getElementById("linkToSignIn"),

    // Terms review buttons in modal
    statusTermsReview: document.getElementById("statusTermsReview"),
    btnConfirmTermsSignUp: document.getElementById("btnConfirmTermsSignUp"),
    btnDeclineTermsSignUp: document.getElementById("btnDeclineTermsSignUp"),

    // Email OTP verification view
    authOtpVerificationView: document.getElementById("authOtpVerificationView"),
    otpHeaderBadge: document.getElementById("otpHeaderBadge"),
    otpTitle: document.getElementById("otpTitle"),
    otpSubtitle: document.getElementById("otpSubtitle"),
    otpTargetEmailDisplay: document.getElementById("otpTargetEmailDisplay"),
    otpCodeInput: document.getElementById("otpCodeInput"),
    otpCountdownTimer: document.getElementById("otpCountdownTimer"),
    statusOtpVerification: document.getElementById("statusOtpVerification"),
    btnSubmitVerifyOtp: document.getElementById("btnSubmitVerifyOtp"),
    btnResendOtp: document.getElementById("btnResendOtp"),
    otpResendCooldown: document.getElementById("otpResendCooldown"),
    btnBackFromOtp: document.getElementById("btnBackFromOtp"),

    // Profile in modal

    profileName: document.getElementById("profileName"),
    profileEmail: document.getElementById("profileEmail"),
    profileIndexVal: document.getElementById("profileIndexVal"),
    btnSignOut: document.getElementById("btnSignOut"),

    // Simulator
    simInput: document.getElementById("simInput"),
    btnSimScan: document.getElementById("btnSimScan"),
    simResultCard: document.getElementById("simResultCard"),
    simResultUrl: document.getElementById("simResultUrl"),
    simResultBadge: document.getElementById("simResultBadge"),
    simFindingsList: document.getElementById("simFindingsList")
  };

  let pendingSignUp = null;
  let pendingOtp = null;

  const AUTH_EMAIL_REGEX = /^(?!\.)[a-zA-Z0-9_.+-]+(?<!\.)@(?!-)[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)*\.[a-zA-Z]{2,24}$/;
  let signInFailures = 0;
  let signInLockoutUntil = 0;

  function validateClientEmail(email) {
    const clean = String(email || "").trim().toLowerCase();
    if (!clean || clean.length > 255 || clean.includes("..") || !AUTH_EMAIL_REGEX.test(clean)) {
      return "Please enter a valid email address (e.g. analyst@safeinbox.ai).";
    }
    // Neutralize SQL injection characters and null bytes
    if (["'", '"', ';', '--', '/*', '*/', '\x00'].some(c => clean.includes(c))) {
      return "Email contains disallowed characters.";
    }
    return null;
  }

  const COMMON_CLIENT_PASSWORDS = [
    "password", "password123", "password1234", "password12345",
    "12345678", "123456789", "1234567890", "qwerty123",
    "admin123", "letmein1", "welcome1", "safeinbox", "safeinbox123"
  ];

  const SEQUENTIAL_RUNS = ["12345", "23456", "34567", "qwerty", "asdfgh", "zxcvbn", "abcdef"];

  function validateClientPassword(password, email, fullName) {
    if (typeof password !== "string" || password.length < 10) {
      return "Password must be at least 10 characters long.";
    }
    if (password.length > 128) {
      return "Password must not exceed 128 characters.";
    }
    const lowered = password.toLowerCase();
    if (COMMON_CLIENT_PASSWORDS.includes(lowered)) {
      return "Password is too common. Please choose a stronger, unique password.";
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
    if (/(.)\1{3,}/.test(password)) {
      return "Password cannot contain 4 or more consecutive identical characters.";
    }
    for (const seq of SEQUENTIAL_RUNS) {
      if (lowered.includes(seq)) {
        return `Password contains a predictable sequential pattern ('${seq}').`;
      }
    }
    if (email) {
      const local = email.split("@")[0].toLowerCase();
      const tokens = local.split(/[._\-+]/).filter(t => t.length >= 3);
      for (const t of tokens) {
        if (lowered.includes(t)) {
          return `Password cannot contain parts of your email address ('${t}').`;
        }
      }
    }
    if (fullName) {
      const tokens = fullName.toLowerCase().split(/\s+/).filter(t => t.length >= 3);
      for (const t of tokens) {
        if (lowered.includes(t)) {
          return `Password cannot contain parts of your name ('${t}').`;
        }
      }
    }
    return null;
  }

  function checkClientSignInRateLimit() {
    const now = Date.now();
    if (now < signInLockoutUntil) {
      const rem = Math.ceil((signInLockoutUntil - now) / 1000);
      return `Too many failed attempts. Please wait ${rem}s before retrying.`;
    }
    return null;
  }

  function registerSignInFailure() {
    signInFailures++;
    if (signInFailures >= 5) {
      signInLockoutUntil = Date.now() + 30000;
      signInFailures = 0;
    }
  }

  function resetSignInFailures() {
    signInFailures = 0;
    signInLockoutUntil = 0;
  }

  function getBackendUrl() {
    return "https://safeinbox-ai.onrender.com";
  }

  function openModal(tab = "signin") {
    if (!el.authModal) return;
    el.authModal.style.display = "flex";
    if (el.authTermsReviewView) el.authTermsReviewView.style.display = "none";
    if (el.authSignedOutView) el.authSignedOutView.style.display = "block";
    switchTab(tab);
  }

  function closeModal() {
    if (!el.authModal) return;
    el.authModal.style.display = "none";
    if (el.authTermsReviewView) el.authTermsReviewView.style.display = "none";
    if (el.authSignedOutView) el.authSignedOutView.style.display = "block";
    clearStatus(el.statusSignIn);
    clearStatus(el.statusSignUp);
    clearStatus(el.statusTermsReview);
    pendingSignUp = null;
    pendingOtp = null;
  }

  function switchTab(tab) {
    if (el.authTermsReviewView) el.authTermsReviewView.style.display = "none";
    if (el.authSignedOutView) el.authSignedOutView.style.display = "block";
    clearStatus(el.statusTermsReview);
    pendingSignUp = null;
    pendingOtp = null;

    if (tab === "signup") {
      el.authTabSignUp?.classList.add("active");
      el.authTabSignIn?.classList.remove("active");
      if (el.formSignUp) el.formSignUp.style.display = "flex";
      if (el.formSignIn) el.formSignIn.style.display = "none";
    } else {
      el.authTabSignIn?.classList.add("active");
      el.authTabSignUp?.classList.remove("active");
      if (el.formSignIn) el.formSignIn.style.display = "flex";
      if (el.formSignUp) el.formSignUp.style.display = "none";
    }
  }


  function setStatus(targetEl, msg, type) {
    if (!targetEl) return;
    targetEl.textContent = msg;
    targetEl.className = `auth-status ${type}`;
    targetEl.style.display = "block";
  }

  function clearStatus(targetEl) {
    if (!targetEl) return;
    targetEl.style.display = "none";
    targetEl.textContent = "";
  }

  function getStoredAuth() {
    return new Promise((resolve) => {
      const FIFTEEN_DAYS_MS = 15 * 24 * 60 * 60 * 1000;
      if (typeof chrome !== "undefined" && chrome.storage && chrome.storage.local) {
        chrome.storage.local.get(["safeinbox_auth"], async (res) => {
          const auth = res && res.safeinbox_auth;
          if (auth && auth.saved_at && (Date.now() - auth.saved_at > FIFTEEN_DAYS_MS)) {
            await removeAuth();
            resolve(null);
            return;
          }
          resolve(auth);
        });
      } else {
        try {
          const raw = localStorage.getItem("safeinbox_auth");
          const auth = raw ? JSON.parse(raw) : null;
          if (auth && auth.saved_at && (Date.now() - auth.saved_at > FIFTEEN_DAYS_MS)) {
            localStorage.removeItem("safeinbox_auth");
            resolve(null);
            return;
          }
          resolve(auth);
        } catch {
          resolve(null);
        }
      }
    });
  }

  function saveAuth(token, user, expiresInSeconds = 15 * 24 * 60 * 60) {
    return new Promise((resolve) => {
      const authData = {
        token,
        user,
        saved_at: Date.now(),
        expires_at: Date.now() + expiresInSeconds * 1000 // 15-day session lifetime
      };
      const sessionData = { email: user.email, name: user.full_name || user.email.split("@")[0] };
      if (typeof chrome !== "undefined" && chrome.storage && chrome.storage.local) {
        chrome.storage.local.set({
          safeinbox_auth: authData,
          safeinbox_user_session: sessionData,
          cloudBackendEnabled: true
        }, resolve);
      } else {
        try {
          localStorage.setItem("safeinbox_auth", JSON.stringify(authData));
          localStorage.setItem("safeinbox_user_session", JSON.stringify(sessionData));
        } catch {}
        resolve();
      }
    });
  }

  async function removeAuth() {
    // 1. Invalidate Bearer token on backend
    try {
      const stored = await getStoredAuth();
      const token = stored && stored.token;
      if (token && !token.startsWith("local_token_")) {
        const baseUrl = getBackendUrl();
        await fetch(`${baseUrl}/api/v1/auth/signout`, {
          method: "POST",
          headers: {
            "Authorization": `Bearer ${token}`,
            "Content-Type": "application/json"
          }
        }).catch(() => {});
      }
    } catch {}

    // 2. Remove all auth and user session keys from storage
    return new Promise((resolve) => {
      if (typeof chrome !== "undefined" && chrome.storage && chrome.storage.local) {
        chrome.storage.local.remove(["safeinbox_auth", "safeinbox_user_session"], () => {
          if (chrome.storage.session) {
            chrome.storage.session.remove(["activeEmailScan"]).catch(() => {});
          }
          resolve();
        });
      } else {
        try {
          localStorage.removeItem("safeinbox_auth");
          localStorage.removeItem("safeinbox_user_session");
        } catch {}
        resolve();
      }
    });
  }

  function detectHardwareMac() {
    return "N/A (Browser Sandbox Restricted: W3C Anti-Fingerprinting Policy)";
  }

  async function hashPasswordLocal(password, salt) {
    if (typeof crypto !== "undefined" && crypto.subtle) {
      const enc = new TextEncoder();
      const keyMaterial = await crypto.subtle.importKey(
        "raw",
        enc.encode(password),
        { name: "PBKDF2" },
        false,
        ["deriveBits"]
      );
      const saltBuffer = enc.encode(salt);
      const derivedBits = await crypto.subtle.deriveBits(
        {
          name: "PBKDF2",
          salt: saltBuffer,
          iterations: 100000,
          hash: "SHA-256"
        },
        keyMaterial,
        256
      );
      return Array.from(new Uint8Array(derivedBits))
        .map(b => b.toString(16).padStart(2, "0"))
        .join("");
    }
    throw new Error("WebCrypto is required for secure authentication.");
  }

  function generateCryptoSalt() {
    if (typeof crypto !== "undefined" && crypto.getRandomValues) {
      const arr = new Uint8Array(16);
      crypto.getRandomValues(arr);
      return Array.from(arr).map(b => b.toString(16).padStart(2, "0")).join("");
    }
    return Date.now().toString(36) + Math.random().toString(36).slice(2, 10);
  }

  function getRegisteredUsers() {
    return new Promise((resolve) => {
      if (typeof chrome !== "undefined" && chrome.storage && chrome.storage.local) {
        chrome.storage.local.get(["safeinbox_registered_users"], (res) => {
          resolve((res && res.safeinbox_registered_users) || {});
        });
      } else {
        try {
          const raw = localStorage.getItem("safeinbox_registered_users");
          resolve(raw ? JSON.parse(raw) : {});
        } catch {
          resolve({});
        }
      }
    });
  }

  function saveRegisteredUser(email, fullName, passwordHash, salt) {
    return new Promise(async (resolve, reject) => {
      const users = await getRegisteredUsers();
      const cleanEmail = email.toLowerCase().trim();
      if (users[cleanEmail]) {
        reject(new Error("An account with this email address already exists. Only 1 account per email is allowed. Please sign in instead."));
        return;
      }
      users[cleanEmail] = {
        email: cleanEmail,
        full_name: fullName || cleanEmail.split("@")[0],
        salt,
        password_hash: passwordHash,
        created_at: new Date().toISOString()
      };
      if (typeof chrome !== "undefined" && chrome.storage && chrome.storage.local) {
        chrome.storage.local.set({ safeinbox_registered_users: users }, resolve);
      } else {
        try {
          localStorage.setItem("safeinbox_registered_users", JSON.stringify(users));
        } catch {}
        resolve();
      }
    });
  }

  function clearFormInputs() {
    el.formSignIn?.reset();
    el.formSignUp?.reset();
    if (el.inputSignInEmail) el.inputSignInEmail.value = "";
    if (el.inputSignInPassword) el.inputSignInPassword.value = "";
    if (el.inputSignUpName) el.inputSignUpName.value = "";
    if (el.inputSignUpEmail) el.inputSignUpEmail.value = "";
    if (el.inputSignUpPassword) el.inputSignUpPassword.value = "";
    if (el.inputSignUpConfirm) el.inputSignUpConfirm.value = "";
  }

  function saveTermsConsent(consentData) {

    return new Promise((resolve) => {
      if (typeof chrome !== "undefined" && chrome.storage && chrome.storage.local) {
        chrome.storage.local.set({ safeinbox_terms_consent: consentData }, resolve);
      } else {
        try {
          localStorage.setItem("safeinbox_terms_consent", JSON.stringify(consentData));
        } catch {}
        resolve();
      }
    });
  }

  async function updateAuthUI() {
    const auth = await getStoredAuth();
    const isSignedIn = Boolean(auth && auth.token && auth.user);

    if (isSignedIn && auth.user) {
      if (el.userNavPill) {
        el.userNavPill.style.display = "inline-flex";
        if (el.userNavName) el.userNavName.textContent = auth.user.full_name || auth.user.email.split("@")[0];
      }
      if (el.btnNavSignIn) el.btnNavSignIn.style.display = "none";
      if (el.btnNavSignUp) el.btnNavSignUp.style.display = "none";

      if (el.authSignedOutView) el.authSignedOutView.style.display = "none";
      if (el.authSignedInView) el.authSignedInView.style.display = "block";
      if (el.profileName) el.profileName.textContent = auth.user.full_name || "Analyst";
      if (el.profileEmail) el.profileEmail.textContent = auth.user.email;
      if (el.profileIndexVal) {
        let fallbackIdx = "SAFE-IDX-ANONYMOUS";
        if (auth.user.email) {
          let h = 0;
          const s = auth.user.email.trim().toLowerCase();
          for (let i = 0; i < s.length; i++) { h = ((h << 5) - h) + s.charCodeAt(i); h |= 0; }
          const hex = Math.abs(h).toString(16).padStart(8, "0").toUpperCase();
          fallbackIdx = `SAFE-IDX-${hex}${hex.slice(0, 4)}`;
        }
        el.profileIndexVal.textContent = auth.user.index_id || fallbackIdx;
      }
    } else {
      if (el.userNavPill) el.userNavPill.style.display = "none";
      if (el.btnNavSignIn) el.btnNavSignIn.style.display = "inline-block";
      if (el.btnNavSignUp) el.btnNavSignUp.style.display = "inline-block";

      if (el.authSignedOutView) el.authSignedOutView.style.display = "block";
      if (el.authSignedInView) el.authSignedInView.style.display = "none";
    }
  }

  function initEventListeners() {
    // Nav & Hero buttons open modal
    el.btnNavSignIn?.addEventListener("click", () => openModal("signin"));
    el.btnNavSignUp?.addEventListener("click", () => openModal("signup"));
    el.btnHeroSignIn?.addEventListener("click", () => openModal("signin"));
    el.btnHeroSignUp?.addEventListener("click", () => openModal("signup"));
    el.userNavPill?.addEventListener("click", () => openModal("signin"));

    // Modal close
    el.authModalClose?.addEventListener("click", closeModal);
    el.authModal?.addEventListener("click", (e) => {
      if (e.target === el.authModal) closeModal();
    });

    // Tab switching
    el.authTabSignIn?.addEventListener("click", () => switchTab("signin"));
    el.authTabSignUp?.addEventListener("click", () => switchTab("signup"));
    el.linkToSignUp?.addEventListener("click", (e) => { e.preventDefault(); switchTab("signup"); });
    el.linkToSignIn?.addEventListener("click", (e) => { e.preventDefault(); switchTab("signin"); });

    // Sign In Submit (Terms verified once at SignUp; returning users sign in directly)
    el.formSignIn?.addEventListener("submit", async (e) => {
      e.preventDefault();

      // Enforce client-side rate limit lockout against brute-force attacks
      const lockoutMsg = checkClientSignInRateLimit();
      if (lockoutMsg) {
        setStatus(el.statusSignIn, `⏳ ${lockoutMsg}`, "error");
        return;
      }

      const email = el.inputSignInEmail.value.trim().toLowerCase();
      const password = el.inputSignInPassword.value;

      const emailErr = validateClientEmail(email);
      if (emailErr) {
        setStatus(el.statusSignIn, emailErr, "error");
        return;
      }
      if (!password) {
        setStatus(el.statusSignIn, "Please enter your password.", "error");
        return;
      }

      setStatus(el.statusSignIn, "Authenticating...", "info");
      el.btnSubmitSignIn.disabled = true;

      const macAddress = detectHardwareMac();
      let token = null;
      let user = null;
      let clientIp = "127.0.0.1 (Local Verified)";
      let agreedAt = new Date().toISOString();
      let authenticated = false;

      // 1. Try Backend API first with 2FA OTP verification
      try {
        const baseUrl = getBackendUrl();
        let resp;
        try {
          resp = await fetch(`${baseUrl}/api/v1/auth/signin/request-otp`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ email, password })
          });
        } catch (_) {
          resp = await fetch(`${baseUrl}/api/v1/auth/signin`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
              email,
              password,
              terms_agreed: true,
              terms_version: "1.0.0",
              mac_address: macAddress
            })
          });
        }

        const data = await resp.json().catch(() => ({}));
        if (!resp.ok) {
          registerSignInFailure();
          setStatus(el.statusSignIn, data.detail || "Invalid email or password.", "error");
          el.btnSubmitSignIn.disabled = false;
          return;
        }

        if (data.requires_otp) {
          pendingOtp = { flow: "signin", email, password, macAddress };
          pendingSignUp = null;

          if (el.authSignedOutView) el.authSignedOutView.style.display = "none";
          if (el.authOtpVerificationView) el.authOtpVerificationView.style.display = "block";
          if (el.otpHeaderBadge) el.otpHeaderBadge.textContent = "🔐 Two-Factor Authorization";
          if (el.otpTitle) el.otpTitle.textContent = "Authorize Sign In";
          if (el.otpSubtitle) {
            el.otpSubtitle.innerHTML = `Enter the 6-digit verification code sent to <strong id="otpTargetEmailDisplay" style="color:#FFA586;">${escapeHtml(email)}</strong> to securely complete Sign In.`;
          }
          if (el.btnSubmitVerifyOtp) el.btnSubmitVerifyOtp.textContent = "✓ Verify & Sign In";
          if (el.btnBackFromOtp) el.btnBackFromOtp.textContent = "← Back to Sign In";
          if (el.otpTargetEmailDisplay) el.otpTargetEmailDisplay.textContent = email;
          if (el.otpCodeInput) {
            el.otpCodeInput.value = "";
            setTimeout(() => el.otpCodeInput.focus(), 100);
          }
          clearStatus(el.statusOtpVerification);
          startOtpTimers(data.expires_in_seconds || 600, data.resend_cooldown_seconds || 60);
          el.btnSubmitSignIn.disabled = false;
          return;
        }

        token = data.access_token;
        user = data.user;
        if (data.terms_consent) {
          clientIp = data.terms_consent.ip_address || clientIp;
          agreedAt = data.terms_consent.agreed_at || agreedAt;
        }
        authenticated = true;
      } catch (networkErr) {
        console.warn("Backend server not responding, attempting local credential verification:", networkErr);
      }

      // 2. If backend is offline, strictly verify against registered local accounts
      if (!authenticated) {
        const registeredUsers = await getRegisteredUsers();
        const existing = registeredUsers[email];
        if (!existing) {
          registerSignInFailure();
          setStatus(el.statusSignIn, "Account not found on this device and unable to reach server. If you registered on another device, please ensure the server is running to sign in on this device.", "error");
          el.btnSubmitSignIn.disabled = false;
          return;
        }

        const computedHash = await hashPasswordLocal(password, existing.salt);
        if (computedHash !== existing.password_hash) {
          registerSignInFailure();
          setStatus(el.statusSignIn, "Invalid email or password.", "error");
          el.btnSubmitSignIn.disabled = false;
          return;
        }

        token = "local_token_" + Date.now();
        user = {
          email: existing.email,
          full_name: existing.full_name,
          is_active: true,
          created_at: existing.created_at
        };
        authenticated = true;
      }

      if (!authenticated) {
        registerSignInFailure();
        setStatus(el.statusSignIn, "Authentication failed. Invalid email or password.", "error");
        el.btnSubmitSignIn.disabled = false;
        return;
      }

      // Reset failure counter on successful sign-in
      resetSignInFailures();

      // Save Auth Session
      await saveAuth(token, user);

      // Cache verified user credentials locally if authenticated from backend
      try {
        const localUsers = await getRegisteredUsers();
        if (!localUsers[email]) {
          const salt = Date.now().toString(36) + Math.random().toString(36);
          const passwordHash = await hashPasswordLocal(password, salt);
          localUsers[email] = {
            email,
            full_name: user.full_name || email.split("@")[0],
            salt,
            password_hash: passwordHash,
            created_at: user.created_at || agreedAt
          };
          if (typeof chrome !== "undefined" && chrome.storage && chrome.storage.local) {
            await new Promise(r => chrome.storage.local.set({ safeinbox_registered_users: localUsers }, r));
          } else if (typeof localStorage !== "undefined") {
            localStorage.setItem("safeinbox_registered_users", JSON.stringify(localUsers));
          }
        }
      } catch {}

      // Save Terms Consent Audit Record
      await saveTermsConsent({
        email,
        ip_address: clientIp,
        mac_address: macAddress,
        terms_version: "1.0.0",
        agreed_at: agreedAt
      });

      // Clear all login input fields immediately so no data remains in the login/log section
      clearFormInputs();

      setStatus(el.statusSignIn, "✓ Signed in successfully!", "success");
      await updateAuthUI();
      setTimeout(() => {
        closeModal();
        el.btnSubmitSignIn.disabled = false;
      }, 600);
    });

    // Sign Up Submit: Validates and shows Terms & Conditions Review Step
    el.formSignUp?.addEventListener("submit", (e) => {
      e.preventDefault();

      const fullName = el.inputSignUpName.value.trim();
      const email = el.inputSignUpEmail.value.trim().toLowerCase();
      const password = el.inputSignUpPassword.value;
      const confirm = el.inputSignUpConfirm.value;

      const emailErr = validateClientEmail(email);
      if (emailErr) {
        setStatus(el.statusSignUp, emailErr, "error");
        return;
      }

      const pwErr = validateClientPassword(password);
      if (pwErr) {
        setStatus(el.statusSignUp, pwErr, "error");
        return;
      }

      if (password !== confirm) {
        setStatus(el.statusSignUp, "Passwords do not match.", "error");
        return;
      }

      // Check if user already exists locally on this device
      getRegisteredUsers().then((registeredUsers) => {
        if (registeredUsers[email]) {
          setStatus(el.statusSignUp, "An account with this email address already exists. Only 1 account per email is allowed. Please sign in instead.", "error");
          return;
        }

        // Store pending registration details
        pendingSignUp = { fullName, email, password };

        // Transition to Terms & Conditions Review step
        if (el.authSignedOutView) el.authSignedOutView.style.display = "none";
        if (el.authTermsReviewView) el.authTermsReviewView.style.display = "block";
        clearStatus(el.statusTermsReview);
      });
    });

    // Decline Terms & Conditions during Sign Up: Refresh immediately
    el.btnDeclineTermsSignUp?.addEventListener("click", () => {
      alert("You declined the Terms & Conditions. Account creation cancelled. The page will now refresh.");
      window.location.reload();
    });

    let otpCountdownInterval = null;
    let otpResendCooldownInterval = null;

    function stopOtpTimers() {
      if (otpCountdownInterval) clearInterval(otpCountdownInterval);
      if (otpResendCooldownInterval) clearInterval(otpResendCooldownInterval);
      otpCountdownInterval = null;
      otpResendCooldownInterval = null;
    }

    function startOtpTimers(expiresInSec = 600, resendCooldownSec = 60) {
      stopOtpTimers();

      let expireLeft = expiresInSec;
      function updateExpireDisplay() {
        if (!el.otpCountdownTimer) return;
        const mins = Math.floor(expireLeft / 60);
        const secs = expireLeft % 60;
        el.otpCountdownTimer.textContent = `${String(mins).padStart(2, "0")}:${String(secs).padStart(2, "0")}`;
        if (expireLeft <= 0) {
          clearInterval(otpCountdownInterval);
          setStatus(el.statusOtpVerification, "Verification code has expired. Please request a new code.", "error");
        }
        expireLeft--;
      }
      updateExpireDisplay();
      otpCountdownInterval = setInterval(updateExpireDisplay, 1000);

      let cooldownLeft = resendCooldownSec;
      function updateCooldownDisplay() {
        if (!el.btnResendOtp || !el.otpResendCooldown) return;
        if (cooldownLeft <= 0) {
          clearInterval(otpResendCooldownInterval);
          el.btnResendOtp.disabled = false;
          el.btnResendOtp.style.opacity = "1";
          el.otpResendCooldown.textContent = "Ready";
        } else {
          el.btnResendOtp.disabled = true;
          el.btnResendOtp.style.opacity = "0.5";
          el.otpResendCooldown.textContent = `${cooldownLeft}s`;
          cooldownLeft--;
        }
      }
      updateCooldownDisplay();
      otpResendCooldownInterval = setInterval(updateCooldownDisplay, 1000);
    }

    // Confirm Terms & Conditions: Request 6-Digit Email OTP
    el.btnConfirmTermsSignUp?.addEventListener("click", async () => {
      if (!pendingSignUp) return;

      setStatus(el.statusTermsReview, "Sending 6-digit verification code to your email...", "info");
      el.btnConfirmTermsSignUp.disabled = true;

      const email = pendingSignUp.email.toLowerCase();
      const password = pendingSignUp.password;
      const fullName = pendingSignUp.fullName;
      const macAddress = detectHardwareMac();

      try {
        const baseUrl = getBackendUrl();
        const resp = await fetch(`${baseUrl}/api/v1/auth/signup/request-otp`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            email,
            password,
            full_name: fullName || null,
            terms_agreed: true,
            terms_version: "1.0.0",
            mac_address: macAddress
          })
        });

        const data = await resp.json().catch(() => ({}));
        if (!resp.ok) {
          setStatus(el.statusTermsReview, data.detail || `Could not request verification code (HTTP ${resp.status})`, "error");
          el.btnConfirmTermsSignUp.disabled = false;
          return;
        }

        // Transition to OTP verification screen
        pendingOtp = { flow: "signup", email, password, fullName };
        pendingSignUp = pendingOtp;

        if (el.authTermsReviewView) el.authTermsReviewView.style.display = "none";
        if (el.authOtpVerificationView) el.authOtpVerificationView.style.display = "block";
        if (el.otpHeaderBadge) el.otpHeaderBadge.textContent = "✉️ Security Verification · Step 2 of 2";
        if (el.otpTitle) el.otpTitle.textContent = "Verify Your Email Address";
        if (el.otpSubtitle) {
          el.otpSubtitle.innerHTML = `A 6-digit verification code has been dispatched to <strong id="otpTargetEmailDisplay" style="color:#FFA586;">${escapeHtml(email)}</strong>. Enter the code below to complete your registration.`;
        }
        if (el.btnSubmitVerifyOtp) el.btnSubmitVerifyOtp.textContent = "✓ Verify & Complete Registration";
        if (el.btnBackFromOtp) el.btnBackFromOtp.textContent = "← Back to Sign Up";
        if (el.otpTargetEmailDisplay) el.otpTargetEmailDisplay.textContent = email;
        if (el.otpCodeInput) {
          el.otpCodeInput.value = "";
          setTimeout(() => el.otpCodeInput.focus(), 100);
        }
        clearStatus(el.statusOtpVerification);
        startOtpTimers(data.expires_in_seconds || 600, data.resend_cooldown_seconds || 60);
      } catch (err) {
        setStatus(
          el.statusTermsReview,
          "❌ Unable to connect to server. Account creation requires a server connection to verify email uniqueness across devices. If you already registered on another device, please switch to Sign In.",
          "error"
        );
      } finally {
        el.btnConfirmTermsSignUp.disabled = false;
      }
    });

    // Verify OTP and Complete Registration or Sign In
    el.btnSubmitVerifyOtp?.addEventListener("click", async () => {
      const activeState = pendingOtp || pendingSignUp;
      if (!activeState) return;

      const flow = activeState.flow || "signup";
      const email = (activeState.email || "").toLowerCase();
      const otp = el.otpCodeInput ? el.otpCodeInput.value.trim() : "";

      if (!/^\d{6}$/.test(otp)) {
        setStatus(el.statusOtpVerification, "Please enter the complete 6-digit numeric verification code.", "error");
        return;
      }

      // 1. SIGN IN OTP VERIFICATION FLOW
      if (flow === "signin") {
        setStatus(el.statusOtpVerification, "Verifying code & authorizing session...", "info");
        el.btnSubmitVerifyOtp.disabled = true;

        try {
          const baseUrl = getBackendUrl();
          const resp = await fetch(`${baseUrl}/api/v1/auth/signin/verify-otp`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ email, otp })
          });

          const data = await resp.json().catch(() => ({}));
          if (!resp.ok) {
            registerSignInFailure();
            setStatus(el.statusOtpVerification, data.detail || `Sign in verification failed (HTTP ${resp.status})`, "error");
            el.btnSubmitVerifyOtp.disabled = false;
            return;
          }

          const token = data.access_token;
          const user = data.user;
          const clientIp = data.terms_consent?.ip_address || "127.0.0.1 (Verified)";
          const agreedAt = data.terms_consent?.agreed_at || new Date().toISOString();
          const macAddress = activeState.macAddress || detectHardwareMac();

          // Reset failure counter on successful sign-in
          resetSignInFailures();

          // Save Auth Session with 15-day expiration
          await saveAuth(token, user, 1296000);

          // Cache verified user credentials locally if authenticated from backend
          try {
            const localUsers = await getRegisteredUsers();
            if (!localUsers[email] && activeState.password) {
              const salt = Date.now().toString(36) + Math.random().toString(36);
              const passwordHash = await hashPasswordLocal(activeState.password, salt);
              localUsers[email] = {
                email,
                full_name: user.full_name || email.split("@")[0],
                salt,
                password_hash: passwordHash,
                created_at: user.created_at || agreedAt
              };
              if (typeof chrome !== "undefined" && chrome.storage && chrome.storage.local) {
                await new Promise(r => chrome.storage.local.set({ safeinbox_registered_users: localUsers }, r));
              } else if (typeof localStorage !== "undefined") {
                localStorage.setItem("safeinbox_registered_users", JSON.stringify(localUsers));
              }
            }
          } catch {}

          // Save Terms Consent Audit Record
          await saveTermsConsent({
            email,
            ip_address: clientIp,
            mac_address: macAddress,
            terms_version: "1.0.0",
            agreed_at: agreedAt
          });

          // Cleanup
          stopOtpTimers();
          clearFormInputs();
          pendingOtp = null;
          pendingSignUp = null;

          setStatus(el.statusOtpVerification, "✓ Verified! Signed in successfully.", "success");
          await updateAuthUI();
          setTimeout(() => {
            closeModal();
            el.btnSubmitVerifyOtp.disabled = false;
          }, 600);
          return;
        } catch (networkErr) {
          setStatus(el.statusOtpVerification, "❌ Network error connecting to server for sign in verification.", "error");
          el.btnSubmitVerifyOtp.disabled = false;
          return;
        }
      }

      // 2. SIGN UP OTP VERIFICATION FLOW
      const password = activeState.password;
      const fullName = activeState.fullName;
      const macAddress = detectHardwareMac();

      setStatus(el.statusOtpVerification, "Verifying code & activating account...", "info");
      el.btnSubmitVerifyOtp.disabled = true;

      const salt = Date.now().toString(36) + Math.random().toString(36);
      const passwordHash = await hashPasswordLocal(password, salt);

      let token = null;
      let user = null;
      let clientIp = "127.0.0.1 (Local Verified)";
      let agreedAt = new Date().toISOString();

      try {
        const baseUrl = getBackendUrl();
        const resp = await fetch(`${baseUrl}/api/v1/auth/signup/verify-otp`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ email, otp })
        });

        const data = await resp.json().catch(() => ({}));
        if (!resp.ok) {
          setStatus(el.statusOtpVerification, data.detail || `Verification failed (HTTP ${resp.status})`, "error");
          el.btnSubmitVerifyOtp.disabled = false;
          return;
        }

        token = data.access_token;
        user = data.user;
        if (data.terms_consent) {
          clientIp = data.terms_consent.ip_address || clientIp;
          agreedAt = data.terms_consent.agreed_at || agreedAt;
        }
      } catch (err) {
        setStatus(el.statusOtpVerification, "❌ Unable to connect to server to verify OTP. Please check your connection.", "error");
        el.btnSubmitVerifyOtp.disabled = false;
        return;
      }

      // Save to registered users store enforcing 1-email-1-account
      try {
        await saveRegisteredUser(email, fullName, passwordHash, salt);
      } catch (dupErr) {
        setStatus(el.statusOtpVerification, dupErr.message, "error");
        el.btnSubmitVerifyOtp.disabled = false;
        return;
      }

      // Save Auth Session with 15-day expiration
      await saveAuth(token, user, 1296000);

      // Save Terms Consent Audit Record
      const consentData = {
        email,
        ip_address: clientIp,
        mac_address: macAddress,
        terms_version: "1.0.0",
        agreed_at: agreedAt
      };
      await saveTermsConsent(consentData);

      // Cleanup
      stopOtpTimers();
      clearFormInputs();
      pendingOtp = null;
      pendingSignUp = null;

      setStatus(el.statusOtpVerification, "✓ Email verified & account created successfully!", "success");
      await updateAuthUI();
      setTimeout(() => {
        closeModal();
        el.btnSubmitVerifyOtp.disabled = false;
      }, 700);
    });

    // Resend OTP
    el.btnResendOtp?.addEventListener("click", async () => {
      const activeState = pendingOtp || pendingSignUp;
      if (!activeState) return;
      const email = (activeState.email || "").toLowerCase();
      const flow = activeState.flow || "signup";

      setStatus(el.statusOtpVerification, "Requesting fresh verification code...", "info");
      el.btnResendOtp.disabled = true;

      try {
        const baseUrl = getBackendUrl();
        const endpoint = flow === "signin"
          ? `${baseUrl}/api/v1/auth/signin/resend-otp`
          : `${baseUrl}/api/v1/auth/signup/resend-otp`;
        const resp = await fetch(endpoint, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ email })
        });

        const data = await resp.json().catch(() => ({}));
        if (!resp.ok) {
          setStatus(el.statusOtpVerification, data.detail || `Could not resend code (HTTP ${resp.status})`, "error");
          return;
        }

        setStatus(el.statusOtpVerification, "✓ Fresh verification code dispatched to your email.", "success");
        startOtpTimers(data.expires_in_seconds || 600, data.resend_cooldown_seconds || 60);
      } catch (err) {
        setStatus(el.statusOtpVerification, "Could not contact server to resend code.", "error");
      }
    });

    // Back from OTP
    el.btnBackFromOtp?.addEventListener("click", () => {
      stopOtpTimers();
      const flow = pendingOtp ? pendingOtp.flow : "signup";
      pendingOtp = null;
      pendingSignUp = null;
      if (el.authOtpVerificationView) el.authOtpVerificationView.style.display = "none";
      if (el.authSignedOutView) el.authSignedOutView.style.display = "block";
      if (flow === "signin") {
        switchTab("signin");
      } else {
        switchTab("signup");
      }
      clearStatus(el.statusOtpVerification);
    });

    // Sign Out
    el.btnSignOut?.addEventListener("click", async () => {
      await removeAuth();
      clearFormInputs();
      clearStatus(el.statusSignIn);
      clearStatus(el.statusSignUp);
      clearStatus(el.statusTermsReview);
      await updateAuthUI();
      closeModal();
    });

    // Password visibility toggle buttons
    document.querySelectorAll(".auth-pw-toggle").forEach((btn) => {
      btn.addEventListener("click", () => {
        const targetId = btn.getAttribute("data-target");
        const input = targetId ? document.getElementById(targetId) : null;
        if (!input) return;
        if (input.type === "password") {
          input.type = "text";
          btn.textContent = "🙈";
        } else {
          input.type = "password";
          btn.textContent = "👁️";
        }
      });
    });


    // Threat Simulator
    el.btnSimScan?.addEventListener("click", runSimulator);
    el.simInput?.addEventListener("keydown", (e) => {
      if (e.key === "Enter") runSimulator();
    });

    document.querySelectorAll(".sim-chip-btn").forEach(chip => {
      chip.addEventListener("click", () => {
        const sampleUrl = chip.getAttribute("data-sample");
        if (el.simInput && sampleUrl) {
          el.simInput.value = sampleUrl;
          runSimulator();
        }
      });
    });
  }

  function runSimulator() {
    if (!el.simInput || !el.simResultCard) return;
    const url = el.simInput.value.trim();
    if (!url) return;

    try {
      if (typeof UrlThreatParser === "undefined" || !UrlThreatParser.analyzeUrl) {
        return;
      }

      const res = UrlThreatParser.analyzeUrl(url);
      const riskScore = Math.round(res.heuristicRisk * 100);
      const isThreat = riskScore >= 50;
      const defanged = url.replace(/https?:\/\//gi, "hxxps://").replace(/\./g, "[.]");

      el.simResultUrl.textContent = defanged;
      el.simResultBadge.className = `sim-result-badge ${isThreat ? "threat" : "safe"}`;
      el.simResultBadge.textContent = isThreat ? `⚠️ THREAT • ${riskScore}/100` : `✓ SAFE • ${riskScore}/100`;

      if (res.findings && res.findings.length > 0) {
        el.simFindingsList.innerHTML = res.findings.map(f => `
          <div class="sim-finding-item">
            <strong>⚠️ ${escapeHtml(f.title || f.attackType)}:</strong> ${escapeHtml(f.detail || "")}
          </div>
        `).join("");
      } else {
        el.simFindingsList.innerHTML = `<div class="sim-finding-item" style="color:#86efac;">✓ No suspicious threat indicators or confusable patterns detected.</div>`;
      }

      el.simResultCard.style.display = "block";
    } catch (err) {
      el.simResultUrl.textContent = url;
      el.simResultBadge.className = "sim-result-badge threat";
      el.simResultBadge.textContent = "INVALID URL";
      el.simFindingsList.innerHTML = `<div class="sim-finding-item" style="color:#fca5a5;">${escapeHtml(err.message)}</div>`;
      el.simResultCard.style.display = "block";
    }
  }

  function escapeHtml(str) {
    return String(str ?? "").replace(/[&<>"']/g, m => ({
      "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
    }[m]));
  }

  // Initialize
  document.addEventListener("DOMContentLoaded", () => {
    initEventListeners();
    updateAuthUI();
  });
})();

