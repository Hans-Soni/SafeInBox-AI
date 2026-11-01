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

    // Profile in modal

    profileName: document.getElementById("profileName"),
    profileEmail: document.getElementById("profileEmail"),
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

  function getBackendUrl() {
    return "http://localhost:8080";
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
  }

  function switchTab(tab) {
    if (el.authTermsReviewView) el.authTermsReviewView.style.display = "none";
    if (el.authSignedOutView) el.authSignedOutView.style.display = "block";
    clearStatus(el.statusTermsReview);
    pendingSignUp = null;

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
      if (typeof chrome !== "undefined" && chrome.storage && chrome.storage.local) {
        chrome.storage.local.get(["safeinbox_auth"], (res) => {
          resolve(res && res.safeinbox_auth);
        });
      } else {
        try {
          const raw = localStorage.getItem("safeinbox_auth");
          resolve(raw ? JSON.parse(raw) : null);
        } catch {
          resolve(null);
        }
      }
    });
  }

  function saveAuth(token, user) {
    return new Promise((resolve) => {
      const authData = { token, user, saved_at: Date.now() };
      if (typeof chrome !== "undefined" && chrome.storage && chrome.storage.local) {
        chrome.storage.local.set({ safeinbox_auth: authData, cloudBackendEnabled: true }, resolve);
      } else {
        try {
          localStorage.setItem("safeinbox_auth", JSON.stringify(authData));
        } catch {}
        resolve();
      }
    });
  }

  function removeAuth() {
    return new Promise((resolve) => {
      if (typeof chrome !== "undefined" && chrome.storage && chrome.storage.local) {
        chrome.storage.local.remove(["safeinbox_auth"], resolve);
      } else {
        try {
          localStorage.removeItem("safeinbox_auth");
        } catch {}
        resolve();
      }
    });
  }

  function detectHardwareMac() {
    return "N/A (Browser Sandbox Restricted: W3C Anti-Fingerprinting Policy)";
  }

  async function hashPasswordLocal(password, salt) {
    try {
      if (typeof crypto !== "undefined" && crypto.subtle) {
        const enc = new TextEncoder();
        const data = enc.encode(password + "::" + salt);
        const hashBuf = await crypto.subtle.digest("SHA-256", data);
        return Array.from(new Uint8Array(hashBuf)).map(b => b.toString(16).padStart(2, "0")).join("");
      }
    } catch {}
    let hash = 0;
    const str = password + "::" + salt;
    for (let i = 0; i < str.length; i++) {
      hash = ((hash << 5) - hash) + str.charCodeAt(i);
      hash |= 0;
    }
    return "h_" + Math.abs(hash).toString(16);
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
    return new Promise(async (resolve) => {
      const users = await getRegisteredUsers();
      users[email.toLowerCase()] = {
        email: email.toLowerCase(),
        full_name: fullName || email.split("@")[0],
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

      const email = el.inputSignInEmail.value.trim().toLowerCase();
      const password = el.inputSignInPassword.value;
      if (!email || !password) return;

      setStatus(el.statusSignIn, "Authenticating...", "info");
      el.btnSubmitSignIn.disabled = true;

      const macAddress = detectHardwareMac();
      let token = null;
      let user = null;
      let clientIp = "127.0.0.1 (Local Verified)";
      let agreedAt = new Date().toISOString();
      let authenticated = false;

      // 1. Try Backend API first if reachable
      try {
        const baseUrl = getBackendUrl();
        const resp = await fetch(`${baseUrl}/api/v1/auth/signin`, {
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

        const data = await resp.json().catch(() => ({}));
        if (!resp.ok) {
          // Backend responded with invalid credentials! Stop immediately!
          setStatus(el.statusSignIn, data.detail || "Invalid email or password.", "error");
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
          setStatus(el.statusSignIn, "Account not found with this email. Please check your credentials or Sign Up first.", "error");
          el.btnSubmitSignIn.disabled = false;
          return; // STOP! Email is not registered!
        }

        const computedHash = await hashPasswordLocal(password, existing.salt);
        if (computedHash !== existing.password_hash) {
          setStatus(el.statusSignIn, "Invalid email or password.", "error");
          el.btnSubmitSignIn.disabled = false;
          return; // STOP! Wrong password!
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
        setStatus(el.statusSignIn, "Authentication failed. Invalid email or password.", "error");
        el.btnSubmitSignIn.disabled = false;
        return;
      }

      // Save Auth Session
      await saveAuth(token, user);

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

      if (!email || !password) return;
      if (password.length < 8) {
        setStatus(el.statusSignUp, "Password must be at least 8 characters.", "error");
        return;
      }
      if (password !== confirm) {
        setStatus(el.statusSignUp, "Passwords do not match.", "error");
        return;
      }

      // Store pending registration details
      pendingSignUp = { fullName, email, password };

      // Transition to Terms & Conditions Review step
      if (el.authSignedOutView) el.authSignedOutView.style.display = "none";
      if (el.authTermsReviewView) el.authTermsReviewView.style.display = "block";
      clearStatus(el.statusTermsReview);
    });

    // Decline Terms & Conditions during Sign Up: Refresh immediately
    el.btnDeclineTermsSignUp?.addEventListener("click", () => {
      alert("You declined the Terms & Conditions. Account creation cancelled. The page will now refresh.");
      window.location.reload();
    });

    // Confirm Terms & Conditions: Create Account and Log Consent Audit Details
    el.btnConfirmTermsSignUp?.addEventListener("click", async () => {
      if (!pendingSignUp) return;

      setStatus(el.statusTermsReview, "Creating account & recording consent...", "info");
      el.btnConfirmTermsSignUp.disabled = true;

      const email = pendingSignUp.email.toLowerCase();
      const password = pendingSignUp.password;
      const fullName = pendingSignUp.fullName;
      const macAddress = detectHardwareMac();

      let token = null;
      let user = null;
      let clientIp = "127.0.0.1 (Local Verified)";
      let agreedAt = new Date().toISOString();

      // Compute local salt and password hash
      const salt = Date.now().toString(36) + Math.random().toString(36);
      const passwordHash = await hashPasswordLocal(password, salt);

      try {
        const baseUrl = getBackendUrl();
        const resp = await fetch(`${baseUrl}/api/v1/auth/signup`, {
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
          setStatus(el.statusTermsReview, data.detail || `Sign up failed (HTTP ${resp.status})`, "error");
          el.btnConfirmTermsSignUp.disabled = false;
          return;
        }

        token = data.access_token;
        user = data.user;
        if (data.terms_consent) {
          clientIp = data.terms_consent.ip_address || clientIp;
          agreedAt = data.terms_consent.agreed_at || agreedAt;
        }
      } catch (err) {
        // If backend is offline or network fails, support autonomous offline mode gracefully!
        console.warn("Backend unavailable during registration; creating local authenticated session:", err);
        token = "local_token_" + Date.now();
        user = {
          email,
          full_name: fullName || email.split("@")[0],
          is_active: true,
          created_at: agreedAt
        };
      }

      // Always save to registered users store so future logins can verify password!
      await saveRegisteredUser(email, fullName, passwordHash, salt);

      // Save Auth Session
      await saveAuth(token, user);

      // Save Terms Consent Audit Record (email, IP, MAC/Device, Version, Timestamp)
      const consentData = {
        email,
        ip_address: clientIp,
        mac_address: macAddress,
        terms_version: "1.0.0",
        agreed_at: agreedAt
      };
      await saveTermsConsent(consentData);

      // Wipe all form inputs so no stale data remains in the login/signup section
      clearFormInputs();
      pendingSignUp = null;

      setStatus(el.statusTermsReview, "✓ Account created & Terms consent recorded!", "success");
      await updateAuthUI();
      setTimeout(() => {
        closeModal();
        el.btnConfirmTermsSignUp.disabled = false;
      }, 700);
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

