"use strict";

(() => {
  const TERMS_VERSION = "1.0.0";
  const BACKEND_URL = "http://localhost:8080";

  const el = {
    consentCard: document.getElementById("consentCard"),
    consentDot: document.getElementById("consentDot"),
    consentTitleText: document.getElementById("consentTitleText"),
    consentBadge: document.getElementById("consentBadge"),
    consentDetails: document.getElementById("consentDetails"),
    valConsentEmail: document.getElementById("valConsentEmail"),
    valConsentIp: document.getElementById("valConsentIp"),
    valConsentMac: document.getElementById("valConsentMac"),
    valConsentVersion: document.getElementById("valConsentVersion"),
    valConsentTime: document.getElementById("valConsentTime"),
    btnPageAgree: document.getElementById("btnPageAgree"),
    btnPageDecline: document.getElementById("btnPageDecline")
  };

  function getStoredItem(key) {
    return new Promise((resolve) => {
      if (typeof chrome !== "undefined" && chrome.storage && chrome.storage.local) {
        chrome.storage.local.get([key], (res) => resolve(res ? res[key] : null));
      } else {
        try {
          const raw = localStorage.getItem(key);
          resolve(raw ? JSON.parse(raw) : null);
        } catch {
          resolve(null);
        }
      }
    });
  }

  function setStoredItem(key, value) {
    return new Promise((resolve) => {
      if (typeof chrome !== "undefined" && chrome.storage && chrome.storage.local) {
        chrome.storage.local.set({ [key]: value }, resolve);
      } else {
        try {
          localStorage.setItem(key, JSON.stringify(value));
        } catch {}
        resolve();
      }
    });
  }

  function removeStoredItem(key) {
    return new Promise((resolve) => {
      if (typeof chrome !== "undefined" && chrome.storage && chrome.storage.local) {
        chrome.storage.local.remove([key], resolve);
      } else {
        try {
          localStorage.removeItem(key);
        } catch {}
        resolve();
      }
    });
  }

  function detectHardwareMac() {
    return "N/A (Browser Sandbox Restricted: W3C Anti-Fingerprinting Policy)";
  }

  async function resolveClientIp() {
    try {
      const resp = await fetch(`${BACKEND_URL}/health`, { signal: AbortSignal.timeout(2000) });
      if (resp.ok) {
        return "127.0.0.1 (Local Verified)";
      }
    } catch {}
    return "127.0.0.1";
  }

  async function loadConsentState() {
    const consent = await getStoredItem("safeinbox_terms_consent");
    const auth = await getStoredItem("safeinbox_auth");

    if (consent && consent.terms_version) {
      renderConsented(consent);
    } else {
      renderPending(auth);
    }
  }

  function renderConsented(consent) {
    if (!el.consentCard) return;
    el.consentCard.classList.add("consented");
    if (el.consentTitleText) el.consentTitleText.textContent = "Consent Status: Active & Logged";
    if (el.consentBadge) {
      el.consentBadge.textContent = "✓ Consented";
      el.consentBadge.style.color = "#4ADE80";
    }
    if (el.consentDetails) el.consentDetails.style.display = "block";

    if (el.valConsentEmail) el.valConsentEmail.textContent = consent.email || "--";
    if (el.valConsentIp) el.valConsentIp.textContent = consent.ip_address || "--";
    if (el.valConsentMac) el.valConsentMac.textContent = consent.mac_address || detectHardwareMac();
    if (el.valConsentVersion) el.valConsentVersion.textContent = `v${consent.terms_version || TERMS_VERSION}`;
    if (el.valConsentTime) {
      const dateStr = consent.agreed_at ? new Date(consent.agreed_at).toUTCString() : "--";
      el.valConsentTime.textContent = dateStr;
    }

    if (el.btnPageAgree) {
      el.btnPageAgree.textContent = "✓ Consent Already Recorded";
      el.btnPageAgree.disabled = true;
      el.btnPageAgree.style.opacity = "0.7";
    }
  }

  function renderPending(auth) {
    if (!el.consentCard) return;
    el.consentCard.classList.remove("consented");
    if (el.consentTitleText) el.consentTitleText.textContent = "Consent Status: Action Required";
    if (el.consentBadge) {
      el.consentBadge.textContent = "Allowance Needed";
      el.consentBadge.style.color = "#FACC15";
    }
    if (el.consentDetails) el.consentDetails.style.display = "none";
    if (el.btnPageAgree) {
      el.btnPageAgree.disabled = false;
      el.btnPageAgree.style.opacity = "1";
    }
  }

  async function handleAgree() {
    const auth = await getStoredItem("safeinbox_auth");
    let email = auth?.user?.email;

    if (!email) {
      email = window.prompt("Please confirm your email address to record consent:", "user@safeinbox.ai");
      if (!email || !email.includes("@")) {
        alert("A valid email address is required to register legal terms allowance.");
        return;
      }
      email = email.trim().toLowerCase();
    }

    const ip = await resolveClientIp();
    const mac = detectHardwareMac();
    const agreedAt = new Date().toISOString();

    const consentData = {
      email,
      ip_address: ip,
      mac_address: mac,
      terms_version: TERMS_VERSION,
      agreed_at: agreedAt
    };

    // Save locally
    await setStoredItem("safeinbox_terms_consent", consentData);

    // Sync to backend if accessible
    try {
      await fetch(`${BACKEND_URL}/api/v1/auth/terms-consent`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          email,
          terms_version: TERMS_VERSION,
          mac_address: mac
        })
      });
    } catch {}

    renderConsented(consentData);
    alert(`Allowance granted! Your consent has been recorded.\n\nEmail: ${email}\nIP: ${ip}\nMAC: ${mac}\nVersion: ${TERMS_VERSION}\nTimestamp: ${agreedAt}`);
  }

  async function handleDecline() {
    await removeStoredItem("safeinbox_terms_consent");
    alert("You declined the Terms & Conditions. The page will now refresh.");
    window.location.reload();
  }

  document.addEventListener("DOMContentLoaded", () => {
    loadConsentState();
    el.btnPageAgree?.addEventListener("click", handleAgree);
    el.btnPageDecline?.addEventListener("click", handleDecline);
  });
})();

