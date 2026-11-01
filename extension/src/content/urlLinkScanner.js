"use strict";

(() => {
  // Webmail platforms (Gmail, Outlook, Yahoo Mail) are dedicated email applications.
  // Email messages are scanned exclusively by contentScript.js, scoped strictly to the
  // opened email content. urlLinkScanner must not execute on webmail to prevent
  // scanning platform navigation (Inbox, Starred, Sent, Drafts), sidebars, toolbars,
  // or user account menus.
  const WEBMAIL_DOMAINS = [
    "mail.google.com",
    "outlook.live.com",
    "outlook.office.com",
    "mail.yahoo.com"
  ];
  if (typeof window !== "undefined" && window.location && window.location.hostname) {
    const host = window.location.hostname.toLowerCase();
    if (WEBMAIL_DOMAINS.some(domain => host === domain || host.endsWith("." + domain))) {
      return;
    }
  }

  const inspected = new WeakMap();
  const resultsByUrl = new Map();
  const containers = new WeakMap();
  const BLOCK_THRESHOLD = 0.45;
  const BATCH_SIZE = 4;
  const PREF_KEY = "site_inspection_preferences";
  let isInspectionActive = false;
  let observer = null;

  function getSiteHost() {
    if (typeof window !== "undefined" && window.location && window.location.hostname) {
      return window.location.hostname.toLowerCase();
    }
    return "";
  }

  function escapeHtml(str) {
    return String(str ?? "").replace(/[&<>"']/g, m => ({
      "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
    }[m]));
  }

  function isHttpLink(anchor) {
    return anchor instanceof HTMLAnchorElement && /^https?:$/i.test(anchor.protocol);
  }

  function ensureContainer(anchor) {
    let container = containers.get(anchor);
    if (container) return container;
    container = document.createElement("span");
    container.className = "url-threat-indicator-host";
    container.style.cssText = "display:inline-flex!important;vertical-align:middle!important;margin-inline-start:5px!important;";
    const shadow = container.attachShadow({ mode: "closed" });
    shadow.innerHTML = `
      <style>
        :host{all:initial;font:12px/1.4 Arial,sans-serif}
        .badge{border:1px solid #d97706;border-radius:999px;background:#fffbeb;color:#92400e;padding:2px 7px;font:700 11px/1.4 Arial,sans-serif;cursor:pointer}
        .badge.danger{border-color:#dc2626;background:#fef2f2;color:#991b1b}
        .badge.signal{border-color:#d97706;background:#fffbeb;color:#92400e}
        .badge.safe{border-color:#15803d;background:#f0fdf4;color:#166534}
        .card{position:fixed;z-index:2147483647;display:none;width:min(350px,calc(100vw - 24px));max-height:300px;overflow:auto;box-sizing:border-box;padding:12px;border:1px solid #475569;border-radius:10px;background:#111827;color:#f9fafb;box-shadow:0 12px 32px #0008;font:12px/1.5 Arial,sans-serif}
        .title{font-weight:700;font-size:13px;margin:0 0 6px}
        .score{color:#fca5a5;margin:0 0 8px}
        .finding{border-top:1px solid #374151;padding:7px 0}
        .finding strong{display:block;color:#fecaca}
        .finding p{margin:2px 0 0;color:#d1d5db;overflow-wrap:anywhere}
        .close{float:right;border:0;background:transparent;color:#cbd5e1;cursor:pointer;font-size:16px}
        .modal{position:fixed;inset:0;z-index:2147483647;display:grid;place-items:center;background:#020617b8;padding:16px}
        .modal-card{max-width:420px;padding:18px;border:1px solid #dc2626;border-radius:12px;background:#111827;color:#f9fafb;box-shadow:0 20px 50px #0009}
        .modal-card h2{margin:0 0 8px;font-size:17px}
        .modal-card p{margin:8px 0;color:#e5e7eb;overflow-wrap:anywhere}
        .actions{display:flex;justify-content:flex-end;gap:8px;margin-top:16px}
        .actions button{border:1px solid #64748b;border-radius:6px;padding:8px 12px;background:#1f2937;color:#fff;cursor:pointer}
        .actions .continue{border-color:#b91c1c;background:#991b1b}
      </style>
      <button class="badge" type="button" aria-label="URL scan pending">Checking link</button>
      <section class="card" role="status" aria-live="polite">
        <button class="close" type="button" aria-label="Close details">&times;</button>
        <h2 class="title">URL assessment</h2>
        <p class="score"></p>
        <div class="findings"></div>
      </section>`;

    const badge = shadow.querySelector(".badge");
    const card = shadow.querySelector(".card");
    badge.addEventListener("click", (event) => {
      event.preventDefault();
      event.stopPropagation();
      card.style.display = card.style.display === "block" ? "none" : "block";
      if (card.style.display === "block") positionCard(card, anchor);
    });
    badge.addEventListener("mouseenter", () => {
      card.style.display = "block";
      positionCard(card, anchor);
    });
    shadow.querySelector(".close").addEventListener("click", () => { card.style.display = "none"; });
    card.addEventListener("mouseleave", () => { card.style.display = "none"; });
    containers.set(anchor, { host: container, shadow, badge, card });
    anchor.insertAdjacentElement("afterend", container);
    return containers.get(anchor);
  }

  function positionCard(card, anchor) {
    const rect = anchor.getBoundingClientRect();
    card.style.left = `${Math.max(12, Math.min(rect.left, window.innerWidth - 362))}px`;
    card.style.top = `${Math.max(12, Math.min(rect.bottom + 8, window.innerHeight - 320))}px`;
  }

  function renderAssessment(anchor, result) {
    const ui = ensureContainer(anchor);
    const danger = result.riskScore >= 0.45;
    const hasSignals = result.findings.length > 0;
    anchor.style.setProperty("outline", danger ? "2px solid #dc2626" : hasSignals ? "2px solid #d97706" : "2px solid #15803d", "important");
    anchor.style.setProperty("outline-offset", "2px", "important");
    ui.badge.className = `badge ${danger ? "danger" : hasSignals ? "signal" : "safe"}`;
    ui.badge.textContent = danger ? "⚠ UNSAFE LINK" : hasSignals ? "⚠ SIGNAL" : "✓ CHECKED";
    ui.badge.setAttribute("aria-label", `${danger ? "High-risk" : hasSignals ? "Low-level indicator" : "No high-risk signals detected"} URL; risk ${(result.riskScore * 100).toFixed(0)} percent`);
    ui.shadow.querySelector(".title").textContent = danger ? "Potentially unsafe URL" : "No high-risk URL signals";
    ui.shadow.querySelector(".score").textContent = `Risk score: ${(result.riskScore * 100).toFixed(0)}% · ${result.modelAvailable ? "ONNX + heuristics" : "heuristics only"}`;
    const findings = ui.shadow.querySelector(".findings");
    findings.replaceChildren();
    for (const finding of result.findings) {
      const item = document.createElement("div");
      item.className = "finding";
      const title = document.createElement("strong");
      title.textContent = finding.title;
      const detail = document.createElement("p");
      detail.textContent = finding.detail;
      item.append(title, detail);
      findings.append(item);
    }
    if (!result.findings.length) {
      const item = document.createElement("p");
      item.className = "finding";
      item.textContent = "No configured threat indicators were found. This is not a guarantee of safety.";
      findings.append(item);
    }
    resultsByUrl.set(anchor.href, result);
  }

  function analyzeUrl(url) {
    if (resultsByUrl.has(url)) return Promise.resolve(resultsByUrl.get(url));
    const localHeuristicResult = (warning) => {
      const parsed = UrlThreatParser.analyzeUrl(url);
      return {
        ...parsed,
        riskScore: parsed.heuristicRisk,
        modelAvailable: false,
        analysisWarning: warning
      };
    };
    if (typeof chrome === "undefined" || !chrome.runtime || !chrome.runtime.sendMessage) {
      return Promise.resolve(localHeuristicResult("Extension runtime is unavailable."));
    }
    return new Promise((resolve, reject) => {
      chrome.runtime.sendMessage({ type: "ANALYZE_URL", url }, (response) => {
        if (chrome.runtime.lastError) {
          resolve(localHeuristicResult(`Background analysis unavailable: ${chrome.runtime.lastError.message}`));
          return;
        }
        if (!response || !response.ok) {
          const error = response && response.error ? response.error : "URL analysis failed.";
          if (/Only HTTP and HTTPS|Enter a URL|could not be parsed/.test(error)) {
            reject(new Error(error));
          } else {
            resolve(localHeuristicResult(`Background analysis unavailable: ${error}`));
          }
          return;
        }
        resolve(response.result);
      });
    });
  }

  async function analyzeBatch(anchors) {
    for (let index = 0; index < anchors.length; index += BATCH_SIZE) {
      const batch = anchors.slice(index, index + BATCH_SIZE);
      await Promise.all(batch.map(async (anchor) => {
        try {
          const result = await analyzeUrl(anchor.href);
          renderAssessment(anchor, result);
        } catch (error) {
          const ui = ensureContainer(anchor);
          ui.badge.className = "badge";
          ui.badge.textContent = "SCAN ERROR";
          ui.badge.title = error.message;
        }
      }));
    }
  }

  function showBlockConfirmation(anchor, result) {
    const host = document.createElement("div");
    host.style.cssText = "all:initial!important;position:fixed!important;inset:0!important;z-index:2147483647!important;";
    const shadow = host.attachShadow({ mode: "closed" });
    shadow.innerHTML = `
      <style>
        :host{all:initial;font:14px/1.5 Arial,sans-serif}
        .backdrop{position:fixed;inset:0;display:grid;place-items:center;background:#020617c9;padding:16px}
        .card{max-width:460px;padding:20px;border:1px solid #dc2626;border-radius:12px;background:#111827;color:#f9fafb;box-shadow:0 20px 60px #000b}
        h2{margin:0 0 8px;font-size:19px;color:#fecaca}
        p{margin:8px 0;overflow-wrap:anywhere}
        ul{padding-left:20px}
        .actions{display:flex;justify-content:flex-end;gap:8px;margin-top:18px}
        button{border:1px solid #64748b;border-radius:6px;padding:9px 13px;background:#1f2937;color:#fff;cursor:pointer}
        .continue{border-color:#b91c1c;background:#991b1b}
      </style>
      <div class="backdrop" role="dialog" aria-modal="true" aria-labelledby="threat-title">
        <section class="card">
          <h2 id="threat-title">Potentially unsafe link blocked</h2>
          <p>Risk score: ${(result.riskScore * 100).toFixed(0)}%. Review the indicators before continuing:</p>
          <ul class="reasons"></ul>
          <p class="url"></p>
          <div class="actions"><button class="cancel" type="button">Go back</button><button class="continue" type="button">Continue anyway</button></div>
        </section>
      </div>`;
    const reasons = shadow.querySelector(".reasons");
    for (const finding of result.findings) {
      const item = document.createElement("li");
      item.textContent = `${finding.title}: ${finding.detail}`;
      reasons.append(item);
    }
    shadow.querySelector(".url").textContent = anchor.href;
    const closeModal = () => {
      host.remove();
      document.removeEventListener("keydown", onKeyDown);
    };
    const onKeyDown = (event) => {
      if (event.key === "Escape") closeModal();
    };
    document.addEventListener("keydown", onKeyDown);
    shadow.querySelector(".cancel").addEventListener("click", closeModal);
    shadow.querySelector(".continue").addEventListener("click", () => {
      closeModal();
      if (anchor.target === "_blank") window.open(anchor.href, "_blank", "noopener,noreferrer");
      else window.location.assign(anchor.href);
    });
    shadow.querySelector(".backdrop").addEventListener("click", (event) => {
      if (event.target === event.currentTarget) closeModal();
    });
    document.documentElement.append(host);
    shadow.querySelector(".cancel").focus();
  }

  document.addEventListener("click", async (event) => {
    if (!isInspectionActive) return;
    const anchor = event.target instanceof Element ? event.target.closest("a[href]") : null;
    if (!anchor || !isHttpLink(anchor)) return;
    const result = resultsByUrl.get(anchor.href);
    if (result && result.riskScore >= BLOCK_THRESHOLD) {
      event.preventDefault();
      event.stopImmediatePropagation();
      showBlockConfirmation(anchor, result);
      return;
    }
    if (!result) {
      event.preventDefault();
      event.stopImmediatePropagation();
      ensureContainer(anchor).badge.textContent = "Checking; click again";
      try {
        renderAssessment(anchor, await analyzeUrl(anchor.href));
      } catch (error) {
        ensureContainer(anchor).badge.title = error.message;
        ensureContainer(anchor).badge.textContent = "SCAN ERROR";
      }
    }
  }, true);

  function inspectNewLinks() {
    if (!isInspectionActive) return;
    const newAnchors = Array.from(document.querySelectorAll('a[href^="http"]'))
      .filter((anchor) => inspected.get(anchor) !== anchor.href && isHttpLink(anchor));
    for (const anchor of newAnchors) inspected.set(anchor, anchor.href);
    if (newAnchors.length) void analyzeBatch(newAnchors);
  }

  function startInspection() {
    if (isInspectionActive) return;
    isInspectionActive = true;

    if (document.readyState === "loading") {
      document.addEventListener("DOMContentLoaded", inspectNewLinks, { once: true });
    } else {
      inspectNewLinks();
    }
    if (!observer && typeof MutationObserver !== "undefined") {
      observer = new MutationObserver(inspectNewLinks);
      observer.observe(document.documentElement, {
        childList: true,
        subtree: true,
        attributes: true,
        attributeFilter: ["href"]
      });
    }
  }

  function showSiteInspectionPrompt(host) {
    if (typeof document === "undefined" || !document.documentElement) return;
    if (document.getElementById("safeinbox-site-prompt-host")) return;

    const hostContainer = document.createElement("div");
    hostContainer.id = "safeinbox-site-prompt-host";
    const shadow = hostContainer.attachShadow({ mode: "closed" });
    shadow.innerHTML = `
      <style>
        :host { all: initial; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Arial, sans-serif; }
        .prompt-card {
          position: fixed;
          bottom: 24px;
          right: 24px;
          z-index: 2147483647;
          width: 320px;
          background: #111827;
          border: 1px solid #384358;
          border-radius: 12px;
          box-shadow: 0 16px 40px rgba(0, 0, 0, 0.7);
          color: #f8fafc;
          padding: 16px;
          box-sizing: border-box;
          animation: safeinboxSlideUp 0.25s cubic-bezier(0.16, 1, 0.3, 1);
        }
        @keyframes safeinboxSlideUp {
          from { transform: translateY(20px); opacity: 0; }
          to { transform: translateY(0); opacity: 1; }
        }
        .header {
          display: flex;
          align-items: center;
          justify-content: space-between;
          margin-bottom: 8px;
        }
        .brand {
          display: flex;
          align-items: center;
          gap: 6px;
          font-size: 12px;
          font-weight: 700;
          color: #FFA586;
          letter-spacing: 0.5px;
        }
        .close-btn {
          background: transparent;
          border: none;
          color: #94a3b8;
          font-size: 18px;
          cursor: pointer;
          line-height: 1;
          padding: 0 4px;
        }
        .close-btn:hover { color: #f8fafc; }
        .desc {
          font-size: 11.5px;
          color: #cbd5e1;
          line-height: 1.45;
          margin-bottom: 14px;
        }
        .host-badge {
          color: #FFA586;
          font-weight: 600;
          word-break: break-all;
        }
        .actions {
          display: flex;
          gap: 8px;
        }
        .btn {
          flex: 1;
          padding: 8px 10px;
          font-size: 11px;
          font-weight: 600;
          border-radius: 6px;
          cursor: pointer;
          border: none;
          transition: all 0.15s;
          text-align: center;
        }
        .btn-primary {
          background: #FFA586;
          color: #10152F;
        }
        .btn-primary:hover {
          background: #ffbba4;
        }
        .btn-secondary {
          background: #1e293b;
          color: #cbd5e1;
          border: 1px solid #384358;
        }
        .btn-secondary:hover {
          background: #334155;
          color: #f8fafc;
        }
      </style>
      <div class="prompt-card" role="dialog" aria-label="SafeInbox AI Site Inspection Request">
        <div class="header">
          <div class="brand">
            <span>🛡️ SafeInbox AI</span>
          </div>
          <button class="close-btn" type="button" aria-label="Dismiss">&times;</button>
        </div>
        <div class="desc">
          Do you want link safety inspections on <span class="host-badge">${escapeHtml(host)}</span>?
        </div>
        <div class="actions">
          <button class="btn btn-primary" type="button" id="btnInspectAlways">Always Inspect</button>
          <button class="btn btn-secondary" type="button" id="btnLeaveIt">Leave It</button>
        </div>
      </div>
    `;

    const closePrompt = () => {
      hostContainer.remove();
    };

    shadow.querySelector(".close-btn").addEventListener("click", closePrompt);

    shadow.querySelector("#btnInspectAlways").addEventListener("click", () => {
      saveSitePreference(host, true);
      closePrompt();
      startInspection();
    });

    shadow.querySelector("#btnLeaveIt").addEventListener("click", () => {
      saveSitePreference(host, false);
      closePrompt();
    });

    document.documentElement.appendChild(hostContainer);
  }

  function saveSitePreference(host, allow) {
    if (typeof chrome === "undefined" || !chrome.storage || !chrome.storage.local) return;
    try {
      chrome.storage.local.get([PREF_KEY], (stored) => {
        const prefs = (stored && stored[PREF_KEY]) || {};
        prefs[host] = Boolean(allow);
        chrome.storage.local.set({ [PREF_KEY]: prefs });
      });
    } catch {
      // Non-blocking
    }
  }

  function checkSiteInspectionPermission() {
    const host = getSiteHost();
    if (!host) return;

    if (typeof chrome === "undefined" || !chrome.storage || !chrome.storage.local) {
      startInspection();
      return;
    }

    try {
      chrome.storage.local.get([PREF_KEY], (items) => {
        const prefs = (items && items[PREF_KEY]) || {};
        const preference = prefs[host];

        if (preference === true) {
          startInspection();
        } else if (preference === false) {
          // User requested to leave this site alone
          return;
        } else {
          // Ask user whether they want inspection on this site
          if (document.readyState === "loading") {
            document.addEventListener("DOMContentLoaded", () => showSiteInspectionPrompt(host), { once: true });
          } else {
            showSiteInspectionPrompt(host);
          }
        }
      });
    } catch {
      startInspection();
    }
  }

  checkSiteInspectionPermission();
})();
