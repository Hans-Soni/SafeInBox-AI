(function (root) {
  "use strict";

  const URL_PATTERN = /https?:\/\/[^\s<>"'`]+|www\.[^\s<>"'`]+/gi;
  const PROTOCOL_PATTERN = /https?:\/\//gi;
  const DOMAIN_PATTERN = /(^|[^a-z0-9_@.-])((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,63}|xn--[a-z0-9-]{2,59})(?::\d{1,5})?(?:\/[^\s<>"'`]*)?)/gi;

  function trimCandidate(value) {
    return value.replace(/[.,;:!?)}\]]+$/g, "");
  }

  function normalizeCandidate(value) {
    const candidate = trimCandidate(value.trim());
    if (!candidate) return null;
    const withScheme = /^https?:\/\//i.test(candidate) ? candidate : `https://${candidate}`;
    try {
      const parsed = new URL(withScheme);
      if (parsed.protocol !== "http:" && parsed.protocol !== "https:") return null;
      return parsed.href;
    } catch {
      return null;
    }
  }

  function extractUrlsFromEmail(text, hrefs = []) {
    const candidates = new Set();
    for (const href of hrefs) {
      if (typeof href === "string") candidates.add(href);
    }
    if (typeof text === "string") {
      const emailUrls = [];
      for (const match of text.matchAll(URL_PATTERN)) {
        candidates.add(match[0]);
        emailUrls.push(match[0]);
      }
      for (const marker of text.matchAll(PROTOCOL_PATTERN)) {
        const remainder = text.slice(marker.index);
        const nestedUrl = /^https?:\/\/[^\s<>"'`]+/i.exec(remainder);
        if (nestedUrl) {
          candidates.add(nestedUrl[0]);
          emailUrls.push(nestedUrl[0]);
        }
      }
      for (const match of text.matchAll(DOMAIN_PATTERN)) {
        if (!emailUrls.some((url) => url.toLowerCase().includes(match[2].toLowerCase()))) {
          candidates.add(match[2]);
        }
      }
    }

    const normalized = new Map();
    for (const candidate of candidates) {
      const url = normalizeCandidate(candidate);
      if (url && !normalized.has(url)) normalized.set(url, url);
    }
    return Array.from(normalized.values());
  }

  const api = { extractUrlsFromEmail };
  root.EmailThreatUtils = api;
  if (typeof module !== "undefined" && module.exports) module.exports = api;
})(typeof globalThis !== "undefined" ? globalThis : self);
