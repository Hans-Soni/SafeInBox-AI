/**
 * SafeInbox AI — Quishing (QR Code Phishing) Detector
 * 
 * Intercepts, extracts, and decodes embedded or inline QR codes inside email bodies.
 * Resolves the hidden destination URL and evaluates it through the SafeInbox AI
 * Threat Intelligence Engine before the user scans it on their mobile phone.
 * 
 * Complies with Manifest V3 and 100% Zero-PII privacy standards.
 */

(function (root, factory) {
  if (typeof define === "function" && define.amd) {
    define(["jsqr"], factory);
  } else if (typeof module === "object" && module.exports) {
    let jsQRMod;
    try {
      jsQRMod = require("jsqr");
    } catch {
      try {
        jsQRMod = require("../../vendor/jsQR.js");
      } catch {
        jsQRMod = null;
      }
    }
    module.exports = factory(jsQRMod);
  } else {
    root.QuishingDetector = factory(root.jsQR);
  }
})(typeof globalThis !== "undefined" ? globalThis : typeof window !== "undefined" ? window : this, function (jsQR) {
  "use strict";

  /**
   * Determine whether an image is a viable candidate for QR code inspection.
   * Discards 1x1 tracking pixels, thin horizontal banners, and oversized photos.
   */
  function isPotentialQrCandidate(img) {
    if (!img) return false;
    const w = img.naturalWidth || img.width || 0;
    const h = img.naturalHeight || img.height || 0;

    // Reject tiny tracking beacons or icon pills
    if (w < 40 || h < 40) return false;

    // Reject enormous wallpapers/attachments (> 2500px)
    if (w > 2500 || h > 2500) return false;

    // QR codes are approximately square (aspect ratio roughly 0.65 to 1.55)
    const ratio = w / h;
    if (ratio < 0.65 || ratio > 1.55) return false;

    return true;
  }

  /**
   * Extract ImageData from an image element or canvas.
   */
  function getImageDataFromElement(imgElement) {
    try {
      if (typeof document === "undefined") return null;
      const w = Math.min(imgElement.naturalWidth || imgElement.width || 300, 1200);
      const h = Math.min(imgElement.naturalHeight || imgElement.height || 300, 1200);
      if (w <= 0 || h <= 0) return null;

      const canvas = document.createElement("canvas");
      canvas.width = w;
      canvas.height = h;
      const ctx = canvas.getContext("2d", { willReadFrequently: true });
      if (!ctx) return null;

      ctx.drawImage(imgElement, 0, 0, w, h);
      return ctx.getImageData(0, 0, w, h);
    } catch (e) {
      // Catches canvas security errors on cross-origin images without CORS headers
      return null;
    }
  }

  /**
   * Decode QR Code from raw ImageData or Image element.
   */
  async function decodeQrCode(source) {
    if (!source) return null;

    // 1. Native Chromium BarcodeDetector API (Zero-allocation fast path)
    if (typeof BarcodeDetector !== "undefined" && typeof source.nodeType === "number") {
      try {
        const detector = new BarcodeDetector({ formats: ["qr_code"] });
        const barcodes = await detector.detect(source);
        if (Array.isArray(barcodes) && barcodes.length > 0 && barcodes[0].rawValue) {
          return formatQrResult(barcodes[0].rawValue);
        }
      } catch (err) {
        // Fallback to pure JS decoder
      }
    }

    // 2. Pure JavaScript jsQR Fallback
    const qrEngine = typeof jsQR === "function" ? jsQR : (typeof window !== "undefined" && window.jsQR);
    if (typeof qrEngine !== "function") {
      return null;
    }

    let imgData = null;
    if (source.data && typeof source.width === "number" && typeof source.height === "number") {
      imgData = source;
    } else if (typeof source.getContext === "function") {
      imgData = source.getContext("2d")?.getImageData(0, 0, source.width, source.height);
    } else if (source.tagName && source.tagName.toUpperCase() === "IMG") {
      imgData = getImageDataFromElement(source);
    }

    if (!imgData || !imgData.data) return null;

    try {
      const code = qrEngine(imgData.data, imgData.width, imgData.height, {
        inversionAttempts: "attemptBoth"
      });
      if (code && code.data && code.data.trim()) {
        return formatQrResult(code.data.trim());
      }
    } catch (err) {
      return null;
    }

    return null;
  }

  /**
   * Format and validate decoded QR content.
   */
  function formatQrResult(rawData) {
    const trimmed = String(rawData || "").trim();
    if (!trimmed) return null;

    // Check if decoded string is an HTTP/HTTPS URL
    const isUrl = /^https?:\/\//i.test(trimmed) ||
                  /^[a-z0-9.-]+\.[a-z]{2,}(\/.*)?$/i.test(trimmed);

    let normalizedUrl = "";
    if (isUrl) {
      normalizedUrl = /^https?:\/\//i.test(trimmed) ? trimmed : `https://${trimmed}`;
    }

    return {
      success: true,
      rawData: trimmed,
      isUrl: Boolean(isUrl),
      url: normalizedUrl
    };
  }

  /**
   * Scan an email message container element for embedded QR codes.
   */
  async function extractQrCodesFromContainer(containerEl) {
    if (!containerEl || typeof containerEl.querySelectorAll !== "function") return [];
    const images = Array.from(containerEl.querySelectorAll("img, picture img, svg image"));
    const candidates = images.filter(isPotentialQrCandidate);

    const results = [];
    for (const img of candidates) {
      try {
        const decoded = await decodeQrCode(img);
        if (decoded && decoded.success) {
          results.push({
            ...decoded,
            imgSrc: (img.src || "").substring(0, 200),
            width: img.naturalWidth || img.width || 0,
            height: img.naturalHeight || img.height || 0,
            element: img
          });
        }
      } catch (err) {
        // Continue inspecting other images
      }
    }

    return results;
  }

  return {
    isPotentialQrCandidate,
    decodeQrCode,
    extractQrCodesFromContainer,
    formatQrResult
  };
});
