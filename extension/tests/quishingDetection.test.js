"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");

const QuishingDetector = require("../src/utils/quishingDetector.js");

test("Quishing: isPotentialQrCandidate accurately filters images by aspect ratio and dimension", () => {
  // 1x1 tracking pixel
  assert.equal(QuishingDetector.isPotentialQrCandidate({ width: 1, height: 1 }), false);

  // Tiny icon / emoji (24x24)
  assert.equal(QuishingDetector.isPotentialQrCandidate({ width: 24, height: 24 }), false);

  // Wide advertising banner (728x90)
  assert.equal(QuishingDetector.isPotentialQrCandidate({ width: 728, height: 90 }), false);

  // Tall skyscraper ad (160x600)
  assert.equal(QuishingDetector.isPotentialQrCandidate({ width: 160, height: 600 }), false);

  // Standard QR code sizes (approximately square, 50x50 to 800x800)
  assert.equal(QuishingDetector.isPotentialQrCandidate({ width: 200, height: 200 }), true);
  assert.equal(QuishingDetector.isPotentialQrCandidate({ width: 350, height: 320 }), true);
  assert.equal(QuishingDetector.isPotentialQrCandidate({ width: 150, height: 170 }), true);
  assert.equal(QuishingDetector.isPotentialQrCandidate({ naturalWidth: 400, naturalHeight: 400 }), true);
});

test("Quishing: formatQrResult correctly categorizes and normalizes URLs vs plain text", () => {
  // Full HTTPS URL
  const res1 = QuishingDetector.formatQrResult("https://secure-banking-portal.xyz/login?session=abc");
  assert.equal(res1.success, true);
  assert.equal(res1.isUrl, true);
  assert.equal(res1.url, "https://secure-banking-portal.xyz/login?session=abc");

  // Bare domain with path
  const res2 = QuishingDetector.formatQrResult("evil-payroll-verify.org/auth");
  assert.equal(res2.success, true);
  assert.equal(res2.isUrl, true);
  assert.equal(res2.url, "https://evil-payroll-verify.org/auth");

  // Plain non-URL text
  const res3 = QuishingDetector.formatQrResult("WIFI:S:MyNetwork;T:WPA;P:SecretPassword;;");
  assert.equal(res3.success, true);
  assert.equal(res3.isUrl, false);
  assert.equal(res3.url, "");
  assert.equal(res3.rawData, "WIFI:S:MyNetwork;T:WPA;P:SecretPassword;;");

  // Empty or invalid inputs
  assert.equal(QuishingDetector.formatQrResult(""), null);
  assert.equal(QuishingDetector.formatQrResult(null), null);
});

test("Quishing: decodeQrCode gracefully handles blank/invalid pixel buffers without throwing", async () => {
  const dummyBuffer = {
    data: new Uint8ClampedArray(64 * 64 * 4),
    width: 64,
    height: 64
  };

  const decoded = await QuishingDetector.decodeQrCode(dummyBuffer);
  assert.equal(decoded, null);
});

test("Quishing: decodeQrCode supports native BarcodeDetector API when available", async () => {
  // Mock global BarcodeDetector
  globalThis.BarcodeDetector = class MockBarcodeDetector {
    constructor(options) {
      this.formats = options?.formats || [];
    }
    async detect(source) {
      return [{ rawValue: "https://intercepted-qr-threat.com/verify" }];
    }
  };

  try {
    const mockElement = { nodeType: 1, tagName: "IMG", width: 250, height: 250 };
    const result = await QuishingDetector.decodeQrCode(mockElement);
    assert.ok(result);
    assert.equal(result.isUrl, true);
    assert.equal(result.url, "https://intercepted-qr-threat.com/verify");
  } finally {
    delete globalThis.BarcodeDetector;
  }
});

test("Quishing: extractQrCodesFromContainer extracts viable QR images from container DOM", async () => {
  globalThis.BarcodeDetector = class MockBarcodeDetector {
    async detect(source) {
      if (source.id === "qr_img_1") {
        return [{ rawValue: "https://quishing-target-domain.com/invoice.pdf" }];
      }
      return [];
    }
  };

  try {
    const mockContainer = {
      querySelectorAll: (selector) => [
        { id: "tracker", width: 1, height: 1, src: "https://tracker.com/1x1.png" },
        { id: "banner", width: 800, height: 80, src: "https://banner.com/banner.png" },
        { id: "qr_img_1", width: 280, height: 280, nodeType: 1, src: "data:image/png;base64,mockqr" }
      ]
    };

    const results = await QuishingDetector.extractQrCodesFromContainer(mockContainer);
    assert.equal(results.length, 1);
    assert.equal(results[0].url, "https://quishing-target-domain.com/invoice.pdf");
    assert.equal(results[0].isUrl, true);
  } finally {
    delete globalThis.BarcodeDetector;
  }
});
