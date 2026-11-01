"use strict";

const fs = require("node:fs");
const path = require("node:path");
const { analyzeEmailText } = require("../extension/src/utils/textParser.js");

const fixturePath = path.join(__dirname, "..", "extension", "tests", "fixtures", "email-samples.json");
const extensionPath = path.join(__dirname, "..", "extension");
const manifest = JSON.parse(fs.readFileSync(path.join(extensionPath, "manifest.json"), "utf8"));
const fixtures = JSON.parse(fs.readFileSync(fixturePath, "utf8"));
const resources = [
  manifest.background.service_worker,
  manifest.side_panel.default_path,
  "offscreen.html",
  ...Object.values(manifest.icons),
  ...manifest.content_scripts.flatMap((entry) => [...entry.js, ...(entry.css || [])]),
  "src/ml/textMlWorker.js",
  "src/ml/textWorkerHost.js"
];
let failed = false;

for (const resource of resources) {
  if (!fs.existsSync(path.join(extensionPath, resource))) {
    failed = true;
    console.error(`Missing extension resource: ${resource}`);
  }
}

for (const fixture of fixtures) {
  const result = analyzeEmailText(fixture.email);
  const missing = fixture.expectedVectors.filter((vector) => !result.threat_vectors.includes(vector));
  const unexpected = result.threat_vectors.filter((vector) => !fixture.expectedVectors.includes(vector));
  if (missing.length || unexpected.length) {
    failed = true;
    console.error(`${fixture.name}: expected threat vectors did not match. Missing: ${missing.join(", ") || "none"}; unexpected: ${unexpected.join(", ") || "none"}.`);
  } else {
    console.log(`${fixture.name}: ${result.risk_level} (${result.risk_score}/100); vectors matched.`);
  }
}

if (failed) process.exitCode = 1;
else {
  const modelPath = path.join(__dirname, "..", "extension", "models", "email-threat.onnx");
  console.log(fs.existsSync(modelPath)
    ? "Email model file found. Confirm it matches the documented model contract before loading."
    : "No trained email model installed; the extension will report heuristic-only results.");
  console.log(`Load unpacked in chrome://extensions: ${extensionPath}`);
  console.log("Use the Side Panel's Netflix Spoof, PayPal Scam, and Safe Email buttons as synthetic demo triggers.");
}
