"use strict";

const fs = require("node:fs");
const path = require("node:path");

const root = path.resolve(__dirname, "..");
const packageRoot = path.join(root, "node_modules", "onnxruntime-web");
const distribution = path.join(packageRoot, "dist");
const destination = path.join(root, "extension", "vendor");

if (!fs.existsSync(distribution)) {
  throw new Error("onnxruntime-web is not installed. Run npm install before syncing its browser runtime.");
}

const runtimeFiles = fs.readdirSync(distribution).filter((file) =>
  file === "ort.min.js" ||
  (file.startsWith("ort-wasm") && /\.(?:wasm|mjs|js)$/.test(file))
);
if (!runtimeFiles.includes("ort.min.js") || !runtimeFiles.some((file) => file.endsWith(".wasm"))) {
  throw new Error("The installed ONNX Runtime package does not contain its browser JS and WASM runtime files.");
}

fs.mkdirSync(destination, { recursive: true });
for (const file of runtimeFiles) {
  fs.copyFileSync(path.join(distribution, file), path.join(destination, file));
}

const licensePath = path.join(packageRoot, "LICENSE");
if (fs.existsSync(licensePath)) {
  fs.copyFileSync(licensePath, path.join(destination, "ONNX_RUNTIME_LICENSE.txt"));
}

console.log(`Copied ${runtimeFiles.length} ONNX Runtime Web assets into extension/vendor.`);
