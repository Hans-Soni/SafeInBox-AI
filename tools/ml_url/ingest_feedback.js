"use strict";

/**
 * User Feedback Ingestion Tool for Master URL Dataset.
 * 
 * Takes user-labeled URLs (Safe/Threat), extracts standard 32 features and 128 character tokens,
 * sanitizes PII query parameters, and appends them directly into data/processed/url/master_urls.bin.
 * 
 * Usage:
 *   node tools/ml_url/ingest_feedback.js --url "https://suspicious-domain.com" --label 1
 *   node tools/ml_url/ingest_feedback.js --file feedback_export.json
 */

const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const { analyzeUrl } = require("../../extension/src/url/urlThreatParser.js");

const MASTER_BIN_PATH = path.resolve(__dirname, "../../data/processed/url/master_urls.bin");
const MASTER_META_PATH = path.resolve(__dirname, "../../data/processed/url/master_urls_meta.json");
const HEADER_SIZE = 4096;
const RECORD_SIZE = 644;
const MAGIC = "SAFEURL1";

function parseArgs() {
  const args = process.argv.slice(2);
  const options = { url: null, label: null, file: null };
  for (let i = 0; i < args.length; i++) {
    if (args[i] === "--url" && args[i + 1]) options.url = args[++i];
    if (args[i] === "--label" && args[i + 1]) options.label = parseInt(args[++i], 10);
    if (args[i] === "--file" && args[i + 1]) options.file = args[++i];
  }
  return options;
}

function sanitizeUrl(rawUrl) {
  try {
    const parsed = new URL(rawUrl);
    // Redact sensitive credentials and query parameters
    parsed.username = "";
    parsed.password = "";
    const sensitiveParams = ["token", "auth", "session", "key", "password", "pwd", "secret", "sig", "signature", "otp", "code"];
    for (const p of sensitiveParams) {
      if (parsed.searchParams.has(p)) {
        parsed.searchParams.set(p, "[REDACTED]");
      }
    }
    return parsed.href;
  } catch (_) {
    return rawUrl;
  }
}

function packRecord(parsed, label, splitId = 0) {
  const buf = Buffer.alloc(RECORD_SIZE);
  // 1. Features: 32 float32 (128 bytes) at offset 0
  for (let i = 0; i < 32; i++) {
    buf.writeFloatLE(parsed.featureVector[i] || 0.0, i * 4);
  }
  // 2. Characters: 128 int32 (512 bytes) at offset 128
  for (let i = 0; i < 128; i++) {
    buf.writeInt32LE(parsed.charTensor[i] || 0, 128 + i * 4);
  }
  // 3. Label: uint8 at offset 640
  buf.writeUInt8(label === 1 ? 1 : 0, 640);
  // 4. Split: uint8 at offset 641 (0=train, 1=val, 2=test)
  buf.writeUInt8(splitId, 641);
  // 5. Source: uint8 at offset 642 (5 = User Feedback)
  buf.writeUInt8(5, 642);
  // 6. Reserved: uint8 at offset 643
  buf.writeUInt8(0, 643);

  return buf;
}

function getSplitForFeedback(urlStr) {
  const hash = crypto.createHash("sha256").update(urlStr).digest("hex");
  const val = parseInt(hash.slice(0, 4), 16) / 65535;
  return val < 0.85 ? 0 : 1; // 85% train, 15% validation
}

function ingestEntries(entries) {
  if (!fs.existsSync(MASTER_BIN_PATH)) {
    throw new Error(`Master URL file not found at ${MASTER_BIN_PATH}. Run build_master_url_dataset.py first.`);
  }

  const fd = fs.openSync(MASTER_BIN_PATH, "r+");
  const headerBuf = Buffer.alloc(HEADER_SIZE);
  fs.readSync(fd, headerBuf, 0, HEADER_SIZE, 0);

  const magic = headerBuf.subarray(0, 8).toString("ascii");
  if (magic !== MAGIC) {
    fs.closeSync(fd);
    throw new Error(`Invalid magic bytes in master file: ${magic}`);
  }

  let totalCount = Number(headerBuf.readBigUInt64LE(16));
  let trainCount = Number(headerBuf.readBigUInt64LE(24));
  let valCount = Number(headerBuf.readBigUInt64LE(32));
  let testCount = Number(headerBuf.readBigUInt64LE(40));
  let feedbackCount = Number(headerBuf.readBigUInt64LE(48));

  let appended = 0;
  for (const entry of entries) {
    if (!entry.url || entry.label === undefined) continue;
    const cleanUrl = sanitizeUrl(entry.url);
    const parsed = analyzeUrl(cleanUrl);
    if (!parsed || !parsed.featureVector || !parsed.charTensor) continue;

    const splitId = getSplitForFeedback(cleanUrl);
    const recordBuf = packRecord(parsed, entry.label, splitId);

    const writeOffset = HEADER_SIZE + totalCount * RECORD_SIZE;
    fs.writeSync(fd, recordBuf, 0, RECORD_SIZE, writeOffset);

    totalCount++;
    feedbackCount++;
    if (splitId === 0) trainCount++;
    else if (splitId === 1) valCount++;
    else testCount++;
    appended++;
  }

  // Update header
  headerBuf.writeBigUInt64LE(BigInt(totalCount), 16);
  headerBuf.writeBigUInt64LE(BigInt(trainCount), 24);
  headerBuf.writeBigUInt64LE(BigInt(valCount), 32);
  headerBuf.writeBigUInt64LE(BigInt(testCount), 40);
  headerBuf.writeBigUInt64LE(BigInt(feedbackCount), 48);
  fs.writeSync(fd, headerBuf, 0, HEADER_SIZE, 0);
  fs.closeSync(fd);

  // Update JSON meta if present
  if (fs.existsSync(MASTER_META_PATH)) {
    const meta = JSON.parse(fs.readFileSync(MASTER_META_PATH, "utf8"));
    meta.total_records = totalCount;
    meta.feedback_count = feedbackCount;
    meta.split_counts = { train: trainCount, val: valCount, test: testCount };
    fs.writeFileSync(MASTER_META_PATH, JSON.stringify(meta, null, 2), "utf8");
  }

  console.log(`[*] Successfully ingested ${appended} user feedback URL(s) into master_urls.bin.`);
  console.log(`    New Total: ${totalCount.toLocaleString()} URLs (User Feedback: ${feedbackCount.toLocaleString()})`);
}

function main() {
  const args = parseArgs();
  if (args.url && args.label !== null) {
    ingestEntries([{ url: args.url, label: args.label }]);
  } else if (args.file) {
    const raw = fs.readFileSync(args.file, "utf8");
    const data = JSON.parse(raw);
    const list = Array.isArray(data) ? data : data.feedback || [data];
    ingestEntries(list);
  } else {
    console.log("Usage: node tools/ml_url/ingest_feedback.js --url <URL> --label <0|1>");
    console.log("       node tools/ml_url/ingest_feedback.js --file <feedback.json>");
  }
}

if (require.main === module) {
  main();
}

module.exports = { ingestEntries, sanitizeUrl, packRecord };
