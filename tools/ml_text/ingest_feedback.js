"use strict";

/**
 * User Feedback Ingestion Tool for Master Email Text Dataset.
 * 
 * Takes user-labeled email texts (Safe/Threat), sanitizes PII/credentials,
 * tokenizes with the WordPiece vocabulary, and appends them directly
 * into data/processed/text/master_emails.bin in O(1) time.
 * 
 * Usage:
 *   node tools/ml_text/ingest_feedback.js --text "Your account is locked. Click here to verify." --label 1
 *   node tools/ml_text/ingest_feedback.js --file feedback_text_export.json
 */

const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const { stripHtml, maskSensitiveTokens, wordPieceTokenize } = require("../../extension/src/utils/textParser.js");

const MASTER_BIN_PATH = path.resolve(__dirname, "../../data/processed/text/master_emails.bin");
const MASTER_META_PATH = path.resolve(__dirname, "../../data/processed/text/master_emails_meta.json");
const VOCAB_PATH = path.resolve(__dirname, "../../extension/models/email-vocab.json");

const HEADER_SIZE = 4096;
const RECORD_SIZE = 1028;
const SEQ_LEN = 128;
const MAGIC = "SAFETXT1";

function parseArgs() {
  const args = process.argv.slice(2);
  const options = { text: null, label: null, file: null };
  for (let i = 0; i < args.length; i++) {
    if (args[i] === "--text" && args[i + 1]) options.text = args[++i];
    if (args[i] === "--label" && args[i + 1]) options.label = parseInt(args[++i], 10);
    if (args[i] === "--file" && args[i + 1]) options.file = args[++i];
  }
  return options;
}

function sanitizeText(rawText) {
  if (!rawText || typeof rawText !== "string") return "";
  let cleaned = stripHtml(rawText);
  // Redact potential inline auth tokens / secret keys / API credentials
  cleaned = cleaned.replace(/\b(?:bearer\s+[a-zA-Z0-9_\-\.]{20,}|ghp_[a-zA-Z0-9]{30,}|sk_live_[a-zA-Z0-9]{24,})\b/gi, "[REDACTED]");
  // Redact passwords and pin codes
  cleaned = cleaned.replace(/(?:password|passcode|pin)[:= ]+\S+/gi, "password [REDACTED]");
  // Standard sensitive masking: URL, IP, MONEY
  return maskSensitiveTokens(cleaned);
}

function packRecord(tokenized, label, splitId = 0) {
  const buf = Buffer.alloc(RECORD_SIZE);
  // 1. input_ids: 128 int32 (512 bytes) at offset 0
  for (let i = 0; i < SEQ_LEN; i++) {
    buf.writeInt32LE(tokenized.input_ids[i] || 0, i * 4);
  }
  // 2. attention_mask: 128 int32 (512 bytes) at offset 512
  for (let i = 0; i < SEQ_LEN; i++) {
    buf.writeInt32LE(tokenized.attention_mask[i] || 0, 512 + i * 4);
  }
  // 3. Label: uint8 at offset 1024
  buf.writeUInt8(label === 1 ? 1 : 0, 1024);
  // 4. Split: uint8 at offset 1025 (0=train, 1=val, 2=test)
  buf.writeUInt8(splitId, 1025);
  // 5. Source: uint8 at offset 1026 (6 = User Feedback)
  buf.writeUInt8(6, 1026);
  // 6. Reserved: uint8 at offset 1027
  buf.writeUInt8(0, 1027);

  return buf;
}

function getSplitForFeedback(textStr) {
  const hash = crypto.createHash("sha256").update(textStr).digest("hex");
  const val = parseInt(hash.slice(0, 4), 16) / 65535;
  return val < 0.85 ? 0 : 1; // 85% train, 15% validation
}

function ingestEntries(entries) {
  if (!fs.existsSync(MASTER_BIN_PATH)) {
    throw new Error(`Master Email file not found at ${MASTER_BIN_PATH}. Run build_master_text_dataset.py first.`);
  }
  if (!fs.existsSync(VOCAB_PATH)) {
    throw new Error(`Email vocabulary file not found at ${VOCAB_PATH}.`);
  }

  const rawVocab = JSON.parse(fs.readFileSync(VOCAB_PATH, "utf-8"));
  const vocab = rawVocab.vocab || rawVocab;
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
  let writeOffset = HEADER_SIZE + totalCount * RECORD_SIZE;

  for (const entry of entries) {
    const raw = entry.text || entry.body || entry.message;
    if (!raw || typeof raw !== "string" || raw.trim().length < 2) continue;

    const label = Number(entry.label) === 1 ? 1 : 0;
    const sanitized = sanitizeText(raw);
    const tokenized = wordPieceTokenize(sanitized, vocab, SEQ_LEN);
    const splitId = getSplitForFeedback(sanitized);

    const recordBuf = packRecord(tokenized, label, splitId);
    fs.writeSync(fd, recordBuf, 0, RECORD_SIZE, writeOffset);
    writeOffset += RECORD_SIZE;

    totalCount++;
    if (splitId === 0) trainCount++;
    else valCount++;
    feedbackCount++;
    appended++;
  }

  // Update binary header
  headerBuf.writeBigUInt64LE(BigInt(totalCount), 16);
  headerBuf.writeBigUInt64LE(BigInt(trainCount), 24);
  headerBuf.writeBigUInt64LE(BigInt(valCount), 32);
  headerBuf.writeBigUInt64LE(BigInt(testCount), 40);
  headerBuf.writeBigUInt64LE(BigInt(feedbackCount), 48);
  fs.writeSync(fd, headerBuf, 0, HEADER_SIZE, 0);

  fs.closeSync(fd);

  // Update metadata JSON if exists
  if (fs.existsSync(MASTER_META_PATH)) {
    const meta = JSON.parse(fs.readFileSync(MASTER_META_PATH, "utf-8"));
    meta.total_records = totalCount;
    meta.split_counts = { train: trainCount, val: valCount, test: testCount };
    meta.feedback_count = feedbackCount;
    fs.writeFileSync(MASTER_META_PATH, JSON.stringify(meta, null, 2), "utf-8");
  }

  console.log(`[+] Successfully ingested ${appended} user feedback samples into master_emails.bin`);
  console.log(`    New Total: ${totalCount.toLocaleString()} Emails, Feedback count: ${feedbackCount.toLocaleString()}`);
  return { appended, totalCount, feedbackCount };
}

function main() {
  const options = parseArgs();
  if (options.url || options.text) {
    const text = options.text || options.url;
    if (options.label === null || isNaN(options.label)) {
      console.error("Error: --label (0 for Safe, 1 for Threat) is required when passing --text.");
      process.exit(1);
    }
    ingestEntries([{ text, label: options.label }]);
  } else if (options.file) {
    const filePath = path.resolve(options.file);
    if (!fs.existsSync(filePath)) {
      console.error(`Error: Feedback file not found at ${filePath}`);
      process.exit(1);
    }
    const data = JSON.parse(fs.readFileSync(filePath, "utf-8"));
    const entries = Array.isArray(data) ? data : data.feedback || [data];
    ingestEntries(entries);
  } else {
    console.log("Usage:");
    console.log("  node tools/ml_text/ingest_feedback.js --text \"<email content>\" --label <0|1>");
    console.log("  node tools/ml_text/ingest_feedback.js --file <feedback.json>");
  }
}

if (require.main === module) {
  main();
}

module.exports = { ingestEntries, sanitizeText, packRecord };
