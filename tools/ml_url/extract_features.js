"use strict";

const fs = require("node:fs");
const path = require("node:path");
const readline = require("node:readline");
const crypto = require("node:crypto");
const { analyzeUrl, FEATURE_COUNT, CHAR_TENSOR_LENGTH } = require("../../extension/src/url/urlThreatParser.js");

function parseArgs() {
  const args = process.argv.slice(2);
  const options = {
    file: null,
    outPrefix: null,
    maxRows: Infinity
  };
  for (let i = 0; i < args.length; i++) {
    if (args[i] === "--file" && args[i + 1]) options.file = args[++i];
    if (args[i] === "--out" && args[i + 1]) options.outPrefix = args[++i];
    if (args[i] === "--max" && args[i + 1]) options.maxRows = parseInt(args[++i], 10);
  }
  return options;
}

function getSplit(str) {
  const hash = crypto.createHash("sha256").update(str).digest("hex");
  const value = parseInt(hash.slice(0, 4), 16) / 65535;
  if (value < 0.80) return "train";
  if (value < 0.90) return "val";
  return "test";
}

function parseRow(headerLine, line) {
  const hLower = headerLine.toLowerCase();
  const trimmed = line.trim();
  if (!trimmed) return null;

  if (hLower.includes("result")) {
    // Format: <index>,<url>,<label>,<result>
    const lastComma = trimmed.lastIndexOf(",");
    if (lastComma === -1) return null;
    const resultToken = trimmed.slice(lastComma + 1).trim();
    const rest = trimmed.slice(0, lastComma);
    const secondLastComma = rest.lastIndexOf(",");
    if (secondLastComma === -1) return null;
    const labelToken = rest.slice(secondLastComma + 1).trim().toLowerCase();
    const firstComma = rest.indexOf(",");
    if (firstComma === -1 || firstComma >= secondLastComma) return null;
    let url = rest.slice(firstComma + 1, secondLastComma).trim();
    if (url.startsWith('"') && url.endsWith('"')) url = url.slice(1, -1).trim();

    let label = -1;
    if (resultToken === "0" || labelToken === "benign") label = 0;
    else if (resultToken === "1" || labelToken === "malicious") label = 1;
    if (label === -1 || !url) return null;
    return { url, label };
  } else {
    // Format: <url>,<label> or <url>,<type>
    const lastComma = trimmed.lastIndexOf(",");
    if (lastComma === -1) return null;
    const labelToken = trimmed.slice(lastComma + 1).trim().toLowerCase();
    let url = trimmed.slice(0, lastComma).trim();
    if (url.startsWith('"') && url.endsWith('"')) url = url.slice(1, -1).trim();

    let label = -1;
    if (labelToken === "good" || labelToken === "benign" || labelToken === "0") {
      label = 0;
    } else if (
      labelToken === "bad" ||
      labelToken === "malicious" ||
      labelToken === "phishing" ||
      labelToken === "defacement" ||
      labelToken === "malware" ||
      labelToken === "1"
    ) {
      label = 1;
    }
    if (label === -1 || !url) return null;
    return { url, label };
  }
}

function parseCsvLine(line) {
  const result = [];
  let current = "";
  let inQuotes = false;
  for (let i = 0; i < line.length; i++) {
    const char = line[i];
    if (char === '"') {
      inQuotes = !inQuotes;
    } else if (char === ',' && !inQuotes) {
      result.push(current);
      current = "";
    } else {
      current += char;
    }
  }
  result.push(current);
  return result;
}

async function processFile() {
  const options = parseArgs();
  if (!options.file || !options.outPrefix) {
    console.error("Usage: node extract_features.js --file raw/URL1.csv --out data/processed/url/URL1");
    process.exit(1);
  }

  const outDir = path.dirname(options.outPrefix);
  fs.mkdirSync(outDir, { recursive: true });

  const splits = ["train", "val", "test"];
  const streams = {};
  const counts = { train: 0, val: 0, test: 0 };
  const labelCounts = {
    train: { 0: 0, 1: 0 },
    val: { 0: 0, 1: 0 },
    test: { 0: 0, 1: 0 }
  };

  for (const s of splits) {
    streams[`${s}_feats`] = fs.createWriteStream(`${options.outPrefix}_${s}_feats.bin`);
    streams[`${s}_chars`] = fs.createWriteStream(`${options.outPrefix}_${s}_chars.bin`);
    streams[`${s}_labels`] = fs.createWriteStream(`${options.outPrefix}_${s}_labels.bin`);
  }

  const fileStream = fs.createReadStream(options.file, { encoding: "utf-8" });
  const rl = readline.createInterface({ input: fileStream, crlfDelay: Infinity });

  let header = null;
  let totalProcessed = 0;
  let skipped = 0;
  const startTime = Date.now();

  for await (const line of rl) {
    if (!line.trim()) continue;

    if (!header) {
      header = line.trim();
      continue;
    }

    const row = parseRow(header, line);
    if (!row) {
      skipped++;
      continue;
    }

    const { url, label } = row;
    if (!url || url.length < 3 || url.length > 4096) {
      skipped++;
      continue;
    }

    let parsed;
    try {
      parsed = analyzeUrl(url);
    } catch {
      skipped++;
      continue;
    }

    const split = getSplit(parsed.canonicalUrl || url);
    counts[split]++;
    labelCounts[split][label]++;

    // Write binary buffers directly
    streams[`${split}_feats`].write(Buffer.from(parsed.featureVector.buffer));
    streams[`${split}_chars`].write(Buffer.from(parsed.charTensor.buffer));
    
    const labelBuf = Buffer.alloc(4);
    labelBuf.writeInt32LE(label, 0);
    streams[`${split}_labels`].write(labelBuf);

    totalProcessed++;
    if (totalProcessed % 50000 === 0) {
      const elapsed = (Date.now() - startTime) / 1000;
      console.log(`[${path.basename(options.file)}] Processed ${totalProcessed.toLocaleString()} URLs (${(totalProcessed / elapsed).toFixed(0)}/s)...`);
    }

    if (totalProcessed >= options.maxRows) break;
  }

  for (const key of Object.keys(streams)) {
    streams[key].end();
  }

  const metadata = {
    sourceFile: options.file,
    featureCount: FEATURE_COUNT,
    charLength: CHAR_TENSOR_LENGTH,
    totalValid: totalProcessed,
    skipped,
    counts,
    labelCounts,
    timestamp: new Date().toISOString()
  };

  fs.writeFileSync(`${options.outPrefix}_meta.json`, JSON.stringify(metadata, null, 2));

  const totalTime = ((Date.now() - startTime) / 1000).toFixed(2);
  console.log(`\n=== Feature Extraction Complete for ${path.basename(options.file)} ===`);
  console.log(`Total URLs: ${totalProcessed.toLocaleString()} valid, ${skipped.toLocaleString()} skipped (${totalTime}s)`);
  console.log(`Train: ${counts.train.toLocaleString()} (Threats: ${labelCounts.train[1].toLocaleString()}, Benign: ${labelCounts.train[0].toLocaleString()})`);
  console.log(`Val:   ${counts.val.toLocaleString()} (Threats: ${labelCounts.val[1].toLocaleString()}, Benign: ${labelCounts.val[0].toLocaleString()})`);
  console.log(`Test:  ${counts.test.toLocaleString()} (Threats: ${labelCounts.test[1].toLocaleString()}, Benign: ${labelCounts.test[0].toLocaleString()})`);
}

processFile().catch(console.error);

