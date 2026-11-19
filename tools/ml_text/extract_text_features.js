"use strict";

const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const { stripHtml, maskSensitiveTokens, wordPieceTokenize } = require("../../extension/src/utils/textParser.js");

const MAX_LENGTH = 128;

function parseCsvFile(filePath, onRow) {
  return new Promise((resolve) => {
    const stream = fs.createReadStream(filePath, { encoding: "utf-8" });
    let inQuotes = false;
    let currentField = "";
    let currentRow = [];
    let header = null;

    stream.on("data", (chunk) => {
      for (let i = 0; i < chunk.length; i++) {
        const c = chunk[i];
        if (c === '"') {
          if (inQuotes && chunk[i + 1] === '"') {
            currentField += '"';
            i++;
          } else {
            inQuotes = !inQuotes;
          }
        } else if (c === "," && !inQuotes) {
          currentRow.push(currentField);
          currentField = "";
        } else if ((c === "\n" || c === "\r") && !inQuotes) {
          if (c === "\r" && chunk[i + 1] === "\n") i++;
          currentRow.push(currentField);
          currentField = "";
          if (currentRow.length > 1 || currentRow[0] !== "") {
            if (!header) {
              header = currentRow.map((h) => h.trim());
            } else {
              onRow(header, currentRow);
            }
          }
          currentRow = [];
        } else {
          currentField += c;
        }
      }
    });

    stream.on("end", () => {
      resolve();
    });
  });
}

function parseDatasetRow(filePath, header, row) {
  if (filePath.includes("text1.csv")) {
    const d = (row[0] || "").trim().toLowerCase();
    const text = (row[4] || "").trim();
    const label = d === "truthful" ? 0 : d === "deceptive" ? 1 : -1;
    return { label, text };
  }
  if (filePath.includes("text2.csv")) {
    const v = (row[0] || "").trim().toLowerCase();
    const text = (row[1] || "").trim();
    const label = v === "ham" ? 0 : v === "spam" ? 1 : -1;
    return { label, text };
  }
  if (filePath.includes("text3.csv")) {
    const text = (row[2] || "").trim();
    const lblNum = (row[3] || "").trim();
    const l = (row[1] || "").trim().toLowerCase();
    const label = lblNum === "0" || l === "ham" ? 0 : lblNum === "1" || l === "spam" ? 1 : -1;
    return { label, text };
  }
  if (filePath.includes("text4.csv")) {
    const l = (row[0] || "").trim();
    const text = (row[2] || "").trim();
    const label = l === "0" ? 0 : l === "1" ? 1 : -1;
    return { label, text };
  }
  if (filePath.includes("both url and txt.csv")) {
    const l = (row[0] || "").trim();
    const text = (row[1] || "").trim();
    const label = l === "0" ? 0 : l === "1" ? 1 : -1;
    return { label, text };
  }
  return { label: -1, text: "" };
}

function getSplit(str) {
  const hash = crypto.createHash("sha256").update(str).digest("hex");
  const value = parseInt(hash.slice(0, 4), 16) / 65535;
  if (value < 0.80) return "train";
  if (value < 0.90) return "val";
  return "test";
}

async function processDataset(inputFile, outPrefix, vocab) {
  console.log(`\n>>> Processing ${inputFile} -> ${outPrefix}...`);
  const outDir = path.dirname(outPrefix);
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
    streams[`${s}_ids`] = fs.createWriteStream(`${outPrefix}_${s}_input_ids.bin`);
    streams[`${s}_mask`] = fs.createWriteStream(`${outPrefix}_${s}_attention_mask.bin`);
    streams[`${s}_labels`] = fs.createWriteStream(`${outPrefix}_${s}_labels.bin`);
  }

  let total = 0;
  let skipped = 0;
  const startTime = Date.now();

  await parseCsvFile(inputFile, (header, row) => {
    const parsed = parseDatasetRow(inputFile, header, row);
    if (parsed.label === -1 || !parsed.text || parsed.text.trim().length < 2) {
      skipped++;
      return;
    }

    const cleaned = maskSensitiveTokens(stripHtml(parsed.text));
    if (!cleaned.trim()) {
      skipped++;
      return;
    }

    const tokenized = wordPieceTokenize(cleaned, vocab, MAX_LENGTH);
    const split = getSplit(cleaned);

    counts[split]++;
    labelCounts[split][parsed.label]++;

    // Write binary buffers directly
    streams[`${split}_ids`].write(Buffer.from(tokenized.input_ids.buffer));
    streams[`${split}_mask`].write(Buffer.from(tokenized.attention_mask.buffer));

    const labelBuf = Buffer.alloc(4);
    labelBuf.writeInt32LE(parsed.label, 0);
    streams[`${split}_labels`].write(labelBuf);

    total++;
    if (total % 25000 === 0) {
      console.log(`  Processed ${total.toLocaleString()} rows...`);
    }
  });

  // Close all streams
  for (const key of Object.keys(streams)) {
    streams[key].end();
  }

  const durationSec = ((Date.now() - startTime) / 1000).toFixed(2);
  console.log(`[*] Completed in ${durationSec}s: ${total.toLocaleString()} valid, ${skipped.toLocaleString()} skipped.`);
  console.log(`    Train: ${counts.train.toLocaleString()} (Threats: ${labelCounts.train[1].toLocaleString()}, Safe: ${labelCounts.train[0].toLocaleString()})`);
  console.log(`    Val:   ${counts.val.toLocaleString()} (Threats: ${labelCounts.val[1].toLocaleString()}, Safe: ${labelCounts.val[0].toLocaleString()})`);
  console.log(`    Test:  ${counts.test.toLocaleString()} (Threats: ${labelCounts.test[1].toLocaleString()}, Safe: ${labelCounts.test[0].toLocaleString()})`);

  const meta = {
    inputFile,
    outPrefix,
    seqLength: MAX_LENGTH,
    totalValid: total,
    totalSkipped: skipped,
    counts,
    labelCounts,
    timestamp: new Date().toISOString()
  };

  fs.writeFileSync(`${outPrefix}_meta.json`, JSON.stringify(meta, null, 2), "utf-8");
}

async function main() {
  const vocabPath = path.resolve(__dirname, "../../extension/models/email-vocab.json");
  const vocabObj = JSON.parse(fs.readFileSync(vocabPath, "utf-8"));
  const vocab = vocabObj.vocab;

  const tasks = [
    { file: "raw/text1.csv", out: "data/processed/text/text1" },
    { file: "raw/text2.csv", out: "data/processed/text/text2" },
    { file: "raw/text3.csv", out: "data/processed/text/text3" },
    { file: "raw/text4.csv", out: "data/processed/text/text4" },
    { file: "raw/both url and txt.csv", out: "data/processed/text/both" }
  ];

  for (const t of tasks) {
    await processDataset(t.file, t.out, vocab);
  }

  console.log("\n=== All 5 Text Datasets Successfully Extracted and Tokenized! ===");
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});

