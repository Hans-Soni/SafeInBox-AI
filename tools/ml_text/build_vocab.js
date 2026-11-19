"use strict";

const fs = require("node:fs");
const path = require("node:path");
const { stripHtml, maskSensitiveTokens } = require("../../extension/src/utils/textParser.js");

const TOKEN_RE = /\[URL\]|\[IP\]|\[MONEY\]|[a-z]+(?:'[a-z]+)?|\d+|[^\s]/gi;
const VOCAB_SIZE = 16384;
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

function extractTextFromRow(file, header, row) {
  if (file.includes("text1.csv")) {
    return row[4] || "";
  }
  if (file.includes("text2.csv")) {
    return row[1] || "";
  }
  if (file.includes("text3.csv")) {
    return row[2] || "";
  }
  if (file.includes("text4.csv")) {
    return row[2] || "";
  }
  if (file.includes("both url and txt.csv")) {
    return row[1] || "";
  }
  return row[row.length - 1] || "";
}

async function buildVocabulary() {
  console.log("=== Building WordPiece Vocabulary for Email Text Model ===");
  const files = [
    "raw/text1.csv",
    "raw/text2.csv",
    "raw/text3.csv",
    "raw/text4.csv",
    "raw/both url and txt.csv"
  ];

  const wordCounts = new Map();
  let rowCount = 0;

  for (const file of files) {
    console.log(`Processing vocabulary from ${file}...`);
    await parseCsvFile(file, (header, row) => {
      const rawText = extractTextFromRow(file, header, row);
      if (!rawText) return;
      rowCount++;
      const cleaned = maskSensitiveTokens(stripHtml(rawText));
      const tokens = cleaned.match(TOKEN_RE) || [];
      for (const t of tokens) {
        const token = t.startsWith("[") ? t.toUpperCase() : t.toLowerCase();
        wordCounts.set(token, (wordCounts.get(token) || 0) + 1);
      }
    });
  }

  console.log(`Total rows processed: ${rowCount.toLocaleString()}`);
  console.log(`Unique raw tokens observed: ${wordCounts.size.toLocaleString()}`);

  // Sort by frequency
  const sorted = Array.from(wordCounts.entries()).sort((a, b) => b[1] - a[1]);

  const specialTokens = [
    "[PAD]",
    "[UNK]",
    "[CLS]",
    "[SEP]",
    "[URL]",
    "[IP]",
    "[MONEY]"
  ];

  const vocab = {};
  specialTokens.forEach((tok, idx) => {
    vocab[tok] = idx;
  });

  let currentId = specialTokens.length;
  for (const [word, count] of sorted) {
    if (vocab[word] !== undefined) continue;
    if (word.length > 32) continue; // Skip random binary garbage
    if (count < 2 && currentId >= VOCAB_SIZE / 2) continue; // Filter noise
    vocab[word] = currentId++;
    if (currentId >= VOCAB_SIZE) break;
  }

  console.log(`Final vocabulary size: ${Object.keys(vocab).length} tokens`);

  const outputObj = {
    vocab,
    max_length: MAX_LENGTH,
    output_type: "logits",
    version: "1.0.0",
    description: "WordPiece token vocabulary for SafeInbox AI local text classification"
  };

  const vocabPath = path.resolve(__dirname, "../../extension/models/email-vocab.json");
  fs.mkdirSync(path.dirname(vocabPath), { recursive: true });
  fs.writeFileSync(vocabPath, JSON.stringify(outputObj, null, 2), "utf-8");
  console.log(`[*] Saved vocabulary to ${vocabPath} (${(fs.statSync(vocabPath).size / 1024).toFixed(1)} KB)`);
}

buildVocabulary().catch((err) => {
  console.error(err);
  process.exit(1);
});
