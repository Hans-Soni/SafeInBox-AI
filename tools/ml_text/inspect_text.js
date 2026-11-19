"use strict";

const fs = require("node:fs");

function countCsvRecords(filePath, labelGetter) {
  return new Promise((resolve) => {
    const stream = fs.createReadStream(filePath, { encoding: "utf-8" });
    let inQuotes = false;
    let currentField = "";
    let currentRow = [];
    let header = null;
    let total = 0;
    const counts = { 0: 0, 1: 0, unknown: 0 };
    let sample0 = null;
    let sample1 = null;

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
              total++;
              const parsed = labelGetter(header, currentRow);
              if (parsed.label === 0 || parsed.label === 1) {
                counts[parsed.label]++;
                if (parsed.label === 0 && !sample0) sample0 = parsed.text.slice(0, 80);
                if (parsed.label === 1 && !sample1) sample1 = parsed.text.slice(0, 80);
              } else {
                counts.unknown++;
              }
            }
          }
          currentRow = [];
        } else {
          currentField += c;
        }
      }
    });

    stream.on("end", () => {
      resolve({ file: filePath, total, counts, sample0, sample1 });
    });
  });
}

function parseText1(header, row) {
  // deceptive,hotel,polarity,source,text
  const d = (row[0] || "").trim().toLowerCase();
  const text = (row[4] || "").trim();
  let label = -1;
  if (d === "truthful") label = 0;
  if (d === "deceptive") label = 1;
  return { label, text };
}

function parseText2(header, row) {
  // v1,v2
  const v = (row[0] || "").trim().toLowerCase();
  const text = (row[1] || "").trim();
  let label = -1;
  if (v === "ham") label = 0;
  if (v === "spam") label = 1;
  return { label, text };
}

function parseText3(header, row) {
  // ,label,text,label_num
  const text = (row[2] || "").trim();
  const lblNum = (row[3] || "").trim();
  const l = (row[1] || "").trim().toLowerCase();
  let label = -1;
  if (lblNum === "0" || l === "ham") label = 0;
  if (lblNum === "1" || l === "spam") label = 1;
  return { label, text };
}

function parseText4(header, row) {
  // label,raw_label,text
  const l = (row[0] || "").trim();
  const text = (row[2] || "").trim();
  let label = -1;
  if (l === "0") label = 0;
  if (l === "1") label = 1;
  return { label, text };
}

function parseBoth(header, row) {
  // label,text
  const l = (row[0] || "").trim();
  const text = (row[1] || "").trim();
  let label = -1;
  if (l === "0") label = 0;
  if (l === "1") label = 1;
  return { label, text };
}

async function main() {
  console.log("Analyzing Raw Text Datasets...");
  console.log(await countCsvRecords("raw/text1.csv", parseText1));
  console.log(await countCsvRecords("raw/text2.csv", parseText2));
  console.log(await countCsvRecords("raw/text3.csv", parseText3));
  console.log(await countCsvRecords("raw/text4.csv", parseText4));
  console.log(await countCsvRecords("raw/both url and txt.csv", parseBoth));
}

main();

