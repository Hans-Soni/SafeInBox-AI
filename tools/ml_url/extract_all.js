const { execSync } = require("child_process");

const files = [
  { file: "raw/URL1.csv", out: "data/processed/url/URL1" },
  { file: "raw/URL2.csv", out: "data/processed/url/URL2" },
  { file: "raw/URL3.csv", out: "data/processed/url/URL3" },
  { file: "raw/URL4.csv", out: "data/processed/url/URL4" }
];

console.log("=== Starting Parallel/Sequential Feature Extraction for URL Corpora ===");
for (const item of files) {
  console.log(`\n>>> Processing ${item.file} -> ${item.out}...`);
  execSync(`node tools/ml_url/extract_features.js --file "${item.file}" --out "${item.out}"`, {
    stdio: "inherit"
  });
}
console.log("\n=== All 4 URL Corpora Successfully Extracted with Normalized Character Representations! ===");

