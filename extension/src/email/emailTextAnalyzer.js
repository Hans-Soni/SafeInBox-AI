(function (root) {
  "use strict";

  const parser = root.EmailTextParser ||
    (typeof require === "function" ? require("../utils/textParser.js") : null);
  if (!parser) throw new Error("The shared email text parser must load before the email analyzer.");

  function analyzeEmailText(input) {
    const result = parser.analyzeEmailText(input);
    const { normalized_text, body_text, ...publicResult } = result;
    return publicResult;
  }

  const api = { analyzeEmailText };
  root.EmailTextAnalyzer = api;
  if (typeof module !== "undefined" && module.exports) module.exports = api;
})(typeof globalThis !== "undefined" ? globalThis : self);
