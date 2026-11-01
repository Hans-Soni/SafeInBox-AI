(function (root) {
  "use strict";

  const BRANDS = [
    { name: "PayPal", domains: ["paypal.com", "paypal.me"], terms: ["paypal", "pay pal"] },
    { name: "Netflix", domains: ["netflix.com"], terms: ["netflix"] },
    { name: "Microsoft", domains: ["microsoft.com", "office.com", "live.com", "outlook.com"], terms: ["microsoft", "office 365", "office365", "outlook"] },
    { name: "Apple", domains: ["apple.com", "icloud.com"], terms: ["apple", "icloud", "apple id"] },
    { name: "Google", domains: ["google.com", "gmail.com"], terms: ["google", "gmail"] },
    { name: "Amazon", domains: ["amazon.com", "amazon.co.uk"], terms: ["amazon", "prime"] },
    { name: "Chase", domains: ["chase.com"], terms: ["chase bank", "chase"] },
    { name: "DHL", domains: ["dhl.com"], terms: ["dhl"] },
    { name: "FedEx", domains: ["fedex.com"], terms: ["fedex"] }
  ];
  const FREE_MAIL_DOMAINS = new Set([
    "gmail.com", "googlemail.com", "yahoo.com", "yahoo.co.uk", "hotmail.com",
    "outlook.com", "live.com", "aol.com", "icloud.com", "proton.me", "protonmail.com"
  ]);
  const URGENCY_RE = /\b(?:urgent(?:ly)?|immediate(?:ly)?|action required|within\s+\d+\s+hours?|account (?:is )?(?:suspended|locked|terminated)|final warning|expires? today)\b/gi;
  const FINANCIAL_RE = /\b(?:unclaimed refund|refund pending|payment overdue|invoice(?:\s+#?\w+)?|wire transfer|gift card|prize(?: money)?|you(?:'|’)ve won|claim your reward|tax refund)\b/gi;
  const CREDENTIAL_RE = /\b(?:password|passcode|pin|one[- ]time code|2fa|multi[- ]factor|verification code|security code|login credentials|sign[ -]?in details)\b/gi;
  const COERCION_RE = /\b(?:legal action|police report|law enforcement|account termination|permanently deleted|arrest warrant|immediately or else|avoid prosecution)\b/gi;
  const EMAIL_RE = /[\w.+-]+@(?:[\w-]+\.)+[a-z]{2,63}/i;
  const TOKEN_RE = /\[URL\]|\[IP\]|\[MONEY\]|[a-z]+(?:'[a-z]+)?|\d+|[^\s]/gi;
  const DEFAULT_MAX_TOKENS = 512;

  function decodeEntities(text) {
    const named = { amp: "&", lt: "<", gt: ">", quot: "\"", apos: "'", nbsp: " ", rsquo: "'", lsquo: "'", rdquo: "\"", ldquo: "\"" };
    return text.replace(/&(#x[\da-f]+|#\d+|[a-z]+);/gi, (entity, value) => {
      if (value[0] === "#") {
        const hex = value[1].toLowerCase() === "x";
        const code = Number.parseInt(value.slice(hex ? 2 : 1), hex ? 16 : 10);
        return Number.isFinite(code) && code > 0 && code <= 0x10ffff ? String.fromCodePoint(code) : entity;
      }
      return named[value.toLowerCase()] || entity;
    });
  }

  function stripHtml(value) {
    return decodeEntities(String(value || "")
      .replace(/<(script|style|head|title|svg|noscript)\b[^>]*>[\s\S]*?<\/\1\s*>/gi, " ")
      .replace(/<(?:br|hr)\b[^>]*\/?>/gi, "\n")
      .replace(/<\/(?:p|div|li|tr|table|h[1-6]|blockquote|section|article)\s*>/gi, "\n")
      .replace(/<[^>]*>/g, " "))
      .replace(/\u00a0/g, " ")
      .replace(/[ \t\f\v]+/g, " ")
      .replace(/ *\n */g, "\n")
      .replace(/\n{3,}/g, "\n\n")
      .trim();
  }

  function maskSensitiveTokens(text) {
    return String(text || "")
      .replace(/\b(?:https?:\/\/|www\.)[^\s<>"']*[^\s<>"'.,;!?)]/gi, "[URL]")
      .replace(/(^|[^a-z0-9_@.-])((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,63}|xn--[a-z0-9-]{2,59})(?:\/[^\s<>"']*)?)/gi, "$1[URL]")
      .replace(/\b(?:\d{1,3}\.){3}\d{1,3}\b|\b[0-9a-f]{0,4}:[0-9a-f:]{2,}\b/gi, "[IP]")
      .replace(/(?:[$€£]\s?\d[\d,]*(?:\.\d{1,2})?|\b\d[\d,]*(?:\.\d{1,2})?\s?(?:USD|EUR|GBP)\b)/gi, "[MONEY]");
  }

  function parseAddresses(value) {
    return String(value || "").match(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,63}/gi) || [];
  }

  function parseHeader(text, header) {
    const match = String(text || "").match(new RegExp(`^${header}:\\s*([^\\r\\n]*)`, "im"));
    return match ? match[1].trim() : "";
  }

  function parseSender(value) {
    const emailMatch = String(value || "").match(EMAIL_RE);
    if (!emailMatch) return { displayName: String(value || "").trim(), email: "", domain: "" };
    const email = emailMatch[0].toLowerCase();
    return {
      displayName: String(value).replace(emailMatch[0], "").replace(/[<>"]/g, "").trim(),
      email,
      domain: email.slice(email.lastIndexOf("@") + 1)
    };
  }

  function countWords(text) {
    return String(text || "").match(/\b[\p{L}\p{N}]+\b/gu) || [];
  }

  function findMatches(pattern, value) {
    pattern.lastIndex = 0;
    return Array.from(String(value || "").matchAll(pattern), (match) => match[0]);
  }

  function makeFinding(ruleId, severity, evidence, remediation, threatVector) {
    return { rule_id: ruleId, severity, evidence, remediation, threat_vector: threatVector };
  }

  function analyzeEmailText(input = {}) {
    const startedAt = typeof performance !== "undefined" ? performance.now() : Date.now();
    const rawText = typeof input.text === "string" ? input.text : "";
    const senderValue = input.sender || parseHeader(rawText, "From");
    const receiverValue = input.receiver || parseHeader(rawText, "To");
    const ccValue = input.cc || parseHeader(rawText, "Cc");
    const bccValue = input.bcc || parseHeader(rawText, "Bcc");
    const subject = String(input.subject || parseHeader(rawText, "Subject")).trim();
    const sender = parseSender(senderValue);
    const senderLower = sender.displayName.toLowerCase();
    const rawVisibleBody = input.body !== undefined ? input.body : rawText;
    const isOverLimit = typeof rawVisibleBody === "string" && rawVisibleBody.length > 1000000;
    const visibleBody = isOverLimit ? rawVisibleBody.slice(0, 1000000) : rawVisibleBody;
    const bodyText = stripHtml(visibleBody);
    const normalizedBody = maskSensitiveTokens(bodyText);
    const normalizedSubject = maskSensitiveTokens(stripHtml(subject));
    const normalizedSender = maskSensitiveTokens(stripHtml(senderValue));
    const normalizedReceiver = maskSensitiveTokens(stripHtml(receiverValue));
    const normalizedCc = maskSensitiveTokens(stripHtml(ccValue));
    const findings = [];
    const vectors = new Set();
    let heuristicRisk = 0;
    let claimedBrand = null;
    const searchable = `${senderValue}\n${subject}\n${bodyText}`.toLowerCase();

    for (const brand of BRANDS) {
      if (brand.terms.some((term) => senderLower.includes(term))) {
        claimedBrand = brand;
        break;
      }
    }

    if (claimedBrand && sender.email) {
      const verified = claimedBrand.domains.some((domain) =>
        sender.domain === domain || sender.domain.endsWith(`.${domain}`)
      ) && !FREE_MAIL_DOMAINS.has(sender.domain);
      if (!verified) {
        vectors.add("SENDER_SPOOFING");
        findings.push(makeFinding(
          "RULE_EMAIL_SENDER_DOMAIN_MISMATCH",
          "CRITICAL",
          `Sender display name claims to represent ${claimedBrand.name}, but the sender address does not match an official domain.`,
          "Verify the sender using a trusted contact method; do not rely on the display name.",
          "SENDER_SPOOFING"
        ));
        heuristicRisk += FREE_MAIL_DOMAINS.has(sender.domain) ? 0.7 : 0.55;
      }
    }

    if (claimedBrand && sender.email && FREE_MAIL_DOMAINS.has(sender.domain)) {
      findings.push(makeFinding(
        "RULE_EMAIL_FREE_MAIL_IMPERSONATION",
        "CRITICAL",
        "A trusted-brand display-name claim uses a free consumer email provider.",
        "Confirm the sender through the organization's official website or a known contact.",
        "SENDER_SPOOFING"
      ));
      heuristicRisk = Math.max(heuristicRisk, 0.8);
      vectors.add("SENDER_SPOOFING");
    }

    const bccAddresses = parseAddresses(bccValue);
    const recipients = [...parseAddresses(receiverValue), ...parseAddresses(ccValue), ...bccAddresses];
    const recipientCount = new Set(recipients.map((address) => address.toLowerCase())).size;
    if (bccAddresses.length >= 5 || recipientCount >= 25) {
      vectors.add("BEHAVIORAL_MANIPULATION");
      findings.push(makeFinding(
        "RULE_EMAIL_BULK_RECIPIENTS",
        "MEDIUM",
        `Broad recipient distribution detected (${recipientCount} visible recipients, including ${bccAddresses.length} Bcc recipients).`,
        "Check whether this message was expected and whether the request is relevant to you.",
        "BEHAVIORAL_MANIPULATION"
      ));
      heuristicRisk += 0.2;
    }

    const subjectUrgency = findMatches(URGENCY_RE, subject);
    if (subjectUrgency.length) {
      vectors.add("ARTIFICIAL_URGENCY");
      findings.push(makeFinding(
        "RULE_EMAIL_SUBJECT_URGENCY",
        "HIGH",
        "Subject contains urgency or account-pressure language.",
        "Do not let deadlines override normal verification steps.",
        "ARTIFICIAL_URGENCY"
      ));
      heuristicRisk += 0.25;
    }

    const financeMatches = findMatches(FINANCIAL_RE, `${subject}\n${bodyText}`);
    if (financeMatches.length) {
      vectors.add("FINANCIAL_SCAM");
      findings.push(makeFinding(
        "RULE_EMAIL_FINANCIAL_HOOK",
        "MEDIUM",
        "Financial, invoice, refund, or reward language was detected.",
        "Independently verify invoices, refunds, and prizes with the organization involved.",
        "FINANCIAL_SCAM"
      ));
      heuristicRisk += 0.2;
    }

    const credentialMatches = findMatches(CREDENTIAL_RE, searchable);
    if (credentialMatches.length) {
      vectors.add("CREDENTIAL_HARVESTING");
      findings.push(makeFinding(
        "RULE_EMAIL_CREDENTIAL_REQUEST",
        "HIGH",
        "Message references sensitive credentials or authentication codes.",
        "Never share passwords, PINs, or one-time authentication codes in response to an email.",
        "CREDENTIAL_HARVESTING"
      ));
      heuristicRisk += 0.3;
    }

    const coercionMatches = findMatches(COERCION_RE, searchable);
    if (coercionMatches.length) {
      vectors.add("BEHAVIORAL_MANIPULATION");
      findings.push(makeFinding(
        "RULE_EMAIL_COERCIVE_LANGUAGE",
        "HIGH",
        "Threatening or coercive language was detected.",
        "Pause and verify the claim through a separate trusted channel.",
        "BEHAVIORAL_MANIPULATION"
      ));
      heuristicRisk += 0.25;
    }

    const normalizedText = [
      normalizedSubject && `subject: ${normalizedSubject}`,
      normalizedSender && `sender: ${normalizedSender}`,
      normalizedReceiver && `recipient: ${normalizedReceiver}`,
      normalizedCc && `cc: ${normalizedCc}`,
      normalizedBody && `body: ${normalizedBody}`
    ].filter(Boolean).join("\n");
    const riskScore = Math.min(1, heuristicRisk);
    const scorePercent = Math.round(riskScore * 100);
    const level = scorePercent >= 80 ? "CRITICAL" : scorePercent >= 60 ? "HIGH" : scorePercent >= 35 ? "MEDIUM" : "LOW";
    const urls = Array.from(rawText.matchAll(/(?:https?:\/\/|www\.)[^\s<>"']+/gi), (match) => match[0]);
    const elapsed = (typeof performance !== "undefined" ? performance.now() : Date.now()) - startedAt;

    return {
      target_type: "EMAIL",
      sender_name: sender.displayName,
      sender_email: sender.email,
      sender_domain: sender.domain,
      receiver: receiverValue,
      cc: ccValue,
      bcc_count: bccAddresses.length,
      recipient_count: recipientCount,
      subject,
      body_text: bodyText,
      normalized_text: normalizedText,
      token_count_estimate: countWords(normalizedText).length,
      truncated: isOverLimit || countWords(normalizedText).length > DEFAULT_MAX_TOKENS * 8,
      claimed_company: claimedBrand ? claimedBrand.name : null,
      company_intelligence: {
        claimed_brand: claimedBrand ? claimedBrand.name : null,
        status: findings.some((finding) => finding.threat_vector === "SENDER_SPOOFING")
          ? "IMPERSONATION_MISMATCH" : claimedBrand ? "VERIFIED_DOMAIN_MATCH" : "NONE_DETECTED",
        sender_domain: sender.domain,
        canonical_domains: claimedBrand ? claimedBrand.domains : []
      },
      extracted_urls_count: urls.length,
      urls_analyzed: [],
      risk_level: level,
      risk_score: scorePercent,
      riskScore,
      heuristicRisk: riskScore,
      threat_vectors: Array.from(vectors),
      summary: findings.length
        ? `Detected ${findings.length} email threat indicator${findings.length === 1 ? "" : "s"} using local checks.`
        : "No configured email threat indicators were detected by local checks.",
      recommended_action: scorePercent >= 50
        ? "Do not click links or share credentials. Verify the sender through a separate trusted channel."
        : "Treat this heuristic assessment as one signal, not a guarantee of safety.",
      evidence: findings,
      model_available: false,
      model_risk: null,
      analysis_note: "Heuristic-only result; no trained email text model is installed.",
      latency_ms: Math.round(elapsed)
    };
  }

  function getVocabularyIds(vocabulary, maxLength) {
    if (!vocabulary || typeof vocabulary !== "object") throw new TypeError("A model-compatible WordPiece vocabulary is required.");
    const entries = Object.entries(vocabulary);
    if (entries.some(([, id]) => !Number.isInteger(Number(id)) || Number(id) < 0)) {
      throw new TypeError("Every WordPiece vocabulary entry must map to a non-negative integer ID.");
    }
    const ids = new Map(entries.map(([token, id]) => [token, Number(id)]));
    const clsId = ids.get("[CLS]");
    const sepId = ids.get("[SEP]");
    const padId = ids.get("[PAD]");
    const unkId = ids.get("[UNK]");
    if (![clsId, sepId, padId, unkId].every(Number.isInteger)) {
      throw new TypeError("The vocabulary must define integer IDs for [CLS], [SEP], [PAD], and [UNK].");
    }
    if (!Number.isInteger(maxLength) || maxLength < 3 || maxLength > 4096) {
      throw new RangeError("Token sequence length must be between 3 and 4096.");
    }
    return { ids, clsId, sepId, padId, unkId, maxLength };
  }

  function encodeWordPiece(original, ids, unkId) {
    if (/^\[(?:URL|IP|MONEY)\]$/i.test(original) && ids.has(original.toUpperCase())) {
      return [ids.get(original.toUpperCase())];
    }
    const word = original.toLowerCase();
    let start = 0;
    const pieces = [];
    let failed = false;
    while (start < word.length) {
      let end = word.length;
      let pieceId = null;
      while (end > start) {
        const piece = `${start ? "##" : ""}${word.slice(start, end)}`;
        if (ids.has(piece)) {
          pieceId = ids.get(piece);
          break;
        }
        end -= 1;
      }
      if (pieceId === null) {
        failed = true;
        break;
      }
      pieces.push(pieceId);
      start = end;
    }
    return failed ? [unkId] : pieces;
  }

  function wordPieceTokenizeChunks(text, vocabulary, maxLength = DEFAULT_MAX_TOKENS, maxChunks = Infinity) {
    if (maxChunks !== Infinity && (!Number.isInteger(maxChunks) || maxChunks < 1)) {
      throw new RangeError("Chunk limit must be a positive integer.");
    }
    const config = getVocabularyIds(vocabulary, maxLength);
    const words = String(text || "").match(TOKEN_RE) || [];
    const chunks = [];
    let active = [];
    let truncated = false;
    for (const original of words) {
      const pieces = encodeWordPiece(original, config.ids, config.unkId);
      if (active.length && active.length + pieces.length > maxLength - 2) {
        chunks.push(active);
        active = [];
        if (chunks.length >= maxChunks) {
          truncated = true;
          break;
        }
      }
      active.push(...(pieces.length > maxLength - 2 ? [config.unkId] : pieces));
    }
    if (active.length || chunks.length === 0) {
      if (chunks.length < maxChunks) chunks.push(active);
      else truncated = true;
    }

    const result = chunks.map((chunk, chunkIndex) => {
      const tokenIds = [config.clsId, ...chunk, config.sepId];
      const inputIds = new Int32Array(config.maxLength);
      const attentionMask = new Int32Array(config.maxLength);
      inputIds.fill(config.padId);
      for (let index = 0; index < tokenIds.length; index += 1) {
        inputIds[index] = tokenIds[index];
        attentionMask[index] = 1;
      }
      return {
        input_ids: inputIds,
        attention_mask: attentionMask,
        token_count: tokenIds.length,
        max_length: config.maxLength,
        chunk_index: chunkIndex
      };
    });
    result.truncated = truncated;
    return result;
  }

  function wordPieceTokenize(text, vocabulary, maxLength = DEFAULT_MAX_TOKENS) {
    return wordPieceTokenizeChunks(text, vocabulary, maxLength)[0];
  }

  function splitIntoChunks(text, maxWords = DEFAULT_MAX_TOKENS) {
    if (!Number.isInteger(maxWords) || maxWords < 1) throw new RangeError("Chunk size must be a positive integer.");
    const words = String(text || "").split(/\s+/).filter(Boolean);
    const chunks = [];
    for (let offset = 0; offset < words.length; offset += maxWords) {
      chunks.push(words.slice(offset, offset + maxWords).join(" "));
    }
    return chunks;
  }

  const api = { analyzeEmailText, maskSensitiveTokens, splitIntoChunks, stripHtml, wordPieceTokenize, wordPieceTokenizeChunks };
  root.EmailTextParser = api;
  if (typeof module !== "undefined" && module.exports) module.exports = api;
})(typeof globalThis !== "undefined" ? globalThis : self);
