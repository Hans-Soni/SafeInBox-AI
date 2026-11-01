(function (root) {
  "use strict";

  const FEATURE_COUNT = 32;
  const CHAR_TENSOR_LENGTH = 128;
  const BRANDS = ["paypal", "google", "microsoft", "apple", "bankofamerica"];
  const CONFUSABLES = {
    "\u0430": "a", "\u0435": "e", "\u043e": "o", "\u0440": "p", "\u0441": "c",
    "\u0445": "x", "\u0443": "y", "\u0456": "i", "\u0458": "j", "\u04cf": "l",
    "\u03b1": "a", "\u03b5": "e", "\u03bf": "o", "\u03c1": "p", "\u03c7": "x",
    "\u03b9": "i", "\u03ba": "k", "\u03bd": "v", "\u03c4": "t", "\u03bc": "m"
  };
  const HOMOGLYPHS = [
    "\u0430", "\u0435", "\u043e", "\u0440", "\u0441", "\u0445", "\u0443", "\u0456", "\u0458", "\u04cf",
    "\u03b1", "\u03b5", "\u03bf", "\u03c1", "\u03c7", "\u03b9", "\u03ba", "\u03bd", "\u03c4", "\u03bc",
    "\u0131", "\u017f", "\u2113", "\u212a", "\u212f", "\u217c", "\u25cf", "\u2024", "\u3002"
  ];
  const CHAR_VOCABULARY = Array.from(
    new Set([...Array.from({ length: 95 }, (_, index) => String.fromCharCode(index + 32)), ...HOMOGLYPHS])
  );
  const CHAR_IDS = new Map(CHAR_VOCABULARY.map((character, index) => [character, index + 2]));
  const SUSPICIOUS_TLDS = new Set([
    "zip", "mov", "top", "xyz", "click", "work", "tk", "ml", "ga", "cf", "gq", "buzz",
    "fit", "rest", "country", "stream", "racing", "download", "club"
  ]);
  const REDIRECT_KEYS = new Set([
    "next", "url", "redirect", "redirect_uri", "return", "returnto", "return_url",
    "continue", "dest", "destination", "target", "goto", "callback"
  ]);
  const SIGNAL_WEIGHTS = {
    homograph: 0.62,
    typo: 0.54,
    punycode: 0.22,
    mixedScripts: 0.34,
    dga: 0.4,
    suspiciousTld: 0.12,
    openRedirect: 0.24,
    internalIp: 0.68,
    pathTraversal: 0.45,
    xss: 0.55,
    sqli: 0.52,
    lfi: 0.45,
    doubleEncoding: 0.35,
    credentials: 0.55
  };
  const KEYBOARD_ROWS = ["qwertyuiop", "asdfghjkl", "zxcvbnm"];
  const INTERNAL_IP_PATTERN =
    /^(?:0\.0\.0\.0|127(?:\.\d{1,3}){3}|10(?:\.\d{1,3}){3}|192\.168(?:\.\d{1,3}){2}|169\.254(?:\.\d{1,3}){2}|172\.(?:1[6-9]|2\d|3[01])(?:\.\d{1,3}){2})$/;

  function decodePunycodeLabel(label) {
    const marker = label.lastIndexOf("-");
    const output = marker >= 0 ? Array.from(label.slice(4, marker)) : [];
    let n = 128;
    let i = 0;
    let bias = 72;
    let index = marker >= 0 ? marker + 1 : 4;

    while (index < label.length) {
      const oldI = i;
      let weight = 1;
      for (let k = 36; ; k += 36) {
        if (index >= label.length) return label;
        const code = label.charCodeAt(index++);
        const digit = code >= 48 && code <= 57 ? code - 22 : code >= 65 && code <= 90 ? code - 65 : code - 97;
        if (digit < 0 || digit >= 36) return label;
        i += digit * weight;
        const threshold = k <= bias ? 1 : k >= bias + 26 ? 26 : k - bias;
        if (digit < threshold) break;
        weight *= 36 - threshold;
      }

      const outputLength = output.length + 1;
      bias = adaptBias(i - oldI, outputLength, oldI === 0);
      n += Math.floor(i / outputLength);
      i %= outputLength;
      output.splice(i, 0, String.fromCodePoint(n));
      i++;
    }
    return output.join("");
  }

  function adaptBias(delta, pointCount, firstTime) {
    delta = firstTime ? Math.floor(delta / 700) : Math.floor(delta / 2);
    delta += Math.floor(delta / pointCount);
    let k = 0;
    while (delta > 455) {
      delta = Math.floor(delta / 35);
      k += 36;
    }
    return k + Math.floor((36 * delta) / (delta + 38));
  }

  function toUnicodeDomain(hostname) {
    return hostname.split(".").map((label) =>
      label.toLowerCase().startsWith("xn--") ? decodePunycodeLabel(label.toLowerCase()) : label
    ).join(".");
  }

  function getRawHostname(input) {
    const authority = input.trim().replace(/^[a-z][a-z0-9+.-]*:\/\//i, "").split(/[/?#]/, 1)[0];
    const host = authority.slice(authority.lastIndexOf("@") + 1);
    if (host.startsWith("[")) return host.slice(1, host.indexOf("]"));
    return host.replace(/:\d+$/, "");
  }

  function getScripts(value) {
    const scripts = new Set();
    for (const character of value) {
      if (/\p{Script=Latin}/u.test(character)) scripts.add("Latin");
      else if (/\p{Script=Cyrillic}/u.test(character)) scripts.add("Cyrillic");
      else if (/\p{Script=Greek}/u.test(character)) scripts.add("Greek");
      else if (/\p{Script=Han}/u.test(character)) scripts.add("Han");
      else if (/\p{Script=Hiragana}|\p{Script=Katakana}/u.test(character)) scripts.add("Japanese");
      else if (/\p{Script=Arabic}/u.test(character)) scripts.add("Arabic");
    }
    return scripts;
  }

  function skeleton(value) {
    return Array.from(value.toLowerCase(), (character) => CONFUSABLES[character] || character)
      .join("")
      .replace(/[^a-z0-9]/g, "");
  }

  function levenshtein(left, right) {
    const row = Array.from({ length: right.length + 1 }, (_, index) => index);
    for (let i = 1; i <= left.length; i++) {
      let diagonal = row[0];
      row[0] = i;
      for (let j = 1; j <= right.length; j++) {
        const above = row[j];
        row[j] = Math.min(row[j] + 1, row[j - 1] + 1, diagonal + (left[i - 1] === right[j - 1] ? 0 : 1));
        diagonal = above;
      }
    }
    return row[right.length];
  }

  function keyboardProximitySwaps(value, candidates) {
    let highest = 0;
    for (const candidate of candidates) {
      if (value.length !== candidate.length) continue;
      let swaps = 0;
      for (let index = 0; index < value.length; index++) {
        if (value[index] === candidate[index]) continue;
        const leftPosition = keyboardPosition(value[index]);
        const rightPosition = keyboardPosition(candidate[index]);
        if (leftPosition && rightPosition &&
            Math.abs(leftPosition.row - rightPosition.row) <= 1 &&
            Math.abs(leftPosition.column - rightPosition.column) <= 1.1) swaps++;
      }
      highest = Math.max(highest, swaps);
    }
    return highest;
  }

  function keyboardPosition(character) {
    for (let row = 0; row < KEYBOARD_ROWS.length; row++) {
      const column = KEYBOARD_ROWS[row].indexOf(character);
      if (column !== -1) return { row, column: column + row * 0.45 };
    }
    return null;
  }

  function shannonEntropy(value) {
    if (!value) return 0;
    const counts = new Map();
    for (const character of value) counts.set(character, (counts.get(character) || 0) + 1);
    let entropy = 0;
    for (const count of counts.values()) {
      const probability = count / value.length;
      entropy -= probability * Math.log2(probability);
    }
    return entropy;
  }

  function ipv4Number(hostname) {
    try {
      const canonical = new URL(`http://${hostname}`).hostname;
      if (!/^\d{1,3}(?:\.\d{1,3}){3}$/.test(canonical)) return null;
      return canonical;
    } catch {
      return null;
    }
  }

  function isInternalHost(hostname, canonicalIpv4) {
    const host = hostname.toLowerCase().replace(/^\[|\]$/g, "");
    if (host === "localhost" || host.endsWith(".localhost") || host.endsWith(".local") ||
        host.endsWith(".internal") || host.endsWith(".lan") || host === "home.arpa") {
      return true;
    }
    if (canonicalIpv4 && INTERNAL_IP_PATTERN.test(canonicalIpv4)) return true;
    const mappedIpv4 = host.match(/(?:^|:)ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/);
    if (mappedIpv4) {
      const high = Number.parseInt(mappedIpv4[1], 16);
      const low = Number.parseInt(mappedIpv4[2], 16);
      const mappedAddress = `${high >>> 8}.${high & 255}.${low >>> 8}.${low & 255}`;
      if (INTERNAL_IP_PATTERN.test(mappedAddress)) return true;
    }
    return host === "::" || host === "::1" || host.startsWith("fe80:") || /^f[cd][0-9a-f]{2}:/i.test(host);
  }

  function decodeForInspection(value) {
    let decoded = value;
    let doubleEncoded = false;
    for (let depth = 0; depth < 3; depth++) {
      if (!/%(?:25)?[0-9a-f]{2}/i.test(decoded)) break;
      try {
        const next = decodeURIComponent(decoded);
        if (next === decoded) break;
        if (depth > 0) doubleEncoded = true;
        decoded = next;
      } catch {
        break;
      }
    }
    return { decoded, doubleEncoded };
  }

  function buildCharacterTensor(value) {
    const tensor = new Int32Array(CHAR_TENSOR_LENGTH);
    const characters = Array.from(value).slice(0, 2048);
    const stride = Math.max(1, Math.ceil(characters.length / CHAR_TENSOR_LENGTH));
    for (let index = 0; index < CHAR_TENSOR_LENGTH; index++) {
      const character = characters[index * stride];
      if (!character) break;
      tensor[index] = CHAR_IDS.get(character) || CHAR_IDS.get(character.toLowerCase()) || 1;
    }
    return tensor;
  }

  function buildFeatureVector(metrics) {
    const vector = new Float32Array(FEATURE_COUNT);
    const values = [
      metrics.isIp ? 1 : 0, metrics.isInternal ? 1 : 0, metrics.hasPunycode ? 1 : 0,
      metrics.mixedScripts ? 1 : 0, metrics.brandDistance / 10, metrics.brandSimilarity,
      Math.min(metrics.entropy / 5, 1), Math.min(metrics.vowelConsonantRatio / 5, 1), metrics.digitRatio, Math.min(metrics.keyboardSwaps / 5, 1),
      metrics.suspiciousTld ? 1 : 0, metrics.redirectParameter ? 1 : 0,
      metrics.externalRedirect ? 1 : 0, metrics.pathTraversal ? 1 : 0, metrics.xss ? 1 : 0,
      metrics.sqli ? 1 : 0, metrics.lfi ? 1 : 0, metrics.doubleEncoded ? 1 : 0,
      metrics.hasCredentials ? 1 : 0, metrics.suspiciousPort ? 1 : 0,
      Math.min(metrics.subdomainCount / 8, 1), Math.min(metrics.urlLength / 2048, 1),
      metrics.hasAtSign ? 1 : 0, metrics.isHttps ? 1 : 0, metrics.isIpv6 ? 1 : 0,
      metrics.isLocalhost ? 1 : 0, metrics.hasUnicode ? 1 : 0,
      metrics.highEntropy ? 1 : 0, metrics.executablePath ? 1 : 0,
      metrics.punycodeLabels / 4, Math.min(metrics.pathDepth / 16, 1),
      Math.min(metrics.queryCount / 32, 1)
    ];
    vector.set(values);
    return vector;
  }

  function analyzeUrl(input) {
    if (typeof input !== "string" || !input.trim()) throw new TypeError("Enter a URL to analyze.");
    const rawInput = input.trim();
    const candidate = /^[a-z][a-z0-9+.-]*:/i.test(rawInput) ? rawInput : `https://${rawInput}`;
    let url;
    try {
      url = new URL(candidate);
    } catch {
      throw new TypeError("The URL could not be parsed.");
    }
    if (url.protocol !== "http:" && url.protocol !== "https:") {
      throw new TypeError("Only HTTP and HTTPS URLs can be analyzed.");
    }

    const asciiHostname = url.hostname.toLowerCase();
    const rawHostname = getRawHostname(candidate);
    const unicodeHostname = toUnicodeDomain(asciiHostname);
    const hostnameForScriptCheck = rawHostname && /[^\x00-\x7f]/.test(rawHostname) ? rawHostname : unicodeHostname;
    const scripts = getScripts(hostnameForScriptCheck);
    const mixedScripts = scripts.size > 1;
    const labels = asciiHostname.split(".");
    const mainDomain = labels.length > 1 ? labels[labels.length - 2] : labels[0];
    const normalizedDomain = skeleton(toUnicodeDomain(mainDomain));
    const hasPunycode = labels.some((label) => label.startsWith("xn--"));
    const punycodeLabels = labels.filter((label) => label.startsWith("xn--")).length;
    const hasUnicode = /[^\x00-\x7f]/.test(rawHostname);
    const isIp = Boolean(ipv4Number(asciiHostname)) || asciiHostname.includes(":");
    const canonicalIpv4 = ipv4Number(asciiHostname);
    const isInternal = isInternalHost(asciiHostname, canonicalIpv4);
    const brandLabels = labels.slice(0, -1).flatMap((label) =>
      toUnicodeDomain(label).split(/[-_]/).map(skeleton).filter(Boolean)
    );
    if (!brandLabels.includes(normalizedDomain)) brandLabels.push(normalizedDomain);
    const matchedBrand = BRANDS.map((brand) => {
      const closestLabel = brandLabels
        .map((label) => ({ label, distance: levenshtein(label, brand) }))
        .sort((left, right) => left.distance - right.distance)[0];
      return { brand, ...closestLabel };
    })
      .sort((left, right) => left.distance - right.distance)[0];
    const exactBrandDomain = BRANDS.some((brand) =>
      asciiHostname === `${brand}.com` || asciiHostname.endsWith(`.${brand}.com`)
    );
    const brandDistance = matchedBrand.distance;
    const brandSimilarity = Math.max(0, 1 - brandDistance / Math.max(normalizedDomain.length, matchedBrand.brand.length, 1));
    const brandTypo = !exactBrandDomain &&
      !(hasPunycode && brandDistance === 0) &&
      matchedBrand.label.length > 2 &&
      brandDistance <= 2 &&
      brandSimilarity >= 0.65;
    const homograph = mixedScripts || (hasPunycode && (brandDistance <= 2 || scripts.size > 1));
    const entropy = shannonEntropy(mainDomain);
    const letters = mainDomain.match(/[a-z]/gi) || [];
    const vowels = mainDomain.match(/[aeiou]/gi) || [];
    const digits = mainDomain.match(/\d/g) || [];
    const digitRatio = digits.length / Math.max(letters.length + digits.length, 1);
    const consonants = Math.max(letters.length - vowels.length, 0);
    const vowelConsonantRatio = vowels.length / Math.max(consonants, 1);
    const keyboardSwaps = keyboardProximitySwaps(matchedBrand.label, BRANDS);
    const tld = labels[labels.length - 1];
    const decoded = decodeForInspection(`${rawInput} ${url.pathname}${url.search}${url.hash}`);
    const decodedLower = decoded.decoded.toLowerCase();
    const queryNames = Array.from(url.searchParams.keys()).map((key) => key.toLowerCase());
    const redirectParameter = queryNames.some((key) => REDIRECT_KEYS.has(key));
    const redirectValues = queryNames.filter((key) => REDIRECT_KEYS.has(key)).flatMap((key) => url.searchParams.getAll(key));
    const externalRedirect = redirectValues.some((value) => {
      try {
        const target = new URL(value, url.origin);
        return target.hostname.toLowerCase() !== asciiHostname;
      } catch {
        return false;
      }
    });
    const pathTraversal = /(?:\.\.\/|\.\.\\|%2e%2e(?:%2f|\/|%5c|\\))/i.test(`${url.pathname}${decoded.decoded}`);
    const xss = /<\s*script|javascript\s*:|on(?:error|load)\s*=|<\s*svg|<\s*img/i.test(decodedLower);
    const sqli = /(?:union\s+(?:all\s+)?select|select\s+[^;]{1,256}?\s+from|(?:'|%27)\s*(?:or|and)\s+['"\d]|;\s*(?:drop|delete|update|insert)\s)/i.test(decodedLower);
    const lfi = /(?:\/etc\/passwd|\/proc\/self|php:\/\/|file:\/\/|(?:\.\.\/){2,})/i.test(decodedLower);
    const hasCredentials = Boolean(url.username || url.password);
    const isIpv6 = asciiHostname.includes(":");
    const isLocalhost = /(?:^|\.)localhost$|\.local$|\.internal$/i.test(asciiHostname);
    const highEntropy = entropy >= 3.5 && mainDomain.length >= 12;
    const dga = highEntropy && (digitRatio >= 0.2 || vowelConsonantRatio < 0.12 || vowelConsonantRatio > 1.5);
    const metrics = {
      isIp, isInternal, hasPunycode, mixedScripts, brandDistance, brandSimilarity, entropy,
      vowelConsonantRatio, digitRatio, keyboardSwaps, suspiciousTld: SUSPICIOUS_TLDS.has(tld),
      redirectParameter, externalRedirect, pathTraversal, xss, sqli, lfi,
      doubleEncoded: decoded.doubleEncoded, hasCredentials,
      suspiciousPort: Boolean(url.port && !["80", "443"].includes(url.port)),
      subdomainCount: Math.max(labels.length - 2, 0), urlLength: rawInput.length, hasAtSign: rawInput.includes("@"),
      isHttps: url.protocol === "https:", isIpv6, isLocalhost, hasUnicode, highEntropy,
      executablePath: /\.(?:exe|msi|apk|dmg|scr|bat|cmd)(?:$|[?#])/i.test(url.pathname),
      punycodeLabels, pathDepth: url.pathname.split("/").filter(Boolean).length,
      queryCount: Array.from(url.searchParams.keys()).length
    };

    const findings = [];
    function addFinding(signal, attackType, title, detail) {
      findings.push({
        signal,
        attackType,
        title,
        detail,
        penalty: SIGNAL_WEIGHTS[signal] || 0.1
      });
    }
    if (homograph) addFinding("homograph", "HOMOGRAPH_ATTACK", "Possible IDN / homograph spoof", `Hostname uses mixed writing systems or a punycode label (${unicodeHostname}).`);
    if (brandTypo) addFinding("typo", "TYPOSQUATTING", "Brand-like domain spelling", `The hostname label '${matchedBrand.label}' resembles ${matchedBrand.brand} (${brandDistance} edit${brandDistance === 1 ? "" : "s"} away).`);
    if (dga) addFinding("dga", "DGA_SUSPECT", "High-entropy domain label", `The main domain label has high character entropy (${entropy.toFixed(2)} bits) and an unusual letter/digit pattern.`);
    if (metrics.suspiciousTld) addFinding("suspiciousTld", "PHISHING_SUSPECT", "Uncommon high-risk TLD", `The .${tld} suffix is frequently abused; this signal alone does not establish maliciousness.`);
    if (redirectParameter) addFinding("openRedirect", "OPEN_REDIRECT", `Redirect parameter: ${queryNames.find((key) => REDIRECT_KEYS.has(key))}`, externalRedirect ? "The redirect parameter points to a different host. This URL is not fetched." : "A redirect-style parameter is present; its destination should be reviewed.");
    if (isInternal) addFinding("internalIp", "INTERNAL_IP_TARGET", "Local or private network destination", `The destination resolves syntactically to a local/internal host (${asciiHostname}); no connection was made.`);
    if (pathTraversal) addFinding("pathTraversal", "INJECTION_PAYLOAD", "Path traversal pattern", "The path contains encoded or literal parent-directory traversal markers.");
    if (xss) addFinding("xss", "INJECTION_PAYLOAD", "Script / HTML injection marker", "The URL contains encoded or literal script/HTML event-handler markers.");
    if (sqli) addFinding("sqli", "INJECTION_PAYLOAD", "SQL injection marker", "The URL contains a recognizable SQL query or control statement pattern.");
    if (lfi) addFinding("lfi", "INJECTION_PAYLOAD", "File inclusion / local file marker", "The URL contains local-file or stream-wrapper path markers.");
    if (decoded.doubleEncoded) addFinding("doubleEncoding", "INJECTION_PAYLOAD", "Repeated URL encoding", "The URL contains percent-encoding that required multiple decoding passes for inspection.");
    if (hasCredentials) addFinding("credentials", "PHISHING_SUSPECT", "Embedded URL credentials", "The authority section contains a username or password.");

    const combinedRisk = findings.reduce((remaining, finding) => remaining * (1 - finding.penalty), 1);
    const heuristicRisk = 1 - combinedRisk;
    if (heuristicRisk >= 0.35 && !findings.some((finding) => finding.attackType === "PHISHING_SUSPECT")) {
      findings.push({
        signal: "aggregate",
        attackType: "PHISHING_SUSPECT",
        title: "Multiple suspicious URL indicators",
        detail: "Several URL characteristics combined to produce an elevated heuristic score.",
        penalty: 0
      });
    }

    return {
      inputUrl: rawInput,
      canonicalUrl: url.href,
      hostname: asciiHostname,
      unicodeHostname,
      mainDomain,
      matchedBrand: brandDistance <= 2 ? matchedBrand.brand : null,
      metrics,
      findings,
      attackTypes: Array.from(new Set(findings.map((finding) => finding.attackType))),
      heuristicRisk,
      featureVector: buildFeatureVector(metrics),
      charTensor: buildCharacterTensor(rawInput)
    };
  }

  const api = {
    FEATURE_COUNT,
    CHAR_TENSOR_LENGTH,
    CHAR_VOCAB_SIZE: CHAR_VOCABULARY.length + 2,
    analyzeUrl,
    buildFeatureVector,
    buildCharacterTensor,
    shannonEntropy,
    levenshtein
  };
  root.UrlThreatParser = api;
  if (typeof module !== "undefined" && module.exports) module.exports = api;
})(typeof globalThis !== "undefined" ? globalThis : self);
