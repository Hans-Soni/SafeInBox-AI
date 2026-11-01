"""Server-side URL threat analysis engine."""

import ipaddress
import math
import re
from urllib.parse import parse_qs, unquote, urlparse

BRANDS = ["paypal", "google", "microsoft", "apple", "bankofamerica"]

CONFUSABLES = {
    "\u0430": "a", "\u0435": "e", "\u043e": "o", "\u0440": "p", "\u0441": "c",
    "\u0445": "x", "\u0443": "y", "\u0456": "i", "\u0458": "j", "\u04cf": "l",
    "\u03b1": "a", "\u03b5": "e", "\u03bf": "o", "\u03c1": "p", "\u03c7": "x",
    "\u03b9": "i", "\u03ba": "k", "\u03bd": "v", "\u03c4": "t", "\u03bc": "m"
}

SUSPICIOUS_TLDS = {
    "zip", "mov", "top", "xyz", "click", "work", "tk", "ml", "ga", "cf", "gq", "buzz",
    "fit", "rest", "country", "stream", "racing", "download", "club"
}

REDIRECT_KEYS = {
    "next", "url", "redirect", "redirect_uri", "return", "returnto", "return_url",
    "continue", "dest", "destination", "target", "goto", "callback"
}

SIGNAL_WEIGHTS = {
    "homograph": 0.62,
    "typo": 0.54,
    "punycode": 0.22,
    "mixedScripts": 0.34,
    "dga": 0.40,
    "suspiciousTld": 0.12,
    "openRedirect": 0.24,
    "internalIp": 0.68,
    "pathTraversal": 0.45,
    "xss": 0.55,
    "sqli": 0.52,
    "lfi": 0.45,
    "doubleEncoding": 0.35,
    "credentials": 0.55
}


def skeleton(value: str) -> str:
    """Normalize confusables to ASCII skeleton."""
    chars = [CONFUSABLES.get(c, c) for c in value.lower()]
    return re.sub(r"[^a-z0-9]", "", "".join(chars))


def levenshtein(left: str, right: str) -> int:
    """Calculate edit distance between two strings."""
    if len(left) < len(right):
        return levenshtein(right, left)
    if len(right) == 0:
        return len(left)

    previous_row = list(range(len(right) + 1))
    for i, c1 in enumerate(left):
        current_row = [i + 1]
        for j, c2 in enumerate(right):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]


def shannon_entropy(value: str) -> float:
    """Compute Shannon character entropy."""
    if not value:
        return 0.0
    counts: dict[str, int] = {}
    for char in value:
        counts[char] = counts.get(char, 0) + 1
    entropy = 0.0
    for count in counts.values():
        prob = count / len(value)
        entropy -= prob * math.log2(prob)
    return entropy


def is_internal_host(hostname: str) -> bool:
    """Detect local, internal, loopback, or private network hostnames and IPs."""
    host = hostname.strip("[]").lower()
    if (
        host == "localhost"
        or host.endswith(".localhost")
        or host.endswith(".local")
        or host.endswith(".internal")
        or host.endswith(".lan")
        or host == "home.arpa"
    ):
        return True

    # Try octal/hex IPv4 conversion
    try:
        # Handles numbers like 0177.0.0.1 or 0x7f000001
        ip_obj = ipaddress.ip_address(host)
        return ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_unspecified
    except ValueError:
        pass

    # Check IPv4-mapped IPv6 patterns
    mapped = re.search(r"(?:^|:)ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$", host, re.I)
    if mapped:
        high = int(mapped.group(1), 16)
        low = int(mapped.group(2), 16)
        mapped_ip = f"{high >> 8}.{high & 255}.{low >> 8}.{low & 255}"
        try:
            return ipaddress.ip_address(mapped_ip).is_private
        except ValueError:
            pass

    return False


def decode_for_inspection(text: str) -> tuple[str, bool]:
    """Inspect and decode multiple levels of percent encoding."""
    decoded = text
    double_encoded = False
    for depth in range(3):
        if not re.search(r"%(?:25)?[0-9a-f]{2}", decoded, re.I):
            break
        try:
            next_dec = unquote(decoded)
            if next_dec == decoded:
                break
            if depth > 0:
                double_encoded = True
            decoded = next_dec
        except Exception:
            break
    return decoded, double_encoded


def analyze_url(input_url: str) -> dict:
    """Analyze URL text for security threats without network requests."""
    if not isinstance(input_url, str) or not input_url.strip():
        raise ValueError("Enter a URL to analyze.")

    raw_input = input_url.strip()
    candidate = raw_input if re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*:", raw_input) else f"https://{raw_input}"

    try:
        parsed = urlparse(candidate)
    except Exception as exc:
        raise ValueError(f"The URL could not be parsed: {exc}")

    if parsed.scheme.lower() not in ("http", "https"):
        raise ValueError("Only HTTP and HTTPS URLs can be analyzed.")

    hostname = (parsed.hostname or "").lower()
    if not hostname:
        raise ValueError("The URL does not contain a valid hostname.")

    try:
        unicode_hostname = hostname.encode("idna").decode("utf-8")
    except Exception:
        unicode_hostname = hostname

    labels = hostname.split(".")
    main_domain = labels[-2] if len(labels) > 1 else labels[0]
    normalized_domain = skeleton(main_domain)

    has_punycode = any(label.startswith("xn--") for label in labels)
    has_unicode = any(ord(c) > 127 for c in hostname)
    is_internal = is_internal_host(hostname)

    # Brand typosquatting evaluation
    brand_labels = []
    for label in labels[:-1]:
        for part in re.split(r"[-_]", label):
            sk = skeleton(part)
            if sk:
                brand_labels.append(sk)
    if normalized_domain not in brand_labels:
        brand_labels.append(normalized_domain)

    matched_brand = None
    min_distance = 999
    for brand in BRANDS:
        for bl in brand_labels:
            dist = levenshtein(bl, brand)
            if dist < min_distance:
                min_distance = dist
                matched_brand = brand

    exact_brand_domain = any(
        hostname == f"{brand}.com" or hostname.endswith(f".{brand}.com") for brand in BRANDS
    )
    brand_similarity = max(0.0, 1.0 - min_distance / max(len(normalized_domain), len(matched_brand or ""), 1))
    brand_typo = (
        not exact_brand_domain
        and matched_brand is not None
        and min_distance <= 2
        and brand_similarity >= 0.65
    )

    homograph = has_unicode or has_punycode
    entropy = shannon_entropy(main_domain)
    digits = re.findall(r"\d", main_domain)
    letters = re.findall(r"[a-z]", main_domain, re.I)
    digit_ratio = len(digits) / max(len(letters) + len(digits), 1)
    high_entropy = entropy >= 3.5 and len(main_domain) >= 12
    dga = high_entropy and digit_ratio >= 0.2

    tld = labels[-1]
    suspicious_tld = tld in SUSPICIOUS_TLDS

    # Decoded inspect
    decoded, double_encoded = decode_for_inspection(f"{raw_input} {parsed.path} {parsed.query}")
    decoded_lower = decoded.lower()

    # Query redirect check
    query_params = parse_qs(parsed.query, keep_blank_values=True)
    redirect_keys_found = [k for k in query_params if k.lower() in REDIRECT_KEYS]
    redirect_parameter = len(redirect_keys_found) > 0
    external_redirect = False
    if redirect_parameter:
        for rk in redirect_keys_found:
            for val in query_params[rk]:
                try:
                    target_parsed = urlparse(val)
                    if target_parsed.netloc and target_parsed.netloc.lower() != hostname:
                        external_redirect = True
                except Exception:
                    pass

    path_traversal = bool(re.search(r"(?:\.\./|\.\.\\|%2e%2e(?:%2f|/|%5c|\\))", f"{parsed.path}{decoded}", re.I))
    xss = bool(re.search(r"<\s*script|javascript\s*:|on(?:error|load)\s*=|<\s*svg|<\s*img", decoded_lower, re.I))
    sqli = bool(re.search(r"(?:union\s+(?:all\s+)?select|select\s+[^;]{1,256}?\s+from|(?:'|%27)\s*(?:or|and)\s+['\"\d]|;\s*(?:drop|delete|update|insert)\s)", decoded_lower, re.I))
    lfi = bool(re.search(r"(?:/etc/passwd|/proc/self|php://|file://|(?:\.\./){2,})", decoded_lower, re.I))
    has_credentials = bool(parsed.username or parsed.password)

    findings = []

    def add_finding(signal: str, attack_type: str, title: str, detail: str):
        findings.append({
            "signal": signal,
            "attackType": attack_type,
            "title": title,
            "detail": detail,
            "penalty": SIGNAL_WEIGHTS.get(signal, 0.1)
        })

    if homograph:
        add_finding("homograph", "HOMOGRAPH_ATTACK", "Possible IDN / homograph spoof", f"Hostname uses IDN or punycode label ({unicode_hostname}).")
    if brand_typo and matched_brand:
        add_finding("typo", "TYPOSQUATTING", "Brand-like domain spelling", f"The hostname resembles brand '{matched_brand}' ({min_distance} edits away).")
    if dga:
        add_finding("dga", "DGA_SUSPECT", "High-entropy domain label", f"Main domain label has high character entropy ({entropy:.2f} bits).")
    if suspicious_tld:
        add_finding("suspiciousTld", "PHISHING_SUSPECT", "Uncommon high-risk TLD", f"The .{tld} suffix is frequently abused in phishing campaigns.")
    if redirect_parameter:
        add_finding("openRedirect", "OPEN_REDIRECT", f"Redirect parameter: {redirect_keys_found[0]}", "Redirects to external host." if external_redirect else "Redirect parameter present.")
    if is_internal:
        add_finding("internalIp", "INTERNAL_IP_TARGET", "Local or private network destination", f"Destination resolves syntactically to internal host ({hostname}).")
    if path_traversal:
        add_finding("pathTraversal", "INJECTION_PAYLOAD", "Path traversal pattern", "Contains directory traversal markers.")
    if xss:
        add_finding("xss", "INJECTION_PAYLOAD", "Script / HTML injection marker", "Contains inline script/HTML event markers.")
    if sqli:
        add_finding("sqli", "INJECTION_PAYLOAD", "SQL injection marker", "Contains recognizable SQL control pattern.")
    if lfi:
        add_finding("lfi", "INJECTION_PAYLOAD", "File inclusion marker", "Contains local file / stream markers.")
    if double_encoded:
        add_finding("doubleEncoding", "INJECTION_PAYLOAD", "Repeated URL encoding", "URL percent-encoding required multiple passes.")
    if has_credentials:
        add_finding("credentials", "PHISHING_SUSPECT", "Embedded URL credentials", "Authority contains inline username or password.")

    combined_risk = 1.0
    for finding in findings:
        combined_risk *= (1.0 - finding["penalty"])
    heuristic_risk = round(1.0 - combined_risk, 4)

    attack_types = list(dict.fromkeys(f["attackType"] for f in findings))
    if heuristic_risk >= 0.8:
        risk_level = "CRITICAL"
    elif heuristic_risk >= 0.6:
        risk_level = "HIGH"
    elif heuristic_risk >= 0.35:
        risk_level = "MEDIUM"
    elif heuristic_risk >= 0.15:
        risk_level = "LOW"
    else:
        risk_level = "SAFE"

    return {
        "inputUrl": raw_input,
        "canonicalUrl": candidate,
        "hostname": hostname,
        "unicodeHostname": unicode_hostname,
        "matchedBrand": matched_brand if min_distance <= 2 else None,
        "riskScore": heuristic_risk,
        "riskLevel": risk_level,
        "attackTypes": attack_types,
        "findings": findings
    }
