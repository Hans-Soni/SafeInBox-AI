"""Canonical Skeleton and Normalization Service for High-Scale Threat Intelligence.

Computes privacy-preserving, mutation-resilient canonical structural hashes for
email texts and URLs in O(1) time. Masks transient entities (names, dates, currency,
invoice numbers, URLs) to detect similar attack patterns across 50,000+ users.
"""

import hashlib
import html
import re
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse


# Volatile query parameters commonly varied by phishing kits / tracking
VOLATILE_QUERY_PARAMS = frozenset({
    "token", "session", "sessionid", "auth", "nonce", "cb", "timestamp",
    "ts", "ref", "source", "clickid", "uid", "userid", "email", "id",
    "utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content",
    "gclid", "fbclid", "mc_eid", "recipient", "_", "rand", "random"
})

# Salutation patterns
GREETING_RE = re.compile(
    r"\b(?:dear|hello|hi|greetings|good\s+(?:morning|afternoon|evening))\s+[\w\s.,'-]{1,30}?(?:,|\n|:)",
    re.IGNORECASE
)

# Email address pattern
EMAIL_RE = re.compile(r"[\w.+-]+@(?:[\w-]+\.)+[a-zA-Z]{2,63}", re.IGNORECASE)

# URL pattern
URL_RE = re.compile(r"\b(?:https?:\/\/|www\.)[^\s<>'\"`]+", re.IGNORECASE)

# IP address pattern
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b|\b[0-9a-f]{0,4}:[0-9a-f:]{2,}\b", re.IGNORECASE)

# Currency and monetary patterns
CURRENCY_RE = re.compile(
    r"(?:[$€£¥₹]\s?\d[\d,]*(?:\.\d{1,2})?|\b\d[\d,]*(?:\.\d{1,2})?\s?(?:USD|EUR|GBP|CAD|AUD|INR)\b)",
    re.IGNORECASE
)

# Number sequence pattern (invoice IDs, account numbers, order numbers)
NUM_RE = re.compile(r"\b(?:\d[-/._]?){2,}\b")

# Date pattern
DATE_RE = re.compile(
    r"\b(?:\d{1,4}[-/.]\d{1,2}[-/.]\d{1,4}|\d{1,2}(?:st|nd|rd|th)?\s+(?:jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)[a-z]*|\b(?:jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)[a-z]*\s+\d{1,2}(?:st|nd|rd|th)?)\b",
    re.IGNORECASE
)


def sha256_hash(text: str) -> str:
    """Compute deterministic SHA-256 hexadecimal digest."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def strip_html_and_decode(text: str) -> str:
    """Strip HTML markup, decode HTML entities, and collapse whitespace."""
    if not text:
        return ""
    clean = re.sub(r"<(script|style|head|title|svg|noscript)\b[^>]*>[\s\S]*?</\1\s*>", " ", text, flags=re.IGNORECASE)
    clean = re.sub(r"<[^>]*>", " ", clean)
    clean = html.unescape(clean)
    clean = re.sub(r"\s+", " ", clean)
    return clean.strip()


def compute_text_skeleton(text: str, subject: str = "") -> str:
    """
    Extract a normalized structural skeleton of an email text and subject.
    Replaces transient attacker mutations (names, dates, amounts, URLs, numbers)
    with invariant tokens ([USER], [DATE], [AMOUNT], [URL], [NUM], [EMAIL]).
    """
    combined = f"{subject}\n{text}".strip()
    raw = strip_html_and_decode(combined)
    if not raw:
        return ""

    # 1. Mask greetings/names
    masked = GREETING_RE.sub("dear [USER], ", raw)

    # 2. Mask URLs, IPs, emails
    masked = URL_RE.sub(" [URL] ", masked)
    masked = IP_RE.sub(" [IP] ", masked)
    masked = EMAIL_RE.sub(" [EMAIL] ", masked)

    # 3. Mask Currency and Dates
    masked = CURRENCY_RE.sub(" [AMOUNT] ", masked)
    masked = DATE_RE.sub(" [DATE] ", masked)

    # 4. Mask numeric identifiers
    masked = NUM_RE.sub(" [NUM] ", masked)

    # 5. Normalize casing and punctuation
    lowered = masked.lower()
    # Retain alphanumeric and placeholder brackets
    skeleton = re.sub(r"[^\w\s\[\]]", " ", lowered)
    skeleton = re.sub(r"\s+", " ", skeleton).strip()

    return skeleton


def compute_text_skeleton_hash(text: str, subject: str = "") -> str:
    """Generate O(1) 64-char SHA-256 fingerprint for canonical email text skeleton."""
    skeleton = compute_text_skeleton(text, subject)
    return sha256_hash(skeleton)


def compute_canonical_url(raw_url: str) -> str:
    """
    Normalize URL by lowercasing scheme/host, stripping trailing slashes,
    sorting query parameters, and eliminating transient tracking parameters.
    """
    url = (raw_url or "").strip()
    if not url:
        return ""

    if not (url.startswith("http://") or url.startswith("https://")):
        url = "https://" + url

    try:
        parsed = urlparse(url)
    except Exception:
        return url.lower()

    scheme = parsed.scheme.lower()
    netloc = parsed.netloc.lower()
    if netloc.startswith("www."):
        netloc = netloc[4:]

    # Remove standard default ports
    if netloc.endswith(":80") and scheme == "http":
        netloc = netloc[:-3]
    elif netloc.endswith(":443") and scheme == "https":
        netloc = netloc[:-4]

    path = parsed.path.rstrip("/")
    if not path:
        path = "/"

    # Strip volatile tracking/session parameters
    if parsed.query:
        query_pairs = parse_qsl(parsed.query, keep_blank_values=False)
        stable_pairs = [
            (k.lower(), v)
            for k, v in query_pairs
            if k.lower() not in VOLATILE_QUERY_PARAMS
        ]
        stable_pairs.sort(key=lambda x: x[0])
        clean_query = urlencode(stable_pairs)
    else:
        clean_query = ""

    return urlunparse((scheme, netloc, path, "", clean_query, ""))


def compute_canonical_url_hash(raw_url: str) -> str:
    """Generate O(1) 64-char SHA-256 fingerprint for canonical URL."""
    canonical = compute_canonical_url(raw_url)
    return sha256_hash(canonical)
