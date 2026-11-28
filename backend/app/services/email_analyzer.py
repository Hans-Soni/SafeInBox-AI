"""Server-side Email text threat analysis engine."""

import html
import re

BRANDS = [
    {"name": "PayPal", "domains": ["paypal.com", "paypal.me"], "terms": ["paypal", "pay pal"]},
    {"name": "Netflix", "domains": ["netflix.com"], "terms": ["netflix"]},
    {"name": "Microsoft", "domains": ["microsoft.com", "office.com", "live.com", "outlook.com"], "terms": ["microsoft", "office 365", "outlook"]},
    {"name": "Apple", "domains": ["apple.com", "icloud.com"], "terms": ["apple", "icloud", "apple id"]},
    {"name": "Google", "domains": ["google.com", "gmail.com"], "terms": ["google", "gmail"]},
    {"name": "Amazon", "domains": ["amazon.com", "amazon.co.uk"], "terms": ["amazon", "prime"]},
    {"name": "Chase", "domains": ["chase.com"], "terms": ["chase bank", "chase"]},
    {"name": "DHL", "domains": ["dhl.com"], "terms": ["dhl"]},
    {"name": "FedEx", "domains": ["fedex.com"], "terms": ["fedex"]}
]

FREE_MAIL_DOMAINS = {
    "gmail.com", "googlemail.com", "yahoo.com", "yahoo.co.uk", "hotmail.com",
    "outlook.com", "live.com", "aol.com", "icloud.com", "proton.me", "protonmail.com"
}

URGENCY_RE = re.compile(
    r"\b(?:urgent(?:ly)?|immediate(?:ly)?|action required|within\s+\d+\s+hours?|account (?:is )?(?:suspended|locked|terminated)|final warning|expires? today)\b",
    re.I
)
FINANCIAL_RE = re.compile(
    r"\b(?:unclaimed refund|refund pending|payment overdue|invoice(?:\s+#?\w+)?|wire transfer|gift card|prize(?: money)?|you(?:'|’)ve won|claim your reward|tax refund)\b",
    re.I
)
CREDENTIAL_RE = re.compile(
    r"\b(?:password|passcode|pin|one[- ]time code|2fa|multi[- ]factor|verification code|security code|(?:login\s+)?credentials|sign[ -]?in details)\b",
    re.I
)
COERCION_RE = re.compile(
    r"\b(?:legal action|police report|law enforcement|account termination|permanently deleted|arrest warrant|immediately or else|avoid prosecution)\b",
    re.I
)
AUTHORITY_EXEC_RE = re.compile(
    r"\b(?:executive (?:board|committee|office)|chief executive|c-suite|cfo|ceo|coo|director|managing partner|human resources|hr department|security operations|compliance officer|internal audit|mandatory compliance)\b",
    re.I
)
AUTHORITY_CONFIDENTIAL_RE = re.compile(
    r"\b(?:strictly confidential|keep this (?:private|between us)|do not (?:discuss|share|forward|mention)|private matter|handle immediately|handle discreetly)\b",
    re.I
)


def compute_manipulation_radar(subject: str, body_text: str, sender_raw: str, threat_vectors: set[str]) -> dict:
    """
    Calculate the 4-axis Psychological Coercion & Manipulation Radar:
    1. Urgency Pressure (0-100)
    2. Authority Coercion (0-100)
    3. Financial Hook (0-100)
    4. Credential Harvest Cue (0-100)
    Runs in strict O(1) time complexity with zero database queries.
    """
    text_combined = f"{subject}\n{body_text}".lower()

    # Axis 1: Urgency Pressure
    urgency_score = 0
    if URGENCY_RE.search(subject):
        urgency_score += 45
    urgency_matches = len(URGENCY_RE.findall(body_text))
    urgency_score += min(55, urgency_matches * 25)
    if "ARTIFICIAL_URGENCY" in threat_vectors:
        urgency_score = max(urgency_score, 50)
    urgency_score = min(100, urgency_score)

    # Axis 2: Authority Coercion
    authority_score = 0
    if COERCION_RE.search(subject):
        authority_score += 40
    if COERCION_RE.search(body_text):
        authority_score += 35
    if AUTHORITY_EXEC_RE.search(text_combined):
        authority_score += 30
    if AUTHORITY_CONFIDENTIAL_RE.search(text_combined):
        authority_score += 25
    if "BEHAVIORAL_MANIPULATION" in threat_vectors or "SENDER_SPOOFING" in threat_vectors:
        authority_score = max(authority_score, 45)
    authority_score = min(100, authority_score)

    # Axis 3: Financial Hook
    financial_score = 0
    if FINANCIAL_RE.search(subject):
        financial_score += 40
    financial_matches = len(FINANCIAL_RE.findall(body_text))
    financial_score += min(60, financial_matches * 25)
    if "FINANCIAL_SCAM" in threat_vectors:
        financial_score = max(financial_score, 50)
    financial_score = min(100, financial_score)

    # Axis 4: Credential Harvest Cue
    credential_score = 0
    if CREDENTIAL_RE.search(subject):
        credential_score += 45
    credential_matches = len(CREDENTIAL_RE.findall(body_text))
    credential_score += min(55, credential_matches * 25)
    if "CREDENTIAL_HARVESTING" in threat_vectors:
        credential_score = max(credential_score, 55)
    credential_score = min(100, credential_score)

    # Dominant Tactic
    scores = {
        "URGENCY": urgency_score,
        "AUTHORITY": authority_score,
        "FINANCIAL": financial_score,
        "CREDENTIAL": credential_score
    }
    max_axis, max_val = max(scores.items(), key=lambda x: x[1])
    dominant_tactic = max_axis if max_val >= 25 else "NONE"

    # Cognitive Load Level
    if max_val >= 75:
        cognitive_load_level = "SEVERE"
    elif max_val >= 50 or (sum(scores.values()) / 4) >= 35:
        cognitive_load_level = "HIGH"
    elif max_val >= 25:
        cognitive_load_level = "MODERATE"
    else:
        cognitive_load_level = "LOW"

    # Active tactics tags
    detected_tactics = []
    if urgency_score >= 35:
        detected_tactics.append(f"Urgency Pressure ({urgency_score}%)")
    if authority_score >= 35:
        detected_tactics.append(f"Authority Coercion ({authority_score}%)")
    if financial_score >= 35:
        detected_tactics.append(f"Financial Hook ({financial_score}%)")
    if credential_score >= 35:
        detected_tactics.append(f"Credential Harvest ({credential_score}%)")

    # Informative psychological summary
    if cognitive_load_level == "SEVERE":
        radar_summary = f"Severe psychological manipulation detected ({dominant_tactic}). Uses extreme pressure or intimidation to bypass rational verification."
    elif cognitive_load_level == "HIGH":
        radar_summary = f"High social engineering cues detected ({dominant_tactic}). Multiple coercive tactics active to prompt immediate unverified action."
    elif cognitive_load_level == "MODERATE":
        radar_summary = f"Moderate cognitive pressure detected ({dominant_tactic}). Contains persuasive or urgent cues warranting sender verification."
    else:
        radar_summary = "Low psychological manipulation detected. Message lacks overt cognitive coercion or urgency cues."

    return {
        "urgency_score": urgency_score,
        "authority_score": authority_score,
        "financial_score": financial_score,
        "credential_score": credential_score,
        "dominant_tactic": dominant_tactic,
        "cognitive_load_level": cognitive_load_level,
        "detected_tactics": detected_tactics,
        "radar_summary": radar_summary
    }


def strip_html(text: str) -> str:
    """Strip HTML markup and decode entities."""
    clean = re.sub(r"<(script|style|head|title|svg|noscript)\b[^>]*>[\s\S]*?</\1\s*>", " ", text or "", flags=re.I)
    clean = re.sub(r"<[^>]*>", " ", clean)
    clean = html.unescape(clean)
    clean = re.sub(r"[ \t\f\v]+", " ", clean)
    clean = re.sub(r"\n{3,}", "\n\n", clean)
    return clean.strip()


def parse_sender(value: str) -> tuple[str, str, str]:
    """Extract display name, email, and domain from a sender field."""
    match = re.search(r"[\w.+-]+@(?:[\w-]+\.)+[a-zA-Z]{2,63}", value or "")
    if not match:
        return value.strip(), "", ""
    email = match.group(0).lower()
    domain = email.split("@")[-1]
    name = value.replace(match.group(0), "").replace("<", "").replace(">", "").replace('"', "").strip()
    return name or email, email, domain


def analyze_email_text(input_data: dict) -> dict:
    """Analyze email sender, subject, and text for social engineering cues."""
    raw_body = input_data.get("body") or input_data.get("text") or ""
    # Safe boundary: bound text analysis to 1,000,000 characters
    if len(raw_body) > 1_000_000:
        raw_body = raw_body[:1_000_000]

    subject = (input_data.get("subject") or "").strip()
    sender_raw = (input_data.get("sender") or "").strip()
    display_name, email, domain = parse_sender(sender_raw)
    display_name_lower = display_name.lower()
    body_text = strip_html(raw_body)

    searchable = f"{sender_raw}\n{subject}\n{body_text}".lower()

    findings = []
    threat_vectors = set()
    heuristic_risk = 0.0

    def add_evidence(rule_id: str, severity: str, evidence: str, remediation: str, vector: str, penalty: float):
        nonlocal heuristic_risk
        threat_vectors.add(vector)
        findings.append({
            "rule_id": rule_id,
            "severity": severity,
            "evidence": evidence,
            "remediation": remediation,
            "threat_vector": vector
        })
        heuristic_risk += penalty

    # Brand claim detection
    claimed_brand = None
    for brand in BRANDS:
        if any(term in display_name_lower for term in brand["terms"]):
            claimed_brand = brand
            break

    if claimed_brand and domain:
        verified = any(domain == d or domain.endswith(f".{d}") for d in claimed_brand["domains"]) and domain not in FREE_MAIL_DOMAINS
        if not verified:
            penalty = 0.7 if domain in FREE_MAIL_DOMAINS else 0.55
            add_evidence(
                "RULE_EMAIL_SENDER_DOMAIN_MISMATCH",
                "CRITICAL",
                f"Sender claims to represent {claimed_brand['name']}, but the sender address does not match an official domain.",
                "Verify the sender through an official trusted channel; do not trust display name.",
                "SENDER_SPOOFING",
                penalty
            )
            if domain in FREE_MAIL_DOMAINS:
                add_evidence(
                    "RULE_EMAIL_FREE_MAIL_IMPERSONATION",
                    "CRITICAL",
                    "A trusted brand claim uses a free consumer email provider.",
                    "Verify directly on official website.",
                    "SENDER_SPOOFING",
                    0.25
                )

    # Urgency check
    if URGENCY_RE.search(subject):
        add_evidence(
            "RULE_EMAIL_SUBJECT_URGENCY",
            "HIGH",
            "Subject line contains artificial urgency or account suspension pressure.",
            "Do not allow time pressure to bypass verification.",
            "ARTIFICIAL_URGENCY",
            0.25
        )

    # Financial hooks
    if FINANCIAL_RE.search(f"{subject}\n{body_text}"):
        add_evidence(
            "RULE_EMAIL_FINANCIAL_HOOK",
            "MEDIUM",
            "Financial scam, invoice, refund, or prize language detected.",
            "Independently verify invoices and prizes before proceeding.",
            "FINANCIAL_SCAM",
            0.20
        )

    # Credential solicitation
    if CREDENTIAL_RE.search(searchable):
        add_evidence(
            "RULE_EMAIL_CREDENTIAL_REQUEST",
            "HIGH",
            "Message solicits sensitive passwords, authentication codes, or login credentials.",
            "Never provide credentials or OTPs in response to emails.",
            "CREDENTIAL_HARVESTING",
            0.30
        )

    # Coercion
    if COERCION_RE.search(searchable):
        add_evidence(
            "RULE_EMAIL_COERCIVE_LANGUAGE",
            "HIGH",
            "Threatening or coercive legal/arrest language detected.",
            "Pause and verify through standard legal/support channels.",
            "BEHAVIORAL_MANIPULATION",
            0.25
        )

    risk_score_float = min(1.0, round(heuristic_risk, 4))
    risk_score = round(risk_score_float * 100)

    if risk_score >= 80:
        level = "CRITICAL"
    elif risk_score >= 60:
        level = "HIGH"
    elif risk_score >= 35:
        level = "MEDIUM"
    elif risk_score >= 15:
        level = "LOW"
    else:
        level = "SAFE"

    status = (
        "IMPERSONATION_MISMATCH" if "SENDER_SPOOFING" in threat_vectors
        else "VERIFIED_DOMAIN_MATCH" if claimed_brand
        else "NONE_DETECTED"
    )

    return {
        "target_type": "EMAIL",
        "risk_level": level,
        "risk_score": risk_score,
        "riskScore": risk_score_float,
        "threat_vectors": sorted(list(threat_vectors)),
        "summary": (
            f"Detected {len(findings)} email threat indicator{'s' if len(findings) != 1 else ''}."
            if findings else "No configured email threat indicators detected."
        ),
        "recommended_action": (
            "Do not click links or share credentials. Verify the sender through a separate trusted channel."
            if risk_score >= 50 else "Standard scrutiny applies."
        ),
        "evidence": findings,
        "company_intelligence": {
            "claimed_brand": claimed_brand["name"] if claimed_brand else None,
            "status": status,
            "sender_domain": domain,
            "canonical_domains": claimed_brand["domains"] if claimed_brand else []
        },
        "manipulation_radar": compute_manipulation_radar(subject, body_text, sender_raw, threat_vectors),
        "extracted_urls_count": len(input_data.get("urls") or []),
        "analysis_note": "Server-side heuristic analysis complete."
    }
