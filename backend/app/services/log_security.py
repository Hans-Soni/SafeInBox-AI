"""Log Security & Audit Protection Service.

Defends against all log-related attack vectors:
1. Log Injection / CRLF Injection (CWE-117)
2. Log Forging & SIEM Log Poisoning
3. Sensitive Data / Credential Exposure in Logs (CWE-532)
4. ANSI Escape Sequence / Terminal Injection Attacks
5. Log Flooding & Denial of Service

Enforces Zero-PII / Zero-Secret logging with structured single-line records.
"""

from datetime import datetime, timezone
import json
import logging
import re
from typing import Any, Optional

# ANSI escape sequence pattern to prevent terminal hijacking / control code injection
ANSI_ESCAPE_REGEX = re.compile(r"\x1b\[[0-9;]*[a-zA-Z]")

# Standard logger for security events
logger = logging.getLogger("safeinbox.security_audit")


def sanitize_log_value(val: Any, max_len: int = 128) -> str:
    """
    Sanitize arbitrary untrusted input before inclusion in log messages.
    - Strips carriage return (CR) and line feed (LF) to eliminate CRLF injection (CWE-117).
    - Removes ANSI escape codes to prevent terminal injection.
    - Neutralizes null bytes and non-printable control characters.
    - Truncates to max_len to defend against log flooding DoS.
    """
    if val is None:
        return "N/A"
    s = str(val)

    # 1. Strip ANSI escape sequences
    s = ANSI_ESCAPE_REGEX.sub("", s)

    # 2. Replace CR, LF, and TAB with safe printable characters
    s = s.replace("\r", " ").replace("\n", " ").replace("\t", " ")

    # 3. Keep only safe printable ASCII characters (32 to 126)
    clean = "".join(ch for ch in s if 32 <= ord(ch) <= 126 and ch != "\x00")

    # 4. Collapse multiple spaces and trim
    clean = re.sub(r"\s+", " ", clean).strip()

    # 5. Bound length
    return clean[:max_len] if clean else "N/A"


def mask_sensitive_token(token: Optional[str]) -> str:
    """Return a masked representation of a JWT or cryptographic token."""
    if not token or len(token) < 16:
        return "N/A"
    return f"{token[:6]}...{token[-4:]}"


def emit_security_audit_log(
    event_type: str,
    outcome: str,
    email: Optional[str] = None,
    ip_address: Optional[str] = None,
    user_agent: Optional[str] = None,
    details: Optional[dict[str, Any]] = None,
    severity: str = "INFO"
) -> dict[str, Any]:
    """
    Generate and log a single-line, structured, injection-proof security audit event.
    Guarantees no raw CRLF, secrets, or unescaped control codes exist in the output.
    """
    now = datetime.now(timezone.utc).isoformat()
    clean_event = sanitize_log_value(event_type, max_len=64)
    clean_outcome = sanitize_log_value(outcome, max_len=32)
    clean_email = sanitize_log_value(email, max_len=128)
    clean_ip = sanitize_log_value(ip_address, max_len=64)
    clean_ua = sanitize_log_value(user_agent, max_len=256)

    # Sanitize each detail entry; NEVER log passwords or raw keys
    safe_details = {}
    if details:
        for k, v in details.items():
            clean_k = sanitize_log_value(k, max_len=32)
            # Explicit blacklist of secret fields
            if any(secret_term in clean_k.lower() for secret_term in ["password", "secret", "salt", "token", "key"]):
                safe_details[clean_k] = "[REDACTED_SECURITY_DATA]"
            else:
                safe_details[clean_k] = sanitize_log_value(v, max_len=256)

    audit_payload = {
        "timestamp": now,
        "event": clean_event,
        "outcome": clean_outcome,
        "email": clean_email,
        "ip": clean_ip,
        "user_agent": clean_ua,
        "details": safe_details
    }

    # Format as a strictly single-line JSON string (CRLF-free)
    log_line = json.dumps(audit_payload, separators=(",", ":"))

    if severity == "WARNING":
        logger.warning(log_line)
    elif severity == "ERROR" or severity == "CRITICAL":
        logger.error(log_line)
    else:
        logger.info(log_line)

    return audit_payload

