"""Email OTP (One-Time Password) generation, hashing, verification, and email dispatch service."""

import asyncio
import html
import logging
import secrets
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import hashlib
import hmac
from datetime import datetime, timezone
from typing import Tuple
import httpx
from sqlalchemy import delete
from sqlalchemy.ext.asyncio import AsyncSession
from app.config import settings
from app.models.user import EmailOTPVerification
from app.services.log_security import emit_security_audit_log

logger = logging.getLogger(__name__)

def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def generate_otp() -> str:
    """Generate a cryptographically secure 6-digit numeric OTP code."""
    # secrets.randbelow(900000) produces [0, 899999] -> + 100000 gives exactly [100000, 999999]
    return f"{secrets.randbelow(900000) + 100000}"


def generate_otp_salt() -> str:
    """Generate a random 16-byte cryptographic salt in hex."""
    return secrets.token_hex(16)


def hash_otp(otp: str, salt: str) -> str:
    """Hash the 6-digit OTP code using HMAC-SHA256 with salt."""
    return hmac.new(
        salt.encode("utf-8"),
        otp.strip().encode("utf-8"),
        hashlib.sha256
    ).hexdigest()


def verify_otp(otp: str, salt: str, expected_hash: str) -> bool:
    """Verify an input OTP against expected hash in constant time to eliminate timing attacks."""
    try:
        computed = hash_otp(otp, salt)
        return secrets.compare_digest(computed, expected_hash)
    except Exception:
        return False


def generate_otp_email_html(
    recipient_email: str,
    recipient_name: str | None,
    otp_code: str,
    expires_minutes: int = 10,
    purpose: str = "signup"
) -> str:
    """Render a responsive, high-contrast security email containing the 6-digit verification code."""
    display_name = html.escape(recipient_name or "SafeInbox AI User")
    safe_email = html.escape(recipient_email)
    spaced_code = " ".join(otp_code)

    if purpose == "signin":
        page_title = "SafeInbox AI Sign In Verification Code"
        heading = "Authorize Account Sign In"
        description = f"Hello <strong style=\"color:#f1f5f9;\">{display_name}</strong>,<br>Use the 6-digit verification code below to securely sign in to your SafeInbox AI account for <strong style=\"color:#38bdf8;\">{safe_email}</strong>."
        notice_action = "sign in to your account"
    elif purpose == "change_password":
        page_title = "SafeInbox AI Password Update Code"
        heading = "Authorize Password Update"
        description = f"Hello <strong style=\"color:#f1f5f9;\">{display_name}</strong>,<br>Use the 6-digit verification code below to authorize your password update for <strong style=\"color:#38bdf8;\">{safe_email}</strong>."
        notice_action = "change your password"
    else:
        page_title = "SafeInbox AI Email Verification Code"
        heading = "Verify Your Email Address"
        description = f"Hello <strong style=\"color:#f1f5f9;\">{display_name}</strong>,<br>Use the 6-digit verification code below to complete your registration for <strong style=\"color:#38bdf8;\">{safe_email}</strong>."
        notice_action = "register this account"

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{page_title}</title>
</head>
<body style="margin:0;padding:0;background-color:#030712;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;color:#f8fafc;">
    <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="background-color:#030712;padding:32px 16px;">
        <tr>
            <td align="center">
                <table role="presentation" width="100%" style="max-width:540px;background-color:#0b1329;border:1px solid #1e293b;border-radius:16px;overflow:hidden;box-shadow:0 20px 25px -5px rgba(0,0,0,0.6);">
                    <!-- Header -->
                    <tr>
                        <td style="background:linear-gradient(135deg,#064e3b 0%,#022c22 100%);padding:28px 32px;border-bottom:1px solid #065f46;">
                            <table role="presentation" width="100%">
                                <tr>
                                    <td>
                                        <div style="font-size:20px;font-weight:800;color:#34d399;letter-spacing:-0.5px;">
                                            🛡️ SafeInbox AI
                                        </div>
                                        <div style="font-size:12px;color:#a7f3d0;font-weight:500;margin-top:2px;">
                                            Intelligent Email Threat Defense &amp; Identity Verification
                                        </div>
                                    </td>
                                </tr>
                            </table>
                        </td>
                    </tr>

                    <!-- Body -->
                    <tr>
                        <td style="padding:32px;">
                            <h1 style="font-size:20px;font-weight:700;color:#f8fafc;margin:0 0 12px 0;">
                                {heading}
                            </h1>
                            <p style="font-size:14px;color:#94a3b8;line-height:1.6;margin:0 0 24px 0;">
                                {description}
                            </p>

                            <!-- OTP Box -->
                            <div style="background:#030712;border:2px solid #059669;border-radius:12px;padding:24px;text-align:center;margin-bottom:24px;">
                                <div style="font-size:12px;text-transform:uppercase;letter-spacing:1.5px;color:#10b981;font-weight:700;margin-bottom:8px;">
                                    Your 6-Digit Verification Code
                                </div>
                                <div style="font-family:'Courier New',Courier,monospace;font-size:36px;font-weight:800;letter-spacing:8px;color:#ffffff;text-shadow:0 0 12px rgba(16,185,129,0.4);">
                                    {otp_code}
                                </div>
                                <div style="font-size:12px;color:#64748b;margin-top:10px;">
                                    ⏱️ Code expires in <strong style="color:#f59e0b;">{expires_minutes} minutes</strong>
                                </div>
                            </div>

                            <!-- Security Warnings -->
                            <div style="background:#1e1b4b;border:1px solid #3730a3;border-radius:8px;padding:16px;margin-bottom:24px;">
                                <div style="font-size:13px;font-weight:700;color:#c7d2fe;margin-bottom:4px;">
                                    🔒 Security Notice:
                                </div>
                                <ul style="margin:0;padding-left:18px;font-size:12px;color:#e0e7ff;line-height:1.5;">
                                    <li>Never share this code with anyone. SafeInbox AI staff will never ask for your code.</li>
                                    <li>If you did not request to {notice_action}, please change your password immediately.</li>
                                    <li>One-time use only: this code is automatically purged upon verification.</li>
                                </ul>
                            </div>

                            <p style="font-size:12px;color:#64748b;line-height:1.5;margin:0;">
                                Questions or concerns? Contact our security operations team at <a href="mailto:security@safeinbox.ai" style="color:#38bdf8;text-decoration:none;">security@safeinbox.ai</a>.
                            </p>
                        </td>
                    </tr>

                    <!-- Footer -->
                    <tr>
                        <td style="background:#030712;border-top:1px solid #1e293b;padding:20px 32px;text-align:center;font-size:11px;color:#475569;">
                            <p style="margin:0 0 4px 0;">SafeInbox AI &bull; Intelligent Email Security &amp; Identity Verification</p>
                            <p style="margin:0;">Automated message sent to {safe_email}. Do not reply directly to this email.</p>
                        </td>
                    </tr>
                </table>
            </td>
        </tr>
    </table>
</body>
</html>"""


def send_smtp_email_sync(to_email: str, subject: str, html_content: str) -> None:
    """Synchronous SMTP email sender executed in asyncio background worker."""
    if not settings.SMTP_HOST:
        raise ValueError("SMTP_HOST is not configured.")

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = f"{settings.SMTP_FROM_NAME} <{settings.SMTP_FROM_EMAIL}>"
    msg["To"] = to_email

    part_html = MIMEText(html_content, "html", "utf-8")
    msg.attach(part_html)

    server = smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT, timeout=15)
    try:
        if settings.SMTP_TLS:
            server.starttls()
        if settings.SMTP_USER and settings.SMTP_PASSWORD:
            server.login(settings.SMTP_USER, settings.SMTP_PASSWORD)
        server.sendmail(settings.SMTP_FROM_EMAIL, [to_email], msg.as_string())
    finally:
        server.quit()


async def dispatch_otp_email(
    recipient_email: str,
    recipient_name: str | None,
    otp_code: str,
    expires_minutes: int = 10,
    purpose: str = "signup"
) -> Tuple[bool, str, str]:
    """
    Format and deliver the 6-digit OTP code to the recipient.
    Supports signup, signin (2FA step-up), and password change authorization.
    Returns (success, message, delivery_mode).
    """
    html_content = generate_otp_email_html(
        recipient_email=recipient_email,
        recipient_name=recipient_name,
        otp_code=otp_code,
        expires_minutes=expires_minutes,
        purpose=purpose
    )
    if purpose == "signin":
        subject = "Your SafeInbox AI Sign In Verification Code"
    elif purpose == "change_password":
        subject = "Your SafeInbox AI Password Update Code"
    else:
        subject = "Your SafeInbox AI Verification Code"

    # Option 1: Google Apps Script Webhook Relay
    if settings.APPS_SCRIPT_URL:
        try:
            payload = {
                "to": recipient_email,
                "subject": subject,
                "html": html_content,
                "secret": settings.APPS_SCRIPT_SECRET or "safeinbox_secret_key"
            }
            async with httpx.AsyncClient(follow_redirects=True, timeout=20.0) as client:
                resp = await client.post(settings.APPS_SCRIPT_URL, json=payload)
                if resp.status_code == 200:
                    data = resp.json()
                    if data.get("success"):
                        emit_security_audit_log(
                            event_type="AUTH_OTP_DISPATCHED_APPS_SCRIPT",
                            outcome="SUCCESS",
                            email=recipient_email,
                            details={"delivery_mode": "apps_script", "expires_minutes": expires_minutes},
                            severity="INFO"
                        )
                        logger.info("Successfully delivered OTP code email to %s via Google Apps Script", recipient_email)
                        return True, f"Verification code sent via email to {recipient_email}.", "apps_script"
                    else:
                        raise ValueError(data.get("error", "Apps Script error response"))
                else:
                    raise ValueError(f"HTTP {resp.status_code}: {resp.text}")
        except Exception as err:
            logger.error("Failed to send verification code email via Apps Script to %s: %s", recipient_email, err)
            emit_security_audit_log(
                event_type="AUTH_OTP_DISPATCH_APPS_SCRIPT_FAILED",
                outcome="ERROR",
                email=recipient_email,
                details={"error": str(err)},
                severity="WARNING"
            )
            if not settings.SMTP_HOST:
                return False, f"Failed to send email via Google Apps Script: {err}", "apps_script_error"

    # Option 2: Direct SMTP Server Delivery
    if settings.SMTP_HOST:
        try:
            await asyncio.to_thread(send_smtp_email_sync, recipient_email, subject, html_content)
            emit_security_audit_log(
                event_type="AUTH_OTP_DISPATCHED_SMTP",
                outcome="SUCCESS",
                email=recipient_email,
                details={"delivery_mode": "smtp", "expires_minutes": expires_minutes},
                severity="INFO"
            )
            return True, f"Verification code sent via email to {recipient_email}.", "smtp"
        except Exception as err:
            logger.error("Failed to send verification code email via SMTP to %s: %s", recipient_email, err)
            emit_security_audit_log(
                event_type="AUTH_OTP_DISPATCH_SMTP_FAILED",
                outcome="ERROR",
                email=recipient_email,
                details={"error": str(err)},
                severity="WARNING"
            )
            return False, f"Failed to send email via SMTP: {err}", "smtp_error"

    # Development / Simulated mode when SMTP is not configured
    emit_security_audit_log(
        event_type="AUTH_OTP_DISPATCHED_SIMULATED",
        outcome="SUCCESS",
        email=recipient_email,
        details={
            "delivery_mode": "simulated_preview",
            "expires_minutes": expires_minutes,
            "dev_notice": "SMTP_HOST not configured. Set SMTP_HOST in .env for production email delivery."
        },
        severity="INFO"
    )
    logger.info(
        "DEVELOPMENT MODE: OTP code for %s is [%s] (expires in %d min)",
        recipient_email,
        otp_code,
        expires_minutes
    )
    return True, f"Verification code generated (simulated dev delivery) for {recipient_email}.", "simulated_preview"


async def cleanup_otp_record(
    db: AsyncSession,
    email: str | None = None,
    record: EmailOTPVerification | None = None
) -> None:
    """
    Ensure zero lingering OTPs in database.
    Immediately deletes the completed OTP verification record, any record matching email,
    and purges all expired OTP records across the entire database.
    """
    try:
        now = utcnow()
        if record is not None:
            await db.delete(record)
        if email:
            await db.execute(delete(EmailOTPVerification).where(EmailOTPVerification.email == email))
        await db.execute(delete(EmailOTPVerification).where(EmailOTPVerification.expires_at < now))
        await db.commit()
    except Exception as err:
        logger.warning("Error during OTP cleanup: %s", err)
        try:
            await db.rollback()
        except Exception:
            pass


