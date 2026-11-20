"""15-Day Security & Threat Audit Digest Service."""

import asyncio
from datetime import datetime, timezone, timedelta
import html
import logging
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import List, Tuple, Optional, Dict, Any
import httpx
from sqlalchemy import delete
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.models.digest import SecurityDigestLog
from app.models.threat import ScanAuditLog, UrlClickLog
from app.models.user import generate_user_index_id
from app.schemas.digest import DigestSendRequest, EmailRecordItem, UrlClickItem

logger = logging.getLogger(__name__)


def generate_digest_html(
    user_email: str,
    user_name: str,
    period_start: str,
    period_end: str,
    records: List[EmailRecordItem],
    url_clicks: Optional[List[UrlClickItem]] = None,
    user_index_id: Optional[str] = None
) -> str:
    """
    Render a clean, high-contrast, responsive HTML email report for the 15-day period.
    Includes:
    - Summary risk statistics
    - All available email threat reports (senders, receivers, time-slabs, ML threat scores, threat vectors)
    - Comprehensive 15-day URL click history
    - 15-day retention policy notification
    """
    total_emails = len(records)
    threats = [r for r in records if r.composite_risk >= 35 or r.risk_level in ("HIGH", "CRITICAL", "MEDIUM")]
    threat_count = len(threats)
    safe_count = total_emails - threat_count

    # Aggregate URL clicks from both explicit url_clicks and individual record clicked_urls
    aggregated_clicks: List[UrlClickItem] = []
    seen_click_keys = set()

    # 1. Clicks from request.url_clicks
    if url_clicks:
        for c in url_clicks:
            key = (c.url, str(c.timestamp))
            if key not in seen_click_keys:
                seen_click_keys.add(key)
                aggregated_clicks.append(c)

    # 2. Clicks from inside individual email records
    for r in records:
        for c in r.clicked_urls:
            key = (c.url, str(c.timestamp))
            if key not in seen_click_keys:
                seen_click_keys.add(key)
                # Attach email subject/sender context if missing
                if not getattr(c, "email_subject", None):
                    c.email_subject = r.subject
                if not getattr(c, "sender", None):
                    c.sender = r.sender
                aggregated_clicks.append(c)

    total_clicks = len(aggregated_clicks)

    # Render individual email record rows
    record_cards_html = ""
    if not records:
        record_cards_html = """
        <div style="background:#0f172a;border:1px solid #1e293b;border-radius:10px;padding:24px;text-align:center;color:#94a3b8;font-size:14px;">
            No webmail scan activity recorded during this 15-day time-slab.
        </div>
        """
    else:
        for idx, rec in enumerate(records, 1):
            is_threat = rec.composite_risk >= 35 or rec.risk_level in ("HIGH", "CRITICAL", "MEDIUM")
            badge_color = "#ef4444" if rec.composite_risk >= 60 else "#f59e0b" if rec.composite_risk >= 35 else "#10b981"
            badge_bg = "#450a0a" if rec.composite_risk >= 60 else "#451a03" if rec.composite_risk >= 35 else "#064e3b"

            # Render clicked URLs inside this email
            clicks_html = ""
            if rec.clicked_urls:
                clicks_list_items = ""
                for click in rec.clicked_urls:
                    c_threat = click.risk_score >= 35 or click.risk_level in ("SUSPICIOUS", "MALICIOUS", "THREAT", "HIGH", "CRITICAL")
                    c_color = "#ef4444" if c_threat else "#10b981"
                    c_defanged = click.defanged or click.url.replace(".", "[.]").replace("http://", "hxxp://").replace("https://", "hxxps://")
                    c_time = str(click.timestamp) if click.timestamp else "Logged"
                    clicks_list_items += f"""
                    <div style="background:#090d16;border:1px solid #1e293b;border-radius:6px;padding:8px 12px;margin-top:6px;font-size:12px;display:flex;justify-content:space-between;align-items:center;">
                        <div>
                            <span style="font-family:monospace;color:#38bdf8;word-break:break-all;">{html.escape(c_defanged)}</span>
                            <span style="color:#64748b;font-size:10px;margin-left:8px;">&bull; {html.escape(c_time)}</span>
                        </div>
                        <span style="color:{c_color};font-weight:bold;margin-left:10px;white-space:nowrap;">Risk: {click.risk_score:.0f}/100</span>
                    </div>
                    """
                clicks_html = f"""
                <div style="margin-top:12px;padding-top:10px;border-top:1px dashed #334155;">
                    <div style="font-size:12px;font-weight:bold;color:#f8fafc;margin-bottom:4px;">
                        🔗 URL Clicks in this email ({len(rec.clicked_urls)}):
                    </div>
                    {clicks_list_items}
                </div>
                """
            else:
                clicks_html = """
                <div style="margin-top:10px;font-size:12px;color:#64748b;font-style:italic;">
                    No links were clicked in this email.
                </div>
                """

            vectors_badge = ""
            if rec.threat_vectors:
                vectors_badge = f"""
                <div style="margin-top:8px;">
                    <span style="font-size:11px;color:#cbd5e1;">Vectors: </span>
                    {" ".join(f'<span style="background:#1e293b;color:#fca5a5;padding:2px 6px;border-radius:4px;font-size:11px;margin-right:4px;">{html.escape(v)}</span>' for v in rec.threat_vectors)}
                </div>
                """

            record_cards_html += f"""
            <div style="background:#0f172a;border:1px solid {'#991b1b' if is_threat else '#1e293b'};border-radius:10px;padding:18px;margin-bottom:16px;">
                <div style="display:flex;justify-content:space-between;align-items:flex-start;border-bottom:1px solid #1e293b;padding-bottom:10px;margin-bottom:10px;">
                    <div>
                        <span style="font-size:15px;font-weight:bold;color:#f8fafc;">#{idx}. {html.escape(rec.subject or '(No Subject)')}</span>
                    </div>
                    <span style="background:{badge_bg};color:{badge_color};border:1px solid {badge_color};padding:3px 10px;border-radius:12px;font-size:12px;font-weight:bold;white-space:nowrap;">
                        ML Score: {rec.composite_risk:.0f}/100 ({html.escape(rec.risk_level)})
                    </span>
                </div>
                
                <table style="width:100%;font-size:13px;color:#cbd5e1;border-collapse:collapse;margin-bottom:8px;">
                    <tr>
                        <td style="padding:3px 0;width:110px;color:#94a3b8;font-weight:600;">Sender:</td>
                        <td style="padding:3px 0;color:#f1f5f9;font-weight:500;">{html.escape(rec.sender)}</td>
                    </tr>
                    <tr>
                        <td style="padding:3px 0;color:#94a3b8;font-weight:600;">Receiver:</td>
                        <td style="padding:3px 0;color:#f1f5f9;font-weight:500;">{html.escape(rec.receiver)}</td>
                    </tr>
                    <tr>
                        <td style="padding:3px 0;color:#94a3b8;font-weight:600;">Time-Slab:</td>
                        <td style="padding:3px 0;color:#94a3b8;">{html.escape(rec.time_slab or rec.date_iso or str(rec.timestamp) or 'Recorded')}</td>
                    </tr>
                    <tr>
                        <td style="padding:3px 0;color:#94a3b8;font-weight:600;">ML Breakdown:</td>
                        <td style="padding:3px 0;color:#94a3b8;">Text Threat: <strong style="color:#f8fafc;">{rec.text_threat_score:.0f}%</strong> | URL Threat: <strong style="color:#f8fafc;">{rec.url_threat_score:.0f}%</strong></td>
                    </tr>
                </table>
                
                {vectors_badge}
                {clicks_html}
            </div>
            """

    # Render dedicated 15-day URL click history section
    url_clicks_section_html = ""
    if not aggregated_clicks:
        url_clicks_section_html = """
        <div style="background:#0f172a;border:1px solid #1e293b;border-radius:10px;padding:20px;text-align:center;color:#94a3b8;font-size:13px;">
            No hyperlink clicks were performed in webmail during this 15-day audit period.
        </div>
        """
    else:
        clicks_items_html = ""
        for c_idx, click in enumerate(aggregated_clicks, 1):
            c_threat = click.risk_score >= 35 or click.risk_level in ("SUSPICIOUS", "MALICIOUS", "THREAT", "HIGH", "CRITICAL")
            c_badge_color = "#ef4444" if click.risk_score >= 60 else "#f59e0b" if click.risk_score >= 35 else "#10b981"
            c_badge_bg = "#450a0a" if click.risk_score >= 60 else "#451a03" if click.risk_score >= 35 else "#064e3b"
            c_border = "#991b1b" if c_threat else "#1e293b"
            c_defanged = click.defanged or click.url.replace(".", "[.]").replace("http://", "hxxp://").replace("https://", "hxxps://")
            c_time = str(click.timestamp) if click.timestamp else "Recorded"
            c_context = click.email_subject or click.sender or "(Webmail Link)"
            c_action_text = "✓ Proceeded" if click.proceeded else "✋ Blocked/Aborted"
            c_action_color = "#10b981" if click.proceeded else "#ef4444"

            clicks_items_html += f"""
            <div style="background:#0f172a;border:1px solid {c_border};border-radius:8px;padding:12px 16px;margin-bottom:10px;">
                <div style="display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:6px;">
                    <div>
                        <span style="font-size:11px;color:#94a3b8;font-weight:bold;margin-right:6px;">#{c_idx}</span>
                        <span style="font-family:monospace;color:#38bdf8;font-size:13px;word-break:break-all;">{html.escape(c_defanged)}</span>
                    </div>
                    <span style="background:{c_badge_bg};color:{c_badge_color};border:1px solid {c_badge_color};padding:2px 8px;border-radius:10px;font-size:11px;font-weight:bold;white-space:nowrap;margin-left:10px;">
                        {click.risk_score:.0f}/100 ({html.escape(click.risk_level)})
                    </span>
                </div>
                <div style="display:flex;justify-content:space-between;align-items:center;font-size:12px;color:#94a3b8;flex-wrap:wrap;gap:6px;">
                    <div>
                        <span style="color:#64748b;">Email Context:</span> <strong style="color:#e2e8f0;">{html.escape(c_context)}</strong>
                    </div>
                    <div>
                        <span style="color:#64748b;">Clicked At:</span> <span style="color:#cbd5e1;">{html.escape(c_time)}</span>
                        <span style="margin-left:8px;padding:2px 6px;border-radius:4px;font-size:10px;background:#1e293b;color:{c_action_color};font-weight:600;">
                            {c_action_text}
                        </span>
                    </div>
                </div>
            </div>
            """
        url_clicks_section_html = clicks_items_html

    resolved_idx = user_index_id or generate_user_index_id(user_email)

    return f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>SafeInbox AI: 15-Day Security Audit Digest</title>
    </head>
    <body style="margin:0;padding:0;background:#030712;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;color:#f8fafc;">
        <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="background:#030712;padding:24px 0;">
            <tr>
                <td align="center">
                    <table role="presentation" width="640" cellspacing="0" cellpadding="0" style="max-width:640px;width:100%;background:#090d16;border:1px solid #1e293b;border-radius:12px;overflow:hidden;">
                        <!-- Header Banner -->
                        <tr>
                            <td style="background:linear-gradient(135deg, #0284c7 0%, #0369a1 50%, #0f172a 100%);padding:28px 24px;text-align:left;">
                                <div style="display:inline-block;background:rgba(255,255,255,0.15);padding:4px 10px;border-radius:20px;font-size:12px;font-weight:bold;color:#e0f2fe;margin-bottom:8px;">
                                    🛡️ 15-Day Security & Threat Audit
                                </div>
                                <h1 style="margin:0;font-size:22px;color:#ffffff;font-weight:800;letter-spacing:-0.5px;">
                                    SafeInbox AI Security Digest
                                </h1>
                                <p style="margin:6px 0 0 0;font-size:13px;color:#bae6fd;">
                                    Audit Window: <strong>{html.escape(period_start)}</strong> &mdash; <strong>{html.escape(period_end)}</strong>
                                </p>
                            </td>
                        </tr>

                        <!-- User Info Bar -->
                        <tr>
                            <td style="background:#0f172a;border-bottom:1px solid #1e293b;padding:12px 24px;font-size:13px;color:#94a3b8;">
                                Prepared exclusively for: <strong style="color:#f8fafc;">{html.escape(user_name)}</strong> (&lt;{html.escape(user_email)}&gt;)
                                &nbsp;&bull;&nbsp; Index ID: <strong style="color:#FFA586;font-family:monospace;">{html.escape(resolved_idx)}</strong>
                            </td>
                        </tr>

                        <!-- Summary Cards -->
                        <tr>
                            <td style="padding:24px;">
                                <table width="100%" cellspacing="0" cellpadding="0" style="margin-bottom:24px;">
                                    <tr>
                                        <td width="24%" style="background:#0f172a;border:1px solid #1e293b;border-radius:8px;padding:14px;text-align:center;">
                                            <div style="font-size:20px;font-weight:bold;color:#f8fafc;">{total_emails}</div>
                                            <div style="font-size:11px;color:#94a3b8;margin-top:2px;">Emails Audited</div>
                                        </td>
                                        <td width="3%"></td>
                                        <td width="23%" style="background:#0f172a;border:1px solid #065f46;border-radius:8px;padding:14px;text-align:center;">
                                            <div style="font-size:20px;font-weight:bold;color:#10b981;">{safe_count}</div>
                                            <div style="font-size:11px;color:#94a3b8;margin-top:2px;">Safe Emails</div>
                                        </td>
                                        <td width="3%"></td>
                                        <td width="23%" style="background:#0f172a;border:1px solid #991b1b;border-radius:8px;padding:14px;text-align:center;">
                                            <div style="font-size:20px;font-weight:bold;color:#ef4444;">{threat_count}</div>
                                            <div style="font-size:11px;color:#94a3b8;margin-top:2px;">Threats Flagged</div>
                                        </td>
                                        <td width="3%"></td>
                                        <td width="24%" style="background:#0f172a;border:1px solid #1e293b;border-radius:8px;padding:14px;text-align:center;">
                                            <div style="font-size:20px;font-weight:bold;color:#38bdf8;">{total_clicks}</div>
                                            <div style="font-size:11px;color:#94a3b8;margin-top:2px;">URL Clicks</div>
                                        </td>
                                    </tr>
                                </table>

                                <!-- Section 1: Email Threat Reports -->
                                <div style="font-size:16px;font-weight:bold;color:#f8fafc;margin-bottom:14px;display:flex;align-items:center;">
                                    📋 15-Day Email Security Reports (Sender, Receiver &amp; ML Threat Scores)
                                </div>
                                {record_cards_html}

                                <!-- Section 2: Comprehensive URL Click History -->
                                <div style="font-size:16px;font-weight:bold;color:#f8fafc;margin-top:24px;margin-bottom:14px;display:flex;align-items:center;">
                                    🔗 15-Day Webmail URL Click Audit Trail ({total_clicks})
                                </div>
                                {url_clicks_section_html}

                                <!-- Guidance Box -->
                                <div style="background:#0c192c;border:1px solid #1e3a8a;border-radius:8px;padding:16px;margin-top:24px;">
                                    <div style="font-size:13px;font-weight:bold;color:#60a5fa;margin-bottom:4px;">
                                        💡 Autonomous Security Recommendation:
                                    </div>
                                    <div style="font-size:12px;color:#93c5fd;line-height:1.5;">
                                        SafeInbox AI inspects all incoming emails and link destinations using local ONNX neural networks. If you see high ML risk scores or unrecognized sender domains above, avoid entering credentials or running file attachments.
                                    </div>
                                </div>
                            </td>
                        </tr>

                        <!-- Footer & 15-Day Retention Notice -->
                        <tr>
                            <td style="background:#030712;border-top:1px solid #1e293b;padding:20px 24px;text-align:center;font-size:11px;color:#64748b;">
                                <p style="margin:0 0 6px 0;">SafeInbox AI &bull; Autonomous Client-Side Threat Intelligence</p>
                                <p style="margin:0 0 6px 0;">This scheduled report is automatically generated every 15 days for your account. Confidential &amp; Encrypted.</p>
                                <p style="margin:6px 0 0 0;color:#94a3b8;font-size:11px;line-height:1.4;">
                                    ⏳ <strong>15-Day Privacy Lifecycle:</strong> Scanned email audit records and URL click history are retained for 15 days, after which they are permanently cleared from our database.
                                </p>
                            </td>
                        </tr>
                    </table>
                </td>
            </tr>
        </table>
    </body>
    </html>
    """


def send_smtp_email(to_email: str, subject: str, html_content: str) -> None:
    """Synchronous SMTP sender executed in a separate background thread."""
    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = f"{settings.SMTP_FROM_NAME} <{settings.SMTP_FROM_EMAIL}>"
    msg["To"] = to_email

    part_html = MIMEText(html_content, "html", "utf-8")
    msg.attach(part_html)

    if not settings.SMTP_HOST:
        raise ValueError("SMTP_HOST is not configured.")

    server = smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT, timeout=15)
    try:
        if settings.SMTP_TLS:
            server.starttls()
        if settings.SMTP_USER and settings.SMTP_PASSWORD:
            server.login(settings.SMTP_USER, settings.SMTP_PASSWORD)
        server.sendmail(settings.SMTP_FROM_EMAIL, [to_email], msg.as_string())
    finally:
        server.quit()


async def purge_expired_15day_history(
    db: AsyncSession,
    user_email: Optional[str] = None,
    days: int = 15
) -> Dict[str, Any]:
    """
    Enforce the 15-day retention lifecycle policy:
    Permanently delete scan audit logs, URL clicks, and past digest logs
    older than 15 days from Neon PostgreSQL / SQLite.
    """
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)

    purged_audits = 0
    purged_clicks = 0
    purged_digests = 0

    try:
        # 1. Purge ScanAuditLog older than 15 days
        stmt_audits = delete(ScanAuditLog).where(ScanAuditLog.created_at < cutoff)
        res_audits = await db.execute(stmt_audits)
        purged_audits = res_audits.rowcount if hasattr(res_audits, "rowcount") and res_audits.rowcount is not None else 0
    except Exception as e:
        logger.warning("Could not purge expired scan_audit_logs: %s", e)

    try:
        # 2. Purge UrlClickLog older than 15 days
        if user_email:
            clean_email = user_email.strip().lower()
            stmt_clicks = delete(UrlClickLog).where(
                (UrlClickLog.clicked_at < cutoff) &
                ((UrlClickLog.user_email == clean_email) | (UrlClickLog.user_email.is_(None)))
            )
        else:
            stmt_clicks = delete(UrlClickLog).where(UrlClickLog.clicked_at < cutoff)
        res_clicks = await db.execute(stmt_clicks)
        purged_clicks = res_clicks.rowcount if hasattr(res_clicks, "rowcount") and res_clicks.rowcount is not None else 0
    except Exception as e:
        logger.warning("Could not purge expired url_clicks: %s", e)

    try:
        # 3. Purge older SecurityDigestLog older than 15 days
        if user_email:
            clean_email = user_email.strip().lower()
            stmt_digests = delete(SecurityDigestLog).where(
                (SecurityDigestLog.created_at < cutoff) & (SecurityDigestLog.user_email == clean_email)
            )
        else:
            stmt_digests = delete(SecurityDigestLog).where(SecurityDigestLog.created_at < cutoff)
        res_digests = await db.execute(stmt_digests)
        purged_digests = res_digests.rowcount if hasattr(res_digests, "rowcount") and res_digests.rowcount is not None else 0
    except Exception as e:
        logger.warning("Could not purge expired security_digest_logs: %s", e)

    try:
        await db.commit()
    except Exception as commit_err:
        logger.warning("Error committing database purge transaction: %s", commit_err)

    total_purged = max(purged_audits, 0) + max(purged_clicks, 0) + max(purged_digests, 0)
    logger.info(
        "Purged 15-day expired database records: %d audits, %d clicks, %d digests (cutoff=%s)",
        purged_audits, purged_clicks, purged_digests, cutoff.isoformat()
    )

    return {
        "purged_audits": max(purged_audits, 0),
        "purged_clicks": max(purged_clicks, 0),
        "purged_digests": max(purged_digests, 0),
        "total_purged": total_purged,
        "retention_days": days,
        "cutoff_iso": cutoff.isoformat()
    }


async def dispatch_15_day_digest(
    db: AsyncSession,
    request: DigestSendRequest
) -> Tuple[bool, str, str, str, Dict[str, Any]]:
    """
    Format and deliver the 15-day security record to the specific user email,
    including all available email reports and URL click history, then automatically
    purges database records older than 15 days.
    Returns (success, message, dispatch_mode, rendered_html, purge_info).
    """
    html_report = generate_digest_html(
        user_email=request.user_email,
        user_name=request.user_name or "SafeInbox AI User",
        period_start=request.period_start,
        period_end=request.period_end,
        records=request.records,
        url_clicks=request.url_clicks
    )

    total_emails = len(request.records)
    threat_count = sum(1 for r in request.records if r.composite_risk >= 35 or r.risk_level in ("HIGH", "CRITICAL", "MEDIUM"))
    
    # Total clicks includes request.url_clicks and in-email clicked_urls
    click_urls_set = set(c.url for c in request.url_clicks)
    for r in request.records:
        for c in r.clicked_urls:
            click_urls_set.add(c.url)
    click_count = max(len(click_urls_set), len(request.url_clicks))

    subject = f"SafeInbox AI: 15-Day Security & Threat Audit ({request.period_start} to {request.period_end})"

    dispatch_mode = "simulated_preview"
    status = "simulated"
    note = "Simulated delivery (SMTP/Apps Script not connected, preview generated)."

    if settings.APPS_SCRIPT_URL:
        try:
            payload = {
                "to": request.user_email,
                "subject": subject,
                "html": html_report,
                "secret": settings.APPS_SCRIPT_SECRET or "safeinbox_secret_key"
            }
            async with httpx.AsyncClient(follow_redirects=True, timeout=20.0) as client:
                resp = await client.post(settings.APPS_SCRIPT_URL, json=payload)
                if resp.status_code == 200 and resp.json().get("success"):
                    dispatch_mode = "apps_script"
                    status = "sent"
                    note = f"Sent successfully via Google Apps Script to {request.user_email}"
                    logger.info("Successfully delivered 15-day digest to %s via Google Apps Script", request.user_email)
                else:
                    raise ValueError(f"Apps Script HTTP {resp.status_code}: {resp.text}")
        except Exception as err:
            logger.error("Failed to send Apps Script digest to %s: %s", request.user_email, err)
            status = "failed"
            note = f"Google Apps Script dispatch failed: {str(err)}"

    elif settings.SMTP_HOST:
        try:
            await asyncio.to_thread(send_smtp_email, request.user_email, subject, html_report)
            dispatch_mode = "smtp"
            status = "sent"
            note = f"Sent successfully via SMTP to {request.user_email}"
            logger.info("Successfully delivered 15-day digest to %s via SMTP", request.user_email)
        except Exception as err:
            logger.error("Failed to send SMTP digest to %s: %s", request.user_email, err)
            status = "failed"
            note = f"SMTP dispatch failed: {str(err)}"
    else:
        logger.info("15-day digest for %s simulated (SMTP credentials not configured)", request.user_email)

    # 1. Record in database log
    try:
        resolved_idx = getattr(request, "user_index_id", None) or generate_user_index_id(request.user_email)
        log_entry = SecurityDigestLog(
            user_email=request.user_email,
            user_index_id=resolved_idx,
            period_start=request.period_start,
            period_end=request.period_end,
            total_emails=total_emails,
            threat_count=threat_count,
            click_count=click_count,
            dispatch_status=status,
            delivery_note=note
        )
        db.add(log_entry)
        await db.commit()
    except Exception as db_err:
        logger.warning("Could not persist SecurityDigestLog to database: %s", db_err)

    # 2. Automatically purge expired records older than 15 days from database
    purge_info = await purge_expired_15day_history(db, user_email=request.user_email, days=15)
    if purge_info.get("total_purged", 0) > 0:
        note += f" | Database: purged {purge_info['total_purged']} expired history records older than 15 days."

    return True, note, dispatch_mode, html_report, purge_info
