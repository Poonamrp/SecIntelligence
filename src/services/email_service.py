import smtplib
import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Tuple, Optional, Dict, Any
from src.config import get_config
from src.models import Advisory, AdvisoryEvent
from src.utils.logging_config import get_logger

logger = get_logger("email_service")

class EmailService:
    """SMTP email service supporting TLS, rich HTML formatting, and test probes."""

    @staticmethod
    def get_smtp_connection():
        cfg = get_config()
        if not cfg.smtp_host or not cfg.smtp_port:
            raise ValueError("SMTP host and port must be configured.")
        
        server = smtplib.SMTP(cfg.smtp_host, cfg.smtp_port, timeout=20.0)
        server.ehlo()
        server.starttls()
        server.ehlo()
        if cfg.smtp_username and cfg.smtp_password:
            server.login(cfg.smtp_username, cfg.smtp_password)
        return server

    @classmethod
    def send_test_email(cls, recipient: Optional[str] = None) -> Tuple[bool, str]:
        """Validates SMTP connection and sends a verified probe email."""
        cfg = get_config()
        to_addr = recipient or cfg.alert_to or cfg.smtp_username
        from_addr = cfg.alert_from or cfg.smtp_username

        if not to_addr:
            return False, "No recipient address specified (check ALERT_TO or SMTP_USERNAME in .env)."
        if not from_addr:
            return False, "No sender address specified (check ALERT_FROM or SMTP_USERNAME in .env)."

        subject = "[TEST] Security Intelligence Monitor - SMTP Verification"
        body_text = (
            "This is a test notification from your Security Intelligence Monitor application.\n\n"
            f"Timestamp: {datetime.datetime.utcnow().isoformat()} UTC\n"
            "SMTP Configuration is active and verified.\n"
        )
        body_html = f"""
        <html>
        <body style="font-family: Arial, sans-serif; line-height: 1.5; color: #333;">
            <div style="background-color: #0f172a; color: #ffffff; padding: 16px; border-radius: 8px;">
                <h2 style="margin: 0; color: #38bdf8;">Security Intelligence Monitor</h2>
                <p style="margin: 4px 0 0 0; color: #94a3b8;">SMTP Configuration Verified</p>
            </div>
            <div style="padding: 16px; border: 1px solid #e2e8f0; border-radius: 8px; margin-top: 12px;">
                <p>This is a test notification confirming that SMTP email delivery is operational.</p>
                <p><strong>Sent at:</strong> {datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC</p>
            </div>
        </body>
        </html>
        """

        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = from_addr
        msg["To"] = to_addr
        msg.attach(MIMEText(body_text, "plain"))
        msg.attach(MIMEText(body_html, "html"))

        try:
            with cls.get_smtp_connection() as server:
                server.sendmail(from_addr, [to_addr], msg.as_string())
            logger.info(f"Test email successfully sent to {to_addr}")
            return True, f"Success! Verification email sent to {to_addr}."
        except Exception as exc:
            err_msg = f"SMTP connection or send failed: {str(exc)}"
            logger.error(err_msg, exc_info=True)
            return False, err_msg

    @classmethod
    def build_advisory_email(
        cls,
        event: AdvisoryEvent,
        advisory: Advisory
    ) -> Tuple[str, str, str]:
        """
        Builds compliant, rich security advisory notification subject,
        plain text body, and HTML body according to Product Requirements Section 9.
        """
        cve_tag = advisory.cve_id or advisory.ghsa_id or advisory.stable_key
        sev_tag = advisory.severity.upper()
        
        # Priority prefix
        if advisory.is_kev:
            priority_tag = "[CRITICAL KEV ALERT]"
        elif advisory.zero_day_status == "CONFIRMED_ZERO_DAY":
            priority_tag = "[0-DAY CONFIRMED ALERT]"
        elif advisory.severity == "Critical":
            priority_tag = "[CRITICAL VULNERABILITY]"
        elif advisory.severity == "High":
            priority_tag = "[HIGH SEVERITY]"
        else:
            priority_tag = f"[{sev_tag}]"

        subject = f"{priority_tag} {cve_tag}: {advisory.title[:80]}"

        # Parse products & references
        import json
        try:
            products = json.loads(advisory.affected_products_json or "[]")
        except Exception:
            products = []
        try:
            references = json.loads(advisory.references_json or "[]")
        except Exception:
            references = []

        products_str = ", ".join(products) if products else "Not specified"
        cvss_str = f"{advisory.cvss_score} (v{advisory.cvss_version or '3.1'})" if advisory.cvss_score is not None else "Unscored / Unknown"
        if advisory.cvss_vector:
            cvss_str += f" [{advisory.cvss_vector}]"

        kev_info = f"YES - Added {advisory.kev_date_added.strftime('%Y-%m-%d') if advisory.kev_date_added else 'Recently'}" if advisory.is_kev else "No (Not in CISA KEV)"
        zero_day_info = advisory.zero_day_status
        if advisory.zero_day_evidence_url:
            zero_day_info += f" (Evidence: {advisory.zero_day_evidence_url})"

        # Plain text body
        text_body = f"""=======================================================
SECURITY INTELLIGENCE ALERT: {cve_tag}
Event: {event.event_type} | Severity: {advisory.severity}
=======================================================

Title: {advisory.title}
Published: {advisory.published_at.strftime('%Y-%m-%d %H:%M:%S UTC') if advisory.published_at else 'Unknown'}
Detected: {event.detected_at.strftime('%Y-%m-%d %H:%M:%S UTC')}
Source: {advisory.source.name if advisory.source else 'Security Monitor'}

SEVERITY & THREAT METRICS:
- Severity: {advisory.severity}
- CVSS Score: {cvss_str}
- CISA KEV Listed: {kev_info}
- Zero-Day Status: {zero_day_info}

AFFECTED SYSTEMS / PACKAGES:
{products_str}

DESCRIPTION:
{advisory.description or advisory.summary or 'No description provided.'}

OFFICIAL ADVISORY & EVIDENCE:
Canonical URL: {advisory.canonical_url}
References:
{chr(10).join(['- ' + r for r in references[:10]])}

RECOMMENDED ACTION:
1. Verify applicability in your environment.
2. Review vendor remediation guidelines and workarounds.
3. Apply official security updates and patches as appropriate.

DISCLAIMER:
This intelligence alert is for defensive awareness only. Monitoring public feeds does not confirm whether your specific assets are affected.
"""

        # HTML body with clean styling
        badge_color = {
            "Critical": "#dc2626",
            "High": "#ea580c",
            "Medium": "#d97706",
            "Low": "#2563eb",
            "Unknown": "#64748b"
        }.get(advisory.severity, "#64748b")

        html_body = f"""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<style>
    body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; line-height: 1.6; color: #1e293b; background-color: #f8fafc; margin: 0; padding: 20px; }}
    .container {{ max-width: 680px; margin: 0 auto; background: #ffffff; border-radius: 8px; border: 1px solid #e2e8f0; overflow: hidden; box-shadow: 0 1px 3px rgba(0,0,0,0.05); }}
    .header {{ background-color: #0f172a; color: #ffffff; padding: 20px; }}
    .header h1 {{ margin: 0; font-size: 20px; color: #f8fafc; }}
    .badge {{ display: inline-block; padding: 4px 10px; border-radius: 4px; font-weight: bold; font-size: 13px; color: #ffffff; margin-top: 8px; background-color: {badge_color}; }}
    .kev-badge {{ display: inline-block; padding: 4px 10px; border-radius: 4px; font-weight: bold; font-size: 13px; color: #ffffff; margin-top: 8px; background-color: #b91c1c; margin-left: 6px; }}
    .content {{ padding: 24px; }}
    .meta-table {{ width: 100%; border-collapse: collapse; margin-bottom: 20px; font-size: 14px; }}
    .meta-table td {{ padding: 8px 12px; border-bottom: 1px solid #f1f5f9; }}
    .meta-label {{ font-weight: 600; color: #64748b; width: 35%; }}
    .action-box {{ background-color: #f0fdf4; border: 1px solid #bbf7d0; border-radius: 6px; padding: 16px; margin: 20px 0; color: #166534; }}
    .btn {{ display: inline-block; padding: 10px 18px; background-color: #0284c7; color: #ffffff; text-decoration: none; border-radius: 6px; font-weight: 500; font-size: 14px; }}
    .footer {{ background-color: #f8fafc; padding: 16px 24px; font-size: 12px; color: #94a3b8; border-top: 1px solid #e2e8f0; text-align: center; }}
</style>
</head>
<body>
<div class="container">
    <div class="header">
        <h1>{priority_tag} {cve_tag}</h1>
        <div>
            <span class="badge">{advisory.severity.upper()} SEVERITY</span>
            {"<span class='kev-badge'>CISA KEV - ACTIVELY EXPLOITED</span>" if advisory.is_kev else ""}
            {"<span class='kev-badge'>CONFIRMED 0-DAY</span>" if advisory.zero_day_status == 'CONFIRMED_ZERO_DAY' else ""}
        </div>
    </div>
    <div class="content">
        <h2 style="font-size: 18px; color: #0f172a; margin-top: 0;">{advisory.title}</h2>
        
        <table class="meta-table">
            <tr><td class="meta-label">Identifier</td><td><strong>{cve_tag}</strong></td></tr>
            <tr><td class="meta-label">CVSS Base Score</td><td>{cvss_str}</td></tr>
            <tr><td class="meta-label">Known Exploited (KEV)</td><td>{kev_info}</td></tr>
            <tr><td class="meta-label">Zero-Day Verification</td><td>{zero_day_info}</td></tr>
            <tr><td class="meta-label">Affected Products</td><td>{products_str}</td></tr>
            <tr><td class="meta-label">Source</td><td>{advisory.source.name if advisory.source else 'Public Source'}</td></tr>
            <tr><td class="meta-label">Detected Timestamp</td><td>{event.detected_at.strftime('%Y-%m-%d %H:%M:%S UTC')}</td></tr>
        </table>

        <h3 style="font-size: 15px; margin-bottom: 8px;">Description</h3>
        <p style="font-size: 14px; color: #334155; line-height: 1.6;">
            {advisory.description or advisory.summary or 'No detailed description available.'}
        </p>

        <div class="action-box">
            <strong>Recommended Next Steps:</strong>
            <ul style="margin: 8px 0 0 0; padding-left: 20px;">
                <li>Verify applicability of affected components in your environment.</li>
                <li>Consult vendor security advisory guidance.</li>
                <li>Test and deploy vendor patches or mitigations.</li>
            </ul>
        </div>

        <p style="margin-top: 24px;">
            <a href="{advisory.canonical_url}" class="btn" target="_blank" rel="noopener noreferrer">View Canonical Advisory &rarr;</a>
        </p>
    </div>
    <div class="footer">
        Security Intelligence Monitor &bull; Defensive Automation &bull; Strictly for awareness
    </div>
</div>
</body>
</html>"""

        return subject, text_body, html_body

    @classmethod
    def send_raw_email(cls, recipient: str, subject: str, text_body: str, html_body: Optional[str] = None) -> None:
        """Sends an email via SMTP with TLS; raises exception on any delivery failure."""
        cfg = get_config()
        from_addr = cfg.alert_from or cfg.smtp_username or "security-monitor@localhost"

        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = from_addr
        msg["To"] = recipient

        msg.attach(MIMEText(text_body, "plain", "utf-8"))
        if html_body:
            msg.attach(MIMEText(html_body, "html", "utf-8"))

        with cls.get_smtp_connection() as server:
            server.sendmail(from_addr, [recipient], msg.as_string())
