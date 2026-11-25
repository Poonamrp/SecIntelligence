import os
import streamlit as st
import json
import datetime
from sqlalchemy.orm import Session
from src.config import get_config
from src.models import Setting, Advisory, AdvisoryEvent
from src.services.email_service import EmailService
from src.services.outbox import get_effective_email_settings
from src.services.change_detection import is_baseline_mode, set_baseline_mode
from src.services.scheduler import get_configured_interval_minutes, reschedule_collection_job

def _save_setting(session: Session, key: str, value) -> None:
    setting = session.query(Setting).filter_by(key=key).first()
    if not setting:
        setting = Setting(key=key, value_json=json.dumps(value))
        session.add(setting)
    else:
        setting.value_json = json.dumps(value)
        setting.updated_at = datetime.datetime.utcnow()
    session.flush()

def render_settings(session: Session):
    st.title("⚙️ System Settings & Notifications")
    st.caption("Configure polling schedules, email alert policies, baseline mode, and verify SMTP connectivity.")

    cfg = get_config()

    # Section 1: Baseline Mode
    st.subheader("🎯 First-Run Baseline Mode")
    current_baseline = is_baseline_mode(session)
    st.write(
        "When **Baseline Mode is ON**, the monitor imports vulnerabilities from all sources without sending alert emails. "
        "This prevents inbox flooding during initial setup. Once satisfied with the initial imported baseline, "
        "turn Baseline Mode OFF to enable real-time alerts."
    )
    new_baseline = st.toggle("Enable Baseline Mode (Suppress Alert Emails)", value=current_baseline)
    if new_baseline != current_baseline:
        set_baseline_mode(session, new_baseline)
        session.commit()
        st.toast(f"Baseline mode updated to: {new_baseline}", icon="✅")
        st.rerun()

    st.markdown("---")

    # Section 1.5: Scheduler Interval
    st.subheader("⏱️ Background Scheduler Interval")
    current_interval = get_configured_interval_minutes()
    with st.form("scheduler_interval_form"):
        new_interval = st.number_input(
            "Check Interval (Minutes, minimum 5)",
            min_value=5,
            max_value=1440,
            value=current_interval,
            step=5,
            help="How often the background scheduler automatically polls all enabled threat sources."
        )
        if st.form_submit_button("💾 Save Schedule Interval"):
            _save_setting(session, "check_interval_minutes", int(new_interval))
            session.commit()
            reschedule_collection_job(int(new_interval))
            st.success(f"Scheduler updated! Automatic collection will now run every {int(new_interval)} minutes.")
            st.rerun()

    st.markdown("---")

    # Section 2: Alert Recipients & Policy
    st.subheader("🔔 Alert Policy & Recipients")
    effective_to, effective_policy = get_effective_email_settings(session)
    policy_options = ["IMMEDIATE_CRITICAL_KEV", "ALL_IMMEDIATE", "DISABLED"]
    policy_idx = policy_options.index(effective_policy) if effective_policy in policy_options else 0

    with st.form("email_policy_form"):
        new_to = st.text_input(
            "Alert Recipient Email(s) (comma-separated for multiple)",
            value=effective_to,
            placeholder="security@example.com, analyst@example.com"
        )
        new_policy = st.selectbox(
            "Email Notification Policy",
            policy_options,
            index=policy_idx,
            help=(
                "IMMEDIATE_CRITICAL_KEV: Immediate emails for Critical, Confirmed 0-day, and CISA KEV additions. "
                "ALL_IMMEDIATE: Email every new or updated advisory. "
                "DISABLED: Pause all outbound alert emails."
            )
        )
        if st.form_submit_button("💾 Save Alert Preferences"):
            _save_setting(session, "alert_to", new_to.strip())
            _save_setting(session, "email_notification_policy", new_policy)
            session.commit()
            st.success("Alert preferences saved!")
            st.rerun()

    st.markdown("---")

    # Section 3: SMTP Configuration & Verification
    st.subheader("📬 SMTP Configuration & Tester")
    smtp_ready = bool(cfg.smtp_host and cfg.smtp_username and cfg.smtp_password)
    if smtp_ready:
        st.success(f"SMTP Credentials loaded from `.env` (`{cfg.smtp_username}` via `{cfg.smtp_host}:{cfg.smtp_port}`)")
    else:
        st.warning(
            "SMTP credentials are not fully configured in `.env`. "
            "Set `SMTP_USERNAME`, `SMTP_PASSWORD` (Gmail App Password), and `ALERT_FROM` in your local `.env` file."
        )

    col_test1, col_test2, col_test3 = st.columns([2, 1, 1])
    with col_test1:
        test_recipient = st.text_input(
            "Send Test Verification Email To",
            value=effective_to.split(",")[0].strip() if effective_to else cfg.smtp_username
        )
    with col_test2:
        st.write("")
        st.write("")
        if st.button("📨 Send Test Email", type="primary", use_container_width=True):
            if not test_recipient:
                st.error("Please enter a recipient email address.")
            else:
                with st.spinner("Connecting to SMTP server and verifying TLS..."):
                    success, message = EmailService.send_test_email(recipient=test_recipient)
                    if success:
                        st.success(message)
                    else:
                        st.error(f"SMTP Test Failed:\n\n{message}")
    with col_test3:
        st.write("")
        st.write("")
        if st.button("🚨 Send Sample Alert", use_container_width=True, help="Sends a sample Critical/KEV HTML alert email"):
            if not test_recipient:
                st.error("Please enter a recipient email address.")
            else:
                with st.spinner("Sending sample Critical KEV alert email..."):
                    sample_adv = session.query(Advisory).filter_by(severity="Critical").first() or Advisory(
                        id=0,
                        stable_key="CVE-2024-0000",
                        cve_id="CVE-2024-0000",
                        title="Sample Critical Security Advisory (Test)",
                        description="This is a sample Critical advisory alert sent from Settings to preview formatting.",
                        canonical_url="https://nvd.nist.gov/",
                        severity="Critical",
                        cvss_score=9.8,
                        is_kev=True,
                        zero_day_status="NONE"
                    )
                    sample_ev = AdvisoryEvent(
                        id=0,
                        advisory_id=sample_adv.id or 0,
                        event_type="NEW",
                        new_hash="sample",
                        detected_at=datetime.datetime.utcnow()
                    )
                    subj, txt, html = EmailService.build_advisory_email(sample_ev, sample_adv)
                    try:
                        EmailService.send_raw_email(test_recipient, f"[SAMPLE] {subj}", txt, html)
                        st.success(f"Sample alert email sent to {test_recipient}!")
                    except Exception as exc:
                        st.error(f"Failed to send sample alert:\n\n{exc}")

    st.markdown("---")

    # Section 3.5: Company Logo Branding
    st.subheader("🏢 Company Logo Branding")
    assets_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "assets")
    os.makedirs(assets_dir, exist_ok=True)
    uploaded_logo = st.file_uploader("Upload Company Logo (PNG, JPG, WEBP)", type=["png", "jpg", "jpeg", "webp"])
    if uploaded_logo is not None:
        ext = uploaded_logo.name.rsplit(".", 1)[-1].lower()
        for old_ext in ("png", "jpg", "jpeg", "webp"):
            old_path = os.path.join(assets_dir, f"logo.{old_ext}")
            if os.path.exists(old_path):
                os.remove(old_path)
        save_path = os.path.join(assets_dir, f"logo.{ext}")
        with open(save_path, "wb") as f:
            f.write(uploaded_logo.getbuffer())
        st.success("Company logo saved! Refreshing dashboard...")
        st.rerun()

    existing_logos = [os.path.join(assets_dir, f"logo.{e}") for e in ("png", "jpg", "jpeg", "webp") if os.path.exists(os.path.join(assets_dir, f"logo.{e}"))]
    if existing_logos:
        if st.button("🗑️ Remove Company Logo"):
            for lp in existing_logos:
                os.remove(lp)
            st.success("Company logo removed.")
            st.rerun()

    st.markdown("---")

    # Section 4: Credentials Guide
    st.subheader("🔑 API & Service Credentials Guide")
    with st.expander("How to obtain free NVD, GitHub, and Gmail App Passwords"):
        st.markdown("""
        ### 1. Gmail SMTP & App Password (Required for Sending Emails)
        - **Why:** Standard Google passwords cannot be used directly with SMTP. Google requires an **App Password** when 2-Factor Authentication (2FA) is enabled.
        - **Get App Password:**
          1. Go to your [Google Account Security Settings](https://myaccount.google.com/security).
          2. Ensure **2-Step Verification** is enabled.
          3. Search for **"App passwords"** and create a 16-letter app password for `"Security Monitor"`.
        - **Add to `.env`:**
          ```ini
          SMTP_HOST=smtp.gmail.com
          SMTP_PORT=587
          SMTP_USERNAME=your_email@gmail.com
          SMTP_PASSWORD=your_16_character_app_password
          ALERT_FROM=your_email@gmail.com
          ALERT_TO=your_alerts_recipient@example.com
          ```

        ### 2. NVD API Key (Optional & Free)
        - **Why:** Increases NVD API rate limit from 5 requests/30s to 50 requests/30s.
        - **Get Key:** [https://nvd.nist.gov/developers/request-an-api-key](https://nvd.nist.gov/developers/request-an-api-key)
        - **Add to `.env`:** `NVD_API_KEY=your_key_here`

        ### 3. GitHub Personal Access Token (Optional & Free)
        - **Why:** Increases GitHub API rate limit from 60 requests/hour to 5,000 requests/hour.
        - **Get Token:** [https://github.com/settings/tokens](https://github.com/settings/tokens) (public read-only access only).
        - **Add to `.env`:** `GITHUB_TOKEN=your_token_here`
        """)
