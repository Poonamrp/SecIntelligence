import streamlit as st
import json
import datetime
from sqlalchemy.orm import Session
from src.config import get_config
from src.models import Setting
from src.services.email_service import EmailService
from src.services.change_detection import is_baseline_mode, set_baseline_mode

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
        st.toast(f"Baseline mode updated to: {new_baseline}", icon="✅")
        st.rerun()

    st.markdown("---")

    # Section 2: SMTP Configuration & Verification
    st.subheader("📬 SMTP Notification Tester")
    st.markdown(
        f"- **SMTP Host:** `{cfg.smtp_host}:{cfg.smtp_port}`\n"
        f"- **SMTP Username:** `{cfg.smtp_username or 'Not set'}`\n"
        f"- **Sender (ALERT_FROM):** `{cfg.alert_from or 'Not set'}`\n"
        f"- **Alert Recipient (ALERT_TO):** `{cfg.alert_to or 'Not set'}`\n"
        f"- **Active Policy:** `{cfg.email_notification_policy}`"
    )

    col_test1, col_test2 = st.columns([2, 1])
    with col_test1:
        test_recipient = st.text_input("Send Test Verification Email To", value=cfg.alert_to or cfg.smtp_username)
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

    st.markdown("---")

    # Section 3: Credentials Guide
    st.subheader("🔑 API & Service Credentials Guide")
    with st.expander("How to obtain free NVD, GitHub, and Gmail App Passwords"):
        st.markdown("""
        ### 1. NVD API Key (Free)
        - **Why:** The National Vulnerability Database allows public requests, but rate limits unauthenticated clients to 5 requests per 30 seconds. A free API key increases this limit to 50 requests per 30 seconds.
        - **Get Key:** Request a free key at [https://nvd.nist.gov/developers/request-an-api-key](https://nvd.nist.gov/developers/request-an-api-key)
        - **Add to .env:** `NVD_API_KEY=your_key_here`

        ### 2. GitHub Personal Access Token (Free)
        - **Why:** Increases public API rate limits from 60 requests/hour to 5,000 requests/hour.
        - **Get Token:** Go to [GitHub Settings &rarr; Tokens](https://github.com/settings/tokens) and generate a classic or fine-grained token with **public read-only** access (no repository write scopes needed).
        - **Add to .env:** `GITHUB_TOKEN=your_token_here`

        ### 3. Gmail SMTP & App Password
        - **Why:** Standard Google passwords cannot be used directly with SMTP. Google requires an **App Password** when 2-Factor Authentication (2FA) is enabled.
        - **Get App Password:**
          1. Go to your [Google Account Security Settings](https://myaccount.google.com/security).
          2. Ensure 2-Step Verification is enabled.
          3. Search for "App Passwords" and create a 16-letter app password for "Security Monitor".
        - **Add to .env:**
          ```ini
          SMTP_HOST=smtp.gmail.com
          SMTP_PORT=587
          SMTP_USERNAME=your_email@gmail.com
          SMTP_PASSWORD=your_16_character_app_password
          ALERT_FROM=your_email@gmail.com
          ALERT_TO=your_alerts_recipient@example.com
          ```
        """)
