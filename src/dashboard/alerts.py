import streamlit as st
import datetime
from sqlalchemy.orm import Session
from src.models import EmailOutbox
from src.services.outbox import process_outbox

def render_alerts(session: Session):
    st.title("📧 Alert Notification Outbox")
    st.caption("Inspect pending, sent, and failed security alert emails. Durable delivery with automatic retry.")

    # Status counts
    total_emails = session.query(EmailOutbox).count()
    sent_count = session.query(EmailOutbox).filter_by(status="SENT").count()
    pending_count = session.query(EmailOutbox).filter_by(status="PENDING").count()
    failed_count = session.query(EmailOutbox).filter_by(status="FAILED").count()

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Total Generated", total_emails)
    c2.metric("Sent", sent_count)
    c3.metric("Pending", pending_count)
    c4.metric("Failed / Retrying", failed_count, delta_color="inverse")

    st.markdown("---")

    col_btn, col_filter, col_date = st.columns([1, 1, 1.5])
    with col_btn:
        st.write("")
        if st.button("🔄 Retry Failed Now", use_container_width=True, type="primary"):
            failed_items = session.query(EmailOutbox).filter(EmailOutbox.status == "FAILED").all()
            for it in failed_items:
                it.status = "PENDING"
                it.attempts = 0
                it.next_attempt_at = datetime.datetime.utcnow()
            session.flush()
            sent = process_outbox(session)
            session.commit()
            st.toast(f"Retried outbox: {sent} emails sent!", icon="📨")
            st.rerun()

    with col_filter:
        status_filter = st.selectbox("Filter Status", ["All", "PENDING", "SENT", "FAILED"])

    with col_date:
        date_filter = st.selectbox("Filter by Date", ["All Dates", "Today", "Last 7 Days", "Last 30 Days", "Custom Date"])

    start_dt, end_dt = None, None
    today = datetime.date.today()
    if date_filter == "Today":
        start_dt = datetime.datetime.combine(today, datetime.time.min)
        end_dt = datetime.datetime.combine(today, datetime.time.max)
    elif date_filter == "Last 7 Days":
        start_dt = datetime.datetime.combine(today - datetime.timedelta(days=7), datetime.time.min)
        end_dt = datetime.datetime.combine(today, datetime.time.max)
    elif date_filter == "Last 30 Days":
        start_dt = datetime.datetime.combine(today - datetime.timedelta(days=30), datetime.time.min)
        end_dt = datetime.datetime.combine(today, datetime.time.max)
    elif date_filter == "Custom Date":
        c_d1, c_d2 = st.columns(2)
        with c_d1:
            d_from = st.date_input("From", value=today - datetime.timedelta(days=7), key="alert_d_from")
            start_dt = datetime.datetime.combine(d_from, datetime.time.min)
        with c_d2:
            d_to = st.date_input("To", value=today, key="alert_d_to")
            end_dt = datetime.datetime.combine(d_to, datetime.time.max)

    query = session.query(EmailOutbox)
    if status_filter != "All":
        query = query.filter(EmailOutbox.status == status_filter)
    if start_dt is not None:
        query = query.filter(EmailOutbox.created_at >= start_dt)
    if end_dt is not None:
        query = query.filter(EmailOutbox.created_at <= end_dt)

    items = query.order_by(EmailOutbox.created_at.desc()).limit(100).all()

    if not items:
        st.info("No emails found matching the filter.")
        return

    table_data = []
    for it in items:
        table_data.append({
            "ID": it.id,
            "Status": "🟢 SENT" if it.status == "SENT" else "⏳ PENDING" if it.status == "PENDING" else "❌ FAILED",
            "Recipient": it.recipient,
            "Subject": it.subject[:65],
            "Attempts": f"{it.attempts}/5",
            "Next Attempt": it.next_attempt_at.strftime("%H:%M:%S") if it.status != "SENT" else "-",
            "Created At": it.created_at.strftime("%Y-%m-%d %H:%M"),
            "Error": it.last_error[:40] if it.last_error else "-"
        })

    st.dataframe(table_data, use_container_width=True, hide_index=True)

    # Email Content Previewer
    st.markdown("---")
    st.subheader("✉️ Email Content Previewer")
    selected_id = st.selectbox("Select email to view content", [it.id for it in items], format_func=lambda x: f"Email #{x} - {next((i.subject[:60] for i in items if i.id == x), str(x))}")

    if selected_id:
        target = session.query(EmailOutbox).filter_by(id=selected_id).first()
        if target:
            st.write(f"**To:** `{target.recipient}` &bull; **Status:** `{target.status}` &bull; **Attempts:** `{target.attempts}`")
            if target.last_error:
                st.error(f"**Delivery Error:** {target.last_error}")
            
            tab_html, tab_text = st.tabs(["Rendered HTML Preview", "Plain Text Payload"])
            with tab_html:
                if target.body_html:
                    st.components.v1.html(target.body_html, height=500, scrolling=True)
                else:
                    st.info("No HTML version available.")
            with tab_text:
                st.code(target.body, language="text")
