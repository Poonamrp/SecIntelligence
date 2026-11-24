import streamlit as st
import datetime
from sqlalchemy.orm import Session
from src.models import Advisory, AdvisoryEvent, CollectionRun, Source
from src.services.change_detection import is_baseline_mode, set_baseline_mode
from src.services.scheduler import is_run_in_progress, trigger_run_now, get_scheduler

def render_overview(session: Session):
    st.title("🛡️ Security Intelligence Monitor")
    st.caption("Automated Vulnerability Intelligence, KEV Tracking, and Alert Center")

    # Baseline Mode Banner
    baseline_active = is_baseline_mode(session)
    if baseline_active:
        st.warning(
            "⚠️ **Baseline Mode is ACTIVE**: The monitor is collecting historical intelligence without sending alert emails. "
            "Once baseline collection is complete, click **Enable Notifications** to start receiving alerts for new/updated items."
        )
        col_b1, col_b2 = st.columns([3, 1])
        with col_b2:
            if st.button("🔔 Enable Notifications", use_container_width=True, type="primary"):
                set_baseline_mode(session, False)
                st.success("Notifications enabled! You will now receive alert emails for new/updated vulnerabilities.")
                st.rerun()

    # KPI Metrics Bar
    total_adv = session.query(Advisory).count()
    crit_count = session.query(Advisory).filter_by(severity="Critical").count()
    high_count = session.query(Advisory).filter_by(severity="High").count()
    kev_count = session.query(Advisory).filter_by(is_kev=True).count()
    zero_day_conf = session.query(Advisory).filter_by(zero_day_status="CONFIRMED_ZERO_DAY").count()
    zero_day_sig = session.query(Advisory).filter_by(zero_day_status="UNVERIFIED_SIGNAL").count()

    kpi1, kpi2, kpi3, kpi4, kpi5, kpi6 = st.columns(6)
    kpi1.metric("Total Advisories", f"{total_adv:,}")
    kpi2.metric("Critical", f"{crit_count:,}", delta_color="inverse")
    kpi3.metric("High", f"{high_count:,}")
    kpi4.metric("CISA KEV", f"{kev_count:,}", help="Vulnerabilities actively exploited in the wild")
    kpi5.metric("Confirmed 0-Day", f"{zero_day_conf:,}", help="Authoritatively verified zero-day exploitation")
    kpi6.metric("0-Day Signals", f"{zero_day_sig:,}", help="Unverified keyword mentions requiring review")

    st.markdown("---")

    # Collection Health & Execution Controls
    col_ctrl, col_health = st.columns([1, 2])
    
    with col_ctrl:
        st.subheader("⚡ Collection Controls")
        running = is_run_in_progress()
        if running:
            st.info("🔄 Collection run currently in progress...")
        else:
            if st.button("▶️ Run Collection Now", use_container_width=True, type="primary"):
                trigger_run_now()
                st.toast("Triggered manual collection cycle!", icon="🚀")
                st.rerun()

        # Scheduler Next Run Info
        sched = get_scheduler()
        if sched and sched.running:
            job = sched.get_job("hourly_threat_collection")
            next_run = job.next_run_time.strftime("%Y-%m-%d %H:%M:%S") if job and job.next_run_time else "Scheduled"
            st.write(f"⏱️ **Next Scheduled Run:** `{next_run}`")
        else:
            st.write("⏱️ **Scheduler:** Background service running")

    with col_health:
        st.subheader("📊 System Health")
        last_run = session.query(CollectionRun).order_by(CollectionRun.started_at.desc()).first()
        if last_run:
            status_color = "green" if last_run.status == "COMPLETED" else "orange" if last_run.status == "PARTIAL" else "red"
            st.markdown(
                f"- **Last Run Status:** :{status_color}[**{last_run.status}**]\n"
                f"- **Completed At:** `{last_run.finished_at.strftime('%Y-%m-%d %H:%M:%S UTC') if last_run.finished_at else 'In progress'}`\n"
                f"- **Records Seen:** `{last_run.records_seen}` (`{last_run.records_new}` new, `{last_run.records_updated}` updated)\n"
                f"- **Errors:** `{last_run.errors_count}`"
            )
        else:
            st.info("No collection cycles have been completed yet. Click 'Run Collection Now' to perform your first baseline collection.")

    st.markdown("---")

    # Recent Security Events
    st.subheader("🚨 Recent Intelligence Events")
    recent_events = (
        session.query(AdvisoryEvent)
        .order_by(AdvisoryEvent.detected_at.desc())
        .limit(10)
        .all()
    )

    if not recent_events:
        st.write("No intelligence events detected yet. Records imported during baseline mode do not emit alert events.")
    else:
        events_data = []
        for ev in recent_events:
            adv = ev.advisory
            events_data.append({
                "Detected (UTC)": ev.detected_at.strftime("%Y-%m-%d %H:%M"),
                "Event Type": ev.event_type,
                "Identifier": adv.cve_id or adv.ghsa_id or adv.stable_key if adv else "Unknown",
                "Severity": adv.severity if adv else "Unknown",
                "Title": adv.title[:70] if adv else "Unknown",
                "CISA KEV": "YES" if (adv and adv.is_kev) else "No",
                "0-Day": adv.zero_day_status if adv else "NONE"
            })
        st.dataframe(events_data, use_container_width=True)
