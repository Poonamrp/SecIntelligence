import os
import streamlit as st
from sqlalchemy.orm import Session
from src.models import CollectionRun, SourceRun, Source

def render_runs(session: Session):
    st.title("📈 Collection Runs & System Health")
    st.caption("Audit history of intelligence polling runs, per-source execution details, and live service logs.")

    runs = session.query(CollectionRun).order_by(CollectionRun.started_at.desc()).limit(30).all()

    if not runs:
        st.info("No collection cycles have been logged yet.")
        return

    # Runs History Table
    runs_table = []
    for r in runs:
        status_icon = "🟢" if r.status == "COMPLETED" else "🟡" if r.status == "PARTIAL" else "🔴"
        duration = "-"
        if r.finished_at and r.started_at:
            secs = int((r.finished_at - r.started_at).total_seconds())
            duration = f"{secs}s"

        runs_table.append({
            "Run ID": r.id,
            "Status": f"{status_icon} {r.status}",
            "Started (UTC)": r.started_at.strftime("%Y-%m-%d %H:%M:%S"),
            "Duration": duration,
            "Records Seen": r.records_seen,
            "New": r.records_new,
            "Updated": r.records_updated,
            "Errors": r.errors_count,
            "Summary": r.summary or "-"
        })

    st.dataframe(runs_table, use_container_width=True, hide_index=True)

    # Per-source breakdown for selected run
    st.markdown("---")
    st.subheader("🔍 Run Diagnostics & Source Breakdown")
    selected_run_id = st.selectbox("Select Run ID to Inspect", [r.id for r in runs])

    if selected_run_id:
        source_runs = session.query(SourceRun).filter_by(run_id=selected_run_id).all()
        if source_runs:
            s_data = []
            for sr in source_runs:
                s_name = sr.source.name if sr.source else f"Source #{sr.source_id}"
                s_icon = "✅" if sr.status == "SUCCESS" else "❌"
                s_data.append({
                    "Source": s_name,
                    "Status": f"{s_icon} {sr.status}",
                    "Records Seen": sr.records_seen,
                    "Started At": sr.started_at.strftime("%H:%M:%S") if sr.started_at else "-",
                    "Finished At": sr.finished_at.strftime("%H:%M:%S") if sr.finished_at else "-",
                    "Error Message": sr.error_message or "None"
                })
            st.dataframe(s_data, use_container_width=True, hide_index=True)

    # Live Log Viewer
    st.markdown("---")
    st.subheader("📜 Application Operational Logs")
    log_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "logs", "security_monitor.log")
    
    if os.path.exists(log_path):
        try:
            with open(log_path, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()
            recent_logs = "".join(lines[-80:])
            st.text_area("Tail of logs/security_monitor.log (Secrets automatically redacted)", recent_logs, height=300)
        except Exception as exc:
            st.error(f"Error reading log file: {exc}")
    else:
        st.info("Log file will be created on initial collection activity.")
