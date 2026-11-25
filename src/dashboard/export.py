import datetime
import streamlit as st
import pandas as pd
from sqlalchemy.orm import Session
from src.models import Advisory, AdvisoryEvent

def _render_date_filter(key_prefix: str):
    """Shared date range selector returning (start_dt, end_dt) or (None, None)."""
    col_p, col_s, col_e = st.columns([1.5, 1, 1])
    with col_p:
        preset = st.selectbox(
            "Date Range",
            ["All Time", "Last 24 Hours", "Last 7 Days", "Last 30 Days", "Custom Range"],
            key=f"{key_prefix}_preset"
        )
    today = datetime.date.today()
    start_date, end_date = None, None
    if preset == "Last 24 Hours":
        start_date, end_date = today - datetime.timedelta(days=1), today
    elif preset == "Last 7 Days":
        start_date, end_date = today - datetime.timedelta(days=7), today
    elif preset == "Last 30 Days":
        start_date, end_date = today - datetime.timedelta(days=30), today
    elif preset == "Custom Range":
        with col_s:
            start_date = st.date_input("From Date", value=today - datetime.timedelta(days=7), key=f"{key_prefix}_start")
        with col_e:
            end_date = st.date_input("To Date", value=today, key=f"{key_prefix}_end")

    start_dt = datetime.datetime.combine(start_date, datetime.time.min) if start_date else None
    end_dt = datetime.datetime.combine(end_date, datetime.time.max) if end_date else None
    return start_dt, end_dt

def render_export(session: Session):
    st.title("📥 Data Export Center")
    st.caption("Export filtered vulnerability records and intelligence change events by date and severity as CSV spreadsheets.")

    tab1, tab2 = st.tabs(["Export Advisories", "Export Intelligence Events"])

    with tab1:
        st.subheader("Export Vulnerability Records")
        sev_choice = st.multiselect("Filter Severities", ["Critical", "High", "Medium", "Low", "Unknown"], default=["Critical", "High", "Medium"])
        col_kev, col_lim = st.columns([1, 1])
        with col_kev:
            kev_only = st.checkbox("CISA KEV Only", value=False)
        with col_lim:
            limit_rows = st.number_input("Max Records to Export", min_value=10, max_value=50000, value=1000)

        start_dt, end_dt = _render_date_filter("adv_export")

        query = session.query(Advisory)
        if sev_choice:
            query = query.filter(Advisory.severity.in_(sev_choice))
        if kev_only:
            query = query.filter(Advisory.is_kev == True)
        if start_dt is not None:
            query = query.filter(Advisory.published_at >= start_dt)
        if end_dt is not None:
            query = query.filter(Advisory.published_at <= end_dt)

        records = query.order_by(Advisory.published_at.desc().nullslast()).limit(limit_rows).all()
        st.write(f"Matched **{len(records)}** records ready for export.")

        if records:
            data = []
            for r in records:
                data.append({
                    "stable_key": r.stable_key,
                    "cve_id": r.cve_id,
                    "ghsa_id": r.ghsa_id,
                    "title": r.title,
                    "severity": r.severity,
                    "cvss_score": r.cvss_score,
                    "cvss_vector": r.cvss_vector,
                    "is_kev": r.is_kev,
                    "kev_date_added": r.kev_date_added.strftime("%Y-%m-%d") if r.kev_date_added else "",
                    "zero_day_status": r.zero_day_status,
                    "source": r.source.name if r.source else "",
                    "canonical_url": r.canonical_url,
                    "published_at": r.published_at.strftime("%Y-%m-%d %H:%M:%S") if r.published_at else "",
                    "first_seen_at": r.first_seen_at.strftime("%Y-%m-%d %H:%M:%S") if r.first_seen_at else ""
                })

            df = pd.DataFrame(data)
            csv_data = df.to_csv(index=False).encode("utf-8")
            st.download_button(
                label="📥 Download Advisories CSV",
                data=csv_data,
                file_name=f"security_advisories_{datetime.date.today().isoformat()}.csv",
                mime="text/csv",
                type="primary"
            )

    with tab2:
        st.subheader("Export Intelligence Events & Diffs")
        event_limit = st.number_input("Max Events to Export", min_value=10, max_value=50000, value=500)
        ev_start_dt, ev_end_dt = _render_date_filter("ev_export")

        ev_query = session.query(AdvisoryEvent)
        if ev_start_dt is not None:
            ev_query = ev_query.filter(AdvisoryEvent.detected_at >= ev_start_dt)
        if ev_end_dt is not None:
            ev_query = ev_query.filter(AdvisoryEvent.detected_at <= ev_end_dt)

        events = ev_query.order_by(AdvisoryEvent.detected_at.desc()).limit(event_limit).all()
        st.write(f"Matched **{len(events)}** intelligence events.")

        if events:
            ev_data = []
            for e in events:
                adv = e.advisory
                ev_data.append({
                    "event_id": e.id,
                    "detected_at": e.detected_at.strftime("%Y-%m-%d %H:%M:%S"),
                    "event_type": e.event_type,
                    "identifier": adv.cve_id or adv.ghsa_id or adv.stable_key if adv else "",
                    "severity": adv.severity if adv else "",
                    "is_kev": adv.is_kev if adv else False,
                    "canonical_url": adv.canonical_url if adv else "",
                    "changes": e.changes_json or ""
                })
            df_ev = pd.DataFrame(ev_data)
            csv_ev = df_ev.to_csv(index=False).encode("utf-8")
            st.download_button(
                label="📥 Download Events CSV",
                data=csv_ev,
                file_name=f"security_events_{datetime.date.today().isoformat()}.csv",
                mime="text/csv",
                type="primary"
            )
