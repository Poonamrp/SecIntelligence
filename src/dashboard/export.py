import streamlit as st
import pandas as pd
from sqlalchemy.orm import Session
from src.models import Advisory, AdvisoryEvent

def render_export(session: Session):
    st.title("📥 Data Export Center")
    st.caption("Export filtered vulnerability records and intelligence change events as standard CSV spreadsheets.")

    tab1, tab2 = st.tabs(["Export Advisories", "Export Intelligence Events"])

    with tab1:
        st.subheader("Export Vulnerability Records")
        sev_choice = st.multiselect("Filter Severities", ["Critical", "High", "Medium", "Low", "Unknown"], default=["Critical", "High", "Medium"])
        kev_only = st.checkbox("CISA KEV Only", value=False)
        limit_rows = st.number_input("Max Records to Export", min_value=10, max_value=50000, value=1000)

        query = session.query(Advisory)
        if sev_choice:
            query = query.filter(Advisory.severity.in_(sev_choice))
        if kev_only:
            query = query.filter(Advisory.is_kev == True)

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
                    "canonical_url": r.canonical_url,
                    "published_at": r.published_at.strftime("%Y-%m-%d %H:%M:%S") if r.published_at else "",
                    "first_seen_at": r.first_seen_at.strftime("%Y-%m-%d %H:%M:%S") if r.first_seen_at else ""
                })

            df = pd.DataFrame(data)
            csv_data = df.to_csv(index=False).encode("utf-8")
            st.download_button(
                label="📥 Download Advisories CSV",
                data=csv_data,
                file_name="security_intelligence_advisories.csv",
                mime="text/csv",
                type="primary"
            )

    with tab2:
        st.subheader("Export Intelligence Events & Diffs")
        event_limit = st.number_input("Max Events to Export", min_value=10, max_value=50000, value=500)
        events = session.query(AdvisoryEvent).order_by(AdvisoryEvent.detected_at.desc()).limit(event_limit).all()
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
                    "changes": e.changes_json or ""
                })
            df_ev = pd.DataFrame(ev_data)
            csv_ev = df_ev.to_csv(index=False).encode("utf-8")
            st.download_button(
                label="📥 Download Events CSV",
                data=csv_ev,
                file_name="security_intelligence_events.csv",
                mime="text/csv",
                type="primary"
            )
