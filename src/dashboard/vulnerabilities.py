import streamlit as st
import json
from sqlalchemy.orm import Session
from src.models import Advisory, Source, AdvisoryEvent

def render_vulnerabilities(session: Session):
    st.title("🔍 Vulnerabilities Explorer")
    st.caption("Search, filter, and inspect normalized security advisories with verifiable source evidence.")

    # Search & Filter Controls
    sources = session.query(Source).order_by(Source.name.asc()).all()
    source_names = ["All Sources"] + [s.name for s in sources]

    col_search, col_src, col_sev, col_kev = st.columns([3, 2, 1, 1])
    with col_search:
        search_query = st.text_input("Search (URL, CVE ID, Keyword, Vendor, Product)", placeholder="e.g. cisco.com, CVE-2024, https://...")
    with col_src:
        src_filter = st.selectbox("Source Feed / URL", source_names)
    with col_sev:
        sev_filter = st.selectbox("Severity", ["All", "Critical", "High", "Medium", "Low", "Unknown"])
    with col_kev:
        kev_filter = st.selectbox("CISA KEV", ["All", "KEV Only", "Non-KEV"])

    # Query Builder
    query = session.query(Advisory)

    if search_query:
        term = f"%{search_query.strip()}%"
        query = query.filter(
            (Advisory.canonical_url.ilike(term)) |
            (Advisory.references_json.ilike(term)) |
            (Advisory.affected_products_json.ilike(term)) |
            (Advisory.cve_id.ilike(term)) |
            (Advisory.ghsa_id.ilike(term)) |
            (Advisory.title.ilike(term)) |
            (Advisory.description.ilike(term))
        )

    if src_filter != "All Sources":
        query = query.filter(Advisory.source.has(name=src_filter))

    if sev_filter != "All":
        query = query.filter(Advisory.severity == sev_filter)

    if kev_filter == "KEV Only":
        query = query.filter(Advisory.is_kev == True)
    elif kev_filter == "Non-KEV":
        query = query.filter(Advisory.is_kev == False)

    # Count & Pagination
    total_matches = query.count()
    st.write(f"Showing **{min(50, total_matches)}** of **{total_matches}** matched advisories")

    advisories = query.order_by(Advisory.published_at.desc().nullslast()).limit(50).all()

    if not advisories:
        st.info("No advisories match the selected filters.")
        return

    # Table View
    table_rows = []
    for a in advisories:
        table_rows.append({
            "ID": a.id,
            "Identifier": a.cve_id or a.ghsa_id or a.stable_key,
            "Severity": a.severity,
            "CVSS": a.cvss_score if a.cvss_score is not None else "-",
            "KEV": "🔥 YES" if a.is_kev else "No",
            "Source": a.source.name if a.source else "External",
            "Title": a.title[:70],
            "URL": a.canonical_url,
            "Published": a.published_at.strftime("%Y-%m-%d") if a.published_at else "Unknown"
        })

    st.dataframe(table_rows, use_container_width=True, hide_index=True)

    # Detailed Inspector
    st.markdown("---")
    st.subheader("📖 Advisory Detail Inspector")
    
    advisory_ids = [a.id for a in advisories]
    selected_id = st.selectbox(
        "Select Advisory to Inspect",
        advisory_ids,
        format_func=lambda aid: next((f"{a.cve_id or a.stable_key} - {a.title[:60]}" for a in advisories if a.id == aid), str(aid))
    )

    if selected_id:
        target = session.query(Advisory).filter_by(id=selected_id).first()
        if target:
            c1, c2 = st.columns([2, 1])
            with c1:
                st.markdown(f"### {target.cve_id or target.stable_key}")
                st.write(f"**Title:** {target.title}")
                st.markdown(f"**Canonical Advisory:** [{target.canonical_url}]({target.canonical_url})")
                st.markdown(f"**Description:**\n{target.description or target.summary or 'No description provided.'}")

                try:
                    products = json.loads(target.affected_products_json or "[]")
                    if products:
                        st.markdown("**Affected Products / Packages:**")
                        st.write(", ".join(products[:15]))
                except Exception:
                    pass

            with c2:
                st.markdown("#### Attributes & Evidence")
                st.metric("Severity", target.severity)
                st.metric("CVSS Score", target.cvss_score if target.cvss_score is not None else "Unscored")
                st.write(f"- **Vector:** `{target.cvss_vector or 'N/A'}`")
                st.write(f"- **CISA KEV:** {'Yes (Added ' + target.kev_date_added.strftime('%Y-%m-%d') + ')' if target.is_kev and target.kev_date_added else 'Yes' if target.is_kev else 'No'}")
                st.write(f"- **Zero-Day Status:** `{target.zero_day_status}`")
                if target.zero_day_evidence_url:
                    st.write(f"- **Zero-Day Evidence:** [{target.zero_day_evidence_url}]({target.zero_day_evidence_url})")
                st.write(f"- **Published:** `{target.published_at or 'N/A'}`")
                st.write(f"- **Last Updated:** `{target.modified_at or 'N/A'}`")
                st.write(f"- **Content Hash:** `{target.content_hash[:16]}...`")

            # Change History Timeline
            events = session.query(AdvisoryEvent).filter_by(advisory_id=target.id).order_by(AdvisoryEvent.detected_at.desc()).all()
            if events:
                with st.expander(f"📜 Change & Event History ({len(events)} events)"):
                    for ev in events:
                        st.write(f"**{ev.event_type}** at `{ev.detected_at.strftime('%Y-%m-%d %H:%M:%S UTC')}`")
                        if ev.changes_json:
                            st.json(json.loads(ev.changes_json))

            # Raw Data Snapshot
            if target.raw_data_json:
                with st.expander("🔍 Raw Source Snapshot (Audit Payload)"):
                    st.json(json.loads(target.raw_data_json))
