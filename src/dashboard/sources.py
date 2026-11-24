import streamlit as st
import json
from sqlalchemy.orm import Session
from src.models import Source, Advisory
from src.collectors import get_collector_for_source
from src.services.scheduler import execute_collection_cycle

def render_sources(session: Session):
    st.title("🌐 Advisory Sources Registry")
    st.caption("Manage threat intelligence feeds, inspect polling health, test connectivity, and add custom sources.")

    sources = session.query(Source).order_by(Source.name.asc()).all()

    # Source Summary Metrics
    total_sources = len(sources)
    enabled_sources = sum(1 for s in sources if s.enabled)
    failed_sources = sum(1 for s in sources if s.last_error is not None)

    m1, m2, m3 = st.columns(3)
    m1.metric("Configured Sources", total_sources)
    m2.metric("Active & Enabled", enabled_sources)
    m3.metric("Sources with Errors", failed_sources, delta_color="inverse")

    st.markdown("---")

    # Sources Table & Controls
    st.subheader("Configured Threat Feeds")

    for src in sources:
        with st.container():
            col_info, col_status, col_btn = st.columns([3, 2, 2])
            
            with col_info:
                st.markdown(f"**{src.name}** `({src.source_type.upper()})`")
                st.caption(src.url)

            with col_status:
                adv_count = session.query(Advisory).filter_by(source_id=src.id).count()
                status_badge = "🟢 Enabled" if src.enabled else "⚪ Disabled"
                st.write(f"{status_badge} &bull; **{adv_count}** advisories")
                if src.last_success_at:
                    st.caption(f"Last success: {src.last_success_at.strftime('%Y-%m-%d %H:%M')}")
                if src.last_error:
                    st.caption(f":red[Error: {src.last_error[:60]}...]")

            with col_btn:
                b1, b2, b3 = st.columns(3)
                # Toggle enabled
                toggle_label = "Disable" if src.enabled else "Enable"
                if b1.button(toggle_label, key=f"tog_{src.id}"):
                    src.enabled = not src.enabled
                    session.flush()
                    st.rerun()

                # Test Connection
                if b2.button("Test", key=f"tst_{src.id}", help="Verify endpoint accessibility"):
                    try:
                        conf = json.loads(src.config_json or "{}")
                        collector = get_collector_for_source(src.name, src.source_type, src.url, conf)
                        result = collector.test_connection()
                        if result["success"]:
                            st.toast(f"{src.name}: {result['message']}", icon="✅")
                        else:
                            st.toast(f"{src.name}: {result['message']}", icon="❌")
                    except Exception as exc:
                        st.toast(f"Test error: {exc}", icon="❌")

                # Collect Now
                if b3.button("Poll", key=f"pol_{src.id}", help="Collect from this source now"):
                    execute_collection_cycle(is_manual=True, target_source_id=src.id)
                    st.toast(f"Polled {src.name}!", icon="📥")
                    st.rerun()

        st.markdown("<hr style='margin: 8px 0; border: none; border-top: 1px solid #f1f5f9;'>", unsafe_allow_html=True)

    # Add Source Section
    st.markdown("---")
    with st.expander("➕ Add New Threat Intelligence Source"):
        with st.form("add_source_form"):
            new_name = st.text_input("Source Name", placeholder="e.g. My Vendor Security RSS")
            new_type = st.selectbox("Source Type", ["rss", "api", "html"])
            new_url = st.text_input("Feed / API URL", placeholder="https://example.com/security.xml")
            new_enabled = st.checkbox("Enable immediately", value=True)
            new_config = st.text_area("Optional Config JSON", value="{}")

            submitted = st.form_submit_button("Save Source")
            if submitted:
                if not new_name or not new_url:
                    st.error("Name and URL are required.")
                else:
                    try:
                        # Validate URL
                        if not new_url.startswith("http://") and not new_url.startswith("https://"):
                            st.error("URL must start with http:// or https://")
                        else:
                            src_new = Source(
                                name=new_name.strip(),
                                source_type=new_type,
                                url=new_url.strip(),
                                enabled=new_enabled,
                                config_json=new_config
                            )
                            session.add(src_new)
                            session.flush()
                            st.success(f"Source '{new_name}' added successfully!")
                            st.rerun()
                    except Exception as exc:
                        st.error(f"Error adding source: {exc}")
