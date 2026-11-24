import streamlit as st
from src.database import init_db, get_db_session
from src.utils.logging_config import setup_logging
from src.services.scheduler import start_scheduler, is_run_in_progress, trigger_run_now, seed_sources_if_empty
from src.services.change_detection import is_baseline_mode
from src.dashboard.overview import render_overview
from src.dashboard.vulnerabilities import render_vulnerabilities
from src.dashboard.sources import render_sources
from src.dashboard.alerts import render_alerts
from src.dashboard.runs import render_runs
from src.dashboard.settings import render_settings
from src.dashboard.export import render_export

# Initialize Streamlit Page Config
st.set_page_config(
    page_title="Security Intelligence Monitor",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Initialize logging and database schema
setup_logging()
init_db()

# Auto-start persistent APScheduler background job once per server process
@st.cache_resource
def start_background_service():
    sched = start_scheduler()
    with get_db_session() as session:
        seed_sources_if_empty(session)
    return sched

start_background_service()

# Sidebar Navigation
st.sidebar.markdown("## 🛡️ SecIntelligence")
st.sidebar.caption("Continuous Vulnerability Awareness")

with get_db_session() as session:
    baseline_active = is_baseline_mode(session)
    if baseline_active:
        st.sidebar.info("🎯 **Mode:** Baseline Active\n(Alerts suppressed)")
    else:
        st.sidebar.success("🔔 **Mode:** Live Alerts Active")

    st.sidebar.markdown("---")
    
    # Navigation Radio
    page = st.sidebar.radio(
        "Navigation",
        [
            "Overview",
            "Vulnerabilities",
            "Sources Registry",
            "Alert Outbox",
            "Runs & Health",
            "Settings",
            "Export Data"
        ],
        index=0
    )

    st.sidebar.markdown("---")
    if is_run_in_progress():
        st.sidebar.warning("⏳ Collector is running...")
    else:
        if st.sidebar.button("▶️ Run Collection Now", use_container_width=True):
            trigger_run_now()
            st.toast("Triggered manual collection cycle!", icon="🚀")
            st.rerun()

    st.sidebar.markdown("---")
    st.sidebar.caption("Defensive Automation Platform\n$0 Cost Architecture")

    # Render target page
    if page == "Overview":
        render_overview(session)
    elif page == "Vulnerabilities":
        render_vulnerabilities(session)
    elif page == "Sources Registry":
        render_sources(session)
    elif page == "Alert Outbox":
        render_alerts(session)
    elif page == "Runs & Health":
        render_runs(session)
    elif page == "Settings":
        render_settings(session)
    elif page == "Export Data":
        render_export(session)
