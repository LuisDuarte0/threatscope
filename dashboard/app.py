import streamlit as st
from database.db_handler import init_db
from config import APP_TITLE, APP_ICON, APP_VERSION

# --- Page config ---
st.set_page_config(
    page_title=APP_TITLE,
    page_icon=APP_ICON,
    layout="wide",
    initial_sidebar_state="expanded",
)

# --- Hide auto-generated sidebar nav ---
st.markdown("""
    <style>
    [data-testid="stSidebarNav"] {display: none;}
    </style>
""", unsafe_allow_html=True)

# --- Init DB on first run ---
init_db()

# --- Sidebar ---
with st.sidebar:
    st.markdown(
        f"""
        <div style='text-align: center; padding: 16px 0 8px 0;'>
            <div style='font-size: 48px;'>{APP_ICON}</div>
            <div style='font-size: 26px; font-weight: 700; letter-spacing: 1px;'>{APP_TITLE}</div>
            <div style='font-size: 11px; color: #888; margin-top: 4px;'>v{APP_VERSION}</div>
        </div>
        """,
        unsafe_allow_html=True
    )
    st.divider()

    page = st.radio(
        "Navigation",
        options=[
            "📡  Live Feed",
            "🔍  IoC Enrichment",
            "📊  Threat Landscape",
            "📄  Report Generator",
        ],
        label_visibility="collapsed",
    )

    st.divider()
    st.caption("Sources: OTX · AbuseIPDB · VirusTotal")
    st.caption("Data stored locally in SQLite")

    if st.button("🔄 Run Collection Now", use_container_width=True):
        with st.spinner("Collecting from all sources..."):
            from collectors.run_collectors import run_all
            run_all()
        st.success("Collection complete!")
        st.rerun()

# --- Route to pages ---
if "Live Feed" in page:
    from dashboard.pages.live_feed import render
    render()
elif "IoC Enrichment" in page:
    from dashboard.pages.enrichment import render
    render()
elif "Threat Landscape" in page:
    from dashboard.pages.threat_landscape import render
    render()
elif "Report Generator" in page:
    from dashboard.pages.report_generator import render
    render()