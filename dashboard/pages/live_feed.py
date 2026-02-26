import streamlit as st
import pandas as pd
from database.db_handler import fetch_iocs, fetch_stats
from processors.normalizer import dataframe_to_display
from processors.scorer import severity_color


def render():
    st.markdown(
        "<h1 style='text-align: center;'>📡 Live Threat Feed</h1>",
        unsafe_allow_html=True
    )
    st.markdown(
        "<p style='text-align: center; color: gray;'>"
        "Real-time IoCs collected from OTX · AbuseIPDB · VirusTotal"
        "</p>",
        unsafe_allow_html=True
    )
    st.markdown(
        "<p style='text-align: center; font-size: 12px; color: #555;'>"
        "Made by Luis Duarte"
        "</p>",
        unsafe_allow_html=True
    )
    st.divider()

    # --- Stats row ---
    stats = fetch_stats()
    c1, c2, c3, c4, c5 = st.columns(5)
    c1.metric("Total IoCs",  stats["total"])
    c2.metric("🔴 Critical", stats["critical"])
    c3.metric("🟠 High",     stats["high"])
    c4.metric("🟡 Medium",   stats["medium"])
    c5.metric("🟢 Low",      stats["low"])

    st.divider()

    # --- Filters ---
    with st.expander("🔧 Filters", expanded=True):
        col1, col2, col3 = st.columns(3)
        with col1:
            ioc_type = st.selectbox(
                "IoC Type",
                ["All", "IPv4", "IPv6", "domain", "hostname",
                 "URL", "FileHash-MD5", "FileHash-SHA1", "FileHash-SHA256"]
            )
        with col2:
            source = st.selectbox("Source", ["All", "OTX", "AbuseIPDB"])
        with col3:
            severity = st.selectbox(
                "Severity", ["All", "Critical", "High", "Medium", "Low"]
            )

        col4, col5 = st.columns(2)
        with col4:
            date_from = st.date_input("From", value=None)
        with col5:
            date_to = st.date_input("To", value=None)

        limit = st.slider("Max results", 50, 1000, 200, step=50)

    # --- Fetch & display ---
    df = fetch_iocs(
        ioc_type  = ioc_type  if ioc_type  != "All" else None,
        source    = source    if source    != "All" else None,
        severity  = severity  if severity  != "All" else None,
        date_from = str(date_from) if date_from else None,
        date_to   = str(date_to)   if date_to   else None,
        limit     = limit,
    )

    if df.empty:
        st.info("No IoCs found. Run a collection first using the sidebar button.")
        return

    display_df = dataframe_to_display(df)

    # Color-code severity column
    def highlight_severity(val):
        color = severity_color(val)
        return f"color: {color}; font-weight: bold"

    styled = display_df.style.map(
        highlight_severity, subset=["Severity"]
    ) if "Severity" in display_df.columns else display_df

    st.dataframe(styled, use_container_width=True, height=500)
    st.caption(f"Showing {len(df)} of {stats['total']} total IoCs")

    # --- Export ---
    csv = df.to_csv(index=False).encode("utf-8")
    st.download_button(
        label="⬇️ Export as CSV",
        data=csv,
        file_name="threatscope_feed.csv",
        mime="text/csv",
    )