import streamlit as st
import plotly.express as px
import plotly.graph_objects as go
import pandas as pd
from database.db_handler import fetch_stats, fetch_iocs


def render():
    st.markdown(
        "<h1 style='text-align: center;'>📊 Threat Landscape</h1>",
        unsafe_allow_html=True
    )
    st.markdown(
        "<p style='text-align: center; color: gray;'>"
        "Aggregate view of all collected threat intelligence — OTX · AbuseIPDB · VirusTotal"
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

    stats = fetch_stats()

    if stats["total"] == 0:
        st.info("No data yet. Run a collection first using the sidebar button.")
        return

    # --- Severity donut ---
    col1, col2 = st.columns(2)

    with col1:
        st.subheader("Severity Distribution")
        sev_data = {
            "Severity": ["Critical", "High", "Medium", "Low"],
            "Count":    [stats["critical"], stats["high"],
                         stats["medium"],   stats["low"]],
        }
        fig_sev = px.pie(
            sev_data, names="Severity", values="Count", hole=0.45,
            color="Severity",
            color_discrete_map={
                "Critical": "#FF4B4B",
                "High":     "#FF8C00",
                "Medium":   "#FFD700",
                "Low":      "#00CC88",
            }
        )
        fig_sev.update_layout(margin=dict(t=20, b=20))
        st.plotly_chart(fig_sev, use_container_width=True)

    with col2:
        st.subheader("IoCs by Source")
        src_df = pd.DataFrame(
            list(stats["by_source"].items()), columns=["Source", "Count"]
        )
        fig_src = px.bar(
            src_df, x="Source", y="Count",
            color="Source",
            color_discrete_sequence=px.colors.qualitative.Set2
        )
        fig_src.update_layout(showlegend=False, margin=dict(t=20, b=20))
        st.plotly_chart(fig_src, use_container_width=True)

    # --- IoC type breakdown ---
    st.subheader("IoC Types")
    type_df = pd.DataFrame(
        list(stats["by_type"].items()), columns=["Type", "Count"]
    ).sort_values("Count", ascending=True)

    fig_type = px.bar(
        type_df, x="Count", y="Type", orientation="h",
        color="Count",
        color_continuous_scale="Reds"
    )
    fig_type.update_layout(margin=dict(t=20, b=20), coloraxis_showscale=False)
    st.plotly_chart(fig_type, use_container_width=True)