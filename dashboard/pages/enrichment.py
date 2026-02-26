import streamlit as st
from collectors.abuseipdb_collector import enrich_ip
from collectors.virustotal_collector import enrich_ioc
from processors.scorer import composite_score, calculate_severity, confidence_label, severity_color


def render():
    st.markdown(
        "<h1 style='text-align: center;'>🔍 IoC Enrichment</h1>",
        unsafe_allow_html=True
    )
    st.markdown(
        "<p style='text-align: center; color: gray;'>"
        "Paste any IP, domain, URL or file hash to enrich it across OTX · AbuseIPDB · VirusTotal"
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

    ioc_input = st.text_input(
        "IoC Value",
        placeholder="e.g. 8.8.8.8 or malicious-domain.com or a SHA256 hash"
    )

    ioc_type = st.selectbox(
        "IoC Type",
        ["IPv4", "domain", "hostname", "URL",
         "FileHash-MD5", "FileHash-SHA1", "FileHash-SHA256"]
    )

    if st.button("🔎 Enrich", use_container_width=True) and ioc_input:
        with st.spinner("Querying sources..."):
            abuse_data = {}
            vt_data    = {}

            if ioc_type == "IPv4":
                abuse_data = enrich_ip(ioc_input)

            vt_data = enrich_ioc(ioc_input, ioc_type)

        st.divider()
        st.subheader(f"Results for `{ioc_input}`")

        # --- Composite score ---
        abuse_score = float(abuse_data.get("abuseConfidenceScore", 0)) if abuse_data and "error" not in abuse_data else None
        vt_score    = vt_data.get("vt_score") if vt_data and "error" not in vt_data else None
        comp        = composite_score(abuse_score=abuse_score, vt_score=vt_score)
        severity    = calculate_severity(comp)
        color       = severity_color(severity)

        col1, col2, col3 = st.columns(3)
        col1.metric("Composite Score", f"{comp:.1f} / 100")
        col2.metric("Severity",        severity)
        col3.metric("Confidence",      confidence_label(comp))

        st.divider()

        # --- AbuseIPDB results ---
        if ioc_type == "IPv4":
            st.subheader("🛡️ AbuseIPDB")
            if "error" in abuse_data:
                st.error(f"AbuseIPDB error: {abuse_data['error']}")
            elif abuse_data:
                a1, a2, a3, a4 = st.columns(4)
                a1.metric("Abuse Score",    abuse_data.get("abuseConfidenceScore", "N/A"))
                a2.metric("Total Reports",  abuse_data.get("totalReports", 0))
                a3.metric("Country",        abuse_data.get("countryCode", "N/A"))
                a4.metric("ISP",            abuse_data.get("isp", "N/A")[:20])
                st.caption(f"Domain: {abuse_data.get('domain', 'N/A')} | "
                           f"Usage: {abuse_data.get('usageType', 'N/A')}")
            else:
                st.info("No AbuseIPDB data available.")

        # --- VirusTotal results ---
        st.subheader("🦠 VirusTotal")
        if "error" in vt_data:
            st.warning(f"VirusTotal: {vt_data['error']}")
        elif vt_data:
            v1, v2, v3, v4 = st.columns(4)
            v1.metric("VT Score",           f"{vt_data.get('vt_score', 0):.1f}")
            v2.metric("Malicious Engines",  vt_data.get("malicious_votes", 0))
            v3.metric("Suspicious Engines", vt_data.get("suspicious_votes", 0))
            v4.metric("Total Engines",      vt_data.get("total_engines", 0))

            if vt_data.get("tags"):
                st.caption(f"Tags: {vt_data['tags']}")
            if vt_data.get("names"):
                st.caption(f"Known as: {vt_data['names']}")
        else:
            st.info("No VirusTotal data available.")