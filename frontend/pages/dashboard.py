"""
SOC AI Assistant — Dashboard Page
"""
import sys, os; sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

import streamlit as st
import pandas as pd
import plotly.express as px
from frontend import api_client
from datetime import datetime

st.markdown("<h2 class='soc-header'>📊 Security Operations Console Dashboard</h2>", unsafe_allow_html=True)

# Fetch Metrics
metrics = api_client.get("/api/dashboard")

if not metrics:
    st.error("Unable to connect to the FastAPI backend. Make sure the server is running on port 8000.")
else:
    # ─── ROW 1: KPI Metrics ───
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric(
            label="Total Ingested Alerts", 
            value=metrics.get("total_alerts", 0), 
            delta="Live Feed"
        )
    with col2:
        st.metric(
            label="Critical Alerts (Priority)", 
            value=metrics.get("critical_alerts", 0),
            delta="Requires Action"
        )
    with col3:
        st.metric(
            label="Active Incidents", 
            value=metrics.get("open_incidents", 0),
            delta="In Progress"
        )
    with col4:
        st.metric(
            label="AI Success Rate", 
            value=f"{metrics.get("ai_success_rate", 0.0) * 100:.1f}%",
            delta="Analysis Engine"
        )

    st.write("")

    # ─── ROW 2: Charts (Severity & Trend) ───
    c1, c2 = st.columns([1, 2])
    with c1:
        st.subheader("Alerts by Severity")
        sev_data = metrics.get("alerts_by_severity", {})
        if sev_data:
            df_sev = pd.DataFrame(list(sev_data.items()), columns=["Severity", "Count"])
            fig = px.pie(
                df_sev, 
                names="Severity", 
                values="Count", 
                hole=0.4, 
                color="Severity",
                color_discrete_map={
                    "Critical": "#FF4B4B",
                    "High": "#FFA500",
                    "Medium": "#FFD700",
                    "Low": "#00F0FF",
                    "Informational": "#A0B0C0"
                }
            )
            fig.update_layout(
                template="plotly_dark", 
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                margin=dict(l=10, r=10, t=10, b=10)
            )
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No severity logs available.")

    with c2:
        st.subheader("Alert Trend (Last 24 Hours)")
        trend_data = metrics.get("alert_trend_24h", [])
        if trend_data:
            df_trend = pd.DataFrame(trend_data)
            df_trend["hour"] = pd.to_datetime(df_trend["hour"]).dt.strftime("%H:%M")
            fig = px.line(
                df_trend, 
                x="hour", 
                y="count",
                markers=True,
                labels={"hour": "Hour of Day", "count": "Alert Count"}
            )
            fig.update_traces(line_color="#00F0FF", marker_color="#00F0FF", fill="tozeroy", fillcolor="rgba(0, 240, 255, 0.1)")
            fig.update_layout(
                template="plotly_dark",
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                margin=dict(l=10, r=10, t=20, b=10)
            )
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No recent log activity in the past 24 hours.")

    # ─── ROW 3: Threat Analytics (Correlations & Metrics) ───
    st.write("---")
    st.subheader("⚡ Correlated Attack Chains Detected")
    chains = metrics.get("attack_chains", [])
    if chains:
        for idx, chain in enumerate(chains):
            with st.container():
                st.markdown(
                    f"""
                    <div style='border: 1px solid #FF4B4B; padding: 1.25rem; border-radius: 8px; margin-bottom: 1rem; background-color: rgba(255, 75, 75, 0.05);'>
                        <span style='color: #FF4B4B; font-weight: bold; font-size: 1.1rem;'>⚠️ {chain["name"]} ({chain["chain_id"]})</span>
                        <p style='margin: 8px 0; color: #E6EDF5;'>{chain["description"]}</p>
                        <div style='font-size: 0.85rem; color: #A0B0C0;'>
                            <span><b>Target Host:</b> {chain["host"]}</span> &nbsp;|&nbsp;
                            <span><b>Suspected Attacker:</b> {chain["attacker"]}</span> &nbsp;|&nbsp;
                            <span><b>Timeline:</b> {chain["start_time"]} to {chain["end_time"]}</span> &nbsp;|&nbsp;
                            <span><b>Alert Count:</b> {chain["alert_count"]}</span>
                        </div>
                    </div>
                    """, 
                    unsafe_allow_html=True
                )
    else:
        st.success("No active attack chains detected by the correlation engine.")

    # ─── ROW 4: Extra SOC Details ───
    st.write("---")
    col_a, col_b, col_c = st.columns(3)
    
    with col_a:
        st.subheader("Top Attacked Hosts")
        hosts = metrics.get("top_attacked_hosts", [])
        if hosts:
            df_hosts = pd.DataFrame(hosts)
            fig = px.bar(df_hosts, x="count", y="host", orientation="h")
            fig.update_traces(marker_color="#FFA500")
            fig.update_layout(
                template="plotly_dark",
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                margin=dict(l=10, r=10, t=10, b=10)
            )
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No host logs.")

    with col_b:
        st.subheader("Top MITRE ATT&CK Techniques")
        techniques = metrics.get("top_mitre_techniques", [])
        if techniques:
            df_tech = pd.DataFrame(techniques)
            fig = px.bar(df_tech, x="count", y="id", hover_data=["name"], orientation="h")
            fig.update_traces(marker_color="#00FF66")
            fig.update_layout(
                template="plotly_dark",
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                margin=dict(l=10, r=10, t=10, b=10)
            )
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No MITRE techniques linked.")

    with col_c:
        st.subheader("Most Targeted Users")
        users = metrics.get("most_targeted_users", [])
        if users:
            df_users = pd.DataFrame(users)
            st.dataframe(df_users, use_container_width=True, hide_index=True)
        else:
            st.info("No usernames logged in recent alerts.")
