"""
SOC AI Assistant — Alerts Management Page
"""
import sys, os; sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

import streamlit as st
import pandas as pd
from frontend import api_client
from datetime import datetime, timedelta

st.markdown("<h2 class='soc-header'>🚨 Alerts Management Console</h2>", unsafe_allow_html=True)

# ─── ADVANCED SEARCH & FILTERS ───
with st.expander("🔍 Advanced 9-Dimension Search Filters", expanded=True):
    col1, col2, col3 = st.columns(3)
    with col1:
        f_host = st.text_input("Host Name", placeholder="e.g. WEB-SERVER-01")
        f_src_ip = st.text_input("Source IP", placeholder="e.g. 185.220.101.42")
        f_username = st.text_input("Target User", placeholder="e.g. administrator")
    with col2:
        f_severity = st.selectbox("Severity Threshold", ["All", "Critical", "High", "Medium", "Low", "Informational"])
        f_status = st.selectbox("Lifecycle Status", ["All", "New", "Investigating", "Resolved", "Closed"])
        f_mitre = st.text_input("MITRE Technique ID", placeholder="e.g. T1059.001")
    with col3:
        f_event = st.text_input("Event ID", placeholder="e.g. 4625")
        f_rule = st.text_input("Rule ID", placeholder="e.g. 60122")
        f_keyword = st.text_input("Keyword Search", placeholder="e.g. powershell")

    # Time range
    col_t1, col_t2 = st.columns(2)
    with col_t1:
        start_date = st.date_input("Start Date", value=datetime.today() - timedelta(days=7))
    with col_t2:
        end_date = st.date_input("End Date", value=datetime.today())

    # Build query params
    params = {}
    if f_host: params["host"] = f_host
    if f_src_ip: params["source_ip"] = f_src_ip
    if f_username: params["username"] = f_username
    if f_severity != "All": params["severity"] = f_severity
    if f_status != "All": params["status"] = f_status
    if f_mitre: params["mitre_technique_id"] = f_mitre
    if f_event: params["event_id"] = f_event
    if f_rule: params["rule_id"] = f_rule
    if f_keyword: params["keyword"] = f_keyword
    
    # Format datetimes
    params["start_date"] = datetime.combine(start_date, datetime.min.time()).isoformat()
    params["end_date"] = datetime.combine(end_date, datetime.max.time()).isoformat()

# Fetch Alerts
alerts = api_client.get("/api/alerts", params=params)

# ─── ACTION TOOLBAR ───
col_act1, col_act2 = st.columns([3, 1])
with col_act2:
    # Trigger CSV Export
    export_params = params.copy()
    if f_severity != "All": export_params["severity"] = f_severity
    if f_status != "All": export_params["status"] = f_status
    
    # Download button mapped to backend CSV exporter
    st.markdown(
        f"""
        <a href="http://localhost:8000/api/alerts/export?severity={f_severity if f_severity != 'All' else ''}&status={f_status if f_status != 'All' else ''}" target="_blank">
            <button style="width:100%; padding:8px; border-radius:4px; background-color:#00F0FF; color:#0A0E14; font-weight:bold; border:none; cursor:pointer;">
                📥 Export CSV
            </button>
        </a>
        """, 
        unsafe_allow_html=True
    )

# ─── ALERTS LISTING ───
if not alerts:
    st.info("No security alerts matching current filter parameters.")
else:
    # Format into DataFrame for Streamlit Table
    formatted_list = []
    for a in alerts:
        formatted_list.append({
            "ID": a["id"],
            "Timestamp": a["timestamp"][:19].replace("T", " "),
            "Severity": a["severity"],
            "Host": a["host"],
            "Source IP": a["source_ip"] or "N/A",
            "Event ID": a["event_id"] or "N/A",
            "MITRE Technique": a["mitre_technique_id"] or "N/A",
            "Status": a["status"],
            "Assigned To": a["assigned_to"] or "Unassigned",
            "Description": a["description"]
        })
        
    df = pd.DataFrame(formatted_list)

    # Render table columns
    # We display a custom selector allowing analysts to pivot to a specific alert detail
    selected_row = st.selectbox("Select Alert to Inspect Detail:", df["ID"].tolist())
    
    if st.button("🔍 Open Alert Details"):
        st.session_state.current_alert_id = selected_row
        st.switch_page("pages/alert_detail.py")
        
    st.dataframe(
        df,
        use_container_width=True,
        hide_index=True,
        column_config={
            "ID": st.column_config.NumberColumn(width=50),
            "Timestamp": st.column_config.TextColumn(width=150),
            "Severity": st.column_config.TextColumn(width=100),
            "Host": st.column_config.TextColumn(width=120),
            "Source IP": st.column_config.TextColumn(width=120),
            "Status": st.column_config.TextColumn(width=100),
            "Assigned To": st.column_config.TextColumn(width=120),
        }
    )
