"""
SOC AI Assistant — Alert Details Page
"""
import sys, os; sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

import streamlit as st
from frontend import api_client

st.markdown("<h2 class='soc-header'>🔍 Alert Details & Triage</h2>", unsafe_allow_html=True)

alert_id = st.session_state.current_alert_id

if not alert_id:
    st.warning("Please select an alert from the Alert Management page first.")
    if st.button("⬅️ Back to Alerts"):
        st.switch_page("pages/alerts.py")
else:
    # Fetch alert details
    alert = api_client.get(f"/api/alerts/{alert_id}")
    
    if not alert:
        st.error(f"Alert ID {alert_id} not found.")
    else:
        # Title Summary
        st.subheader(f"Alert #{alert['id']}: {alert['description']}")
        
        # ─── ACTION TOOLBAR ───
        col_act1, col_act2, col_act3 = st.columns(3)
        with col_act1:
            status_opts = ["New", "Investigating", "Resolved", "Closed"]
            curr_idx = status_opts.index(alert["status"]) if alert["status"] in status_opts else 0
            new_status = st.selectbox("Update Case Status:", status_opts, index=curr_idx)
            if new_status != alert["status"]:
                api_client.put(f"/api/alerts/{alert_id}/status", params={"status": new_status})
                st.toast(f"Status updated to {new_status}")
                st.rerun()

        with col_act2:
            analyst_name = st.text_input("Assign Case to (Name):", value=alert["assigned_to"] or "")
            if st.button("Assign Analyst"):
                if analyst_name:
                    api_client.put(f"/api/alerts/{alert_id}/assign", params={"analyst": analyst_name})
                    st.toast(f"Assigned to {analyst_name}")
                    st.rerun()

        with col_act3:
            st.write("")
            st.write("")
            if st.button("🧠 Analyze with AI Analysis Engine", type="primary", use_container_width=True):
                # Request analysis trigger
                api_client.post("/api/analyze", data={"alert_id": alert_id})
                st.switch_page("pages/ai_analysis.py")

        # ─── DETAILS PANEL ───
        st.write("---")
        col_info1, col_info2 = st.columns(2)
        with col_info1:
            st.markdown(
                f"""
                <div class='cyber-panel'>
                    <h4>Metadata Context</h4>
                    <table style='width:100%; border-collapse: collapse;'>
                        <tr><td><b>Timestamp:</b></td><td>{alert['timestamp']}</td></tr>
                        <tr><td><b>Sensor Source:</b></td><td>{alert['source']}</td></tr>
                        <tr><td><b>Rule ID:</b></td><td>{alert['rule_id']}</td></tr>
                        <tr><td><b>Event ID:</b></td><td>{alert['event_id']}</td></tr>
                        <tr><td><b>System Host:</b></td><td>{alert['host']}</td></tr>
                        <tr><td><b>Wazuh Agent:</b></td><td>{alert['agent']}</td></tr>
                    </table>
                </div>
                """,
                unsafe_allow_html=True
            )
        
        with col_info2:
            st.markdown(
                f"""
                <div class='cyber-panel'>
                    <h4>Network & User Context</h4>
                    <table style='width:100%; border-collapse: collapse;'>
                        <tr><td><b>Severity Level:</b></td><td><span class='badge-{alert['severity'].lower()}'>{alert['severity']}</span></td></tr>
                        <tr><td><b>Source IP:</b></td><td><code>{alert['source_ip'] or 'N/A'}</code></td></tr>
                        <tr><td><b>Destination IP:</b></td><td><code>{alert['dest_ip'] or 'N/A'}</code></td></tr>
                        <tr><td><b>Target Username:</b></td><td><code>{alert['username'] or 'N/A'}</code></td></tr>
                        <tr><td><b>MITRE Tactic:</b></td><td>{alert['mitre_tactic'] or 'N/A'}</td></tr>
                        <tr><td><b>MITRE Technique:</b></td><td>{alert['mitre_technique_id'] or 'N/A'} - {alert['mitre_technique_name'] or 'N/A'}</td></tr>
                    </table>
                </div>
                """,
                unsafe_allow_html=True
            )

        # ─── ATTACK TIMELINE (If correlated) ───
        st.write("---")
        st.subheader("Timeline Analysis & Incident Correlation")
        
        # Check if alert belongs to any active attack chain
        chains = api_client.get("/api/alerts/correlated")
        linked_chain = None
        if chains:
            for chain in chains:
                alert_ids = [item["id"] for item in chain["timeline"]]
                if alert_id in alert_ids:
                    linked_chain = chain
                    break
        
        if linked_chain:
            st.warning(f"This alert is correlated in attack chain: **{linked_chain['name']}**")
            # Render visual timeline step-by-step
            for step in linked_chain["timeline"]:
                is_curr = "👉" if step["id"] == alert_id else "•"
                st.markdown(
                    f"""
                    <div style='padding: 6px 12px; margin-left: 20px; border-left: 2px solid #00F0FF;'>
                        <span>{is_curr} <b>{step['time'][:19].replace("T", " ")}</b> - {step['event']}</span> <br/>
                        <small style='color:#A0B0C0;'>Severity: {step['severity']} | MITRE: {step['mitre']}</small>
                    </div>
                    """, 
                    unsafe_allow_html=True
                )
        else:
            st.info("This alert is currently standalone and has not matched any correlation rules.")

        # ─── RAW LOGS ───
        st.write("---")
        st.subheader("Raw Event Log Data")
        st.code(alert["raw_log"], language="text")

        if st.button("⬅️ Back to Alerts List"):
            st.switch_page("pages/alerts.py")
