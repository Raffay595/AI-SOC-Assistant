"""
SOC AI Assistant — AI Alert Analysis Page
"""
import sys, os; sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

import streamlit as st
import time
from frontend import api_client

st.markdown("<h2 class='soc-header'>🧠 AI-Powered Alert Analysis</h2>", unsafe_allow_html=True)

alert_id = st.session_state.current_alert_id

if not alert_id:
    st.warning("Please select an alert from the Alert Management page first.")
    if st.button("⬅️ Back to Alerts"):
        st.switch_page("pages/alerts.py")
else:
    # Get alert detail
    alert = api_client.get(f"/api/alerts/{alert_id}")
    
    # Retrieve current analysis or check status
    analysis = api_client.get(f"/api/analyze/alert/{alert_id}")
    
    if not analysis:
        # Auto-trigger if not started
        st.info("Starting AI Analysis pipeline...")
        analysis = api_client.post("/api/analyze", data={"alert_id": alert_id})
        st.rerun()

    # Handle status rendering
    if analysis["status"] in ("queued", "running"):
        with st.status(f"AI Engine Status: {analysis['status'].upper()}", expanded=True) as status_box:
            st.write("Calling OpenRouter Model endpoint...")
            st.write("Generating structured JSON analysis payload...")
            st.write("Parsing confidence indicators...")
            time.sleep(1.0)
            st.rerun()
            
    elif analysis["status"] == "failed":
        st.error(f"AI Analysis pipeline failed: {analysis['error_message']}")
        if st.button("🔄 Retry Analysis"):
            api_client.post("/api/analyze", data={"alert_id": alert_id})
            st.rerun()
            
    elif analysis["status"] == "completed" and analysis["result"]:
        res = analysis["result"]
        
        # ─── HEADER PANEL (Summary & Confidence) ───
        col_sum, col_conf = st.columns([3, 1])
        with col_sum:
            st.markdown(f"#### AI Incident Executive Summary")
            st.write(res["summary"])
            
        with col_conf:
            # Custom styled gauge representation
            conf = res.get("confidence", 0.0)
            color = "#00FF66" if conf > 0.8 else ("#FFA500" if conf > 0.5 else "#FF4B4B")
            st.markdown(
                f"""
                <div style='text-align: center; border: 1px solid rgba(255,255,255,0.1); padding: 10px; border-radius: 8px; background-color:#121721;'>
                    <span style='font-size: 0.8rem; color:#A0B0C0; text-transform:uppercase;'>Confidence Score</span><br/>
                    <span style='font-size: 2.2rem; font-weight:bold; color:{color};'>{int(conf * 100)}%</span><br/>
                    <small style='font-size: 0.75rem; color:#A0B0C0;'>Reason: {res.get("confidence_reason", "N/A")}</small>
                </div>
                """,
                unsafe_allow_html=True
            )

        # ─── STAGE AND MITRE MAPPING ───
        st.write("---")
        col_stage, col_mitre = st.columns(2)
        with col_stage:
            st.subheader("Identified Attack Stage")
            st.info(f"**Stage Category:** {res.get('attack_stage', 'Unknown')}")
            
        with col_mitre:
            st.subheader("MITRE ATT&CK Mapping")
            mitre = res.get("mitre")
            if mitre:
                st.success(f"**Technique ID:** {mitre.get('technique_id')} — {mitre.get('technique')}")
                st.write(mitre.get("description"))
            else:
                st.info("No reliable MITRE mapping concluded.")

        # ─── EVIDENCE & FACTS VS ASSUMPTIONS ───
        st.write("---")
        col_ev, col_facts = st.columns(2)
        
        with col_ev:
            st.subheader("Observed Evidence List")
            for ev in res.get("evidence", []):
                st.markdown(f"✅ {ev}")
                
        with col_facts:
            st.subheader("Facts vs Assumptions Analysis")
            f_vs_a = res.get("facts_vs_assumptions", {})
            
            c_f, c_a = st.columns(2)
            with c_f:
                st.markdown("**Facts (Observed)**")
                for f in f_vs_a.get("facts", []):
                    st.markdown(f"• {f}")
            with c_a:
                st.markdown("**Assumptions (Inferred)**")
                for a in f_vs_a.get("assumptions", []):
                    st.markdown(f"• {a}")

        # ─── IOC TABLE ───
        st.write("---")
        st.subheader("Extracted Indicators of Compromise (IOCs)")
        iocs = res.get("iocs", [])
        if iocs:
            # Custom styled indicator list
            for ioc in iocs:
                st.markdown(f"🔑 **{ioc['type']}:** `{ioc['value']}`")
        else:
            st.info("No indicators extracted from alert logs.")

        # ─── RECOMMENDATIONS & INVESTIGATION STEPS ───
        st.write("---")
        col_rec, col_steps = st.columns(2)
        with col_rec:
            st.subheader("Remediation Recommendations")
            for rec in res.get("recommendations", []):
                st.markdown(f"• {rec}")
                
        with col_steps:
            st.subheader("Suggested Investigation Steps")
            for step in res.get("investigation_steps", []):
                st.markdown(f"{step}")

        # Footer return buttons
        st.write("")
        col_back, col_chat = st.columns(2)
        with col_back:
            if st.button("⬅️ Back to Alert Triage"):
                st.switch_page("pages/alert_detail.py")
        with col_chat:
            if st.button("💬 Ask Chat Assistant about Alert"):
                st.switch_page("pages/chat.py")
