"""
SOC AI Assistant — MITRE ATT&CK Matrix Page
"""
import sys, os; sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

import streamlit as st
import pandas as pd
from frontend import api_client

st.markdown("<h2 class='soc-header'>🌐 MITRE ATT&CK Matrix Navigator</h2>", unsafe_allow_html=True)
st.write("Browse techniques aligned to enterprise tactics. Highlights represent current alert frequencies.")

# Fetch tactics and stats
tactics = api_client.get("/api/mitre/tactics")
stats = api_client.get("/api/mitre/stats") or {}

if not tactics:
    st.error("Unable to load MITRE ATT&CK data from the backend.")
else:
    # ─── MATRIX MATRIX COLUMNS ───
    # Streamlit column container representing tactics
    cols = st.columns(len(tactics))
    
    for idx, tactic in enumerate(tactics):
        with cols[idx]:
            # Tactic Header
            st.markdown(
                f"""
                <div style='background-color:#121721; padding: 10px; border-bottom: 2px solid #00F0FF; text-align:center; min-height: 80px; border-radius: 4px 4px 0 0;'>
                    <b style='font-size:0.85rem; color:#E6EDF5;'>{tactic['name']}</b><br/>
                    <small style='font-size:0.7rem; color:#A0B0C0;'>{tactic['tactic_id']}</small>
                </div>
                """,
                unsafe_allow_html=True
            )
            st.write("")
            
            # List Techniques inside tactic
            for tech in tactic["techniques"]:
                tech_id = tech["technique_id"]
                count = stats.get(tech_id, 0)
                
                # Check for subtechniques count if parent is checked
                sub_count = 0
                for k, v in stats.items():
                    if k.startswith(tech_id + "."):
                        sub_count += v
                total_count = count + sub_count
                
                # Dynamic highlighting
                border_color = "rgba(255, 255, 255, 0.05)"
                bg_color = "rgba(18, 23, 33, 0.5)"
                text_color = "#A0B0C0"
                glow = ""
                
                if total_count > 0:
                    border_color = "#FF4B4B" if total_count >= 5 else "#FFA500"
                    bg_color = "rgba(255, 75, 75, 0.1)" if total_count >= 5 else "rgba(255, 165, 0, 0.1)"
                    text_color = "#E6EDF5"
                    glow = f"<span style='float:right; background-color:{border_color}; color:#0A0E14; padding:0px 5px; border-radius:10px; font-size:0.65rem; font-weight:bold;'>{total_count}</span>"
                
                # Display technique block
                st.markdown(
                    f"""
                    <div style='border: 1px solid {border_color}; background-color:{bg_color}; padding:8px; border-radius:4px; margin-bottom:6px; font-size:0.75rem; color:{text_color}; min-height:60px;'>
                        <b>{tech_id}</b> {glow}<br/>
                        <span>{tech['name']}</span>
                    </div>
                    """,
                    unsafe_allow_html=True
                )

    # ─── DRILL DOWN SECTOR ───
    st.write("---")
    st.subheader("Technique Detail & Active Alert Mapping")
    
    # Form lookup
    flat_techs = api_client.get("/api/mitre/techniques")
    if flat_techs:
        opts = [f"{t['technique_id']} - {t['name']}" for t in flat_techs]
        selected_opt = st.selectbox("Select Technique to Inspect Active Alerts:", opts)
        selected_id = selected_opt.split(" - ")[0]
        
        tech = api_client.get(f"/api/mitre/techniques/{selected_id}")
        if tech:
            st.markdown(f"### {tech['technique_id']}: {tech['name']}")
            st.write(tech["description"])
            st.info(f"💡 **Detection Guidance:** {tech['detection']}")
            
            # Pivot alerts
            linked_alerts = api_client.get("/api/alerts", params={"mitre_technique_id": selected_id})
            if linked_alerts:
                st.write(f"**Linked Ingested Alerts ({len(linked_alerts)}):**")
                for la in linked_alerts:
                    if st.button(f"🚨 Alert #{la['id']} on host {la['host']}: {la['description']}", key=f"btn_la_{la['id']}"):
                        st.session_state.current_alert_id = la["id"]
                        st.switch_page("pages/alert_detail.py")
            else:
                st.success("No active alerts map to this technique in the environment database.")
