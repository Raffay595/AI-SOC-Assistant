"""
SOC AI Assistant — Threat Intelligence Lookup Page
"""
import sys, os; sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

import streamlit as st
from frontend import api_client

st.markdown("<h2 class='soc-header'>👁️‍C Threat Intelligence Indicator Lookup</h2>", unsafe_allow_html=True)
st.write("Query IPs, domain names, or file hashes. System checks structured threat datasets to avoid hallucinations.")

# ─── ENTRY PANEL ───
col_in1, col_in2 = st.columns([1, 3])
with col_in1:
    ioc_type = st.selectbox("Indicator Type:", ["IP", "Domain", "Hash"])
with col_in2:
    ioc_val = st.text_input("Enter Indicator Value:", placeholder="e.g. 185.220.101.42")

if st.button("Query Reputation Database", type="primary", use_container_width=True):
    if ioc_val:
        res = api_client.post("/api/threat-intel/lookup", data={
            "indicator": ioc_val,
            "type": ioc_type.lower()
        })
        
        if res:
            st.write("---")
            rep = res.get("reputation")
            
            # Color badge reputation mapping
            color = "#FF4B4B" if rep == "Known Malicious" else ("#FFA500" if rep == "Suspicious" else "#A0B0C0")
            
            st.markdown(
                f"""
                <div style='border: 1px solid {color}; padding: 20px; border-radius: 8px; background-color: rgba(18,23,33,0.9);'>
                    <h3 style='margin-top:0; color:{color};'>{rep.upper()}</h3>
                    <p><b>Indicator queried:</b> <code>{res['indicator']}</code> (Type: {res['type'].upper()})</p>
                    <p><b>Threat Intelligence Source:</b> {res.get('source') or 'N/A'}</p>
                    <p><b>Identified Threat Family:</b> {res.get('malware_family') or 'Unknown / Clean'}</p>
                </div>
                """,
                unsafe_allow_html=True
            )
            
            st.write("")
            st.subheader("Recommended SOC Actions")
            for act in res.get("recommended_actions", []):
                st.markdown(f"• {act}")
        else:
            st.error("Threat lookup request failed.")
    else:
        st.error("Please enter a value to query.")
