"""
SOC AI Assistant — Incident Cases Page
"""
import sys, os; sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

import streamlit as st
import pandas as pd
from frontend import api_client

st.markdown("<h2 class='soc-header'>📂 Incident Case Manager</h2>", unsafe_allow_html=True)

# ─── CASE INGESTION FORM ───
with st.expander("🆕 Create New Incident Case File"):
    c_title = st.text_input("Incident Title (Name)", placeholder="e.g. Host WEB-SERVER-01 Privilege Escalation Attack")
    c_sev = st.selectbox("Severity Classification", ["Critical", "High", "Medium", "Low"])
    c_desc = st.text_area("Initial Summary / Scope", placeholder="Describe system impact, suspected origin IP, etc.")
    
    # Selection of alerts
    all_alerts = api_client.get("/api/alerts", params={"limit": 100})
    linked_ids = []
    if all_alerts:
        formatted_opts = {a["id"]: f"#{a['id']} - {a['timestamp'][:16].replace('T',' ')} | {a['host']} | {a['description']}" for a in all_alerts}
        selected_alerts = st.multiselect("Link Alerts to Incident File:", options=list(formatted_opts.keys()), format_func=lambda x: formatted_opts[x])
        linked_ids = selected_alerts

    if st.button("Create Incident"):
        if c_title:
            res = api_client.post("/api/incidents", data={
                "title": c_title,
                "severity": c_sev,
                "description": c_desc,
                "alert_ids": linked_ids
            })
            if res:
                st.success("Incident Case file created successfully.")
                st.rerun()
        else:
            st.error("Please enter an incident title.")

# Fetch Active incidents
incidents = api_client.get("/api/incidents")

if not incidents:
    st.info("No incident cases logged. Use the form above to record a new case.")
else:
    # ─── CASE LIST ───
    formatted_list = []
    for inc in incidents:
        formatted_list.append({
            "ID": inc["id"],
            "Incident Title": inc["title"],
            "Severity": inc["severity"],
            "Status": inc["status"],
            "Created Date": inc["created_at"][:19].replace("T", " "),
            "Linked Alerts": len(inc["alert_ids"])
        })
    df_inc = pd.DataFrame(formatted_list)
    
    st.write("### Active Incident Cases")
    selected_inc_id = st.selectbox("Select Incident to Inspect / Generate Report:", df_inc["ID"].tolist())
    
    st.dataframe(df_inc, use_container_width=True, hide_index=True)
    
    st.write("---")
    
    # ─── REPORT GENERATION VIEW ───
    if selected_inc_id:
        inc = api_client.get(f"/api/incidents/{selected_inc_id}")
        if inc:
            st.markdown(f"### Case Report: {inc['title']}")
            st.markdown(f"**Severity:** {inc['severity']} &nbsp;|&nbsp; **Status:** {inc['status']} &nbsp;|&nbsp; **Linked Alerts:** {len(inc['alert_ids'])}")
            
            report = inc.get("report")
            
            if not report:
                st.warning("No incident report has been generated yet for this case file.")
                if st.button("🧠 Generate Incident Report via AI Engine", type="primary"):
                    with st.spinner("AI Analysis Engine running sequential section analysis..."):
                        res = api_client.post(f"/api/incidents/{selected_inc_id}/generate-report")
                        if res:
                            st.success("Report generated successfully.")
                            st.rerun()
            else:
                # DISPLAY REPORT SECTIONS
                with st.expander("📄 1. Executive Summary", expanded=True):
                    st.write(report.get("executive_summary", ""))
                    
                with st.expander("🕒 2. Threat Activity Timeline"):
                    timeline = report.get("timeline", [])
                    for t in timeline:
                        st.markdown(f"**{t.get('time')[:19].replace('T',' ')}** - {t.get('event')} *({t.get('source')})*")
                        
                with st.expander("🖥️ 3. Affected System Hostnames"):
                    for host in report.get("affected_hosts", []):
                        st.markdown(f"• `{host}`")
                        
                with st.expander("🔑 4. Extracted Indicators of Compromise (IOCs)"):
                    iocs = report.get("iocs", [])
                    for ioc in iocs:
                        st.markdown(f"- **{ioc.get('type')}:** `{ioc.get('value')}`")
                        
                with st.expander("🌐 5. MITRE ATT&CK Mappings"):
                    mitre = report.get("mitre_mapping", [])
                    for m in mitre:
                        st.markdown(f"**{m.get('technique_id')} - {m.get('technique')}:** {m.get('description')}")
                        
                with st.expander("💥 6. Root Cause Analysis"):
                    st.write(report.get("root_cause", ""))
                    
                with st.expander("🛠️ 7. Recommendations"):
                    for rec in report.get("recommendations", []):
                        st.markdown(f"• {rec}")
                        
                with st.expander("📋 8. Next Investigation Actions"):
                    for act in report.get("next_actions", []):
                        st.markdown(f"• {act}")
                        
                # Exporter triggers
                st.write("")
                report_text = f"""# INCIDENT CASE REPORT: {inc['title']}
Severity: {inc['severity']} | Status: {inc['status']}

## 1. EXECUTIVE SUMMARY
{report.get('executive_summary', '')}

## 2. TIMELINE
"""
                for t in report.get("timeline", []):
                    report_text += f"- {t.get('time')[:19]} | {t.get('event')} ({t.get('source')})\n"
                
                report_text += "\n## 3. AFFECTED HOSTS\n"
                for h in report.get("affected_hosts", []):
                    report_text += f"- {h}\n"

                report_text += "\n## 4. EXTRACTED IOCS\n"
                for i in report.get("iocs", []):
                    report_text += f"- {i.get('type')}: {i.get('value')}\n"

                report_text += "\n## 5. MITRE MAPPINGS\n"
                for m in report.get("mitre_mapping", []):
                    report_text += f"- {m.get('technique_id')} - {m.get('technique')}: {m.get('description')}\n"

                report_text += f"\n## 6. ROOT CAUSE ANALYSIS\n{report.get('root_cause', '')}\n"

                report_text += "\n## 7. RECOMMENDATIONS\n"
                for r in report.get("recommendations", []):
                    report_text += f"- {r}\n"

                report_text += "\n## 8. NEXT ACTIONS\n"
                for a in report.get("next_actions", []):
                    report_text += f"- {a}\n"

                st.download_button(
                    label="💾 Download Report (Markdown)",
                    data=report_text,
                    file_name=f"incident_{selected_inc_id}_report.md",
                    mime="text/markdown",
                    use_container_width=True
                )
