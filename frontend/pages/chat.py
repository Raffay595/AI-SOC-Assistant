"""
SOC AI Assistant — Analyst Chat Assistant Page
"""
import sys, os; sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

import streamlit as st
from frontend import api_client

# ─── HEADER ROW ───
col_title, col_delete = st.columns([5, 1])
with col_title:
    st.markdown("<h2 class='soc-header'>💬 Analyst Chat Assistant</h2>", unsafe_allow_html=True)
with col_delete:
    st.write("")  # vertical spacer
    if st.button("🗑️ Delete Chat", use_container_width=True, type="secondary"):
        st.session_state["confirm_delete_chat"] = True

# ─── DELETE CONFIRMATION ───
if st.session_state.get("confirm_delete_chat"):
    st.warning("Are you sure you want to delete the entire conversation?")
    col_yes, col_no = st.columns(2)
    with col_yes:
        if st.button("Yes, delete it", type="primary", use_container_width=True):
            session_id = st.session_state.chat_session_id
            api_client.delete(f"/api/chat/history/{session_id}")
            st.session_state["confirm_delete_chat"] = False
            st.rerun()
    with col_no:
        if st.button("Cancel", use_container_width=True):
            st.session_state["confirm_delete_chat"] = False
            st.rerun()

# ─── CONTEXT PANEL ───
context_alert_id = st.session_state.current_alert_id
alert_ctx_text = "No Alert Context Loaded"
if context_alert_id:
    alert_ctx_text = f"🟢 Grounded Context: Alert #{context_alert_id}"

col_desc, col_ctx = st.columns([3, 1])
with col_desc:
    st.write("Discuss threat payloads, Event IDs, command decoding, and triage steps with security agents.")
with col_ctx:
    st.markdown(
        f"""
        <div style='text-align:center; padding: 4px; border-radius:4px; border:1px solid #00F0FF; background-color:rgba(0,240,255,0.05); font-size:0.8rem; color:#00F0FF;'>
            {alert_ctx_text}
        </div>
        """,
        unsafe_allow_html=True
    )

# ─── QUICK QUESTIONS BAR ───
st.write("")
st.write("💡 *Quick Questions:*")
col_q1, col_q2, col_q3 = st.columns(3)
quick_msg = None
with col_q1:
    if st.button("What does Windows Event ID 4625 mean?", use_container_width=True):
        quick_msg = "What does Event ID 4625 mean?"
with col_q2:
    if st.button("How do I investigate PowerShell commands?", use_container_width=True):
        quick_msg = "How should I investigate a suspicious PowerShell alert?"
with col_q3:
    if st.button("Explain MITRE technique T1059", use_container_width=True):
        quick_msg = "What does T1059 mean?"

# Load Chat history
session_id = st.session_state.chat_session_id
history = api_client.get(f"/api/chat/history/{session_id}") or []

# ─── RENDER CHAT HISTORY ───
for item in history:
    role = item["role"]
    avatar = "🛡️" if role == "assistant" else "👤"
    with st.chat_message(role, avatar=avatar):
        # Render as plain text to avoid heavy markdown formatting
        st.text(item["content"])

# ─── HANDLE MESSAGE INPUTS ───
prompt = st.chat_input("Enter security query...")
if quick_msg:
    prompt = quick_msg

if prompt:
    # Display user input
    with st.chat_message("user", avatar="👤"):
        st.text(prompt)

    with st.spinner("AI analyst generating response..."):
        # Send message with contextual alert_id
        res = api_client.post("/api/chat", data={
            "message": prompt,
            "session_id": session_id,
            "alert_id": context_alert_id
        })

        if res:
            st.rerun()
