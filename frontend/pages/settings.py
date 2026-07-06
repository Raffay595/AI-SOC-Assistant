"""
SOC AI Assistant — Settings Page
"""
import sys, os; sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

import streamlit as st
from frontend import api_client

st.markdown("<h2 class='soc-header'>⚙️ Console Settings</h2>", unsafe_allow_html=True)
st.write("Configure model integration settings. Parameters are saved in database tables.")

# Load settings from backend
settings_list = api_client.get("/api/settings") or []
settings_dict = {s["key"]: s["value"] for s in settings_list}

# Form fields
st.write("### AI Integration Credentials")
openrouter_key = st.text_input("OpenRouter API Key:", value=settings_dict.get("openrouter_api_key", ""), type="password")

st.write("")
st.write("### Model Parameters")
model_options = [
    "anthropic/claude-sonnet-4",
    "openai/gpt-4o",
    "google/gemini-2.5-flash",
    "deepseek/deepseek-chat",
    "qwen/qwen-2.5-72b-instruct"
]
curr_model = settings_dict.get("ai_model", "anthropic/claude-sonnet-4")
model_val = st.selectbox("Active Analysis Model:", model_options, index=model_options.index(curr_model) if curr_model in model_options else 0)

temp_val = st.slider("Temperature (Creativity):", min_value=0.0, max_value=1.0, value=float(settings_dict.get("ai_temperature", 0.3)), step=0.1)

max_tok = st.number_input("Max Output Tokens Limit:", min_value=512, max_value=8192, value=int(settings_dict.get("ai_max_tokens", 4096)), step=256)

st.write("")
st.write("### Console Preferences")
refresh_options = ["5", "10", "30", "60", "off"]
curr_refresh = settings_dict.get("auto_refresh_interval", "30")
refresh_val = st.selectbox("Dashboard Auto-Refresh Rate (Seconds):", refresh_options, index=refresh_options.index(curr_refresh) if curr_refresh in refresh_options else 2)

if st.button("Save Configuration", type="primary"):
    # Sequential updates
    api_client.put("/api/settings", data={"key": "openrouter_api_key", "value": openrouter_key})
    api_client.put("/api/settings", data={"key": "ai_model", "value": model_val})
    api_client.put("/api/settings", data={"key": "ai_temperature", "value": str(temp_val)})
    api_client.put("/api/settings", data={"key": "ai_max_tokens", "value": str(max_tok)})
    api_client.put("/api/settings", data={"key": "auto_refresh_interval", "value": refresh_val})
    
    st.toast("Settings saved successfully!")
    st.rerun()
