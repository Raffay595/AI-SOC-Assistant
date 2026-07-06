import sys
import os

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import streamlit as st

# Setup page configurations
st.set_page_config(
    page_title="AI SOC Assistant — Security Operations Console",
    layout="wide",
    page_icon="🛡️",
)

# Read index.html SPA
index_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "index.html")
if os.path.exists(index_path):
    with open(index_path, "r", encoding="utf-8") as f:
        html_content = f.read()
    
    # Render full screen iframe containing the high-density HTML console
    st.components.v1.html(html_content, height=1080, scrolling=True)
else:
    st.error("Frontend index.html SPA not found. Please compile it first.")

