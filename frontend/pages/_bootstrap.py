"""
SOC AI Assistant — Path bootstrap

Import this at the top of every page file to ensure the project root
is on sys.path so that `from frontend import api_client` works when
Streamlit runs pages as standalone scripts.
"""
import sys
import os

_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _root not in sys.path:
    sys.path.insert(0, _root)
