"""
SOC AI Assistant — Custom Premium CSS Styles

Implements:
- Cyber-security glassmorphic styling
- Premium CSS gradients & box glows
- Custom status badges with animated micro-actions
- Scrollbars and dashboard layouts
"""

import streamlit as st


def inject_custom_css():
    """Injects high-fidelity SOC style layouts into the Streamlit session."""
    st.markdown(
        """
        <style>
        /* Base page styling */
        @import url('https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;500;700&family=JetBrains+Mono:wght@400;500;700&display=swap');
        
        html, body, [class*="css"] {
            font-family: 'Outfit', sans-serif;
        }
        
        code, pre {
            font-family: 'JetBrains Mono', monospace;
        }

        /* Glassmorphism Metric Cards */
        div[data-testid="stMetricValue"] {
            font-size: 2rem;
            font-weight: 700;
            color: #00F0FF;
            text-shadow: 0 0 10px rgba(0, 240, 255, 0.3);
        }
        
        div[data-testid="metric-container"] {
            background: linear-gradient(135deg, rgba(18, 23, 33, 0.8) 0%, rgba(10, 14, 20, 0.9) 100%);
            border: 1px solid rgba(0, 240, 255, 0.15);
            padding: 1.25rem;
            border-radius: 12px;
            box-shadow: 0 4px 20px rgba(0, 0, 0, 0.4);
            transition: all 0.3s ease;
        }
        
        div[data-testid="metric-container"]:hover {
            border-color: #00F0FF;
            box-shadow: 0 4px 25px rgba(0, 240, 255, 0.2);
            transform: translateY(-2px);
        }

        /* Severity Badges styling */
        .badge-critical {
            background-color: rgba(255, 75, 75, 0.15);
            color: #FF4B4B;
            border: 1px solid #FF4B4B;
            padding: 2px 8px;
            border-radius: 4px;
            font-weight: 500;
            font-size: 0.85rem;
            text-transform: uppercase;
        }

        .badge-high {
            background-color: rgba(255, 165, 0, 0.15);
            color: #FFA500;
            border: 1px solid #FFA500;
            padding: 2px 8px;
            border-radius: 4px;
            font-weight: 500;
            font-size: 0.85rem;
            text-transform: uppercase;
        }

        .badge-medium {
            background-color: rgba(255, 215, 0, 0.15);
            color: #FFD700;
            border: 1px solid #FFD700;
            padding: 2px 8px;
            border-radius: 4px;
            font-weight: 500;
            font-size: 0.85rem;
            text-transform: uppercase;
        }

        .badge-low {
            background-color: rgba(0, 240, 255, 0.1);
            color: #00F0FF;
            border: 1px solid #00F0FF;
            padding: 2px 8px;
            border-radius: 4px;
            font-weight: 500;
            font-size: 0.85rem;
            text-transform: uppercase;
        }

        .badge-informational {
            background-color: rgba(120, 140, 160, 0.15);
            color: #A0B0C0;
            border: 1px solid #A0B0C0;
            padding: 2px 8px;
            border-radius: 4px;
            font-weight: 500;
            font-size: 0.85rem;
            text-transform: uppercase;
        }

        /* Status badges */
        .status-new {
            color: #FF4B4B;
            font-weight: bold;
        }
        
        .status-investigating {
            color: #FFA500;
            font-weight: bold;
        }
        
        .status-resolved {
            color: #00FF66;
            font-weight: bold;
        }

        /* Premium headers */
        .soc-header {
            color: #E6EDF5;
            border-bottom: 2px solid rgba(0, 240, 255, 0.2);
            padding-bottom: 0.5rem;
            margin-bottom: 1.5rem;
            font-weight: 700;
        }

        .cyber-panel {
            background-color: #121721;
            border: 1px solid rgba(255, 255, 255, 0.05);
            border-radius: 8px;
            padding: 1.5rem;
            margin-bottom: 1rem;
            box-shadow: 0 4px 15px rgba(0, 0, 0, 0.3);
        }

        /* Custom Scrollbar for Preformatted code */
        pre {
            background-color: #080B10 !important;
            border: 1px solid rgba(255, 255, 255, 0.05) !important;
            border-radius: 8px !important;
            padding: 1rem !important;
            max-height: 400px;
            overflow-y: auto;
        }

        /* Hide Streamlit default watermark/menu */
        #MainMenu {visibility: hidden;}
        footer {visibility: hidden;}
        header {visibility: hidden;}
        
        /* Sidebar styling override */
        section[data-testid="stSidebar"] {
            background-color: #080B10;
            border-right: 1px solid rgba(0, 240, 255, 0.1);
        }
        
        /* Auto-refresh indicator widget */
        .refresh-pill {
            display: inline-block;
            padding: 4px 10px;
            font-size: 0.75rem;
            border-radius: 20px;
            background-color: rgba(0, 240, 255, 0.1);
            color: #00F0FF;
            border: 1px solid rgba(0, 240, 255, 0.3);
        }
        </style>
        """,
        unsafe_allow_html=True
    )
