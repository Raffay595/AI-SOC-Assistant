# 🛡️ AI SOC Assistant — Enterprise Operations Console

AI SOC Assistant is a modern, dark-mode, enterprise-grade Security Operations Center (SOC) dashboard. It aggregates security alerts, correlates multi-stage attack chains, maps alerts to MITRE ATT&CK techniques, and utilizes advanced AI models to provide analysts with real-time analysis, mitigation strategies, and an interactive chat assistant.

---

## 🚀 Key Features

* **Real-Time Security Dashboard:** At-a-glance KPI metrics showing total alerts, critical alerts, active incidents, and AI success rates alongside alert trends.
* **Correlated Attack Chains:** Visual tracking of multi-stage attacker timelines mapping source IPs, target hosts, and sequence of MITRE ATT&CK tactics.
* **AI Analysis Console:** Powered by OpenRouter, offering automated explanations, threat assessments, and actionable mitigation plans for security incidents.
* **Interactive AI Chat:** A conversational assistant page for security analysts to query logs, ask for context, and troubleshoot threats.
* **Premium Interactive UI:**
  * **FlowingMenu Navigation:** A sleek, GSAP-driven sidebar navigation featuring marquee scrolling items and themed Material Symbol icon pills.
  * **GradientText Brand:** A custom, loop-animated gradient title running on pure CSS keyframes.
  * **SpotlightCard Panels:** High-performance, cursor-following radial gradient glow overlays on hover for all dashboard cards.

---

## 🛠️ Technology Stack

* **Backend:** FastAPI, Python, SQLite (for database storage & seeds), Uvicorn (ASGI server).
* **Frontend:** Single-Page Application (SPA) built with Semantic HTML5, CSS3, Tailwind CSS, and vanilla ES6 JavaScript.
* **Animations:** GreenSock Animation Platform (GSAP), CSS keyframes.

---

## 📂 Project Structure

```text
soc-ai-assistant/
├── backend/                # FastAPI application code
│   ├── database.py         # DB connection setup
│   ├── init_db.py          # Database seeding script
│   ├── main.py             # Router paths & server controllers
│   ├── models.py           # Database schemas
│   └── schemas.py          # Pydantic request/response validation
├── frontend/               # SPA static website files
│   └── index.html          # Unified main UI & JS engine
├── run.py                  # Concurrent process runner (launch script)
└── README.md               # GitHub documentation
```

---

## ⚙️ Getting Started & Installation

### 1. Prerequisites
Ensure you have Python 3.10+ installed on your system.

### 2. Install Dependencies
Install the required packages in your Python environment:
```bash
pip install fastapi uvicorn sqlite3
```

---

## 🏃 Running the Project

To launch both the backend API server and static frontend dashboard concurrently, run the helper launch script from the project root:

```bash
python run.py
```

### Accessing the services:
* **🛡️ Frontend Console:** [http://localhost:8501](http://localhost:8501)
* **⚙️ Backend Swagger API Documentation:** [http://localhost:8000/docs](http://localhost:8000/docs)

---

## 🔧 AI Configuration (OpenRouter)

1. Open the Frontend Console at [http://localhost:8501](http://localhost:8501).
2. Go to **Settings** in the bottom left menu.
3. Paste your **OpenRouter API Key**.
4. Select one of the available AI models (such as the free models like `liquid/lfm2.5-1.2b-thinking:free` or `qwen/qwen3-coder-480b-a35b:free`).
5. Click **Save Configurations**. The system will save your preferences and route all future AI analyses and chat queries through the selected engine.
