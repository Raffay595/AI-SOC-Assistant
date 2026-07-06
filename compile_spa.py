import os
import re
import json

# Directory containing the downloaded content.md files
# We will load them from the steps folder where they were saved
steps_dir = "../../brain/e3dbc65b-8a3c-42ec-9250-e3dfe2280651/.system_generated/steps"

# Map of screens to their step step_index and filename
screens = {
    "dashboard": "219",
    "alerts": "229",
    "alert_detail": "230",
    "ai_analysis": "231",
    "mitre": "232",
    "incidents": "233",
    "threat_intel": "234",
    "chat": "235",
    "settings": "236"
}

templates = {}

for name, step in screens.items():
    path = f"C:/Users/User/.gemini/antigravity-ide/brain/e3dbc65b-8a3c-42ec-9250-e3dfe2280651/.system_generated/steps/{step}/content.md"
    print(f"Parsing {name} from {path}...")
    if not os.path.exists(path):
        print(f"Error: path {path} does not exist.")
        continue
        
    with open(path, "r", encoding="utf-8") as f:
        content = f.read()
        
    # Extract HTML content
    # Find <!DOCTYPE html>
    idx = content.find("<!DOCTYPE html>")
    if idx == -1:
        idx = content.find("<html")
    if idx == -1:
        print(f"Warning: could not find HTML start in {name}")
        continue
        
    html = content[idx:]
    
    # Extract the main content inside <main>...</main>
    # We can use regex or simple string find
    main_start = html.find("<main")
    if main_start == -1:
        print(f"Warning: could not find <main> in {name}")
        continue
        
    # Find the tag end of <main ...>
    main_tag_end = html.find(">", main_start)
    
    # Find the closing </main>
    # Note: we need to find the main closing tag, which is usually right before the Contextual FAB or script tags
    main_end = html.find("</main>")
    if main_end == -1:
        print(f"Warning: could not find </main> in {name}")
        continue
        
    main_content = html[main_tag_end+1:main_end]
    templates[name] = main_content.strip()

print(f"Successfully extracted {len(templates)} screen templates.")

# Save template dictionary to a JS file
with open("frontend/static_templates.js", "w", encoding="utf-8") as f:
    f.write("const SCREEN_TEMPLATES = " + json.dumps(templates, indent=2) + ";")
print("Saved templates to frontend/static_templates.js")
