import urllib.request
import json
import os

screens = {
    "dashboard": "https://contribution.usercontent.google.com/download?c=CgthaWRhX2NvZGVmeBJ8Eh1hcHBfY29tcGFuaW9uX2dlbmVyYXRlZF9maWxlcxpbCiVodG1sXzIzNGQzNjY1ZTFiZTQ0YjdhMGU4M2ZlMzAwYjhmNzhiEgsSBxCF3ID_ygwYAZIBJAoKcHJvamVjdF9pZBIWQhQxMTM4NjM3MDAzMjA3ODYyMDkxMw&filename=&opi=89354086",
    "alerts": "https://contribution.usercontent.google.com/download?c=CgthaWRhX2NvZGVmeBJ8Eh1hcHBfY29tcGFuaW9uX2dlbmVyYXRlZF9maWxlcxpbCiVodG1sX2FjZTUwYzM1ZTRiNDRmZmRhZjFhZTcxYjhkODMwODA2EgsSBxCF3ID_ygwYAZIBJAoKcHJvamVjdF9pZBIWQhQxMTM4NjM3MDAzMjA3ODYyMDkxMw&filename=&opi=89354086",
    "alert_detail": "https://contribution.usercontent.google.com/download?c=CgthaWRhX2NvZGVmeBJ8Eh1hcHBfY29tcGFuaW9uX2dlbmVyYXRlZF9maWxlcxpbCiVodG1sXzgyNTQyZDc5MDVkMTQ5NTE4MjgyYTkxYTA1ZWJhYTA0EgsSBxCF3ID_ygwYAZIBJAoKcHJvamVjdF9pZBIWQhQxMTM4NjM3MDAzMjA3ODYyMDkxMw&filename=&opi=89354086",
    "ai_analysis": "https://contribution.usercontent.google.com/download?c=CgthaWRhX2NvZGVmeBJ8Eh1hcHBfY29tcGFuaW9uX2dlbmVyYXRlZF9maWxlcxpbCiVodG1sX2VhN2ZiNTU1ZDBjNDQ4ZDFhZThjNjVkM2VmNWY4MzE0EgsSBxCF3ID_ygwYAZIBJAoKcHJvamVjdF9pZBIWQhQxMTM4NjM3MDAzMjA3ODYyMDkxMw&filename=&opi=89354086",
    "mitre": "https://contribution.usercontent.google.com/download?c=CgthaWRhX2NvZGVmeBJ8Eh1hcHBfY29tcGFuaW9uX2dlbmVyYXRlZF9maWxlcxpbCiVodG1sX2MxYjI5M2E1NWJhNjQ1M2ViYmIwNzA3ODA3YzBhNGVlEgsSBxCF3ID_ygwYAZIBJAoKcHJvamVjdF9pZBIWQhQxMTM4NjM3MDAzMjA3ODYyMDkxMw&filename=&opi=89354086",
    "incidents": "https://contribution.usercontent.google.com/download?c=CgthaWRhX2NvZGVmeBJ8Eh1hcHBfY29tcGFuaW9uX2dlbmVyYXRlZF9maWxlcxpbCiVodG1sXzM1YTZlOGU3OWM0NzQ2YTU5M2VkNDhiZDM5NjUxZDhhEgsSBxCF3ID_ygwYAZIBJAoKcHJvamVjdF9pZBIWQhQxMTM4NjM3MDAzMjA3ODYyMDkxMw&filename=&opi=89354086",
    "threat_intel": "https://contribution.usercontent.google.com/download?c=CgthaWRhX2NvZGVmeBJ8Eh1hcHBfY29tcGFuaW9uX2dlbmVyYXRlZF9maWxlcxpbCiVodG1sX2Y0MWZhMmM4NDE2ODQ1ZjQ4NzUwMTZhMDcwNzIzZjAwEgsSBxCF3ID_ygwYAZIBJAoKcHJvamVjdF9pZBIWQhQxMTM4NjM3MDAzMjA3ODYyMDkxMw&filename=&opi=89354086",
    "chat": "https://contribution.usercontent.google.com/download?c=CgthaWRhX2NvZGVmeBJ8Eh1hcHBfY29tcGFuaW9uX2dlbmVyYXRlZF9maWxlcxpbCiVodG1sXzJiM2JlNDJlMGMyYjQyZmM5NWMwNzcxMTZkZTgzNjY3EgsSBxCF3ID_ygwYAZIBJAoKcHJvamVjdF9pZBIWQhQxMTM4NjM3MDAzMjA3ODYyMDkxMw&filename=&opi=89354086",
    "settings": "https://contribution.usercontent.google.com/download?c=CgthaWRhX2NvZGVmeBJ8Eh1hcHBfY29tcGFuaW9uX2dlbmVyYXRlZF9maWxlcxpbCiVodG1sX2E1ZDJjMzU0NjE4NjRlODM4MjBhMDMyYjA0OTEyNWI1EgsSBxCF3ID_ygwYAZIBJAoKcHJvamVjdF9pZBIWQhQxMTM4NjM3MDAzMjA3ODYyMDkxMw&filename=&opi=89354086"
}

os.makedirs("frontend/static", exist_ok=True)

headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
}

for name, url in screens.items():
    print(f"Downloading {name}...")
    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req) as response:
            html = response.read().decode('utf-8')
            # Save raw HTML template
            with open(f"frontend/static/{name}.html", "w", encoding="utf-8") as f:
                f.write(html)
            print(f"Saved frontend/static/{name}.html")
    except Exception as e:
        print(f"Error downloading {name}: {e}")

print("Done downloading all screens!")
