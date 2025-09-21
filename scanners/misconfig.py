import requests

SENSITIVE_PATHS = [".git/", ".env", "backup/", "config.php"]

def check_misconfig(base_url):
    issues = []
    for path in SENSITIVE_PATHS:
        url = f"{base_url}/{path}"
        try:
            response = requests.get(url, timeout=5)
            if response.status_code == 200 and len(response.text) > 0:
                issues.append({
                    "vulnerability": f"Sensitive file exposed: {path}",
                    "url": url,
                    "payload": None,
                    "severity": "High",
                    "description": "Sensitive file or directory accessible"
                })
        except requests.RequestException:
            continue
    return issues
