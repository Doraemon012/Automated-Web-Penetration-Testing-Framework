import requests
from urllib.parse import parse_qs, urljoin, urlparse, urlunparse

# Sensitive endpoints
SENSITIVE_PATHS = [".git/", ".env", "backup/", "config.php"]

# Open redirect payloads
OPEN_REDIRECT_PAYLOADS = ["https://evil.com", "//evil.com"]

def check_misconfig(base_url):
    issues = []
    for path in SENSITIVE_PATHS:
        url = urljoin(base_url, path)
        try:
            r = requests.get(url, timeout=5)
            if r.status_code == 200 and len(r.text) > 0:
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

def check_open_redirect(base_url, discovered_links):
    issues = []
    for link in discovered_links:
        for payload in OPEN_REDIRECT_PAYLOADS:
            test_url = f"{link}?next={payload}"
            try:
                r = requests.get(test_url, timeout=5, allow_redirects=False)
                if r.status_code in [301, 302] and payload in r.headers.get("Location", ""):
                    issues.append({
                        "vulnerability": "Open Redirect",
                        "url": test_url,
                        "payload": payload,
                        "severity": "Medium",
                        "description": "Open redirect detected"
                    })
            except requests.RequestException:
                continue
    return issues

def fuzz_url_params(url, payloads=["<script>alert(1)</script>", "' OR 1=1 --"]):
    issues = []
    parsed = urlparse(url)
    qs = parse_qs(parsed.query)
    for param in qs:
        for payload in payloads:
            qs_copy = qs.copy()
            qs_copy[param] = payload
            new_query = "&".join([f"{k}={v[0]}" for k, v in qs_copy.items()])
            test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, "", new_query, ""))
            try:
                r = requests.get(test_url, timeout=5)
                if payload in r.text:
                    issues.append({
                        "vulnerability": "Reflected XSS in URL parameter",
                        "url": test_url,
                        "payload": payload,
                        "severity": "High",
                        "description": "Payload reflected in URL parameter"
                    })
            except requests.RequestException:
                continue
    return issues
