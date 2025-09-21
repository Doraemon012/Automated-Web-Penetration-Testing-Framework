# scanners/xss.py
import requests

XSS_PAYLOADS = ["<script>alert(1)</script>", "'\"><img src=x onerror=alert(1)>"]

def test_xss(url, forms):
    issues = []
    for form in forms:
        target_url = form["action"]
        for inp in form["inputs"]:
            if inp["name"]:
                for payload in XSS_PAYLOADS:
                    data = {inp["name"]: payload}
                    try:
                        if form["method"] == "post":
                            response = requests.post(target_url, data=data, timeout=5)
                        else:
                            response = requests.get(target_url, params=data, timeout=5)
                        if payload in response.text:
                            issues.append({
                                "vulnerability": "Reflected XSS",
                                "url": target_url,
                                "payload": payload,
                                "severity": "High",
                                "description": "Payload reflected unescaped in response"
                            })
                    except requests.RequestException:
                        continue
    return issues
