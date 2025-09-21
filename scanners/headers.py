import requests

def check_security_headers(url):
    issues = []
    try:
        response = requests.get(url, timeout=5)
        headers = response.headers

        required_headers = {
            "X-Frame-Options": "Protects against clickjacking",
            "Content-Security-Policy": "Helps prevent XSS",
            "Strict-Transport-Security": "Enforces HTTPS"
        }

        for header, desc in required_headers.items():
            if header not in headers:
                issues.append({
                    "vulnerability": f"Missing {header}",
                    "url": url,
                    "payload": None,
                    "severity": "Medium",
                    "description": desc
                })

        # HTTPS check
        if not url.startswith("https://"):
            issues.append({
                "vulnerability": "HTTPS not enforced",
                "url": url,
                "payload": None,
                "severity": "High",
                "description": "Website should enforce HTTPS for security"
            })

    except requests.RequestException:
        pass

    return issues
