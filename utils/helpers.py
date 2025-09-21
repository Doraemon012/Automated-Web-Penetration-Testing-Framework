import requests

def normalize_url(url):
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    return url.rstrip("/")

def is_site_up(url):
    try:
        response = requests.get(url, timeout=5)
        return response.status_code in [200, 301, 302]
    except requests.RequestException:
        return False
