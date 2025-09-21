import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, urldefrag, parse_qs, urlunparse
import json
import time

class Crawler:
    def __init__(self, base_url, max_depth=2, respect_robots=True):
        self.base_url = base_url
        self.visited = set()
        self.discovered = {"links": [], "forms": []}
        self.max_depth = max_depth
        self.respect_robots = respect_robots
        self.robots_disallowed = set()
        if self.respect_robots:
            self.parse_robots()

    def parse_robots(self):
        try:
            r = requests.get(urljoin(self.base_url, "/robots.txt"), timeout=5)
            for line in r.text.splitlines():
                if line.startswith("Disallow:"):
                    path = line.split(":")[1].strip()
                    self.robots_disallowed.add(urljoin(self.base_url, path))
        except requests.RequestException:
            pass

    def is_internal(self, url):
        return urlparse(url).netloc == urlparse(self.base_url).netloc

    def normalize_url(self, url):
        url, _ = urldefrag(url)  # remove fragments
        parsed = urlparse(url)
        path = parsed.path.rstrip("/")
        query = "&".join([f"{k}={v[0]}" for k, v in parse_qs(parsed.query).items()])
        normalized = urlunparse((parsed.scheme or "http", parsed.netloc, path, "", query, ""))
        return normalized

    def get_links(self, url):
        links = []
        try:
            response = requests.get(url, timeout=5)
            soup = BeautifulSoup(response.text, "html.parser")

            # Extract anchor tags
            for a_tag in soup.find_all("a", href=True):
                full_url = urljoin(url, a_tag["href"])
                full_url = self.normalize_url(full_url)
                if self.is_internal(full_url) and full_url not in self.visited:
                    if not self.respect_robots or full_url not in self.robots_disallowed:
                        links.append(full_url)

            # Extract forms (avoid duplicates)
            for form in soup.find_all("form"):
                form_details = {
                    "action": urljoin(url, form.get("action")),
                    "method": form.get("method", "get").lower(),
                    "inputs": []
                }
                for input_tag in form.find_all("input"):
                    form_details["inputs"].append({
                        "name": input_tag.get("name"),
                        "type": input_tag.get("type", "text")
                    })
                if form_details not in self.discovered["forms"]:
                    self.discovered["forms"].append(form_details)

        except requests.RequestException:
            pass
        return links

    def crawl(self, url=None, depth=0):
        if url is None:
            url = self.base_url
        if url in self.visited or depth > self.max_depth:
            return

        self.visited.add(url)
        print(f"[+] Crawling: {url}")
        self.discovered["links"].append(url)

        for link in self.get_links(url):
            if link not in self.visited:
                self.crawl(link, depth + 1)

    def save_results(self, filename="discovered.json"):
        with open(filename, "w") as f:
            json.dump(self.discovered, f, indent=4)
        print(f"[+] Results saved to {filename}")
