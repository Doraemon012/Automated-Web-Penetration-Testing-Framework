import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, urldefrag, parse_qs, urlunparse
import json
import time
import re
from collections import defaultdict

class Crawler:
    def __init__(self, base_url, max_depth=2, respect_robots=True, session_manager=None, max_pages=100):
        self.base_url = base_url
        self.visited = set()
        self.discovered = {"links": [], "forms": []}
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.respect_robots = respect_robots
        self.robots_disallowed = set()
        self.session_manager = session_manager
        self.pages_crawled = 0
        
        # Enhanced deduplication
        self.url_patterns = defaultdict(set)  # Track URL patterns to avoid infinite loops
        self.parameter_variants = defaultdict(set)  # Track parameter combinations
        
        if self.respect_robots:
            self.parse_robots()

    def parse_robots(self):
        try:
            session = self.session_manager.get_session() if self.session_manager else requests
            r = session.get(urljoin(self.base_url, "/robots.txt"), timeout=5)
            for line in r.text.splitlines():
                if line.startswith("Disallow:"):
                    path = line.split(":")[1].strip()
                    self.robots_disallowed.add(urljoin(self.base_url, path))
        except requests.RequestException:
            pass

    def is_internal(self, url):
        return urlparse(url).netloc == urlparse(self.base_url).netloc

    def normalize_url(self, url):
        """Enhanced URL normalization with better deduplication"""
        url, _ = urldefrag(url)  # remove fragments
        parsed = urlparse(url)
        
        # Normalize path
        path = parsed.path.rstrip("/") or "/"
        
        # Handle query parameters with intelligent deduplication
        query_params = parse_qs(parsed.query, keep_blank_values=True)
        
        # Remove common pagination/tracking parameters that cause infinite loops
        ignore_params = {
            'page', 'p', 'offset', 'start', 'limit', 'pagesize', 'pagenum',
            'utm_source', 'utm_medium', 'utm_campaign', 'utm_term', 'utm_content',
            'fbclid', 'gclid', '_ga', '_gid', 'sessionid', 'timestamp', 'rand', 'random'
        }
        
        # Filter out ignored parameters
        filtered_params = {k: v for k, v in query_params.items() if k.lower() not in ignore_params}
        
        # Sort parameters for consistent URLs
        sorted_params = sorted(filtered_params.items())
        query = "&".join([f"{k}={v[0]}" for k, v in sorted_params])
        
        normalized = urlunparse((parsed.scheme or "http", parsed.netloc, path, "", query, ""))
        
        # Track URL patterns to detect parameter-based infinite loops
        base_path = f"{parsed.scheme or 'http'}://{parsed.netloc}{path}"
        param_signature = tuple(sorted(filtered_params.keys()))
        
        # Avoid infinite parameter variations
        if len(self.parameter_variants[base_path]) > 5:  # Limit parameter variations per path
            return None
            
        self.parameter_variants[base_path].add(param_signature)
        
        return normalized

    def is_duplicate_pattern(self, url):
        """Detect if URL follows a pattern we've already crawled extensively"""
        parsed = urlparse(url)
        path_parts = [part for part in parsed.path.split('/') if part]
        
        # Create pattern by replacing numbers with placeholders
        pattern_parts = []
        for part in path_parts:
            if re.match(r'^\d+$', part):  # Pure number
                pattern_parts.append('[ID]')
            elif re.search(r'\d+', part):  # Contains numbers
                pattern_parts.append(re.sub(r'\d+', '[NUM]', part))
            else:
                pattern_parts.append(part)
        
        pattern = '/' + '/'.join(pattern_parts)
        
        # Limit similar patterns
        if len(self.url_patterns[pattern]) > 3:
            return True
            
        self.url_patterns[pattern].add(url)
        return False

    def get_links(self, url):
        links = []
        try:
            session = self.session_manager.get_session() if self.session_manager else requests
            response = session.get(url, timeout=5)
            soup = BeautifulSoup(response.text, "html.parser")

            # Extract anchor tags
            for a_tag in soup.find_all("a", href=True):
                href = a_tag["href"]
                
                # Skip javascript links, email links, etc.
                if href.startswith(('javascript:', 'mailto:', 'tel:', 'ftp:')):
                    continue
                    
                full_url = urljoin(url, href)
                normalized_url = self.normalize_url(full_url)
                
                if (normalized_url and 
                    self.is_internal(normalized_url) and 
                    normalized_url not in self.visited and
                    not self.is_duplicate_pattern(normalized_url)):
                    
                    if not self.respect_robots or normalized_url not in self.robots_disallowed:
                        links.append(normalized_url)

            # Extract forms (improved deduplication)
            for form in soup.find_all("form"):
                action = form.get("action", "")
                if not action:
                    action = url  # Form submits to same page
                else:
                    action = urljoin(url, action)
                
                form_details = {
                    "action": action,
                    "method": form.get("method", "get").lower(),
                    "inputs": []
                }
                
                # Extract all input types including hidden fields
                for input_tag in form.find_all(["input", "select", "textarea"]):
                    input_details = {
                        "name": input_tag.get("name"),
                        "type": input_tag.get("type", "text"),
                        "value": input_tag.get("value", "")
                    }
                    
                    # For select elements, get options
                    if input_tag.name == "select":
                        input_details["type"] = "select"
                        options = [opt.get("value", opt.text) for opt in input_tag.find_all("option")]
                        input_details["options"] = options
                    
                    form_details["inputs"].append(input_details)
                
                # Check for duplicate forms (same action + method + input structure)
                form_signature = (
                    form_details["action"],
                    form_details["method"],
                    tuple((inp["name"], inp["type"]) for inp in form_details["inputs"])
                )
                
                # Avoid duplicate forms
                existing_signatures = [
                    (f["action"], f["method"], tuple((inp["name"], inp["type"]) for inp in f["inputs"]))
                    for f in self.discovered["forms"]
                ]
                
                if form_signature not in existing_signatures:
                    self.discovered["forms"].append(form_details)

        except requests.RequestException as e:
            print(f"[-] Error crawling {url}: {e}")
        return links

    def crawl(self, url=None, depth=0):
        if url is None:
            url = self.base_url
            
        if (url in self.visited or 
            depth > self.max_depth or 
            self.pages_crawled >= self.max_pages):
            return

        self.visited.add(url)
        self.pages_crawled += 1
        
        print(f"[+] Crawling [{self.pages_crawled}/{self.max_pages}]: {url}")
        
        # Add to discovered links if not already present
        if url not in self.discovered["links"]:
            self.discovered["links"].append(url)

        # Get links from current page
        new_links = self.get_links(url)
        
        # Crawl discovered links
        for link in new_links:
            if link not in self.visited and self.pages_crawled < self.max_pages:
                time.sleep(0.1)  # Be respectful with delays
                self.crawl(link, depth + 1)

    def save_results(self, filename="discovered.json"):
        # Add metadata to results
        results = {
            "metadata": {
                "base_url": self.base_url,
                "pages_crawled": self.pages_crawled,
                "max_depth": self.max_depth,
                "authenticated": self.session_manager.is_authenticated() if self.session_manager else False,
                "crawl_time": time.strftime("%Y-%m-%d %H:%M:%S")
            },
            "discovered": self.discovered
        }
        
        with open(filename, "w") as f:
            json.dump(results, f, indent=4)
        print(f"[+] Results saved to {filename} - Found {len(self.discovered['links'])} links and {len(self.discovered['forms'])} forms")