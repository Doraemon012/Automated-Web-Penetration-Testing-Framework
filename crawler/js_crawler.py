import asyncio
from playwright.async_api import async_playwright, TimeoutError as PlaywrightTimeoutError
from urllib.parse import urljoin, urlparse, parse_qs, urlunparse
from bs4 import BeautifulSoup
import json
import time

class JSCrawler:
    def __init__(self, base_url, max_depth=2, session_manager=None, max_pages=100):
        self.base_url = base_url
        self.visited = set()
        self.discovered = {"links": [], "forms": []}
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.session_manager = session_manager
        self.pages_crawled = 0
        self.url_patterns = {}
        self.parameter_variants = {}
        self.browser = None
        self.context = None
        self.page = None
        
    async def init_browser(self):
        """Initialize Playwright browser"""
        self.playwright = await async_playwright().start()
        self.browser = await self.playwright.chromium.launch(
            headless=True,
            args=['--no-sandbox', '--disable-dev-shm-usage']
        )
        
        # Create context with authentication cookies if available
        if self.session_manager and hasattr(self.session_manager, 'session'):
            cookies = self.session_manager.session.cookies
            cookie_list = [
                {
                    'name': c.name,
                    'value': c.value,
                    'domain': c.domain,
                    'path': c.path
                }
                for c in cookies
            ]
            self.context = await self.browser.new_context(storage_state={'cookies': cookie_list})
        else:
            self.context = await self.browser.new_context()
        
        self.page = await self.context.new_page()
        
    async def close_browser(self):
        """Clean up browser resources"""
        if self.context:
            await self.context.close()
        if self.browser:
            await self.browser.close()
        if hasattr(self, 'playwright'):
            await self.playwright.stop()
    
    def normalize_url(self, url):
        """Normalize URL like regular crawler"""
        from urllib.parse import urldefrag
        url, _ = urldefrag(url)
        parsed = urlparse(url)
        
        path = parsed.path.rstrip("/") or "/"
        
        query_params = parse_qs(parsed.query, keep_blank_values=True)
        
        # Remove pagination/tracking params
        ignore_params = {
            'page', 'p', 'offset', 'start', 'limit', 'pagesize',
            'utm_source', 'utm_medium', 'utm_campaign', 'fbclid', 'gclid'
        }
        
        filtered_params = {k: v for k, v in query_params.items() if k.lower() not in ignore_params}
        sorted_params = sorted(filtered_params.items())
        query = "&".join([f"{k}={v[0]}" for k, v in sorted_params])
        
        return urlunparse((parsed.scheme or "http", parsed.netloc, path, "", query, ""))
    
    def is_internal(self, url):
        return urlparse(url).netloc == urlparse(self.base_url).netloc
    
    async def get_links(self, url):
        """Extract links and forms from rendered page"""
        links = []
        
        try:
            await self.page.goto(url, wait_until="networkidle", timeout=30000)
            
            # Wait for JavaScript to render
            await asyncio.sleep(2)
            
            # Get rendered HTML
            content = await self.page.content()
            soup = BeautifulSoup(content, "html.parser")
            
            # Extract anchor tags
            for a_tag in soup.find_all("a", href=True):
                href = a_tag["href"]
                
                if href.startswith(('javascript:', 'mailto:', 'tel:', 'ftp:')):
                    continue
                    
                full_url = urljoin(url, href)
                normalized_url = self.normalize_url(full_url)
                
                if (normalized_url and 
                    self.is_internal(normalized_url) and 
                    normalized_url not in self.visited):
                    links.append(normalized_url)
            
            # Extract forms
            for form in soup.find_all("form"):
                action = form.get("action", "")
                if not action:
                    action = url
                else:
                    action = urljoin(url, action)
                
                form_details = {
                    "action": action,
                    "method": form.get("method", "get").lower(),
                    "inputs": []
                }
                
                # Extract all input types
                for input_tag in form.find_all(["input", "select", "textarea"]):
                    input_details = {
                        "name": input_tag.get("name"),
                        "type": input_tag.get("type", "text"),
                        "value": input_tag.get("value", "")
                    }
                    
                    if input_tag.name == "select":
                        input_details["type"] = "select"
                        options = [opt.get("value", opt.text) for opt in input_tag.find_all("option")]
                        input_details["options"] = options
                    
                    form_details["inputs"].append(input_details)
                
                # Check for duplicate forms
                form_signature = (
                    form_details["action"],
                    form_details["method"],
                    tuple((inp["name"], inp["type"]) for inp in form_details["inputs"])
                )
                
                existing_signatures = [
                    (f["action"], f["method"], tuple((inp["name"], inp["type"]) for inp in f["inputs"]))
                    for f in self.discovered["forms"]
                ]
                
                if form_signature not in existing_signatures:
                    self.discovered["forms"].append(form_details)
        
        except PlaywrightTimeoutError:
            print(f"[-] Timeout loading {url}")
        except Exception as e:
            print(f"[-] Error crawling {url}: {e}")
        
        return links
    
    async def crawl_page(self, url, depth=0):
        """Crawl a single page and its children"""
        if (url in self.visited or 
            depth > self.max_depth or 
            self.pages_crawled >= self.max_pages):
            return
        
        self.visited.add(url)
        self.pages_crawled += 1
        
        print(f"[+] JS Crawler (headless): [{self.pages_crawled}/{self.max_pages}]: {url}")
        
        if url not in self.discovered["links"]:
            self.discovered["links"].append(url)
        
        # Get links from current page
        new_links = await self.get_links(url)
        
        # Crawl discovered links
        for link in new_links:
            if link not in self.visited and self.pages_crawled < self.max_pages:
                await asyncio.sleep(0.5)  # Be respectful with delays
                await self.crawl_page(link, depth + 1)
    
    async def run_crawl(self):
        """Main crawl method"""
        await self.init_browser()
        
        try:
            await self.crawl_page(self.base_url)
        finally:
            await self.close_browser()
    
    def save_results(self, filename="discovered.json"):
        """Save crawl results"""
        results = {
            "metadata": {
                "base_url": self.base_url,
                "pages_crawled": self.pages_crawled,
                "max_depth": self.max_depth,
                "authenticated": self.session_manager.is_authenticated() if self.session_manager else False,
                "crawl_time": time.strftime("%Y-%m-%d %H:%M:%S"),
                "crawler_type": "JavaScript-Enabled (Playwright)"
            },
            "discovered": self.discovered
        }
        
        with open(filename, "w") as f:
            json.dump(results, f, indent=4)
        print(f"[+] Results saved to {filename} - Found {len(self.discovered['links'])} links and {len(self.discovered['forms'])} forms")

