# import sys
# from crawler.crawler import Crawler
# from utils.helpers import normalize_url, is_site_up
# from scanners.headers import check_security_headers
# from scanners.sqli import test_sqli
# from scanners.xss import test_xss
# from scanners.misc import check_misconfig, check_open_redirect, fuzz_url_params
# from reports.reporter import Reporter

# if __name__ == "__main__":
#     if len(sys.argv) != 2:
#         print("Usage: python main.py <target_url>")
#         sys.exit(1)

#     target = normalize_url(sys.argv[1])

#     if not is_site_up(target):
#         print(f"[-] Cannot reach target: {target}")
#         sys.exit(1)

#     print(f"[+] Target is up: {target}")

#     # ====================
#     # Step 1: Crawl
#     # ====================
#     crawler = Crawler(target, max_depth=2, respect_robots=True)
#     crawler.crawl()
#     crawler.save_results()

#     # ====================
#     # Step 2: Initialize Reporter
#     # ====================
#     reporter = Reporter()

#     # ====================
#     # Step 3: Run Scans
#     # ====================

#     # 3a: Security headers
#     reporter.add_findings(check_security_headers(target))

#     # 3b: SQL Injection
#     reporter.add_findings(test_sqli(target, crawler.discovered["forms"]))

#     # 3c: XSS
#     reporter.add_findings(test_xss(target, crawler.discovered["forms"]))

#     # 3d: Misconfigurations / Sensitive files
#     reporter.add_findings(check_misconfig(target))

#     # 3e: Open Redirects
#     reporter.add_findings(check_open_redirect(target, crawler.discovered["links"]))

#     # 3f: Parameter fuzzing (XSS / SQLi in URL parameters)
#     for link in crawler.discovered["links"]:
#         reporter.add_findings(fuzz_url_params(link))

#     # ====================
#     # Step 4: Save Reports
#     # ====================
#     reporter.save_json()
#     reporter.save_markdown()

#     print("[+] Scanning complete! Reports generated as report.json and report.md")


import sys
from crawler.crawler import Crawler
from utils.helpers import normalize_url, is_site_up
from scanners.headers import check_security_headers
from scanners.sqli import test_sqli
from scanners.xss import test_xss
from scanners.misc import check_misconfig, check_open_redirect, fuzz_url_params
from reports.reporter import Reporter

def run_complete_scan(target_url):
    """Complete scan function that returns results instead of just printing"""
    target = normalize_url(target_url)
    
    if not is_site_up(target):
        raise Exception(f"Cannot reach target: {target}")
    
    # Crawl
    crawler = Crawler(target, max_depth=2, respect_robots=True)
    crawler.crawl()
    crawler.save_results()
    
    # Initialize Reporter
    reporter = Reporter()
    
    # Run all scans
    reporter.add_findings(check_security_headers(target))
    reporter.add_findings(test_sqli(target, crawler.discovered["forms"]))
    reporter.add_findings(test_xss(target, crawler.discovered["forms"]))
    reporter.add_findings(check_misconfig(target))
    reporter.add_findings(check_open_redirect(target, crawler.discovered["links"]))
    
    for link in crawler.discovered["links"]:
        reporter.add_findings(fuzz_url_params(link))
    
    return reporter.findings

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python main.py <target_url>")
        sys.exit(1)

    target = normalize_url(sys.argv[1])

    if not is_site_up(target):
        print(f"[-] Cannot reach target: {target}")
        sys.exit(1)

    print(f"[+] Target is up: {target}")

    # ====================
    # Step 1: Crawl
    # ====================
    crawler = Crawler(target, max_depth=2, respect_robots=True)
    crawler.crawl()
    crawler.save_results()

    # ====================
    # Step 2: Initialize Reporter
    # ====================
    reporter = Reporter()

    # ====================
    # Step 3: Run Scans
    # ====================

    # 3a: Security headers
    reporter.add_findings(check_security_headers(target))

    # 3b: SQL Injection
    reporter.add_findings(test_sqli(target, crawler.discovered["forms"]))

    # 3c: XSS
    reporter.add_findings(test_xss(target, crawler.discovered["forms"]))

    # 3d: Misconfigurations / Sensitive files
    reporter.add_findings(check_misconfig(target))

    # 3e: Open Redirects
    reporter.add_findings(check_open_redirect(target, crawler.discovered["links"]))

    # 3f: Parameter fuzzing (XSS / SQLi in URL parameters)
    for link in crawler.discovered["links"]:
        reporter.add_findings(fuzz_url_params(link))

    # ====================
    # Step 4: Save Reports
    # ====================
    reporter.save_json()
    reporter.save_markdown()

    print("[+] Scanning complete! Reports generated as report.json and report.md")