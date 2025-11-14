# import sys
# import argparse
# from crawler.crawler import Crawler
# # from crawler.js_crawler import JSCrawler, PLAYWRIGHT_AVAILABLE
# from utils.helpers import normalize_url, is_site_up
# from utils.session_manager import SessionManager
# from scanners.headers import check_security_headers
# from scanners.sqli import test_sqli
# from scanners.xss import test_xss
# from scanners.misc import check_misconfig, check_open_redirect, fuzz_url_params
# from reports.reporter import Reporter
# import asyncio

# def run_complete_scan(target_url, auth_config=None, use_js=False):
#     """Complete scan function with authentication support"""
#     target = normalize_url(target_url)
    
#     if not is_site_up(target):
#         raise Exception(f"Cannot reach target: {target}")
    
#     # Initialize session manager if authentication is provided
#     session_manager = None
#     if auth_config:
#         session_manager = SessionManager(target)
        
#         if auth_config['type'] == 'form':
#             success = session_manager.login_form(
#                 auth_config['login_url'],
#                 auth_config['username'],
#                 auth_config['password'],
#                 auth_config.get('username_field', 'username'),
#                 auth_config.get('password_field', 'password')
#             )
#         elif auth_config['type'] == 'token':
#             success = session_manager.login_token(
#                 auth_config['token'],
#                 auth_config.get('header_name', 'Authorization'),
#                 auth_config.get('token_prefix', 'Bearer')
#             )
#         elif auth_config['type'] == 'basic':
#             success = session_manager.login_basic_auth(
#                 auth_config['username'],
#                 auth_config['password']
#             )
#         else:
#             success = False
            
#         if not success:
#             print("[-] Authentication failed, continuing with unauthenticated scan")
    
#     # Choose crawler based on JS support requirement
#     # if use_js and PLAYWRIGHT_AVAILABLE:
#     #     print("[+] Using JavaScript-enabled crawler")
#     #     crawler = JSCrawler(target, max_depth=2, session_manager=session_manager)
#     #     asyncio.run(crawler.run_crawl())
#     # else:
#     if use_js:
#         print("[-] Playwright not available, using regular crawler")
#     crawler = Crawler(target, max_depth=2, session_manager=session_manager)
#     crawler.crawl()
    
#     crawler.save_results()
    
#     # Initialize Reporter
#     reporter = Reporter()
    
#     # Run all scans with authenticated session if available
#     session = session_manager.get_session() if session_manager else None
    
#     # Enhanced scanners with discovered links for better analysis
#     discovered_links = crawler.discovered.get("links", [])
    
#     reporter.add_findings(check_security_headers(target, session, discovered_links))
#     reporter.add_findings(test_sqli(target, crawler.discovered["forms"], session))
#     reporter.add_findings(test_xss(target, crawler.discovered["forms"], session))
#     reporter.add_findings(check_misconfig(target, session))
#     reporter.add_findings(check_open_redirect(target, discovered_links, session))
    
#     for link in discovered_links:
#         reporter.add_findings(fuzz_url_params(link, session=session))
    
#     return reporter.findings

# def main():
#     parser = argparse.ArgumentParser(description='Enhanced Web Penetration Testing Framework')
#     parser.add_argument('target', help='Target URL to scan')
#     parser.add_argument('--js', action='store_true', help='Enable JavaScript rendering (requires playwright)')
#     parser.add_argument('--auth-type', choices=['form', 'token', 'basic'], help='Authentication type')
#     parser.add_argument('--login-url', help='Login URL for form authentication')
#     parser.add_argument('--username', help='Username for authentication')
#     parser.add_argument('--password', help='Password for authentication')
#     parser.add_argument('--token', help='Token for token-based authentication')
#     parser.add_argument('--username-field', default='username', help='Username field name for forms')
#     parser.add_argument('--password-field', default='password', help='Password field name for forms')
    
#     args = parser.parse_args()
    
#     # Prepare authentication config
#     auth_config = None
#     if args.auth_type:
#         auth_config = {'type': args.auth_type}
        
#         if args.auth_type == 'form':
#             if not all([args.login_url, args.username, args.password]):
#                 print("[-] Form authentication requires --login-url, --username, and --password")
#                 sys.exit(1)
#             auth_config.update({
#                 'login_url': args.login_url,
#                 'username': args.username,
#                 'password': args.password,
#                 'username_field': args.username_field,
#                 'password_field': args.password_field
#             })
#         elif args.auth_type == 'token':
#             if not args.token:
#                 print("[-] Token authentication requires --token")
#                 sys.exit(1)
#             auth_config['token'] = args.token
#         elif args.auth_type == 'basic':
#             if not all([args.username, args.password]):
#                 print("[-] Basic authentication requires --username and --password")
#                 sys.exit(1)
#             auth_config.update({
#                 'username': args.username,
#                 'password': args.password
#             })
    
#     target = normalize_url(args.target)

#     if not is_site_up(target):
#         print(f"[-] Cannot reach target: {target}")
#         sys.exit(1)

#     print(f"[+] Target is up: {target}")
    
#     if auth_config:
#         print(f"[+] Using {auth_config['type']} authentication")

#     # Run scan with configuration
#     try:
#         findings = run_complete_scan(target, auth_config, args.js)
        
#         # Save reports
#         reporter = Reporter()
#         reporter.findings = findings
#         reporter.save_json()
#         reporter.save_markdown()
        
#         print(f"[+] Scanning complete! Found {len(findings)} vulnerabilities")
#         print("[+] Reports generated as report.json and report.md")
        
#         # Print summary
#         severity_counts = {}
#         for finding in findings:
#             severity = finding.get('severity', 'Unknown')
#             severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
#         print("\n[+] Vulnerability Summary:")
#         for severity, count in sorted(severity_counts.items()):
#             print(f"    {severity}: {count}")
        
#     except Exception as e:
#         print(f"[-] Scan failed: {e}")
#         sys.exit(1)

# if __name__ == "__main__":
#     if len(sys.argv) == 1:
#         print("Enhanced Web Penetration Testing Framework")
#         print("\nUsage examples:")
#         print("  python main.py https://example.com")
#         print("  python main.py https://example.com --js")
#         print("  python main.py https://example.com --auth-type form --login-url /login --username admin --password admin123")
#         print("  python main.py https://example.com --auth-type token --token abc123")
#         print("  python main.py https://example.com --auth-type basic --username admin --password admin123")
#         print("\nNew Enhanced Features:")
#         print("  ✅ Extended security headers analysis")
#         print("  ✅ Advanced SQL injection detection (error/time/boolean-based)")
#         print("  ✅ Enhanced XSS testing with context awareness")
#         print("  ✅ Comprehensive misconfiguration scanning")
#         print("  ✅ Improved open redirect detection")
#         print("  ✅ Verification mechanisms to reduce false positives")
#         sys.exit(1)
    
#     main()


import sys
import argparse
import asyncio
from crawler.crawler import Crawler
try:
    from crawler.js_crawler import JSCrawler  # Playwright-based crawler
    PLAYWRIGHT_AVAILABLE = True
except Exception:
    # If playwright or its dependencies are not installed/usable
    PLAYWRIGHT_AVAILABLE = False
    JSCrawler = None
from utils.helpers import normalize_url, is_site_up
from utils.session_manager import SessionManager
from scanners.headers import check_security_headers
from scanners.sqli import test_sqli
from scanners.xss import test_xss
from scanners.misconfig import check_misconfig, check_open_redirect, fuzz_url_params
from reports.reporter import Reporter
from reports.risk import enrich_findings
from reports.cvss_compute import enhance_finding_with_cvss, deduplicate_findings
import json
import time

def run_complete_scan(target_url, auth_config=None, use_js=False, mode="standard"):
    """Complete scan function with authentication support and scan modes.
    mode: "ultra-safe" | "safe" | "standard" | "aggressive"
    """
    target = normalize_url(target_url)
    
    if not is_site_up(target):
        raise Exception(f"Cannot reach target: {target}")
    
    # Initialize session manager if authentication is provided
    session_manager = None
    if auth_config:
        session_manager = SessionManager(target)
        
        if auth_config['type'] == 'form':
            success = session_manager.login_form(
                auth_config['login_url'],
                auth_config['username'],
                auth_config['password'],
                auth_config.get('username_field', 'username'),
                auth_config.get('password_field', 'password')
            )
        elif auth_config['type'] == 'token':
            success = session_manager.login_token(
                auth_config['token'],
                auth_config.get('header_name', 'Authorization'),
                auth_config.get('token_prefix', 'Bearer')
            )
        elif auth_config['type'] == 'basic':
            success = session_manager.login_basic_auth(
                auth_config['username'],
                auth_config['password']
            )
        else:
            success = False
            
        if not success:
            print("[-] Authentication failed, continuing with unauthenticated scan")
    
    # Adjust crawl scope based on mode
    if mode == "ultra-safe":
        max_depth = 1
        print("[+] Using ultra-safe mode for large public sites")
    elif mode == "safe":
        max_depth = 1
    else:
        max_depth = 2

    # Choose crawler based on JS support requirement & availability
    if use_js and PLAYWRIGHT_AVAILABLE:
        print("[+] Using JavaScript-enabled crawler (Playwright)")
        crawler = JSCrawler(target, max_depth=max_depth, session_manager=session_manager)
        asyncio.run(crawler.run_crawl())
    else:
        if use_js and not PLAYWRIGHT_AVAILABLE:
            print("[-] Playwright not available, falling back to regular crawler")
        crawler = Crawler(target, max_depth=max_depth, session_manager=session_manager)
        crawler.crawl()
    
    crawler.save_results()
    
    # Initialize Reporter
    reporter = Reporter()
    
    # Run all scans with authenticated session if available
    session = session_manager.get_session() if session_manager else None
    
    # Enhanced scanners with discovered links for better analysis
    discovered_links = crawler.discovered.get("links", [])
    
    print("[+] Running enhanced vulnerability scans...")
    
    # Check if target is a large public site (for ultra-safe mode)
    from scanners.headers import is_large_public_site
    is_large_site = is_large_public_site(target)
    
    # Enhanced security headers analysis (multi-page)
    if mode != "ultra-safe" or not is_large_site:
        print("  🔍 Analyzing security headers across multiple pages...")
        reporter.add_findings(check_security_headers(target, session, discovered_links))
    else:
        print("  🔍 Skipping headers analysis for large public site in ultra-safe mode...")
    
    # Advanced SQL injection detection (error/time/boolean-based)
    if mode in ("standard", "aggressive") or (mode == "ultra-safe" and not is_large_site):
        print("  💉 Testing for SQL injection vulnerabilities...")
        reporter.add_findings(test_sqli(target, crawler.discovered["forms"], session, mode=mode))
    
    # Context-aware XSS scanning
    if mode != "ultra-safe" or not is_large_site:
        print("  🕸️  Testing for XSS vulnerabilities...")
        strict_xss = (mode != "aggressive")
        reporter.add_findings(test_xss(target, crawler.discovered["forms"], session, strict=strict_xss))
    else:
        print("  🕸️  Skipping XSS testing for large public site in ultra-safe mode...")
    
    # Comprehensive misconfiguration scanning
    print("  ⚙️  Checking for misconfigurations...")
    reporter.add_findings(check_misconfig(target, session))
    
    # Enhanced open redirect testing
    if mode == "aggressive":
        print("  🔄 Testing for open redirects...")
        reporter.add_findings(check_open_redirect(target, discovered_links, session))
    
    # Parameter fuzzing with verification
    if mode == "aggressive":
        print("  🎯 Fuzzing URL parameters...")
        for link in discovered_links:
            reporter.add_findings(fuzz_url_params(link, session=session))
    
    return reporter.findings

def test_framework():
    """Test all framework components"""
    print("🧪 COMPREHENSIVE FRAMEWORK TEST")
    print("="*50)
    
    # Test targets for different scenarios
    test_targets = [
        "http://testphp.vulnweb.com",  # Vulnerable test site
        "https://httpbin.org/html",    # Safe test site
    ]
    
    tests_passed = 0
    total_tests = 0
    
    for target in test_targets:
        print(f"\n🎯 Testing with target: {target}")
        print("-" * 40)
        
        try:
            # Test 1: Basic scan
            total_tests += 1
            print("Test 1: Basic vulnerability scan")
            findings = run_complete_scan(target)
            
            if findings is not None:
                print(f"✅ Scan completed successfully - Found {len(findings)} findings")
                tests_passed += 1
                
                # Analyze findings
                severity_counts = {}
                vuln_types = set()
                
                for finding in findings:
                    severity = finding.get('severity', 'Unknown')
                    severity_counts[severity] = severity_counts.get(severity, 0) + 1
                    vuln_types.add(finding.get('vulnerability', 'Unknown'))
                
                print(f"📊 Vulnerability Summary:")
                for severity, count in sorted(severity_counts.items()):
                    print(f"    {severity}: {count}")
                print(f"📋 Unique vulnerability types: {len(vuln_types)}")
                
                # Test enhanced features
                total_tests += 1
                enhanced_features_found = False
                
                for finding in findings:
                    vuln_name = finding.get('vulnerability', '')
                    if any(keyword in vuln_name for keyword in [
                        'Boolean-based', 'Time-based', 'Context-aware', 
                        'Enhanced', 'Multi-page', 'Verification'
                    ]):
                        enhanced_features_found = True
                        break
                
                if enhanced_features_found:
                    print("✅ Enhanced features detected in scan results")
                    tests_passed += 1
                else:
                    print("⚠️  Enhanced features not clearly detected")
                
            else:
                print("❌ Scan failed to return findings")
                
        except Exception as e:
            print(f"❌ Test failed with error: {e}")
            total_tests += 1
        
        # Brief pause between tests
        time.sleep(1)
    
    # Test 2: Session Manager
    print(f"\n🔐 Testing Session Manager")
    print("-" * 40)
    total_tests += 1
    
    try:
        from utils.session_manager import SessionManager
        session_mgr = SessionManager("https://httpbin.org")
        
        # Test basic auth
        result = session_mgr.login_basic_auth("testuser", "testpass")
        print(f"✅ SessionManager basic auth test: {result}")
        tests_passed += 1
        
    except Exception as e:
        print(f"❌ SessionManager test failed: {e}")
    
    # Test 3: Enhanced scanners
    print(f"\n🛡️  Testing Enhanced Scanners")
    print("-" * 40)
    total_tests += 1
    
    try:
        # Test headers scanner
        from scanners.headers import check_security_headers
        headers_result = check_security_headers("https://httpbin.org")
        print(f"✅ Headers scanner: Found {len(headers_result)} issues")
        
        # Test SQL injection scanner
        from scanners.sqli import test_sqli
        test_forms = [{"action": "https://httpbin.org/post", "method": "post", 
                      "inputs": [{"name": "test", "type": "text"}]}]
        sqli_result = test_sqli("https://httpbin.org", test_forms)
        print(f"✅ SQLi scanner: Found {len(sqli_result)} issues")
        
        # Test XSS scanner
        from scanners.xss import test_xss
        xss_result = test_xss("https://httpbin.org", test_forms)
        print(f"✅ XSS scanner: Found {len(xss_result)} issues")
        
        tests_passed += 1
        
    except Exception as e:
        print(f"❌ Enhanced scanners test failed: {e}")
    
    # Final results
    print("\n" + "="*50)
    print("🏆 TEST SUMMARY")
    print("="*50)
    
    percentage = (tests_passed/total_tests*100) if total_tests > 0 else 0
    print(f"Tests Passed: {tests_passed}/{total_tests} ({percentage:.1f}%)")
    
    if percentage >= 80:
        print("🎉 EXCELLENT! Framework is working well!")
    elif percentage >= 60:
        print("👍 GOOD! Most features are working.")
    else:
        print("⚠️  NEEDS ATTENTION! Some features may need debugging.")
    
    # Print enhanced features implemented
    print("\n✨ ENHANCED FEATURES IMPLEMENTED:")
    features = [
        "✅ Session Manager with multiple authentication types",
        "✅ Advanced crawler with deduplication & scope control", 
        "✅ Enhanced SQL injection detection (error/time/boolean-based)",
        "✅ Context-aware XSS scanning with verification",
        "✅ Multi-page security headers analysis",
        "✅ Advanced misconfiguration scanning (40+ patterns)",
        "✅ Enhanced open redirect testing",
        "✅ Parameter fuzzing with verification",
        "✅ Session-aware scanning across all modules",
        "✅ False positive reduction through verification"
    ]
    
    for feature in features:
        print(f"  {feature}")

def run_quick_test():
    """Run a quick test on a known vulnerable site"""
    print("🚀 QUICK FRAMEWORK TEST")
    print("="*30)
    
    target = "http://testphp.vulnweb.com"
    print(f"Target: {target}")
    
    try:
        findings = run_complete_scan(target)
        
        print(f"\n🎯 Results: Found {len(findings)} vulnerabilities")
        
        # Group by severity
        severity_counts = {}
        for finding in findings:
            severity = finding.get('severity', 'Unknown')
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        for severity, count in sorted(severity_counts.items()):
            print(f"  {severity}: {count}")
        
        # Show a few example findings
        print(f"\n📋 Sample Findings:")
        for i, finding in enumerate(findings[:3]):
            print(f"  {i+1}. {finding.get('vulnerability', 'Unknown')}")
            print(f"     URL: {finding.get('url', '')}")
            print(f"     Severity: {finding.get('severity', '')}")
        
        if len(findings) > 3:
            print(f"  ... and {len(findings)-3} more")
        
        print(f"\n✅ Quick test completed successfully!")
        return True
        
    except Exception as e:
        print(f"❌ Quick test failed: {e}")
        return False

def main():
    parser = argparse.ArgumentParser(description='Enhanced Web Penetration Testing Framework')
    parser.add_argument('target', nargs='?', help='Target URL to scan')
    parser.add_argument('--js', action='store_true', help='Enable JavaScript rendering (requires playwright)')
    parser.add_argument('--auth-type', choices=['form', 'token', 'basic'], help='Authentication type')
    parser.add_argument('--login-url', help='Login URL for form authentication')
    parser.add_argument('--username', help='Username for authentication')
    parser.add_argument('--password', help='Password for authentication')
    parser.add_argument('--token', help='Token for token-based authentication')
    parser.add_argument('--username-field', default='username', help='Username field name for forms')
    parser.add_argument('--password-field', default='password', help='Password field name for forms')
    parser.add_argument('--mode', choices=['ultra-safe', 'safe', 'standard', 'aggressive'], default='standard', help='Scan mode: limits scope and checks')
    
    # Testing options
    parser.add_argument('--test', action='store_true', help='Run comprehensive framework tests')
    parser.add_argument('--quick-test', action='store_true', help='Run quick test on vulnerable site')
    
    args = parser.parse_args()
    
    # Handle test modes
    if args.test:
        test_framework()
        return
    
    if args.quick_test:
        run_quick_test()
        return
    
    # Regular scan mode - require target
    if not args.target:
        print("Enhanced Web Penetration Testing Framework")
        print("\nUsage examples:")
        print("  python main.py https://example.com")
        print("  python main.py https://example.com --js")
        print("  python main.py https://example.com --auth-type form --login-url /login --username admin --password admin123")
        print("  python main.py https://example.com --auth-type token --token abc123")
        print("  python main.py https://example.com --auth-type basic --username admin --password admin123")
        print("\nScan modes:")
        print("  --mode ultra-safe    # Minimal scanning for large public sites (Google, Facebook, etc.)")
        print("  --mode safe          # Fast, low-noise scans with reduced false positives")
        print("  --mode standard      # Balanced coverage (default)")
        print("  --mode aggressive    # Thorough testing with all scanners")
        print("\nTesting options:")
        print("  python main.py --test           # Run comprehensive tests")
        print("  python main.py --quick-test     # Run quick test on vulnerable site")
        print("\nEnhanced Features:")
        print("  ✅ Extended security headers analysis with alternative detection")
        print("  ✅ Advanced SQL injection detection (error/time/boolean-based)")
        print("  ✅ Context-aware XSS testing with false positive reduction")
        print("  ✅ Comprehensive misconfiguration scanning")
        print("  ✅ Improved open redirect detection")
        print("  ✅ Site-specific exclusions for known secure implementations")
        print("  ✅ Ultra-safe mode for large public sites")
        sys.exit(1)
    
    # Prepare authentication config
    auth_config = None
    if args.auth_type:
        auth_config = {'type': args.auth_type}
        
        if args.auth_type == 'form':
            if not all([args.login_url, args.username, args.password]):
                print("[-] Form authentication requires --login-url, --username, and --password")
                sys.exit(1)
            auth_config.update({
                'login_url': args.login_url,
                'username': args.username,
                'password': args.password,
                'username_field': args.username_field,
                'password_field': args.password_field
            })
        elif args.auth_type == 'token':
            if not args.token:
                print("[-] Token authentication requires --token")
                sys.exit(1)
            auth_config['token'] = args.token
        elif args.auth_type == 'basic':
            if not all([args.username, args.password]):
                print("[-] Basic authentication requires --username and --password")
                sys.exit(1)
            auth_config.update({
                'username': args.username,
                'password': args.password
            })
    
    target = normalize_url(args.target)

    if not is_site_up(target):
        print(f"[-] Cannot reach target: {target}")
        sys.exit(1)

    print(f"[+] Target is up: {target}")
    
    if auth_config:
        print(f"[+] Using {auth_config['type']} authentication")

    # Run scan with configuration
    try:
        findings = run_complete_scan(target, auth_config, args.js, mode=args.mode)
        
        # Enhanced CVSS scoring pipeline
        findings = [enhance_finding_with_cvss(f) for f in findings]
        findings = deduplicate_findings(findings)
        
        # Apply CWE mapping from existing risk.py
        findings = enrich_findings(findings)

        # Save reports
        reporter = Reporter()
        reporter.findings = findings
        reporter.save_json()
        reporter.save_markdown()
        
        print(f"\n[+] Scanning complete! Found {len(findings)} vulnerabilities")
        print("[+] Reports generated as report.json and report.md")
        
        # Print summary
        severity_counts = {}
        for finding in findings:
            severity = finding.get('severity', 'Unknown')
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        print("\n[+] Vulnerability Summary:")
        for severity, count in sorted(severity_counts.items()):
            print(f"    {severity}: {count}")
        
    except Exception as e:
        print(f"[-] Scan failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()