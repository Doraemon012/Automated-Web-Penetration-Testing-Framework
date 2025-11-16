import sys
import os
import threading
import json
from datetime import datetime
from flask import Flask, render_template, request, jsonify, send_file

# Add the parent directory to the Python path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from main import run_complete_scan
    from crawler.crawler import Crawler
    from utils.helpers import normalize_url, is_site_up
    from utils.session_manager import SessionManager
    from scanners.headers import check_security_headers
    from scanners.sqli import test_sqli
    from scanners.xss import test_xss
    from scanners.misconfig import check_misconfig, check_open_redirect, fuzz_url_params
    from scanners.injection import test_command_injection, test_authentication_weaknesses, test_ssrf, test_xml_injection, test_html_injection
    from scanners.file_upload import test_file_upload
    from reports.reporter import Reporter
    from reports.risk import enrich_findings
    from reports.cvss_compute import enhance_finding_with_cvss, deduplicate_findings
    
    # Try to import JS crawler, but don't fail if not available
    try:
        from crawler.js_crawler import JSCrawler
        JS_CRAWLER_AVAILABLE = True
    except ImportError:
        JS_CRAWLER_AVAILABLE = False
        print("JavaScript crawler not available. Install playwright: pip install playwright && playwright install")
except ImportError as e:
    print(f"Could not import project modules. Make sure your project structure is correct. Error: {e}")
    JS_CRAWLER_AVAILABLE = False
    # Define dummy classes/functions if imports fail, to allow the app to at least start.
    class Reporter:
        def __init__(self): self.findings = []
        def add_findings(self, f): pass
        def save_json(self, fn, data): pass
        def save_markdown(self, fn, data): pass
    # You might need to add more dummy functions for other missing imports if you run into issues.

app = Flask(__name__)

# Global variables to track scan status
scan_status = {
    'running': False,
    'progress': 0,
    'current_task': '',
    'results': None,
    'error': None
}

def run_scan_background(target_url, scan_config=None):
    """Run the complete scan in a background thread with enhanced features"""
    global scan_status
    session_manager = None
    
    try:
        scan_status.update({'running': True, 'progress': 0, 'current_task': 'Initializing...', 'error': None})
        
        target = normalize_url(target_url)
        
        scan_status.update({'current_task': 'Checking target availability...', 'progress': 10})
        if not is_site_up(target):
            raise Exception(f"Target is down or unreachable: {target}")
        
        # Initialize session manager if authentication is provided
        if scan_config and scan_config.get('auth_type'):
            scan_status.update({'current_task': 'Setting up authentication...', 'progress': 15})
            session_manager = SessionManager(target)
            
            auth_type = scan_config['auth_type']
            if auth_type == 'form':
                success = session_manager.login_form(
                    scan_config.get('login_url', '/login'),
                    scan_config.get('username', ''),
                    scan_config.get('password', '')
                )
            elif auth_type == 'token':
                success = session_manager.login_token(
                    scan_config.get('token', ''),
                    'Authorization',
                    'Bearer'
                )
            elif auth_type == 'basic':
                success = session_manager.login_basic_auth(
                    scan_config.get('username', ''),
                    scan_config.get('password', '')
                )
            else:
                success = False
                
            if not success:
                scan_status.update({'current_task': 'Authentication failed, continuing with unauthenticated scan...', 'progress': 20})
        
        # Check if JS rendering is enabled
        js_enabled = scan_config.get('js_enabled', False) if scan_config else False
        use_jscrawler = js_enabled and JS_CRAWLER_AVAILABLE
        
        print(f"[DEBUG] Full scan_config: {scan_config}")
        print(f"[DEBUG] js_enabled from config: {js_enabled}, JS_CRAWLER_AVAILABLE: {JS_CRAWLER_AVAILABLE}, use_jscrawler: {use_jscrawler}")
        
        scan_status.update({'current_task': f'Starting {"JavaScript-enabled" if use_jscrawler else "regular"} crawler...', 'progress': 25})
        
        # Adjust crawl scope based on mode
        mode = scan_config.get('mode', 'standard') if scan_config else 'standard'
        if mode == 'ultra-safe':
            max_depth = 1
        elif mode == 'safe':
            max_depth = 1
        else:
            max_depth = 2
        
        # Choose crawler based on JS support
        if use_jscrawler:
            print("[+] Using JavaScript-enabled crawler (Playwright)")
            print("[+] This will take longer but finds more vulnerabilities on JS-heavy sites")
            import asyncio
            from concurrent.futures import ThreadPoolExecutor
            
            crawler = JSCrawler(target, max_depth=max_depth, session_manager=session_manager)
            
            # Run async crawler in thread pool
            def run_async_crawl():
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                try:
                    return loop.run_until_complete(crawler.run_crawl())
                finally:
                    loop.close()
            
            with ThreadPoolExecutor() as executor:
                future = executor.submit(run_async_crawl)
                future.result(timeout=300)  # 5 minute timeout
            
            crawler.save_results()
        else:
            if js_enabled and not JS_CRAWLER_AVAILABLE:
                print("[-] JavaScript crawler requested but not available.")
                print("[!] To use JavaScript crawler, install Playwright:")
                print("[!]   pip install playwright")
                print("[!]   playwright install chromium")
                print("[!] Using regular HTML crawler instead...")
            crawler = Crawler(target, max_depth=max_depth, session_manager=session_manager)
            crawler.crawl()
            crawler.save_results()
        
        reporter = Reporter()
        
        # Run scans with authenticated session if available
        session = session_manager.get_session() if session_manager else None
        discovered_links = crawler.discovered.get("links", [])
        
        # Check if target is a large public site (for ultra-safe mode)
        from scanners.headers import is_large_public_site
        is_large_site = is_large_public_site(target)
        
        scan_status.update({'current_task': 'Analyzing security headers...', 'progress': 40})
        print("[DEBUG] Checking headers...")
        if mode == 'ultra-safe':
            print("[DEBUG] Skipping headers for ultra-safe mode")
            scan_status.update({'current_task': 'Skipping headers analysis in ultra-safe mode...', 'progress': 45})
        else:
            reporter.add_findings(check_security_headers(target, session, discovered_links))
            print("[DEBUG] Headers check complete")
        
        if mode != 'ultra-safe':
            scan_status.update({'current_task': 'Testing for SQL injection...', 'progress': 50})
            print(f"[DEBUG] Checking SQLi in {mode} mode...")
            reporter.add_findings(test_sqli(target, crawler.discovered["forms"], session, mode=mode))
            print("[DEBUG] SQLi check complete")
        else:
            print("[DEBUG] Skipping SQLi for ultra-safe mode")
            scan_status.update({'current_task': 'Skipping SQL injection testing in ultra-safe mode...', 'progress': 55})
        
        if mode != 'ultra-safe':
            scan_status.update({'current_task': 'Testing for XSS vulnerabilities...', 'progress': 55})
            print("[DEBUG] Checking XSS...")
            strict_xss = (mode != 'aggressive')
            reporter.add_findings(test_xss(target, crawler.discovered["forms"], session, strict=strict_xss))
            print("[DEBUG] XSS check complete")
        else:
            print("[DEBUG] Skipping XSS for ultra-safe mode")
            scan_status.update({'current_task': 'Skipping XSS testing in ultra-safe mode...', 'progress': 60})
        
        if mode != 'ultra-safe':
            scan_status.update({'current_task': 'Checking for misconfigurations...', 'progress': 60})
            print("[DEBUG] Checking misconfig...")
            reporter.add_findings(check_misconfig(target, session))
            print("[DEBUG] Misconfig check complete")
        else:
            print("[DEBUG] Skipping misconfig for ultra-safe mode")
            scan_status.update({'current_task': 'Skipping misconfig checks in ultra-safe mode...', 'progress': 65})
        
        if mode in ('standard', 'aggressive'):
            scan_status.update({'current_task': 'Testing for authentication weaknesses...', 'progress': 65})
            reporter.add_findings(test_authentication_weaknesses(target, session))
        
        if mode == 'aggressive':
            scan_status.update({'current_task': 'Testing for command injection...', 'progress': 70})
            reporter.add_findings(test_command_injection(target, crawler.discovered["forms"], session))
            
            scan_status.update({'current_task': 'Testing for file upload vulnerabilities...', 'progress': 72})
            reporter.add_findings(test_file_upload(target, crawler.discovered["forms"], session))
            
            scan_status.update({'current_task': 'Testing for XML/XXE injection...', 'progress': 74})
            reporter.add_findings(test_xml_injection(target, crawler.discovered["forms"], session))
            
            scan_status.update({'current_task': 'Testing for HTML injection...', 'progress': 76})
            reporter.add_findings(test_html_injection(target, crawler.discovered["forms"], session))
            
            scan_status.update({'current_task': 'Testing for open redirects...', 'progress': 78})
            reporter.add_findings(check_open_redirect(target, discovered_links, session))
            
            scan_status.update({'current_task': 'Testing for SSRF vulnerabilities...', 'progress': 80})
            reporter.add_findings(test_ssrf(target, crawler.discovered["forms"], discovered_links, session))
            
            scan_status.update({'current_task': 'Fuzzing URL parameters...', 'progress': 85})
            for link in discovered_links[:20]:  # Limit to 20 links to avoid excessive requests
                reporter.add_findings(fuzz_url_params(link, session=session))
        
        print(f"[DEBUG] All scans complete. Total findings: {len(reporter.findings)}")
        scan_status.update({'current_task': 'Generating reports...', 'progress': 95})
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        json_filename = f"report_{timestamp}.json"
        md_filename = f"report_{timestamp}.md"
        
        # Enhanced CVSS scoring pipeline
        print(f"[DEBUG] Starting CVSS enrichment for {len(reporter.findings)} findings...")
        reporter.findings = [enhance_finding_with_cvss(f) for f in reporter.findings]
        print(f"[DEBUG] CVSS enrichment complete. Deduplicating...")
        reporter.findings = deduplicate_findings(reporter.findings)
        print(f"[DEBUG] Deduplication complete. {len(reporter.findings)} unique findings.")
        print(f"[DEBUG] Finalizing report generation...")
        
        # Apply CWE mapping from existing risk.py
        reporter.findings = enrich_findings(reporter.findings)
        
        # Prepare the results dictionary
        vulnerabilities = {}
        for finding in reporter.findings:
            severity = finding.get('severity', 'Info')
            vulnerabilities[severity] = vulnerabilities.get(severity, 0) + 1
        
        scan_time = datetime.now().isoformat()

        # Save reports
        reporter.save_json(json_filename)
        reporter.save_markdown(md_filename)
        
        # Also save the complete scan results with metadata
        complete_results = {
            'target_url': target,
            'total_vulnerabilities': len(reporter.findings),
            'vulnerabilities_by_severity': vulnerabilities,
            'scan_time': scan_time,
            'mode': mode,
            'auth_used': bool(session_manager and session_manager.authenticated),
            'findings': reporter.findings
        }
        
        with open(json_filename, 'w', encoding='utf-8') as f:
            json.dump(complete_results, f, indent=4)
        reporter.findings.clear()

        scan_status['results'] = {
            'total_vulnerabilities': complete_results['total_vulnerabilities'],
            'vulnerabilities_by_severity': vulnerabilities,
            'json_report': json_filename,
            'md_report': md_filename,
            'target_url': target,
            'scan_time': scan_time,
            'mode': mode,
            'auth_used': bool(session_manager and session_manager.authenticated),
            'findings_file': json_filename
        }
        
        scan_status.update({'current_task': 'Scan completed!', 'progress': 100})
        
    except Exception as e:
        import traceback
        error_msg = str(e)
        traceback_str = traceback.format_exc()
        print(f"[ERROR] Scan failed: {error_msg}")
        print(f"[ERROR] Traceback:\n{traceback_str}")
        scan_status['error'] = error_msg
    finally:
        if session_manager:
            session_manager.logout()
        scan_status['running'] = False

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/api/scan', methods=['POST'])
def start_scan():
    global scan_status
    if scan_status['running']:
        return jsonify({'error': 'Scan already in progress'}), 400
    
    data = request.get_json()
    target_url = data.get('url')
    if not target_url:
        return jsonify({'error': 'URL is required'}), 400
    
    # Extract scan configuration
    scan_config = {
        'mode': data.get('mode', 'standard'),
        'auth_type': data.get('auth_type', ''),
        'username': data.get('username', ''),
        'password': data.get('password', ''),
        'login_url': data.get('login_url', ''),
        'token': data.get('token', ''),
        'js_enabled': data.get('js_enabled', False)
    }
    
    scan_status = {'running': True, 'progress': 0, 'current_task': 'Starting scan...', 'results': None, 'error': None}
    
    thread = threading.Thread(target=run_scan_background, args=(target_url, scan_config))
    thread.daemon = True
    thread.start()
    
    return jsonify({'status': 'started', 'message': 'Scan initiated successfully'})

@app.route('/api/status')
def get_status():
    return jsonify(scan_status)

@app.route('/api/results')
def get_results():
    """Get scan results"""
    if not scan_status['results']:
        return jsonify({'error': 'No results available'}), 404

    results = dict(scan_status['results'])
    if 'findings' not in results:
        findings_file = results.get('findings_file') or results.get('json_report')
        findings_data = []
        if findings_file and os.path.exists(findings_file):
            try:
                with open(findings_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                if isinstance(data, dict) and isinstance(data.get('findings'), list):
                    findings_data = data['findings']
                elif isinstance(data, list):
                    findings_data = data
            except Exception as exc:
                print(f"[ERROR] Failed to load findings from {findings_file}: {exc}")
        results['findings'] = findings_data
    return jsonify(results)

@app.route('/api/download/<path:filename>')
def download_report(filename):
    if os.path.exists(filename) and os.path.isfile(filename):
        return send_file(filename, as_attachment=True)
    return jsonify({'error': 'File not found'}), 404

@app.route('/history')
def scan_history():
    reports = []
    for file in sorted(os.listdir('.'), reverse=True):
        if file.startswith('report_') and file.endswith('.json'):
            try:
                with open(file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                
                timestamp_str = file.replace('report_', '').replace('.json', '')
                try:
                    dt_obj = datetime.strptime(timestamp_str, "%Y%m%d_%H%M%S")
                    formatted_time = dt_obj.strftime('%Y-%m-%d %H:%M:%S')
                except ValueError:
                    formatted_time = timestamp_str.replace('_', ' ')

                # Handle different data formats
                if isinstance(data, dict):
                    # New format with metadata
                    target_url = data.get('target_url', 'N/A')
                    vulnerability_count = data.get('total_vulnerabilities', 0)
                    scan_mode = data.get('mode', 'Unknown')
                    auth_used = data.get('auth_used', False)
                    scan_time = data.get('scan_time', 'Unknown')
                    vulnerabilities_by_severity = data.get('vulnerabilities_by_severity', {})
                elif isinstance(data, list):
                    # Old format - list of findings, try to extract URL from first finding
                    vulnerability_count = len(data)
                    scan_mode = 'Unknown'
                    auth_used = False
                    scan_time = 'Unknown'
                    vulnerabilities_by_severity = {}
                    
                    if data and isinstance(data[0], dict) and 'url' in data[0]:
                        # Extract domain from first finding's URL
                        first_url = data[0]['url']
                        try:
                            from urllib.parse import urlparse
                            parsed = urlparse(first_url)
                            target_url = f"{parsed.scheme}://{parsed.netloc}"
                        except:
                            target_url = first_url
                    else:
                        target_url = 'N/A'
                else:
                    # Unknown format
                    target_url = 'N/A'
                    vulnerability_count = 0
                    scan_mode = 'Unknown'
                    auth_used = False
                    scan_time = 'Unknown'
                    vulnerabilities_by_severity = {}

                reports.append({
                    'json_file': file,
                    'md_file': file.replace('.json', '.md'),
                    'timestamp': formatted_time,
                    'target_url': target_url,
                    'vulnerability_count': vulnerability_count,
                    'scan_mode': scan_mode,
                    'auth_used': auth_used,
                    'scan_time': scan_time,
                    'vulnerabilities_by_severity': vulnerabilities_by_severity
                })
            except (IOError, json.JSONDecodeError) as e:
                print(f"Could not process report file {file}: {e}")
    
    return render_template('history.html', reports=reports)

@app.route('/docs')
def docs():
    return render_template('docs.html')

if __name__ == '__main__':
    # Make sure you have a 'templates' folder with your html files in it.
    app.run(debug=True, host='0.0.0.0', port=5000)