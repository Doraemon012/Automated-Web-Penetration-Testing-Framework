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
    from reports.reporter import Reporter
    from reports.risk import enrich_findings
except ImportError as e:
    print(f"Could not import project modules. Make sure your project structure is correct. Error: {e}")
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
    
    try:
        scan_status.update({'running': True, 'progress': 0, 'current_task': 'Initializing...', 'error': None})
        
        target = normalize_url(target_url)
        
        scan_status.update({'current_task': 'Checking target availability...', 'progress': 10})
        if not is_site_up(target):
            raise Exception(f"Target is down or unreachable: {target}")
        
        # Initialize session manager if authentication is provided
        session_manager = None
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
        
        scan_status.update({'current_task': 'Starting crawler...', 'progress': 25})
        
        # Adjust crawl scope based on mode
        mode = scan_config.get('mode', 'standard') if scan_config else 'standard'
        if mode == 'ultra-safe':
            max_depth = 1
        elif mode == 'safe':
            max_depth = 1
        else:
            max_depth = 2
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
        if mode != 'ultra-safe' or not is_large_site:
            reporter.add_findings(check_security_headers(target, session, discovered_links))
        else:
            scan_status.update({'current_task': 'Skipping headers analysis for large public site in ultra-safe mode...', 'progress': 45})
        
        if mode in ('standard', 'aggressive') or (mode == 'ultra-safe' and not is_large_site):
            scan_status.update({'current_task': 'Testing for SQL injection...', 'progress': 50})
            reporter.add_findings(test_sqli(target, crawler.discovered["forms"], session))
        
        scan_status.update({'current_task': 'Testing for XSS vulnerabilities...', 'progress': 60})
        if mode != 'ultra-safe' or not is_large_site:
            strict_xss = (mode != 'aggressive')
            reporter.add_findings(test_xss(target, crawler.discovered["forms"], session, strict=strict_xss))
        else:
            scan_status.update({'current_task': 'Skipping XSS testing for large public site in ultra-safe mode...', 'progress': 65})
        
        scan_status.update({'current_task': 'Checking for misconfigurations...', 'progress': 70})
        reporter.add_findings(check_misconfig(target, session))
        
        if mode == 'aggressive':
            scan_status.update({'current_task': 'Testing for open redirects...', 'progress': 80})
            reporter.add_findings(check_open_redirect(target, discovered_links, session))
        
        if mode == 'aggressive':
            scan_status.update({'current_task': 'Fuzzing URL parameters...', 'progress': 90})
            for link in discovered_links:
                reporter.add_findings(fuzz_url_params(link, session=session))
        
        scan_status.update({'current_task': 'Generating reports...', 'progress': 95})
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        json_filename = f"report_{timestamp}.json"
        md_filename = f"report_{timestamp}.md"
        
        # Enrich findings with risk metadata
        reporter.findings = enrich_findings(reporter.findings)
        
        # Prepare the results dictionary
        vulnerabilities = {}
        for finding in reporter.findings:
            severity = finding.get('severity', 'Info')
            vulnerabilities[severity] = vulnerabilities.get(severity, 0) + 1
        
        scan_status['results'] = {
            'total_vulnerabilities': len(reporter.findings),
            'vulnerabilities_by_severity': vulnerabilities,
            'json_report': json_filename,
            'md_report': md_filename,
            'target_url': target,
            'scan_time': datetime.now().isoformat(),
            'findings': reporter.findings,
            'mode': mode,
            'auth_used': bool(session_manager and session_manager.authenticated)
        }
        
        # Save reports
        reporter.save_json(json_filename)
        reporter.save_markdown(md_filename)
        
        # Also save the complete scan results with metadata
        complete_results = {
            'target_url': target,
            'total_vulnerabilities': len(reporter.findings),
            'vulnerabilities_by_severity': vulnerabilities,
            'scan_time': datetime.now().isoformat(),
            'mode': mode,
            'auth_used': bool(session_manager and session_manager.authenticated),
            'findings': reporter.findings
        }
        
        with open(json_filename, 'w', encoding='utf-8') as f:
            json.dump(complete_results, f, indent=4)
        
        scan_status.update({'current_task': 'Scan completed!', 'progress': 100})
        
    except Exception as e:
        scan_status['error'] = str(e)
    finally:
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
        'token': data.get('token', '')
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
    if scan_status['results']:
        return jsonify(scan_status['results'])
    else:
        return jsonify({'error': 'No results available'}), 404

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

if __name__ == '__main__':
    # Make sure you have a 'templates' folder with your html files in it.
    app.run(debug=True, host='0.0.0.0', port=5000)