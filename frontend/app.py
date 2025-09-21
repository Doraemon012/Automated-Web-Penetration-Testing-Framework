import sys
import os

# Add the parent directory to the Python path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


from flask import Flask, render_template, request, jsonify, send_file
import threading
import json
from datetime import datetime
from main import run_complete_scan
from crawler.crawler import Crawler
from utils.helpers import normalize_url, is_site_up
from scanners.headers import check_security_headers
from scanners.sqli import test_sqli
from scanners.xss import test_xss
from scanners.misc import check_misconfig, check_open_redirect, fuzz_url_params
from reports.reporter import Reporter

app = Flask(__name__)

# Global variables to track scan status
scan_status = {
    'running': False,
    'progress': 0,
    'current_task': '',
    'results': None,
    'error': None
}

def run_scan_background(target_url):
    """Run the complete scan in background thread"""
    global scan_status
    
    try:
        scan_status['running'] = True
        scan_status['progress'] = 0
        scan_status['current_task'] = 'Initializing...'
        scan_status['error'] = None
        
        target = normalize_url(target_url)
        
        # Check if site is up
        scan_status['current_task'] = 'Checking target availability...'
        scan_status['progress'] = 10
        
        if not is_site_up(target):
            scan_status['error'] = f"Cannot reach target: {target}"
            scan_status['running'] = False
            return
        
        # Initialize crawler
        scan_status['current_task'] = 'Starting crawler...'
        scan_status['progress'] = 20
        
        crawler = Crawler(target, max_depth=2, respect_robots=True)
        crawler.crawl()
        crawler.save_results()
        
        # Initialize reporter
        scan_status['current_task'] = 'Initializing reporter...'
        scan_status['progress'] = 30
        
        reporter = Reporter()
        
        # Run various scans
        scan_status['current_task'] = 'Checking security headers...'
        scan_status['progress'] = 40
        reporter.add_findings(check_security_headers(target))
        
        scan_status['current_task'] = 'Testing for SQL injection...'
        scan_status['progress'] = 50
        reporter.add_findings(test_sqli(target, crawler.discovered["forms"]))
        
        scan_status['current_task'] = 'Testing for XSS vulnerabilities...'
        scan_status['progress'] = 60
        reporter.add_findings(test_xss(target, crawler.discovered["forms"]))
        
        scan_status['current_task'] = 'Checking misconfigurations...'
        scan_status['progress'] = 70
        reporter.add_findings(check_misconfig(target))
        
        scan_status['current_task'] = 'Testing for open redirects...'
        scan_status['progress'] = 80
        reporter.add_findings(check_open_redirect(target, crawler.discovered["links"]))
        
        scan_status['current_task'] = 'Fuzzing URL parameters...'
        scan_status['progress'] = 90
        for link in crawler.discovered["links"]:
            reporter.add_findings(fuzz_url_params(link))
        
        # Save reports
        scan_status['current_task'] = 'Generating reports...'
        scan_status['progress'] = 95
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        json_filename = f"report_{timestamp}.json"
        md_filename = f"report_{timestamp}.md"
        
        reporter.save_json(json_filename)
        reporter.save_markdown(md_filename)
        
        # Prepare results summary
        vulnerabilities = {}
        for finding in reporter.findings:
            severity = finding['severity']
            if severity not in vulnerabilities:
                vulnerabilities[severity] = 0
            vulnerabilities[severity] += 1
        
        scan_status['results'] = {
            'total_vulnerabilities': len(reporter.findings),
            'vulnerabilities_by_severity': vulnerabilities,
            'json_report': json_filename,
            'md_report': md_filename,
            'target_url': target,
            'scan_time': datetime.now().isoformat(),
            'findings': reporter.findings
        }
        
        scan_status['current_task'] = 'Scan completed!'
        scan_status['progress'] = 100
        
    except Exception as e:
        scan_status['error'] = str(e)
    finally:
        scan_status['running'] = False

@app.route('/')
def home():
    """Main dashboard page"""
    return render_template('index.html')

@app.route('/api/scan', methods=['POST'])
def start_scan():
    """Start a new scan"""
    global scan_status
    
    if scan_status['running']:
        return jsonify({'error': 'Scan already in progress'}), 400
    
    data = request.get_json()
    target_url = data.get('url')
    
    if not target_url:
        return jsonify({'error': 'URL is required'}), 400
    
    # Reset scan status
    scan_status = {
        'running': True,
        'progress': 0,
        'current_task': 'Starting scan...',
        'results': None,
        'error': None
    }
    
    # Start scan in background thread
    thread = threading.Thread(target=run_scan_background, args=(target_url,))
    thread.daemon = True
    thread.start()
    
    return jsonify({'status': 'started', 'message': 'Scan initiated successfully'})

@app.route('/api/status')
def get_status():
    """Get current scan status"""
    return jsonify(scan_status)

@app.route('/api/results')
def get_results():
    """Get scan results"""
    if scan_status['results']:
        return jsonify(scan_status['results'])
    else:
        return jsonify({'error': 'No results available'}), 404

@app.route('/api/download/<filename>')
def download_report(filename):
    """Download report file"""
    if os.path.exists(filename):
        return send_file(filename, as_attachment=True)
    else:
        return jsonify({'error': 'File not found'}), 404

@app.route('/history')
def scan_history():
    """Show scan history page"""
    # Get all report files
    reports = []
    for file in os.listdir('.'):
        if file.startswith('report_') and file.endswith('.json'):
            try:
                with open(file, 'r') as f:
                    data = json.load(f)
                    if data:
                        timestamp = file.replace('report_', '').replace('.json', '')
                        reports.append({
                            'filename': file,
                            'timestamp': timestamp,
                            'vulnerability_count': len(data)
                        })
            except:
                pass
    
    reports.sort(key=lambda x: x['timestamp'], reverse=True)
    return render_template('history.html', reports=reports)

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)