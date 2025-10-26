import requests
from urllib.parse import parse_qs, urljoin, urlparse, urlunparse, quote
import re

# Expanded sensitive file/directory list (excluding legitimate public files)
SENSITIVE_PATHS = [
    # Version control
    ".git/", ".git/config", ".git/HEAD", ".gitignore",
    ".svn/", ".hg/", ".bzr/",
    
    # Environment and config files
    ".env", ".env.local", ".env.production", ".env.development",
    "config.php", "config.yml", "config.yaml", "config.json",
    "wp-config.php", "wp-config.php.bak", "configuration.php",
    "settings.py", "local_settings.py", "app.config",
    
    # Backup files
    "backup/", "backups/", "backup.sql", "dump.sql",
    "database.sql", "db_backup.sql", "site_backup.zip",
    ".bak", "backup.tar.gz", "backup.zip",
    
    # System files (keep OS artifacts, drop public files like robots/sitemap)
    ".DS_Store", "Thumbs.db", "desktop.ini",
    # Removed crossdomain.xml - it's legitimately public for Flash/Adobe apps
    
    # Admin/Debug interfaces
    "admin/", "administrator/", "phpmyadmin/", "phpinfo.php",
    "test.php", "debug.php", "info.php", "phpinfo.php",
    "status", "server-status", "server-info",
    
    # Log files
    "error.log", "access.log", "debug.log", "application.log",
    "error_log", "access_log", "logs/", "log/",
    
    # Documentation
    "README.md", "INSTALL.txt", "CHANGELOG.txt", "TODO.txt"
]

# Legitimate public files that should never be flagged
LEGITIMATE_PUBLIC_FILES = [
    "robots.txt", "sitemap.xml", "crossdomain.xml", "favicon.ico",
    "humans.txt", "security.txt", ".well-known/security.txt"
]

def is_legitimate_public_file(path):
    """Check if file is legitimately public and should not be flagged"""
    path_lower = path.lower()
    return any(legitimate in path_lower for legitimate in LEGITIMATE_PUBLIC_FILES)

# Enhanced open redirect payloads
OPEN_REDIRECT_PAYLOADS = [
    "https://evil.com",
    "//evil.com", 
    "http://evil.com",
    "https%3A%2F%2Fevil.com",  # URL encoded
    "%2F%2Fevil.com",          # Protocol-relative encoded
    "https://google.com@evil.com",  # Domain confusion
    "javascript:alert(1)",      # JavaScript scheme
    "data:text/html,<script>alert(1)</script>",  # Data scheme
]

def check_misconfig(base_url, session=None):
    """Enhanced misconfiguration checking"""
    issues = []
    
    # Check sensitive files/directories
    sensitive_findings = check_sensitive_files(base_url, session)
    issues.extend(sensitive_findings)
    
    # Check for directory listing
    directory_findings = check_directory_listing(base_url, session)
    issues.extend(directory_findings)
    
    # Check CORS configuration
    cors_findings = check_cors(base_url, session)
    issues.extend(cors_findings)
    
    # Check cookie security flags
    cookie_findings = check_cookie_security(base_url, session)
    issues.extend(cookie_findings)

    # Check CSRF protections on forms (basic heuristics)
    csrf_findings = check_csrf_tokens(base_url, session)
    issues.extend(csrf_findings)
    
    return issues

def check_sensitive_files(base_url, session=None):
    """Check for exposed sensitive files and directories"""
    issues = []
    
    for path in SENSITIVE_PATHS:
        url = urljoin(base_url, path)
        
        try:
            if session:
                response = session.get(url, timeout=5)
            else:
                response = requests.get(url, timeout=5)
            
            if response.status_code == 200 and len(response.text) > 0:
                # Skip legitimate public files
                if is_legitimate_public_file(path):
                    continue
                
                # Verify it's actually sensitive content, not a 404 page
                if is_sensitive_content(response, path):
                    severity = determine_file_severity(path)
                    content_preview = get_content_preview(response.text, path)
                    
                    issues.append({
                        "vulnerability": f"Sensitive file exposed: {path}",
                        "url": url,
                        "payload": None,
                        "severity": severity,
                        "description": f"Sensitive file or directory '{path}' is publicly accessible",
                        "evidence": f"HTTP {response.status_code}, Content-Length: {len(response.text)}, Preview: {content_preview}",
                        "recommendation": f"Remove or restrict access to '{path}'",
                        "content_type": response.headers.get('Content-Type', 'Unknown')
                    })
                    
        except requests.RequestException:
            continue
    
    return issues

def check_csrf_tokens(base_url, session=None):
    """Heuristic CSRF protection check: Look for forms lacking CSRF tokens and SameSite cookies."""
    issues = []
    try:
        response = (session.get if session else requests.get)(base_url, timeout=7)
        html = response.text
        forms = re.findall(r"<form[^>]*>(.*?)</form>", html, flags=re.IGNORECASE | re.DOTALL)
        for idx, form_html in enumerate(forms):
            # Look for hidden inputs that are likely CSRF tokens
            has_hidden_token = re.search(r"<input[^>]+type=['\"]hidden['\"][^>]*>", form_html, re.IGNORECASE)
            has_common_name = re.search(r"name=['\"](csrf|_csrf|csrfmiddlewaretoken|authenticity_token|__requestverificationtoken)['\"]", form_html, re.IGNORECASE)
            has_meta_csrf = re.search(r"<meta[^>]+name=['\"]csrf-token['\"][^>]*>", html, re.IGNORECASE)
            
            if not (has_hidden_token and has_common_name) and not has_meta_csrf:
                issues.append({
                    "vulnerability": "Potential missing CSRF token in form",
                    "url": base_url,
                    "payload": None,
                    "severity": "Medium",
                    "description": "Form appears to lack a CSRF token field",
                    "evidence": f"Form index {idx} has no recognizable CSRF token",
                    "recommendation": "Include server-generated CSRF token in forms and validate on submit"
                })
    except requests.RequestException:
        pass
    return issues

def check_cors(base_url, session=None):
    """Check for permissive CORS headers and misconfigurations"""
    issues = []
    test_url = urljoin(base_url, "/")
    try:
        response = (session.get if session else requests.get)(test_url, timeout=5)
        acao = response.headers.get("Access-Control-Allow-Origin", "")
        acac = response.headers.get("Access-Control-Allow-Credentials", "")
        acah = response.headers.get("Access-Control-Allow-Headers", "")
        
        # Wildcard with credentials is dangerous
        if acao == "*" and acac.lower() == "true":
            issues.append({
                "vulnerability": "Permissive CORS with credentials",
                "url": test_url,
                "payload": None,
                "severity": "High",
                "description": "CORS allows any origin with credentials enabled",
                "evidence": f"Access-Control-Allow-Origin: {acao}; Access-Control-Allow-Credentials: {acac}",
                "recommendation": "Avoid wildcard origins when credentials are allowed; use explicit origin list"
            })
        
        # Wildcard origin generally risky
        elif acao == "*":
            issues.append({
                "vulnerability": "Permissive CORS",
                "url": test_url,
                "payload": None,
                "severity": "Medium",
                "description": "CORS allows any origin",
                "evidence": f"Access-Control-Allow-Origin: {acao}",
                "recommendation": "Restrict allowed origins to specific domains"
            })
        
        # Check for exposing sensitive headers
        if acah and any(h in acah.lower() for h in ["authorization", "cookie"]):
            issues.append({
                "vulnerability": "CORS exposes sensitive headers",
                "url": test_url,
                "payload": None,
                "severity": "Medium",
                "description": "CORS allows sensitive headers in requests",
                "evidence": f"Access-Control-Allow-Headers: {acah}",
                "recommendation": "Avoid allowing Authorization/Cookie headers for cross-origin requests"
            })
    except requests.RequestException:
        pass
    return issues

def check_cookie_security(base_url, session=None):
    """Check for missing cookie security flags on session cookies"""
    issues = []
    test_url = urljoin(base_url, "/")
    try:
        response = (session.get if session else requests.get)(test_url, timeout=5)
        for cookie in response.cookies:
            name = cookie.name.lower()
            # Heuristic: session/auth cookies likely named like these
            if any(k in name for k in ["session", "auth", "sid", "token"]):
                flags = []
                if not cookie.secure:
                    flags.append("Secure")
                if "httponly" not in cookie._rest.keys():
                    flags.append("HttpOnly")
                # SameSite not directly exposed; check header if present
                set_cookie_headers = response.headers.get("Set-Cookie", "")
                if name in set_cookie_headers.lower() and "samesite" not in set_cookie_headers.lower():
                    flags.append("SameSite")
                if flags:
                    issues.append({
                        "vulnerability": f"Cookie missing security flags: {cookie.name}",
                        "url": test_url,
                        "payload": None,
                        "severity": "Medium",
                        "description": f"Cookie lacks: {', '.join(flags)}",
                        "evidence": f"Set-Cookie for {cookie.name}: {set_cookie_headers}",
                        "recommendation": "Set Secure, HttpOnly, and SameSite on session cookies"
                    })
    except requests.RequestException:
        pass
    return issues

def check_directory_listing(base_url, session=None):
    """Check for directory listing vulnerabilities"""
    issues = []
    
    # Common directories that might have listing enabled
    test_dirs = [
        "admin/", "backup/", "logs/", "files/", "uploads/", 
        "images/", "css/", "js/", "includes/", "config/"
    ]
    
    for directory in test_dirs:
        url = urljoin(base_url, directory)
        
        try:
            if session:
                response = session.get(url, timeout=5)
            else:
                response = requests.get(url, timeout=5)
            
            if response.status_code == 200:
                if is_directory_listing(response.text):
                    issues.append({
                        "vulnerability": f"Directory listing enabled: {directory}",
                        "url": url,
                        "payload": None,
                        "severity": "Medium",
                        "description": f"Directory '{directory}' has directory listing enabled, exposing file structure",
                        "evidence": f"Directory listing patterns detected in response",
                        "recommendation": f"Disable directory listing for '{directory}'"
                    })
                    
        except requests.RequestException:
            continue
    
    return issues

def check_open_redirect(base_url, discovered_links, session=None):
    """Enhanced open redirect testing"""
    issues = []
    
    # Common redirect parameters
    redirect_params = [
        "next", "url", "redirect", "goto", "return", "returnUrl", 
        "redirectUrl", "target", "dest", "destination", "continue",
        "forward", "ref", "referer", "callback"
    ]
    
    for link in discovered_links:
        parsed = urlparse(link)
        
        # Test with redirect parameters
        for param in redirect_params:
            for payload in OPEN_REDIRECT_PAYLOADS:
                test_url = f"{link}{'&' if parsed.query else '?'}{param}={quote(payload)}"
                
                if test_open_redirect_payload(test_url, payload, session):
                    issues.append({
                        "vulnerability": "Open Redirect",
                        "url": test_url,
                        "payload": payload,
                        "severity": determine_redirect_severity(payload),
                        "description": f"Open redirect vulnerability detected via '{param}' parameter",
                        "evidence": f"Redirects to external domain: {payload}",
                        "parameter": param,
                        "recommendation": "Implement redirect URL validation and whitelist allowed domains"
                    })
    
    return issues

def test_open_redirect_payload(test_url, payload, session=None):
    """Test individual open redirect payload"""
    try:
        if session:
            response = session.get(test_url, timeout=5, allow_redirects=False)
        else:
            response = requests.get(test_url, timeout=5, allow_redirects=False)
        
        if response.status_code in [301, 302, 303, 307, 308]:
            location = response.headers.get("Location", "")
            
            # Check if redirecting to external domain
            if payload in location:
                return True
            
            # Check for encoded versions
            if quote(payload) in location:
                return True
                
    except requests.RequestException:
        pass
    
    return False

def fuzz_url_params(url, payloads=None, session=None):
    """Enhanced URL parameter fuzzing"""
    if payloads is None:
        payloads = [
            # XSS payloads
            "<script>alert(1)</script>",
            "'\"><img src=x onerror=alert(1)>",
            # SQLi payloads  
            "' OR 1=1 --",
            "\" OR \"1\"=\"1",
            # Command injection
            "; ls -la",
            "| whoami",
            # Directory traversal
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
            # LDAP injection
            "*)(uid=*",
            # XPath injection
            "' or '1'='1",
        ]
    
    issues = []
    parsed = urlparse(url)
    qs = parse_qs(parsed.query)
    
    for param in qs:
        for payload in payloads:
            qs_copy = qs.copy()
            qs_copy[param] = [payload]
            new_query = "&".join([f"{k}={v[0]}" for k, v in qs_copy.items()])
            test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, "", new_query, ""))
            
            try:
                if session:
                    response = session.get(test_url, timeout=5)
                else:
                    response = requests.get(test_url, timeout=5)
                
                # Check for payload reflection (XSS)
                if payload in response.text:
                    vulnerability_type = determine_payload_type(payload)
                    
                    issues.append({
                        "vulnerability": f"{vulnerability_type} in URL parameter",
                        "url": test_url,
                        "payload": payload,
                        "severity": determine_payload_severity(payload),
                        "description": f"Payload reflected in response via URL parameter '{param}'",
                        "evidence": f"Payload '{payload}' reflected in response",
                        "parameter": param,
                        "recommendation": "Implement proper input validation and output encoding"
                    })
                    
            except requests.RequestException:
                continue
    
    return issues

def is_sensitive_content(response, path):
    """Determine if response contains actual sensitive content"""
    content = response.text.lower()
    
    # Common 404 page indicators
    not_found_indicators = [
        "not found", "404", "file not found", "page not found",
        "does not exist", "cannot find", "no such file"
    ]
    
    for indicator in not_found_indicators:
        if indicator in content:
            return False
    
    # Path-specific content validation
    if path.endswith('.git/') or '.git' in path:
        git_indicators = ["ref:", "repository", "[core]", "gitdir"]
        return any(indicator in content for indicator in git_indicators)
    
    if path.endswith('.env'):
        env_indicators = ["=", "db_", "api_", "secret", "key", "password"]
        return any(indicator in content for indicator in env_indicators)
    
    if 'config' in path:
        config_indicators = ["<?php", "database", "username", "password", "host"]
        return any(indicator in content for indicator in config_indicators)
    
    # For other files, check length and content type
    return len(response.text) > 10 and response.headers.get('Content-Type', '').startswith('text/')

def is_directory_listing(content):
    """Check if content appears to be a directory listing"""
    listing_patterns = [
        r"<title>Index of /",
        r"Directory listing for",
        r"<h1>Index of", 
        r"Parent Directory",
        r"\[DIR\]",
        r"<pre>.*<a href=",  # Common Apache listing format
        r"<table.*>.*Name.*Size.*Date",  # Table-based listings
    ]
    
    for pattern in listing_patterns:
        if re.search(pattern, content, re.IGNORECASE | re.DOTALL):
            return True
    
    return False

def determine_file_severity(path):
    """Determine severity based on file type"""
    high_risk = ['.env', 'config', '.git', 'backup', 'database', '.sql']
    medium_risk = ['admin', 'phpmyadmin', 'debug', 'log']
    
    path_lower = path.lower()
    
    for risk_file in high_risk:
        if risk_file in path_lower:
            return "High"
    
    for risk_file in medium_risk:
        if risk_file in path_lower:
            return "Medium"
    
    return "Low"

def determine_redirect_severity(payload):
    """Determine open redirect severity"""
    if "javascript:" in payload or "data:" in payload:
        return "High"
    return "Medium"

def determine_payload_type(payload):
    """Determine what type of vulnerability the payload tests for"""
    if "<script>" in payload or "alert(" in payload or "onerror=" in payload:
        return "Cross-Site Scripting (XSS)"
    elif "OR 1=1" in payload or "' OR '" in payload:
        return "SQL Injection"
    elif ";" in payload and ("ls" in payload or "whoami" in payload):
        return "Command Injection"
    elif "../" in payload or "..\\" in payload:
        return "Directory Traversal"
    else:
        return "Code Injection"

def determine_payload_severity(payload):
    """Determine payload severity"""
    if "<script>" in payload or "OR 1=1" in payload:
        return "High"
    elif "alert(" in payload or "onerror=" in payload:
        return "Medium"
    else:
        return "Low"

def get_content_preview(content, path):
    """Get a safe preview of file content"""
    # For binary files or very long content, return metadata
    if len(content) > 1000:
        preview = content[:100] + "..."
    else:
        preview = content[:200]
    
    # Remove newlines and sanitize for JSON
    preview = preview.replace('\n', ' ').replace('\r', ' ').strip()
    
    # For certain file types, return just metadata
    if any(ext in path for ext in ['.zip', '.tar', '.gz', '.sql']):
        return f"File size: {len(content)} bytes"
    
    return preview