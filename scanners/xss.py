import requests
import re
import html
import uuid
from urllib.parse import urlparse

# Site-specific exclusions for XSS testing
XSS_EXCLUSIONS = {
    'google.com': {
        'skip_search_pages': True,
        'reason': 'Search results legitimately reflect user input'
    },
    'bing.com': {
        'skip_search_pages': True,
        'reason': 'Search results legitimately reflect user input'
    },
    'duckduckgo.com': {
        'skip_search_pages': True,
        'reason': 'Search results legitimately reflect user input'
    }
}

def is_search_engine(url):
    """Check if URL belongs to a search engine"""
    parsed = urlparse(url)
    domain = parsed.netloc.lower()
    
    search_engines = [
        'google.com', 'bing.com', 'duckduckgo.com', 'yahoo.com',
        'baidu.com', 'yandex.com', 'ask.com'
    ]
    
    return any(engine in domain for engine in search_engines)

def is_search_page(url):
    """Check if URL is a search page"""
    search_indicators = ['search', 'query', 'q=', 's=', 'search?']
    url_lower = url.lower()
    return any(indicator in url_lower for indicator in search_indicators)

def is_intentional_reflection(url, response_text, payload):
    """Check if reflection is intentional (like search results)"""
    # Check if it's a search engine
    if is_search_engine(url):
        return True
    
    # Check if it's a search page
    if is_search_page(url):
        return True
    
    # Check for search result patterns in response
    search_patterns = [
        r'search.*result',
        r'no.*result.*found',
        r'did.*you.*mean',
        r'search.*for',
        r'query.*result'
    ]
    
    response_lower = response_text.lower()
    return any(re.search(pattern, response_lower) for pattern in search_patterns)

def analyze_reflection_context(response_text, payload):
    """Analyze if reflection is in a vulnerable context"""
    # Check if payload is properly encoded
    if html.escape(payload) in response_text:
        return "safe_encoded"
    
    # Check if in search results context
    if 'search' in response_text.lower() and 'result' in response_text.lower():
        return "search_context"
    
    # Check if in error message context
    error_patterns = [
        r'error.*message',
        r'invalid.*input',
        r'not.*found',
        r'bad.*request'
    ]
    
    for pattern in error_patterns:
        if re.search(pattern, response_text, re.IGNORECASE):
            return "error_context"
    
    return "vulnerable"

def get_xss_site_config(url):
    """Get site-specific XSS configuration"""
    parsed = urlparse(url)
    domain = parsed.netloc.lower()
    
    for site, config in XSS_EXCLUSIONS.items():
        if site in domain:
            return config
    return None

# Enhanced XSS payloads categorized by type
XSS_PAYLOADS = {
    "basic_reflected": [
        "<script>alert(1)</script>",
        "'\"><img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "<iframe src=javascript:alert(1)>",
        "javascript:alert(1)"
    ],
    "attribute_injection": [
        "\" onmouseover=\"alert(1)\"",
        "' onfocus='alert(1)'",
        "\"><svg onload=alert(1)>",
        "'><body onfocus=alert(1)>",
        "\" autofocus onfocus=\"alert(1)\"",
        "' onclick='alert(1)' x='"
    ],
    "context_breaking": [
        "</script><script>alert(1)</script>", 
        "</title><script>alert(1)</script>",
        "</textarea><script>alert(1)</script>",
        "*/alert(1)/*",
        "\";alert(1);//",
        "';alert(1);//"
    ],
    "encoding_bypass": [
        "&lt;script&gt;alert(1)&lt;/script&gt;",
        "%3Cscript%3Ealert(1)%3C/script%3E",
        "&#60;script&#62;alert(1)&#60;/script&#62;",
        "\\x3cscript\\x3ealert(1)\\x3c/script\\x3e"
    ]
}

def test_xss(url, forms, session=None, strict=False):
    """Enhanced XSS testing with multiple detection methods and context awareness.
    If strict=True, only report reflections in clearly executable contexts
    (script or HTML attribute) or exact payload matches.
    """
    issues = []
    
    # Get site-specific configuration
    site_config = get_xss_site_config(url)
    
    # Skip XSS testing for search engines if configured
    if site_config and site_config.get('skip_search_pages') and is_search_page(url):
        return issues
    
    for form in forms:
        target_url = form["action"]
        
        for inp in form["inputs"]:
            if inp["name"]:
                # Test reflected XSS
                reflected_findings = test_reflected_xss(target_url, form, inp, session, strict=strict)
                issues.extend(reflected_findings)
                
                # Test DOM-based XSS (basic check)
                dom_findings = test_dom_xss(target_url, form, inp, session)
                issues.extend(dom_findings)

                # Test stored XSS (submit then revisit)
                stored_findings = test_stored_xss(url, target_url, form, inp, session)
                issues.extend(stored_findings)
    
    return issues

def test_reflected_xss(target_url, form, inp, session=None, strict=False):
    """Test for reflected XSS with enhanced detection.
    If strict=True, filter out non-executable or ambiguous contexts.
    """
    issues = []
    
    # Generate unique marker for this test
    unique_marker = f"XSS_TEST_{uuid.uuid4().hex[:8]}"
    
    # Test different payload categories
    for category, payloads in XSS_PAYLOADS.items():
        for payload in payloads:
            # Add unique marker to payload
            marked_payload = payload.replace("alert(1)", f"alert('{unique_marker}')")
            if "alert" not in payload:
                marked_payload = f"{payload}{unique_marker}"
            
            data = {inp["name"]: marked_payload}
            
            try:
                if form["method"] == "post":
                    if session:
                        response = session.post(target_url, data=data, timeout=5)
                    else:
                        response = requests.post(target_url, data=data, timeout=5)
                else:
                    if session:
                        response = session.get(target_url, params=data, timeout=5)
                    else:
                        response = requests.get(target_url, params=data, timeout=5)
                
                # Check multiple reflection patterns
                xss_detected, context = detect_xss_reflection(response.text, marked_payload, unique_marker)
                
                if xss_detected:
                    # Check if reflection is intentional (like search results)
                    if is_intentional_reflection(target_url, response.text, marked_payload):
                        continue
                    
                    # Analyze reflection context for safety
                    reflection_context = analyze_reflection_context(response.text, marked_payload)
                    if reflection_context in ["safe_encoded", "search_context", "error_context"]:
                        continue
                    
                    # In strict mode, only allow clearly executable contexts
                    if strict and context not in {"script_context", "attribute_context", "exact_match"}:
                        continue
                    
                    # Verify with a second request using different marker
                    if verify_xss_finding(target_url, form, inp, payload, session):
                        severity = determine_xss_severity(context, marked_payload)
                        
                        issues.append({
                            "vulnerability": f"Cross-Site Scripting (XSS) - {category.replace('_', ' ').title()}",
                            "url": target_url,
                            "payload": marked_payload,
                            "severity": severity,
                            "description": f"XSS payload reflected in {context}",
                            "evidence": f"Payload reflected in response {context}",
                            "parameter": inp["name"],
                            "method": form["method"].upper(),
                            "context": context,
                            "recommendation": "Implement proper input validation and output encoding"
                        })
                        break  # Don't test more payloads for same param in this category
                        
            except requests.RequestException:
                continue
    
    return issues

def test_stored_xss(base_url, target_url, form, inp, session=None):
    """Basic stored XSS detection: submit unique marker, revisit key pages, and look for the marker."""
    issues = []
    unique_marker = f"STORED_XSS_{uuid.uuid4().hex[:8]}"
    payload = f"<script>alert('{unique_marker}')</script>"
    data = {inp["name"]: payload}
    
    try:
        # Submit payload
        if form["method"] == "post":
            (session.post if session else requests.post)(target_url, data=data, timeout=7)
        else:
            (session.get if session else requests.get)(target_url, params=data, timeout=7)
    except requests.RequestException:
        return issues
    
    # Revisit likely pages where content may render (target page and base URL)
    revisit_urls = list({target_url, base_url})
    for revisit in revisit_urls:
        try:
            response = (session.get if session else requests.get)(revisit, timeout=7)
            detected, context = detect_xss_reflection(response.text, payload, unique_marker)
            if detected:
                issues.append({
                    "vulnerability": "Cross-Site Scripting (XSS) - Stored",
                    "url": revisit,
                    "payload": payload,
                    "severity": determine_xss_severity(context, payload),
                    "description": "Stored XSS detected: previously submitted payload rendered on revisit",
                    "evidence": f"Marker {unique_marker} reflected in {context}",
                    "parameter": inp["name"],
                    "method": form["method"].upper(),
                    "context": context,
                    "recommendation": "Sanitize stored content and encode output; validate inputs on write"
                })
                break
        except requests.RequestException:
            continue
    
    return issues

def test_dom_xss(target_url, form, inp, session=None):
    """Basic DOM-based XSS detection"""
    issues = []
    
    # Use simple marker for DOM XSS detection
    dom_marker = f"DOM_XSS_TEST_{uuid.uuid4().hex[:8]}"
    data = {inp["name"]: dom_marker}
    
    try:
        if form["method"] == "post":
            if session:
                response = session.post(target_url, data=data, timeout=5)
            else:
                response = requests.post(target_url, data=data, timeout=5)
        else:
            if session:
                response = session.get(target_url, params=data, timeout=5)
            else:
                response = requests.get(target_url, params=data, timeout=5)
        
        # Look for marker in JavaScript contexts
        js_contexts = [
            r'<script[^>]*>.*?' + re.escape(dom_marker) + r'.*?</script>',
            r'javascript:[^"\']*' + re.escape(dom_marker),
            r'on\w+=["\'][^"\']*' + re.escape(dom_marker),
            r'document\..*?' + re.escape(dom_marker),
            r'window\..*?' + re.escape(dom_marker)
        ]
        
        for pattern in js_contexts:
            if re.search(pattern, response.text, re.IGNORECASE | re.DOTALL):
                issues.append({
                    "vulnerability": "Potential DOM-based XSS",
                    "url": target_url,
                    "payload": dom_marker,
                    "severity": "Medium",
                    "description": "Input reflected in JavaScript context, potential for DOM-based XSS",
                    "evidence": f"Marker found in JavaScript context: {pattern}",
                    "parameter": inp["name"],
                    "method": form["method"].upper(),
                    "context": "JavaScript/DOM",
                    "recommendation": "Review client-side code and implement proper DOM manipulation security"
                })
                break
                
    except requests.RequestException:
        pass
    
    return issues

def detect_xss_reflection(response_text, payload, marker):
    """Enhanced XSS reflection detection"""
    
    # Check for exact payload reflection
    if payload in response_text:
        return True, "exact_match"
    
    # Check for marker in different contexts
    if marker in response_text:
        # Check if in script tags
        if re.search(r'<script[^>]*>.*?' + re.escape(marker) + r'.*?</script>', response_text, re.DOTALL | re.IGNORECASE):
            return True, "script_context"
        
        # Check if in HTML attributes
        if re.search(r'<[^>]*\s+[^>]*=["\'][^"\']*' + re.escape(marker) + r'[^"\']*["\']', response_text):
            return True, "attribute_context"
        
        # Check if in HTML content
        if re.search(r'>[^<]*' + re.escape(marker) + r'[^<]*<', response_text):
            return True, "html_content"
        
        # Check if in JSON response
        if re.search(r'["\']' + re.escape(marker) + r'["\']', response_text):
            return True, "json_context"
        
        # Generic reflection
        return True, "generic_reflection"
    
    # Check for HTML-encoded versions
    encoded_marker = html.escape(marker)
    if encoded_marker in response_text:
        return True, "html_encoded"
    
    # Check for URL-encoded versions
    import urllib.parse
    url_encoded_marker = urllib.parse.quote(marker)
    if url_encoded_marker in response_text:
        return True, "url_encoded"
    
    return False, None

def determine_xss_severity(context, payload):
    """Determine XSS severity based on context and payload"""
    
    # High severity contexts
    if context in ["script_context", "exact_match"] and "<script>" in payload.lower():
        return "High"
    
    # Medium severity contexts  
    if context in ["attribute_context", "html_content"]:
        return "Medium"
    
    # Lower severity for encoded or limited contexts
    if context in ["html_encoded", "url_encoded", "json_context"]:
        return "Low"
    
    # Default medium severity
    return "Medium"

def verify_xss_finding(target_url, form, inp, original_payload, session=None):
    """Verify XSS finding with a different marker"""
    
    verification_marker = f"VERIFY_{uuid.uuid4().hex[:8]}"
    verify_payload = original_payload.replace("alert(1)", f"alert('{verification_marker}')")
    if "alert" not in original_payload:
        verify_payload = f"{original_payload}{verification_marker}"
    
    data = {inp["name"]: verify_payload}
    
    try:
        if form["method"] == "post":
            if session:
                response = session.post(target_url, data=data, timeout=5)
            else:
                response = requests.post(target_url, data=data, timeout=5)
        else:
            if session:
                response = session.get(target_url, params=data, timeout=5)
            else:
                response = requests.get(target_url, params=data, timeout=5)
        
        # Check if verification marker is reflected
        xss_detected, _ = detect_xss_reflection(response.text, verify_payload, verification_marker)
        return xss_detected
        
    except requests.RequestException:
        return False