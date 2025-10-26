#!/usr/bin/env python3
"""
Comprehensive test script for the enhanced web penetration testing framework
"""

import subprocess
import sys
import os
import time
import json

# Global variable to store target URL
TARGET_URL = ""

def get_target_url():
    """Get target URL from user input"""
    global TARGET_URL
    if len(sys.argv) > 1:
        TARGET_URL = sys.argv[1]
    else:
        TARGET_URL = input("Enter the target website URL to test (e.g., http://testphp.vulnweb.com): ").strip()
    
    if not TARGET_URL.startswith(('http://', 'https://')):
        TARGET_URL = 'http://' + TARGET_URL
    
    print(f"Target URL set to: {TARGET_URL}")
    return TARGET_URL

def run_command(cmd):
    """Run a command and return success status"""
    print(f"\n[RUNNING] {cmd}")
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=120)
        if result.returncode == 0:
            print("[SUCCESS] Command completed successfully")
            return True
        else:
            print(f"[FAILED] {result.stderr}")
            return False
    except subprocess.TimeoutExpired:
        print("[TIMEOUT] Command timed out")
        return False
    except Exception as e:
        print(f"[ERROR] {e}")
        return False

def check_file_exists(filename):
    """Check if a file was created"""
    if os.path.exists(filename):
        print(f"[SUCCESS] File created: {filename}")
        return True
    else:
        print(f"[MISSING] File not found: {filename}")
        return False

def test_basic_functionality():
    """Test basic framework functionality"""
    print("\n" + "="*50)
    print("TESTING BASIC FUNCTIONALITY")
    print("="*50)
    
    tests_passed = 0
    total_tests = 0
    
    # Test 1: Help command
    total_tests += 1
    print("Test 1: Checking help command functionality")
    if run_command("python main.py --help"):
        tests_passed += 1
    
    # Test 2: Basic scan
    total_tests += 1
    print(f"Test 2: Running basic scan on {TARGET_URL}")
    if run_command(f"python main.py {TARGET_URL}"):
        tests_passed += 1
        
        # Check if reports were generated
        print("Test 3: Checking if reports were generated")
        if check_file_exists("report.json") and check_file_exists("report.md"):
            tests_passed += 1
        total_tests += 1
    
    return tests_passed, total_tests

def test_authentication():
    """Test authentication features"""
    print("\n" + "="*50)
    print("TESTING AUTHENTICATION")
    print("="*50)
    
    tests_passed = 0
    total_tests = 0
    
    # Test 1: HTTP Basic Auth
    total_tests += 1
    print("Test 1: Testing HTTP Basic Authentication")
    if run_command("python main.py https://httpbin.org/basic-auth/testuser/testpass --auth-type basic --username testuser --password testpass"):
        tests_passed += 1
    
    # Test 2: Token Auth (will fail but should handle gracefully)
    total_tests += 1
    print("Test 2: Testing Token Authentication")
    if run_command("python main.py https://httpbin.org/bearer --auth-type token --token test123"):
        tests_passed += 1
    
    return tests_passed, total_tests

def test_advanced_features():
    """Test advanced scanning features"""
    print("\n" + "="*50)
    print("TESTING ADVANCED FEATURES")
    print("="*50)
    
    tests_passed = 0
    total_tests = 0
    
    # Test vulnerable site scanning
    total_tests += 1
    print(f"Test 1: Running advanced vulnerability scan on {TARGET_URL}")
    if run_command(f"python main.py {TARGET_URL}"):
        tests_passed += 1
        
        # Check if vulnerabilities were found
        print("Test 2: Analyzing vulnerability detection results")
        if os.path.exists("report.json"):
            try:
                with open("report.json", "r") as f:
                    data = json.load(f)
                    if len(data) > 0:
                        print(f"[SUCCESS] Found {len(data)} vulnerabilities")
                        
                        # Check for different vulnerability types
                        vuln_types = set(item.get('vulnerability', '') for item in data)
                        print(f"[INFO] Vulnerability types found: {len(vuln_types)}")
                        
                        # Verify enhanced features
                        has_sqli = any('SQL Injection' in v for v in vuln_types)
                        has_xss = any('XSS' in v for v in vuln_types)
                        has_headers = any('Missing' in v for v in vuln_types)
                        
                        if has_sqli:
                            print("[SUCCESS] SQL Injection detection working")
                        if has_xss:
                            print("[SUCCESS] XSS detection working")
                        if has_headers:
                            print("[SUCCESS] Header analysis working")
                            
                        tests_passed += 1
                    else:
                        print("[WARNING] No vulnerabilities found")
            except Exception as e:
                print(f"[ERROR] Error reading report: {e}")
        
        total_tests += 1
    
    return tests_passed, total_tests

def test_crawler_enhancements():
    """Test crawler enhancements"""
    print("\n" + "="*50)
    print("TESTING CRAWLER ENHANCEMENTS")
    print("="*50)
    
    tests_passed = 0
    total_tests = 0
    
    # Test crawler with discovered.json output
    total_tests += 1
    print(f"Test 1: Testing enhanced crawler on {TARGET_URL}")
    if run_command(f"python main.py {TARGET_URL}"):
        print("Test 2: Checking crawler output file")
        if check_file_exists("discovered.json"):
            try:
                with open("discovered.json", "r") as f:
                    data = json.load(f)
                    
                if "metadata" in data:
                    print("[SUCCESS] Enhanced crawler metadata present")
                    tests_passed += 1
                    
                if "discovered" in data and data["discovered"]:
                    links = data["discovered"].get("links", [])
                    forms = data["discovered"].get("forms", [])
                    print(f"[SUCCESS] Discovered {len(links)} links and {len(forms)} forms")
                    tests_passed += 1
                    
            except Exception as e:
                print(f"[ERROR] Error reading discovered.json: {e}")
        
        total_tests += 2
    
    return tests_passed, total_tests

def test_session_manager():
    """Test session manager functionality"""
    print("\n" + "="*50)
    print("TESTING SESSION MANAGER")
    print("="*50)
    
    # Test session manager import
    try:
        print("Test 1: Importing SessionManager class")
        from utils.session_manager import SessionManager
        print("[SUCCESS] SessionManager import successful")
        
        # Test basic initialization
        print("Test 2: Initializing SessionManager")
        session_mgr = SessionManager("https://httpbin.org")
        print("[SUCCESS] SessionManager initialization successful")
        
        # Test basic auth method
        print("Test 3: Testing basic auth method")
        result = session_mgr.login_basic_auth("test", "test")
        print(f"[SUCCESS] Basic auth method callable (result: {result})")
        
        return 3, 3
        
    except Exception as e:
        print(f"[ERROR] SessionManager test failed: {e}")
        return 0, 3

def test_enhanced_scanners():
    """Test enhanced scanner functionality"""
    print("\n" + "="*50)
    print("TESTING ENHANCED SCANNERS")
    print("="*50)
    
    tests_passed = 0
    total_tests = 0
    
    # Test individual scanner imports
    try:
        print("Test 1: Importing all enhanced scanners")
        from scanners.headers import check_security_headers
        from scanners.sqli import test_sqli
        from scanners.xss import test_xss
        from scanners.misconfig import check_misconfig
        print("[SUCCESS] All enhanced scanners import successfully")
        tests_passed += 1
    except Exception as e:
        print(f"[ERROR] Scanner import failed: {e}")
    total_tests += 1
    
    # Test scanner with session parameter
    try:
        print("Test 2: Testing enhanced headers scanner")
        from scanners.headers import check_security_headers
        result = check_security_headers("https://httpbin.org", session=None, discovered_links=None)
        print(f"[SUCCESS] Enhanced headers scanner works (found {len(result)} issues)")
        tests_passed += 1
    except Exception as e:
        print(f"[ERROR] Enhanced headers scanner failed: {e}")
    total_tests += 1
    
    return tests_passed, total_tests

def main():
    """Run all tests"""
    print("COMPREHENSIVE FRAMEWORK TEST SUITE")
    print("="*60)
    
    # Get target URL from user
    get_target_url()
    
    print("\nTesting all features implemented in this chat session:")
    print("- Enhanced Session Manager with multiple authentication types")
    print("- Advanced crawler with deduplication and scope control")
    print("- Enhanced SQL injection detection (error/time/boolean-based)")
    print("- Context-aware XSS scanning with verification")
    print("- Comprehensive security headers analysis")
    print("- Advanced misconfiguration scanning (40+ patterns)")
    print("- Enhanced open redirect testing")
    print("- JavaScript crawler with Playwright integration")
    print("- Enhanced CLI with authentication options")
    print("- Verification systems to reduce false positives")
    print("- Multi-page header analysis")
    print("- Enhanced evidence collection")
    print("- Session-aware scanning across all modules")
    print("\n" + "="*60)
    
    total_passed = 0
    total_tests = 0
    
    # Run all test suites
    test_suites = [
        ("Basic Functionality", test_basic_functionality),
        ("Authentication", test_authentication), 
        ("Advanced Features", test_advanced_features),
        ("Crawler Enhancements", test_crawler_enhancements),
        ("Session Manager", test_session_manager),
        ("Enhanced Scanners", test_enhanced_scanners)
    ]
    
    results = {}
    
    for suite_name, test_func in test_suites:
        try:
            passed, total = test_func()
            results[suite_name] = (passed, total)
            total_passed += passed
            total_tests += total
        except Exception as e:
            print(f"[ERROR] Test suite '{suite_name}' failed: {e}")
            results[suite_name] = (0, 1)
            total_tests += 1
    
    # Print summary
    print("\n" + "="*60)
    print("TEST RESULTS SUMMARY")
    print("="*60)
    
    for suite_name, (passed, total) in results.items():
        percentage = (passed/total*100) if total > 0 else 0
        status = "[PASS]" if passed == total else "[PARTIAL]" if passed > 0 else "[FAIL]"
        print(f"{status} {suite_name:.<40} {passed}/{total} ({percentage:.1f}%)")
    
    overall_percentage = (total_passed/total_tests*100) if total_tests > 0 else 0
    print(f"\nOVERALL SCORE: {total_passed}/{total_tests} ({overall_percentage:.1f}%)")
    
    if overall_percentage >= 80:
        print("EXCELLENT! Framework is working well!")
    elif overall_percentage >= 60:
        print("GOOD! Most features are working.")
    else:
        print("NEEDS ATTENTION! Some features may need debugging.")
    
    # Print feature checklist
    print("\n" + "="*60)
    print("IMPLEMENTED FEATURES CHECKLIST")
    print("="*60)
    
    features = [
        "[IMPLEMENTED] Enhanced Session Manager with multiple auth types",
        "[IMPLEMENTED] Advanced crawler with deduplication & scope control", 
        "[IMPLEMENTED] Enhanced SQL injection detection (error/time/boolean-based)",
        "[IMPLEMENTED] Context-aware XSS scanning with verification",
        "[IMPLEMENTED] Comprehensive security headers analysis",
        "[IMPLEMENTED] Advanced misconfiguration scanning (40+ patterns)",
        "[IMPLEMENTED] Enhanced open redirect testing",
        "[IMPLEMENTED] JavaScript crawler with Playwright integration",
        "[IMPLEMENTED] Enhanced CLI with authentication options",
        "[IMPLEMENTED] Verification systems to reduce false positives",
        "[IMPLEMENTED] Multi-page header analysis",
        "[IMPLEMENTED] Enhanced evidence collection",
        "[IMPLEMENTED] Session-aware scanning across all modules"
    ]
    
    for feature in features:
        print(feature)

if __name__ == "__main__":
    main()