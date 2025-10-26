# 🎯 **SCORING MECHANISM IN YOUR WEBPENTEST FRAMEWORK**

## Overview
Your framework uses a **two-tier scoring system**:
1. **Initial Severity Assignment** (by individual scanners)
2. **Risk Enrichment** (by the risk module that adds CVSS scores, CWE mappings, and confidence levels)

---

## 📊 **TIER 1: INITIAL SEVERITY ASSIGNMENT**

Each scanner assigns severity levels directly when finding vulnerabilities:

### **1. SQL Injection Scanner** (`scanners/sqli.py`)

```python
# All SQL injection findings get "High" severity
issues.append({
    "vulnerability": "SQL Injection (Error-based)",
    "severity": "High",  # ← Direct assignment
    "url": target_url,
    "payload": payload,
    "description": "Database error message detected...",
})

# Error-based (lines 122-133)
# Time-based blind (lines 254-265)  
# Boolean-based (lines 313-324)
# UNION-based (lines 183-195)
```

**Example Output:**
```json
{
  "vulnerability": "SQL Injection (Time-based Blind)",
  "severity": "High",
  "evidence": "Response delayed by 5.23 seconds (baseline: 0.45s)"
}
```

### **2. XSS Scanner** (`scanners/xss.py`)

Uses **context-aware severity** based on where the payload is reflected:

```python
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
```

**Example Output:**
```json
{
  "vulnerability": "Cross-Site Scripting (XSS)",
  "severity": "High",  # ← When in <script> context
  "context": "script_context",
  "payload": "<script>alert(1)</script>"
}
```

### **3. Headers Scanner** (`scanners/headers.py`)

Assigns severity based on **header importance**:

```python
required_headers = {
    "X-Frame-Options": {
        "description": "Protects against clickjacking attacks",
        "severity": "Medium",  # ← Predefined
    },
    "Content-Security-Policy": {
        "description": "Helps prevent XSS and data injection attacks", 
        "severity": "Medium",
    },
    "Strict-Transport-Security": {
        "description": "Enforces HTTPS connections",
        "severity": "High",  # ← Higher severity
    },
    # ... more headers
}
```

**Example Output:**
```json
{
  "vulnerability": "Missing Strict-Transport-Security",
  "severity": "High",
  "url": "https://example.com",
  "description": "Enforces HTTPS connections"
}
```

### **4. Misconfig Scanner** (`scanners/misconfig.py`)

Uses **file-type based severity**:

```python
def determine_file_severity(path):
    """Determine severity based on file type"""
    high_risk = ['.env', 'config', '.git', 'backup', 'database', '.sql']
    medium_risk = ['admin', 'phpmyadmin', 'debug', 'log']
    
    path_lower = path.lower()
    
    for risk_file in high_risk:
        if risk_file in path_lower:
            return "High"  # ← High for sensitive files
    
    for risk_file in medium_risk:
        if risk_file in path_lower:
            return "Medium"
    
    return "Low"
```

**Example Output:**
```json
{
  "vulnerability": "Sensitive file exposed: .env",
  "severity": "High",  # ← Because .env is in high_risk list
  "url": "https://example.com/.env"
}
```

---

## 🔧 **TIER 2: RISK ENRICHMENT** (`reports/risk.py`)

After scanners assign initial severity, the risk module enriches findings with:

### **1. CWE (Common Weakness Enumeration) Mapping**

```python
VULN_TO_CWE = [
    ("SQL Injection", "CWE-89"),      # SQL injection
    ("Cross-Site Scripting", "CWE-79"), # XSS
    ("XSS", "CWE-79"),                 # XSS (alternative name)
    ("Open Redirect", "CWE-601"),      # Open redirect
    ("Directory listing", "CWE-548"),   # Directory info exposure
    ("Information disclosure", "CWE-200"),
    ("Missing Strict-Transport-Security", "CWE-319"), # HTTPS
]

def infer_cwe(vuln_name: str) -> str:
    name_lower = vuln_name.lower()
    for key, cwe in VULN_TO_CWE:
        if key.lower() in name_lower:
            return cwe
    return "CWE-000"  # Unknown
```

**Before Enrichment:**
```json
{
  "vulnerability": "SQL Injection (Error-based)",
  "severity": "High"
}
```

**After Enrichment:**
```json
{
  "vulnerability": "SQL Injection (Error-based)",
  "severity": "High",
  "cwe": "CWE-89",  # ← Added by risk.py
  "cvss_score": 8.0,
  "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
}
```

### **2. CVSS Score Mapping**

```python
SEVERITY_TO_CVSS = {
    "Critical": 9.0,
    "High": 8.0,        # ← Maps to CVSS 8.0
    "Medium": 5.5,
    "Low": 3.1,
    "Info": 0.1,
}
```

**How it works:**
```python
def enrich_issue(issue: Dict[str, Any]) -> Dict[str, Any]:
    enriched = dict(issue)
    severity_text = enriched.get("severity", "Low")
    
    # Add CWE mapping
    enriched["cwe"] = infer_cwe(enriched.get("vulnerability", ""))
    
    # Add CVSS vector
    enriched["cvss_vector"] = default_cvss_vector(severity_text)
    
    # Add CVSS score
    enriched["cvss_score"] = SEVERITY_TO_CVSS.get(severity_text, 3.1)
    
    # Add confidence level
    enriched["confidence"] = infer_confidence(enriched)
    
    return enriched
```

### **3. CVSS Vector Generation**

```python
def default_cvss_vector(severity: str) -> str:
    """Provide generic CVSS vector per severity band"""
    band = severity.capitalize()
    
    if band == "High":
        return "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
        # Attack Vector: Network, Attack Complexity: Low, 
        # Privileges Required: None, User Interaction: None,
        # Scope: Unchanged, Confidentiality: High, Integrity: High
    if band == "Medium":
        return "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N"
    if band == "Low":
        return "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N"
    if band == "Critical":
        return "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
    return "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N"
```

### **4. Confidence Level Inference**

```python
def infer_confidence(issue: Dict[str, Any]) -> str:
    name = (issue.get("vulnerability") or "").lower()
    evidence = (issue.get("evidence") or "").lower()
    
    # If scanners mention verification
    if "verify" in evidence or "verification" in evidence:
        return "Verified"  # ← Highest confidence
    
    # SQLi/XSS functions already try double requests
    if any(k in name for k in ["sql injection", "cross-site scripting", "xss"]):
        return "Probable"  # ← Medium confidence
    
    return "Tentative"  # ← Lower confidence
```

---

## 🔄 **COMPLETE EXAMPLE: FROM DETECTION TO SCORING**

### **Step 1: Scanner Detects Vulnerability**

```python
# scanners/sqli.py - test_error_based_sqli()
issues.append({
    "vulnerability": "SQL Injection (Error-based)",
    "url": "https://example.com/login",
    "payload": "' OR 1=1 --",
    "severity": "High",  # ← Scanner assigns severity
    "evidence": "MySQL error detected"
})
```

### **Step 2: Enrichment Applied**

```python
# main.py line 600
findings = enrich_findings(findings)  # ← Applies enrichment
```

```python
# reports/risk.py - enrich_findings()
def enrich_findings(findings: list) -> list:
    return [enrich_issue(f) for f in findings]

def enrich_issue(issue: Dict[str, Any]) -> Dict[str, Any]:
    enriched = dict(issue)
    enriched["cwe"] = infer_cwe("SQL Injection")  # → "CWE-89"
    enriched["cvss_score"] = 8.0  # → High severity maps to 8.0
    enriched["cvss_vector"] = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
    enriched["confidence"] = infer_confidence(enriched)  # → "Probable"
    return enriched
```

### **Step 3: Final Enriched Finding**

```json
{
  "vulnerability": "SQL Injection (Error-based)",
  "url": "https://example.com/login",
  "payload": "' OR 1=1 --",
  "severity": "High",
  "cwe": "CWE-89",
  "cvss_score": 8.0,
  "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
  "confidence": "Probable",
  "evidence": "MySQL error detected"
}
```

---

## 📈 **SEVERITY BREAKDOWN**

| Severity | CVSS Score | When Assigned |
|----------|------------|---------------|
| **Critical** | 9.0 | Never automatically assigned (manual override) |
| **High** | 8.0 | SQL injection, XSS (script context), Missing HSTS, Exposed credentials |
| **Medium** | 5.5 | Missing security headers, XSS (attribute context), CSRF, Cookie issues |
| **Low** | 3.1 | Info disclosure headers, XSS (encoded context), Directory listing |
| **Info** | 0.1 | Non-security issues, informational notices |

---

## 🎯 **KEY POINTS**

1. **Scanners assign severity immediately** based on vulnerability type and context
2. **Risk module enriches** with CWE, CVSS, and confidence after scanning
3. **Context matters**: Same vulnerability (XSS) can be High/Medium/Low based on reflection context
4. **Verification reduces false positives** and increases confidence from "Tentative" to "Verified"
5. **CVSS vectors are simplified** and not precise - they represent severity bands

---

## 💡 **REAL CODE EXAMPLES FROM YOUR WORKSPACE**

### **Example 1: SQL Injection (High Severity)**
```python
# scanners/sqli.py:123-132
issues.append({
    "vulnerability": "SQL Injection (Error-based)",
    "url": target_url,
    "payload": payload,
    "severity": "High",  # ← Directly assigned
    "description": "Database error message detected...",
})
```

### **Example 2: XSS with Context-Aware Severity**
```python
# scanners/xss.py:213-227
issues.append({
    "vulnerability": "Cross-Site Scripting (XSS)",
    "severity": severity,  # ← Determined by context
    "context": context,     # ← "script_context" = High
})
```

### **Example 3: Missing Header (Medium Severity)**
```python
# scanners/headers.py:196-205
issues.append({
    "vulnerability": "Missing X-Frame-Options",
    "severity": "Medium",  # ← From required_headers dict
    "description": "Protects against clickjacking attacks"
})
```

---

## 🔍 **HOW TO TRACE A FINDING**

1. **Scanner finds issue** → Assigns initial severity
2. **Reporter collects findings** → All scanner results aggregated
3. **`enrich_findings()` called** → Risk module adds CWE, CVSS, confidence
4. **Saved to report.json** → Final enriched JSON with all scoring data
5. **Frontend displays** → Shows severity, CVSS score, CWE, confidence

**Code Path:**
```
main.py:600 → enrich_findings(findings)
    ↓
reports/risk.py:68 → enrich_findings(findings)
    ↓
reports/risk.py:55 → enrich_issue(issue)
    ↓
Adds: cwe, cvss_score, cvss_vector, confidence
```

---

This is how your scoring system works! 🎯

