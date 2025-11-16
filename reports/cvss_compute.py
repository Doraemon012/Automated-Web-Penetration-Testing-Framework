"""
CVSS Computation Module for Enhanced Vulnerability Scoring

This module provides advanced CVSS scoring capabilities:
- Computes actual CVSS vectors from vulnerability characteristics
- Calculates numeric scores (not rough mappings)
- Adds temporal and environmental metrics
- Provides deduplication and canonical IDs
"""

import hashlib
from typing import Dict, Any, Iterable, Iterator
# from cvss import CVSS3

try:
    from cvss import CVSS3
    CVSS_AVAILABLE = True
    print("CVSS library loaded successfully...")
except ImportError:
    print("CVSS library not found, please install it using 'pip install cvss'")
    CVSS_AVAILABLE = False


def generate_canonical_id(finding: Dict[str, Any]) -> str:
    """
    Generate a canonical ID for deduplication.
    
    The ID is based on URL, vulnerability type, and parameter to uniquely
    identify the same finding across different scanners.
    
    Args:
        finding: Vulnerability finding dictionary
        
    Returns:
        Canonical ID string (16 char hex)
    """
    url = finding.get('url', '')
    vuln_name = finding.get('vulnerability', '')
    parameter = finding.get('parameter', '')
    
    unique_string = f"{url}#{vuln_name}#{parameter}"
    return hashlib.sha256(unique_string.encode()).hexdigest()[:16]


def infer_cvss_base_metrics(finding: Dict[str, Any]) -> Dict[str, str]:
    """
    Infer CVSS Base Metrics from vulnerability characteristics.
    
    Args:
        finding: Vulnerability finding dictionary
        
    Returns:
        Dictionary with CVSS metrics:
        {
            'AV': 'N',  # Attack Vector (N/A/L/P)
            'AC': 'L',  # Attack Complexity (L/H)
            'PR': 'N',  # Privileges Required (N/L/H)
            'UI': 'N',  # User Interaction (N/R)
            'S': 'U',   # Scope (U/C)
            'C': 'H',   # Confidentiality Impact (N/L/H)
            'I': 'H',   # Integrity Impact (N/L/H)
            'A': 'N'    # Availability Impact (N/L/H)
        }
    """
    vuln_name = finding.get('vulnerability', '').lower()
    vuln_type = finding.get('vulnerability', '').lower()
    evidence = finding.get('evidence', '').lower()
    context = finding.get('context', '').lower()
    requires_auth = finding.get('requires_auth', False)
    
    # Attack Vector (AV) - Assume Network unless specified otherwise
    AV = 'N'  # Network
    
    # Attack Complexity (AC)
    # Simple if error messages detected, complex otherwise
    if 'error' in evidence or 'mysql' in evidence or 'database' in evidence:
        AC = 'L'  # Low complexity
    elif 'time-based' in vuln_name or 'blind' in vuln_name:
        AC = 'H'  # High complexity
    else:
        AC = 'L'
    
    # Privileges Required (PR)
    if requires_auth:
        PR = 'L'  # Low (authentication required)
    else:
        PR = 'N'  # None
    
    # User Interaction (UI)
    # SQLi and reflected XSS usually don't require user interaction
    if 'xss' in vuln_name and 'stored' in vuln_name:
        UI = 'R'  # Required (user must visit page)
    elif 'xss' in vuln_name and context and 'script' in context:
        UI = 'N'  # None (automated execution)
    else:
        UI = 'N'
    
    # Scope (S) - Usually Unchanged for web apps
    S = 'U'  # Unchanged
    
    # Impact on Confidentiality (C), Integrity (I), Availability (A)
    
    # SQL Injection
    if 'sql injection' in vuln_name:
        C = 'H'  # High - data theft
        I = 'H'  # High - data tampering
        A = 'N'  # None - no DoS impact
    
    # Cross-Site Scripting
    elif 'xss' in vuln_name or 'cross-site scripting' in vuln_name:
        if 'stored' in vuln_name:
            # Stored XSS can be more severe
            C = 'H'  # Session hijacking
            I = 'H'  # Content tampering
            A = 'L'  # Low - potential DoS
        elif context and 'script' in context:
            # XSS in script context - very exploitable
            C = 'H'
            I = 'H'
            A = 'L'
        else:
            # Reflected XSS
            C = 'H'
            I = 'L'  # Lower integrity impact for reflected
            A = 'N'
    
    # Missing Security Headers
    elif 'missing' in vuln_name and 'hsts' in vuln_name:
        C = 'H'  # Traffic interception risk
        I = 'L'
        A = 'N'
    elif 'missing' in vuln_name:
        # Other missing headers
        C = 'L'
        I = 'L'
        A = 'N'
    
    # Open Redirect
    elif 'open redirect' in vuln_name:
        C = 'L'
        I = 'L'
        A = 'N'
    
    # Directory Listing / Information Disclosure
    elif 'directory listing' in vuln_name or 'information disclosure' in vuln_name:
        C = 'L'  # Low - info disclosure
        I = 'N'
        A = 'N'
    
    # Command Injection (Critical - RCE)
    elif 'command injection' in vuln_name:
        C = 'H'  # High - complete system compromise
        I = 'H'  # High - arbitrary command execution
        A = 'H'  # High - DoS possible
    
    # File Upload vulnerabilities
    elif 'insecure file upload' in vuln_name or 'file upload' in vuln_name:
        if 'php' in vuln_name or 'executable' in vuln_name or 'critical' in vuln_name.lower():
            C = 'H'  # Critical - RCE via webshell
            I = 'H'
            A = 'H'
        else:
            C = 'H'
            I = 'M'  # Medium - potential data exfiltration
            A = 'N'
    
    # XML/XXE Injection
    elif 'xxe' in vuln_name or 'xml external entity' in vuln_name:
        C = 'H'  # High - file disclosure
        I = 'H'  # High - SSRF
        A = 'N'
    
    # Broken Access Control
    elif 'broken access control' in vuln_name or 'access control' in vuln_name.lower():
        C = 'H'  # High - unauthorized data access
        I = 'H'  # High - privilege escalation
        A = 'N'
    
    # SSRF
    elif 'ssrf' in vuln_name or 'server-side request forgery' in vuln_name.lower():
        C = 'H'  # High - internal network access
        I = 'H'  # High - potential RCE
        A = 'N'
    
    # Authentication weaknesses
    elif 'authentication' in vuln_name.lower() or 'login' in vuln_name.lower() or 'weak login' in vuln_name.lower():
        C = 'H'  # High - credential theft
        I = 'M'  # Medium - account compromise
        A = 'N'
    
    # Session Management
    elif 'session' in vuln_name.lower() or 'cookie' in vuln_name.lower():
        C = 'H'  # High - session hijacking
        I = 'M'  # Medium - identity theft
        A = 'N'
    
    # Content-Type Validation Bypass
    elif 'content-type' in vuln_name.lower():
        C = 'H'  # Critical - RCE via malicious file
        I = 'H'
        A = 'H'
    
    # Path Traversal
    elif 'path traversal' in vuln_name.lower() or 'directory traversal' in vuln_name.lower():
        C = 'H'  # High - file disclosure
        I = 'H'  # High - arbitrary file write
        A = 'N'
    
    # Missing File Size Limits
    elif 'file size' in vuln_name.lower():
        C = 'N'  # None
        I = 'N'
        A = 'H'  # High - DoS via resource exhaustion
    
    # HTML Injection
    elif 'html injection' in vuln_name.lower():
        C = 'M'  # Medium - potential for XSS
        I = 'L'  # Low - content spoofing
        A = 'N'
    
    # XML Injection (non-XXE)
    elif 'xml injection' in vuln_name.lower():
        C = 'M'  # Medium - data manipulation
        I = 'M'
        A = 'N'
    
    # Default (conservative)
    else:
        C = 'L'
        I = 'L'
        A = 'N'
    
    return {
        'AV': AV,
        'AC': AC,
        'PR': PR,
        'UI': UI,
        'S': S,
        'C': C,
        'I': I,
        'A': A
    }


def build_cvss_vector(metrics: Dict[str, str]) -> str:
    """
    Build CVSS v3.1 vector string from metrics.
    
    Args:
        metrics: Dictionary with CVSS metrics
        
    Returns:
        CVSS vector string
    """
    return f"CVSS:3.1/AV:{metrics['AV']}/AC:{metrics['AC']}/PR:{metrics['PR']}/UI:{metrics['UI']}/S:{metrics['S']}/C:{metrics['C']}/I:{metrics['I']}/A:{metrics['A']}"


def compute_cvss_score(vector: str) -> Dict[str, float]:
    """
    Compute CVSS score from vector using CVSS library.
    
    Args:
        vector: CVSS vector string
        
    Returns:
        Dictionary with scores:
        {
            'vector': str,
            'base_score': float,
            'impact_score': float,
            'exploitability_score': float
        }
    """
    if not CVSS_AVAILABLE:
        # Fallback: return default values if library not available
        print("[WARNING] CVSS library not available. Install with: pip install cvss")
        return {
            'vector': vector,
            'base_score': 0.0,
            'impact_score': 0.0,
            'exploitability_score': 0.0
        }
    
    try:
        cvss_obj = CVSS3(vector)
        scores = cvss_obj.scores()
        
        # The cvss library returns a tuple: (base_score, impact_subscore, exploitability_subscore)
        # or just base_score depending on version
        if isinstance(scores, tuple) and len(scores) >= 3:
            base_score = scores[0]
            impact_score = scores[1]
            exploitability_score = scores[2]
        else:
            base_score = scores if isinstance(scores, (int, float)) else scores[0]
            # Calculate sub-scores manually if not provided
            impact_score = base_score * 0.4  # Approximation
            exploitability_score = base_score * 0.6  # Approximation
        
        return {
            'vector': vector,
            'base_score': float(base_score),
            'impact_score': float(impact_score),
            'exploitability_score': float(exploitability_score)
        }
    except Exception as e:
        # If CVSS computation fails, return zeros and log error
        print(f"[WARNING] CVSS computation failed for vector '{vector}': {e}")
        return {
            'vector': vector,
            'base_score': 0.0,
            'impact_score': 0.0,
            'exploitability_score': 0.0
        }


def score_to_severity(cvss_score: float) -> str:
    """
    Map numeric CVSS score to severity band.
    
    Args:
        cvss_score: Numeric CVSS score (0.0-10.0)
        
    Returns:
        Severity band string
    """
    if cvss_score >= 9.0:
        return "Critical"
    elif cvss_score >= 7.0:
        return "High"
    elif cvss_score >= 4.0:
        return "Medium"
    elif cvss_score >= 0.1:
        return "Low"
    else:
        return "Info"


def infer_confidence_numeric(issue: Dict[str, Any]) -> float:
    """
    Infer numeric confidence (0.0-1.0) from finding characteristics.
    
    Args:
        issue: Vulnerability finding dictionary
        
    Returns:
        Confidence value (0.0-1.0)
    """
    vuln_name = issue.get('vulnerability', '').lower()
    evidence = issue.get('evidence', '').lower()
    
    # High confidence: verification mentioned
    if 'verify' in evidence or 'verification' in evidence:
        return 0.95
    
    # High confidence: error-based SQLi (direct evidence)
    if 'sql injection' in vuln_name and 'error-based' in vuln_name:
        return 0.85
    
    # Medium-high confidence: SQL injection (tested)
    if 'sql injection' in vuln_name:
        return 0.75
    
    # Medium-high confidence: XSS with specific contexts
    if 'xss' in vuln_name or 'cross-site scripting' in vuln_name:
        context = issue.get('context', '').lower()
        if context and 'script' in context:
            return 0.70
        if 'stored' in vuln_name:
            return 0.65
        return 0.60
    
    # Lower confidence: time-based (more prone to false positives)
    if 'time-based' in vuln_name or 'blind' in vuln_name:
        return 0.65
    
    # Low confidence: search contexts or info disclosure
    if 'search' in vuln_name or 'information disclosure' in vuln_name:
        return 0.40
    
    # Medium confidence for other findings
    return 0.50


def check_exploit_availability(vuln_name: str) -> Dict[str, Any]:
    """
    Check if exploit is available for this vulnerability.
    
    Note: This is a placeholder. In production, integrate with:
    - Exploit-DB API
    - MITRE ATT&CK
    - NVD API
    - Internal threat intelligence
    
    Args:
        vuln_name: Vulnerability name
        
    Returns:
        Dictionary with exploit information
    """
    vuln_lower = vuln_name.lower()
    
    # Basic heuristic: known vulnerabilities likely have exploits
    has_exploit = False
    has_poc = False
    
    # SQL injection and XSS typically have available exploits
    if 'sql injection' in vuln_lower:
        has_exploit = True
        has_poc = True
    
    if 'xss' in vuln_lower or 'cross-site scripting' in vuln_lower:
        has_poc = True
    
    return {
        'exploit_published': has_exploit,
        'poc_available': has_poc,
        'weaponized': has_exploit,
        'days_since_publish': None
    }


def get_asset_criticality(url: str) -> int:
    """
    Determine asset criticality (1-10) based on URL patterns.
    
    Args:
        url: Target URL
        
    Returns:
        Criticality score (1-10)
    """
    url_lower = url.lower()
    
    # Production / Critical infrastructure
    if 'prod' in url_lower or 'production' in url_lower or 'live' in url_lower:
        return 10
    
    # Admin / Security endpoints
    if 'admin' in url_lower or 'secure' in url_lower or 'payment' in url_lower:
        return 9
    
    # DMZ / Public endpoints
    if 'dmz' in url_lower or 'public' in url_lower:
        return 8
    
    # Internal systems
    if 'internal' in url_lower or 'corp' in url_lower or 'intranet' in url_lower:
        return 6
    
    # Staging
    if 'staging' in url_lower or 'stage' in url_lower:
        return 5
    
    # Development / Testing
    if 'test' in url_lower or 'dev' in url_lower or 'demo' in url_lower:
        return 3
    
    # Default
    return 5


def compute_environmental_adjustment(
    base_score: float,
    asset_criticality: int,
    exploit_available: bool
) -> Dict[str, Any]:
    """
    Compute environmental adjustment to CVSS score.
    
    Args:
        base_score: Base CVSS score
        asset_criticality: Asset criticality (1-10)
        exploit_available: Whether exploit is available
        
    Returns:
        Dictionary with adjustment details
    """
    # High criticality + exploit available → boost by 15%
    if asset_criticality >= 8 and exploit_available:
        adjusted = base_score * 1.15
        return {
            'adjusted_score': min(10.0, adjusted),
            'modifier': 'critical_asset_with_exploit',
            'reason': 'Critical asset with active exploits'
        }
    
    # High criticality asset
    if asset_criticality >= 8:
        adjusted = base_score * 1.08
        return {
            'adjusted_score': min(10.0, adjusted),
            'modifier': 'critical_asset',
            'reason': 'Critical asset'
        }
    
    # Moderate criticality
    if asset_criticality >= 6:
        adjusted = base_score * 1.05
        return {
            'adjusted_score': min(10.0, adjusted),
            'modifier': 'moderate_asset',
            'reason': 'Moderately critical asset'
        }
    
    # Low criticality (development/test) - slight reduction
    if asset_criticality <= 4:
        adjusted = base_score * 0.90
        return {
            'adjusted_score': max(0.0, adjusted),
            'modifier': 'low_priority_asset',
            'reason': 'Development/test environment'
        }
    
    return {
        'adjusted_score': base_score,
        'modifier': 'none',
        'reason': 'Standard priority'
    }


def deduplicate_findings(findings: Iterable[Dict[str, Any]]) -> Iterator[Dict[str, Any]]:
    """
    Deduplicate findings by canonical ID.
    
    - Groups findings by canonical_id
    - Merges evidence from multiple scanners
    - Increases confidence if multiple scanners agree
    - Counts occurrences
    
    Args:
        findings: List of vulnerability findings
        
    Returns:
        Deduplicated list of findings
    """
    canonical_map = {}
    
    for finding in findings:
        cid = finding.get('canonical_id')
        if not cid:
            # If no canonical_id, generate one
            cid = generate_canonical_id(finding)
            finding['canonical_id'] = cid
        
        if cid not in canonical_map:
            canonical_map[cid] = {
                'finding': finding,
                'occurrences': 1,
                'evidence_list': [finding.get('evidence', '')],
                'scanners': [finding.get('scanner', 'unknown')]
            }
        else:
            canonical_map[cid]['occurrences'] += 1
            canonical_map[cid]['evidence_list'].append(finding.get('evidence', ''))
            canonical_map[cid]['scanners'].append(finding.get('scanner', 'unknown'))
    
    # Merge each group
    for cid, data in canonical_map.items():
        merged = data['finding'].copy()
        merged['occurrences'] = data['occurrences']
        merged['evidence_merged'] = ' | '.join(set([e for e in data['evidence_list'] if e]))
        merged['scanners'] = ', '.join(set(data['scanners']))
        
        # Boost confidence for multi-scanner finds
        if data['occurrences'] > 1:
            base_conf = merged.get('confidence', 0.5)
            merged['confidence'] = min(0.95, base_conf + 0.1)
        
        yield merged


def compute_final_priority(
    cvss_base_score: float,
    confidence: float,
    exploit_available: bool,
    asset_criticality: int,
    occurrences: int = 1
) -> Dict[str, Any]:
    """
    Compute final priority combining all factors.
    
    Args:
        cvss_base_score: Base CVSS score
        confidence: Confidence level (0.0-1.0)
        exploit_available: Whether exploit is available
        asset_criticality: Asset criticality (1-10)
        occurrences: Number of occurrences
        
    Returns:
        Dictionary with priority information
    """
    # Weighted formula combining all factors
    priority_score = (
        cvss_base_score * 0.5 +          # Base CVSS (50% weight)
        confidence * 10 * 0.2 +           # Confidence (20% weight)
        (asset_criticality / 10) * 10 * 0.15 +  # Asset importance (15% weight)
        (10 if exploit_available else 0) * 0.15  # Exploit availability (15% weight)
    )
    
    # Cap at 10.0
    priority_score = min(10.0, priority_score)
    
    # Map to band
    if priority_score >= 9.0:
        priority = "Critical"
        rec = "Immediate remediation required"
    elif priority_score >= 7.0:
        priority = "High"
        rec = "Prioritize remediation within 30 days"
    elif priority_score >= 4.0:
        priority = "Medium"
        rec = "Schedule remediation within 90 days"
    elif priority_score >= 0.1:
        priority = "Low"
        rec = "Address as resources allow"
    else:
        priority = "Info"
        rec = "Informational only"
    
    return {
        'final_priority': priority,
        'priority_score': priority_score,
        'recommendation': rec,
        'components': {
            'cvss_contribution': cvss_base_score * 0.5,
            'confidence_contribution': confidence * 10 * 0.2,
            'asset_contribution': (asset_criticality / 10) * 10 * 0.15,
            'exploit_contribution': (10 if exploit_available else 0) * 0.15
        }
    }


def enhance_finding_with_cvss(finding: Dict[str, Any]) -> Dict[str, Any]:
    """
    Complete enhancement pipeline for a vulnerability finding.
    
    This function:
    1. Generates canonical ID
    2. Infers base metrics
    3. Builds CVSS vector
    4. Computes CVSS score
    5. Checks exploit availability
    6. Applies environmental adjustments
    7. Converts confidence to numeric
    8. Computes final priority
    
    Args:
        finding: Vulnerability finding dictionary
        
    Returns:
        Enhanced finding dictionary with all CVSS data
    """
    # 1. Canonical ID
    finding['canonical_id'] = generate_canonical_id(finding)
    
    # 2. Infer metrics
    metrics = infer_cvss_base_metrics(finding)
    
    # 3. Build vector
    vector = build_cvss_vector(metrics)
    finding['cvss_vector'] = vector
    
    # 4. Compute score
    cvss_data = compute_cvss_score(vector)
    finding['cvss_base_score'] = cvss_data['base_score']
    finding['impact_score'] = cvss_data['impact_score']
    finding['exploitability_score'] = cvss_data['exploitability_score']
    
    # Debug: Log if CVSS score is unexpectedly low
    if cvss_data['base_score'] < 4.0 and finding.get('severity') in ['High', 'Critical']:
        print(f"[DEBUG] Low CVSS score {cvss_data['base_score']:.1f} for {finding.get('vulnerability', 'Unknown')} (vector: {vector})")
    
    # 5. Exploit check
    exploit_info = check_exploit_availability(finding.get('vulnerability', ''))
    finding['exploit_published'] = exploit_info['exploit_published']
    finding['poc_available'] = exploit_info['poc_available']
    
    # 6. Environmental
    asset_criticality = get_asset_criticality(finding.get('url', ''))
    env_adjust = compute_environmental_adjustment(
        cvss_data['base_score'],
        asset_criticality,
        exploit_info['exploit_published']
    )
    finding['asset_criticality'] = asset_criticality
    finding['adjusted_cvss_score'] = env_adjust['adjusted_score']
    finding['env_modifier'] = env_adjust['reason']
    
    # 7. Confidence
    finding['confidence'] = infer_confidence_numeric(finding)
    
    # 8. Final priority
    priority_data = compute_final_priority(
        env_adjust['adjusted_score'],
        finding['confidence'],
        exploit_info['exploit_published'],
        asset_criticality
    )
    finding['final_priority'] = priority_data['final_priority']
    finding['priority_score'] = priority_data['priority_score']
    finding['recommendation_priority'] = priority_data['recommendation']
    
    # Only override severity if CVSS computation succeeded and score is meaningful
    # Otherwise preserve original scanner severity
    if cvss_data['base_score'] >= 0.1:
        finding['severity'] = score_to_severity(cvss_data['base_score'])
    # If CVSS failed (0.0), keep original severity from scanner
    
    # Keep CWE mapping (from existing risk.py)
    # This will be done separately in the integration
    
    return finding


