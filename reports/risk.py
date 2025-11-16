from typing import Dict, Any, Iterable, Iterator

# Simple mappings for CWE by vulnerability name keywords
VULN_TO_CWE = [
    ("SQL Injection", "CWE-89"),
    ("Cross-Site Scripting", "CWE-79"),
    ("XSS", "CWE-79"),
    ("Open Redirect", "CWE-601"),
    ("Directory listing", "CWE-548"),
    ("Information disclosure", "CWE-200"),
    ("Missing Strict-Transport-Security", "CWE-319"),
]

# Map textual severity to approximate CVSS v3.1 score ranges
SEVERITY_TO_CVSS = {
    "Critical": 9.0,
    "High": 8.0,
    "Medium": 5.5,
    "Low": 3.1,
    "Info": 0.1,
}

def infer_cwe(vuln_name: str) -> str:
    name_lower = vuln_name.lower()
    for key, cwe in VULN_TO_CWE:
        if key.lower() in name_lower:
            return cwe
    return "CWE-000"

def default_cvss_vector(severity: str) -> str:
    # Provide a generic vector per severity band (not precise, but consistent)
    band = severity.capitalize()
    if band == "High":
        return "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
    if band == "Medium":
        return "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N"
    if band == "Low":
        return "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N"
    if band == "Critical":
        return "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
    return "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N"

def infer_confidence(issue: Dict[str, Any]) -> str:
    # Heuristic confidence: prefer Verified if scanner ran a second check
    name = (issue.get("vulnerability") or "").lower()
    evidence = (issue.get("evidence") or "").lower()
    # If scanners mention verification or secondary confirmation
    if "verify" in evidence or "verification" in evidence:
        return "Verified"
    # SQLi/XSS functions already try double requests; mark as Probable
    if any(k in name for k in ["sql injection", "cross-site scripting", "xss"]):
        return "Probable"
    return "Tentative"

def enrich_issue(issue: Dict[str, Any]) -> Dict[str, Any]:
    enriched = dict(issue)
    severity_text = enriched.get("severity", "Low")
    enriched["cwe"] = infer_cwe(enriched.get("vulnerability", ""))
    enriched["cvss_vector"] = default_cvss_vector(severity_text)
    enriched["cvss_score"] = SEVERITY_TO_CVSS.get(severity_text, 3.1)
    enriched["confidence"] = infer_confidence(enriched)
    # Short evidence summary, if long
    ev = enriched.get("evidence")
    if isinstance(ev, str) and len(ev) > 240:
        enriched["evidence_summary"] = ev[:240] + "..."
    return enriched

def enrich_findings(findings: Iterable[Dict[str, Any]]) -> Iterator[Dict[str, Any]]:
    for finding in findings:
        yield enrich_issue(finding)


