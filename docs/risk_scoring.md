## Risk Scoring and Enrichment

This document describes the lightweight risk scoring layer that enriches scanner findings with standardized metadata (CVSS, CWE, confidence) after scanning and before report generation.

### What it adds
- `cvss_score`: Numeric approximation based on severity bands (CVSS v3.1-inspired).
- `cvss_vector`: Generic CVSS v3.1 vector per band for consistency.
- `cwe`: CWE mapping by vulnerability type (best-effort keyword mapping).
- `confidence`: Heuristic confidence level (Verified, Probable, Tentative).
- `evidence_summary`: Trimmed evidence when the full evidence is very long.

### Where it lives
- Module: `reports/risk.py`
- Integration: Applied in `main.py` right before saving reports.

### How it works
1. Each finding emitted by scanners (headers, XSS, SQLi, misconfig, etc.) includes at least `vulnerability`, `severity`, `url` and `description`.
2. The orchestrator calls `reports.risk.enrich_findings(findings)` to map:
   - CWE: best-effort mapping from vulnerability name keywords.
   - CVSS: severity → default vector and approximate score (e.g., High → 8.0).
   - Confidence: based on evidence and whether verification is indicated.
3. The enriched findings are persisted by the reporter unchanged otherwise.

### Field details
- `cwe`:
  - SQL Injection → `CWE-89`
  - Cross-Site Scripting/XSS → `CWE-79`
  - Open Redirect → `CWE-601`
  - Directory Listing → `CWE-548`
  - Information Disclosure → `CWE-200`
  - Missing HSTS → `CWE-319`
  - Fallback → `CWE-000` (unknown)

- `cvss_vector` (examples):
  - Critical → `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H`
  - High → `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N`
  - Medium → `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N`
  - Low → `CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N`

- `cvss_score` (approximate bands):
  - Critical: 9.0
  - High: 8.0
  - Medium: 5.5
  - Low: 3.1

- `confidence` (heuristic):
  - Verified: evidence mentions secondary confirmation/verification.
  - Probable: common double-checking scanners (e.g., SQLi/XSS) without explicit verification evidence.
  - Tentative: others.

### Rationale
- Standardizes outputs for triage and reporting without invasive scanner changes.
- Provides CWE and CVSS context that aligns with common security programs.
- Adds confidence levels to help prioritize manual validation.

### Notes & future work
- This is a pragmatic baseline, not a full CVSS calculator.
- Future enhancements could include:
  - True CVSS computation per finding (using vector components).
  - Environment/asset-aware adjustments (data classification, auth, exposure).
  - Explicit Confidence derived from per-scanner verification flags.
  - Per-finding CWE selection refined by context rather than keywords.


