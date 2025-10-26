## Scan Modes and False-Positive Reduction

This document explains the enhanced scan modes and changes that significantly reduce false positives and improve performance on large/public targets.

### Overview
- Added `--mode {ultra-safe,safe,standard,aggressive}` to `main.py`.
- Introduced strict XSS reporting (default in safe/standard) that only reports executable reflections.
- Enhanced security headers detection with alternative implementations (meta tags, domain-level HSTS).
- Site-specific exclusions for known secure implementations (Google, Facebook, etc.).
- Misconfiguration scanner no longer flags intentionally public files like `robots.txt`/`sitemap.xml`/`crossdomain.xml`.

### Modes
#### Ultra-Safe (NEW)
- Purpose: Minimal scanning for large public sites (Google, Facebook, Microsoft, etc.).
- Behavior:
  - Minimal crawl depth (1 level).
  - **Smart Detection**: Only skips headers/XSS for large public sites; runs full scans for regular sites.
  - **Vulnerable Test Sites**: Automatically detects and runs full scans on Juice Shop, DVWA, testphp.vulnweb.com, etc.
  - Runs: Misconfig + Headers + XSS + SQLi (for regular sites), Misconfig only (for large public sites).
  - Skips: Open Redirect, URL parameter fuzzing.
  - Use for: Large public sites where headers and XSS checks produce false positives, but also works great for vulnerable test applications.

#### Safe
- Purpose: Fast, low-noise scans for large/hardened sites.
- Behavior:
  - Reduced crawl depth (1 level).
  - Runs: Security headers (with alternative detection), Misconfig (reduced noise), XSS (strict).
  - Skips: SQL Injection, Open Redirect, URL parameter fuzzing.

#### Standard (default)
- Purpose: Balanced coverage with low false positives.
- Behavior:
  - Moderate crawl depth (2 levels).
  - Runs: Headers (with alternative detection), Misconfig, XSS (strict), SQL Injection.
  - Skips: Open Redirect and parameter fuzzing.

#### Aggressive
- Purpose: Thorough testing; slower and more likely to trigger rate limits.
- Behavior:
  - Same crawl depth as standard (2 levels).
  - Runs: Headers (with alternative detection), Misconfig, XSS (not strict), SQL Injection, Open Redirect, URL parameter fuzzing.

### Why these changes?
- Large public targets (e.g., search engines) produce massive crawl graphs and anti-bot responses.
- Naive reflections and content-length differences can look like XSS/SQLi when they are not.
- Public files like `robots.txt` are not vulnerabilities; flagging them adds noise.
- Security headers may be implemented via alternative methods (meta tags, domain-level config).
- Search engines legitimately reflect user input in search results.

### Usage Examples
```bash
# Ultra-Safe (minimal, for large public sites)
python main.py https://www.google.com --mode ultra-safe

# Ultra-Safe (full scan, for vulnerable test sites)
python main.py http://testphp.vulnweb.com --mode ultra-safe
python main.py http://localhost:3000 --mode ultra-safe  # Juice Shop

# Safe (fast, quiet)
python main.py https://www.google.com --mode safe

# Standard (default)
python main.py https://example.com --mode standard

# Aggressive (thorough)
python main.py https://example.com --mode aggressive
```

### Implementation Notes (Code References)
- Modes: Orchestrated in `main.py` via the `mode` argument of `run_complete_scan()`; controls crawl depth and which scanners execute.
- XSS strict: `scanners/xss.py` adds `strict=True` flag and context awareness to only accept `script_context`, `attribute_context`, or `exact_match`, and still re-verifies.
- Headers: `scanners/headers.py` checks for alternative CSP implementations (meta tags) and domain-level HSTS.
- Site exclusions: `scanners/headers.py` and `scanners/xss.py` include site-specific configurations for known secure implementations.
- Misconfig: `scanners/misconfig.py` removes `robots.txt`/`sitemap.xml`/`crossdomain.xml` from `SENSITIVE_PATHS`.

### Recommended Practices
- Use `--mode ultra-safe` for very large/public domains (Google, Facebook, Microsoft) to avoid false positives.
- Use `--mode ultra-safe` for vulnerable test sites (Juice Shop, DVWA, testphp.vulnweb.com) - it will automatically run full scans.
- Prefer `--mode safe` for other large/hardened sites to avoid long runtimes and noise.
- Use `--mode standard` for most authenticated app assessments.
- Reserve `--mode aggressive` for smaller scopes or lab environments.

### False Positive Reduction Features
- **Context-aware XSS detection**: Distinguishes between intentional reflection (search results) and vulnerable reflection.
- **Alternative security header detection**: Checks for CSP in meta tags and domain-level HSTS.
- **Site-specific exclusions**: Whitelists known secure implementations for major sites.
- **Legitimate file exclusions**: Skips flagging intentionally public files.
- **Enhanced verification**: Double-checks findings before reporting.

### Related Documentation
- [False Positive Reduction Guide](false_positive_reduction.md) - Comprehensive guide to false positive reduction features
- [Risk Scoring Documentation](risk_scoring.md) - Vulnerability risk assessment and scoring


