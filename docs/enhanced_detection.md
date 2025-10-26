# Enhanced Vulnerability Detection

This document describes the expanded detection capabilities added in this update: advanced SQL Injection payloads (including UNION/boolean), DOM & stored XSS, CSRF checks, and deeper misconfiguration checks (CORS, cookies).

## SQL Injection Enhancements (scanners/sqli.py)

- Error-based: Extensive DB error patterns
- Time-based blind: Baseline timing + verification (>4s)
- Boolean-based blind: True/false response differential + verification
- UNION-based: Column count/error heuristics and significant content/status change
- Verification: All findings attempt a confirming second request

## XSS Enhancements (scanners/xss.py)

- Reflected XSS: Marker-based detection with context analysis
- DOM-based XSS: JavaScript context patterns (script, attributes, document/window)
- Stored XSS: Submit unique marker, revisit pages, detect marker rendering
- Strict mode: Only executable contexts reported in safe/standard modes

## CSRF Heuristics (scanners/misconfig.py)

- Forms parsed from HTML are checked for recognizable CSRF tokens
- Hidden input or meta token names matched: `csrf`, `_csrf`, `csrfmiddlewaretoken`, `authenticity_token`, `__RequestVerificationToken`
- Findings reported when tokens are absent

## CORS Checks (scanners/misconfig.py)

- Flags `Access-Control-Allow-Origin: *` with `Access-Control-Allow-Credentials: true` (High)
- Flags wildcard origins (Medium)
- Flags sensitive headers exposed via `Access-Control-Allow-Headers` (Authorization/Cookie)

## Cookie Security (scanners/misconfig.py)

- Session/auth cookies checked for `Secure`, `HttpOnly`, and `SameSite`
- Evidence includes `Set-Cookie` header snapshot

## Wiring and Modes

- Standard/Aggressive modes include SQLi (error/time/boolean/UNION) and XSS (reflected/DOM/stored)
- Ultra-safe mode uses smart target detection to decide which scanners to run
- Misconfiguration scans always run; CORS/cookie/CSRF checks included

## Usage

```bash
# Balanced
python main.py https://example.com --mode standard

# Thorough
python main.py https://example.com --mode aggressive
```

## Notes and Limitations

- CSRF checks are heuristic; presence of tokens does not guarantee validation server-side
- Stored XSS requires pages that render submitted content; not all targets will show this
- UNION-based heuristics rely on content/status shifts or error strings; may be muted by custom error pages

