# Plan for Next Evaluation (2 Weeks)

## Current Status (Baseline Implemented)

So far, we have built a baseline framework that includes:

* Basic project setup (repo, README, requirements).
* CLI entrypoint that takes a target URL.
* A crawler that discovers internal links and forms with depth-limiting, robots.txt support, and URL normalization.
* Initial vulnerability checks:

  * Missing security headers.
  * Basic SQL Injection (error-based, limited blind timing).
  * Basic Reflected XSS (simple payload reflection).
  * Misconfiguration checks (`.git`, `.env`, `config.php`).
  * Open Redirects and simple parameter fuzzing.
* Report generation in JSON and Markdown.

This provides a functional proof of concept, but most modules are basic and need to be enhanced to reach a usable, reliable tool.

---

## Week 3 – Fingerprinting & Passive Checks (Enhancement Focus)

### Goals

1. Implement a **Fingerprinting Module**:

   * Detect web server type (`Apache`, `Nginx`, `IIS`) from headers.
   * Detect frameworks from hints (PHP extensions, Django CSRF tokens, Node.js headers, etc.).
   * Record cookies and flags (`HttpOnly`, `Secure`, `SameSite`).

2. Enhance existing **Headers Scanner**:

   * Move beyond just detecting missing headers.
   * Add detailed evidence (header values) in the report.
   * Classify severity more clearly (for example: missing HSTS → High).

3. Implement **Passive Vulnerability Checks**:

   * Missing headers: CSP, HSTS, X-Frame-Options.
   * Insecure cookies (cookies without `HttpOnly` or `Secure`).
   * Improve SQL error detection with a broader keyword list.

### Deliverables

* New `scanners/fingerprinting.py`.
* Enhanced `headers.py` with richer analysis.
* Findings stored with evidence and severity scoring.

---

## Week 4 – Expanded Checks Engine & Plugin Architecture

### Goals

1. Add **More Passive Checks**:

   * Verbose error messages (stack traces, database dumps).
   * Directory listing detection.
   * Mixed content (HTTP resources on HTTPS pages).

2. Enhance Current Active Checks:

   * SQL Injection: add more payloads and better blind detection.
   * XSS: extend payload set and introduce basic stored XSS detection.
   * Misconfigurations: expand sensitive paths list.

4. Deduplication and Severity Scoring:

   * Avoid duplicate findings in reports.
   * Ensure each finding has a clear severity (Low/Medium/High).

### Deliverables

* At least 5–6 passive checks implemented.
* Existing scanners enhanced with more payloads and detection logic.
* Plugin-based architecture for checks.
* Reports showing expanded findings with severity and no duplicates.

---

## Stretch Enhancements (If Time Allows)

* Rate limiting and retry logic to make crawling/scanning more stable.
* Confidence scoring (High/Medium/Low confidence on each finding).
* Preliminary support for JavaScript-heavy sites (via Playwright or Selenium).

