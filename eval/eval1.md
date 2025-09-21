## **Key Features**

1. **Web Crawler**
   - Discovers all internal links and forms on the target website.
   - Respects `robots.txt` if configured.
   - Saves discovered links and forms to discovered.json.

2. **Vulnerability Scanners**
   - **Security Headers Check:** Detects missing HTTP security headers.
   - **SQL Injection (SQLi):** Tests forms for SQL injection vulnerabilities using error-based and time-based payloads.
   - **Cross-Site Scripting (XSS):** Tests forms for reflected XSS using common payloads.
   - **Misconfiguration/Sensitive Files:** Checks for exposed sensitive files (e.g., `.git/`, `.env`, `backup/`, `config.php`).
   - **Open Redirect:** Detects open redirect vulnerabilities in discovered links.
   - **Parameter Fuzzing:** Fuzzes URL parameters for reflected XSS and SQLi.

3. **Reporting**
   - Aggregates all findings.
   - Generates reports in both JSON (report.json) and Markdown (report.md) formats.

---

## **Implementation Details**

### **1. Crawler (`crawler/crawler.py`)**

- **Class:** `Crawler`
- **Libraries Used:** `requests`, `BeautifulSoup` (from `bs4`), `urllib.parse`, `json`
- **How it works:**
  - **Initialization:** Takes a base URL, max crawl depth, and whether to respect `robots.txt`.
  - **Robots.txt Parsing:** Downloads and parses `robots.txt` to avoid disallowed paths.
  - **Link Discovery:** For each page, extracts all internal anchor links and forms.
  - **Form Extraction:** Gathers form actions, methods, and input fields.
  - **Normalization:** Normalizes URLs to avoid duplicates.
  - **Recursion:** Crawls discovered links up to the specified depth.
  - **Results:** Stores all found links and forms in `self.discovered` and saves to discovered.json.

### **2. Helper Utilities (`utils/helpers.py`)**

- **Functions:**
  - `normalize_url`: Ensures URLs have a scheme and no trailing slash.
  - `is_site_up`: Checks if the target site is reachable (HTTP 200/301/302).

### **3. Vulnerability Scanners (`scanners/`)**

#### **a. Security Headers (`scanners/headers.py`)**
- **Function:** `check_security_headers`
- **Checks for:** `X-Frame-Options`, `Content-Security-Policy`, `Strict-Transport-Security`
- **Also checks:** If HTTPS is enforced.

#### **b. SQL Injection (`scanners/sqli.py`)**
- **Function:** `test_sqli`
- **How:** Submits SQLi payloads to each form input, detects:
  - Error-based SQLi (by searching for SQL error messages in responses).
  - Blind SQLi (by measuring response delays for time-based payloads).

#### **c. Cross-Site Scripting (`scanners/xss.py`)**
- **Function:** `test_xss`
- **How:** Submits XSS payloads to form inputs, checks if payload is reflected in the response.

#### **d. Misconfiguration & Sensitive Files (misconfig.py, `scanners/misc.py`)**
- **Function:** `check_misconfig`, `check_misconfig`
- **How:** Requests common sensitive file paths and checks if they are accessible.

#### **e. Open Redirect (`scanners/misc.py`)**
- **Function:** `check_open_redirect`
- **How:** Appends open redirect payloads to discovered links and checks if the server redirects to an external site.

#### **f. Parameter Fuzzing (`scanners/misc.py`)**
- **Function:** `fuzz_url_params`
- **How:** Modifies URL parameters with XSS/SQLi payloads and checks if payloads are reflected in the response.

### **4. Reporting (`reports/reporter.py`)**

- **Class:** `Reporter`
- **How:**
  - Aggregates findings from all scanners.
  - Saves results as:
    - **JSON:** For programmatic use.
    - **Markdown:** For human-readable reports.

---

## **Workflow (as per `main.py`)**

1. **Input:** Takes a target URL as a command-line argument.
2. **Pre-check:** Normalizes the URL and checks if the site is up.
3. **Crawling:** Uses `Crawler` to discover links and forms.
4. **Reporting:** Initializes a `Reporter` instance.
5. **Scanning:** Runs all scanners in sequence, adding findings to the reporter.
6. **Parameter Fuzzing:** Fuzzes all discovered links for reflected vulnerabilities.
7. **Output:** Saves the aggregated findings to report.json and report.md.

---

## **Dependencies**

- `requests`: HTTP requests.
- `beautifulsoup4`: HTML parsing.
- `tqdm`: (Not used in the provided code, but likely for progress bars).
- `colorama`: (Not used in the provided code, but likely for colored terminal output).

---

## **Summary Table**

| Feature                | Implemented In                | How It Works                                                                 |
|------------------------|------------------------------|------------------------------------------------------------------------------|
| Crawling               | crawler.py | Recursively discovers links/forms, respects robots.txt, saves to JSON         |
| Security Headers       | headers.py | Checks for missing HTTP security headers                                      |
| SQL Injection          | sqli.py       | Submits payloads to forms, detects error/timing-based SQLi                    |
| XSS                    | xss.py         | Submits payloads to forms, detects reflected XSS                              |
| Sensitive Files        | misconfig.py, misc.py | Requests common sensitive paths                                               |
| Open Redirect          | misc.py       | Appends payloads to URLs, checks for external redirects                       |
| Parameter Fuzzing      | misc.py       | Fuzzes URL parameters for reflected payloads                                  |
| Reporting              | reporter.py | Aggregates findings, outputs JSON/Markdown                                    |

---

## **Example Output**

- **JSON Report:** Machine-readable, lists all findings with details.
- **Markdown Report:** Human-readable, grouped by vulnerability type.

---

## **Extensibility**

- **Modular Design:** Each scanner is in its own file, making it easy to add new vulnerability checks.
- **Crawler and Reporter:** Decoupled from scanning logic, reusable for other types of scans.

---

## **Conclusion**

This framework provides an automated, extensible way to crawl web applications and scan for a variety of common vulnerabilities, outputting comprehensive reports for further analysis. It leverages Python’s requests and BeautifulSoup for HTTP and HTML parsing, and is structured for easy maintenance and extension.