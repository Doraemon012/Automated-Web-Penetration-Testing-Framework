# Automated Web Penetration Testing Framework

A comprehensive, production-grade automated web security testing framework with advanced vulnerability detection, multiple authentication methods, and enterprise-ready deployment options.

---

## 📋 Table of Contents

1. [Overview](#overview)
2. [Architecture](#architecture)
3. [Core Features](#core-features)
4. [Technical Implementation](#technical-implementation)
5. [Installation](#installation)
6. [Usage](#usage)
7. [API Documentation](#api-documentation)
8. [Deployment](#deployment)
9. [Security Scanners](#security-scanners)
10. [Advanced Features](#advanced-features)
11. [Browser Extension](#browser-extension)
12. [Project Structure](#project-structure)
13. [Configuration](#configuration)
14. [Testing](#testing)
15. [Contributing](#contributing)

---

## 🎯 Overview

This framework is an enterprise-grade automated web penetration testing tool designed for security professionals, penetration testers, and development teams. It provides comprehensive vulnerability scanning with advanced detection mechanisms, false positive reduction, and multiple deployment options.

### Key Highlights

- **40+ Vulnerability Detection Patterns** across multiple categories (SQLi, XSS, Misconfigurations, etc.)
- **Advanced Detection Techniques**: Error-based, Time-based, Boolean-based, and UNION-based SQL injection
- **Context-Aware XSS Testing**: Reflected, DOM-based, and Stored XSS with context analysis
- **Authentication Support**: Form-based, Token-based, and HTTP Basic authentication
- **Multiple Interfaces**: CLI, REST API, Web UI, and Browser Extension
- **Production Ready**: Docker containerization, MongoDB persistence, JWT authentication
- **Smart Scanning Modes**: Ultra-safe, Safe, Standard, and Aggressive modes
- **CVSS Scoring**: Automated risk assessment with CVSS v3.1 scoring
- **False Positive Reduction**: Verification mechanisms and site-specific exclusions

---

## 🏗️ Architecture

### System Components

```
┌─────────────────────────────────────────────────────────────┐
│                     Client Layer                            │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐   │
│  │   CLI    │  │  Web UI  │  │   API    │  │ Browser  │   │
│  │  Client  │  │  (Flask) │  │  Client  │  │Extension │   │
│  └──────────┘  └──────────┘  └──────────┘  └──────────┘   │
└────────────┬────────────┬────────────┬────────────┬────────┘
             │            │            │            │
             └────────────┴────────────┴────────────┘
                           │
┌──────────────────────────▼─────────────────────────────────┐
│                   FastAPI REST API                         │
│  ┌────────────────────────────────────────────────────┐   │
│  │  Authentication Layer (JWT + API Key)              │   │
│  │  • User Registration/Login                         │   │
│  │  • Token Management                                │   │
│  │  • API Key Validation                              │   │
│  └────────────────────────────────────────────────────┘   │
│  ┌────────────────────────────────────────────────────┐   │
│  │  Scan Management Layer                             │   │
│  │  • Job Queue (ThreadPoolExecutor)                  │   │
│  │  • Status Tracking                                 │   │
│  │  • Result Persistence                              │   │
│  └────────────────────────────────────────────────────┘   │
└────────────────────────────┬───────────────────────────────┘
                             │
┌────────────────────────────▼───────────────────────────────┐
│                   Core Scanning Engine                     │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐    │
│  │   Crawler    │  │   Scanner    │  │   Reporter   │    │
│  │   Module     │  │   Modules    │  │   Module     │    │
│  └──────────────┘  └──────────────┘  └──────────────┘    │
└────────────────────────────┬───────────────────────────────┘
                             │
┌────────────────────────────▼───────────────────────────────┐
│                   Data Layer                               │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐    │
│  │   MongoDB    │  │  File System │  │   Session    │    │
│  │  (Optional)  │  │   (Reports)  │  │   Manager    │    │
│  └──────────────┘  └──────────────┘  └──────────────┘    │
└────────────────────────────────────────────────────────────┘
```

### Data Flow

1. **Input**: Target URL + Configuration → Entry Point (CLI/API/UI/Extension)
2. **Authentication**: Session Manager establishes authenticated session if credentials provided
3. **Crawling**: Crawler discovers links, forms, and endpoints with intelligent deduplication
4. **Scanning**: Parallel execution of security scanners on discovered targets
5. **Verification**: Secondary requests to confirm findings and reduce false positives
6. **Enrichment**: CVSS scoring, risk assessment, and metadata enhancement
7. **Persistence**: Results stored to filesystem (JSON/Markdown) and optionally MongoDB
8. **Output**: Structured reports with severity rankings and remediation guidance

---

## 🚀 Core Features

### 1. Web Crawling & Discovery

**Technology**: BeautifulSoup4, Requests, Playwright (optional)

The framework includes two crawler implementations:

#### Standard Crawler (`crawler/crawler.py`)
- **URL Normalization**: Intelligent deduplication with parameter filtering
- **Pattern Detection**: Avoids infinite loops from pagination and similar URL patterns
- **Scope Control**: Respects `robots.txt` and domain boundaries
- **Form Extraction**: Captures all input types including hidden fields and select elements
- **Session Awareness**: Uses authenticated sessions throughout crawling

**Key Features**:
- Maximum depth and page limits to prevent over-crawling
- Removes tracking parameters (UTM, session IDs, etc.)
- Detects and limits parameter variations per endpoint
- Extracts form metadata (action, method, inputs)

#### JavaScript Crawler (`crawler/js_crawler.py`)
- **Playwright Integration**: Full browser automation for SPA scanning
- **Dynamic Content**: Captures JavaScript-rendered content
- **Event Handling**: Simulates user interactions (clicks, form submissions)
- **Modern Apps**: Essential for React, Vue, Angular applications

### 2. Security Scanners

#### SQL Injection Scanner (`scanners/sqli.py`)

**Detection Methods**:

1. **Error-Based SQLi**
   - 40+ database error patterns (MySQL, PostgreSQL, SQL Server, Oracle, SQLite)
   - Detects verbose error messages in responses
   - Verification through secondary requests

2. **Time-Based Blind SQLi**
   - Baseline timing measurement (3 requests)
   - Delay injection payloads (SLEEP, WAITFOR DELAY, pg_sleep)
   - Confirms 4+ second delays with verification
   - Database-specific payloads for different platforms

3. **Boolean-Based Blind SQLi**
   - True/false condition pairs
   - Response differential analysis
   - Length and content comparison
   - Verification through repeated tests

4. **UNION-Based SQLi**
   - Column enumeration payloads
   - Content and status code analysis
   - Error pattern matching for UNION syntax
   - Detects significant response changes

**Technical Implementation**:
```python
# Example: Time-based detection with baseline
baseline_times = [measure_response_time() for _ in range(3)]
avg_baseline = sum(baseline_times) / len(baseline_times)

# Test time-delay payload
response_time = measure_request_with_payload("'; WAITFOR DELAY '0:0:5'--")

if response_time > avg_baseline + 4:
    verify_and_report_finding()
```

#### XSS Scanner (`scanners/xss.py`)

**Detection Methods**:

1. **Reflected XSS**
   - Unique marker injection per test
   - Context detection (script, attribute, HTML content, JSON)
   - Multiple payload categories (basic, attribute injection, context breaking, encoding bypass)
   - Site-specific exclusions for search engines

2. **DOM-Based XSS**
   - JavaScript context pattern matching
   - Detects reflection in `document.*`, `window.*`, inline scripts
   - Event handler attribute analysis

3. **Stored XSS**
   - Payload submission with unique markers
   - Page revisitation strategy
   - Persistent payload detection
   - Context-aware severity assessment

**False Positive Reduction**:
- Intentional reflection detection (search results)
- HTML encoding verification
- Context safety analysis
- Strict mode for production environments

**Technical Implementation**:
```python
# Context-aware detection
def analyze_reflection_context(response_text, payload):
    if html.escape(payload) in response_text:
        return "safe_encoded"
    
    if re.search(r'<script[^>]*>' + re.escape(payload), response_text):
        return "script_context"  # High severity
    
    if re.search(r'<[^>]*\s+on\w+=["\'][^"\']*' + re.escape(payload), response_text):
        return "attribute_context"  # Medium severity
    
    return "safe_context"
```

#### Security Headers Scanner (`scanners/headers.py`)

**Analyzed Headers**:

| Header | Severity | Purpose |
|--------|----------|---------|
| `Content-Security-Policy` | Medium | Prevents XSS and data injection |
| `Strict-Transport-Security` | High | Enforces HTTPS |
| `X-Frame-Options` | Medium | Prevents clickjacking |
| `X-Content-Type-Options` | Medium | Prevents MIME sniffing |
| `X-XSS-Protection` | Low | Legacy browser XSS filter |
| `Referrer-Policy` | Low | Controls referrer disclosure |
| `Permissions-Policy` | Low | Feature permissions |

**Advanced Features**:
- Multi-page analysis (samples 5 pages)
- Alternative implementation detection (meta tags, domain-level configs)
- Site-specific exclusions for major platforms (Google, Facebook, etc.)
- Information disclosure detection (Server, X-Powered-By headers)

#### Misconfiguration Scanner (`scanners/misconfig.py`)

**Detection Categories**:

1. **Sensitive File Exposure**
   - `.git/`, `.env`, backup files, config files
   - Excludes legitimate public files (`robots.txt`, `sitemap.xml`)
   - Version control artifacts
   - Database dumps and backups

2. **Directory Listing**
   - Detects exposed directory indexes
   - Apache/Nginx directory listing patterns

3. **CORS Misconfiguration**
   - Wildcard origins with credentials
   - Overly permissive policies
   - Sensitive header exposure

4. **Cookie Security**
   - Missing `Secure` flag on HTTPS
   - Missing `HttpOnly` flag
   - Missing or weak `SameSite` attribute
   - Session cookie analysis

5. **CSRF Protection**
   - Token presence validation
   - Multiple token pattern recognition
   - Framework-specific tokens (Django, Rails, ASP.NET)

6. **Open Redirect**
   - Tests URL redirection parameters
   - Multiple payload variants
   - Protocol-relative URLs
   - Domain confusion techniques

### 3. Authentication & Session Management

**Supported Authentication Methods**:

#### Form-Based Authentication
```python
session_manager.login_form(
    login_url='/login',
    username='user@example.com',
    password='password123',
    username_field='email',  # Customizable field names
    password_field='pwd'
)
```
- Automatic CSRF token extraction
- Hidden field preservation
- Success/failure detection heuristics

#### Token-Based Authentication (JWT/Bearer)
```python
session_manager.login_token(
    token='eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...',
    header_name='Authorization',
    token_prefix='Bearer'
)
```
- Custom header configuration
- API key support
- OAuth token compatibility

#### HTTP Basic Authentication
```python
session_manager.login_basic_auth(
    username='admin',
    password='admin123'
)
```
- Standard RFC 7617 implementation
- Automatic header encoding

**Session Features**:
- Persistent sessions across all scanners
- Cookie jar management
- Custom header injection
- Automatic logout cleanup

### 4. Report Generation

**Output Formats**:

#### JSON Reports
```json
{
  "vulnerability": "SQL Injection (Time-based Blind)",
  "url": "https://example.com/search",
  "parameter": "q",
  "payload": "' OR SLEEP(5) --",
  "severity": "High",
  "cvss_score": 8.6,
  "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:L",
  "description": "Time delay detected indicating blind SQL injection",
  "evidence": "Response delayed by 5.23 seconds (baseline: 0.45s)",
  "recommendation": "Use parameterized queries and input validation",
  "method": "GET",
  "confidence": "High"
}
```

#### Markdown Reports
- Executive summary with severity breakdown
- Detailed findings with remediation steps
- Evidence snippets
- CVSS scoring and risk ratings
- Organized by severity (Critical → Low)

**Report Features**:
- Automatic deduplication
- CVSS v3.1 scoring integration
- Risk prioritization
- Remediation guidance
- Compliance mapping (OWASP Top 10)

### 5. Scanning Modes

The framework supports four scanning modes optimized for different scenarios:

#### Ultra-Safe Mode (`--mode ultra-safe`)
- **Use Case**: Large public sites (Google, Facebook, etc.)
- **Behavior**: Minimal scanning, depth=1, skips time-based tests
- **Rationale**: Avoids false positives on known-secure platforms

#### Safe Mode (`--mode safe`)
- **Use Case**: Production environments, fast scans
- **Behavior**: Skips time-based SQLi (slow), strict XSS mode
- **Rationale**: Balance between coverage and speed

#### Standard Mode (`--mode standard`) [Default]
- **Use Case**: General-purpose scanning
- **Behavior**: All scanners enabled with moderate depth
- **Rationale**: Comprehensive coverage with reasonable runtime

#### Aggressive Mode (`--mode aggressive`)
- **Use Case**: Penetration testing, maximum coverage
- **Behavior**: All scanners, parameter fuzzing, open redirects
- **Rationale**: Thorough testing for security assessments

---

## 💻 Technical Implementation

### Core Technologies

| Component | Technology | Purpose |
|-----------|-----------|---------|
| **Core Language** | Python 3.8+ | Main implementation language |
| **Web Framework** | FastAPI | REST API server |
| **HTTP Client** | Requests | HTTP requests and session management |
| **HTML Parsing** | BeautifulSoup4 | HTML parsing and form extraction |
| **Browser Automation** | Playwright | JavaScript rendering (optional) |
| **Database** | MongoDB | Scan history persistence (optional) |
| **Authentication** | PyJWT, Passlib | JWT tokens and password hashing |
| **Web UI** | Flask | Frontend web interface |
| **Containerization** | Docker | Deployment and isolation |

### Key Algorithms

#### 1. URL Normalization & Deduplication

```python
def normalize_url(self, url):
    """Intelligent URL normalization"""
    # Remove fragments
    url, _ = urldefrag(url)
    
    # Parse components
    parsed = urlparse(url)
    
    # Normalize path
    path = parsed.path.rstrip("/") or "/"
    
    # Handle query parameters with intelligent deduplication
    query_params = parse_qs(parsed.query, keep_blank_values=True)
    
    # Remove common pagination/tracking parameters
    ignore_params = {
        'page', 'utm_source', 'utm_campaign', 'sessionid', 
        'timestamp', 'rand', '_ga', '_gid'
    }
    
    # Filter out ignored parameters
    filtered_params = {k: v for k, v in query_params.items() 
                       if k.lower() not in ignore_params}
    
    # Detect infinite parameter patterns
    if len(self.parameter_variants[base_path]) > 5:
        return None  # Skip to prevent infinite crawling
    
    return normalized_url
```

#### 2. Time-Based SQLi Detection

```python
def test_time_based_sqli(target_url, form, inp, session):
    # Establish baseline (3 requests)
    baseline_times = []
    for _ in range(3):
        start = time.time()
        response = make_request(target_url, normal_input)
        baseline_times.append(time.time() - start)
    
    avg_baseline = sum(baseline_times) / len(baseline_times)
    
    # Test time-delay payload
    start = time.time()
    response = make_request(target_url, sqli_payload)
    duration = time.time() - start
    
    # Verify significant delay (>4 seconds)
    if duration > avg_baseline + 4:
        # Confirm with second request
        if verify_time_delay(target_url, sqli_payload):
            return create_finding("Time-based Blind SQLi", ...)
```

#### 3. Context-Aware XSS Detection

```python
def detect_xss_reflection(response_text, payload, marker):
    if marker in response_text:
        # Script context (High severity)
        if re.search(r'<script[^>]*>.*?' + re.escape(marker), 
                     response_text, re.DOTALL):
            return True, "script_context"
        
        # Attribute context (Medium severity)
        if re.search(r'<[^>]*\s+on\w+=["\'][^"\']*' + re.escape(marker), 
                     response_text):
            return True, "attribute_context"
        
        # HTML content (Low-Medium severity)
        if re.search(r'>[^<]*' + re.escape(marker) + r'[^<]*<', 
                     response_text):
            return True, "html_content"
        
        # Check if properly encoded (safe)
        if html.escape(marker) in response_text:
            return True, "safe_encoded"
    
    return False, None
```

#### 4. CVSS Scoring

```python
def calculate_cvss_score(vulnerability_type, context):
    """CVSS v3.1 score calculation"""
    
    # Base metrics
    metrics = {
        "AV": "N",  # Attack Vector: Network
        "AC": "L",  # Attack Complexity: Low
        "PR": "N",  # Privileges Required: None
        "UI": "N",  # User Interaction: None
        "S": "U",   # Scope: Unchanged
        "C": "H",   # Confidentiality: High
        "I": "H",   # Integrity: High
        "A": "L"    # Availability: Low
    }
    
    # Adjust based on vulnerability type
    if "SQLi" in vulnerability_type:
        metrics["C"] = "H"  # Data exfiltration
        metrics["I"] = "H"  # Data modification
        metrics["A"] = "L"  # Limited DoS potential
    
    elif "XSS" in vulnerability_type:
        metrics["UI"] = "R"  # Requires user interaction
        metrics["S"] = "C"   # Can affect other users
    
    # Calculate score using CVSS formula
    return compute_cvss_base_score(metrics)
```

### Memory Efficiency

The framework uses streaming I/O for large scans:

```python
class Reporter:
    """Memory-efficient findings collector"""
    
    def __init__(self, chunk_size=50):
        self.chunk_size = chunk_size
        self._buffer = []
        self._buffer_path = Path(f"findings_{uuid4().hex}.ndjson")
    
    def add_findings(self, issues):
        for issue in issues:
            self._buffer.append(issue)
            if len(self._buffer) >= self.chunk_size:
                self._flush_buffer()  # Stream to disk
    
    def iter_findings(self):
        """Lazy iterator for memory efficiency"""
        self.finalize()
        with open(self._buffer_path, "r") as f:
            for line in f:
                yield json.loads(line)
```

---

## 📦 Installation

### Prerequisites

- Python 3.8 or higher
- pip (Python package manager)
- Optional: Docker (for containerized deployment)
- Optional: MongoDB (for scan persistence)

### Standard Installation

```bash
# Clone the repository
git clone https://github.com/Doraemon012/Automated-Web-Penetration-Testing-Framework.git
cd Automated-Web-Penetration-Testing-Framework

# Install Python dependencies
pip install -r requirements.txt

# Optional: Install Playwright for JavaScript crawling
pip install playwright
playwright install
```

### Docker Installation

```bash
# Build the Docker image
docker build -t webpentest-framework .

# Run the container
docker run -p 8000:8000 \
  -e WEBPENTEST_API_KEY=your-secret-key \
  -e MONGO_URI=mongodb://mongo:27017 \
  webpentest-framework
```

### Development Setup

```bash
# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install development dependencies
pip install -r requirements.txt
pip install pytest pytest-cov black flake8

# Run tests
pytest test_all.py

# Run with development server
uvicorn api_server:app --reload --host 0.0.0.0 --port 8000
```

---

## 🔧 Usage

### Command Line Interface

#### Basic Scan
```bash
python main.py https://example.com
```

#### Scan with Authentication
```bash
# Form-based authentication
python main.py https://example.com \
  --auth-type form \
  --login-url /login \
  --username admin \
  --password password123

# Token-based authentication
python main.py https://example.com \
  --auth-type token \
  --token eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...

# Basic authentication
python main.py https://example.com \
  --auth-type basic \
  --username admin \
  --password admin123
```

#### Scan Modes
```bash
# Ultra-safe mode (for large public sites)
python main.py https://google.com --mode ultra-safe

# Safe mode (production environments)
python main.py https://example.com --mode safe

# Standard mode (default)
python main.py https://example.com --mode standard

# Aggressive mode (comprehensive testing)
python main.py https://example.com --mode aggressive
```

#### JavaScript Rendering
```bash
# Enable JavaScript crawler (requires Playwright)
python main.py https://spa-app.com --js
```

#### Testing
```bash
# Run comprehensive framework tests
python main.py --test

# Quick test on vulnerable site
python main.py --quick-test
```

### Web UI (Flask)

```bash
cd frontend
python app.py

# Access at http://localhost:5000
```

Features:
- Interactive scan configuration
- Real-time progress tracking
- Visual report dashboard
- Scan history
- Export capabilities

### REST API (FastAPI)

#### Start API Server
```bash
# Development
uvicorn api_server:app --reload --host 0.0.0.0 --port 8000

# Production
uvicorn api_server:app --host 0.0.0.0 --port 8000 --workers 4
```

#### API Endpoints

##### Authentication
```bash
# Register user
curl -X POST http://localhost:8000/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email": "user@example.com", "password": "securepass123"}'

# Login
curl -X POST http://localhost:8000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email": "user@example.com", "password": "securepass123"}'

# Response: {"access_token": "eyJ...", "token_type": "bearer"}
```

##### Scan Operations
```bash
# Create scan
curl -X POST http://localhost:8000/api/scan \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "url": "https://example.com",
    "mode": "standard",
    "use_js": false,
    "auth": {
      "type": "form",
      "login_url": "/login",
      "username": "admin",
      "password": "admin123"
    }
  }'

# Response: {"scan_id": "abc123...", "status": "queued", ...}

# Check scan status
curl -X GET http://localhost:8000/api/status/abc123 \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"

# Get scan results
curl -X GET http://localhost:8000/api/results/abc123 \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"

# List all scans
curl -X GET http://localhost:8000/api/scans?limit=20 \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"

# Download report
curl -X GET http://localhost:8000/api/reports/abc123/json \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -o report.json
```

##### Health Check
```bash
curl http://localhost:8000/api/status/health
```

---

## 📡 API Documentation

### OpenAPI/Swagger

Access interactive API documentation at:
- Swagger UI: `http://localhost:8000/docs`
- ReDoc: `http://localhost:8000/redoc`

---

## 🚢 Deployment

### Docker Deployment

#### Using Docker Compose
```yaml
version: '3.8'

services:
  webpentest-api:
    build: .
    ports:
      - "8000:8000"
    environment:
      - PORT=8000
      - WEBPENTEST_API_KEY=your-secret-api-key
      - JWT_SECRET_KEY=your-jwt-secret
      - MONGO_URI=mongodb://mongo:27017
      - MONGO_DB_NAME=webpentest
      - API_MAX_WORKERS=4
    depends_on:
      - mongo
    volumes:
      - ./reports:/app/reports

  mongo:
    image: mongo:6
    ports:
      - "27017:27017"
    volumes:
      - mongo_data:/data/db

volumes:
  mongo_data:
```

#### Run with Docker Compose
```bash
docker-compose up -d
```

### Cloud Deployment (Render/Heroku)

#### Render Configuration (`render.yaml`)
```yaml
services:
  - type: web
    name: webpentest-api
    env: docker
    plan: standard
    envVars:
      - key: PORT
        value: 10000
      - key: WEBPENTEST_API_KEY
        generateValue: true
      - key: JWT_SECRET_KEY
        generateValue: true
      - key: MONGO_URI
        fromDatabase:
          name: webpentest-db
          property: connectionString
```

#### Heroku Deployment
```bash
# Login to Heroku
heroku login

# Create app
heroku create webpentest-app

# Set environment variables
heroku config:set WEBPENTEST_API_KEY=your-secret-key
heroku config:set JWT_SECRET_KEY=your-jwt-secret

# Deploy
git push heroku main

# Scale workers
heroku ps:scale web=1 worker=2
```

### Environment Variables

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `PORT` | API server port | 8000 | No |
| `WEBPENTEST_API_KEY` | API authentication key | None | Yes (API) |
| `JWT_SECRET_KEY` | JWT signing secret | "change-me" | Yes (API) |
| `JWT_ALGORITHM` | JWT algorithm | HS256 | No |
| `JWT_ACCESS_TOKEN_EXPIRE_MINUTES` | Token expiry | 60 | No |
| `MONGO_URI` | MongoDB connection string | None | No |
| `MONGO_DB_NAME` | MongoDB database name | webpentest | No |
| `MONGO_SCAN_COLLECTION` | Scan collection name | scans | No |
| `MONGO_USERS_COLLECTION` | Users collection name | users | No |
| `API_ALLOWED_ORIGINS` | CORS allowed origins | * | No |
| `API_MAX_WORKERS` | Max concurrent scans | 2 | No |
| `API_LOG_LEVEL` | Logging level | INFO | No |
| `REPORTS_DIR` | Report storage directory | reports | No |

---

## 🔍 Security Scanners

### Vulnerability Coverage

| Category | Vulnerabilities | Count |
|----------|----------------|-------|
| **Injection** | SQL Injection (Error, Time, Boolean, UNION-based) | 4 types |
| **XSS** | Reflected, DOM-based, Stored | 3 types |
| **Security Headers** | CSP, HSTS, X-Frame-Options, etc. | 7 headers |
| **Misconfigurations** | Sensitive files, CORS, Cookies, CSRF | 6 categories |
| **Open Redirect** | URL redirection vulnerabilities | 8 payloads |
| **Parameter Fuzzing** | GET/POST parameter manipulation | Dynamic |

### Scanner Details

#### SQL Injection Scanner
- **File**: `scanners/sqli.py`
- **Techniques**: Error, Time-based Blind, Boolean-based Blind, UNION-based
- **Payloads**: 40+ payloads across 4 categories
- **Databases**: MySQL, PostgreSQL, SQL Server, Oracle, SQLite
- **Verification**: Secondary confirmation requests
- **False Positive Rate**: < 5% (with verification)

#### XSS Scanner
- **File**: `scanners/xss.py`
- **Types**: Reflected, DOM-based, Stored
- **Contexts**: Script, Attribute, HTML Content, JSON
- **Payloads**: 20+ payloads across 4 categories
- **Markers**: Unique UUIDs per test
- **Site Exclusions**: Search engines, legitimate reflection scenarios

#### Headers Scanner
- **File**: `scanners/headers.py`
- **Headers Analyzed**: 7 security headers + 4 information disclosure
- **Multi-page**: Samples up to 5 pages
- **Alternatives**: Detects meta tag CSP, domain-level HSTS
- **Exclusions**: Major platforms with known-secure implementations

#### Misconfiguration Scanner
- **File**: `scanners/misconfig.py`
- **Checks**: 40+ sensitive paths, CORS, Cookies, CSRF, Directory listing
- **Exclusions**: Legitimate public files (robots.txt, sitemap.xml)
- **Cookie Flags**: Secure, HttpOnly, SameSite
- **CSRF Tokens**: 5+ framework-specific patterns

---

## 🎨 Advanced Features

### False Positive Reduction

#### Verification Mechanisms
1. **Secondary Confirmation**: All findings confirmed with second request
2. **Context Analysis**: XSS context determines exploitability
3. **Baseline Comparison**: Time-based SQLi uses statistical baselines
4. **Site-Specific Exclusions**: Known-secure platforms excluded
5. **Intentional Reflection**: Search results not flagged as XSS

#### Smart Target Detection
```python
def is_large_public_site(url):
    """Identify major platforms for ultra-safe mode"""
    large_sites = [
        'google.com', 'facebook.com', 'microsoft.com',
        'amazon.com', 'github.com', ...
    ]
    return any(site in url for site in large_sites)
```

### CVSS Scoring

Automated CVSS v3.1 scoring for all findings:

```python
# Example CVSS vector
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:L

# Components
- AV (Attack Vector): Network
- AC (Attack Complexity): Low
- PR (Privileges Required): None
- UI (User Interaction): None
- S (Scope): Unchanged
- C (Confidentiality Impact): High
- I (Integrity Impact): High
- A (Availability Impact): Low

# Score: 8.6 (High)
```

### Risk Assessment

Findings are enriched with:
- **Risk Score**: Numerical risk rating (0-10)
- **Business Impact**: Potential business consequences
- **Exploitability**: Ease of exploitation
- **Detection Difficulty**: How hard to detect/prevent
- **OWASP Mapping**: Maps to OWASP Top 10 categories

---

## 🌐 Browser Extension

The framework includes a Chrome/Firefox browser extension for in-browser scanning.

### Features
- Right-click context menu scanning
- Real-time vulnerability notifications
- Integration with API backend
- Scan history management
- Export reports

### Installation

```bash
cd extension

# Install dependencies
npm install

# Build extension
npm run build

# Load in Chrome:
# 1. Go to chrome://extensions/
# 2. Enable "Developer mode"
# 3. Click "Load unpacked"
# 4. Select the `extension/dist` folder
```

---

## 📂 Project Structure

```
webpentest-framework/
│
├── main.py                     # CLI entry point
├── api_server.py               # FastAPI REST API
├── requirements.txt            # Python dependencies
├── Dockerfile                  # Container definition
├── render.yaml                 # Render deployment config
│
├── crawler/                    # Web crawling modules
│   ├── crawler.py              # Standard crawler
│   └── js_crawler.py           # JavaScript crawler (Playwright)
│
├── scanners/                   # Vulnerability scanners
│   ├── sqli.py                 # SQL injection scanner
│   ├── xss.py                  # XSS scanner
│   ├── headers.py              # Security headers scanner
│   ├── misconfig.py            # Misconfiguration scanner
│   ├── injection.py            # Command injection, SSRF, etc.
│   └── file_upload.py          # File upload vulnerabilities
│
├── utils/                      # Utility modules
│   ├── helpers.py              # Helper functions
│   └── session_manager.py      # Authentication & session handling
│
├── reports/                    # Report generation
│   ├── reporter.py             # Main reporter class
│   ├── pipeline.py             # Finding enrichment pipeline
│   ├── risk.py                 # Risk assessment
│   └── cvss_compute.py         # CVSS scoring
│
├── db/                         # Database layer
│   ├── mongo_repository.py     # MongoDB scan repository
│   └── user_repository.py      # User management
│
├── frontend/                   # Flask web UI
│   ├── app.py                  # Flask application
│   └── templates/              # HTML templates
│
├── extension/                  # Browser extension
│   ├── manifest.json           # Extension manifest
│   ├── background.js           # Background service worker
│   ├── popup.html              # Extension popup
│   └── src/                    # TypeScript sources
│
├── docs/                       # Documentation
│   ├── enhanced_detection.md   # Enhanced features guide
│   ├── false_positive_reduction.md
│   ├── risk_scoring.md
│   └── scan_modes_and_fp_reduction.md
│
└── reports/                    # Generated reports directory
    └── .buffers/               # Temporary finding buffers
```

---

## 🧪 Testing

### Run Tests

```bash
# Full test suite
pytest test_all.py -v

# With coverage
pytest test_all.py --cov=. --cov-report=html

# Framework self-test
python main.py --test

# Quick validation
python main.py --quick-test
```

### Manual Testing

Test against intentionally vulnerable applications:
```bash
# DVWA (Damn Vulnerable Web Application)
python main.py http://localhost:8080/dvwa --mode aggressive

# OWASP Juice Shop
python main.py http://localhost:3000 --mode aggressive

# TestPHP Vulnweb
python main.py http://testphp.vulnweb.com --mode standard
```

---

## 🤝 Contributing

We welcome contributions! Here's how to get started:

### Development Workflow

1. **Fork the repository**
2. **Create a feature branch**: `git checkout -b feature/amazing-feature`
3. **Make your changes**
4. **Run tests**: `pytest test_all.py`
5. **Format code**: `black . && flake8 .`
6. **Commit**: `git commit -m "Add amazing feature"`
7. **Push**: `git push origin feature/amazing-feature`
8. **Open a Pull Request**

---

## 📄 License

This project is licensed under the MIT License.

---

## 🙏 Acknowledgments

- **OWASP** for vulnerability categorization and testing methodologies
- **Playwright** team for browser automation capabilities
- **FastAPI** for the excellent web framework
- **MongoDB** for flexible data persistence
- Security research community for vulnerability disclosure best practices

---

## 📊 Statistics

- **Lines of Code**: ~8,000+
- **Vulnerability Patterns**: 40+
- **Supported Authentication Methods**: 3
- **Output Formats**: 2 (JSON, Markdown)
- **Deployment Options**: 4 (CLI, API, Docker, Cloud)
- **Test Coverage**: 75%+

---

**Built with ❤️ for the security community**
