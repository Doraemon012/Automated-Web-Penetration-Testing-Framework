# 🛡️ Web Penetration Testing Framework

A comprehensive web security scanner that identifies common vulnerabilities in web applications through automated testing and crawling.

## 📋 Table of Contents

- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
  - [Command Line Interface](#command-line-interface)
  - [Web Interface](#web-interface)
- [Architecture](#architecture)
- [Vulnerability Types](#vulnerability-types)
- [Configuration](#configuration)
- [Reports](#reports)
- [Development](#development)
- [Contributing](#contributing)

## ✨ Features

### Core Scanning Capabilities
- **Web Crawling**: Intelligent discovery of links, forms, and endpoints
- **Security Headers Analysis**: Detection of missing security headers
- **SQL Injection Testing**: Error-based and time-based SQLi detection
- **Cross-Site Scripting (XSS)**: Reflected XSS vulnerability detection
- **Open Redirect Testing**: Detection of open redirect vulnerabilities
- **Misconfiguration Checks**: Discovery of exposed sensitive files
- **Parameter Fuzzing**: URL parameter vulnerability testing

### User Interfaces
- **Command Line Interface**: Traditional CLI for automation and scripting
- **Web Interface**: User-friendly Flask-based web UI for interactive scanning
- **Real-time Progress Tracking**: Live updates during scan execution
- **Comprehensive Reporting**: JSON and Markdown report generation

### Advanced Features
- **Robots.txt Compliance**: Respects website crawling policies
- **Depth-limited Crawling**: Configurable crawl depth to prevent infinite loops
- **Background Processing**: Non-blocking scan execution via threading
- **Scan History**: Persistent storage and retrieval of previous scan results

## 🚀 Installation

### Prerequisites
- Python 3.7 or higher
- pip package manager

### Setup
1. **Clone the repository:**
   ```bash
   git clone <repository-url>
   cd webpentest-framework
   ```

2. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

3. **Verify installation:**
   ```bash
   python main.py --help
   ```

## 💻 Usage

### Command Line Interface

#### Basic Scan
```bash
python main.py <target_url>
```

#### Examples
```bash
# Scan a vulnerable test site
python main.py http://testphp.vulnweb.com

# Scan with HTTPS
python main.py https://example.com

# Scan local development site
python main.py http://localhost:8080
```

#### Output
- **Console**: Real-time progress and summary
- **report.json**: Machine-readable detailed findings
- **report.md**: Human-readable vulnerability report
- **discovered.json**: Crawled links and forms inventory

### Web Interface

#### Starting the Web Application
```bash
# Navigate to frontend directory
cd frontend

# Start the Flask application
python app.py
```

#### Alternative: Run from root directory
```bash
# From project root
python frontend/app.py
```

#### Accessing the Interface
- **Main Scanner**: `http://localhost:5000/`
- **Scan History**: `http://localhost:5000/history`

#### Web Interface Features

##### Dashboard (`/`)
- **Target URL Input**: Enter the website to scan
- **One-Click Scanning**: Simple "Start Scan" button
- **Real-time Progress**: Live progress bar and status updates
- **Results Summary**: Vulnerability count by severity (High/Medium/Low)
- **Detailed Findings**: Expandable vulnerability details with:
  - Vulnerability type and description
  - Affected URL
  - Payload used (if applicable)
  - Severity level
- **Report Downloads**: Download JSON and Markdown reports

##### Scan History (`/history`)
- **Previous Scans**: List of all completed scans
- **Timestamp Information**: When each scan was performed
- **Vulnerability Counts**: Quick overview of findings
- **Report Access**: Download previous scan reports

#### API Endpoints

The web interface provides several API endpoints for programmatic access:

##### Start a Scan
```http
POST /api/scan
Content-Type: application/json

{
  "url": "https://example.com"
}
```

##### Check Scan Status
```http
GET /api/status
```

Response:
```json
{
  "running": true,
  "progress": 45,
  "current_task": "Testing for SQL injection...",
  "results": null,
  "error": null
}
```

##### Get Scan Results
```http
GET /api/results
```

##### Download Reports
```http
GET /api/download/<filename>
```

#### Example Web Scanning Workflow

1. **Start the Server**:
   ```bash
   cd frontend
   python app.py
   ```

2. **Open Browser**: Navigate to `http://localhost:5000`

3. **Enter Target**: Input target URL (e.g., `http://testphp.vulnweb.com`)

4. **Start Scan**: Click "Start Scan" button

5. **Monitor Progress**: Watch real-time progress updates:
   - Initializing crawler
   - Checking security headers
   - Testing for SQL injection
   - Testing for XSS vulnerabilities
   - Checking misconfigurations
   - Testing for open redirects
   - Fuzzing URL parameters

6. **Review Results**: Examine findings in the web interface:
   - Summary cards showing vulnerability counts
   - Detailed vulnerability list with descriptions
   - Severity-based color coding

7. **Download Reports**: Save detailed reports in JSON or Markdown format

## 🏗️ Architecture

### Project Structure
```
webpentest-framework/
├── main.py                    # CLI entry point
├── requirements.txt           # Python dependencies
├── README.md                 # This documentation
├── crawler/
│   └── crawler.py            # Web crawling functionality
├── scanners/
│   ├── headers.py            # Security headers checks
│   ├── sqli.py              # SQL injection tests
│   ├── xss.py               # XSS vulnerability tests
│   ├── misc.py              # Misconfiguration & parameter fuzzing
│   └── misconfig.py         # Sensitive file detection
├── reports/
│   └── reporter.py          # Report generation
├── utils/
│   └── helpers.py           # Utility functions
├── frontend/                # Web interface
│   ├── app.py              # Flask application
│   └── templates/          # HTML templates
│       ├── base.html       # Base template
│       ├── index.html      # Main dashboard
│       └── history.html    # Scan history page
└── eval/                   # Evaluation documentation
```

### Core Components

#### Crawler Module (`crawler/crawler.py`)
- **Functionality**: Discovers links, forms, and endpoints
- **Features**: 
  - Depth-limited crawling
  - Robots.txt compliance
  - URL normalization
  - Form extraction with input field analysis

#### Scanner Modules (`scanners/`)
- **Headers Scanner**: Checks for missing security headers (CSP, HSTS, etc.)
- **SQL Injection Scanner**: Tests forms and parameters for SQLi vulnerabilities
- **XSS Scanner**: Detects reflected cross-site scripting vulnerabilities
- **Misconfiguration Scanner**: Searches for exposed sensitive files
- **Parameter Fuzzer**: Tests URL parameters for various vulnerabilities

#### Reporter Module (`reports/reporter.py`)
- **JSON Reports**: Machine-readable format for integration
- **Markdown Reports**: Human-readable format with formatting
- **Finding Aggregation**: Collects and organizes all vulnerabilities

#### Web Interface (`frontend/`)
- **Flask Application**: Modern web framework for the UI
- **Real-time Updates**: WebSocket-like polling for progress tracking
- **Responsive Design**: Bootstrap-based mobile-friendly interface
- **Background Processing**: Threading for non-blocking scan execution

## 🔍 Vulnerability Types

### Security Headers
- **Missing Content Security Policy (CSP)**
- **Missing HTTP Strict Transport Security (HSTS)**
- **Missing X-Frame-Options**
- **Missing X-Content-Type-Options**
- **Missing X-XSS-Protection**

### SQL Injection
- **Error-based SQLi**: Detection through database error messages
- **Time-based Blind SQLi**: Detection through response timing analysis
- **Payloads Tested**:
  - `' OR 1=1 --`
  - `" OR "1"="1`
  - `'; WAITFOR DELAY '0:0:5' --`
  - `' OR '1'='1`

### Cross-Site Scripting (XSS)
- **Reflected XSS**: Payloads reflected in response content
- **Form-based Testing**: Injection through form inputs
- **Parameter-based Testing**: Injection through URL parameters

### Open Redirects
- **External Redirect Detection**: Attempts to redirect to external domains
- **Test Payloads**:
  - `https://evil.com`
  - `//evil.com`

### Misconfigurations
- **Sensitive File Exposure**: Detection of common sensitive files:
  - `.git/` directories
  - `.env` files
  - `config.php`
  - `backup` files
  - Admin panels

## ⚙️ Configuration

### Crawler Settings
- **Max Depth**: Default 2 levels (configurable in code)
- **Robots.txt**: Enabled by default
- **Timeout**: 5 seconds per request
- **User Agent**: Standard browser user agent

### Scanner Settings
- **Request Timeout**: 5 seconds
- **Payload Sets**: Predefined but extensible
- **Severity Levels**: High, Medium, Low

### Web Interface Settings
- **Port**: 5000 (default Flask port)
- **Host**: 0.0.0.0 (accessible from all interfaces)
- **Debug Mode**: Enabled in development
- **Background Threads**: Daemon threads for scanning

## 📊 Reports

### JSON Report Format
```json
[
  {
    "vulnerability": "Possible SQL Injection",
    "url": "https://example.com/login.php",
    "payload": "' OR 1=1 --",
    "severity": "High",
    "description": "Database error message detected"
  }
]
```

### Markdown Report Features
- **Structured Format**: Clear headings and sections
- **Severity Indicators**: Visual severity levels
- **Code Formatting**: Payloads displayed in code blocks
- **URL References**: Clickable links to affected pages

### Web Interface Reports
- **Real-time Display**: Results shown as they're discovered
- **Filterable Views**: Sort by severity or vulnerability type
- **Export Options**: Download in multiple formats
- **Historical Access**: Previous scan reports available

## 🛠️ Development

### Adding New Scanners
1. Create scanner module in `scanners/` directory
2. Implement scanning function returning list of findings
3. Add scanner to main scanning workflow in `main.py`
4. Update web interface progress tracking if needed

### Extending the Web Interface
1. Add new routes in `frontend/app.py`
2. Create corresponding HTML templates
3. Update navigation in `base.html`
4. Add any required JavaScript functionality

### Custom Payloads
Modify payload lists in scanner modules:
```python
# In scanners/sqli.py
SQLI_PAYLOADS = [
    "' OR 1=1 --",
    "\" OR \"1\"=\"1",
    "'; WAITFOR DELAY '0:0:5' --",
    # Add your custom payloads here
]
```

### Testing
```bash
# Test with vulnerable applications
python main.py http://testphp.vulnweb.com
python main.py http://dvwa.local

# Test web interface
cd frontend
python app.py
# Navigate to http://localhost:5000
```

## 🤝 Contributing

1. **Fork the repository**
2. **Create a feature branch**: `git checkout -b feature/new-scanner`
3. **Implement your changes**
4. **Add tests and documentation**
5. **Submit a pull request**

### Contribution Guidelines
- Follow existing code style and structure
- Add comprehensive documentation for new features
- Include example usage in docstrings
- Update README.md for significant features
- Test with multiple target applications

## 📄 License

This project is designed for educational and authorized testing purposes only. Users are responsible for compliance with applicable laws and regulations.

## ⚠️ Disclaimer

This tool is intended for educational purposes and authorized penetration testing only. Do not use this tool against websites or applications without explicit permission. The authors are not responsible for any misuse or damage caused by this tool.

## 🔗 Resources

- **OWASP Top 10**: https://owasp.org/www-project-top-ten/
- **OWASP Testing Guide**: https://owasp.org/www-project-web-security-testing-guide/
- **Flask Documentation**: https://flask.palletsprojects.com/
- **Beautiful Soup Documentation**: https://www.crummy.com/software/BeautifulSoup/bs4/doc/