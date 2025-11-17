const logoutBtn = document.getElementById("logoutBtn");
const authStatus = document.getElementById("authStatus");
const authSettingsBtn = document.getElementById("authSettingsBtn");
const authMessage = document.getElementById("authMessage");
const scanSection = document.getElementById("scanSection");
const scanForm = document.getElementById("scanForm");
const scanStatus = document.getElementById("scanStatus");
const historyList = document.getElementById("historyList");
const historyTemplate = document.getElementById("historyItemTemplate");
const resultSection = document.getElementById("resultSection");
const resultSummary = document.getElementById("resultSummary");
const severityBadges = document.getElementById("severityBadges");
const refreshHistoryBtn = document.getElementById("refreshHistory");
const openOptionsBtn = document.getElementById("openOptions");
const currentUrlBadge = document.getElementById("currentUrl");
const modeChips = document.querySelectorAll(".mode-chip");
const authLockedSections = document.querySelectorAll("[data-auth-locked]");
const websiteViewBtn = document.getElementById("website-view-btn");
const analystViewBtn = document.getElementById("analyst-view-btn");
const websiteFindingsView = document.getElementById("websiteFindingsView");
const analystViewPanel = document.getElementById("analystViewPanel");
const listPanel = document.getElementById("listPanel");
const detailPanel = document.getElementById("detailPanel");
const detailContent = document.getElementById("detailContent");
const vulnerabilityAccordion = document.getElementById("vulnerabilityAccordion");
const prevVulnBtn = document.getElementById("prevVuln");
const nextVulnBtn = document.getElementById("nextVuln");
const expandMinimizeBtn = document.getElementById("expandMinimizeBtn");
const downloadJsonBtn = document.getElementById("downloadJson");
const downloadMarkdownBtn = document.getElementById("downloadMarkdown");
const totalVulnsEl = document.getElementById("totalVulns");
const highVulnsEl = document.getElementById("highVulns");
const mediumVulnsEl = document.getElementById("mediumVulns");
const lowVulnsEl = document.getElementById("lowVulns");
const avgCvssEl = document.getElementById("avgCvss");
const criticalPriorityEl = document.getElementById("criticalPriority");
const withExploitEl = document.getElementById("withExploit");
const highConfidenceEl = document.getElementById("highConfidence");
const enhancedMetrics = document.getElementById("enhancedMetrics");
const STATUS_VARIANTS = ["status-pill-success", "status-pill-warn", "status-pill-danger", "status-pill-info"];

let currentTargetUrl = null;
let activeTabId = null;
let latestResult = null;
let groupedFindings = {};
let currentVulnIndex = 0;
let allVulnGroups = [];

const vulnerabilityDB = {
  "SQL Injection": {
    title: "SQL Injection (SQLi)",
    what: `SQL Injection lets an attacker inject SQL statements into queries the application runs against its database.`
      + ` It is one of the most common and dangerous web vulnerabilities because a successful attack can expose or destroy data.`,
    how: `The attacker sends crafted input (for example through a login form) that is concatenated directly into a SQL query.`
      + ` Without parameterized statements the rogue input executes as SQL and can dump tables, tamper with records, or escalate privileges.`,
    prevention: `<ul><li><strong>Always use parameterized queries:</strong> never concatenate raw input into SQL strings.</li>`
      + `<li><strong>Validate and sanitize user input:</strong> enforce strict types and allowed characters.</li>`
      + `<li><strong>Apply least privilege:</strong> give application accounts only the database permissions they need.</li></ul>`,
  },
  "Cross-Site Scripting (XSS)": {
    title: "Cross-Site Scripting (XSS)",
    what: `XSS lets attackers run arbitrary JavaScript in a victim's browser by injecting malicious markup into web pages.`,
    how: `Injected scripts run in the context of the vulnerable site and can steal cookies, hijack sessions, or rewrite the UI.`,
    prevention: `<ul><li><strong>Encode output based on context:</strong> escape user data before rendering in HTML, attributes, or URLs.</li>`
      + `<li><strong>Adopt a strict Content Security Policy:</strong> restrict where scripts can load from.</li>`
      + `<li><strong>Set HttpOnly cookies:</strong> prevents client-side scripts from reading session tokens.</li></ul>`,
  },
  "Reflected XSS": {
    title: "Reflected Cross-Site Scripting (XSS)",
    what: `Reflected XSS reflects attacker input immediately back to the browser via parameters such as search terms or error messages.`,
    how: `A victim clicks a crafted link where the attacker supplied script is echoed and executed in their browser.`,
    prevention: `<ul><li><strong>HTML-encode untrusted input before rendering:</strong> never output raw request parameters.</li>`
      + `<li><strong>Validate incoming data:</strong> reject suspicious characters or payloads.</li>`
      + `<li><strong>Use CSP:</strong> require scripts to come from trusted hosts only.</li></ul>`,
  },
  "Missing X-Frame-Options": {
    title: "Missing X-Frame-Options Header",
    what: `Without the X-Frame-Options header, your pages can be embedded in iframes, enabling clickjacking attacks.`,
    how: `Attackers can load the site in a hidden iframe and trick users into clicking buttons the attacker controls.`,
    prevention: `<ul><li><code>X-Frame-Options: DENY</code></li><li><code>X-Frame-Options: SAMEORIGIN</code></li></ul>`,
  },
  "Possible SQL Injection": {
    title: "Possible SQL Injection (SQLi)",
    what: `Potential SQL injection was detected. Even if not confirmed, sanitize inputs and review query handling.`,
    how: `The scanner observed patterns consistent with user input reaching SQL statements without proper encoding.`,
    prevention: `<ul><li><strong>Use prepared statements:</strong> bind variables instead of concatenating strings.</li>`
      + `<li><strong>Validate inputs:</strong> enforce whitelist patterns on parameters.</li>`
      + `<li><strong>Harden database accounts:</strong> ensure compromised queries cannot modify schema.</li></ul>`,
  },
  "Missing Content-Security-Policy": {
    title: "Missing Content-Security-Policy (CSP)",
    what: `CSP limits where browsers can load scripts, styles, and other resources. Without it, XSS exploits are easier.`,
    how: `If attackers find an injection vector they can freely load external scripts or exfiltrate data with no CSP in place.`,
    prevention: `<strong>Send a Content-Security-Policy header</strong> that whitelists trusted domains.`
      + ` Start with <code>default-src 'self'</code> and expand carefully.`,
  },
  "Missing Strict-Transport-Security": {
    title: "Missing HTTP Strict-Transport-Security (HSTS)",
    what: `HSTS forces browsers to use HTTPS for all future requests, preventing protocol downgrade and cookie leakage.`,
    how: `Without HSTS, an attacker on the network can intercept the first HTTP request before a redirect to HTTPS occurs.`,
    prevention: `<strong>Add</strong> <code>Strict-Transport-Security: max-age=31536000; includeSubDomains</code> to HTTPS responses.`,
  },
  "HTTPS not enforced": {
    title: "HTTPS Not Enforced",
    what: `Pages are accessible over HTTP or fail to redirect to HTTPS, allowing attackers to intercept traffic.`,
    how: `Unencrypted HTTP exposes credentials, cookies, and form data to anyone on the same network.`,
    prevention: `<ul><li>Redirect all HTTP requests to HTTPS.</li><li>Ensure every internal asset uses HTTPS URLs.</li><li>Mark cookies as Secure.</li></ul>`,
  },
  "Open Redirect": {
    title: "Open Redirect",
    what: `User-supplied URLs are used for redirects without validation, enabling phishing chains.`,
    how: `Attackers craft a trusted link that bounces victims to a malicious destination via your domain.`,
    prevention: `<strong>Maintain a whitelist</strong> of safe destinations or use internal IDs rather than raw URLs.`,
  },
  "Command Injection": {
    title: "Command Injection (OS Injection)",
    what: `Untrusted input reaches shell commands, letting attackers execute arbitrary operating system commands.`,
    how: `Payloads like <code>; cat /etc/passwd</code> become part of shell strings built from user data.`,
    prevention: `<ul><li>Avoid invoking shells with untrusted input.</li><li>If unavoidable, strictly whitelist commands and arguments.</li>`
      + `<li>Use parameter arrays instead of string concatenation.</li><li>Run processes with least privilege.</li></ul>`,
  },
  "Weak Login Page Security": {
    title: "Weak Login Page Security",
    what: `Login flows missing rate limiting, lockouts, or strong password policies are vulnerable to brute-force attacks.`,
    how: `Attackers automate credential stuffing or password guessing without controls to slow them down.`,
    prevention: `<ul><li>Enforce rate limits per IP/account.</li><li>Add CAPTCHA after repeated failures.</li>`
      + `<li>Require strong passwords and enable temporary lockouts.</li></ul>`,
  },
  "Broken Access Control": {
    title: "Broken Access Control",
    what: `Authorization checks are missing or inconsistent, allowing users to access data or actions beyond their role.`,
    how: `Attackers call privileged endpoints directly, manipulate IDs, or reuse references to view other tenants' data.`,
    prevention: `<ul><li>Enforce authorization on every request.</li><li>Adopt role-based access control.</li>`
      + `<li>Never rely on hidden UI elements to protect resources.</li></ul>`,
  },
  "Server-Side Request Forgery (SSRF)": {
    title: "Server-Side Request Forgery (SSRF)",
    what: `SSRF tricks the server into making HTTP requests to arbitrary URLs chosen by the attacker.`,
    how: `Abusing parameters such as <code>url=</code> the attacker targets internal services (169.254.169.254, localhost) and exfiltrates data.`,
    prevention: `<ul><li>Whitelist allowable destinations.</li><li>Block internal IP ranges.</li>`
      + `<li>Validate protocols and require https/http only.</li></ul>`,
  },
  "Insecure File Upload": {
    title: "Insecure File Upload",
    what: `Uploading files without strict validation lets attackers store malware or scripts on the server.`,
    how: `Malicious files (web shells, executables) are uploaded and then executed or served to other users.`,
    prevention: `<ul><li>Whitelist safe extensions and verify MIME types.</li><li>Inspect magic bytes.</li>`
      + `<li>Store uploads outside the web root and use random filenames.</li></ul>`,
  },
  "XML External Entity (XXE) Injection": {
    title: "XML External Entity (XXE) Injection",
    what: `XML parsers that allow external entities can be abused to read local files or pivot internally.`,
    how: `The attacker defines an external entity that references file:// or http:// resources; the parser fetches and returns the data.`,
    prevention: `<ul><li>Disable DTDs and external entity resolution.</li><li>Use hardened XML parsers.</li>`
      + `<li>Validate XML against schemas before processing.</li></ul>`,
  },
  "XML Injection": {
    title: "XML Injection",
    what: `Improperly sanitized XML input allows attackers to modify document structure or trigger parser bugs.`,
    how: `Injected nodes, attributes, or malformed entities change application logic or create denial-of-service payloads.`,
    prevention: `<ul><li>Validate XML syntax and structure.</li><li>Escape special characters in user input.</li>`
      + `<li>Limit parser features to only what is required.</li></ul>`,
  },
  "HTML Injection": {
    title: "HTML Injection",
    what: `Raw user input is rendered as HTML, allowing attackers to insert elements or scripts.`,
    how: `Attacker-supplied markup is reflected back to the page; browsers interpret it as part of the DOM.`,
    prevention: `<ul><li>HTML-encode untrusted content.</li><li>Sanitize input to strip disallowed tags.</li>`
      + `<li>Use a Content Security Policy.</li></ul>`,
  },
  "Insecure File Upload: PHP Script": {
    title: "Insecure File Upload: PHP Script",
    what: `Allowing PHP uploads means attackers can deploy web shells and execute arbitrary code.`,
    how: `The uploaded script is requested directly, running with the application's privileges.`,
    prevention: `Block executable file types, inspect file signatures, and keep uploads outside the document root.`,
  },
  "Insecure File Upload: Server Script": {
    title: "Insecure File Upload: Server Script",
    what: `Server-side script uploads (ASP, JSP) can take over the application server.`,
    how: `Files execute within the server runtime and can issue arbitrary commands.`,
    prevention: `Disallow script extensions and validate file content, not just the extension.`,
  },
  "Insecure File Upload: Executable": {
    title: "Insecure File Upload: Executable",
    what: `Binary executables can contain malware or be used for lateral movement.`,
    how: `Uploaded binaries may be downloaded by other users or executed by misconfigured services.`,
    prevention: `Reject executable MIME types and scan uploads with antivirus tooling.`,
  },
  "Insecure File Upload: Apache Configuration": {
    title: "Insecure File Upload: Apache Configuration",
    what: `Allowing .htaccess uploads lets attackers alter server behavior and enable script execution.`,
    how: `.htaccess directives can override PHP execution rules, rewrite traffic, or disable security headers.`,
    prevention: `Block configuration file extensions and manage Apache settings at the server level.`,
  },
  "Insecure File Upload: HTML/JavaScript": {
    title: "Insecure File Upload: HTML/JavaScript",
    what: `Uploaded HTML or JS files can host persistent XSS payloads accessible to other users.`,
    how: `Victims open the hostile HTML directly from your domain, trusting its origin.`,
    prevention: `Sanitize uploaded markup and serve it with Content Security Policy protections.`,
  },
  "Path Traversal in File Upload": {
    title: "Path Traversal in File Upload",
    what: `Filenames that contain ../ sequences can place files outside the intended directory.`,
    how: `Attackers craft filenames targeting sensitive paths to overwrite or create files elsewhere on the server.`,
    prevention: `Normalize and sanitize filenames, strip traversal sequences, and resolve absolute storage paths.`,
  },
  "Missing File Size Limits": {
    title: "Missing File Size Limits",
    what: `Unlimited uploads enable denial-of-service by exhausting disk or memory.`,
    how: `Large payloads tie up resources during upload and storage, affecting service availability.`,
    prevention: `Set strict client and server-side size caps and monitor upload volume.`,
  },
  "Content-Type Validation Bypass": {
    title: "Content-Type Validation Bypass",
    what: `Relying solely on the Content-Type header allows spoofed uploads of dangerous files.`,
    how: `Attackers send a malicious file but set Content-Type: image/png to bypass naive filters.`,
    prevention: `Inspect magic bytes or use libraries to determine actual file signatures.`,
  },
  "Directory Traversal in Uploaded Filename": {
    title: "Directory Traversal in Uploaded Filename",
    what: `Directory traversal in filenames stores uploads in unintended directories, often above the upload root.`,
    how: `Using ../../ sequences a malicious upload could overwrite configuration or executable files.`,
    prevention: `Strip traversal characters and store files using generated names in fixed directories.`,
  },
  "Command Injection (Unix)": {
    title: "Command Injection (Unix/Linux)",
    what: `User input reaches Unix shell commands allowing execution of arbitrary shell syntax.`,
    how: `Payloads append commands using ;, |, or && to leverage system utilities.`,
    prevention: `Avoid shell execution and prefer vetted APIs. If unavoidable, whitelist and escape arguments carefully.`,
  },
  "Command Injection (Windows)": {
    title: "Command Injection (Windows)",
    what: `Windows command shells invoked with untrusted input can execute arbitrary commands.`,
    how: `Attackers use & or | to concatenate commands such as reading sensitive files.`,
    prevention: `Avoid cmd.exe invocation and use structured APIs like ProcessBuilder equivalents with sanitized arguments.`,
  },
  "Command Injection (Time-based Blind)": {
    title: "Command Injection (Time-based Blind)",
    what: `Even when output is suppressed, attackers rely on timing (sleep) to confirm command execution.`,
    how: `Injected sleep statements delay responses, proving execution despite no direct output.`,
    prevention: `Never pass user input to shell commands; employ strict validation and sandbox execution contexts.`,
  },
  "Session ID in URL": {
    title: "Session ID in URL",
    what: `Putting session identifiers in query strings exposes them via logs, referrers, and browser history.`,
    how: `Anyone with access to URL logs or shared bookmarks can hijack the session.`,
    prevention: `Store session IDs in Secure, HttpOnly cookies and avoid URL-based session tracking.`,
  },
  "Insecure Cookie (Missing Secure Flag)": {
    title: "Insecure Cookie - Missing Secure Flag",
    what: `Session cookies without the Secure flag can be sent over HTTP, risking interception.`,
    how: `On mixed-content or misconfigured deployments cookies leak over plaintext requests.`,
    prevention: `Serve only over HTTPS and mark authentication cookies with the Secure attribute.`,
  },
  "Cookie Missing HttpOnly Flag": {
    title: "Cookie Missing HttpOnly Flag",
    what: `Without HttpOnly, JavaScript can read or modify session cookies during an XSS attack.`,
    how: `document.cookie leaks tokens to attacker-controlled scripts.`,
    prevention: `Set HttpOnly on all sensitive cookies so browsers block script access.`,
  },
};

chrome.runtime.onMessage.addListener((message) => {
  if (message.type === "scan_progress") {
    renderScanStatus(message.payload);
  }
  if (message.type === "auth_changed") {
    renderAuth(message.payload);
  }
});

init();

async function init() {
  openOptionsBtn.addEventListener("click", () => chrome.runtime.openOptionsPage());
  authSettingsBtn.addEventListener("click", () => chrome.runtime.openOptionsPage());
  logoutBtn.addEventListener("click", handleLogout);
  refreshHistoryBtn.addEventListener("click", refreshHistory);
  downloadJsonBtn.addEventListener("click", downloadResultAsJson);
  downloadMarkdownBtn.addEventListener("click", downloadResultAsMarkdown);
  prevVulnBtn.addEventListener("click", () => navigateVuln(-1));
  nextVulnBtn.addEventListener("click", () => navigateVuln(1));
  expandMinimizeBtn.addEventListener("click", toggleExpandMinimize);
  websiteViewBtn.addEventListener("click", () => switchView("website"));
  analystViewBtn.addEventListener("click", () => switchView("analyst"));
  scanForm.addEventListener("submit", submitScanForm);
  wireModeChips();
  await loadAuthState();
  await hydrateTargetContext();
  await refreshHistory();
}

async function loadAuthState() {
  const { data } = await callBackground("get_auth_state");
  renderAuth(data || {});
}

function renderAuth(state) {
  const signedIn = Boolean(state?.token);
  authStatus.textContent = signedIn ? `Signed in as ${state.email}` : "Signed out";
  if (authMessage) {
    authMessage.textContent = signedIn
      ? "You're ready to launch scans from the popup. Manage your credentials in settings."
      : "Open the settings page to sign in or create an account before running scans.";
  }
  authLockedSections.forEach((section) => toggleSection(section, signedIn));
  logoutBtn.classList.toggle("hidden", !signedIn);
}

function toggleSection(section, enabled) {
  section.classList.toggle("opacity-50", !enabled);
  section.classList.toggle("pointer-events-none", !enabled);
  section.querySelectorAll("input, select, textarea, button").forEach((control) => {
    control.disabled = !enabled;
  });
}

async function handleLogout() {
  await callBackground("logout");
  resultSection.classList.add("hidden");
  chrome.storage.local.remove(["floatingResult", "floatingUpdatedAt"]);
}

async function submitScanForm(event) {
  event.preventDefault();
  const formData = new FormData(scanForm);
  if (!currentTargetUrl) {
    toast("Active tab URL unavailable");
    return;
  }
  const payload = {
    url: currentTargetUrl,
    mode: formData.get("mode") || "standard",
    useJs: Boolean(formData.get("useJs")),
  };
  try {
    const { data } = await callBackground("start_scan", payload);
    renderScanStatus(data);
    toast("Scan started");
  } catch (error) {
    toast(error.message || "Unable to start scan");
  }
}

async function hydrateTargetContext() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (tab?.url) {
    activeTabId = tab.id || null;
    currentTargetUrl = tab.url;
    currentUrlBadge.textContent = new URL(tab.url).hostname;
  } else {
    activeTabId = null;
    currentUrlBadge.textContent = "Grant tab access";
  }
}

function wireModeChips() {
  updateModeChipState();
  modeChips.forEach((chip) => {
    chip.addEventListener("click", () => {
      const input = chip.querySelector("input");
      if (input) {
        input.checked = true;
        updateModeChipState();
      }
    });
  });
  scanForm.addEventListener("change", (event) => {
    if (event.target.name === "mode") {
      updateModeChipState();
    }
  });
}

function updateModeChipState() {
  modeChips.forEach((chip) => {
    const checked = chip.querySelector("input")?.checked;
    chip.classList.toggle("active", Boolean(checked));
  });
}

function switchView(mode = "website") {
  if (!websiteFindingsView || !analystViewPanel) {
    return;
  }
  if (mode === "analyst") {
    websiteFindingsView.classList.add("hidden");
    analystViewPanel.classList.remove("hidden");
    websiteViewBtn?.classList.remove("active");
    analystViewBtn?.classList.add("active");
  } else {
    analystViewPanel.classList.add("hidden");
    websiteFindingsView.classList.remove("hidden");
    analystViewBtn?.classList.remove("active");
    websiteViewBtn?.classList.add("active");
  }
}

async function refreshHistory() {
  try {
    const { data } = await callBackground("list_scans", { limit: 6 });
    const scans = await Promise.all((data || []).map(updateScanIfStale));
    renderHistory(scans);
  } catch (error) {
    toast("Cannot load history");
  }
}

async function updateScanIfStale(scan) {
  if (!scan) {
    return scan;
  }
  const status = (scan.status || "").toLowerCase();
  const terminal = ["completed", "failed", "cancelled", "error"]; // treat anything else as stale
  if (terminal.includes(status)) {
    return scan;
  }
  try {
    const { data } = await callBackground("fetch_status", { scanId: scan.scan_id });
    return data || scan;
  } catch (error) {
    return scan;
  }
}

function renderHistory(scans) {
  historyList.innerHTML = "";
  if (!scans.length) {
    const empty = document.createElement("p");
    empty.className = "text-xs text-slate-400";
    empty.textContent = "No recent scans yet.";
    historyList.appendChild(empty);
    return;
  }
  scans.forEach((scan) => {
    const entry = historyTemplate.content.cloneNode(true);
    entry.querySelector(".data-target").textContent = scan.target_url;
    const statusNode = entry.querySelector(".data-status");
    statusNode.textContent = formatStatus(scan.status);
    applyStatusTone(statusNode, scan.status);
    entry.querySelector(".data-mode").textContent = `${scan.mode} - ${scan.use_js ? "Playwright" : "HTTP"}`;
    entry.querySelector(".data-view").addEventListener("click", () => viewResult(scan.scan_id));
    historyList.appendChild(entry);
  });
}

async function viewResult(scanId) {
  try {
    const { data } = await callBackground("fetch_results", { scanId });
    latestResult = data;
    renderResult(data);
  } catch (error) {
    toast(error.message || "Result unavailable");
  }
}

function renderResult(result) {
  if (!result) {
    return;
  }

  latestResult = result;
  chrome.storage.local.set({ floatingResult: latestResult, floatingUpdatedAt: Date.now() });

  const findings = result.findings || [];
  const totalCount = resolveTotalFindings(result, findings);
  const severityCounts = normalizeSeverityCounts(result, findings);
  const metrics = computeEnhancedMetrics(findings);
  const completedAt = result.completed_at ? new Date(result.completed_at).toLocaleString() : "Processing";
  const runMeta = [
    result.mode ? `Mode: ${escapeHTML(String(result.mode).toUpperCase())}` : null,
    result.use_js ? "Playwright" : "HTTP",
    result.scan_id ? `Scan ${escapeHTML(String(result.scan_id))}` : null,
  ]
    .filter(Boolean)
    .join(" - ");
  const targetDisplay = escapeHTML(result.target_url || currentTargetUrl || "Unknown target");

  totalVulnsEl.textContent = totalCount;
  highVulnsEl.textContent = severityCounts.high + severityCounts.critical;
  mediumVulnsEl.textContent = severityCounts.medium;
  lowVulnsEl.textContent = severityCounts.low;

  avgCvssEl.textContent = metrics.avgCvss;
  criticalPriorityEl.textContent = metrics.criticalPriority;
  withExploitEl.textContent = metrics.withExploit;
  highConfidenceEl.textContent = metrics.highConfidence;
  enhancedMetrics.classList.toggle("hidden", !metrics.hasCvss);

  resultSummary.innerHTML = `
    <div class="text-xs text-slate-400 uppercase tracking-wide">Target</div>
    <p class="text-base font-semibold text-white">${targetDisplay}</p>
    <div class="text-xs text-slate-400 uppercase tracking-wide mt-3">Completed</div>
    <p class="text-sm text-slate-200">${completedAt}</p>
    <div class="text-xs text-slate-400 uppercase tracking-wide mt-3">Run details</div>
    <p class="text-sm text-slate-200">${runMeta || "Cloud scan"}</p>
  `;

  renderSeverityBadges(severityCounts);
  renderWebsiteFindings(findings, result);
  renderAnalystView(findings);
  switchView("website");

  if (allVulnGroups.length) {
    requestAnimationFrame(() => {
      const firstGroup = allVulnGroups[0];
      showVulnerabilityDetail(firstGroup, 0, groupedFindings[firstGroup]);
    });
  } else {
    detailContent.innerHTML = '<div class="text-slate-400 text-sm">No vulnerability details available for this scan.</div>';
  }

  broadcastFindings(result).catch((error) => {
    console.warn("Unable to relay findings to page", error);
  });
}

async function resolveActiveTabId() {
  if (activeTabId) {
    return activeTabId;
  }
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  activeTabId = tab?.id || null;
  return activeTabId;
}

function severityColor(level) {
  switch ((level || "").toLowerCase()) {
    case "critical":
      return "critical";
    case "high":
      return "high";
    case "medium":
      return "medium";
    case "low":
      return "low";
    default:
      return "info";
  }
}

function resolveTotalFindings(result, findings) {
  if (typeof result?.total_vulnerabilities === "number") {
    return result.total_vulnerabilities;
  }
  if (typeof result?.total_findings === "number") {
    return result.total_findings;
  }
  return findings.length;
}

function normalizeSeverityCounts(result, findings = []) {
  const counts = { critical: 0, high: 0, medium: 0, low: 0 };
  const source = result?.vulnerabilities_by_severity || result?.severity_counts || {};
  Object.entries(source).forEach(([key, value]) => {
    const normalized = key.toLowerCase();
    if (counts[normalized] !== undefined) {
      counts[normalized] = Number(value) || 0;
    }
  });
  if (!Object.values(counts).some(Boolean) && findings.length) {
    findings.forEach((finding) => {
      const severity = (finding?.severity || "low").toLowerCase();
      if (counts[severity] !== undefined) {
        counts[severity] += 1;
      }
    });
  }
  return counts;
}

function computeEnhancedMetrics(findings = []) {
  let totalCvss = 0;
  let cvssCount = 0;
  let criticalPriority = 0;
  let withExploit = 0;
  let highConfidence = 0;

  findings.forEach((finding) => {
    const baseScore = parseScore(finding?.cvss_base_score);
    if (baseScore !== null) {
      totalCvss += baseScore;
      cvssCount += 1;
    }
    if ((finding?.final_priority || "").toLowerCase() === "critical") {
      criticalPriority += 1;
    }
    if (finding?.exploit_published) {
      withExploit += 1;
    }
    if (typeof finding?.confidence === "number" && finding.confidence >= 0.8) {
      highConfidence += 1;
    }
  });

  return {
    avgCvss: cvssCount ? (totalCvss / cvssCount).toFixed(1) : "0.0",
    criticalPriority,
    withExploit,
    highConfidence,
    hasCvss: cvssCount > 0,
  };
}

function renderSeverityBadges(counts) {
  severityBadges.innerHTML = "";
  Object.entries(counts).forEach(([key, value]) => {
    const badge = document.createElement("span");
    badge.className = `severity-pill badge-${severityColor(key)}`;
    badge.textContent = `${key.charAt(0).toUpperCase() + key.slice(1)}: ${value}`;
    severityBadges.appendChild(badge);
  });
}

async function broadcastFindings(result) {
  if (!result) {
    return;
  }
  const tabId = await resolveActiveTabId();
  if (!tabId) {
    return;
  }
  const findings = Array.isArray(result.findings) ? result.findings : [];
  const target = result.target_url || currentTargetUrl || "Unknown target";
  chrome.tabs.sendMessage(tabId, { type: "render_findings", payload: { target, findings } });
}

function renderScanStatus(status) {
  if (!status) return;
  scanStatus.textContent = `${formatStatus(status.status)} - ${status.progress}% - ${status.message}`;
  applyStatusTone(scanStatus, status.status);
}

function toast(message) {
  scanStatus.textContent = message;
  applyStatusTone(scanStatus, "info");
}

function callBackground(type, payload) {
  return new Promise((resolve, reject) => {
    chrome.runtime.sendMessage({ type, payload }, (response) => {
      if (chrome.runtime.lastError) {
        reject(new Error(chrome.runtime.lastError.message));
        return;
      }
      if (!response) {
        reject(new Error("No response"));
        return;
      }
      if (!response.ok) {
        reject(new Error(response.error || "Request failed"));
        return;
      }
      resolve(response);
    });
  });
}

function applyStatusTone(node, status) {
  if (!node) return;
  STATUS_VARIANTS.forEach((cls) => node.classList.remove(cls));
  const tone = statusClass(status);
  if (tone) {
    node.classList.add(tone);
  }
}

function statusClass(status) {
  const normalized = (status || "").toLowerCase();
  if (["completed", "ready", "done", "success"].includes(normalized)) {
    return "status-pill-success";
  }
  if (["failed", "error", "cancelled"].includes(normalized)) {
    return "status-pill-danger";
  }
  if (["running", "in_progress", "queued", "pending"].includes(normalized)) {
    return "status-pill-warn";
  }
  return "status-pill-info";
}

function formatStatus(status) {
  const normalized = (status || "").toLowerCase().replace(/_/g, " ");
  return normalized.replace(/(^|\s)\S/g, (match) => match.toUpperCase()) || "Unknown";
}

function renderWebsiteFindings(findings, result) {
  if (!websiteFindingsView) return;
  if (!findings || findings.length === 0) {
    websiteFindingsView.innerHTML = '<div class="text-center p-4 text-slate-400"><p>No vulnerabilities detected for this target.</p></div>';
    return;
  }

  const targetDisplay = escapeHTML(result.target_url || 'Scanned Target');
  const modeDisplay = escapeHTML(String(result.mode || 'Unknown').toUpperCase());
  const severitySummary = findings.reduce((acc, item) => {
    const key = (item.severity || 'Info').toLowerCase();
    acc[key] = (acc[key] || 0) + 1;
    return acc;
  }, {});
  const summaryChips = ['critical', 'high', 'medium', 'low'].map(level => {
    if (!severitySummary[level]) return '';
    return `<span class="website-tag">${level.charAt(0).toUpperCase() + level.slice(1)}: ${severitySummary[level]}</span>`;
  }).join('');

  const cardsHtml = findings.map((finding, idx) => renderWebsiteFindingCard(finding, idx)).join('');
  websiteFindingsView.innerHTML = `
    <div class="website-findings-header">
      <div>
        <small>Findings (${findings.length})</small>
        <h4>${targetDisplay}</h4>
        <div class="text-slate-400">Mode: ${modeDisplay}</div>
      </div>
      <div class="text-right">
        ${summaryChips || '<span class="text-slate-400">Awaiting severity breakdown...</span>'}
      </div>
    </div>
    <div class="website-findings-cards">
      ${cardsHtml}
    </div>
  `;
}

function renderWebsiteFindingCard(finding, index) {
  const severity = finding.severity || 'Info';
  const severityClass = websiteSeverityClass(severity);
  const cvssScore = parseScore(finding.cvss_base_score ?? finding.cvss_score);
  const confidenceLabel = formatConfidence(finding.confidence);
  const details = [];
  
  details.push(`
    <div class="detail-block">
      <small>Endpoint</small>
      <code>${escapeHTML(finding.url || 'N/A')}</code>
    </div>
  `);
  details.push(`
    <div class="detail-block">
      <small>Description</small>
      <p>${escapeHTML(finding.description || 'No description available.')}</p>
    </div>
  `);
  if (finding.payload) {
    details.push(`
      <div class="detail-block">
        <small>Payload</small>
        <code>${escapeHTML(finding.payload)}</code>
      </div>
    `);
  }
  if (finding.evidence) {
    details.push(`
      <div class="detail-block">
        <small>Evidence</small>
        <p>${escapeHTML(truncateText(finding.evidence, 150))}</p>
      </div>
    `);
  }
  if (finding.recommendation) {
    details.push(`
      <div class="detail-block">
        <small>Recommendation</small>
        <p>${escapeHTML(truncateText(finding.recommendation, 150))}</p>
      </div>
    `);
  }
  if (cvssScore !== null) {
    details.push(`
      <div class="detail-block">
        <small>CVSS Score</small>
        <p class="mb-1">${cvssScore.toFixed(1)}</p>
        ${finding.cvss_vector ? `<code>${escapeHTML(finding.cvss_vector)}</code>` : ''}
      </div>
    `);
  }
  if (finding.cwe) {
    details.push(`
      <div class="detail-block">
        <small>CWE</small>
        <code>${escapeHTML(finding.cwe)}</code>
      </div>
    `);
  }

  const tags = [];
  if (finding.final_priority) {
    tags.push(`<span class="website-tag">Priority: ${escapeHTML(finding.final_priority)}</span>`);
  }
  if (finding.asset_criticality) {
    tags.push(`<span class="website-tag">Asset: ${escapeHTML(String(finding.asset_criticality))}</span>`);
  }
  if (finding.exploit_published) {
    tags.push('<span class="website-tag">Known Exploit</span>');
  }
  if (finding.occurrences && finding.occurrences > 1) {
    tags.push(`<span class="website-tag">${finding.occurrences} detections</span>`);
  }

  return `
    <div class="website-finding-card">
      <div class="website-finding-header">
        <div>
          <small class="text-slate-400">Finding #${index + 1}</small>
          <h5>${escapeHTML(finding.vulnerability || 'Unnamed Finding')}</h5>
          <div class="website-finding-meta">
            ${escapeHTML(severity)} - ${escapeHTML(confidenceLabel)}${cvssScore !== null ? ` - CVSS ${cvssScore.toFixed(1)}` : ''}
          </div>
        </div>
        <span class="website-badge ${severityClass}">${escapeHTML(severity)}</span>
      </div>
      <div class="website-finding-body">
        ${details.join('')}
      </div>
      ${tags.length ? `<div class="website-tag-row">${tags.join('')}</div>` : ''}
    </div>
  `;
}

function websiteSeverityClass(severity = '') {
  const normalized = severity.toLowerCase();
  if (normalized === 'critical' || normalized === 'high') return 'high';
  if (normalized === 'medium') return 'medium';
  if (normalized === 'low') return 'low';
  return 'info';
}

function parseScore(value) {
  if (typeof value === 'number') return value;
  if (typeof value === 'string' && value.trim() !== '') {
    const parsed = parseFloat(value);
    return isNaN(parsed) ? null : parsed;
  }
  return null;
}

function truncateText(text, limit = 150) {
  if (!text) return '';
  if (text.length <= limit) return text;
  return `${text.substring(0, limit)}...`;
}

function formatConfidence(confidence) {
  if (typeof confidence === 'number') {
    return `${(confidence * 100).toFixed(0)}% confidence`;
  }
  if (typeof confidence === 'string' && confidence.trim() !== '') {
    return confidence;
  }
  return 'Confidence N/A';
}

function escapeHTML(text) {
  const div = document.createElement('div');
  div.textContent = text || '';
  return div.innerHTML;
}

function renderAnalystView(findings = []) {
  groupedFindings = {};
  allVulnGroups = [];
  vulnerabilityAccordion.innerHTML = '';

  if (!findings.length) {
    vulnerabilityAccordion.innerHTML = '<div class="text-center text-slate-400 py-6">No vulnerabilities were detected during this scan.</div>';
    detailContent.innerHTML = '<div class="text-slate-400 text-sm">Select a scan result to view its analyst breakdown.</div>';
    return;
  }

  groupedFindings = findings.reduce((acc, finding) => {
    const key = finding.vulnerability || 'Unnamed Finding';
    if (!acc[key]) {
      acc[key] = [];
    }
    acc[key].push(finding);
    return acc;
  }, {});

  allVulnGroups = Object.keys(groupedFindings);
  const fragment = document.createDocumentFragment();

  allVulnGroups.forEach((groupName, index) => {
    const groupItems = groupedFindings[groupName];
    const firstItem = groupItems[0];
    const severity = firstItem.severity || 'Info';
    const severityClass = `badge-${severityToBadge(severity)}`;
    const payloadPreview = firstItem.payload ? `${firstItem.payload.slice(0, 48)}${firstItem.payload.length > 48 ? '...' : ''}` : null;
    const urlPreview = firstItem.url ? `${firstItem.url.slice(0, 70)}${firstItem.url.length > 70 ? '...' : ''}` : 'Unknown URL';

    const listItem = document.createElement('div');
    listItem.className = 'vuln-list-item';
    listItem.dataset.group = groupName;
    listItem.dataset.index = String(index);
    listItem.innerHTML = `
      <div class="flex justify-between gap-3">
        <div class="flex-1">
          <div class="flex items-center gap-2 mb-2">
            <span class="badge ${severityClass}">${escapeHTML(severity)}</span>
            <h6 class="text-sm text-white font-semibold">${escapeHTML(groupName)}</h6>
            <span class="badge badge-secondary">${groupItems.length}</span>
          </div>
          ${payloadPreview ? `<div class="text-xs text-slate-400 mb-1">Payload: <code>${escapeHTML(payloadPreview)}</code></div>` : ''}
          <div class="text-xs text-slate-400">${escapeHTML(urlPreview)}</div>
        </div>
        <div class="text-right text-xs text-slate-400">
          ${firstItem.cvss_base_score ? `<div class="mb-1"><span class="badge badge-danger">CVSS ${Number(firstItem.cvss_base_score).toFixed(1)}</span></div>` : ''}
          ${firstItem.final_priority ? `<div class="mb-1"><span class="badge badge-${severityToBadge(firstItem.final_priority)}">${escapeHTML(firstItem.final_priority)}</span></div>` : ''}
          ${typeof firstItem.confidence === 'number' ? `<div><span class="badge badge-info">${(firstItem.confidence * 100).toFixed(0)}%</span></div>` : ''}
        </div>
      </div>
    `;
    listItem.addEventListener('click', () => showVulnerabilityDetail(groupName, index, groupItems));
    fragment.appendChild(listItem);
  });

  vulnerabilityAccordion.appendChild(fragment);
}

function showVulnerabilityDetail(groupName, index, groupItems) {
  if (!groupItems || !groupItems.length) {
    return;
  }

  const vulnerabilityInfo = vulnerabilityDB[groupName] || { title: groupName, what: 'No description available.', how: '', prevention: '' };

  currentVulnIndex = Number(index);
  allVulnGroups = Object.keys(groupedFindings);

  document.querySelectorAll('.vuln-list-item').forEach((item) => {
    item.classList.toggle('active', item.dataset.index === String(index));
  });

  detailPanel.classList.add('active');
  if (detailPanel.classList.contains('full-mode')) {
    listPanel.classList.add('hidden');
    listPanel.classList.remove('split-mode');
  } else {
    listPanel.classList.add('split-mode');
    listPanel.classList.remove('hidden');
  }
  updateNavButtons();

  const primary = groupItems[0];
  const severity = (primary.severity || 'Info').toLowerCase();
  const title = vulnerabilityInfo.title || groupName;
  const totalOccurrences = groupItems.reduce((sum, item) => sum + (item.occurrences || 1), 0);
  const uniqueEndpoints = groupItems.length;
  const scanners = uniqueList(groupItems.map((item) => item.scanners));
  const payloadSamples = groupItems.map((item) => item.payload).filter(Boolean).slice(0, 4);
  const evidenceSamples = groupItems.map((item) => item.evidence || item.evidence_merged).filter(Boolean).slice(0, 2);
  const descriptionHtml = formatMultiLine(primary.description) || vulnerabilityInfo.what;
  const recommendationHtml = formatMultiLine(primary.recommendation) || vulnerabilityInfo.prevention;
  const evidenceHtml = formatMultiLine(primary.evidence || primary.evidence_merged || vulnerabilityInfo.how);
  const confidenceLabel = formatConfidenceValue(primary.confidence) || 'Unknown';

  const metaChips = [];
  metaChips.push(`<span class="meta-chip"><i class="fas fa-bullseye"></i> ${uniqueEndpoints} endpoint${uniqueEndpoints === 1 ? '' : 's'}</span>`);
  metaChips.push(`<span class="meta-chip"><i class="fas fa-layer-group"></i> ${totalOccurrences} hit${totalOccurrences === 1 ? '' : 's'}</span>`);
  if (primary.cvss_base_score) {
    metaChips.push(`<span class="meta-chip"><i class="fas fa-thermometer-half"></i> CVSS ${Number(primary.cvss_base_score).toFixed(1)}</span>`);
  }
  if (primary.final_priority) {
    metaChips.push(`<span class="meta-chip"><i class="fas fa-flag"></i> ${escapeHTML(primary.final_priority)}</span>`);
  }
  if (primary.cwe) {
    metaChips.push(`<span class="meta-chip"><i class="fas fa-code"></i> ${escapeHTML(primary.cwe)}</span>`);
  }
  if (scanners.length) {
    metaChips.push(`<span class="meta-chip"><i class="fas fa-robot"></i> ${escapeHTML(scanners.join(', '))}</span>`);
  }

  detailContent.innerHTML = `
    <div class="vuln-details">
      <div class="flex flex-wrap items-center gap-3 mb-3">
        <h4 class="text-lg font-semibold text-white flex items-center gap-2">
          <span class="badge badge-${severityToBadge(primary.severity)}">${escapeHTML(primary.severity || 'Info')}</span>
          ${escapeHTML(title)}
        </h4>
        <span class="text-slate-400 text-sm">${escapeHTML(groupName)}</span>
      </div>
      <div class="detail-meta-chips">${metaChips.join('')}</div>
      <div class="grid grid-cols-2 gap-3 mb-4">
        <div class="mini-stat">
          <div class="label">Confidence</div>
          <div class="value">${escapeHTML(confidenceLabel)}</div>
        </div>
        <div class="mini-stat">
          <div class="label">Occurrences</div>
          <div class="value">${totalOccurrences}</div>
        </div>
        <div class="mini-stat">
          <div class="label">Endpoints</div>
          <div class="value">${uniqueEndpoints}</div>
        </div>
        <div class="mini-stat">
          <div class="label">Exploit</div>
          <div class="value">${primary.exploit_published ? 'Available' : 'Unknown'}</div>
        </div>
      </div>
      <div class="mb-4">
        <h5 class="text-slate-100 font-semibold mb-1"><i class="fas fa-info-circle"></i> What We Found</h5>
        <div class="text-slate-300 text-sm">${descriptionHtml || 'No description provided.'}</div>
      </div>
      <div class="mb-4">
        <h5 class="text-slate-100 font-semibold mb-1"><i class="fas fa-microscope"></i> Evidence & Trigger</h5>
        <div class="text-slate-300 text-sm mb-2">${evidenceHtml || 'Scanner did not record supporting evidence.'}</div>
        ${payloadSamples.length ? `<div class="flex flex-wrap gap-2">${payloadSamples
          .map((payload) => `<span class="payload-pill"><code>${escapeHTML(payload)}</code></span>`)
          .join('')}</div>` : ''}
        ${evidenceSamples.length ? `<div class="text-slate-400 text-xs mt-2">${evidenceSamples
          .map((sample) => `<div class="mb-1"><code>${escapeHTML(sample)}</code></div>`)
          .join('')}</div>` : ''}
      </div>
      <div class="mb-4">
        <h5 class="text-slate-100 font-semibold mb-1"><i class="fas fa-shield-alt"></i> Recommended Fix</h5>
        <div class="text-slate-300 text-sm">${recommendationHtml || 'Follow standard remediation guidance for this vulnerability type.'}</div>
      </div>
      <div class="mb-4">
        <h5 class="text-slate-100 font-semibold mb-1"><i class="fas fa-map-marker-alt"></i> Affected Locations (${groupItems.length})</h5>
        <div style="max-height: 320px; overflow-y: auto;">${groupItems.map((item) => renderAffectedLocationCard(item)).join('')}</div>
      </div>
    </div>
  `;
}

function navigateVuln(direction) {
  const nextIndex = currentVulnIndex + direction;
  if (nextIndex < 0 || nextIndex >= allVulnGroups.length) {
    return;
  }
  const groupName = allVulnGroups[nextIndex];
  showVulnerabilityDetail(groupName, nextIndex, groupedFindings[groupName]);
}

function toggleExpandMinimize() {
  const isFullMode = detailPanel.classList.toggle('full-mode');
  if (isFullMode) {
    listPanel.classList.add('hidden');
    listPanel.classList.remove('split-mode');
    expandMinimizeBtn.textContent = 'Minimize';
    expandMinimizeBtn.title = 'Minimize';
  } else {
    listPanel.classList.remove('hidden');
    listPanel.classList.add('split-mode');
    expandMinimizeBtn.textContent = 'Expand';
    expandMinimizeBtn.title = 'Expand';
  }
  updateNavButtons();
}

function updateNavButtons() {
  const inFullMode = detailPanel.classList.contains('full-mode');
  prevVulnBtn.classList.toggle('hidden', !inFullMode || currentVulnIndex === 0);
  nextVulnBtn.classList.toggle('hidden', !inFullMode || currentVulnIndex >= allVulnGroups.length - 1);
}

function renderAffectedLocationCard(item) {
  const badges = [];
  if (item.asset_criticality) {
    const tone = item.asset_criticality >= 8 ? 'badge-danger' : item.asset_criticality >= 6 ? 'badge-warning' : 'badge-secondary';
    badges.push(`<span class="badge ${tone}">Asset ${item.asset_criticality}/10</span>`);
  }
  const confidenceBadge = formatConfidenceValue(item.confidence);
  if (confidenceBadge) {
    badges.push(`<span class="badge badge-info">${escapeHTML(confidenceBadge)}</span>`);
  }
  if (item.occurrences > 1) {
    badges.push(`<span class="badge badge-warning">${item.occurrences} detections</span>`);
  }
  if (item.cwe) {
    badges.push(`<span class="badge badge-secondary">${escapeHTML(item.cwe)}</span>`);
  }

  return `
    <div class="affected-card">
      <div class="flex justify-between gap-3 mb-2">
        <div class="flex-1">
          <div class="text-xs text-slate-400">Endpoint</div>
          <code>${escapeHTML(item.url || 'Unknown URL')}</code>
        </div>
        <div class="text-right text-xs text-slate-400">
          ${item.cvss_base_score ? `<div><span class="badge badge-danger">${Number(item.cvss_base_score).toFixed(1)}</span></div>` : ''}
          ${item.final_priority ? `<div><span class="badge badge-${severityToBadge(item.final_priority)}">${escapeHTML(item.final_priority)}</span></div>` : ''}
        </div>
      </div>
      ${badges.length ? `<div class="flex flex-wrap gap-2 mb-2">${badges.join('')}</div>` : ''}
      ${item.payload ? `<div class="mb-2"><strong class="text-xs text-slate-400">Payload</strong><code>${escapeHTML(item.payload)}</code></div>` : ''}
      ${(item.evidence || item.evidence_merged) ? `<div class="mb-2"><strong class="text-xs text-slate-400">Evidence</strong><code>${escapeHTML(item.evidence || item.evidence_merged)}</code></div>` : ''}
      ${item.description ? `<p class="text-xs text-slate-300 mb-0">${escapeHTML(item.description)}</p>` : ''}
    </div>
  `;
}

function formatConfidenceValue(confidence) {
  if (confidence === null || confidence === undefined) {
    return null;
  }
  if (typeof confidence === 'number') {
    return `${(confidence * 100).toFixed(0)}%`;
  }
  return `${confidence}`;
}

function formatMultiLine(value) {
  if (!value) {
    return '';
  }
  return escapeHTML(value).replace(/\n/g, '<br>');
}

function uniqueList(values = []) {
  return [...new Set(values.filter(Boolean).map((value) => (typeof value === 'string' ? value.trim() : value)))].filter(Boolean);
}

function severityToBadge(severity = '') {
  const normalized = severity.toLowerCase();
  if (normalized === 'critical') {
    return 'critical';
  }
  if (normalized === 'high') {
    return 'high';
  }
  if (normalized === 'medium') {
    return 'medium';
  }
  if (normalized === 'low') {
    return 'low';
  }
  return 'info';
}

function downloadResultAsJson() {
  if (!latestResult) {
    toast('View a scan result first');
    return;
  }
  const blob = new Blob([JSON.stringify(latestResult, null, 2)], { type: 'application/json' });
  const filename = `scan_${latestResult.scan_id || Date.now()}.json`;
  const url = URL.createObjectURL(blob);
  chrome.downloads.download({ url, filename, saveAs: true }, () => {
    setTimeout(() => URL.revokeObjectURL(url), 4000);
  });
}

function downloadResultAsMarkdown() {
  if (!latestResult) {
    toast('View a scan result first');
    return;
  }
  const markdown = buildMarkdownReport(latestResult);
  const blob = new Blob([markdown], { type: 'text/markdown' });
  const filename = `scan_${latestResult.scan_id || Date.now()}.md`;
  const url = URL.createObjectURL(blob);
  chrome.downloads.download({ url, filename, saveAs: true }, () => {
    setTimeout(() => URL.revokeObjectURL(url), 4000);
  });
}

function buildMarkdownReport(result) {
  const findings = result.findings || [];
  const lines = [];
  lines.push('# Vanguard Scan Result');
  lines.push('');
  lines.push(`- Target: ${result.target_url || 'Unknown target'}`);
  lines.push(`- Completed: ${result.completed_at ? new Date(result.completed_at).toLocaleString() : 'Processing'}`);
  lines.push(`- Mode: ${result.mode || 'standard'} ${result.use_js ? '(Playwright)' : '(HTTP)'}`);
  lines.push(`- Total Findings: ${resolveTotalFindings(result, findings)}`);
  lines.push('');
  if (!findings.length) {
    lines.push('No vulnerabilities were reported for this scan.');
    return lines.join('\n');
  }
  lines.push('## Findings');
  lines.push('');
  findings.forEach((finding, index) => {
    lines.push(`### ${index + 1}. ${finding.vulnerability || 'Unnamed Finding'}`);
    lines.push(`- Severity: ${finding.severity || 'Info'}`);
    if (finding.cvss_base_score) {
      lines.push(`- CVSS: ${Number(finding.cvss_base_score).toFixed(1)}`);
    }
    if (finding.final_priority) {
      lines.push(`- Priority: ${finding.final_priority}`);
    }
    if (finding.url) {
      lines.push(`- Endpoint: ${finding.url}`);
    }
    if (finding.cwe) {
      lines.push(`- CWE: ${finding.cwe}`);
    }
    if (finding.description) {
      lines.push('');
      lines.push('**What We Found**');
      lines.push('');
      lines.push(finding.description);
    }
    if (finding.evidence || finding.evidence_merged) {
      lines.push('');
      lines.push('**Evidence**');
      lines.push('');
      lines.push(finding.evidence || finding.evidence_merged);
    }
    if (finding.recommendation) {
      lines.push('');
      lines.push('**Recommendation**');
      lines.push('');
      lines.push(finding.recommendation);
    }
    if (finding.payload) {
      lines.push('');
      lines.push('**Payload**');
      lines.push('');
      lines.push('```');
      lines.push(finding.payload);
      lines.push('```');
    }
    lines.push('');
  });
  return lines.join('\n');
}
