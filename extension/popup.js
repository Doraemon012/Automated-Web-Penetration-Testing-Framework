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
const downloadBtn = document.getElementById("downloadReport");
const refreshHistoryBtn = document.getElementById("refreshHistory");
const openOptionsBtn = document.getElementById("openOptions");
const currentUrlBadge = document.getElementById("currentUrl");
const modeChips = document.querySelectorAll(".mode-chip");
const authLockedSections = document.querySelectorAll("[data-auth-locked]");
const websiteViewBtn = document.getElementById("website-view-btn");
const summaryViewBtn = document.getElementById("summary-view-btn");
const summaryView = document.getElementById("summaryView");
const websiteFindingsView = document.getElementById("websiteFindingsView");
const STATUS_VARIANTS = ["status-pill-success", "status-pill-warn", "status-pill-danger", "status-pill-info"];
let currentTargetUrl = null;

let latestResult = null;

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
  openOptionsBtn.addEventListener("click", () => {
    chrome.runtime.openOptionsPage();
  });
  authSettingsBtn.addEventListener("click", () => {
    chrome.runtime.openOptionsPage();
  });

  await loadAuthState();
  await hydrateTargetContext();
  wireModeChips();
  wireViewToggle();
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

logoutBtn.addEventListener("click", async () => {
  await callBackground("logout");
  resultSection.classList.add("hidden");
});

scanForm.addEventListener("submit", async (event) => {
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
});

refreshHistoryBtn.addEventListener("click", async () => {
  await refreshHistory();
});

downloadBtn.addEventListener("click", () => {
  if (!latestResult) return;
  const blob = new Blob([JSON.stringify(latestResult, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  chrome.downloads.download({ url, filename: `scan_${latestResult.scan_id}.json`, saveAs: true });
  setTimeout(() => URL.revokeObjectURL(url), 5000);
});

async function hydrateTargetContext() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (tab?.url) {
    currentTargetUrl = tab.url;
    currentUrlBadge.textContent = new URL(tab.url).hostname;
  } else {
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

function wireViewToggle() {
  websiteViewBtn?.addEventListener('click', () => switchView('website'));
  summaryViewBtn?.addEventListener('click', () => switchView('summary'));
}

function switchView(viewMode) {
  if (viewMode === 'summary') {
    websiteFindingsView.style.display = 'none';
    summaryView.style.display = 'block';
    summaryViewBtn.classList.add('active');
    websiteViewBtn.classList.remove('active');
  } else {
    summaryView.style.display = 'none';
    websiteFindingsView.style.display = 'flex';
    websiteViewBtn.classList.add('active');
    summaryViewBtn.classList.remove('active');
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
    entry.querySelector(".data-mode").textContent = `${scan.mode} • ${scan.use_js ? "Playwright" : "HTTP"}`;
    entry.querySelector(".data-view").addEventListener("click", () => viewResult(scan.scan_id));
    historyList.appendChild(entry);
  });
}

async function viewResult(scanId) {
  try {
    const { data } = await callBackground("fetch_results", { scanId });
    latestResult = data;
    renderResult(data);
    await broadcastFindings(data);
  } catch (error) {
    toast(error.message || "Result unavailable");
  }
}

function renderResult(result) {
  if (!result) return;
  resultSection.classList.remove("hidden");
  console.log("renderResult called with:", result); // Debug log
  const completed = result.completed_at
    ? new Date(result.completed_at).toLocaleString()
    : "Processing";
  resultSummary.innerHTML = `
    <div class="text-xs text-slate-400 uppercase tracking-wide">Target</div>
    <p class="text-base font-semibold text-white">${result.target_url}</p>
    <div class="text-xs text-slate-400 uppercase tracking-wide mt-2">Run details</div>
    <p>${completed} • ${result.mode} • ${result.use_js ? "Playwright" : "HTTP"} mode</p>
    <div class="text-xs text-slate-400 uppercase tracking-wide mt-2">Findings</div>
    <p class="text-lg font-semibold">${result.total_findings ?? 0}</p>
  `;
  severityBadges.innerHTML = "";
  Object.entries(result.severity_counts || {}).forEach(([key, value]) => {
    const badge = document.createElement("span");
    badge.className = `severity-pill badge-${severityColor(key)}`;
    badge.textContent = `${key}: ${value}`;
    severityBadges.appendChild(badge);
  });
  console.log("About to call renderWebsiteFindings with findings:", result.findings); // Debug log
  renderWebsiteFindings(result.findings || [], result);
  switchView('website');
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

async function broadcastFindings(result) {
  const findings = (result.findings || []).slice(0, 50);
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab?.id) return;
  chrome.tabs.sendMessage(tab.id, { type: "render_findings", payload: { target: result.target_url, findings } });
}

function renderScanStatus(status) {
  if (!status) return;
  scanStatus.textContent = `${formatStatus(status.status)} • ${status.progress}% • ${status.message}`;
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
  console.log("renderWebsiteFindings called", { findings, result, websiteFindingsView }); // Debug log
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
            ${escapeHTML(severity)} • ${escapeHTML(confidenceLabel)}${cvssScore !== null ? ` • CVSS ${cvssScore.toFixed(1)}` : ''}
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
