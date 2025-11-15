const authForm = document.getElementById("authForm");
const registerBtn = document.getElementById("registerBtn");
const logoutBtn = document.getElementById("logoutBtn");
const authStatus = document.getElementById("authStatus");
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

  await loadAuthState();
  await hydrateTargetContext();
  wireModeChips();
  await refreshHistory();
}

async function loadAuthState() {
  const { data } = await callBackground("get_auth_state");
  renderAuth(data || {});
}

function renderAuth(state) {
  const signedIn = Boolean(state?.token);
  authStatus.textContent = signedIn ? `Signed in as ${state.email}` : "Signed out";
  toggleSection(scanSection, signedIn);
  logoutBtn.classList.toggle("hidden", !signedIn);
}

function toggleSection(section, enabled) {
  section.classList.toggle("opacity-50", !enabled);
  section.classList.toggle("pointer-events-none", !enabled);
}

authForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const formData = new FormData(authForm);
  const payload = {
    email: formData.get("email"),
    password: formData.get("password"),
  };
  try {
    await callBackground("login", payload);
    authForm.reset();
  } catch (error) {
    toast(error.message || "Unable to login");
  }
});

registerBtn.addEventListener("click", async () => {
  const formData = new FormData(authForm);
  const payload = {
    email: formData.get("email"),
    password: formData.get("password"),
  };
  try {
    await callBackground("register", payload);
    toast("Registration successful. You can sign in now.");
  } catch (error) {
    toast(error.message || "Registration failed");
  }
});

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

async function refreshHistory() {
  try {
    const { data } = await callBackground("list_scans", { limit: 6 });
    renderHistory(data || []);
  } catch (error) {
    toast("Cannot load history");
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
