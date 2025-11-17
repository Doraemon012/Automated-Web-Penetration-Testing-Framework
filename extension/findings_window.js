const floatingPanel = document.getElementById("floatingPanel");
const floatingHandle = document.getElementById("floatingHandle");
const floatingTarget = document.getElementById("floatingTarget");
const floatingSummary = document.getElementById("floatingSummary");
const floatingFindings = document.getElementById("floatingFindings");
const floatingBody = document.getElementById("floatingBody");
const pinFloatingBtn = document.getElementById("pinFloating");
const minFloatingBtn = document.getElementById("minFloating");
const closeFloatingBtn = document.getElementById("closeFloating");

let isPinned = false;
let isCollapsed = false;
let currentResult = null;

init();

function init() {
  bindControls();
  makePanelDraggable(floatingPanel, floatingHandle);
  hydrateFromStorage();
  chrome.storage.onChanged.addListener(handleStorageUpdate);
}

function bindControls() {
  pinFloatingBtn.addEventListener("click", () => {
    isPinned = !isPinned;
    pinFloatingBtn.textContent = isPinned ? "Pinned" : "Pin";
    pinFloatingBtn.classList.toggle("active", isPinned);
  });

  minFloatingBtn.addEventListener("click", () => {
    isCollapsed = !isCollapsed;
    floatingPanel.classList.toggle("collapsed", isCollapsed);
    minFloatingBtn.textContent = isCollapsed ? "Expand" : "Minimize";
  });

  closeFloatingBtn.addEventListener("click", () => window.close());
}

function hydrateFromStorage() {
  chrome.storage.local.get(["floatingResult"], ({ floatingResult }) => {
    if (!floatingResult) {
      renderEmpty();
      return;
    }
    renderResult(floatingResult);
  });
}

function handleStorageUpdate(changes, area) {
  if (area !== "local" || !changes.floatingResult) {
    return;
  }
  renderResult(changes.floatingResult.newValue);
}

function renderEmpty() {
  floatingTarget.textContent = "No scan selected";
  floatingSummary.innerHTML = '<div class="floating-card"><small>Status</small><strong>Idle</strong></div>';
  floatingFindings.innerHTML = '<div class="text-slate-400">Open the extension popup and select a scan to broadcast results here.</div>';
}

function renderResult(result) {
  if (!result) {
    renderEmpty();
    return;
  }
  currentResult = result;
  floatingTarget.textContent = result.target_url || "Unknown target";
  renderSummaryCards(result);
  renderFindingList(result.findings || []);
}

function renderSummaryCards(result) {
  const findings = result.findings || [];
  const total = resolveTotalFindings(result, findings);
  const counts = normalizeSeverityCounts(result, findings);
  const metrics = computeEnhancedMetrics(findings);
  const completedAt = result.completed_at ? new Date(result.completed_at).toLocaleString() : "Processing";

  floatingSummary.innerHTML = [
    summaryCard("Total", total),
    summaryCard("High", counts.high + counts.critical),
    summaryCard("Medium", counts.medium),
    summaryCard("Low", counts.low),
    summaryCard("Avg CVSS", metrics.avgCvss),
    summaryCard("Critical Priority", metrics.criticalPriority),
    summaryCard("With Exploit", metrics.withExploit),
    summaryCard("High Confidence", metrics.highConfidence),
    summaryCard("Completed", completedAt, true),
  ].join("");
}

function summaryCard(label, value, wrap) {
  return `
    <div class="floating-card">
      <small>${escapeHTML(label)}</small>
      <strong ${wrap ? 'style="font-size:1rem;line-height:1.3"' : ''}>${escapeHTML(String(value ?? '0'))}</strong>
    </div>
  `;
}

function renderFindingList(findings) {
  if (!findings.length) {
    floatingFindings.innerHTML = '<div class="text-slate-400">This scan did not report any vulnerabilities.</div>';
    return;
  }
  floatingFindings.innerHTML = findings
    .map((finding, idx) => {
      const severity = finding.severity || "Info";
      const cvssScore = parseScore(finding.cvss_base_score ?? finding.cvss_score);
      const confidenceLabel = formatConfidence(finding.confidence);
      const description = escapeHTML(finding.description || "No description provided.");
      const endpoint = escapeHTML(finding.url || "N/A");
      const payload = finding.payload ? `<code>${escapeHTML(finding.payload)}</code>` : "";
      const evidence = finding.evidence ? `<div><small>Evidence</small><code>${escapeHTML(truncateText(finding.evidence, 220))}</code></div>` : "";
      return `
        <article class="finding-entry">
          <div class="finding-header">
            <div>
              <small class="text-slate-400">Finding #${idx + 1}</small>
              <h4>${escapeHTML(finding.vulnerability || 'Unnamed Finding')}</h4>
              <div class="finding-meta">${escapeHTML(severity)} - ${escapeHTML(confidenceLabel)}${cvssScore !== null ? ` - CVSS ${cvssScore.toFixed(1)}` : ''}</div>
            </div>
            <span class="badge badge-${severityToBadge(severity)}">${escapeHTML(severity)}</span>
          </div>
          <div class="finding-body">
            <div><small>Endpoint</small><code>${endpoint}</code></div>
            <div><small>Details</small><p>${description}</p></div>
            ${payload ? `<div><small>Payload</small>${payload}</div>` : ''}
            ${evidence}
          </div>
        </article>
      `;
    })
    .join("");
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
  };
}

function parseScore(value) {
  if (typeof value === "number") {
    return value;
  }
  if (typeof value === "string" && value.trim() !== "") {
    const parsed = parseFloat(value);
    return Number.isNaN(parsed) ? null : parsed;
  }
  return null;
}

function truncateText(text, limit = 220) {
  if (!text) {
    return "";
  }
  if (text.length <= limit) {
    return text;
  }
  return `${text.substring(0, limit)}...`;
}

function formatConfidence(confidence) {
  if (typeof confidence === "number") {
    return `${(confidence * 100).toFixed(0)}% confidence`;
  }
  if (typeof confidence === "string" && confidence.trim() !== "") {
    return confidence;
  }
  return "Confidence N/A";
}

function escapeHTML(text) {
  const div = document.createElement("div");
  div.textContent = text || "";
  return div.innerHTML;
}

function severityToBadge(severity = "") {
  const normalized = severity.toLowerCase();
  if (normalized === "critical" || normalized === "high") {
    return "high";
  }
  if (normalized === "medium") {
    return "medium";
  }
  if (normalized === "low") {
    return "low";
  }
  return "info";
}

function makePanelDraggable(panel, handle) {
  if (!panel || !handle) {
    return;
  }
  let isDragging = false;
  let startX = 0;
  let startY = 0;
  let initialX = 0;
  let initialY = 0;

  const startDrag = (event) => {
    if (isPinned) {
      return;
    }
    isDragging = true;
    const pointer = event.touches ? event.touches[0] : event;
    startX = pointer.clientX;
    startY = pointer.clientY;
    const rect = panel.getBoundingClientRect();
    initialX = rect.left;
    initialY = rect.top;
    panel.classList.add("dragging");
    event.preventDefault();
  };

  const duringDrag = (event) => {
    if (!isDragging) {
      return;
    }
    const pointer = event.touches ? event.touches[0] : event;
    if (event.cancelable) {
      event.preventDefault();
    }
    const deltaX = pointer.clientX - startX;
    const deltaY = pointer.clientY - startY;
    const viewportWidth = window.innerWidth;
    const viewportHeight = window.innerHeight;
    const panelWidth = panel.offsetWidth;
    const panelHeight = panel.offsetHeight;
    const clampedX = Math.min(Math.max(0, initialX + deltaX), viewportWidth - panelWidth);
    const clampedY = Math.min(Math.max(0, initialY + deltaY), viewportHeight - panelHeight);
    panel.style.position = "fixed";
    panel.style.left = `${clampedX}px`;
    panel.style.top = `${clampedY}px`;
  };

  const endDrag = () => {
    if (!isDragging) {
      return;
    }
    isDragging = false;
    panel.classList.remove("dragging");
  };

  handle.addEventListener("mousedown", startDrag);
  handle.addEventListener("touchstart", startDrag, { passive: false });
  window.addEventListener("mousemove", duringDrag, { passive: false });
  window.addEventListener("touchmove", duringDrag, { passive: false });
  window.addEventListener("mouseup", endDrag);
  window.addEventListener("touchend", endDrag);
}
