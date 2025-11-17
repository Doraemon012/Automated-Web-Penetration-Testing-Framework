const PANEL_ID = "webpentest-panel";
const PANEL_HANDLE_ID = `${PANEL_ID}-handle`;
const OUTLINE_CLASS = "webpentest-outline";
let panelRef = null;
let isPanelPinned = false;
let isPanelCollapsed = false;
let dragState = { active: false, startX: 0, startY: 0, initialX: 0, initialY: 0 };

chrome.runtime.onMessage.addListener((message) => {
  if (message.type === "render_findings") {
    renderFindings(message.payload);
  }
});

function renderFindings(payload) {
  clearHighlights();
  if (!payload?.findings?.length) {
    removePanel();
    return;
  }
  injectPanel(payload.findings, payload.target);
  payload.findings.forEach((finding) => {
    const element = locateElement(finding.url);
    if (element) {
      element.classList.add(OUTLINE_CLASS);
      element.dataset.webPentestFinding = finding.vulnerability;
    }
  });
}

function locateElement(url) {
  if (!url) return null;
  try {
    const parsed = new URL(url);
    const selector = `a[href*="${parsed.pathname}"]`;
    const anchor = document.querySelector(selector);
    if (anchor) return anchor;
    const form = document.querySelector(`form[action*="${parsed.pathname}"]`);
    if (form) return form;
  } catch (error) {
    return null;
  }
  return null;
}

function injectPanel(findings, target) {
  if (!panelRef) {
    panelRef = createPanelShell();
    document.body.appendChild(panelRef);
    injectStyles();
  }
  updatePanel(panelRef, findings, target);
}

function createPanelShell() {
  const panel = document.createElement("aside");
  panel.id = PANEL_ID;
  panel.innerHTML = `
    <div class="floating-header" id="${PANEL_HANDLE_ID}">
      <div>
        <p class="floating-title">Vanguard Findings</p>
        <p class="floating-subtitle" data-role="subtitle">Waiting for scan...</p>
      </div>
      <div class="floating-actions">
        <button class="pill-btn" data-action="pin">Pin</button>
        <button class="pill-btn" data-action="min">Minimize</button>
        <button class="pill-btn danger" data-action="close">Close</button>
      </div>
    </div>
    <div class="floating-body">
      <section class="floating-summary" data-role="summary"></section>
      <section class="floating-list" data-role="list"></section>
    </div>
  `;

  const pinBtn = panel.querySelector('[data-action="pin"]');
  const minBtn = panel.querySelector('[data-action="min"]');
  const closeBtn = panel.querySelector('[data-action="close"]');
  const handle = panel.querySelector(`#${PANEL_HANDLE_ID}`);

  pinBtn.addEventListener("click", () => {
    isPanelPinned = !isPanelPinned;
    pinBtn.classList.toggle("active", isPanelPinned);
    pinBtn.textContent = isPanelPinned ? "Pinned" : "Pin";
  });

  minBtn.addEventListener("click", () => {
    isPanelCollapsed = !isPanelCollapsed;
    panel.classList.toggle("collapsed", isPanelCollapsed);
    minBtn.textContent = isPanelCollapsed ? "Expand" : "Minimize";
  });

  closeBtn.addEventListener("click", () => {
    removePanel();
  });

  makePanelDraggable(panel, handle);
  return panel;
}

function updatePanel(panel, findings, target) {
  const subtitle = panel.querySelector('[data-role="subtitle"]');
  const summaryNode = panel.querySelector('[data-role="summary"]');
  const listNode = panel.querySelector('[data-role="list"]');
  subtitle.textContent = safeHostname(target);
  summaryNode.innerHTML = buildSummaryCards(findings);
  listNode.innerHTML = buildFindingCards(findings);
}

function buildSummaryCards(findings) {
  const counts = normalizeSeverityCounts(findings);
  const metrics = computeEnhancedMetrics(findings);
  const cards = [
    summaryCard("Total", findings.length),
    summaryCard("Critical", counts.critical),
    summaryCard("High", counts.high),
    summaryCard("Medium", counts.medium),
    summaryCard("Low", counts.low),
    summaryCard("Avg CVSS", metrics.avgCvss),
    summaryCard("With Exploit", metrics.withExploit),
    summaryCard("High Confidence", metrics.highConfidence),
  ];
  return cards.join("");
}

function summaryCard(label, value) {
  return `
    <div class="floating-card">
      <small>${escapeHTML(label)}</small>
      <strong>${escapeHTML(String(value ?? "0"))}</strong>
    </div>
  `;
}

function buildFindingCards(findings) {
  if (!findings.length) {
    return '<div class="text-muted">No vulnerabilities were reported for this scan.</div>';
  }
  return findings
    .map((finding, index) => {
      const severity = finding.severity || "Info";
      const cvssScore = parseScore(finding.cvss_base_score || finding.cvss_score);
      const confidenceLabel = formatConfidence(finding.confidence);
      const endpoint = escapeHTML(finding.url || "N/A");
      const description = escapeHTML(truncateText(finding.description || "No description provided."));
      const payload = finding.payload ? `<div><small>Payload</small><code>${escapeHTML(finding.payload)}</code></div>` : "";
      const evidence = finding.evidence ? `<div><small>Evidence</small><code>${escapeHTML(truncateText(finding.evidence, 220))}</code></div>` : "";
      return `
        <article class="finding-entry">
          <div class="finding-header">
            <div>
              <small class="text-muted">Finding #${index + 1}</small>
              <h4>${escapeHTML(finding.vulnerability || 'Unnamed Finding')}</h4>
              <div class="finding-meta">${escapeHTML(severity)} - ${escapeHTML(confidenceLabel)}${cvssScore !== null ? ` - CVSS ${cvssScore.toFixed(1)}` : ''}</div>
            </div>
            <span class="badge badge-${severityColor(severity)}">${escapeHTML(severity)}</span>
          </div>
          <div class="finding-body">
            <div><small>Endpoint</small><code>${endpoint}</code></div>
            <div><small>Details</small><p>${description}</p></div>
            ${payload}
            ${evidence}
          </div>
        </article>
      `;
    })
    .join("");
}

function normalizeSeverityCounts(findings = []) {
  return findings.reduce(
    (acc, finding) => {
      const level = (finding?.severity || "Info").toLowerCase();
      if (acc[level] !== undefined) {
        acc[level] += 1;
      }
      return acc;
    },
    { critical: 0, high: 0, medium: 0, low: 0 }
  );
}

function computeEnhancedMetrics(findings = []) {
  let totalCvss = 0;
  let cvssCount = 0;
  let withExploit = 0;
  let highConfidence = 0;
  findings.forEach((finding) => {
    const score = parseScore(finding?.cvss_base_score);
    if (score !== null) {
      totalCvss += score;
      cvssCount += 1;
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

function safeHostname(url) {
  try {
    return new URL(url).hostname;
  } catch (error) {
    return "Unknown target";
  }
}

function severityColor(level = "") {
  switch (level.toLowerCase()) {
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

function removePanel() {
  document.getElementById(PANEL_ID)?.remove();
  panelRef = null;
  isPanelPinned = false;
  isPanelCollapsed = false;
}

function clearHighlights() {
  document.querySelectorAll(`.${OUTLINE_CLASS}`).forEach((el) => {
    el.classList.remove(OUTLINE_CLASS);
    delete el.dataset.webPentestFinding;
  });
}

function injectStyles() {
  if (document.getElementById("webpentest-style")) {
    return;
  }
  const style = document.createElement("style");
  style.id = "webpentest-style";
  style.textContent = `
    #${PANEL_ID} {
      position: fixed;
      top: 1.5rem;
      right: 1.5rem;
      width: min(480px, 90vw);
      max-height: 85vh;
      background: linear-gradient(180deg, rgba(8,12,20,0.98), rgba(4,6,10,0.92));
      border-radius: 16px;
      border: 1px solid rgba(255, 255, 255, 0.06);
      box-shadow: 0 12px 40px rgba(2,6,23,0.7);
      color: #e6f0fb;
      font-family: "Inter", system-ui, -apple-system, BlinkMacSystemFont, sans-serif;
      backdrop-filter: blur(8px) saturate(120%);
      z-index: 2147483647;
      display: flex;
      flex-direction: column;
    }
    #${PANEL_ID}.collapsed .floating-body {
      display: none;
    }
    #${PANEL_ID} .floating-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding: 0.85rem 1rem;
      border-bottom: 1px solid rgba(255, 255, 255, 0.04);
      gap: 0.5rem;
      cursor: move;
      user-select: none;
    }
    #${PANEL_ID} .floating-title {
      margin: 0;
      font-size: 1.05rem;
      font-weight: 700;
      letter-spacing: 0.01em;
    }
    #${PANEL_ID} .floating-subtitle {
      margin: 0.15rem 0 0;
      font-size: 0.78rem;
      color: rgba(230, 240, 251, 0.75);
    }
    #${PANEL_ID} .floating-actions {
      display: flex;
      gap: 0.4rem;
    }
    #${PANEL_ID} .pill-btn {
      border: 1px solid rgba(255,255,255,0.06);
      background: rgba(255,255,255,0.02);
      color: #dceefc;
      border-radius: 999px;
      padding: 0.28rem 0.7rem;
      font-size: 0.72rem;
      text-transform: none;
      letter-spacing: 0.02em;
      cursor: pointer;
      transition: all 0.18s cubic-bezier(.2,.9,.2,1);
    }
    #${PANEL_ID} .pill-btn:hover {
      transform: translateY(-1px);
      border-color: rgba(0,150,255,0.6);
      color: #dff7ff;
    }
    #${PANEL_ID} .pill-btn.active {
      border-color: rgba(0,150,255,0.85);
      background: rgba(0,150,255,0.12);
      color: #e6f9ff;
    }
    #${PANEL_ID} .pill-btn.danger {
      border-color: rgba(255,99,132,0.5);
      background: rgba(255,99,132,0.08);
      color: #ffdfe6;
    }
    #${PANEL_ID} .floating-body {
      padding: 0.9rem 1rem 1rem;
      overflow-y: auto;
      display: flex;
      flex-direction: column;
      gap: 0.9rem;
    }
    #${PANEL_ID} .floating-summary {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
      gap: 0.65rem;
    }
    #${PANEL_ID} .floating-card {
      background: rgba(255,255,255,0.02);
      border: 1px solid rgba(255,255,255,0.04);
      border-radius: 12px;
      padding: 0.65rem 0.75rem;
      display: flex;
      flex-direction: column;
      gap: 0.25rem;
    }
    #${PANEL_ID} .floating-card small {
      font-size: 0.6rem;
      letter-spacing: 0.08em;
      text-transform: uppercase;
      color: rgba(255, 255, 255, 0.55);
    }
    #${PANEL_ID} .floating-card strong {
      display: block;
      font-size: 1.4rem;
      margin-top: 0.2rem;
    }
    #${PANEL_ID} .finding-entry {
      border: 1px solid rgba(255, 255, 255, 0.04);
      border-radius: 12px;
      padding: 0.75rem;
      background: linear-gradient(180deg, rgba(8,10,14,0.6), rgba(6,8,12,0.65));
      margin-bottom: 0.6rem;
      box-shadow: 0 8px 20px rgba(3,6,12,0.5);
    }
    #${PANEL_ID} .finding-header {
      display: flex;
      justify-content: space-between;
      gap: 0.75rem;
    }
    #${PANEL_ID} .finding-header h4 {
      margin: 0.1rem 0;
      font-size: 1.02rem;
      line-height: 1.1;
    }
    #${PANEL_ID} .finding-meta {
      font-size: 0.78rem;
      color: rgba(230,240,251,0.7);
    }
    #${PANEL_ID} .badge {
      display: inline-flex;
      align-items: center;
      padding: 0.15rem 0.55rem;
      border-radius: 999px;
      font-size: 0.7rem;
      text-transform: none;
      letter-spacing: 0.02em;
      border: 1px solid rgba(255,255,255,0.04);
      background: rgba(255,255,255,0.02);
      color: #e6f3ff;
    }
    #${PANEL_ID} .badge-critical { background: rgba(249,115,22,0.12); color: #ffd9c9; border-color: rgba(249,115,22,0.14); }
    #${PANEL_ID} .badge-high { background: rgba(251,146,60,0.12); color: #fff1e6; border-color: rgba(251,146,60,0.14); }
    #${PANEL_ID} .badge-medium { background: rgba(250,204,21,0.08); color: #0b1220; border-color: rgba(250,204,21,0.12); }
    #${PANEL_ID} .badge-low { background: rgba(56,189,248,0.08); color: #dff7ff; border-color: rgba(56,189,248,0.12); }
    #${PANEL_ID} .badge-info { background: rgba(168,85,247,0.08); color: #f1e8ff; border-color: rgba(168,85,247,0.12); }
    #${PANEL_ID} .finding-body {
      margin-top: 0.75rem;
      display: flex;
      flex-direction: column;
      gap: 0.35rem;
      font-size: 0.85rem;
    }
    #${PANEL_ID} .finding-body code {
      background: rgba(10,14,20,0.6);
      padding: 0.2rem 0.45rem;
      border-radius: 6px;
      word-break: break-all;
      display: inline-block;
      color: #dff8ff;
      font-size: 0.82rem;
    }
    #${PANEL_ID} .text-muted {
      color: rgba(255, 255, 255, 0.55);
      font-size: 0.85rem;
    }
    .${OUTLINE_CLASS} {
      outline: 3px solid rgba(56,189,248,0.95) !important;
      outline-offset: 3px;
      position: relative;
    }
    .${OUTLINE_CLASS}::after {
      content: attr(data-web-pentest-finding);
      position: absolute;
      top: -0.65rem;
      left: 0;
      background: rgba(6,10,16,0.95);
      color: rgba(220,247,255,0.98);
      font-size: 0.68rem;
      padding: 0.12rem 0.36rem;
      border-radius: 999px;
      border: 1px solid rgba(56,189,248,0.22);
    }
  `;
  document.head.appendChild(style);
}

function makePanelDraggable(panel, handle) {
  handle.addEventListener("mousedown", startDrag);
  handle.addEventListener("touchstart", startDrag, { passive: false });
  window.addEventListener("mousemove", duringDrag, { passive: false });
  window.addEventListener("touchmove", duringDrag, { passive: false });
  window.addEventListener("mouseup", endDrag);
  window.addEventListener("touchend", endDrag);

  function startDrag(event) {
    if (isPanelPinned) {
      return;
    }
    dragState.active = true;
    const pointer = event.touches ? event.touches[0] : event;
    dragState.startX = pointer.clientX;
    dragState.startY = pointer.clientY;
    const rect = panel.getBoundingClientRect();
    dragState.initialX = rect.left;
    dragState.initialY = rect.top;
    panel.classList.add("dragging");
    if (event.cancelable) {
      event.preventDefault();
    }
  }

  function duringDrag(event) {
    if (!dragState.active) {
      return;
    }
    const pointer = event.touches ? event.touches[0] : event;
    if (event.cancelable) {
      event.preventDefault();
    }
    const deltaX = pointer.clientX - dragState.startX;
    const deltaY = pointer.clientY - dragState.startY;
    const viewportWidth = window.innerWidth;
    const viewportHeight = window.innerHeight;
    const panelWidth = panel.offsetWidth;
    const panelHeight = panel.offsetHeight;
    const clampedX = Math.min(Math.max(0, dragState.initialX + deltaX), viewportWidth - panelWidth);
    const clampedY = Math.min(Math.max(0, dragState.initialY + deltaY), viewportHeight - panelHeight);
    panel.style.left = `${clampedX}px`;
    panel.style.top = `${clampedY}px`;
    panel.style.right = "auto";
    panel.style.bottom = "auto";
  }

  function endDrag() {
    if (!dragState.active) {
      return;
    }
    dragState.active = false;
    panel.classList.remove("dragging");
  }
}
