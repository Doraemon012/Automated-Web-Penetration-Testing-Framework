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
      background: linear-gradient(180deg, rgba(10,12,16,0.98), rgba(10,12,16,0.95));
      border-radius: 16px;
      border: 1px solid rgba(0, 191, 255, 0.2);
      box-shadow: 0 12px 40px rgba(0, 0, 0, 0.6), 0 0 25px rgba(0, 191, 255, 0.15);
      color: #e0e0e0;
      font-family: "Inter", system-ui, -apple-system, BlinkMacSystemFont, sans-serif;
      backdrop-filter: blur(12px) saturate(120%);
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
      padding: 1rem 1.25rem;
      border-bottom: 1px solid rgba(0, 191, 255, 0.2);
      gap: 0.75rem;
      cursor: move;
      user-select: none;
      background: rgba(0, 0, 0, 0.2);
    }
    #${PANEL_ID} .floating-title {
      margin: 0;
      font-size: 1.1rem;
      font-weight: 700;
      letter-spacing: 0.01em;
      color: #0037ffff;
      text-shadow: 0 0 10px rgba(0, 191, 255, 0.3);
    }
    #${PANEL_ID} .floating-subtitle {
      margin: 0.25rem 0 0;
      font-size: 0.8rem;
      color: rgba(224, 224, 224, 0.8);
    }
    #${PANEL_ID} .floating-actions {
      display: flex;
      gap: 0.4rem;
    }
    #${PANEL_ID} .pill-btn {
      border: 1px solid rgba(0, 191, 255, 0.2);
      background: rgba(0, 191, 255, 0.05);
      color: #e0e0e0;
      border-radius: 6px;
      padding: 0.35rem 0.85rem;
      font-size: 0.75rem;
      text-transform: none;
      letter-spacing: 0.02em;
      cursor: pointer;
      transition: all 0.2s ease;
      font-weight: 500;
    }
    #${PANEL_ID} .pill-btn:hover {
      transform: translateY(-1px);
      border-color: rgba(0, 191, 255, 0.6);
      background: rgba(0, 191, 255, 0.12);
      color: #ffffff;
      box-shadow: 0 0 15px rgba(0, 191, 255, 0.3);
    }
    #${PANEL_ID} .pill-btn.active {
      border-color: #0037ffff;
      background: rgba(0, 55, 255, 0.15);
      color: #ffffff;
      box-shadow: 0 0 15px rgba(0, 191, 255, 0.4);
    }
    #${PANEL_ID} .pill-btn.danger {
      border-color: rgba(255, 69, 0, 0.4);
      background: rgba(255, 69, 0, 0.1);
      color: #ff4500;
    }
    #${PANEL_ID} .pill-btn.danger:hover {
      background: rgba(255, 69, 0, 0.2);
      color: #ff6347;
      box-shadow: 0 0 15px rgba(255, 69, 0, 0.3);
    }
    #${PANEL_ID} .floating-body {
      padding: 1.25rem;
      overflow-y: auto;
      display: flex;
      flex-direction: column;
      gap: 1rem;
    }
    #${PANEL_ID} .floating-summary {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
      gap: 0.75rem;
    }
    #${PANEL_ID} .floating-card {
      background: rgba(26, 29, 46, 0.7);
      border: 1px solid rgba(0, 191, 255, 0.2);
      border-radius: 12px;
      padding: 1rem;
      display: flex;
      flex-direction: column;
      gap: 0.4rem;
      box-shadow: 0 4px 16px rgba(0, 0, 0, 0.3);
      backdrop-filter: blur(10px);
      transition: all 0.2s ease;
    }
    #${PANEL_ID} .floating-card:hover {
      transform: translateY(-2px);
      box-shadow: 0 0 20px rgba(0, 191, 255, 0.15);
    }
    #${PANEL_ID} .floating-card small {
      font-size: 0.7rem;
      letter-spacing: 0.1em;
      text-transform: uppercase;
      color: rgba(255, 255, 255, 0.6);
      font-weight: 500;
    }
    #${PANEL_ID} .floating-card strong {
      display: block;
      font-size: 1.85rem;
      margin-top: 0.2rem;
      color: #e0e0e0;
      font-family: 'Roboto Mono', monospace;
      font-weight: 700;
    }
    #${PANEL_ID} .finding-entry {
      border: 1px solid rgba(0, 191, 255, 0.2);
      border-radius: 12px;
      padding: 1rem;
      background: rgba(0, 0, 0, 0.3);
      margin-bottom: 0.85rem;
      box-shadow: 0 8px 32px rgba(0, 0, 0, 0.37);
      backdrop-filter: blur(10px);
      transition: all 0.25s ease;
    }
    #${PANEL_ID} .finding-entry:hover {
      transform: translateY(-2px);
      box-shadow: 0 4px 20px rgba(0, 191, 255, 0.15);
      border-color: rgba(0, 191, 255, 0.4);
    }
    #${PANEL_ID} .finding-header {
      display: flex;
      justify-content: space-between;
      gap: 1rem;
      margin-bottom: 0.75rem;
    }
    #${PANEL_ID} .finding-header h4 {
      margin: 0.3rem 0;
      font-size: 1rem;
      line-height: 1.3;
      color: #e0e0e0;
      font-weight: 600;
    }
    #${PANEL_ID} .finding-meta {
      font-size: 0.75rem;
      color: rgba(224, 224, 224, 0.7);
      margin-top: 0.25rem;
    }
    #${PANEL_ID} .badge {
      display: inline-flex;
      align-items: center;
      padding: 0.25rem 0.65rem;
      border-radius: 6px;
      font-size: 0.7rem;
      text-transform: none;
      letter-spacing: 0.02em;
      border: 1px solid rgba(255, 255, 255, 0.2);
      background: rgba(255, 255, 255, 0.1);
      color: #ffffff;
      font-weight: 600;
      white-space: nowrap;
    }
    #${PANEL_ID} .badge-critical { background: rgba(139, 0, 0, 1); color: #fff; border-color: rgba(139, 0, 0, 0.6); }
    #${PANEL_ID} .badge-high { background: rgba(255, 69, 0, 0.2); color: #ff4500; border: 1px solid #ff4500; }
    #${PANEL_ID} .badge-medium { background: rgba(255, 193, 7, 0.2); color: #ffc107; border: 1px solid #ffc107; }
    #${PANEL_ID} .badge-low { background: rgba(32, 201, 151, 0.2); color: #20c997; border: 1px solid #20c997; }
    #${PANEL_ID} .badge-info { background: rgba(0, 191, 255, 0.2); color: #0037ffff; border: 1px solid #0037ffff; }
    #${PANEL_ID} .finding-body {
      display: flex;
      flex-direction: column;
      gap: 0.5rem;
      font-size: 0.85rem;
    }
    #${PANEL_ID} .finding-body small {
      display: block;
      text-transform: uppercase;
      font-size: 0.65rem;
      color: rgba(255, 255, 255, 0.6);
      letter-spacing: 0.1em;
      margin-bottom: 0.3rem;
      font-weight: 500;
    }
    #${PANEL_ID} .finding-body code {
      background: rgba(0, 0, 0, 0.4);
      padding: 0.5rem;
      border-radius: 6px;
      word-break: break-all;
      display: block;
      color: #00FFAB;
      font-family: 'Roboto Mono', monospace;
      font-size: 0.8rem;
      border: 1px solid rgba(255, 255, 255, 0.05);
      margin-top: 0.25rem;
    }
    #${PANEL_ID} .finding-body p {
      color: #e0e0e0;
      line-height: 1.5;
      margin: 0;
    }
    #${PANEL_ID} .text-muted {
      color: rgba(224, 224, 224, 0.7);
      font-size: 0.85rem;
    }
    .${OUTLINE_CLASS} {
      outline: 3px solid rgba(0, 191, 255, 0.8) !important;
      outline-offset: 3px;
      position: relative;
      animation: pulseOutline 2s ease-in-out infinite;
    }
    @keyframes pulseOutline {
      0%, 100% { outline-color: rgba(0, 191, 255, 0.8); }
      50% { outline-color: rgba(0, 55, 255, 1); }
    }
    .${OUTLINE_CLASS}::after {
      content: attr(data-web-pentest-finding);
      position: absolute;
      top: -0.65rem;
      left: 0;
      background: rgba(10, 12, 16, 0.95);
      color: #0037ffff;
      font-size: 0.7rem;
      padding: 0.15rem 0.5rem;
      border-radius: 6px;
      border: 1px solid rgba(0, 191, 255, 0.4);
      font-weight: 600;
      box-shadow: 0 0 10px rgba(0, 191, 255, 0.3);
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
