const PANEL_ID = "webpentest-panel";
const OUTLINE_CLASS = "webpentest-outline";

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
  removePanel();
  const panel = document.createElement("aside");
  panel.id = PANEL_ID;
  panel.innerHTML = `
    <header>
      <strong>Findings (${findings.length})</strong>
      <span>${new URL(target).hostname}</span>
    </header>
    <div class="list"></div>
  `;
  const list = panel.querySelector(".list");
  findings.forEach((finding) => {
    const item = document.createElement("article");
    item.className = `finding finding-${severityColor(finding.severity)}`;
    item.innerHTML = `
      <p class="title">${finding.vulnerability || "Unknown"}</p>
      <p class="meta">${finding.severity || "N/A"} • ${finding.parameter || finding.context || ""}</p>
    `;
    list.appendChild(item);
  });
  document.body.appendChild(panel);
  injectStyles();
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
      top: 1rem;
      right: 1rem;
      width: 260px;
      max-height: calc(100vh - 2rem);
      overflow-y: auto;
      background: rgba(15, 23, 42, 0.95);
      color: #e2e8f0;
      border-radius: 1rem;
      border: 1px solid rgba(148, 163, 184, 0.3);
      box-shadow: 0 20px 40px rgba(15, 23, 42, 0.4);
      font-family: "Inter", system-ui, -apple-system, BlinkMacSystemFont, sans-serif;
      z-index: 2147483647;
      padding: 1rem;
    }
    #${PANEL_ID} header {
      display: flex;
      flex-direction: column;
      margin-bottom: 0.75rem;
      font-size: 0.85rem;
    }
    #${PANEL_ID} header span {
      color: #94a3b8;
      font-size: 0.7rem;
    }
    #${PANEL_ID} .finding {
      border-radius: 0.75rem;
      padding: 0.65rem;
      margin-bottom: 0.5rem;
      background: rgba(148, 163, 184, 0.08);
      border: 1px solid rgba(148, 163, 184, 0.2);
    }
    #${PANEL_ID} .finding .title {
      font-weight: 600;
      margin: 0 0 0.25rem 0;
    }
    #${PANEL_ID} .finding .meta {
      margin: 0;
      font-size: 0.7rem;
      color: #94a3b8;
    }
    .finding-critical { border-color: #f87171; }
    .finding-high { border-color: #fb923c; }
    .finding-medium { border-color: #facc15; }
    .finding-low { border-color: #38bdf8; }
    .finding-info { border-color: #a855f7; }
    .${OUTLINE_CLASS} {
      outline: 3px solid #38bdf8 !important;
      outline-offset: 3px;
      position: relative;
    }
    .${OUTLINE_CLASS}::after {
      content: attr(data-web-pentest-finding);
      position: absolute;
      top: -0.75rem;
      left: 0;
      background: #0f172a;
      color: #38bdf8;
      font-size: 0.65rem;
      padding: 0.15rem 0.4rem;
      border-radius: 999px;
      border: 1px solid rgba(56, 189, 248, 0.4);
    }
  `;
  document.head.appendChild(style);
}
