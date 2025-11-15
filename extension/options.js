const settingsForm = document.getElementById("settingsForm");
const scheduleForm = document.getElementById("scheduleForm");
const scheduleList = document.getElementById("scheduleList");
const scheduleTemplate = document.getElementById("scheduleItemTemplate");
const statusLabel = document.getElementById("settingsStatus");
const testBtn = document.getElementById("testConnection");

const SCHEDULE_KEY = "scanSchedules";

init();

function init() {
  loadSettings();
  loadSchedules();
  settingsForm.addEventListener("submit", saveSettings);
  scheduleForm.addEventListener("submit", addSchedule);
  testBtn.addEventListener("click", testConnection);
}

async function loadSettings() {
  const { data } = await callBackground("get_settings");
  settingsForm.apiBaseUrl.value = data.apiBaseUrl || "";
  settingsForm.apiKey.value = data.apiKey || "";
  settingsForm.defaultMode.value = data.defaultMode || "standard";
  settingsForm.useJsCrawler.checked = Boolean(data.useJsCrawler);
  settingsForm.passiveChecksEnabled.checked = Boolean(data.passiveChecksEnabled);
  settingsForm.pollingIntervalMs.value = data.pollingIntervalMs || 4000;
}

async function saveSettings(event) {
  event.preventDefault();
  const formData = new FormData(settingsForm);
  const payload = Object.fromEntries(formData.entries());
  payload.apiKey = (payload.apiKey || "").trim();
  payload.useJsCrawler = Boolean(formData.get("useJsCrawler"));
  payload.passiveChecksEnabled = Boolean(formData.get("passiveChecksEnabled"));
  payload.pollingIntervalMs = Number(payload.pollingIntervalMs) || 4000;
  try {
    await callBackground("save_settings", payload);
    statusLabel.textContent = "Settings saved";
  } catch (error) {
    statusLabel.textContent = error.message || "Unable to save";
  }
}

async function testConnection() {
  statusLabel.textContent = "Testing...";
  try {
    const { data } = await callBackground("health_check");
    statusLabel.textContent = `API OK • ${data.status}`;
  } catch (error) {
    statusLabel.textContent = error.message || "API unreachable";
  }
}

async function addSchedule(event) {
  event.preventDefault();
  const formData = new FormData(scheduleForm);
  const settings = new FormData(settingsForm);
  const entry = {
    id: crypto.randomUUID(),
    target: formData.get("target"),
    frequency: formData.get("frequency"),
    mode: settings.get("defaultMode"),
    lastRun: 0,
  };
  const schedules = await getSchedules();
  schedules.push(entry);
  await chrome.storage.local.set({ [SCHEDULE_KEY]: schedules });
  scheduleForm.reset();
  renderSchedules(schedules);
}

async function loadSchedules() {
  const schedules = await getSchedules();
  renderSchedules(schedules);
}

async function getSchedules() {
  const stored = await chrome.storage.local.get(SCHEDULE_KEY);
  return stored[SCHEDULE_KEY] || [];
}

async function removeSchedule(id) {
  const schedules = (await getSchedules()).filter((entry) => entry.id !== id);
  await chrome.storage.local.set({ [SCHEDULE_KEY]: schedules });
  renderSchedules(schedules);
}

function renderSchedules(schedules) {
  scheduleList.innerHTML = "";
  schedules.forEach((entry) => {
    const row = scheduleTemplate.content.cloneNode(true);
    row.querySelector(".data-target").textContent = entry.target;
    row.querySelector(".data-frequency").textContent = `${entry.frequency} • ${entry.mode}`;
    row.querySelector(".data-remove").addEventListener("click", () => removeSchedule(entry.id));
    scheduleList.appendChild(row);
  });
}

function callBackground(type, payload) {
  return new Promise((resolve, reject) => {
    chrome.runtime.sendMessage({ type, payload }, (response) => {
      if (chrome.runtime.lastError) {
        reject(new Error(chrome.runtime.lastError.message));
        return;
      }
      if (!response || !response.ok) {
        reject(new Error(response?.error || "Request failed"));
        return;
      }
      resolve(response);
    });
  });
}
