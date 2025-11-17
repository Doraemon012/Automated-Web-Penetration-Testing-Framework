const settingsForm = document.getElementById("settingsForm");
const scheduleForm = document.getElementById("scheduleForm");
const scheduleList = document.getElementById("scheduleList");
const scheduleTemplate = document.getElementById("scheduleItemTemplate");
const statusLabel = document.getElementById("settingsStatus");
const testBtn = document.getElementById("testConnection");
const resetDefaultsBtn = document.getElementById("resetDefaults");
const optionsAuthForm = document.getElementById("optionsAuthForm");
const optionsRegisterBtn = document.getElementById("optionsRegisterBtn");
const optionsLogoutBtn = document.getElementById("optionsLogoutBtn");
const optionsAuthStatus = document.getElementById("optionsAuthStatus");
const testApiBtn = document.getElementById("testApiBtn");
const authLockedSections = document.querySelectorAll("[data-auth-locked]");

const SCHEDULE_KEY = "scanSchedules";

init().catch((error) => console.error("Options init failed", error));

async function init() {
  chrome.runtime.onMessage.addListener((message) => {
    if (message.type === "auth_changed") {
      renderAuthState(message.payload || {});
    }
  });

  await loadAuthState();
  await loadSettings();
  await loadSchedules();

  settingsForm?.addEventListener("submit", saveSettings);
  scheduleForm?.addEventListener("submit", addSchedule);
  testBtn?.addEventListener("click", testConnection);
  resetDefaultsBtn?.addEventListener("click", resetDefaults);
  optionsAuthForm?.addEventListener("submit", submitAuthLogin);
  optionsRegisterBtn?.addEventListener("click", submitAuthRegister);
  optionsLogoutBtn?.addEventListener("click", submitAuthLogout);
  testApiBtn?.addEventListener("click", testApiConnection);
}

async function loadAuthState() {
  try {
    const { data } = await callBackground("get_auth_state");
    renderAuthState(data || {});
  } catch (error) {
    console.error("Auth state unavailable", error);
    renderAuthState({});
  }
}

function renderAuthState(state) {
  const signedIn = Boolean(state?.token);
  if (optionsAuthStatus) {
    optionsAuthStatus.textContent = signedIn ? `Signed in as ${state.email}` : "Signed out";
  }
  if (optionsLogoutBtn) {
    optionsLogoutBtn.classList.toggle("hidden", !signedIn);
  }
  toggleAuthLockedSections(signedIn);
}

function toggleAuthLockedSections(enabled) {
  authLockedSections.forEach((section) => {
    section.classList.toggle("opacity-50", !enabled);
    section.classList.toggle("pointer-events-none", !enabled);
    section.querySelectorAll("input, select, textarea, button").forEach((control) => {
      control.disabled = !enabled;
    });
  });
}

async function submitAuthLogin(event) {
  event.preventDefault();
  const formData = new FormData(optionsAuthForm);
  const email = formData.get("email");
  const password = formData.get("password");
  
  if (!email || !email.includes('@')) {
    if (optionsAuthStatus) {
      optionsAuthStatus.textContent = "Please enter a valid email address";
    }
    return;
  }
  
  if (!password || password.length < 8) {
    if (optionsAuthStatus) {
      optionsAuthStatus.textContent = "Password must be at least 8 characters";
    }
    return;
  }
  
  const payload = { email: email.trim(), password };
  
  try {
    if (optionsAuthStatus) {
      optionsAuthStatus.textContent = "Signing in...";
    }
    await callBackground("login", payload);
    optionsAuthForm.reset();
  } catch (error) {
    console.error('Login error:', error);
    if (optionsAuthStatus) {
      optionsAuthStatus.textContent = error.message || "Login failed";
    }
  }
}

async function submitAuthRegister(event) {
  event.preventDefault();
  const formData = new FormData(optionsAuthForm);
  const email = formData.get("email");
  const password = formData.get("password");
  
  // Validate input before sending
  if (!email || !email.includes('@')) {
    if (optionsAuthStatus) {
      optionsAuthStatus.textContent = "Please enter a valid email address";
    }
    return;
  }
  
  if (!password || password.length < 8) {
    if (optionsAuthStatus) {
      optionsAuthStatus.textContent = "Password must be at least 8 characters";
    }
    return;
  }
  
  const payload = { email: email.trim(), password };
  
  try {
    if (optionsAuthStatus) {
      optionsAuthStatus.textContent = "Creating account...";
    }
    await callBackground("register", payload);
    if (optionsAuthStatus) {
      optionsAuthStatus.textContent = "Registration successful. Sign in to continue.";
    }
  } catch (error) {
    console.error('Registration error:', error);
    if (optionsAuthStatus) {
      optionsAuthStatus.textContent = error.message || "Registration failed";
    }
  }
}

async function submitAuthLogout() {
  try {
    await callBackground("logout");
  } catch (error) {
    if (optionsAuthStatus) {
      optionsAuthStatus.textContent = error.message || "Logout failed";
    }
  }
}

async function testApiConnection() {
  try {
    if (optionsAuthStatus) {
      optionsAuthStatus.textContent = "Testing API connection...";
    }
    await callBackground("test_registration");
    if (optionsAuthStatus) {
      optionsAuthStatus.textContent = "API connection test successful ✓";
    }
  } catch (error) {
    console.error('API test failed:', error);
    if (optionsAuthStatus) {
      optionsAuthStatus.textContent = `API test failed: ${error.message}`;
    }
  }
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

async function resetDefaults() {
  statusLabel.textContent = "Restoring defaults...";
  try {
    await callBackground("reset_settings");
    await loadSettings();
    statusLabel.textContent = "Defaults restored";
  } catch (error) {
    statusLabel.textContent = error.message || "Unable to reset";
  }
}

async function testConnection() {
  statusLabel.textContent = "Testing...";
  const apiBaseUrl = settingsForm.apiBaseUrl.value.trim();
  const apiKey = settingsForm.apiKey.value.trim();
  if (!apiBaseUrl) {
    statusLabel.textContent = "API URL required";
    return;
  }
  try {
    const { data } = await callBackground("health_check", { apiBaseUrl, apiKey });
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
  if (!schedules.length) {
    const empty = document.createElement("p");
    empty.className = "text-xs text-slate-400";
    empty.textContent = "No schedules configured.";
    scheduleList.appendChild(empty);
    return;
  }
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
