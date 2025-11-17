const DEFAULT_SETTINGS = {
  apiBaseUrl: "https://vanguard-api-h9x9.onrender.com",
  apiKey: "8c8e14cb922e5fbb914cb61b7ee08873",
  defaultMode: "standard",
  useJsCrawler: true,
  passiveChecksEnabled: true,
  pollingIntervalMs: 4000,
};

function normalizeSettings(raw) {
  return { ...DEFAULT_SETTINGS, ...(raw || {}) };
}

let authState = {
  email: null,
  token: null,
  expiresAt: null,
};

const scanPollers = new Map();
const SCHEDULE_KEY = "scanSchedules";
const FREQUENCIES = {
  daily: 1000 * 60 * 60 * 24,
  weekly: 1000 * 60 * 60 * 24 * 7,
  monthly: 1000 * 60 * 60 * 24 * 30,
};

chrome.runtime.onInstalled.addListener(async () => {
  await bootstrapState();
  startScheduleWatcher();
});

chrome.runtime.onStartup.addListener(async () => {
  await bootstrapState();
  startScheduleWatcher();
});

async function bootstrapState() {
  const stored = await chrome.storage.local.get(["settings", "authState"]);
  if (stored.settings) {
    const normalized = normalizeSettings(stored.settings);
    await chrome.storage.local.set({ settings: normalized });
  } else {
    await chrome.storage.local.set({ settings: DEFAULT_SETTINGS });
  }
  if (stored.authState) {
    authState = stored.authState;
  }
}

function updateSettings(next) {
  const normalized = normalizeSettings(next);
  chrome.storage.local.set({ settings: normalized });
}

async function resetSettingsToDefault() {
  await chrome.storage.local.set({ settings: DEFAULT_SETTINGS });
  notifyClients({ type: "settings_changed", payload: DEFAULT_SETTINGS });
  return DEFAULT_SETTINGS;
}

async function getSettings() {
  const { settings } = await chrome.storage.local.get("settings");
  return normalizeSettings(settings);
}

function cacheAuthState(next) {
  authState = next;
  chrome.storage.local.set({ authState: next });
}

function clearAuthState({ silent } = {}) {
  authState = { email: null, token: null, expiresAt: null };
  chrome.storage.local.remove("authState");
  if (!silent) {
    notifyClients({ type: "auth_changed", payload: authState });
  }
}

function tokenIsValid() {
  if (!authState.token || !authState.expiresAt) {
    return false;
  }
  return Date.now() < authState.expiresAt - 60 * 1000;
}

async function apiFetch(path, { method = "GET", body, headers = {}, requiresAuth = true, overrideSettings = null } = {}) {
  const settings = await getSettings();
  const effectiveSettings = { ...settings, ...(overrideSettings || {}) };

  if (!effectiveSettings.apiBaseUrl) {
    throw new Error("API base URL not configured");
  }

  if (requiresAuth && !tokenIsValid()) {
    throw new Error("Authentication required");
  }

  const fetchHeaders = {
    "Content-Type": "application/json",
    ...headers,
  };

  if (effectiveSettings.apiKey) {
    fetchHeaders["X-API-Key"] = effectiveSettings.apiKey;
  }

  if (requiresAuth) {
    fetchHeaders["Authorization"] = `Bearer ${authState.token}`;
  }

  const response = await fetch(new URL(path, effectiveSettings.apiBaseUrl).toString(), {
    method,
    headers: fetchHeaders,
    body,
  });

  if (!response.ok) {
    const detail = await safeReadJson(response);
    let message = response.statusText;
    
    if (detail) {
      if (typeof detail.detail === 'string') {
        message = detail.detail;
      } else if (detail.detail && Array.isArray(detail.detail)) {
        // Handle validation errors array
        message = detail.detail.map(err => err.msg || err.message || JSON.stringify(err)).join(', ');
      } else if (detail.message) {
        message = detail.message;
      } else if (typeof detail === 'string') {
        message = detail;
      } else {
        // Handle object errors by extracting meaningful info
        message = JSON.stringify(detail);
      }
    }
    
    throw new Error(`API error ${response.status}: ${message}`);
  }

  if (response.status === 204) {
    return null;
  }
  return response.json();
}

async function safeReadJson(response) {
  try {
    return await response.json();
  } catch (error) {
    return null;
  }
}

async function registerUser(payload, overrides = null) {
  console.log('Registering user with payload:', payload);
  try {
    const result = await apiFetch("/api/auth/register", {
      method: "POST",
      body: JSON.stringify(payload),
      requiresAuth: false,
      overrideSettings: overrides,
    });
    console.log('Registration successful:', result);
    return result;
  } catch (error) {
    console.error('Registration failed:', error);
    throw error;
  }
}

function decodeJwt(token) {
  try {
    const payload = token.split(".")[1];
    const normalized = payload.replace(/-/g, "+").replace(/_/g, "/");
    const decoded = atob(normalized);
    return JSON.parse(decoded);
  } catch (error) {
    return null;
  }
}

async function loginUser(payload, overrides = null) {
  console.log('Logging in user with payload:', payload);
  try {
    const result = await apiFetch("/api/auth/login", {
      method: "POST",
      body: JSON.stringify(payload),
      requiresAuth: false,
      overrideSettings: overrides,
    });
    const decoded = decodeJwt(result.access_token);
    const expiresAt = decoded?.exp ? decoded.exp * 1000 : Date.now() + 1000 * 60 * 60;
    cacheAuthState({ email: payload.email, token: result.access_token, expiresAt });
    notifyClients({ type: "auth_changed", payload: authState });
    console.log('Login successful');
    return result;
  } catch (error) {
    console.error('Login failed:', error);
    throw error;
  }
}

async function startScan({ url, mode, useJs, authConfig }) {
  const body = {
    url,
    mode,
    use_js: useJs,
    auth: authConfig || null,
  };
  const response = await apiFetch("/api/scan", {
    method: "POST",
    body: JSON.stringify(body),
  });
  schedulePolling(response.scan_id);
  return response;
}

async function listScans(limit = 20) {
  return apiFetch(`/api/scans?limit=${limit}`);
}

async function fetchResults(scanId) {
  return apiFetch(`/api/results/${scanId}`);
}

async function fetchStatus(scanId) {
  return apiFetch(`/api/status/${scanId}`);
}

async function healthCheck(overrides) {
  return apiFetch("/api/status/health", { requiresAuth: false, overrideSettings: overrides });
}

async function schedulePolling(scanId) {
  if (scanPollers.has(scanId)) {
    return;
  }
  const settings = await getSettings();
  const runner = async () => {
    try {
      const status = await fetchStatus(scanId);
      notifyClients({ type: "scan_progress", payload: status });
      if (status.status === "completed" || status.status === "failed") {
        scanPollers.get(scanId)?.stop();
        scanPollers.delete(scanId);
      }
    } catch (error) {
      console.error("Polling error", scanId, error);
    }
  };

  const poller = {
    stop() {
      clearInterval(poller.timer);
    },
    timer: null,
  };

  runner();
  poller.timer = setInterval(async () => {
    await runner();
  }, settings.pollingIntervalMs || DEFAULT_SETTINGS.pollingIntervalMs);

  scanPollers.set(scanId, poller);
}

function notifyClients(message) {
  chrome.runtime.sendMessage(message).catch(() => undefined);
}

function startScheduleWatcher() {
  if (startScheduleWatcher.started) return;
  startScheduleWatcher.started = true;
  setInterval(() => {
    checkSchedules().catch((error) => console.error("Schedule check failed", error));
  }, 15 * 60 * 1000);
}

async function checkSchedules() {
  if (!tokenIsValid()) {
    return;
  }
  const { [SCHEDULE_KEY]: schedules = [] } = await chrome.storage.local.get(SCHEDULE_KEY);
  if (!schedules.length) return;
  const settings = await getSettings();
  let changed = false;
  for (const entry of schedules) {
    const windowMs = FREQUENCIES[entry.frequency] || FREQUENCIES.weekly;
    const lastRun = entry.lastRun || 0;
    if (Date.now() - lastRun >= windowMs) {
      try {
        await startScan({
          url: entry.target,
          mode: entry.mode || settings.defaultMode,
          useJs: settings.useJsCrawler,
        });
        entry.lastRun = Date.now();
        changed = true;
      } catch (error) {
        console.error("Scheduled scan failed", entry.target, error);
      }
    }
  }
  if (changed) {
    await chrome.storage.local.set({ [SCHEDULE_KEY]: schedules });
  }
}

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  const { type, payload, overrides } = message;

  const respond = (data, isError = false) => {
    sendResponse({ ok: !isError, data: isError ? undefined : data, error: isError ? data : undefined });
  };

  (async () => {
    try {
      switch (type) {
        case "register":
          await registerUser(payload, overrides);
          respond({ success: true });
          break;
        case "login":
          await loginUser(payload, overrides);
          respond({ success: true });
          break;
        case "logout":
          clearAuthState();
          respond({ success: true });
          break;
        case "get_auth_state":
          respond(authState);
          break;
        case "get_settings":
          respond(await getSettings());
          break;
        case "save_settings":
          updateSettings(payload);
          respond({ success: true });
          break;
        case "reset_settings":
          await resetSettingsToDefault();
          respond({ success: true });
          break;
        case "start_scan":
          respond(await startScan(payload));
          break;
        case "list_scans":
          respond(await listScans(payload?.limit));
          break;
        case "fetch_results":
          respond(await fetchResults(payload.scanId));
          break;
        case "fetch_status":
          respond(await fetchStatus(payload.scanId));
          break;
        case "health_check":
          respond(await healthCheck(payload));
          break;
        default:
          respond({ message: "Unknown message" }, true);
      }
    } catch (error) {
      console.error("Background error", error);
      respond(error.message || "Unexpected error", true);
    }
  })();

  return true;
});
