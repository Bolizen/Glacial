export const SESSION_STATE_KEY = "codexforge.ui-state.v1";
export const SESSION_STATE_VERSION = 1;

export const VALID_SECTIONS = Object.freeze([
  "workspace",
  "projects",
  "trustProfiles",
  "reports",
  "changelog",
  "settings",
]);

export const VALID_PANELS = Object.freeze([
  "changelog",
  "scanReport",
  "agents",
  "notes",
  "history",
]);

export function parseSessionState(raw) {
  if (typeof raw !== "string") return null;
  let value;
  try {
    value = JSON.parse(raw);
  } catch {
    return null;
  }
  if (!isRecord(value) || value.version !== SESSION_STATE_VERSION || typeof value.workspaceRoot !== "string" || !value.workspaceRoot) {
    return null;
  }

  const panels = {};
  if (isRecord(value.panels)) {
    for (const panel of VALID_PANELS) {
      if (typeof value.panels[panel] === "boolean") panels[panel] = value.panels[panel];
    }
  }

  return {
    version: SESSION_STATE_VERSION,
    workspaceRoot: value.workspaceRoot,
    selectedProjectPath: typeof value.selectedProjectPath === "string" ? value.selectedProjectPath : "",
    activeSection: VALID_SECTIONS.includes(value.activeSection) ? value.activeSection : "workspace",
    selectedScanId: Number.isSafeInteger(value.selectedScanId) && value.selectedScanId >= 0 ? value.selectedScanId : null,
    panels,
  };
}

export function serializeSessionState(value) {
  try {
    const parsed = parseSessionState(JSON.stringify({
      version: SESSION_STATE_VERSION,
      workspaceRoot: value?.workspaceRoot,
      selectedProjectPath: value?.selectedProjectPath,
      activeSection: value?.activeSection,
      selectedScanId: value?.selectedScanId,
      panels: value?.panels,
    }));
    return parsed ? JSON.stringify(parsed) : null;
  } catch {
    return null;
  }
}

export function stateForWorkspace(value, workspaceRoot) {
  return value?.workspaceRoot === workspaceRoot ? value : null;
}

export function readSessionState(storage = browserStorage()) {
  try {
    return storage ? parseSessionState(storage.getItem(SESSION_STATE_KEY)) : null;
  } catch {
    return null;
  }
}

export function writeSessionState(value, storage = browserStorage()) {
  const serialized = serializeSessionState(value);
  if (!serialized || !storage) return false;
  try {
    storage.setItem(SESSION_STATE_KEY, serialized);
    return true;
  } catch {
    return false;
  }
}

export function clearSessionState(storage = browserStorage()) {
  try {
    storage?.removeItem(SESSION_STATE_KEY);
    return true;
  } catch {
    return false;
  }
}

function browserStorage() {
  try {
    return globalThis.localStorage || globalThis.window?.localStorage || null;
  } catch {
    return null;
  }
}

function isRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}
