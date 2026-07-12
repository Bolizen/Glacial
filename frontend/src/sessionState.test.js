import assert from "node:assert/strict";
import test from "node:test";

import {
  clearSessionState,
  parseSessionState,
  readSessionState,
  serializeSessionState,
  SESSION_STATE_KEY,
  stateForWorkspace,
  writeSessionState,
} from "./sessionState.js";

const VALID_STATE = {
  workspaceRoot: "C:/workspace",
  selectedProjectPath: "C:/workspace/project-a",
  activeSection: "reports",
  selectedScanId: 0,
  panels: { history: false, notes: true },
};

test("serializes and parses valid durable state while preserving zero and false", () => {
  const parsed = parseSessionState(serializeSessionState(VALID_STATE));
  assert.deepEqual(parsed, { version: 1, ...VALID_STATE });
});

test("malformed JSON and unsupported schema versions are ignored", () => {
  assert.equal(parseSessionState("{"), null);
  assert.equal(parseSessionState(JSON.stringify({ version: 2, workspaceRoot: "C:/workspace" })), null);
});

test("unknown sections and panels fall back or are ignored", () => {
  const parsed = parseSessionState(JSON.stringify({
    version: 1,
    workspaceRoot: "C:/workspace",
    activeSection: "removed",
    panels: { history: false, removed: true, notes: "false" },
    unknown: "ignored",
  }));
  assert.equal(parsed.activeSection, "workspace");
  assert.deepEqual(parsed.panels, { history: false });
  assert.equal("unknown" in parsed, false);
});

test("wrong field types are replaced with safe defaults", () => {
  const parsed = parseSessionState(JSON.stringify({
    version: 1,
    workspaceRoot: "C:/workspace",
    selectedProjectPath: 42,
    activeSection: false,
    selectedScanId: false,
    panels: { history: 0, notes: false },
  }));
  assert.equal(parsed.selectedProjectPath, "");
  assert.equal(parsed.activeSection, "workspace");
  assert.equal(parsed.selectedScanId, null);
  assert.deepEqual(parsed.panels, { notes: false });
});

test("workspace-specific state is rejected for another root", () => {
  const parsed = parseSessionState(serializeSessionState(VALID_STATE));
  assert.equal(stateForWorkspace(parsed, "D:/other"), null);
  assert.equal(stateForWorkspace(parsed, "C:/workspace"), parsed);
});

test("unavailable storage never throws during read, write, or clear", () => {
  const storage = {
    getItem() { throw new Error("blocked"); },
    setItem() { throw new Error("blocked"); },
    removeItem() { throw new Error("blocked"); },
  };
  assert.equal(readSessionState(storage), null);
  assert.equal(writeSessionState(VALID_STATE, storage), false);
  assert.equal(clearSessionState(storage), false);
});

test("storage helpers modify only the CodexForge session key", () => {
  const values = new Map([["unrelated", "keep"]]);
  const storage = {
    getItem: (key) => values.get(key) ?? null,
    setItem: (key, value) => values.set(key, value),
    removeItem: (key) => values.delete(key),
  };
  assert.equal(writeSessionState(VALID_STATE, storage), true);
  assert.ok(values.has(SESSION_STATE_KEY));
  assert.equal(readSessionState(storage).selectedScanId, 0);
  assert.equal(clearSessionState(storage), true);
  assert.equal(values.get("unrelated"), "keep");
});
