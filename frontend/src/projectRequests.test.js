import assert from "node:assert/strict";
import test from "node:test";

import { isAbortError, requestIsCurrent } from "./projectRequests.js";

test("accepts a response only for the current project generation", () => {
  assert.equal(requestIsCurrent("project-a", 4, "project-a", 4), true);
});

test("rejects a response from a previously selected project", () => {
  assert.equal(requestIsCurrent("project-b", 5, "project-a", 4), false);
});

test("rejects an old response after switching away and back", () => {
  assert.equal(requestIsCurrent("project-a", 6, "project-a", 4), false);
});

test("identifies abort errors without treating ordinary failures as aborts", () => {
  assert.equal(isAbortError({ name: "AbortError" }), true);
  assert.equal(isAbortError(new Error("Request failed")), false);
  assert.equal(isAbortError(null), false);
});
