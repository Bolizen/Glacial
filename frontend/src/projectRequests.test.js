import assert from "node:assert/strict";
import test from "node:test";

import {
  isAbortError,
  projectListResponsePolicy,
  requestIsCurrent,
  scopedRequestIsCurrent,
  shouldReloadSelectedProjectAfterMutation,
} from "./projectRequests.js";

test("accepts a response only for the current project generation", () => {
  assert.equal(requestIsCurrent("project-a", 4, "project-a", 4), true);
});

test("rejects a response from a previously selected project", () => {
  assert.equal(requestIsCurrent("project-b", 5, "project-a", 4), false);
});

test("rejects an old response after switching away and back", () => {
  assert.equal(requestIsCurrent("project-a", 6, "project-a", 4), false);
});

test("rejects an older scoped response for the same project generation", () => {
  assert.equal(
    scopedRequestIsCurrent(12, 11, "project-a", 4, "project-a", 4),
    false,
  );
});

test("accepts only the latest scoped response for the current project generation", () => {
  assert.equal(
    scopedRequestIsCurrent(12, 12, "project-a", 4, "project-a", 4),
    true,
  );
});

test("reloads selected details after an old mutation completes following A to B to A", () => {
  assert.equal(
    shouldReloadSelectedProjectAfterMutation("project-a", 6, "project-a", 4),
    true,
  );
});

test("does not reload another project's details after switching away", () => {
  assert.equal(
    shouldReloadSelectedProjectAfterMutation("project-b", 5, "project-a", 4),
    false,
  );
});

test("does not reload details for the current project generation", () => {
  assert.equal(
    shouldReloadSelectedProjectAfterMutation("project-a", 4, "project-a", 4),
    false,
  );
});

test("rejects an older project-list response", () => {
  assert.equal(
    projectListResponsePolicy(
      8,
      7,
      "project-a",
      4,
      "project-a",
      4,
    ).applySelection,
    false,
  );
});

test("rejects a project-list response after switching projects", () => {
  assert.equal(
    projectListResponsePolicy(
      8,
      8,
      "project-b",
      5,
      "project-a",
      4,
    ).applySelection,
    false,
  );
});

test("applies latest project metadata without selection side effects after switching projects", () => {
  assert.deepEqual(
    projectListResponsePolicy(
      8,
      8,
      "project-b",
      5,
      "project-a",
      4,
    ),
    { applyData: true, applySelection: false },
  );
});

test("rejects both metadata and selection effects from an older project-list response", () => {
  assert.deepEqual(
    projectListResponsePolicy(
      8,
      7,
      "project-a",
      4,
      "project-a",
      4,
    ),
    { applyData: false, applySelection: false },
  );
});

test("accepts the latest global project-list response", () => {
  assert.equal(
    projectListResponsePolicy(
      8,
      8,
      "project-b",
      5,
      null,
      null,
    ).applySelection,
    true,
  );
});

test("identifies abort errors without treating ordinary failures as aborts", () => {
  assert.equal(isAbortError({ name: "AbortError" }), true);
  assert.equal(isAbortError(new Error("Request failed")), false);
  assert.equal(isAbortError(null), false);
});
