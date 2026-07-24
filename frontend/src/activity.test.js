import assert from "node:assert/strict";
import test from "node:test";

import {
  activityDetail,
  activityTitle,
  groupActivityByDate,
  normalizeActivityPage,
} from "./activity.js";

test("activity pages stay bounded, group chronologically, and render malformed details conservatively", () => {
  const page = normalizeActivityPage({
    events: [
      {
        eventId: "evt_drift",
        projectId: "C:/workspace/project",
        eventType: "observed_drift_adopted",
        timestamp: "2026-07-24T14:00:00Z",
        relatedScanId: 12,
        details: {
          category: "expectedManifestFiles",
          adoptedValue: "pyproject.toml",
          replacedValue: "package.json",
        },
        malformed: false,
      },
      {
        eventId: "evt_unknown",
        projectId: "C:/workspace/project",
        eventType: "future_event",
        timestamp: "2026-07-24T13:00:00Z",
        relatedScanId: null,
        details: {},
        malformed: true,
      },
      {
        eventId: "evt_old",
        projectId: "C:/workspace/project",
        eventType: "project_registered",
        timestamp: "2026-07-23T13:00:00Z",
        relatedScanId: null,
        details: { projectName: "Project" },
        malformed: false,
      },
    ],
    has_more: true,
    next_offset: 3,
  });

  assert.equal(page.hasMore, true);
  assert.equal(page.nextOffset, 3);
  assert.equal(activityTitle(page.events[0]), "Observed drift adopted");
  assert.equal(
    activityDetail(page.events[0]),
    "Dependency manifests: adopted pyproject.toml, replacing package.json.",
  );
  assert.equal(activityTitle(page.events[1]), "Project activity");
  assert.match(activityDetail(page.events[1]), /details are unavailable/i);
  assert.deepEqual(groupActivityByDate(page.events).map((group) => group.events.length), [2, 1]);

  const malformedPage = normalizeActivityPage({
    events: [{ eventId: "evt_bad", eventType: "project_expectations_updated", details: "invalid" }],
    has_more: true,
    next_offset: "3",
  });
  assert.equal(malformedPage.events[0].malformed, true);
  assert.match(activityDetail(malformedPage.events[0]), /underlying project data was not changed/i);
  assert.equal(malformedPage.hasMore, false);
});
