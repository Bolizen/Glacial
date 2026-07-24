import test from "node:test";
import assert from "node:assert/strict";
import {
  acceptExpectationSuggestion,
  buildAgentsProjectContext,
  buildProjectExpectationsViewModel,
  dismissExpectationSuggestion,
  editApprovedExpectations,
  normalizeProjectExpectations,
  provenanceLabel,
  removeApprovedExpectation,
} from "./projectExpectations.js";

test("legacy trust-profile values become approved expectations without invented provenance", () => {
  const profile = normalizeProjectExpectations({
    trustedPackageManagers: [" npm ", "npm", "PIP", null, { name: "cargo" }],
    expectedManifestFiles: [".\\package.json", "./package.json"],
    riskTolerance: "CAUTIOUS",
    notes: ["malformed"],
  });

  assert.deepEqual(profile.trustedPackageManagers, ["npm", "pip"]);
  assert.deepEqual(profile.expectedManifestFiles, ["package.json"]);
  assert.deepEqual(profile.expectationProvenance, {});
  assert.equal(profile.riskTolerance, "cautious");
  assert.equal(profile.notes, "");
  assert.equal(provenanceLabel(undefined), "Legacy approved");
});

test("complete scan metadata produces bounded deterministic inert suggestions", () => {
  const report = completeReport();
  const findingsBefore = structuredClone(report.findings);
  const model = buildProjectExpectationsViewModel({
    profile: {},
    report,
    scan: { id: 10 },
  });

  assert.deepEqual(field(model, "trustedPackageManagers").suggestions, ["npm", "pip"]);
  assert.deepEqual(field(model, "expectedManifestFiles").suggestions, ["package.json", "requirements.txt"]);
  assert.deepEqual(field(model, "expectedLockfiles").suggestions, ["package-lock.json"]);
  assert.deepEqual(field(model, "allowedLifecycleScripts").suggestions, ["postinstall"]);
  assert.deepEqual(field(model, "expectedEcosystems").suggestions, ["node", "python"]);
  assert.equal(field(model, "ignoredPaths").state, "observed");
  assert.deepEqual(report.findings, findingsBefore, "expectation derivation must not mutate findings");
});

test("large observed arrays remain bounded and report omitted values", () => {
  const report = completeReport();
  report.manifests = Array.from({ length: 75 }, (_, index) => `manifest-${String(index).padStart(2, "0")}.json`);
  const model = buildProjectExpectationsViewModel({
    profile: {},
    report,
    scan: { id: 10 },
  });
  const manifests = field(model, "expectedManifestFiles");
  assert.equal(manifests.observed.length, 50);
  assert.equal(manifests.suggestions.length, 50);
  assert.equal(manifests.observedOmittedCount, 25);
});

test("single suggestion acceptance records provenance without approving sibling suggestions", () => {
  const accepted = acceptExpectationSuggestion({}, "trustedPackageManagers", "NPM");
  assert.deepEqual(accepted.trustedPackageManagers, ["npm"]);
  assert.deepEqual(accepted.expectationProvenance, {
    trustedPackageManagers: { npm: "accepted-suggestion" },
  });

  const model = buildProjectExpectationsViewModel({
    profile: accepted,
    report: completeReport(),
    scan: { id: 10 },
  });
  assert.deepEqual(field(model, "trustedPackageManagers").suggestions, ["pip"]);
  assert.equal(field(model, "trustedPackageManagers").state, "changed");
});

test("manual editing, removal, and retained observations stay independent", () => {
  const manual = editApprovedExpectations(
    { expectedManifestFiles: ["legacy.json"] },
    "expectedManifestFiles",
    [" package.json ", "custom.json", "package.json"],
  );
  assert.deepEqual(manual.expectedManifestFiles, ["package.json", "custom.json"]);
  assert.deepEqual(manual.expectationProvenance.expectedManifestFiles, {
    "package.json": "manual",
    "custom.json": "manual",
  });

  const removed = removeApprovedExpectation(manual, "expectedManifestFiles", "package.json");
  const model = buildProjectExpectationsViewModel({
    profile: removed,
    report: completeReport(),
    scan: { id: 10 },
  });
  assert.deepEqual(removed.expectedManifestFiles, ["custom.json"]);
  assert.ok(field(model, "expectedManifestFiles").observed.some((item) => item.value === "package.json"));
  assert.ok(field(model, "expectedManifestFiles").suggestions.includes("package.json"));
});

test("dismissed suggestions remain observed but are not suggested again", () => {
  const dismissed = dismissExpectationSuggestion({}, "expectedLockfiles", "package-lock.json");
  const model = buildProjectExpectationsViewModel({
    profile: dismissed,
    report: completeReport(),
    scan: { id: 10 },
  });

  assert.deepEqual(dismissed.dismissedSuggestions, {
    expectedLockfiles: ["package-lock.json"],
  });
  assert.deepEqual(field(model, "expectedLockfiles").suggestions, []);
  assert.deepEqual(field(model, "expectedLockfiles").observed.map((item) => item.value), ["package-lock.json"]);
  assert.equal(field(model, "expectedLockfiles").state, "observed");
});

test("matching and changed approved expectations are distinguished conservatively", () => {
  const matching = buildProjectExpectationsViewModel({
    profile: { expectedLockfiles: ["package-lock.json"] },
    report: completeReport(),
    scan: { id: 10 },
  });
  assert.equal(field(matching, "expectedLockfiles").state, "approved");

  const changed = buildProjectExpectationsViewModel({
    profile: { expectedLockfiles: ["yarn.lock"] },
    report: completeReport(),
    scan: { id: 10 },
  });
  assert.equal(field(changed, "expectedLockfiles").state, "changed");
  assert.equal(field(changed, "expectedLockfiles").approved[0].provenance, "legacy-approved");
});

test("incomplete and historical scans show observations but withhold suggestions", () => {
  const incompleteReport = {
    ...completeReport(),
    completeness: { known: true, complete: false },
  };
  const incomplete = buildProjectExpectationsViewModel({
    profile: {},
    report: incompleteReport,
    scan: { id: 11 },
  });
  assert.deepEqual(field(incomplete, "expectedManifestFiles").suggestions, []);
  assert.equal(field(incomplete, "expectedManifestFiles").state, "observed");
  assert.match(field(incomplete, "expectedManifestFiles").reliabilityMessage, /coverage is incomplete/i);

  const historical = buildProjectExpectationsViewModel({
    profile: {},
    report: { ...completeReport(), completeness: { known: false, complete: false } },
    scan: { id: 1 },
  });
  assert.deepEqual(field(historical, "expectedManifestFiles").suggestions, []);
  assert.match(field(historical, "expectedManifestFiles").reliabilityMessage, /historical scan/i);
});

test("malformed or incomplete dependency analysis cannot create reliable suggestions", () => {
  for (const status of ["malformed", "incomplete", "unsupported"]) {
    const model = buildProjectExpectationsViewModel({
      profile: { expectationProvenance: "bad", dismissedSuggestions: ["bad"] },
      report: {
        ...completeReport(),
        dependencyTrust: {
          ...completeReport().dependencyTrust,
          status,
        },
      },
      scan: { id: 10 },
    });
    assert.deepEqual(field(model, "trustedPackageManagers").suggestions, []);
    assert.deepEqual(field(model, "expectedEcosystems").suggestions, []);
    assert.equal(field(model, "trustedPackageManagers").state, "observed");
  }
});

test("approved dependency snapshot remains separate from Project Expectations", () => {
  const report = completeReport();
  const model = buildProjectExpectationsViewModel({
    profile: { trustedPackageManagers: ["npm"] },
    report,
    scan: { id: 10 },
  });
  assert.equal(model.dependency.configured, true);
  assert.equal(model.dependency.valid, true);
  assert.equal(model.dependency.label, "Separate approval configured");
  assert.deepEqual(normalizeProjectExpectations({ trustedPackageManagers: ["npm"] }).trustedPackageManagers, ["npm"]);

  const unapprovedReport = completeReport();
  unapprovedReport.dependencyTrust = {
    ...unapprovedReport.dependencyTrust,
    trustedBaseline: {
      configured: false,
      valid: false,
      status: "not-configured",
      approval: { eligible: true },
    },
  };
  const unapproved = buildProjectExpectationsViewModel({
    profile: {},
    report: unapprovedReport,
    scan: { id: 10 },
  });
  assert.equal(unapproved.dependency.label, "No approved dependency snapshot");
});

test("future AGENTS context exposes only approved values, approved dependency context, and reviewed notes", () => {
  const context = buildAgentsProjectContext({
    profile: {
      trustedPackageManagers: ["npm"],
      notes: "Reviewed local script assumptions.",
      dismissedSuggestions: { expectedLockfiles: ["package-lock.json"] },
    },
    dependencyTrust: completeReport().dependencyTrust,
  });
  assert.deepEqual(context, {
    schemaVersion: 1,
    approvedExpectations: { trustedPackageManagers: ["npm"] },
    approvedDependencyContext: {
      fingerprint: "tdb1_example",
      status: "current",
      note: "Reviewed dependency snapshot.",
    },
    reviewedSafetyNotes: "Reviewed local script assumptions.",
  });
});

function field(model, name) {
  const value = model.fields.find((item) => item.field === name);
  assert.ok(value, `Expected ${name} field`);
  return value;
}

function completeReport() {
  return {
    completeness: { known: true, complete: true },
    manifests: ["package.json", "requirements.txt"],
    lockfiles: ["package-lock.json"],
    lifecycleScripts: [{ path: "package.json", script: "postinstall" }],
    reviewedFiles: ["src/main.js"],
    ignoredFiles: ["vendor/output.js"],
    findings: [{ fingerprint: "cf1_example", severity: "high", review: null }],
    dependencyTrust: {
      available: true,
      status: "complete",
      ecosystems: ["node", "python"],
      packageManagers: ["npm", "pip"],
      trustedBaseline: {
        configured: true,
        valid: true,
        fingerprint: "tdb1_example",
        status: "current",
        note: "Reviewed dependency snapshot.",
      },
    },
  };
}
