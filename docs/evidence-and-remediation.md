# Understanding Glacial results

Glacial reports evidence from bounded local inspections. It does not certify that a project, dependency, or generated change is safe.

## Findings and severity

A finding records a rule, severity, project-relative path, explanation, recommended action, and any bounded evidence the scanner retained. Severity expresses the rule's review priority:

- **High**: review before running or trusting the affected content.
- **Medium**: inspect the behavior and its context before proceeding.
- **Low**: note the condition and confirm that it is expected.

Severity is not proof of exploitation, malware, or compromise. A project can also require attention because coverage is incomplete even when it has no high-severity finding.

**Complete** means Glacial finished every supported inspection for that scan without a recorded coverage gap. **Incomplete** means at least one supported input could not be fully inspected. **Unknown** is used for older records that lack current coverage metadata. Ignored, linked, unreadable, malformed, oversized, truncated, unsupported, or resource-limited input is not counted as clean evidence.

## Review states

Review decisions are separate from scanner evidence:

- **Reviewed** records that a person considered the exact finding.
- **Reviewed as expected** records that the exact finding is expected in this project.
- **Reopen** removes the review decision and returns the finding to unresolved.

Reviewing a finding does not change its severity, evidence, raw project risk, or scan coverage. The decision is tied to a fingerprint of the finding type, relative path, severity, and stable evidence. A relevant change produces a new unresolved finding rather than carrying an old acknowledgement forward.

Project Expectations describe approved project metadata such as expected manifests or package managers. They do not acknowledge findings. Observed drift can be adopted only through an explicit per-value action, and incomplete observations remain read-only.

## Baselines and comparisons

A trusted dependency baseline is a user-approved snapshot of supported dependency metadata. A trusted scan baseline is a user-selected complete, structurally reliable scan. Neither baseline states that packages or source code are safe.

Comparisons are read-only. They report added, removed, changed, matching, unavailable, or indeterminate evidence according to the records being compared. Missing evidence in an incomplete scan cannot prove that a prior finding or dependency disappeared.

Review checkpoints record that the available evidence met the checkpoint rules at a particular time. They are not certificates and do not prevent later evidence from changing the result.

## Reports, briefs, and packages

A Markdown scan report contains the selected scan's findings, coverage, dependency summary, comparison context, and review state. Check the scan identity and coverage status before sharing it.

An **Agent Remediation Brief** is a human-readable Markdown handoff for unresolved findings. An **Agent Remediation Package** is a deterministic data-only ZIP containing `README.md`, `AGENT_TASK.md`, `findings.json`, `manifest.json`, and `CHECKSUMS.sha256`. It contains no project source files, scripts, executables, or symlinks.

One brief or package includes at most the first 100 unresolved findings in severity-first canonical order. The preview and generated files state the exact unresolved, included, and omitted counts. The cap does not limit scanning, storage, review, or display.

Generating, copying, or downloading a report, brief, or package does not edit project code, launch another tool, install dependencies, or apply a remediation. A person remains responsible for selecting work, reviewing proposed changes, and deciding whether to run anything.

## Reader checklist

Before acting on a result:

1. Confirm the project and scan identity.
2. Read the coverage status and every stated limitation.
3. Review unresolved findings in severity order.
4. Treat reviews, expectations, and baselines as recorded judgement, not scanner proof.
5. Check the unresolved, included, and omitted counts before using a remediation handoff.
6. Review generated material for sensitive content before copying, exporting, or sharing it.
