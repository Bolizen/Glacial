# Glacial 0.8.0 Agent Remediation Brief

Glacial 0.8.0 adds a bounded generated review aid for handing the latest scan's unresolved findings to a human-supervised coding agent.

## Agent Remediation Brief

- Adds an explicit action to the canonical Review workspace and always targets the selected project's latest scan, independent of historical Reports selection.
- Generates authoritative deterministic Markdown in the backend, reconstructing accepted canonical scanner explanations and using conservative fallback text for legacy or malformed findings.
- Includes only unresolved findings in severity-priority order, with bounded project-relative evidence, preserved suspicious-text redaction, inert project-evidence fences, and explicit incomplete or indeterminate coverage limitations.
- Requires preview before explicit `Copy brief` or `Download .md` actions and provides loading, empty, error, success, keyboard, scrolling, and narrow-width states.
- Does not launch an agent, call a remote agent API, execute project code or package scripts, install dependencies, write into the scanned project, or mutate scan and review evidence.
- Keeps findings as review prompts rather than proof of compromise, autonomous remediation, or certification of safety.

# Glacial 0.7.3 Finding Explainability Correction

Glacial 0.7.3 keeps finding review controls immediately available while hardening persisted scanner explanations.

## Finding explainability correction

- Collapses canonical and legacy explanation content behind an accessible native disclosure labelled `Why Glacial flagged this`.
- Keeps finding identity, review state, and review controls visible and usable without expanding the explanation.
- Reconstructs accepted canonical explanation prose from the backend scanner-owned builder instead of trusting persisted descriptive strings.
- Drops malformed or altered explainability metadata conservatively while keeping the finding readable through the legacy fallback.
- Preserves finding fingerprints, review decisions, detector coverage, severity classifications, scan risk, and completeness behavior.

# Glacial 0.7.2 Finding Explainability

Glacial 0.7.2 makes newly generated findings self-explanatory using bounded, persisted, scanner-owned evidence.

## Finding explainability

- Adds stable rule identity, display name, rule version, category, observed evidence, impact, severity rationale, manual inspection guidance, and limitations to every newly generated scanner finding.
- Builds the explanation only after core scanner and dependency findings converge, without adding detectors, changing severity, executing project content, or introducing remediation.
- Bounds persisted paths, locations, excerpts, and metadata while reusing the existing redacted suspicious-text evidence.
- Prefers canonical backend explanations in finding cards and Markdown reports.
- Keeps older persisted findings visible with conservative frontend guidance and an explicit notice that exact detector provenance and severity rationale are unavailable.

# Glacial 0.7.1 Review Context Correctness

Glacial 0.7.1 is a focused correctness patch that keeps latest Review evidence distinct from historical Reports context.

## Review context correctness

- Determines whether Review has started from the actual latest scan rather than timestamp metadata.
- Keeps existing scans with missing or malformed timestamps in Review with fail-closed status and an indeterminate evidence timestamp.
- Hides the global report export and copy controls in Review while retaining Run Scan.
- Preserves historical Reports selection and its existing export and copy behavior when moving between Reports and Review.

# Glacial 0.7.0 Guided Review Workspace

Glacial 0.7.0 brings the existing scan, investigation, review, and checkpoint capabilities into one canonical Review destination.

## Guided Review Workspace

- Summarizes the latest canonical Project Security Status with its interpretation, evidence timestamp, baseline source, and existing security disclaimer.
- Presents one prioritized next action and up to two additional actions, then navigates into the existing detailed review tools without running or approving anything automatically.
- Shows the six canonical evidence sections in order without hiding indeterminate, not-applicable, significant-change, or fail-closed states.
- Integrates current checkpoint state, explicit eligible checkpoint creation, bounded ineligible reasons, and the newest three immutable checkpoint records.
- Keeps Review pinned to the latest project scan even when Reports displays historical evidence, and opens Review after each successful scan.
- Replaces the older five-step workflow authority with a compact, locally dismissible link to Review.
- Treats readiness and checkpoints as records of available evidence and manual review, never as certification or a security guarantee.

# Glacial 0.6.9 Review Checkpoint Eligibility Correction

Glacial 0.6.9 aligns backend review-checkpoint eligibility with the canonical Project Security Status evaluator.

## Checkpoint eligibility parity

- Represents complete scans with no supported dependency metadata as explicitly not applicable, without fabricating a dependency approval fingerprint.
- Detects new critical/high findings relative to the applicable trusted or bounded automatic baseline even after those findings are reviewed or marked expected.
- Treats malformed applicable baseline finding evidence as indeterminate and derives eligibility entirely from persisted evidence.
- Advances the checkpoint evaluator version so earlier checkpoints cannot be mistaken for current under the corrected semantics.

# Glacial 0.6.8 Project Review Checkpoints

Glacial 0.6.8 adds immutable, project-scoped audit records for explicitly recording manual review of the exact current security evidence.

## Project review checkpoints

- Allows recording a checkpoint only when the canonical Project Security Status is exactly Ready for reviewed work.
- Captures bounded normalized identities for the latest scan, baseline provenance, Project Expectations, dependency analysis and approval, finding review, coverage, metadata reliability, and evaluator/schema versions.
- Derives explicit Current, Review required, Indeterminate, and No checkpoint states, with any newer scan requiring a new manual review.
- Prevents identical duplicate checkpoints and writes exactly one activity event atomically with each successfully created checkpoint.
- Shows a compact confirmation preview and bounded newest-first history without adding edit, delete, override, remediation, or certification behavior.
- Keeps checkpoint calculation and viewing read-only; checkpoints do not mutate scans, findings, review decisions, severity, raw risk, dependencies, expectations, baselines, coverage, or project trust.

## Project security status summary

- Synthesizes only existing persisted scan, coverage, finding-review, dependency, Project Expectations, and baseline evidence without creating a score, approval, cache, or mutable status record.
- Uses explicit conservative precedence: Blocked by incomplete scan, Insufficient evidence, Significant changes detected, Review required, then Ready for reviewed work.
- Keeps Scan coverage, Findings, Dependencies, Project Expectations, Baseline and drift, and Review completion independently visible as Satisfied, Action required, Significant change, Indeterminate, or Not applicable.
- Treats incomplete scans and malformed current evidence conservatively, never inferring resolved findings, removed dependencies, or absent drift from gaps.
- Preserves trusted-baseline precedence and prominently reports unavailable explicit baselines without automatic fallback.
- Shows no more than three prioritized state-specific actions, each navigating to an existing view and never running automatically.
- Presents Ready for reviewed work only when all applicable current evidence is reliable and sufficiently reviewed; it remains explicitly not a guarantee of security.

## Trusted scan baseline management

- Lets users explicitly set, atomically replace, or clear one trusted scan baseline per project after reviewing a compact confirmation preview.
- Accepts only project-owned scans with complete and internally consistent coverage, structurally reliable persisted metadata, and supported complete dependency metadata.
- Stores only the project ID, scan ID, pinned UTC timestamp, and bounded manual provenance; scan contents remain in their original scan row.
- Gives a valid trusted reference precedence over automatic baseline selection in Project Expectations and reports an invalid or unavailable reference without silently falling back.
- Treats a baseline that is also the latest scan as a neutral state and never describes self-comparison as unchanged.
- Preselects the trusted scan as the base and latest scan as the target in the existing read-only Scan Comparison view.
- Records only successful set, replacement, and clear activity events in the same transaction as the baseline change.
- Does not alter scans, findings, review decisions, severity, raw risk, Project Expectations, dependency approval, coverage, provenance, or project trust state.

## Explicit scan comparison

- Lets users select distinct base and target scans, shows their timestamps, identifiers, completion, and reliability state, and orders the result chronologically even when selected in reverse.
- Compares persisted findings using stable scanner identity with conservative secondary matching for meaningful severity, category, detector, path, and evidence changes.
- Compares normalized dependency inventories for additions, removals, and version changes while withholding removal claims from incomplete or malformed analysis.
- Compares exact persisted coverage counts and marks missing, malformed, or internally inconsistent metrics Indeterminate instead of assuming zero.
- Reuses the Project Expectations drift normalization and deterministic pairing semantics across package managers, manifests, lockfiles, lifecycle scripts, ecosystems, reviewed paths, and ignored paths.
- Reports Comparable, Partially comparable, Indeterminate, or Unavailable independently for each section and never hides an indeterminate subsection behind a successful overall result.
- Creates no comparison records, findings, review decisions, dependency approvals, Project Expectations updates, project activity, or other project-state changes.

## Project activity timeline

## Project activity timeline

- Merges existing project registration and scan rows with append-only activity events instead of duplicating reconstructable history.
- Records material Project Expectations updates, individual observed drift adoption, the first completed finding-review transition per scan, and meaningful dependency snapshot approval.
- Orders activity deterministically newest-first, groups it by date, links to locally available related scans, and loads older entries through bounded pagination.
- Stores only bounded structured details. Unknown event types or malformed historical details remain renderable as generic read-only activity.
- Does not record navigation, panel state, suggestion dismissal, preview/cancellation, no-op saves, individual finding decisions, transient errors, or development activity.
- Event insertion shares the primary SQLite transaction wherever practical, so a failed event write cannot leave a successful-looking primary update or vice versa.

## Selective drift adoption

- Adds “Adopt into expectations” beside eligible observed values in expectation drift across package managers, manifests, lockfiles, lifecycle scripts, ecosystems, reviewed paths, and ignored paths.
- Shows a compact preview of values being added, values being removed or replaced, and the resulting approved expectation values before requiring explicit confirmation.
- Saves through the existing Project Expectations persistence and normalization path, retaining per-value provenance and existing dismissal behavior.
- Provides no bulk adoption action. Indeterminate or unreliable drift, historical scans, and exported reports remain read-only.
- Adoption never changes findings, severity, raw risk, review state, scan history, raw scan data, coverage, dependency approval, or review completion.

## Project drift summary

- Added separate scan-to-scan and expectation-drift summaries across the seven metadata categories already represented by Project Expectations.
- Shows unchanged, added or new, removed or missing, and changed or different values with compact counts and specific values.
- Withholds no-drift claims when current coverage, historical baselines, persisted metadata, or dependency analysis is unavailable, malformed, incomplete, or otherwise unreliable.
- Keeps approved expectations, raw observations, and inert suggestions distinct. No drift calculation approves, dismisses, overwrites, or mutates Project Expectations.
- Includes the same distinctions and conservative states in Markdown reports without creating or changing findings.

## Unified finding review

- Added one priority-ordered finding-review workbench with review-status, severity, and category filters; title and project-relative-path search; visible progress; and Next unresolved navigation.
- Preserved persisted finding review and reopen behavior, stable finding identities, historical scans, and the existing category-based detail views.
- Reduced the prominence of immutable raw-risk metrics after findings are reviewed while keeping scanner context available.

## Bounded scanner evidence

- Suspicious-text-pattern findings now include the first one-based matching line, deterministic match count, rule identifier, and a short sanitized excerpt.
- Evidence remains bounded and redacts credential-like values, authorization material, URLs containing credentials, private-key text, and long high-entropy values.
- Existing secret-designated files never contribute excerpts.
- The same safe scanner context appears in the Reports workbench and Markdown reports; legacy findings without evidence continue to render normally.

## Honest completion and coverage

- “Review complete for this scan” appears only when every finding has a review state, scan coverage is known and complete, and any applicable dependency snapshot exactly matches a valid explicitly approved baseline.
- Incomplete or unavailable coverage, unresolved findings, dependency drift, malformed dependency data, and approval-required dependency snapshots remain visible and keep the workflow incomplete.
- Current and historical scans receive separate conservative summaries. No completion state claims that Glacial verified project safety.

## Guided first-project flow

- Added a compact, dismissible five-step checklist covering project registration, first scan, finding review, coverage understanding, and dependency review when applicable.
- New or registered projects lead directly toward the first scan, and successful scans lead to the Reports workbench.
- Checklist dismissal is local UI state only and does not alter project, scan, finding-review, coverage, or dependency data.

## Desktop presentation

- Refined Projects into compact project entries with a separate selected-project metadata editor.
- Preserved the Icefields-branded OLED interface, local owned-backend lifecycle, English-only NSIS packaging, and signed installer and portable release semantics.
- Validated the guided-review and project flows at normal desktop and narrower responsive widths, including empty, unresolved, incomplete, complete, dependency-action, dismissed-checklist, and historical-scan states.
