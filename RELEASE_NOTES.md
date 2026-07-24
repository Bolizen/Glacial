# Glacial 0.6.4 Project Activity Timeline

Glacial 0.6.4 adds a compact, read-only history of meaningful persisted activity for the selected project.

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
