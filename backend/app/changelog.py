from __future__ import annotations

CHANGELOG_ENTRIES = [
    {
        "version": "0.9.8",
        "date": "2026-07-28",
        "title": "Documentation, privacy, legal, and support boundaries",
        "changes": [
            "Published task-oriented installed lifecycle, evidence interpretation, supported-environment, privacy and network, security-reporting, and support documentation.",
            "Reviewed third-party notices against the locked frontend, Python, Rust, installer, and bundled-runtime inventory while retaining the final artifact and owner sign-off gate.",
            "Kept the repository NOT READY and limited readiness changes to requirements supported by complete G051 evidence.",
        ],
    },
    {
        "version": "0.9.7",
        "date": "2026-07-27",
        "title": "Installed lifecycle acceptance",
        "changes": [
            "Prepared an exact-source Windows x64 NSIS artifact for the remaining installed-edition lifecycle acceptance matrix.",
            "Extended lifecycle, recovery, restoration, reinstall, and uninstall evidence without reviving the retired portable edition or weakening production safety controls.",
            "Retained the conservative NOT READY verdict while clean release-candidate, security, documentation, signing, and final authorization work remains outstanding.",
        ],
    },
    {
        "version": "0.9.6",
        "date": "2026-07-27",
        "title": "Hex-secret redaction and installed lifecycle correction",
        "changes": [
            "Corrected the G048 privacy boundary so generic free text redacts standalone 40-128 character hexadecimal values by default, including values in evidence, paths, errors, diagnostics, reports, and generated outputs.",
            "Preserved legitimate commits, checksums, signing hashes, dependency identities, and Glacial fingerprints only through explicit field-specific validation; digest-like characters or prefixes alone no longer grant trusted treatment.",
            "Added actual installed path inventory and an exact-confirmation application-state reset with a mandatory recovery backup; project files, backups, and logs remain untouched.",
            "Advanced SQLite state to schema version 2 through an ordered idempotent migration and documented the current-user NSIS default-retention and optional data-removal boundaries.",
            "Recorded focused one-host installed upgrade/reset/reinstall/default-uninstall evidence while retaining deterministic remediation packages, the installed-only product boundary, and the NOT READY verdict.",
        ],
    },
    {
        "version": "0.9.5",
        "date": "2026-07-27",
        "title": "Data privacy and disclosure boundary",
        "changes": [
            "Centralized secret redaction, safe path presentation, bounded evidence, and sanitized error/diagnostic handling across persisted scans, reports, remediation outputs, generated instructions, and release records.",
            "Added hostile fake-canary coverage for credentials, host paths, control characters, filenames, dependency metadata, user-authored state, archives, and diagnostics while retaining useful relative paths, rule IDs, line numbers, counts, identities, hashes, and stable ordering.",
            "Published the canonical privacy-surface inventory and network boundary; Glacial remains pre-v1 and NOT READY while other P1 requirements remain unresolved.",
        ],
    },
    {
        "version": "0.9.4",
        "date": "2026-07-27",
        "title": "Installed-only Windows product scope",
        "changes": [
            "Retired the portable binary distribution and narrowed the supported v1 Windows product to the installed NSIS edition.",
            "Removed portable archive construction, signing, hashing, validation, publication, development commands, and duplicate artifact acceptance while preserving internal unpacked build staging.",
            "Reduced ambiguous state locations, relocation behavior, filesystem compatibility problems, duplicate artifact testing, and unclear upgrade/uninstall semantics; Glacial remains pre-v1 and NOT READY while installed-edition lifecycle acceptance is incomplete.",
        ],
    },
    {
        "version": "0.9.3",
        "date": "2026-07-27",
        "title": "Versioned state lifecycle and recovery",
        "changes": [
            "Introduced authoritative SQLite PRAGMA user_version schema versioning with conservative migration of supported unversioned Glacial databases.",
            "Added verified pre-migration backups, transactional schema publication, fail-closed future/corrupt-state handling, and focused rollback evidence for multi-record state mutations.",
            "Published the application-state lifecycle and recovery policy, clarified the remediation-reader readiness contract, and added a mandatory pre-release-candidate Deep Security Scan gate; Glacial remains NOT READY while P1 work remains.",
        ],
    },
    {
        "version": "0.9.2",
        "date": "2026-07-27",
        "title": "Remediation policy closure and PostCSS remediation",
        "changes": [
            "Accepted the bounded 100-finding v1 remediation preview and package policy with explicit unresolved, included, and omitted counts and focused boundary evidence.",
            "Published independent Agent Remediation Brief and Package format compatibility, reader, retention, and deprecation rules while retaining package format 1.0.0.",
            "Narrowly remediated the PostCSS advisory through an exact transitive override; Glacial remains NOT READY for v1.0 while P1 work remains.",
        ],
    },
    {
        "version": "0.9.1",
        "date": "2026-07-27",
        "title": "v1.0 readiness contract and gap audit",
        "changes": [
            "Added a measurable v1.0 readiness contract with permanent requirement identifiers across product, scanning, filesystem, data, remediation, desktop, security, release, documentation, and usability boundaries.",
            "Audited current evidence into matching human-readable and machine-readable gap snapshots without treating unknowns, accepted limitations, or unrun release acceptance as passes.",
            "Published a bounded G045-and-later remediation sequence for the remaining release blockers and explicit owner decisions; this planning milestone does not claim v1.0 readiness.",
        ],
    },
    {
        "version": "0.9.0",
        "date": "2026-07-26",
        "title": "Agent Remediation Package",
        "changes": [
            "Added a deterministic data-only ZIP export containing a versioned machine-readable finding set, package manifest, and exact-byte checksums.",
            "Bound package generation to the immutable Agent Remediation Brief preview snapshot and fail closed when scan, project, finding, coverage, or review state becomes stale.",
            "Preserved the existing human-readable brief preview, copy, and standalone Markdown export without launching an agent or modifying the selected project.",
        ],
    },
    {
        "version": "0.8.2",
        "title": "Public release candidate trust gate",
        "changes": [
            "Separated internal signed-preview and public-rc release profiles with strict explicit command-line selection.",
            "Required verified signer trust classified exactly as publicly-trusted before any public-RC build or artifact-producing release step.",
            "Recorded release profile and trust requirements honestly while preserving the existing signed-preview, timestamp, signature, payload, and atomic-publication checks.",
        ],
    },
    {
        "version": "0.8.1",
        "title": "Remediation Brief correctness",
        "changes": [
            "Included freshly reconstructed canonical severity rationales in generated remediation briefs without inventing rationale for legacy or malformed findings.",
            "Read project, requested scan, latest-scan identity, and finding reviews through one explicit SQLite read snapshot before brief generation.",
            "Preserved endpoint schemas, finding and review semantics, evidence safety, frontend behavior, and the database schema.",
        ],
    },
    {
        "version": "0.8.0",
        "title": "Agent Remediation Brief",
        "changes": [
            "Added an explicit latest-scan Review action that previews backend-authored Markdown before copy or download without launching an agent or writing into the scanned project.",
            "Included deterministically ordered unresolved findings using canonical bounded scanner explanations, conservative legacy fallback, inert evidence fencing, secret redaction, and explicit coverage limitations.",
            "Kept scans, findings, reviews, checkpoints, baselines, dependencies, expectations, risk, completeness, activity, and AGENTS.md behavior unchanged.",
        ],
    },
    {
        "version": "0.7.3",
        "title": "Finding Explainability correction",
        "changes": [
            "Collapsed canonical and legacy explanation content behind an accessible native disclosure while keeping review controls immediately available.",
            "Reconstructed accepted canonical explanation prose from backend scanner-owned metadata and rejected semantically altered persisted envelopes.",
            "Preserved conservative legacy fallback, finding fingerprints, review linkage, detector coverage, severity, risk, and completeness behavior.",
        ],
    },
    {
        "version": "0.7.2",
        "title": "Finding Explainability",
        "changes": [
            "Added a bounded scanner-owned explanation envelope to every newly generated finding with stable rule provenance, observed evidence, impact, severity rationale, manual inspection guidance, and limitations.",
            "Persisted finding explanations in the existing scan JSON without relational migrations or detector, severity, execution, or remediation changes.",
            "Preferred canonical backend explanations in finding cards and Markdown while retaining explicit conservative fallback presentation for older scans.",
        ],
    },
    {
        "version": "0.7.1",
        "title": "Review context correctness",
        "changes": [
            "Determined Review scan presence from the actual latest scan rather than timestamp metadata.",
            "Kept scans with missing or malformed timestamps in a started, fail-closed Review state with indeterminate timestamp presentation.",
            "Separated latest Review evidence from historical Reports export and copy controls while preserving the historical Reports selection.",
        ],
    },
    {
        "version": "0.7.0",
        "title": "Guided Review Workspace",
        "changes": [
            "Added a canonical Review destination summarizing the latest Project Security Status, prioritized next action, and six-section evidence path.",
            "Linked Review actions to existing finding, dependency, Project Expectations, drift, baseline, comparison, and scan surfaces without automatic mutations.",
            "Integrated checkpoint state, explicit eligible checkpoint creation, bounded ineligible reasons, and compact recent history into Review.",
            "Opened Review after successful scans and reduced the older guided checklist to a compact, locally dismissible Review link.",
            "Kept readiness and checkpoints conservative review records rather than certifications or security guarantees.",
        ],
    },
    {
        "version": "0.6.9",
        "title": "Review checkpoint eligibility correction",
        "changes": [
            "Aligned backend checkpoint eligibility with canonical Project Security Status boundaries for dependency applicability and new critical/high findings.",
            "Represented no supported dependency metadata explicitly without fabricating an approval fingerprint.",
            "Added bounded baseline-finding identities and fail-closed handling for malformed historical finding evidence.",
            "Made client-supplied Ready status non-authoritative; persisted normalized evidence now determines eligibility.",
        ],
    },
    {
        "version": "0.6.8",
        "title": "Project review checkpoints",
        "changes": [
            "Added immutable project-scoped checkpoints for manually reviewed evidence when Project Security Status is exactly Ready for reviewed work.",
            "Added conservative Current, Review required, Indeterminate, and No checkpoint states over normalized scan, baseline, expectation, dependency, finding-review, coverage, and metadata identities.",
            "Added an explicit evidence preview, bounded read-only checkpoint history, duplicate prevention, and one atomic project activity event per successful checkpoint.",
            "Kept checkpoints separate from approvals, risk acceptance, remediation, project trust, and any permission to execute project code.",
        ],
    },
    {
        "version": "0.6.7",
        "title": "Project security status summary",
        "changes": [
            "Added a compact conservative work-readiness summary over existing persisted scan, review, dependency, expectation, and baseline evidence.",
            "Added independent Scan coverage, Findings, Dependencies, Project Expectations, Baseline and drift, and Review completion evidence sections.",
            "Prioritized incomplete scans and insufficient evidence before significant changes, remaining review work, or Ready for reviewed work.",
            "Added up to three state-specific navigation actions without creating scores, approvals, activity events, cached status, or project-state writes.",
        ],
    },
    {
        "version": "0.6.6",
        "title": "Trusted scan baseline management",
        "changes": [
            "Added one deliberate project-level trusted scan reference for complete, structurally reliable scans.",
            "Added explicit set, atomic replacement, and clear workflows with compact confirmation previews and bounded activity events.",
            "Made the exact trusted scan take precedence in Project Expectations without silently substituting an automatic baseline when the reference is invalid or unavailable.",
            "Integrated read-only latest-to-trusted comparison preselection while preserving scans, findings, reviews, expectations, dependency approval, coverage, and trust state.",
        ],
    },
    {
        "version": "0.6.5",
        "title": "Explicit scan comparison",
        "changes": [
            "Added a read-only Scan Comparison view for two explicitly selected scans from the same project.",
            "Compared persisted findings, normalized dependency inventories, exact available coverage counts, and all seven expectation-backed metadata categories.",
            "Added independent Comparable, Partially comparable, Indeterminate, and Unavailable reliability states that never infer removals or resolutions from incomplete scans.",
            "Kept comparisons bounded, conservatively renderable, chronologically ordered, and free of scan, review, expectation, dependency-approval, trust, or activity mutations.",
        ],
    },
    {
        "version": "0.6.4",
        "title": "Project activity timeline",
        "changes": [
            "Added a compact read-only Activity view that merges project registration and persisted scans with meaningful project events.",
            "Added append-only, project-scoped events for material Project Expectations updates, observed drift adoption, first finding-review completion, and dependency approval.",
            "Added deterministic newest-first pagination with bounded, conservatively rendered event details and scan linkage.",
            "Avoided events for navigation, previews, dismissals, no-op saves, individual finding decisions, and transient errors.",
        ],
    },
    {
        "version": "0.6.3",
        "title": "Selective project drift adoption",
        "changes": [
            "Added per-value adoption actions for reliable drift across all seven Project Expectations categories.",
            "Added an explicit preview of values added, removed or replaced, and the resulting approved expectations before confirmation.",
            "Kept incomplete and historical observations read-only and omitted any bulk drift-adoption action.",
            "Preserved scan evidence, findings, raw risk, review state, coverage, dependency approval, dismissal state, and expectation provenance.",
        ],
    },
    {
        "version": "0.6.2",
        "title": "Project drift summary",
        "changes": [
            "Added a conservative scan-to-scan summary across the existing Project Expectations metadata categories.",
            "Added a separate comparison between reliable observations and user-approved Project Expectations without changing approvals or dismissed suggestions.",
            "Included the same observed-versus-approved distinction and indeterminate states in Markdown scan reports.",
            "Preserved findings, raw risk, review state, coverage, dependency approval, and review-completion behavior.",
        ],
    },
    {
        "version": "0.5.0",
        "title": "Guided finding review",
        "changes": [
            "Added a unified finding-review workbench with deterministic prioritization, search, filters, next-unresolved navigation, and persisted review and reopen behavior.",
            "Added bounded, redacted suspicious-text scanner context to findings, the Reports interface, and Markdown exports without changing finding identity.",
            "Added conservative review-completion criteria that keep coverage gaps and applicable dependency-baseline approval visible.",
            "Added a dismissible five-step guided-review checklist, clearer first-project and first-scan flow, and conservative historical-scan summaries.",
            "Improved responsive desktop and narrow-width layouts while preserving category detail views and existing security boundaries.",
        ],
    },
    {
        "version": "0.4.0",
        "title": "Glacial by Icefields",
        "changes": [
            "Adopted the new Glacial application icon across desktop and Windows packaging assets.",
            "Added restrained Icefields and icefields.dev product branding and package metadata.",
            "Preserved local-only operation, authenticated desktop behavior, scanner safeguards, and NSIS-only packaging.",
        ],
    },
    {
        "version": "0.3.0",
        "title": "Fail-closed scanning and authenticated development",
        "changes": [
            "Repository-policy exclusions remain visible and now make scan coverage incomplete and unverified.",
            "Malformed, non-object, invalid-UTF-8, and excessively nested package manifests now produce conservative inspection evidence instead of aborting scans.",
            "Scanner resource budgets now stop safely, preserve findings collected before the stop, and report incomplete coverage.",
            "Trusted dependency baselines now include opaque VCS selector and resolved-revision identity; schema-1 baselines require explicit recreation or reapproval.",
            "Missing, empty, or malformed backend authentication now fails closed.",
            "The supported authenticated full-stack workflow is npm.cmd run tauri:dev; direct browser-to-Uvicorn development is unsupported.",
            "Added SECURITY.md to define hostile repository inputs, local API authentication, workspace-root assumptions, privilege expectations, and supported deployment boundaries.",
        ],
    },
    {
        "version": "0.11",
        "title": "Scanner report polish",
        "changes": [
            "Added Markdown scan report export and Copy Markdown report actions.",
            "Added concise scanner card guidance for review context.",
            "Cleaned public-facing setup and workspace-root documentation.",
        ],
    },
    {
        "version": "0.10",
        "title": "Latest scan comparison",
        "changes": [
            "Added a Changed since previous scan section comparing the newest scan with the immediately previous scan for the same project.",
            "Showed risk change, finding count delta, reviewed count delta, ignored count delta, and finding-type summary changes.",
            "Used compact scan history metadata only, with no raw file contents or compromise detection claims.",
        ],
    },
    {
        "version": "0.09",
        "title": "Risk explanation",
        "changes": [
            "Added a concise Why this risk? section near the scan summary.",
            "Explained LOW risk with reassuring scan signals and MEDIUM/HIGH risk with contributing finding types.",
            "Kept explanations as review context, not compromise or malware detection claims.",
        ],
    },
    {
        "version": "0.08",
        "title": "Scan history metadata",
        "changes": [
            "Stored recent scan history locally with timestamp, risk, finding count, reviewed count, ignored count, and finding-type summary.",
            "Added compact risk-change markers when a scan risk differs from the previous scan.",
            "Kept scan history metadata-only; older rows may show zero or unavailable metadata for fields added later.",
        ],
    },
    {
        "version": "0.07",
        "title": "Grouped scanner dashboard",
        "changes": [
            "Grouped scan results into overall risk, manifests, lockfiles, lifecycle scripts, secret findings, executable files, and zone/metadata sections.",
            "Added expandable reviewed and ignored file details near the scan summary.",
            "Added .glacialignore support for known-safe local scanner noise; ignored files are neutral, not suspicious by default.",
        ],
    },
    {
        "version": "0.06",
        "title": "Bugfix pass",
        "changes": [
            "Case-insensitive scanner skip directories.",
            "Scan history finding normalization.",
            "Frontend stale selected project cleanup.",
            "Unexpected severity tolerance.",
        ],
    },
    {
        "version": "0.05",
        "title": "AGENTS.md end-to-end review/manual test notes",
        "changes": [
            "Reviewed AGENTS.md preview and write flow.",
            "Added manual test notes for project creation, AGENTS.md generation, overwrite behavior, and scanning.",
        ],
    },
    {
        "version": "0.04",
        "title": "Workspace root correction",
        "changes": [
            "Changed the default workspace root to a neutral app-specific folder under the user's home directory.",
            "Validated selected projects under the configured workspace root.",
        ],
    },
    {
        "version": "0.03",
        "title": "AGENTS.md generator",
        "changes": [
            "Added AGENTS.md preview and write endpoints.",
            "Added frontend form with overwrite confirmation.",
        ],
    },
    {
        "version": "0.02",
        "title": "Scanner implementation",
        "changes": [
            "Added read-only project risk scanning.",
            "Added scan report display and scan history storage.",
        ],
    },
    {
        "version": "0.01",
        "title": "MVP scaffold",
        "changes": [
            "Added FastAPI backend, React/Vite frontend, and SQLite storage.",
            "Added local project dashboard and project creation flow.",
        ],
    },
]
