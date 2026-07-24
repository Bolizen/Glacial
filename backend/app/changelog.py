from __future__ import annotations

CHANGELOG_ENTRIES = [
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
