from __future__ import annotations

CHANGELOG_ENTRIES = [
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
            "Added .codexforgeignore support for known-safe local scanner noise; ignored files are neutral, not suspicious by default.",
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
