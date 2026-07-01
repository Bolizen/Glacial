from __future__ import annotations

CHANGELOG_ENTRIES = [
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
        "title": r"Workspace root correction to C:\CodeProjects",
        "changes": [
            r"Changed the default workspace root to C:\CodeProjects.",
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
