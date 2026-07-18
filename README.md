# Glacial

Glacial is a local-first safety dashboard for reviewing Codex and AI-generated coding projects before running anything in a development environment.

It is designed to read project metadata and scan files without executing project code, package scripts, installers, or shell files.

## Why Glacial Exists
AI coding agents are more useful when generated work is easy to review before execution. Glacial keeps project access local, scoped, and reviewable while surfacing scanner findings, project metadata, notes, and AGENTS.md instructions in one dashboard.

# Current Status

Glacial is an early stage local-first project focused on project scanning, safety review, and safe AGENTS.md generation.

## Licensing

Glacial v0.2.0 is licensed under the Functional Source License, Version 1.1, ALv2 Future License (`FSL-1.1-ALv2`). It is Fair Source and source-available, but it is not presently OSI open source.

Internal use, study, modification, and redistribution are permitted subject to the license. Offering Glacial, or substantially similar functionality, to others as a competing commercial product or service is not permitted under the public license. Separate commercial licensing may be available from the copyright holder.

Each software version becomes available under the Apache License, Version 2.0 on the second anniversary of the date that version was made available. The root `LICENSE` file is authoritative if this summary and the license text ever appear inconsistent.



## Stack

- Frontend: React + Vite
- Backend: Python FastAPI
- Database: SQLite
- Default workspace root: `~/GlacialProjects`

## Safety Model

- Glacial runs locally only.
- It does not add telemetry or cloud services.
- Scans only read files.
- It never runs package scripts, project commands, installers, or scanned project code.
- Project access is limited to the configured workspace root.
- Folder creation sanitizes project names and prevents path traversal.

## Setup

Clone the repository and open two terminals from the repo root.

Clean-room setup and verification have been completed with Python 3.12.13 and Python 3.13.13, Node.js 24.16.0, and npm 11.13.0. These are verified versions, not declared minimum-version guarantees.

```bash
git clone https://github.com/Bolizen/Glacial.git Glacial
cd Glacial
```

### Backend

PowerShell:

```powershell
cd backend
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.lock.txt
.\.venv\Scripts\python.exe -m pip check
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
.\.venv\Scripts\python.exe -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

If `python` is not available as a Windows command, try `py -3 -m venv .venv`. If neither launcher is on `PATH`, invoke an installed Python executable by its full path to create `.venv`; use `.\.venv\Scripts\python.exe` for all remaining backend commands.

macOS/Linux:

```bash
cd backend
python -m venv .venv
./.venv/bin/python -m pip install -r requirements.lock.txt
./.venv/bin/python -m pip check
./.venv/bin/python -m unittest discover -s tests -v
./.venv/bin/python -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

If `requirements.lock.txt` is not present, install from `requirements.txt` instead. The API runs at `http://127.0.0.1:8000` by default. On Windows without permission to create symlinks, three real symlink integration tests are expected to skip; the deterministic link and reparse-point tests still run.

### Frontend

```bash
cd frontend
npm ci --ignore-scripts
npm test
npm run build
npm audit --ignore-scripts
npm run dev
```

On Windows PowerShell, use the corresponding `npm.cmd ci --ignore-scripts`, `npm.cmd test`, `npm.cmd run build`, `npm.cmd audit --ignore-scripts`, and `npm.cmd run dev` commands.

The app runs at `http://127.0.0.1:5173`.

### Local service configuration

The frontend sends API requests to `http://127.0.0.1:8000` by default. Set `VITE_API_BASE_URL` before `npm run dev` or `npm run build` to use another backend base URL:

```powershell
$env:VITE_API_BASE_URL = "http://127.0.0.1:8010"
npm.cmd run dev
```

The backend accepts browser requests from `http://127.0.0.1:5173` and `http://localhost:5173` by default. Set `GLACIAL_CORS_ORIGINS` to a comma-separated list of explicit HTTP or HTTPS origins when the frontend uses other origins. Wildcards, credentials, paths, queries, and fragments are rejected.

```powershell
$env:GLACIAL_CORS_ORIGINS = "http://127.0.0.1:5174,http://localhost:5174"
.\.venv\Scripts\python.exe -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

The documented default ports remain `8000` for the backend and `5173` for the frontend.

## Notes

- Glacial stores its SQLite database at `backend/data/glacial.db`.
- The default workspace root is `~/GlacialProjects`. You can configure a different absolute workspace root in the app.
- Settings validates workspace-root changes through the backend. Changing roots clears visible project state but never moves or deletes project folders.
- Project descriptions and project types can be edited from the Projects screen. Unregister removes Glacial database records only; project files remain untouched, including when the registered folder is unavailable.
- Registered folders that are missing or unsafe remain visible with an unavailable status so they can be unregistered.
- Active scans disable duplicate submissions and show a scanning state. Backend reachability is checked at startup and can be retried without polling.
- Projects with no scan are labelled `Not scanned`; risk and scan-coverage status are displayed separately.
- The frontend restores the last valid project, section, historical scan, and panel layout for the configured workspace. Settings can reset only this saved UI state without changing backend data or configuration.
- If the configured workspace root does not exist, the dashboard shows a clear message and does not create it until you create a project.
- Creating a project will create the configured workspace root folder if needed.
- The scanner dashboard groups scan results by overall risk, manifests, lockfiles, lifecycle scripts, secret findings, executable files, zone/metadata findings, reviewed files, and ignored files.
- Dependency Trust performs bounded structural and heuristic inspection of local Node metadata (`package.json`, npm lock/shrinkwrap versions 1-3) and Python metadata (`requirements*.txt`, `requirements/*.txt`, `pyproject.toml`, `poetry.lock`, `Pipfile`, and `Pipfile.lock`). It reports locally supportable manifest/lock consistency, source types and safe host names, integrity coverage, install-script indicators present in npm locks, and changes from the newest compatible scan of the same project. npm v1 root/group evidence is limited, and common requirements/PEP 621/Poetry/Pipenv syntax is recognized without claiming full semver, PEP 508, or package-manager resolution. Pyproject build requirements and dependency groups, non-npm lock formats, workspace graphs, and unsupported requirements options are disclosed as incomplete rather than normalized as an empty or clean dependency set.
- A complete supported dependency snapshot can be explicitly approved as the project’s trusted dependency baseline. Glacial never creates or replaces this baseline automatically; later current and historical scans compare against the active baseline separately from previous-scan comparison. Approval does not claim that packages are safe or malware-free.
- Trusted baseline fingerprints use a versioned `cfdb2_` SHA-256 identity over bounded, deterministically ordered dependency-analysis schema data, project-relative manifest and lockfile identities, package-manager metadata, normalized dependency specifications, versions, safe source identities, opaque typed VCS selector and resolved-revision digests, integrity values, and relevant flags. Timestamps, display wording, scan findings, review state, prior-scan comparisons, absolute paths, credentials, URL queries, fragments, and raw VCS selector values are excluded. Older baseline schemas require explicit reapproval.
- Dependency analysis is offline and evidence-limited: custom registries, local paths, VCS sources, URLs, unpinned specifications, and metadata changes are review prompts rather than malware verdicts. Glacial does not contact registries, evaluate package reputation, install dependencies, inspect installed dependency code, or execute project code.
- Unsupported, malformed, unsafe, unreadable, or oversized dependency inputs are disclosed as unavailable or incomplete analysis and participate in scan completeness. Older scan history remains readable with Dependency Trust shown as unavailable rather than clean.
- The "Why this risk?" explanation uses existing scan metadata and findings: LOW risk can call out reassuring signals such as no lifecycle scripts, no secret-looking files, no executables, and reviewed manifests or lockfiles; MEDIUM/HIGH risk summarizes contributing finding types.
- Recent scans are stored locally in SQLite as compact metadata: timestamp, overall risk, finding count, reviewed file count, ignored file count, finding-type summary, and risk-change marker.
- The "Changed since previous scan" section compares the newest scan with the immediately previous scan for the same project, showing risk change, count deltas, and finding-type summary changes. If there is no previous scan, it shows a friendly empty state.
- Copied and downloaded Markdown reports include every scanner finding with its severity, type, path, explanation, recommended action, and available metadata, plus the compact offline Dependency Trust summary, previous-scan changes, and separately labelled trusted-baseline status and drift evidence.
- Individual findings can be marked reviewed or reviewed as expected with an optional reason. Reviews are project-scoped and match only a versioned SHA-256 fingerprint of the finding type, project-relative path, severity, and stable scanner evidence; display wording, timestamps, absolute host context, and the raw evidence itself are not exposed by the fingerprint. Changing the path, finding type, matched pattern, or other identity evidence makes the finding unreviewed again.
- Fingerprint paths normalize `/` and `\\` separators but preserve letter case, so a case-only path change is intentionally treated as changed evidence on every platform. Severity is also identity-defining: a scanner policy change that alters severity requires a fresh review rather than carrying forward an acknowledgement made under a different risk classification.
- Finding reviews preserve the original evidence, severity, and raw risk. The dashboard and Markdown report show raw risk separately from reviewed and unresolved counts and the highest unreviewed severity. Exact finding reviews are separate from Trust Profile reviewed paths, which remain broad project expectations and never acknowledge a scanner finding automatically.
- Scan results distinguish complete coverage, incomplete coverage with inspection-issue counts, and older scans whose coverage is unknown. A file is counted as reviewed only after its intended filename-only or content inspection succeeds; ignored and safely rejected linked paths are not reviewed.
- General scans use deterministic resource ceilings of 50,000 directories, 100,000 files, 150,000 filesystem entries, 512 MiB of inspected content, 10,000 ordinary findings, and 100,000 accumulated path/result records. These defaults accommodate large source trees after generated/vendor exclusions while bounding hostile-repository work. `.glacialignore` is limited to 256 KiB and 10,000 distinct normalized patterns; an over-limit policy is rejected in full and makes coverage incomplete rather than suppressing inspection.
- Older scan rows may show unavailable or zero metadata for fields added after those scans were created. Scan history does not store full file contents.
- Findings are review prompts, not proof of compromise, and the scanner is not a malware detector.
- `.glacialignore` can suppress known-safe local or self-referential scanner noise. Ignored files remain visible and are treated neutrally for risk, but each repository-policy exclusion is an explicit completeness gap, so that scan cannot be reported as complete.
- The AGENTS.md generator previews Markdown before writing. Existing AGENTS.md files require explicit overwrite confirmation.

## Manual Test Notes

Use a small throwaway project folder under `<workspace-root>` for these checks, such as `~/GlacialProjects/<project-name>`.

1. Create a project:
   - Start the backend and frontend.
   - Enter a project name, description, and project type.
   - Select Create.
   - Confirm a sanitized folder appears under `<workspace-root>` and the dashboard lists it by absolute path.

2. Preview AGENTS.md:
   - Select the test project.
   - Fill in project purpose, project rules, build commands, test commands, and security notes.
   - Select Preview.
   - Confirm Markdown appears in the preview area and no `AGENTS.md` file is written yet.

3. Write AGENTS.md:
   - After previewing, select Write AGENTS.md.
   - Confirm the success message appears.
   - Confirm `<workspace-root>/<project-name>/AGENTS.md` exists and contains the previewed sections.

4. Confirm overwrite behavior:
   - With `AGENTS.md` already present, edit a field and preview again.
   - Select Write AGENTS.md.
   - Confirm the browser asks before overwriting.
   - Cancel once and confirm the file is unchanged, then repeat and confirm overwrite to verify the file updates.

5. Scan a test project:
   - Add harmless sample files such as a `package.json` with a `postinstall` script, a `.env` file, or a `.ps1` file.
   - Select Scan.
   - Confirm the report shows overall risk, grouped scan sections, and expandable reviewed and ignored file details.
