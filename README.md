# CodexForge

CodexForge is a local-first safety dashboard for reviewing Codex and AI-generated coding projects before running anything in a development environment.

It is designed to read project metadata and scan files without executing project code, package scripts, installers, or shell files.

## Why CodexForge Exists
AI coding agents are more useful when generated work is easy to review before execution. CodexForge keeps project access local, scoped, and reviewable while surfacing scanner findings, project metadata, notes, and AGENTS.md instructions in one dashboard.

# Current Status

CodexForge is an early stage open source project. It currently focuses on local-first project scanning, safety review, and safe AGENTS.md generation.



## Stack

- Frontend: React + Vite
- Backend: Python FastAPI
- Database: SQLite
- Default workspace root: `~/CodexForgeProjects`

## Safety Model

- CodexForge runs locally only.
- It does not add telemetry or cloud services.
- Scans only read files.
- It never runs package scripts, project commands, installers, or scanned project code.
- Project access is limited to the configured workspace root.
- Folder creation sanitizes project names and prevents path traversal.

## Setup

Clone the repository and open two terminals from the repo root.

```bash
git clone <repo-url>
cd CodexForge
```

### Backend

PowerShell:

```powershell
cd backend
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.lock.txt
.\.venv\Scripts\python.exe -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

macOS/Linux:

```bash
cd backend
python -m venv .venv
./.venv/bin/python -m pip install -r requirements.lock.txt
./.venv/bin/python -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

If `requirements.lock.txt` is not present, install from `requirements.txt` instead. The API runs at `http://127.0.0.1:8000`.

### Frontend

```bash
cd frontend
npm install --ignore-scripts
npm run dev
```

On Windows PowerShell, use `npm.cmd install --ignore-scripts` and `npm.cmd run dev`.

The app runs at `http://127.0.0.1:5173`.

## Notes

- CodexForge stores its SQLite database at `backend/data/codexforge.db`.
- The default workspace root is `~/CodexForgeProjects`. You can configure a different absolute workspace root in the app.
- If the configured workspace root does not exist, the dashboard shows a clear message and does not create it until you create a project.
- Creating a project will create the configured workspace root folder if needed.
- The scanner dashboard groups scan results by overall risk, manifests, lockfiles, lifecycle scripts, secret findings, executable files, zone/metadata findings, reviewed files, and ignored files.
- The "Why this risk?" explanation uses existing scan metadata and findings: LOW risk can call out reassuring signals such as no lifecycle scripts, no secret-looking files, no executables, and reviewed manifests or lockfiles; MEDIUM/HIGH risk summarizes contributing finding types.
- Recent scans are stored locally in SQLite as compact metadata: timestamp, overall risk, finding count, reviewed file count, ignored file count, finding-type summary, and risk-change marker.
- The "Changed since previous scan" section compares the newest scan with the immediately previous scan for the same project, showing risk change, count deltas, and finding-type summary changes. If there is no previous scan, it shows a friendly empty state.
- Copied and downloaded Markdown reports include every scanner finding with its severity, type, path, explanation, recommended action, and available metadata.
- Scan results distinguish complete coverage, incomplete coverage with inspection-issue counts, and older scans whose coverage is unknown. A file is counted as reviewed only after its intended filename-only or content inspection succeeds; ignored and safely rejected linked paths are not reviewed.
- Older scan rows may show unavailable or zero metadata for fields added after those scans were created. Scan history does not store full file contents.
- Findings are review prompts, not proof of compromise, and the scanner is not a malware detector.
- `.codexforgeignore` can suppress known-safe local or self-referential scanner noise. Ignored files are treated neutrally, not as suspicious by default.
- The AGENTS.md generator previews Markdown before writing. Existing AGENTS.md files require explicit overwrite confirmation.

## Manual Test Notes

Use a small throwaway project folder under `<workspace-root>` for these checks, such as `~/CodexForgeProjects/<project-name>`.

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
