# CodexForge

CodexForge is a local-first project dashboard for safely managing Codex and AI-generated coding projects inside a VM or local development environment.

It is designed to read project metadata and scan files without executing project code, package scripts, installers, or shell files.

## Why CodexForge Exists
AI coding agents are more useful when they have clear project instructions, boundaries, build commands, test commands, and security expectations. CodexForge helps developers generate those instructions in a repeatable way while keeping file access local, scoped, and reviewable.

# Current Status

CodexForge is an early stage open source project. It currently focuses on local project scanning and safe AGENTS.md generation.



## Stack

- Frontend: React + Vite
- Backend: Python FastAPI
- Database: SQLite
- Canonical workspace root: `Z:\CodexProjects`

## Safety Model

- CodexForge runs locally only.
- It does not add telemetry or cloud services.
- Scans only read files.
- It never runs package scripts, project commands, installers, or scanned project code.
- Project access is limited to the configured workspace root.
- Folder creation sanitizes project names and prevents path traversal.

## Windows / Icefields Setup

Open two PowerShell terminals from this repository.

CodexForge is configured for projects under `Z:\CodexProjects`.

### Backend

```powershell
cd backend
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.lock.txt
.\.venv\Scripts\python.exe -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

If `requirements.lock.txt` is not present, install from `requirements.txt` instead. The API runs at `http://127.0.0.1:8000`.

### Frontend

```powershell
cd frontend
npm.cmd install --ignore-scripts
npm.cmd run dev
```

The app runs at `http://127.0.0.1:5173`.

## Notes

- CodexForge stores its SQLite database at `backend/data/codexforge.db`.
- The canonical workspace root is `Z:\CodexProjects`. If it does not exist, the dashboard shows a clear message and does not create it until you create a project.
- Creating a project will create the configured workspace root folder if needed.
- The scanner highlights files and patterns for review; it does not claim that every finding is malicious.
- The AGENTS.md generator previews Markdown before writing. Existing AGENTS.md files require explicit overwrite confirmation.

## Manual Test Notes

Use a small throwaway project folder under `Z:\CodexProjects` for these checks.

1. Create a project:
   - Start the backend and frontend.
   - Enter a project name, description, and project type.
   - Select Create.
   - Confirm a sanitized folder appears under `Z:\CodexProjects` and the dashboard lists it by absolute path.

2. Preview AGENTS.md:
   - Select the test project.
   - Fill in project purpose, project rules, build commands, test commands, and security notes.
   - Select Preview.
   - Confirm Markdown appears in the preview area and no `AGENTS.md` file is written yet.

3. Write AGENTS.md:
   - After previewing, select Write AGENTS.md.
   - Confirm the success message appears.
   - Confirm `Z:\CodexProjects\<ProjectName>\AGENTS.md` exists and contains the previewed sections.

4. Confirm overwrite behavior:
   - With `AGENTS.md` already present, edit a field and preview again.
   - Select Write AGENTS.md.
   - Confirm the browser asks before overwriting.
   - Cancel once and confirm the file is unchanged, then repeat and confirm overwrite to verify the file updates.

5. Scan a test project:
   - Add harmless sample files such as a `package.json` with a `postinstall` script, a `.env` file, or a `.ps1` file.
   - Select Scan.
   - Confirm the report groups findings by severity and explains what to review.
