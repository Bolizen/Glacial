from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware

from .agents import generate_agents_md
from .changelog import CHANGELOG_ENTRIES
from .database import (
    WORKSPACE_ROOT_SETTING,
    get_connection,
    get_setting,
    init_db,
    latest_scan_map,
    note_counts,
    row_to_scan,
    set_setting,
)
from .safety import configured_root, ensure_inside_root, ensure_project_directory, sanitize_folder_name
from .scanner import scan_project
from .schemas import AgentPreviewRequest, NoteCreate, ProjectCreate, ProjectPathRequest, ProjectRootUpdate, TrustProfileRequest


app = FastAPI(title="CodexForge API")

TRUST_PROFILE_FIELDS = (
    "trustedPackageManagers",
    "expectedManifestFiles",
    "expectedLockfiles",
    "allowedLifecycleScripts",
    "reviewedPaths",
    "ignoredPaths",
)
RISK_TOLERANCES = {"cautious", "normal", "permissive"}

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://127.0.0.1:5173", "http://localhost:5173"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
def startup() -> None:
    init_db()


@app.get("/api/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/api/config")
def get_config() -> dict[str, str]:
    return {"project_root": _project_root_value()}


@app.get("/api/changelog")
def get_changelog() -> dict[str, object]:
    return {"entries": CHANGELOG_ENTRIES}


@app.put("/api/config/project-root")
def update_project_root(payload: ProjectRootUpdate) -> dict[str, str]:
    root = configured_root(payload.project_root)
    set_setting(WORKSPACE_ROOT_SETTING, str(root))
    return {"project_root": str(root)}


@app.get("/api/projects")
def list_projects() -> dict[str, object]:
    root = _project_root()
    scans = latest_scan_map()
    counts = note_counts()
    metadata = _project_metadata()

    projects = []
    root_exists = root.exists()
    if root_exists:
        for child in sorted(root.iterdir(), key=lambda path: path.name.lower()):
            if not child.is_dir():
                continue
            path = str(child.resolve())
            scan = scans.get(path)
            project_meta = metadata.get(path, {})
            projects.append(
                {
                    "name": project_meta.get("name") or child.name,
                    "path": path,
                    "description": project_meta.get("description", ""),
                    "project_type": project_meta.get("project_type", ""),
                    "last_scan_time": scan["scan_date"] if scan else None,
                    "last_risk_level": scan["overall_risk"] if scan else "none",
                    "notes_count": counts.get(path, 0),
                }
            )

    return {
        "project_root": str(root),
        "root_exists": root_exists,
        "message": None if root_exists else "Workspace root does not exist yet. Create a project to create it.",
        "projects": projects,
    }


@app.post("/api/projects")
def create_project(payload: ProjectCreate) -> dict[str, str]:
    root = _project_root()
    folder_name = sanitize_folder_name(payload.project_name)
    root.mkdir(parents=True, exist_ok=True)

    project_path = ensure_inside_root(root, root / folder_name)
    if project_path.exists():
        raise HTTPException(status_code=409, detail="A project folder with that sanitized name already exists.")

    project_path.mkdir()
    now = _now()
    with get_connection() as connection:
        connection.execute(
            "INSERT INTO projects (path, name, description, project_type, created_at) VALUES (?, ?, ?, ?, ?)",
            (str(project_path), payload.project_name.strip(), payload.description.strip(), payload.project_type.strip(), now),
        )

    return {"name": payload.project_name.strip(), "path": str(project_path), "created_at": now}


@app.post("/api/agents/preview")
def preview_agents(payload: AgentPreviewRequest) -> dict[str, str]:
    _ensure_project(payload.project_path)
    return {"content": _agent_content(payload)}


@app.get("/api/agents/exists")
def agents_exists(project_path: str = Query(min_length=1, max_length=1000)) -> dict[str, object]:
    project = _ensure_project(project_path)
    agents_path = _agents_path(project)
    return {"exists": agents_path.exists(), "path": str(agents_path)}


@app.post("/api/agents/write")
def write_agents(payload: AgentPreviewRequest) -> dict[str, object]:
    project = _ensure_project(payload.project_path)
    agents_path = _agents_path(project)
    if agents_path.exists() and not payload.overwrite:
        return {
            "written": False,
            "confirmation_required": True,
            "path": str(agents_path),
            "message": "AGENTS.md already exists. Confirm overwrite to write a new version.",
        }

    content = _agent_content(payload)
    agents_path.write_text(content, encoding="utf-8")
    return {
        "written": True,
        "confirmation_required": False,
        "path": str(agents_path),
        "content": content,
        "message": "AGENTS.md written successfully.",
    }


@app.post("/api/scans")
def run_scan(payload: ProjectPathRequest) -> dict[str, object]:
    project = _ensure_project(payload.project_path)
    result = scan_project(project)
    now = _now()
    finding_summary = _finding_summary(result["findings"])
    scan_metadata = _scan_metadata(result)
    with get_connection() as connection:
        cursor = connection.execute(
            """
            INSERT INTO scans (
                project_path,
                scan_date,
                overall_risk,
                findings_json,
                finding_count,
                reviewed_file_count,
                ignored_file_count,
                finding_summary_json,
                scan_metadata_json
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                str(project),
                now,
                result["overall_risk"],
                json.dumps(result["findings"]),
                len(result["findings"]),
                result["reviewedFileCount"],
                len(result["ignoredFiles"]),
                json.dumps(finding_summary),
                json.dumps(scan_metadata),
            ),
        )
    return {
        "id": cursor.lastrowid,
        "project_path": str(project),
        "scan_date": now,
        "overall_risk": result["overall_risk"],
        "findings": result["findings"],
        "findingCount": len(result["findings"]),
        "findingSummary": finding_summary,
        "manifests": result["manifests"],
        "lockfiles": result["lockfiles"],
        "lifecycleScripts": result["lifecycleScripts"],
        "secretFiles": result["secretFiles"],
        "ignoredFiles": result["ignoredFiles"],
        "ignoredFileCount": len(result["ignoredFiles"]),
        "reviewedFiles": result["reviewedFiles"],
        "reviewedFileCount": result["reviewedFileCount"],
        "zone": result["zone"],
    }


@app.get("/api/scans/history")
def scan_history(project_path: str = Query(min_length=1, max_length=1000)) -> dict[str, object]:
    project = _ensure_project(project_path)
    with get_connection() as connection:
        rows = connection.execute(
            "SELECT * FROM scans WHERE project_path = ? ORDER BY scan_date DESC LIMIT 20",
            (str(project),),
        ).fetchall()
    return {"scans": [row_to_scan(row) for row in rows]}


@app.get("/api/notes")
def list_notes(project_path: str = Query(min_length=1, max_length=1000)) -> dict[str, object]:
    project = _ensure_project(project_path)
    with get_connection() as connection:
        rows = connection.execute(
            "SELECT id, project_path, body, created_at FROM notes WHERE project_path = ? ORDER BY created_at DESC",
            (str(project),),
        ).fetchall()
    return {"notes": [dict(row) for row in rows]}


@app.get("/api/trust-profile")
def get_trust_profile(project_path: str = Query(min_length=1, max_length=1000)) -> dict[str, object]:
    project = _ensure_project(project_path)
    with get_connection() as connection:
        row = connection.execute(
            "SELECT profile_json, updated_at FROM project_trust_profiles WHERE project_path = ?",
            (str(project),),
        ).fetchone()

    profile = _empty_trust_profile(str(project))
    if not row:
        return profile

    try:
        stored = json.loads(row["profile_json"])
    except (TypeError, json.JSONDecodeError):
        stored = {}
    profile.update(_normalize_trust_profile(stored, str(project)))
    profile["updated_at"] = row["updated_at"]
    return profile


@app.put("/api/trust-profile")
def update_trust_profile(payload: TrustProfileRequest) -> dict[str, object]:
    project = _ensure_project(payload.project_path)
    profile = _normalize_trust_profile(_model_data(payload), str(project))
    now = _now()
    with get_connection() as connection:
        connection.execute(
            "INSERT INTO project_trust_profiles (project_path, profile_json, updated_at) VALUES (?, ?, ?) "
            "ON CONFLICT(project_path) DO UPDATE SET profile_json = excluded.profile_json, updated_at = excluded.updated_at",
            (str(project), json.dumps(_profile_for_storage(profile), sort_keys=True), now),
        )
    return {**profile, "updated_at": now}


@app.post("/api/notes")
def add_note(payload: NoteCreate) -> dict[str, object]:
    project = _ensure_project(payload.project_path)
    now = _now()
    with get_connection() as connection:
        cursor = connection.execute(
            "INSERT INTO notes (project_path, body, created_at) VALUES (?, ?, ?)",
            (str(project), payload.body.strip(), now),
        )
    return {"id": cursor.lastrowid, "project_path": str(project), "body": payload.body.strip(), "created_at": now}


def _project_root_value() -> str:
    value = get_setting(WORKSPACE_ROOT_SETTING)
    if not value:
        raise HTTPException(status_code=500, detail="Workspace root is not configured.")
    return value


def _project_root() -> Path:
    return configured_root(_project_root_value())


def _ensure_project(project_path: str) -> Path:
    return ensure_project_directory(_project_root(), project_path)


def _project_metadata() -> dict[str, dict[str, str]]:
    with get_connection() as connection:
        rows = connection.execute("SELECT path, name, description, project_type FROM projects").fetchall()
    return {row["path"]: dict(row) for row in rows}


def _agent_content(payload: AgentPreviewRequest) -> str:
    return generate_agents_md(
        payload.project_purpose,
        payload.project_rules,
        payload.build_commands,
        payload.test_commands,
        payload.security_notes,
    )


def _agents_path(project: Path) -> Path:
    agents_path = ensure_inside_root(_project_root(), project / "AGENTS.md")
    try:
        agents_path.relative_to(project)
    except ValueError as exc:
        raise HTTPException(status_code=403, detail="AGENTS.md target is outside the selected project folder.") from exc
    return agents_path


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _finding_summary(findings: list[dict[str, str]]) -> dict[str, int]:
    summary: dict[str, int] = {}
    for finding in findings:
        finding_type = finding.get("type") or "unknown"
        summary[finding_type] = summary.get(finding_type, 0) + 1
    return summary


def _empty_trust_profile(project_path: str) -> dict[str, object]:
    return {
        "project_path": project_path,
        "trustedPackageManagers": [],
        "expectedManifestFiles": [],
        "expectedLockfiles": [],
        "allowedLifecycleScripts": [],
        "reviewedPaths": [],
        "ignoredPaths": [],
        "riskTolerance": "normal",
        "notes": "",
        "updated_at": None,
    }


def _normalize_trust_profile(data: dict[str, object], project_path: str) -> dict[str, object]:
    profile = _empty_trust_profile(project_path)
    for field in TRUST_PROFILE_FIELDS:
        profile[field] = _normalize_string_list(data.get(field))
    risk_tolerance = str(data.get("riskTolerance") or "normal").strip().lower()
    profile["riskTolerance"] = risk_tolerance if risk_tolerance in RISK_TOLERANCES else "normal"
    profile["notes"] = str(data.get("notes") or "").strip()[:4000]
    return profile


def _model_data(payload: TrustProfileRequest) -> dict[str, object]:
    if hasattr(payload, "model_dump"):
        return payload.model_dump()
    return payload.dict()


def _normalize_string_list(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    normalized: list[str] = []
    seen: set[str] = set()
    for item in value:
        text = str(item).strip()
        if not text or text in seen:
            continue
        normalized.append(text)
        seen.add(text)
    return normalized


def _profile_for_storage(profile: dict[str, object]) -> dict[str, object]:
    return {key: profile[key] for key in (*TRUST_PROFILE_FIELDS, "riskTolerance", "notes")}


def _scan_metadata(result: dict[str, object]) -> dict[str, object]:
    return {
        "manifests": result.get("manifests", []),
        "lockfiles": result.get("lockfiles", []),
        "lifecycleScripts": result.get("lifecycleScripts", []),
        "secretFiles": result.get("secretFiles", []),
        "ignoredFiles": result.get("ignoredFiles", []),
        "reviewedFiles": result.get("reviewedFiles", []),
        "zone": result.get("zone", "Unknown"),
    }
