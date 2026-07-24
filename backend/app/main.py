from __future__ import annotations

import hmac
import json
from datetime import datetime, timezone
from pathlib import Path

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from .agents import generate_agents_md
from .agents_write import filesystem_error_status, safe_write_project_file
from .changelog import CHANGELOG_ENTRIES
from .config import allowed_cors_origins, desktop_auth_token
from .database import (
    WORKSPACE_ROOT_SETTING,
    get_connection,
    get_setting,
    init_db,
    latest_scan_map,
    note_counts,
    row_to_scan,
    scan_completeness_for_row,
    set_setting,
)
from .dependency_trust import SCHEMA_VERSION as DEPENDENCY_TRUST_SCHEMA_VERSION
from .finding_reviews import enrich_scan, finding_fingerprint, valid_fingerprint
from .safety import configured_root, ensure_inside_root, ensure_project_directory, existing_workspace_root, has_multiple_hardlinks, sanitize_folder_name
from .scanner import scan_project
from .schemas import AgentPreviewRequest, FindingReviewDelete, FindingReviewRequest, NoteCreate, ProjectCreate, ProjectMetadataUpdate, ProjectPathRequest, ProjectRegister, ProjectRootUpdate, TrustProfileRequest, TrustedDependencyBaselineApprove, TrustedDependencyBaselineNote
from .trusted_dependency_baseline import BASELINE_SCHEMA_VERSION, BaselineError, approval_for_analysis, enrich_scan as enrich_trusted_baseline, public_baseline, snapshot_from_analysis, snapshot_json, valid_fingerprint as valid_baseline_fingerprint


app = FastAPI(title="Glacial API")

TRUST_PROFILE_FIELDS = (
    "trustedPackageManagers",
    "expectedManifestFiles",
    "expectedLockfiles",
    "allowedLifecycleScripts",
    "expectedEcosystems",
    "reviewedPaths",
    "ignoredPaths",
)
EXPECTATION_PROVENANCE_TYPES = {"accepted-suggestion", "manual"}
MAX_DISMISSED_SUGGESTIONS_PER_FIELD = 200
RISK_TOLERANCES = {"cautious", "normal", "permissive"}

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_cors_origins(),
    allow_credentials=False,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
)


@app.middleware("http")
async def require_desktop_authentication(request: Request, call_next):
    try:
        token = desktop_auth_token()
    except ValueError:
        return JSONResponse(
            status_code=503,
            content={"detail": "Desktop API authentication is unavailable."},
        )
    if not _authorized_api_request(
        request.url.path,
        request.method,
        request.headers.get("authorization"),
        token,
    ):
        return JSONResponse(
            status_code=401,
            content={"detail": "Desktop API authentication is required."},
            headers={"WWW-Authenticate": "Bearer"},
        )
    return await call_next(request)


@app.on_event("startup")
def startup() -> None:
    desktop_auth_token()
    init_db()


@app.get("/api/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


def _authorized_api_request(
    path: str,
    method: str,
    authorization: str | None,
    token: str | None,
) -> bool:
    if method == "OPTIONS" or not path.startswith("/api/"):
        return True
    if not token:
        return False
    presented = authorization or ""
    expected = f"Bearer {token}"
    return hmac.compare_digest(presented.encode("utf-8"), expected.encode("ascii"))


@app.get("/api/config")
def get_config() -> dict[str, str]:
    return {"project_root": _project_root_value()}


@app.get("/api/changelog")
def get_changelog() -> dict[str, object]:
    return {"entries": CHANGELOG_ENTRIES}


@app.put("/api/config/project-root")
def update_project_root(payload: ProjectRootUpdate) -> dict[str, str]:
    root = existing_workspace_root(payload.project_root)
    set_setting(WORKSPACE_ROOT_SETTING, str(root))
    return {"project_root": str(root)}


@app.get("/api/projects")
def list_projects() -> dict[str, object]:
    root = _project_root()
    scans = latest_scan_map()
    counts = note_counts()

    projects = []
    root_exists = root.exists()
    with get_connection() as connection:
        rows = connection.execute(
            "SELECT path, name, description, project_type FROM projects ORDER BY name COLLATE NOCASE"
        ).fetchall()
    for row in rows:
        stored_path = Path(row["path"])
        try:
            stored_path.absolute().relative_to(root)
        except (OSError, ValueError):
            continue
        availability = "available"
        try:
            project_path = ensure_inside_root(root, stored_path)
            if not project_path.exists():
                availability = "missing"
            elif not project_path.is_dir():
                availability = "not-a-directory"
        except HTTPException as exc:
            availability = "missing" if exc.status_code == 404 else "unsafe"
        except OSError:
            availability = "inaccessible"
        path = str(stored_path)
        scan = scans.get(path)
        projects.append(
            {
                "name": row["name"],
                "path": path,
                "description": row["description"],
                "project_type": row["project_type"],
                "last_scan_time": scan["scan_date"] if scan else None,
                "last_risk_level": scan["overall_risk"] if scan else "none",
                "last_scan_completeness": scan_completeness_for_row(scan) if scan else None,
                "scan_state": "scanned" if scan else "not_scanned",
                "available": availability == "available",
                "availability": availability,
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


@app.post("/api/projects/register")
def register_project(payload: ProjectRegister) -> dict[str, str]:
    project_path = ensure_project_directory(_project_root(), payload.project_path)
    now = _now()
    with get_connection() as connection:
        connection.execute(
            "INSERT INTO projects (path, name, description, project_type, created_at) VALUES (?, ?, ?, ?, ?) "
            "ON CONFLICT(path) DO UPDATE SET description = excluded.description, project_type = excluded.project_type",
            (str(project_path), project_path.name, payload.description.strip(), payload.project_type.strip(), now),
        )
    return {"name": project_path.name, "path": str(project_path), "created_at": now}


@app.put("/api/projects/metadata")
def update_project_metadata(payload: ProjectMetadataUpdate) -> dict[str, object]:
    project = _ensure_project(payload.project_path)
    description = payload.description.strip()
    project_type = payload.project_type.strip()
    with get_connection() as connection:
        cursor = connection.execute(
            "UPDATE projects SET description = ?, project_type = ? WHERE path = ?",
            (description, project_type, str(project)),
        )
    if cursor.rowcount != 1:
        raise HTTPException(status_code=404, detail="Project registration was not found.")
    return {
        "path": str(project),
        "name": project.name,
        "description": description,
        "project_type": project_type,
    }


@app.delete("/api/projects")
def unregister_project(payload: ProjectPathRequest) -> dict[str, object]:
    root = _project_root()
    try:
        requested = Path(payload.project_path).expanduser()
        if not requested.is_absolute() or "\0" in str(requested) or any(part == ".." for part in str(requested).replace("\\", "/").split("/")):
            raise ValueError
        requested.absolute().relative_to(root)
    except (OSError, RuntimeError, TypeError, ValueError) as exc:
        raise HTTPException(status_code=400, detail="Project path is not a valid registration in this workspace.") from exc

    path = str(requested.absolute())
    with get_connection() as connection:
        row = connection.execute("SELECT name FROM projects WHERE path = ?", (path,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Project registration was not found.")
        connection.execute("DELETE FROM scans WHERE project_path = ?", (path,))
        connection.execute("DELETE FROM notes WHERE project_path = ?", (path,))
        connection.execute("DELETE FROM project_trust_profiles WHERE project_path = ?", (path,))
        connection.execute("DELETE FROM finding_reviews WHERE project_path = ?", (path,))
        connection.execute("DELETE FROM trusted_dependency_baselines WHERE project_path = ?", (path,))
        connection.execute("DELETE FROM projects WHERE path = ?", (path,))
    return {
        "unregistered": True,
        "name": row["name"],
        "path": path,
        "message": "Project unregistered. Project files were not changed.",
    }


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
    agents_path = project / "AGENTS.md"
    content = _agent_content(payload)

    try:
        agents_path = safe_write_project_file(
            _project_root(),
            project,
            "AGENTS.md",
            content,
            overwrite=payload.overwrite,
        )
    except FileExistsError:
        return {
            "written": False,
            "confirmation_required": True,
            "path": str(agents_path),
            "message": "AGENTS.md already exists. Confirm overwrite to write a new version.",
        }
    except OSError as exc:
        status_code = filesystem_error_status(exc)
        detail = (
            "AGENTS.md could not be safely written."
            if status_code == 409
            else "AGENTS.md could not be written."
        )
        raise HTTPException(status_code=status_code, detail=detail) from exc

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
    previous_dependency_trust = None
    with get_connection() as connection:
        previous_rows = connection.execute(
            "SELECT * FROM scans WHERE project_path = ? ORDER BY scan_date DESC, id DESC",
            (str(project),),
        )
        try:
            for row in previous_rows:
                candidate = row_to_scan(row).get("dependencyTrust")
                if (
                    isinstance(candidate, dict)
                    and candidate.get("schemaVersion") == DEPENDENCY_TRUST_SCHEMA_VERSION
                    and isinstance(candidate.get("entries"), list)
                ):
                    previous_dependency_trust = candidate
                    break
        finally:
            previous_rows.close()
    result = scan_project(project, previous_dependency_trust=previous_dependency_trust)
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
    response = {
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
        "scanCompleteness": result["scanCompleteness"],
        "dependencyTrust": result.get("dependencyTrust"),
    }
    response = enrich_scan(response, _finding_reviews(str(project)))
    return enrich_trusted_baseline(response, _trusted_baseline_row(str(project)))


@app.get("/api/scans/history")
def scan_history(project_path: str = Query(min_length=1, max_length=1000)) -> dict[str, object]:
    project = _ensure_project(project_path)
    with get_connection() as connection:
        rows = connection.execute(
            "SELECT * FROM scans WHERE project_path = ? ORDER BY scan_date DESC LIMIT 20",
            (str(project),),
        ).fetchall()
    reviews = _finding_reviews(str(project))
    baseline = _trusted_baseline_row(str(project))
    return {"scans": [enrich_trusted_baseline(enrich_scan(row_to_scan(row), reviews), baseline) for row in rows]}


@app.get("/api/trusted-dependency-baseline")
def get_trusted_dependency_baseline(project_path: str = Query(min_length=1, max_length=1000)) -> dict[str, object]:
    project = _ensure_project(project_path)
    return public_baseline(_trusted_baseline_row(str(project)))


@app.put("/api/trusted-dependency-baseline")
def approve_trusted_dependency_baseline(payload: TrustedDependencyBaselineApprove) -> dict[str, object]:
    project = _ensure_project(payload.project_path)
    fingerprint = payload.fingerprint.strip().lower()
    if not valid_baseline_fingerprint(fingerprint):
        raise HTTPException(status_code=422, detail="Trusted baseline fingerprint is invalid.")
    scan = _scan_for_baseline_approval(str(project), payload.scan_id)
    approval = approval_for_analysis(scan.get("dependencyTrust"))
    if not approval["eligible"]:
        raise HTTPException(status_code=409, detail=approval["reason"])
    if approval["fingerprint"] != fingerprint:
        raise HTTPException(status_code=409, detail="Dependency snapshot changed; refresh the scan before approving it.")
    try:
        snapshot = snapshot_from_analysis(scan["dependencyTrust"])
    except BaselineError as error:
        raise HTTPException(status_code=409, detail=str(error)) from error
    now = _now()
    note = payload.note.strip()
    values = (
        str(project), BASELINE_SCHEMA_VERSION, DEPENDENCY_TRUST_SCHEMA_VERSION, fingerprint,
        snapshot_json(snapshot), scan["id"], scan["scan_date"], note, now, now,
    )
    with get_connection() as connection:
        connection.execute("BEGIN IMMEDIATE")
        latest = connection.execute(
            "SELECT id FROM scans WHERE project_path = ? ORDER BY scan_date DESC, id DESC LIMIT 1",
            (str(project),),
        ).fetchone()
        if not latest or latest["id"] != scan["id"]:
            raise HTTPException(status_code=409, detail="Only the current latest scan can be approved as a trusted baseline.")
        existing = connection.execute(
            "SELECT 1 FROM trusted_dependency_baselines WHERE project_path = ?", (str(project),),
        ).fetchone()
        if existing and not payload.replace:
            raise HTTPException(status_code=409, detail="A trusted dependency baseline already exists. Confirm replacement to continue.")
        if existing:
            connection.execute(
                "UPDATE trusted_dependency_baselines SET baseline_schema_version = ?, dependency_schema_version = ?, "
                "fingerprint = ?, snapshot_json = ?, source_scan_id = ?, source_scan_date = ?, note = ?, "
                "created_at = ?, updated_at = ? WHERE project_path = ?",
                (*values[1:], values[0]),
            )
        else:
            connection.execute(
                "INSERT INTO trusted_dependency_baselines (project_path, baseline_schema_version, dependency_schema_version, "
                "fingerprint, snapshot_json, source_scan_id, source_scan_date, note, created_at, updated_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                values,
            )
        row = connection.execute(
            "SELECT * FROM trusted_dependency_baselines WHERE project_path = ?", (str(project),),
        ).fetchone()
    return public_baseline(dict(row))


@app.patch("/api/trusted-dependency-baseline")
def update_trusted_dependency_baseline_note(payload: TrustedDependencyBaselineNote) -> dict[str, object]:
    project = _ensure_project(payload.project_path)
    with get_connection() as connection:
        cursor = connection.execute(
            "UPDATE trusted_dependency_baselines SET note = ?, updated_at = ? WHERE project_path = ?",
            (payload.note.strip(), _now(), str(project)),
        )
        if cursor.rowcount != 1:
            raise HTTPException(status_code=404, detail="No trusted dependency baseline is configured for this project.")
        row = connection.execute(
            "SELECT * FROM trusted_dependency_baselines WHERE project_path = ?", (str(project),),
        ).fetchone()
    return public_baseline(dict(row))


@app.delete("/api/trusted-dependency-baseline")
def clear_trusted_dependency_baseline(payload: ProjectPathRequest) -> dict[str, object]:
    project = _ensure_project(payload.project_path)
    with get_connection() as connection:
        connection.execute("DELETE FROM trusted_dependency_baselines WHERE project_path = ?", (str(project),))
    return {"configured": False, "cleared": True, "status": "not-configured"}


@app.get("/api/finding-reviews")
def list_finding_reviews(project_path: str = Query(min_length=1, max_length=1000)) -> dict[str, object]:
    project = _ensure_project(project_path)
    return {"reviews": _finding_reviews(str(project))}


@app.put("/api/finding-reviews")
def update_finding_review(payload: FindingReviewRequest) -> dict[str, object]:
    project = _ensure_project(payload.project_path)
    fingerprint = _validated_fingerprint(payload.fingerprint)
    if not _project_has_fingerprint(str(project), fingerprint):
        raise HTTPException(status_code=404, detail="The exact finding is not present in this project's scan history.")
    note = payload.note.strip()
    now = _now()
    with get_connection() as connection:
        connection.execute(
            "INSERT INTO finding_reviews (project_path, fingerprint, status, note, created_at, updated_at) "
            "VALUES (?, ?, ?, ?, ?, ?) "
            "ON CONFLICT(project_path, fingerprint) DO UPDATE SET "
            "status = excluded.status, note = excluded.note, updated_at = excluded.updated_at",
            (str(project), fingerprint, payload.status, note, now, now),
        )
        row = connection.execute(
            "SELECT fingerprint, status, note, created_at, updated_at FROM finding_reviews "
            "WHERE project_path = ? AND fingerprint = ?",
            (str(project), fingerprint),
        ).fetchone()
    return {"review": dict(row)}


@app.delete("/api/finding-reviews")
def delete_finding_review(payload: FindingReviewDelete) -> dict[str, object]:
    project = _ensure_project(payload.project_path)
    fingerprint = _validated_fingerprint(payload.fingerprint)
    with get_connection() as connection:
        connection.execute(
            "DELETE FROM finding_reviews WHERE project_path = ? AND fingerprint = ?",
            (str(project), fingerprint),
        )
    return {"reopened": True, "fingerprint": fingerprint}


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
    if not isinstance(stored, dict):
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
    project = ensure_project_directory(_project_root(), project_path)
    with get_connection() as connection:
        row = connection.execute("SELECT 1 FROM projects WHERE path = ?", (str(project),)).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Project folder is not registered in Glacial.")
    return project


def _agent_content(payload: AgentPreviewRequest) -> str:
    return generate_agents_md(
        payload.project_purpose,
        payload.project_rules,
        payload.build_commands,
        payload.test_commands,
        payload.security_notes,
    )


def _agents_path(project: Path) -> Path:
    agents_path = project / "AGENTS.md"
    validated_path = ensure_inside_root(_project_root(), agents_path)
    try:
        validated_path.relative_to(project)
    except ValueError as exc:
        raise HTTPException(status_code=403, detail="AGENTS.md target is outside the selected project folder.") from exc
    if validated_path != agents_path:
        raise HTTPException(status_code=403, detail="AGENTS.md target was redirected.")
    try:
        hardlinked = has_multiple_hardlinks(agents_path)
    except OSError as exc:
        raise HTTPException(
            status_code=409,
            detail="AGENTS.md target could not be safely inspected.",
        ) from exc
    if hardlinked:
        raise HTTPException(status_code=409, detail="AGENTS.md target has multiple hard links.")
    if agents_path.exists() and not agents_path.is_file():
        raise HTTPException(status_code=409, detail="AGENTS.md target exists but is not a regular file.")
    return agents_path


def _finding_reviews(project_path: str) -> list[dict[str, object]]:
    with get_connection() as connection:
        rows = connection.execute(
            "SELECT fingerprint, status, note, created_at, updated_at FROM finding_reviews "
            "WHERE project_path = ? ORDER BY updated_at DESC, fingerprint",
            (project_path,),
        ).fetchall()
    return [dict(row) for row in rows]


def _validated_fingerprint(value: str) -> str:
    fingerprint = str(value or "").strip().lower()
    if not valid_fingerprint(fingerprint):
        raise HTTPException(status_code=422, detail="Finding fingerprint is invalid.")
    return fingerprint


def _project_has_fingerprint(project_path: str, fingerprint: str) -> bool:
    with get_connection() as connection:
        rows = connection.execute(
            "SELECT findings_json FROM scans WHERE project_path = ? ORDER BY scan_date DESC, id DESC",
            (project_path,),
        )
        try:
            for row in rows:
                try:
                    findings = json.loads(row["findings_json"])
                except (TypeError, json.JSONDecodeError):
                    continue
                if not isinstance(findings, list):
                    continue
                for finding in findings:
                    if isinstance(finding, dict):
                        try:
                            if finding_fingerprint(finding) == fingerprint:
                                return True
                        except ValueError:
                            continue
        finally:
            rows.close()
    return False


def _trusted_baseline_row(project_path: str) -> dict[str, object] | None:
    with get_connection() as connection:
        row = connection.execute(
            "SELECT * FROM trusted_dependency_baselines WHERE project_path = ?", (project_path,),
        ).fetchone()
    return dict(row) if row else None


def _scan_for_baseline_approval(project_path: str, scan_id: int) -> dict[str, object]:
    with get_connection() as connection:
        row = connection.execute(
            "SELECT * FROM scans WHERE id = ? AND project_path = ?", (scan_id, project_path),
        ).fetchone()
        if not row:
            other_project = connection.execute("SELECT 1 FROM scans WHERE id = ?", (scan_id,)).fetchone()
            if other_project:
                raise HTTPException(status_code=403, detail="The selected scan belongs to another project.")
            raise HTTPException(status_code=404, detail="The selected scan was not found.")
        latest = connection.execute(
            "SELECT id FROM scans WHERE project_path = ? ORDER BY scan_date DESC, id DESC LIMIT 1", (project_path,),
        ).fetchone()
    if not latest or latest["id"] != scan_id:
        raise HTTPException(status_code=409, detail="Only the current latest scan can be approved as a trusted baseline.")
    return row_to_scan(row)


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
        "expectedEcosystems": [],
        "reviewedPaths": [],
        "ignoredPaths": [],
        "expectationProvenance": {},
        "dismissedSuggestions": {},
        "riskTolerance": "normal",
        "notes": "",
        "updated_at": None,
    }


def _normalize_trust_profile(data: dict[str, object], project_path: str) -> dict[str, object]:
    profile = _empty_trust_profile(project_path)
    for field in TRUST_PROFILE_FIELDS:
        profile[field] = _normalize_string_list(data.get(field))
    profile["expectationProvenance"] = _normalize_expectation_provenance(
        data.get("expectationProvenance"),
        profile,
    )
    profile["dismissedSuggestions"] = _normalize_dismissed_suggestions(
        data.get("dismissedSuggestions"),
        profile,
    )
    risk_value = data.get("riskTolerance")
    risk_tolerance = risk_value.strip().lower() if isinstance(risk_value, str) else "normal"
    profile["riskTolerance"] = risk_tolerance if risk_tolerance in RISK_TOLERANCES else "normal"
    notes = data.get("notes")
    profile["notes"] = notes.strip()[:4000] if isinstance(notes, str) else ""
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
        if not isinstance(item, str):
            continue
        text = item.strip()
        if not text or text in seen:
            continue
        normalized.append(text)
        seen.add(text)
    return normalized


def _normalize_expectation_provenance(
    value: object,
    profile: dict[str, object],
) -> dict[str, dict[str, str]]:
    if not isinstance(value, dict):
        return {}
    normalized: dict[str, dict[str, str]] = {}
    for field in TRUST_PROFILE_FIELDS:
        field_value = value.get(field)
        if not isinstance(field_value, dict):
            continue
        approved = set(profile[field])
        entries: dict[str, str] = {}
        for item, source in field_value.items():
            text = str(item).strip()
            source_text = str(source).strip().lower()
            if text in approved and source_text in EXPECTATION_PROVENANCE_TYPES:
                entries[text] = source_text
        if entries:
            normalized[field] = entries
    return normalized


def _normalize_dismissed_suggestions(
    value: object,
    profile: dict[str, object],
) -> dict[str, list[str]]:
    if not isinstance(value, dict):
        return {}
    normalized: dict[str, list[str]] = {}
    for field in TRUST_PROFILE_FIELDS:
        dismissed = [
            item
            for item in _normalize_string_list(value.get(field))
            if item not in profile[field]
        ][:MAX_DISMISSED_SUGGESTIONS_PER_FIELD]
        if dismissed:
            normalized[field] = dismissed
    return normalized


def _profile_for_storage(profile: dict[str, object]) -> dict[str, object]:
    return {
        key: profile[key]
        for key in (
            *TRUST_PROFILE_FIELDS,
            "expectationProvenance",
            "dismissedSuggestions",
            "riskTolerance",
            "notes",
        )
    }


def _scan_metadata(result: dict[str, object]) -> dict[str, object]:
    return {
        "manifests": result.get("manifests", []),
        "lockfiles": result.get("lockfiles", []),
        "lifecycleScripts": result.get("lifecycleScripts", []),
        "secretFiles": result.get("secretFiles", []),
        "ignoredFiles": result.get("ignoredFiles", []),
        "reviewedFiles": result.get("reviewedFiles", []),
        "zone": result.get("zone", "Unknown"),
        "scanCompleteness": result.get("scanCompleteness"),
        "dependencyTrust": result.get("dependencyTrust"),
    }
