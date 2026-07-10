from __future__ import annotations

import os
import re
import stat
from pathlib import Path

from fastapi import HTTPException


SAFE_NAME_PATTERN = re.compile(r"[^a-zA-Z0-9._ -]+")


def sanitize_folder_name(name: str) -> str:
    cleaned = SAFE_NAME_PATTERN.sub("-", name).strip(" .-_")
    cleaned = re.sub(r"\s+", " ", cleaned)
    cleaned = cleaned.replace(" ", "-")
    cleaned = re.sub(r"-{2,}", "-", cleaned)
    if not cleaned:
        raise HTTPException(status_code=400, detail="Project name must contain usable characters.")
    return cleaned[:80]


def configured_root(root_value: str) -> Path:
    try:
        root = Path(root_value).expanduser()
    except (TypeError, ValueError) as exc:
        raise HTTPException(status_code=400, detail="Workspace root is malformed.") from exc
    if not root.is_absolute():
        raise HTTPException(status_code=400, detail="Workspace root must be an absolute path.")
    try:
        return root.resolve()
    except (OSError, RuntimeError, ValueError) as exc:
        raise HTTPException(status_code=400, detail="Workspace root could not be resolved.") from exc


def ensure_inside_root(workspace_root: Path, candidate: str | Path) -> Path:
    root = workspace_root.resolve()
    try:
        path = Path(candidate).expanduser()
    except (TypeError, ValueError) as exc:
        raise HTTPException(status_code=400, detail="Path is malformed.") from exc
    path_text = str(path)
    if "\0" in path_text:
        raise HTTPException(status_code=400, detail="Path is malformed.")
    if not path.is_absolute():
        raise HTTPException(status_code=400, detail="Path must be absolute.")
    if any(part == ".." for part in re.split(r"[\\/]+", path_text)):
        raise HTTPException(status_code=400, detail="Path traversal is not allowed.")

    try:
        absolute = Path(os.path.abspath(path))
        relative = absolute.relative_to(root)
    except (OSError, RuntimeError, ValueError) as exc:
        raise HTTPException(status_code=403, detail="Path is outside the configured workspace root.") from exc

    current = root
    for part in relative.parts:
        current /= part
        if is_reparse_point_or_symlink(current):
            raise HTTPException(status_code=403, detail="Symlinks and junctions are not allowed in project paths.")

    try:
        resolved = absolute.resolve()
    except (OSError, RuntimeError, ValueError) as exc:
        raise HTTPException(status_code=400, detail="Path could not be resolved.") from exc
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise HTTPException(status_code=403, detail="Path is outside the configured workspace root.") from exc
    return resolved


def ensure_project_directory(workspace_root: Path, project_path: str) -> Path:
    resolved = ensure_inside_root(workspace_root, project_path)
    if resolved == workspace_root:
        raise HTTPException(status_code=400, detail="Select a project folder inside the workspace root.")
    if not resolved.exists() or not resolved.is_dir():
        raise HTTPException(status_code=404, detail="Project folder was not found.")
    return resolved


def is_reparse_point_or_symlink(path: Path) -> bool:
    try:
        if path.is_symlink():
            return True
        is_junction = getattr(path, "is_junction", None)
        if is_junction and is_junction():
            return True
        attributes = getattr(path.stat(follow_symlinks=False), "st_file_attributes", 0)
        return bool(attributes & 0x400)
    except OSError:
        return False


def has_multiple_hardlinks(path: Path) -> bool:
    try:
        file_status = path.stat(follow_symlinks=False)
    except FileNotFoundError:
        return False

    return (
        stat.S_ISREG(file_status.st_mode)
        and file_status.st_nlink > 1
    )
