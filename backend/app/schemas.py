from __future__ import annotations

from pydantic import BaseModel, Field


class ProjectCreate(BaseModel):
    project_name: str = Field(min_length=1, max_length=120)
    description: str = Field(default="", max_length=2000)
    project_type: str = Field(default="", max_length=120)


class ProjectRootUpdate(BaseModel):
    project_root: str = Field(min_length=1, max_length=1000)


class ProjectPathRequest(BaseModel):
    project_path: str = Field(min_length=1, max_length=1000)


class AgentPreviewRequest(ProjectPathRequest):
    project_purpose: str = Field(default="", max_length=4000)
    project_rules: str = Field(default="", max_length=4000)
    build_commands: str = Field(default="", max_length=4000)
    test_commands: str = Field(default="", max_length=4000)
    security_notes: str = Field(default="", max_length=4000)
    overwrite: bool = False


class NoteCreate(ProjectPathRequest):
    body: str = Field(min_length=1, max_length=4000)


class TrustProfileRequest(ProjectPathRequest):
    trustedPackageManagers: list[str] = Field(default_factory=list)
    expectedManifestFiles: list[str] = Field(default_factory=list)
    expectedLockfiles: list[str] = Field(default_factory=list)
    allowedLifecycleScripts: list[str] = Field(default_factory=list)
    reviewedPaths: list[str] = Field(default_factory=list)
    ignoredPaths: list[str] = Field(default_factory=list)
    riskTolerance: str = Field(default="normal", max_length=20)
    notes: str = Field(default="", max_length=4000)
