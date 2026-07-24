from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field


class ProjectCreate(BaseModel):
    project_name: str = Field(min_length=1, max_length=120)
    description: str = Field(default="", max_length=2000)
    project_type: str = Field(default="", max_length=120)


class ProjectRegister(BaseModel):
    project_path: str = Field(min_length=1, max_length=1000)
    description: str = Field(default="", max_length=2000)
    project_type: str = Field(default="", max_length=120)


class ProjectMetadataUpdate(BaseModel):
    project_path: str = Field(min_length=1, max_length=1000)
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
    expectedEcosystems: list[str] = Field(default_factory=list)
    reviewedPaths: list[str] = Field(default_factory=list)
    ignoredPaths: list[str] = Field(default_factory=list)
    expectationProvenance: dict[str, dict[str, str]] = Field(default_factory=dict)
    dismissedSuggestions: dict[str, list[str]] = Field(default_factory=dict)
    riskTolerance: str = Field(default="normal", max_length=20)
    notes: str = Field(default="", max_length=4000)


class FindingReviewRequest(ProjectPathRequest):
    fingerprint: str = Field(min_length=68, max_length=68)
    status: Literal["reviewed", "expected"]
    note: str = Field(default="", max_length=1000)


class FindingReviewDelete(ProjectPathRequest):
    fingerprint: str = Field(min_length=68, max_length=68)


class TrustedDependencyBaselineApprove(ProjectPathRequest):
    scan_id: int = Field(gt=0)
    fingerprint: str = Field(min_length=70, max_length=70)
    note: str = Field(default="", max_length=1000)
    replace: bool = False

    class Config:
        extra = "forbid"


class TrustedDependencyBaselineNote(ProjectPathRequest):
    note: str = Field(default="", max_length=1000)

    class Config:
        extra = "forbid"
