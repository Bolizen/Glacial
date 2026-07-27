from __future__ import annotations

from .privacy import sanitize_private_text


DEFAULT_PROJECT_RULES = """- Work only inside this project folder unless explicitly told otherwise.
- Read files before editing and keep changes scoped to the requested task.
- Preserve user changes and avoid destructive git or filesystem operations."""

HARD_SAFETY_RULES = """- Do not modify files outside this project folder.
- Do not install dependencies without explaining why.
- Do not execute install scripts automatically.
- Do not add telemetry.
- Do not add cloud services unless explicitly requested.
- Do not store secrets in source files.
- Prefer small, reviewable changes.
- Explain security-sensitive changes."""


def generate_agents_md(
    project_purpose: str,
    project_rules: str,
    build_commands: str,
    test_commands: str,
    security_notes: str,
) -> str:
    purpose = sanitize_private_text(
        project_purpose,
        limit=4000,
        preserve_lines=True,
    ) or "Describe what this project is for."
    rules = sanitize_private_text(
        project_rules,
        limit=4000,
        preserve_lines=True,
    ) or DEFAULT_PROJECT_RULES
    build = sanitize_private_text(
        build_commands,
        limit=4000,
        preserve_lines=True,
    ) or "Document build commands here after verifying they are safe to run."
    test = sanitize_private_text(
        test_commands,
        limit=4000,
        preserve_lines=True,
    ) or "Document test commands here after verifying they are safe to run."
    security = sanitize_private_text(
        security_notes,
        limit=4000,
        preserve_lines=True,
    ) or "Review scripts, installers, environment files, and generated code before execution."

    return f"""# AGENTS.md

## Project Purpose

{purpose}

## Rules for Codex

{rules}

## Build Commands

{build}

## Test Commands

{test}

## Security Notes

{security}

## Hard Safety Rules

{HARD_SAFETY_RULES}
"""
