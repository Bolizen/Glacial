# Glacial Security Policy and Supported Model

This document defines the security boundary Glacial is designed to support. A scan marked **Complete** means only that Glacial completed its supported local inspections without a recorded coverage gap. It is not a malware verdict or a guarantee that a repository or dependency is safe.

## Supported deployment surfaces

Glacial's supported security deployment is the Windows desktop application: a Tauri frontend supervises a FastAPI backend bound to loopback on an ephemeral port. The supervisor generates a fresh 256-bit token for each backend launch, passes it to the backend, and attaches it to proxied API requests.

The supported full-stack development workflow uses the Tauri development runner and the same generated-token and API-bridge boundary. A standalone development backend is supported only with an explicit, ephemeral 256-bit token supplied through `GLACIAL_DESKTOP_AUTH_TOKEN` and an authenticated client. Missing, empty, or malformed token configuration prevents backend startup. Direct browser-to-backend Vite development is unsupported because browser-visible configuration is not an acceptable token store. Loopback reachability and CORS are not authentication.

Remote service deployment is unsupported. Do not bind Glacial to `0.0.0.0`, a LAN address, a public interface, a container ingress, or a reverse proxy.

## Trust boundaries

### Hostile repositories

All repository-controlled input is untrusted, including files, paths, directory layouts, manifests, lockfiles, dependency metadata, VCS selectors, scripts, and `.glacialignore` rules. Invalid syntax, invalid top-level types, deeply nested structures, oversized inputs, excessive file trees, and other adversarial forms are within the supported scanning threat model.

Glacial must inspect these inputs without executing project code, package scripts, installers, or shell files. Unsupported, malformed, excluded, unreadable, truncated, or resource-limited input is a coverage gap, not clean evidence.

### Local API

Other local processes and other OS users are not trusted API clients merely because they can reach loopback. In packaged and Tauri development launches, only requests authenticated with the fresh token held by the supervisor are trusted. Standalone backend requests require the explicitly configured ephemeral token.

### Workspace roots and filesystem authority

A supported workspace root is a stable directory controlled by the current user. A root that an unrelated principal can write, rename, delete, or replace is outside Glacial's guaranteed boundary. Glacial also does not claim to isolate filesystem objects from another process already running with the current user's filesystem authority.

Within a supported root, Glacial must reject traversal, absolute-path injection, symlinks, junctions, reparse points, unsafe hardlinks, and writes outside the currently validated root. File creation remains narrowly limited to the documented project operation, including explicit confirmation before replacing an existing root `AGENTS.md`.

Pathname confinement is not directory-identity confinement. If an actor can rename or replace the selected root or project directory during an operation, a later pathname check alone cannot prove that it still names the originally validated directory.

### Privilege model

Glacial is intended to run as the interactive, non-elevated user. Do not run it as Administrator or rely on it to mediate reads or writes between principals with different privilege levels. An elevated Glacial process would extend any backend or filesystem mistake to elevated authority and is outside the supported model.

## Security guarantees

For supported deployments and assumptions, Glacial must:

- fail closed when inspection is incomplete or ambiguous;
- never present ignored, malformed, truncated, unreadable, unsafe, or resource-limited coverage as verified Complete;
- preserve findings and higher-risk evidence collected before a conservative stop;
- keep repository traversal, parser work, inspected bytes, findings, and persisted result structures bounded;
- keep ignored paths and coverage-gap counts visible rather than silently treating them as reviewed;
- reject writes that escape the currently validated workspace and project boundaries; and
- never persist dependency credentials, access tokens, sensitive URL parameters, or raw sensitive VCS selectors. VCS revision identity may be retained only as a sanitized, opaque identity.

Older scans without completeness metadata are **Unknown**, not Complete. Review acknowledgements and trusted dependency baselines do not convert incomplete coverage into verified coverage.

## Decisions for triaged findings

- **AUTH-001:** Cross-process and cross-user loopback clients are outside the trusted API boundary. Packaged and Tauri development launches enforce the boundary with a fresh supervisor token; standalone backend startup requires an explicit valid token and never treats missing configuration as authorization.
- **BWRITE-001:** Exploitation requires authority to rename or replace the selected project directory. Adversarially replaceable project roots are unsupported, so Glacial is not a security mediator against that actor. Binding Windows publication and cleanup to a validated directory identity remains desirable defense in depth.
- **BWRITE-002:** A workspace root replaceable by an adversarial principal is unsupported. This assumption does not prove pathname-based re-resolution safe; revalidating or retaining workspace-root directory identity remains desirable defense in depth.

## Reporting a vulnerability

Do not report an undisclosed vulnerability in a public GitHub issue. Use [GitHub private vulnerability reporting](https://github.com/Bolizen/Glacial/security/advisories/new). GitHub sign-in is required. The report is visible to repository security managers rather than the public issue tracker.

Include:

- the affected Glacial version and installed or development context;
- the operating system and architecture;
- a concise impact statement;
- the smallest safe reproduction and required preconditions;
- the expected and observed security boundary;
- whether the issue is already public; and
- a safe way to coordinate follow-up through the advisory.

Do not include working credentials, private keys, real customer data, unnecessary personal data, or unrelated proprietary source. Use synthetic evidence where possible. Do not test against systems or data you do not own or have permission to assess.

The maintainer aims to acknowledge a complete report within 7 calendar days. Initial acknowledgement is not validation. The advisory will receive a status update at least every 30 calendar days while active when maintainer availability permits. Fix timing depends on severity, reproducibility, affected versions, and release safety; no resolution deadline is guaranteed.

Keep technical details private until a coordinated disclosure date is agreed or the maintainer states that disclosure can proceed. Credit and publication details are decided with the reporter. The maintainer may close reports that are not security vulnerabilities, cannot be reproduced within the supported model, affect only unsupported deployments, or lack enough safe detail to investigate.

If the private reporting form is unavailable, open a [public issue](https://github.com/Bolizen/Glacial/issues/new) containing only a request for private contact and a non-sensitive one-sentence summary. Do not include exploit steps or sensitive evidence. Ordinary bugs, documentation problems, and feature requests belong in GitHub Issues.
