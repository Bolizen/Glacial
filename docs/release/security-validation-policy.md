# Proportional security validation policy

This document is the authoritative security-validation policy for Glacial
changes and release acceptance. It separates the assurance objective from any
particular scanner, model, agent workflow, or orchestration mechanism.

Codex Security Deep is available, but it is not the default validation level
and is not inherently required for release confidence. The former Deep-mode
requirement in `V1-SEC-007` was an internal Glacial implementation choice. No
external law, standard, platform rule, or distribution requirement identified
by the readiness audit mandates Codex Security Deep specifically. If a future
external requirement does mandate a method, the acceptance record must cite the
exact source and preserve that separate obligation.

## Evidence-based acceptance contract

Every security acceptance record must address the following boundaries.

### A. Known acceptance boundary

Identify the exact repository and revision being accepted, the relevant
security-sensitive surfaces and trust boundaries, and every material change
since the last applicable broad review. Security evidence is valid only for its
stated assumptions and baseline.

### B. Reuse of valid prior evidence

Prior evidence remains usable while the reviewed surface, threat assumptions,
and relevant controls have not materially changed. A new commit hash alone does
not invalidate it. Applicable evidence includes:

- completed repository-wide Standard or other broad reviews;
- targeted security and attack-path reviews;
- independent adversarial reviews;
- validated finding ledgers and remediation records;
- regression and hostile-path tests;
- release-boundary, signing, provenance, and supply-chain validation; and
- earlier broad reviews whose assumptions remain valid.

The acceptance record must identify what is reused and why it still applies.

### C. Delta validation

Every material change since the applicable broad evidence must receive
validation proportional to its actual security impact. A localized change
normally requires review of the changed code or configuration, directly
affected trust boundaries, relevant regressions, and concrete attack paths. It
does not automatically require repository-wide rediscovery.

### D. Finding closure

Every reportable finding affecting the accepted baseline must be one of:

- fixed and appropriately verified;
- explicitly accepted through a documented owner, rationale, scope, and expiry
  or review condition when the governing contract permits acceptance; or
- retained as a release blocker.

Incomplete, abandoned, duplicate, or superseded records must remain traceable.
They may not silently disappear or be counted as closure.

### E. Honest coverage

Reports must distinguish reviewed and unreviewed surfaces, complete and
incomplete tooling, resolved and unresolved questions, validated findings, and
unvalidated candidates. A failed, interrupted, zero-coverage, or partially
covered scan is not a clean result. A displayed zero finding count has no
security meaning unless the associated coverage and validation are defensible.

### F. Escalation when necessary

Broad repository-wide rediscovery remains available when targeted evidence is
insufficient. The validation need selects the tool. No individual tool is
mandatory without a separately documented reason or external obligation.

## Validation levels

### Level 1 — Routine validation

Level 1 is the default for ordinary low-risk work such as documentation, UI
presentation, narrowly scoped tests, refactors without a trust-boundary change,
routine bug fixes, and internal tooling that does not alter a security boundary.

Typical evidence is the relevant tests, lint/typecheck/build where applicable,
diff review, repository hygiene, and focused behavioral verification. A
security scan is not required merely because code changed.

### Level 2 — Security-targeted validation

Level 2 is the default when a change touches a known security-sensitive surface
without materially changing the overall architecture. Examples include path
containment, persistence safety, WebView configuration, IPC/authentication,
release scripts, signing enforcement, dependency remediation, filesystem write
boundaries, and known vulnerability remediation.

Typical evidence is a focused threat or attack-path review, targeted
adversarial testing, regression coverage, relevant implementation checks, and
one bounded independent review when independence adds meaningful assurance. A
repository-wide scan is required only if targeted work reveals evidence of a
broader systemic problem.

G131 is the reference example: it reproduced one development-WebView attack
path, applied the smallest fail-closed configuration fix, added a focused
regression, reran the hostile condition and legitimate control, and obtained one
bounded independent review without rediscovering the repository.

### Level 3 — Broad / Deep validation

Level 3 is reserved for substantial systemic risk or consequential release
circumstances where prior and targeted evidence cannot provide adequate
coverage. Tools may include Codex Security Deep, a repository-wide Standard
review, or another broad adversarial method. The method must match the stated
risk and stopping condition.

## Level 3 escalation criteria

Concrete reasons that can justify broad rediscovery include:

- a major new trust, authentication, authorization, or privilege boundary;
- a new mechanism that executes or interprets untrusted project content;
- a major signing, update, publication, sandboxing, filesystem-containment, or
  supply-chain architecture redesign;
- a large security-sensitive change set whose interactions cannot reasonably
  be validated locally;
- credible compromise evidence;
- a severe vulnerability suggesting systemic related weaknesses;
- repeated serious findings across components suggesting a missed pattern;
- a particularly consequential public release whose applicable broad evidence
  has become materially stale; or
- another documented risk whose expected assurance gain justifies broad
  rediscovery.

The following are not sufficient by themselves:

- incrementing a handoff number, making a small change, or fixing one isolated
  vulnerability;
- documentation-only work;
- elapsed time alone;
- a request for “more confidence” or “security best practice” without a concrete
  threat argument;
- the availability of Deep mode, a prior Deep failure, or unused Codex quota.

## Required pre-scan justification

Before any Level 3 validation is authorized, record concise answers to:

1. What concrete risk are we trying to detect?
2. Why can targeted validation not adequately address it?
3. What repository or security surface requires broad rediscovery?
4. What existing evidence can be reused?
5. What expected assurance gain justifies the resource cost?
6. What is the stopping condition?
7. How will interruption and cancellation be handled safely?

If these questions cannot be answered clearly, broad scanning is not
authorized.

## Resource proportionality

Codex usage and orchestration cost are legitimate engineering constraints. They
must not suppress necessary security work, but expensive validation must have a
corresponding expected assurance value.

For expensive agentic validation:

- define scope before launch and reuse applicable prior evidence;
- avoid repeating completed analysis without a specific reason;
- prefer bounded targeted review where it is sufficient;
- checkpoint durable progress where supported and set an explicit stop
  condition;
- prevent recursive task expansion and distinguish investigation from
  remediation;
- use independent workers only when independence adds meaningful assurance; and
- stop when expected marginal assurance becomes low.

A failed run that produced little or no substantive evidence does not gain value
merely by being repeated.

## Cancellation and durable execution

G130 demonstrated that interrupting a visible parent turn or waiter does not
necessarily cancel a durable scan coordinator or its child workers. Every broad
agentic procedure must document coordinator and child-worker lifecycles,
durable background execution, cancellation semantics, and how termination will
be confirmed.

When a user intends to stop an expensive scan, the operator must use the
workflow's supported cancellation mechanism when one exists and verify that all
scan-owned coordinators, workers, and subprocesses have actually stopped.
Stopping the visible interaction alone is not proof of cancellation.

## Acceptance outcomes

Security acceptance is `PASS` only when the explicit baseline, reusable
evidence, material delta, finding closure, and coverage limitations together
support a defensible conclusion. It is `PARTIAL` when a concrete evidence gap
remains and must name the smallest proportional task that can close it. It is
`FAIL` when evidence establishes an unresolved release-blocking defect.

Changing this policy never converts a failed scan into a successful scan,
manufactures unperformed coverage, closes an unresolved finding, or declares
Glacial secure.
