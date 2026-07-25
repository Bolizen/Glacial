# `glib 0.18.5` soundness backport

## Status and scope

Glacial carries a local source backport for
[`RUSTSEC-2024-0429`](https://rustsec.org/advisories/RUSTSEC-2024-0429.html) /
[`GHSA-wrw7-89jp-8q8g`](https://github.com/advisories/GHSA-wrw7-89jp-8q8g).
The advisory affects `glib` versions `>= 0.15.0, < 0.20.0`; upstream identifies
`0.20.0` as the first patched release. Glacial retains the package identity
`glib 0.18.5` while applying the upstream correction locally.

Commit `57383649f2766e6752170811286d89d393b318c6`
(`fix(deps): backport glib soundness fix`) introduced the backport.
`frontend/src-tauri/Cargo.toml` selects it with:

```toml
[patch.crates-io]
glib = { path = "../../third_party/rust/glib-0.18.5-patched" }
```

The corresponding `Cargo.lock` package has version `0.18.5` and no registry
`source` or `checksum`, which is Cargo's lockfile representation for the
path-resolved package. Run `node scripts/security/verify-glib-backport.mjs` to
check these invariants.

The verifier runs automatically in `.github/workflows/glib-backport.yml` when
relevant files change in a pull request targeting `main` or a push to `main`.
Pushes run the verifier from the trusted pushed commit. Pull requests use
`pull_request_target` so the workflow checks out the trusted base commit and
the exact proposed head commit into separate directories, then runs:

```text
node trusted/scripts/security/verify-glib-backport.mjs --repo-root candidate
```

The candidate checkout is data only. The base-owned verifier reads its
repository invariants through the `--repo-root` interface; the workflow must
never execute, import, source, install, build, or otherwise evaluate candidate
content. It must not add candidate-controlled actions, package or build
commands, caches, secrets, write permissions, or artifacts.

The no-argument local command remains available for pre-commit verification,
and `--repo-root <path>` can select another repository tree explicitly. Both
forms validate the same documented invariants. This CI check does not compile
or execute the Linux/BSD application.

## Defect and correction

`VariantStrIter::impl_get` initializes a `*mut libc::c_char` to null and passes
its address as an out-argument to the variadic GLib FFI function
`g_variant_get_child`. Pristine `glib 0.18.5` passed `&p`, an immutable Rust
reference, even though C writes a new pointer value through it. That violates
Rust's reference and aliasing rules. Optimized compilation can disregard the
write, after which `CStr::from_ptr` receives null and its safety contract is
violated.

The local correction is exactly the upstream two-line mutability fix:

```diff
-let p: *mut libc::c_char = std::ptr::null_mut();
+let mut p: *mut libc::c_char = std::ptr::null_mut();
 ...
-&p,
+&mut p,
```

The source is recorded in
[`gtk-rs/gtk-rs-core#1343`](https://github.com/gtk-rs/gtk-rs-core/pull/1343),
upstream patch commit
[`b5a4071e439bef2b5eea76c3aa25e5ae84839e34`](https://github.com/gtk-rs/gtk-rs-core/commit/b5a4071e439bef2b5eea76c3aa25e5ae84839e34),
merged as
[`05dff0ee696f9bcd8617cd48c4b812d046d440cb`](https://github.com/gtk-rs/gtk-rs-core/commit/05dff0ee696f9bcd8617cd48c4b812d046d440cb).

## Independent source audit

On 2026-07-25, the official crates.io metadata and download endpoints were
queried independently. The downloaded `glib 0.18.5` archive was 267,679 bytes
and its SHA-256 was:

```text
233daaf6e83ae6a12a52055f568f9d7cf4671dabb78ff9560ab6da230ce00ee5
```

That exactly matched the checksum published by crates.io and the original
registry entry removed from `Cargo.lock` when the path override was introduced.
The archive was extracted and all files were compared against the vendored
tree. The official archive contained 121 files; the vendored tree contained
123. The complete intentional difference set was:

1. `src/variant_iter.rs` has only the two upstream mutability changes shown
   above.
2. `GHSA-wrw7-89jp-8q8g.patch` was added to record that source diff.
3. `PROVENANCE.md` was added to record origin, integrity, licensing, and
   retirement information.

Every other source and metadata file matched the official archive byte for
byte. In particular, `.cargo_vcs_info.json`, `Cargo.toml`, `Cargo.toml.orig`,
`LICENSE`, and `COPYRIGHT` are pristine crate files rather than Glacial
modifications. The repository-level `[patch.crates-io]` entry is the Cargo path
resolution mechanism; it is not a change inside the crate.

## Why the override remains necessary

Glacial currently resolves Tauri `2.11.5` and Wry `0.55.1`. For Linux,
DragonFly BSD, FreeBSD, OpenBSD, and NetBSD, Wry's target-specific dependency
chain uses WebKitGTK `2.0.2` and GTK `0.18.2`, which in turn use the `glib 0.18`
API line. Updating only `glib` to `0.20` is not a sound Cargo substitution:
the GTK/WebKitGTK crates require the `0.18` line and Rust types from different
major/minor crate lines are not interchangeable. The normal update is
therefore blocked until the Tauri/Wry/WebKitGTK/GTK chain moves together to an
officially patched `glib` line.

This dependency path is relevant to Linux and BSD targets. Glacial's current
release tooling emits Windows x64 artifacts only, and Wry uses WebView2 rather
than WebKitGTK on Windows. That lowers the exposure of current published
artifacts, but it does not make an unsound locked dependency acceptable:
developers can resolve other targets, future release scope can change, and
automated dependency analysis correctly continues to inspect the manifest and
lockfile.

## Dependabot interpretation

Dependabot reasons from package identity and advisory version ranges. The local
crate deliberately remains named and versioned `glib 0.18.5`, so Dependabot may
continue reporting it even though the vendored source contains the correction.
The alert is still useful: it preserves visibility of a locally maintained
security exception and the need to retire it. It must not be dismissed or
ignored without this provenance, deterministic verification, and an explicit
removal plan.

The public GitHub advisory classifies the issue as **Moderate**. The exact
repository-specific Dependabot alert payload is separate from the public
advisory; package, affected manifest, severity, and state should be reported
only when that authenticated payload is directly available.

## Removal conditions

Remove the local override only when all of the following are true:

1. Glacial's supported Tauri/Wry dependency graph resolves an official `glib`
   release outside the advisory's affected range for every supported
   Linux/BSD target, without a parallel vulnerable `glib 0.18` instance.
2. The compatible WebKitGTK/GTK bindings have moved to that patched GLib API
   line; do not force only `glib` across an incompatible crate boundary.
3. `frontend/src-tauri/Cargo.toml` can remove the `[patch.crates-io]` entry and
   a freshly resolved `Cargo.lock` restores an official registry source and
   checksum for `glib`.
4. The vendored directory, this verification script, and backport-specific
   provenance can be removed in the same reviewed change.
5. Focused dependency resolution and supported-target validation pass, and the
   repository's Dependabot result no longer relies on a local-source exception.
