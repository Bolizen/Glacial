# glib 0.18.5 soundness backport provenance

## Origin

- Original crate: `glib`
- Original version: `0.18.5`
- Official archive: `https://crates.io/api/v1/crates/glib/0.18.5/download`
- Official crates.io SHA-256: `233daaf6e83ae6a12a52055f568f9d7cf4671dabb78ff9560ab6da230ce00ee5`
- Recorded crate VCS commit: `42b9caf98e03ded086362d9653ca58fe94dc8658`
- Upstream repository: `https://github.com/gtk-rs/gtk-rs-core`
- Advisories: `GHSA-wrw7-89jp-8q8g`, `RUSTSEC-2024-0429`
- Upstream fix: `https://github.com/gtk-rs/gtk-rs-core/pull/1343`
- Upstream patch commit: `b5a4071e439bef2b5eea76c3aa25e5ae84839e34`
- Upstream merge commit: `05dff0ee696f9bcd8617cd48c4b812d046d440cb`
- Glacial backport commit: `57383649f2766e6752170811286d89d393b318c6`

The official metadata and archive were fetched again on 2026-07-25. The
downloaded 267,679-byte archive hash matched the checksum published by
crates.io. A complete extracted-tree comparison found the intentional
differences listed below and no others.

## Preserved licence

The crate is MIT-licensed. The official `LICENSE` and `COPYRIGHT` files are
preserved byte for byte:

- `LICENSE` SHA-256 (LF-normalized):
  `8cf56d10131ce201cf69ab74b111d3ebac1acca3833d7efb39ae357224b70edb`
- `COPYRIGHT` SHA-256 (LF-normalized):
  `dae402989de65164815b7e2b6bc2b9576285434c3785934c8b6ece0fa055960d`

## Complete intentional deviation list

The official archive contains 121 files. This vendored directory contains the
same files plus two provenance records, for 123 files total. Every intentional
deviation from pristine `glib 0.18.5` is:

1. `src/variant_iter.rs`: in `VariantStrIter::impl_get`, `let p` is changed to
   `let mut p`, and the FFI out-argument `&p` is changed to `&mut p`.
2. `GHSA-wrw7-89jp-8q8g.patch`: added by Glacial as the complete two-line
   source-diff record.
3. `PROVENANCE.md`: added by Glacial as this provenance, integrity, licence,
   and retirement record.

No licence file or Cargo package metadata was added or altered for the
backport. `.cargo_vcs_info.json`, `Cargo.toml`, `Cargo.toml.orig`, `LICENSE`,
and `COPYRIGHT` are pristine files from the official archive. Cargo path
resolution is configured outside this directory in
`frontend/src-tauri/Cargo.toml`.

## Documented verification baseline

- Pristine `src/variant_iter.rs` SHA-256 (LF-normalized):
  `1fd02859333761c45321b32f28b24233446b97d0022a90d3a937ed162585b90e`
- Patched `src/variant_iter.rs` SHA-256 (LF-normalized):
  `a0f5ee8acb8faa089bcdfbc9a57372609fce7654026ccef7d9a224d05a654ccc`
- `GHSA-wrw7-89jp-8q8g.patch` SHA-256 (LF-normalized):
  `982b07f58864aad3d0aa0421cdd8ddc7438bb862b93e7b6b34da96b4147f8add`

Run `node scripts/security/verify-glib-backport.mjs` from the Glacial
repository root to enforce this baseline.

## Retirement

Remove the override only after Glacial's supported Tauri/Wry/WebKitGTK/GTK
dependency graph resolves an official `glib` version outside
`>= 0.15.0, < 0.20.0` for every supported Linux/BSD target, the Cargo patch
and vendored crate can be removed together, and supported-target resolution
and validation pass without a parallel affected `glib` package.
