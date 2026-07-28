# Third-party notices

Glacial includes third-party software in its installed Windows application. This file identifies the current runtime inventory and separates it from tools used only to build or test Glacial. It is a notice record, not legal advice and not a change to Glacial's own license.

The exact machine-readable inventory is in [`docs/release/third-party-runtime-inventory.json`](docs/release/third-party-runtime-inventory.json). Versions are derived from the locked frontend, Python, and Windows-target Rust dependency graphs used for the installed application.

## Installed runtime

- **Frontend bundle:** `@tauri-apps/api`, React, React DOM, and Scheduler. Tauri API code is available under Apache-2.0 or MIT; React, React DOM, and Scheduler are MIT-licensed and copyright Meta Platforms, Inc. and affiliates.
- **Windows application:** Tauri, Wry, Tao, the Tauri single-instance and shell plugins, WebView2 bindings, `serde_json`, `windows-sys`, the vendored patched `glib` crate, and their locked Windows-target Rust dependencies. Their exact versions and SPDX license expressions are recorded in the inventory. The patched `glib` source retains its [MIT license](third_party/rust/glib-0.18.5-patched/LICENSE), [copyright record](third_party/rust/glib-0.18.5-patched/COPYRIGHT), and [provenance](third_party/rust/glib-0.18.5-patched/PROVENANCE.md).
- **Packaged backend:** Python 3.13 runtime, FastAPI, Starlette, Pydantic, Uvicorn, AnyIO, Click, h11, idna, annotated-doc, annotated-types, pydantic-core, typing-inspection, typing-extensions, Colorama, and bundled supporting runtime files. Package versions and declared licenses are recorded in the inventory.
- **Native backend libraries:** the Python distribution includes OpenSSL, SQLite, libffi, and Microsoft Visual C++ runtime files used by the packaged backend.
- **Installer:** the NSIS installer and Tauri NSIS support code package the application. Microsoft Edge WebView2 Evergreen Runtime is a prerequisite acquired from Microsoft when absent; it is not redistributed as a Glacial-owned component in the current download-bootstrapper configuration.

The standard MIT, BSD-3-Clause, Apache-2.0, Python Software Foundation, OpenSSL, and other component license terms remain those published by each component and identified by the inventory's license field. Upstream copyright and notice files remain authoritative for each dependency.

## Build and development tools

Vite, `@vitejs/plugin-react`, the Tauri CLI, PyInstaller, PyInstaller hooks, setuptools build tooling, Cargo, Rust, npm, and the remaining test dependencies are build or development inputs. They are not installed as standalone Glacial runtime packages. Generated or embedded portions, such as the PyInstaller bootloader and Vite runtime helpers, remain subject to their upstream terms and are represented in the runtime review.

## Project license

Glacial v0.9.8 is licensed under the Functional Source License, Version 1.1, ALv2 Future License (`FSL-1.1-ALv2`). The root [`LICENSE`](LICENSE) file controls Glacial's original code. Third-party components remain under their own licenses.

## Review status

The G051 review reconciles lockfiles, the Windows-target Cargo graph, Python runtime locks, the PyInstaller payload families, Tauri configuration, and the G050 installed inventory. It does not constitute legal sign-off. Before public candidate authorization, the maintainer must confirm that the final installer carries or makes available every notice and license required by the exact frozen artifact. Until that artifact readback and owner review occur, `V1-DOC-005` remains incomplete.
