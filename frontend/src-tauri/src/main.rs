#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod api_bridge;
mod backend;
mod windows_job;

use std::{
    fmt, fs,
    fs::OpenOptions,
    io::Write,
    path::Path,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    thread,
};
#[cfg(test)]
use std::path::PathBuf;

use backend::{BackendSupervisor, StartupError};
use serde_json::Value;
use tauri::Manager;

mod compiled_identity {
    include!(concat!(env!("OUT_DIR"), "/build_identity.rs"));
}

const MAX_EXPORT_BYTES: usize = 16 * 1024 * 1024;
static EXPORT_SEQUENCE: AtomicU64 = AtomicU64::new(0);

fn main() {
    let backend = Arc::new(BackendSupervisor::new());
    let setup_backend = Arc::clone(&backend);

    let app = tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| {
            if let Some(window) = app.get_webview_window("main") {
                let _ = window.set_focus();
            }
        }))
        .manage(Arc::clone(&backend))
        .invoke_handler(tauri::generate_handler![
            api_bridge::api_request,
            build_identity,
            save_export
        ])
        .setup(move |app| {
            let app_handle = app.handle().clone();
            let startup_backend = Arc::clone(&setup_backend);
            thread::spawn(move || {
                let startup = startup_backend.start_and_wait(&app_handle);
                if matches!(startup, Err(StartupError::Cancelled)) {
                    return;
                }
                if startup.is_err() {
                    startup_backend.terminate_child();
                }

                let error_message = startup.err().map(|error| {
                    let message = error.to_string();
                    eprintln!("Glacial desktop startup failed: {message}");
                    message
                });
                let window_backend = Arc::clone(&startup_backend);
                let main_thread_handle = app_handle.clone();
                if app_handle
                    .run_on_main_thread(move || {
                        if create_main_window(&main_thread_handle, error_message.as_deref())
                            .is_err()
                        {
                            eprintln!("Glacial could not create its main window.");
                            window_backend.shutdown();
                            main_thread_handle.exit(1);
                        }
                    })
                    .is_err()
                {
                    startup_backend.shutdown();
                    app_handle.exit(1);
                }
            });
            Ok(())
        })
        .build(tauri::generate_context!())
        .expect("error while building Glacial desktop application");

    app.run(move |app_handle, event| match event {
        tauri::RunEvent::WindowEvent {
            label,
            event: tauri::WindowEvent::Destroyed,
            ..
        } if label == "main" => {
            backend.shutdown();
            app_handle.exit(0);
        }
        tauri::RunEvent::ExitRequested { .. } | tauri::RunEvent::Exit => backend.shutdown(),
        _ => {}
    });
}

#[tauri::command]
fn build_identity() -> Result<Value, String> {
    serde_json::from_str(compiled_identity::BUILD_IDENTITY_JSON)
        .map_err(|_| "The compiled Glacial build identity is unavailable.".to_string())
}

#[tauri::command]
fn save_export(app: tauri::AppHandle, file_name: String, bytes: Vec<u8>) -> Result<String, String> {
    let downloads = app
        .path()
        .download_dir()
        .map_err(|_| export_error())?;
    save_export_to_directory(&downloads, &file_name, &bytes).map_err(|_| export_error())
}

fn export_error() -> String {
    "Glacial could not save the export.".to_string()
}

fn save_export_to_directory(
    directory: &Path,
    file_name: &str,
    bytes: &[u8],
) -> std::io::Result<String> {
    if !valid_export_file_name(file_name) || bytes.is_empty() || bytes.len() > MAX_EXPORT_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "invalid export",
        ));
    }
    let directory = fs::canonicalize(directory)?;
    if !directory.is_dir() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "download directory is unavailable",
        ));
    }

    let sequence = EXPORT_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let temporary = directory.join(format!(
        ".glacial-export-{}-{sequence}.tmp",
        std::process::id()
    ));
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)?;
    let publication = (|| {
        output.write_all(bytes)?;
        output.sync_all()?;
        drop(output);
        for collision in 0..1000 {
            let candidate_name = export_collision_name(file_name, collision);
            let candidate = directory.join(&candidate_name);
            if candidate.exists() {
                continue;
            }
            match fs::rename(&temporary, &candidate) {
                Ok(()) => return Ok(candidate_name),
                Err(_) if candidate.exists() => continue,
                Err(error) => return Err(error),
            }
        }
        Err(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "export filename space is exhausted",
        ))
    })();
    if publication.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    publication
}

fn valid_export_file_name(value: &str) -> bool {
    if value == "scan-report.md" {
        return true;
    }
    for (prefix, suffix) in [
        ("glacial-agent-remediation-brief-scan-", ".md"),
        ("glacial-agent-remediation-package-scan-", ".zip"),
    ] {
        let Some(scan_id) = value
            .strip_prefix(prefix)
            .and_then(|remaining| remaining.strip_suffix(suffix))
        else {
            continue;
        };
        if !scan_id.is_empty()
            && !scan_id.starts_with('0')
            && scan_id.bytes().all(|byte| byte.is_ascii_digit())
        {
            return true;
        }
    }
    false
}

fn export_collision_name(file_name: &str, collision: usize) -> String {
    if collision == 0 {
        return file_name.to_string();
    }
    let (stem, extension) = file_name
        .rsplit_once('.')
        .expect("validated export filenames always have an extension");
    format!("{stem} ({collision}).{extension}")
}

fn create_main_window(app: &tauri::AppHandle, startup_error: Option<&str>) -> tauri::Result<()> {
    let mut window_config = app
        .config()
        .app
        .windows
        .iter()
        .find(|window| window.label == "main")
        .expect("main window configuration is missing")
        .clone();
    if let Some(message) = startup_error {
        window_config.url = tauri::WebviewUrl::App(startup_error_url(message).into());
    }
    tauri::WebviewWindowBuilder::from_config(app, &window_config)?
        .general_autofill_enabled(webview_general_autofill_enabled())
        .build()?;
    Ok(())
}

fn webview_general_autofill_enabled() -> bool {
    false
}

fn startup_error_url(message: &str) -> String {
    let mut url = String::from("startup-error.html?message=");
    for byte in message.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            url.push(char::from(byte));
        } else {
            use fmt::Write as _;
            let _ = write!(url, "%{byte:02X}");
        }
    }
    url
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn startup_diagnostics_are_percent_encoded_and_use_text_content() {
        let url = startup_error_url("bad </script> & \"quoted\"");
        assert_eq!(
            url,
            "startup-error.html?message=bad%20%3C%2Fscript%3E%20%26%20%22quoted%22"
        );
        let script = include_str!("../../public/startup-error.js");
        assert!(script.contains("detail.textContent"));
        assert!(!script.contains("innerHTML"));
    }

    #[test]
    fn compiled_build_identity_is_bounded_and_matches_the_rust_package() {
        let identity: Value = serde_json::from_str(compiled_identity::BUILD_IDENTITY_JSON).unwrap();
        assert_eq!(identity["schemaVersion"], 1);
        assert_eq!(identity["productName"], "Glacial");
        assert_eq!(identity["productVersion"], env!("CARGO_PKG_VERSION"));
        assert_eq!(identity["tauriVersion"], env!("CARGO_PKG_VERSION"));
        assert!(compiled_identity::BUILD_IDENTITY_JSON.len() < 4096);
    }

    #[test]
    fn native_exports_are_bounded_allowlisted_atomic_and_non_overwriting() {
        let directory = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("target")
            .join(format!("glacial-export-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&directory);
        fs::create_dir_all(&directory).unwrap();

        let first =
            save_export_to_directory(&directory, "scan-report.md", b"first report").unwrap();
        let second =
            save_export_to_directory(&directory, "scan-report.md", b"second report").unwrap();
        assert_eq!(first, "scan-report.md");
        assert_eq!(second, "scan-report (1).md");
        assert_eq!(fs::read(directory.join(first)).unwrap(), b"first report");
        assert_eq!(fs::read(directory.join(second)).unwrap(), b"second report");
        assert!(!fs::read_dir(&directory)
            .unwrap()
            .any(|entry| entry.unwrap().file_name().to_string_lossy().starts_with(".glacial-export-")));

        for invalid in [
            "../scan-report.md",
            r"..\scan-report.md",
            r"C:\scan-report.md",
            "glacial-agent-remediation-brief-scan-0.md",
            "glacial-agent-remediation-package-scan-latest.zip",
            "report.html",
        ] {
            assert!(save_export_to_directory(&directory, invalid, b"content").is_err());
        }
        assert!(save_export_to_directory(&directory, "scan-report.md", &[]).is_err());
        assert!(save_export_to_directory(
            &directory,
            "glacial-agent-remediation-package-scan-1.zip",
            &vec![0; MAX_EXPORT_BYTES + 1],
        )
        .is_err());

        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn webview_general_autofill_is_disabled_for_sensitive_project_forms() {
        assert!(!webview_general_autofill_enabled());
    }
}
