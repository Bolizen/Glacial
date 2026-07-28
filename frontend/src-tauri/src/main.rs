#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod api_bridge;
mod backend;
mod windows_job;

use std::{fmt, sync::Arc, thread};

use backend::{BackendSupervisor, StartupError};
use serde_json::Value;
use tauri::Manager;

mod compiled_identity {
    include!(concat!(env!("OUT_DIR"), "/build_identity.rs"));
}

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
        .invoke_handler(tauri::generate_handler![api_bridge::api_request, build_identity])
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
    tauri::WebviewWindowBuilder::from_config(app, &window_config)?.build()?;
    Ok(())
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
}
