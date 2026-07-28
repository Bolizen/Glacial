use std::{env, fs, path::PathBuf};

fn main() {
    let profile = env::var("PROFILE").expect("Cargo build profile is unavailable");
    let version = env::var("CARGO_PKG_VERSION").expect("Cargo package version is unavailable");
    let identity = match env::var("GLACIAL_BUILD_IDENTITY_JSON") {
        Ok(value) => value,
        Err(_) if profile == "debug" => format!(
            concat!(
                r#"{{"schemaVersion":1,"productName":"Glacial","productVersion":"{}","#,
                r#""sourceCommit":null,"buildProfile":"development","lifecycleStage":"development","#,
                r#""trustClassification":"unsigned","signingState":"unsigned","signerSubject":null,"#,
                r#""signerThumbprint":null,"signerVerification":"not-applicable","frontendVersion":"{}","#,
                r#""tauriVersion":"{}","unavailableFields":["sourceCommit","signerSubject","signerThumbprint"]}}"#
            ),
            version, version, version
        ),
        Err(_) => panic!("Release construction requires a validated GLACIAL_BUILD_IDENTITY_JSON"),
    };
    validate_identity(&identity, &version, &profile);
    let output = PathBuf::from(env::var("OUT_DIR").expect("Cargo output directory is unavailable"))
        .join("build_identity.rs");
    fs::write(
        output,
        format!("pub const BUILD_IDENTITY_JSON: &str = {:?};\n", identity),
    )
    .expect("Could not write compiled build identity");
    println!("cargo:rerun-if-env-changed=GLACIAL_BUILD_IDENTITY_JSON");
    tauri_build::build()
}

fn validate_identity(value: &str, version: &str, profile: &str) {
    if value.len() > 4096
        || !value.is_ascii()
        || value.contains(['\r', '\n'])
        || !value.contains(r#""schemaVersion":1"#)
        || !value.contains(r#""productName":"Glacial""#)
        || !value.contains(&format!(r#""productVersion":"{version}""#))
        || !value.contains(&format!(r#""frontendVersion":"{version}""#))
        || !value.contains(&format!(r#""tauriVersion":"{version}""#))
    {
        panic!("Compiled build identity is missing or inconsistent");
    }
    if profile != "debug"
        && (!value.contains(r#""sourceCommit":"#)
            || value.contains(r#""sourceCommit":null"#)
            || !value.contains(r#""buildProfile":"#))
    {
        panic!("Production build identity lacks a source commit or profile");
    }
}
