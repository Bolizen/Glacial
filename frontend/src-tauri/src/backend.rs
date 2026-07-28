use std::{
    fmt, fs,
    io::{Read, Write},
    net::{SocketAddr, TcpStream},
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Receiver, RecvTimeoutError},
        Arc, Mutex,
    },
    time::{Duration, Instant},
};

#[cfg(debug_assertions)]
use std::{
    path::Path,
    process::{Child, Command, Stdio},
    sync::mpsc::Sender,
    thread,
};
use tauri::{AppHandle, Manager};
#[cfg(not(debug_assertions))]
use tauri_plugin_shell::{
    process::{CommandChild, CommandEvent},
    ShellExt,
};
use windows_sys::Win32::Security::Cryptography::{
    BCryptGenRandom, BCRYPT_USE_SYSTEM_PREFERRED_RNG,
};

use crate::windows_job::JobObject;
#[cfg(not(debug_assertions))]
use crate::windows_job::ProcessWaitHandle;

const AUTH_TOKEN_ENV: &str = "GLACIAL_DESKTOP_AUTH_TOKEN";
const DATA_DIR_ENV: &str = "GLACIAL_DESKTOP_DATA_DIR";
#[cfg(not(debug_assertions))]
const SIDECAR_NAME: &str = "glacial-backend";
const STARTUP_PREFIX: &str = "GLACIAL_BACKEND_READY ";
const MAX_STARTUP_MESSAGE_BYTES: usize = 96;
const MAX_DIAGNOSTIC_BYTES: usize = 64 * 1024;
const STARTUP_TIMEOUT: Duration = Duration::from_secs(15);
const POLL_INTERVAL: Duration = Duration::from_millis(100);
const HEALTH_IO_TIMEOUT: Duration = Duration::from_millis(500);
#[cfg(not(debug_assertions))]
const PROCESS_WAIT_MILLIS: u32 = 5_000;

#[derive(Clone)]
pub(crate) struct BackendEndpoint {
    pub(crate) address: SocketAddr,
    pub(crate) token: String,
}

pub(crate) struct BackendSupervisor {
    child: Mutex<Option<OwnedChild>>,
    endpoint: Mutex<Option<BackendEndpoint>>,
    job: Mutex<Option<JobObject>>,
    shutting_down: AtomicBool,
}

impl BackendSupervisor {
    pub(crate) fn new() -> Self {
        Self {
            child: Mutex::new(None),
            endpoint: Mutex::new(None),
            job: Mutex::new(None),
            shutting_down: AtomicBool::new(false),
        }
    }

    pub(crate) fn start_and_wait(&self, app: &AppHandle) -> Result<(), StartupError> {
        let token = generate_auth_token()?;
        let paths = DesktopPaths::resolve(app)?;
        let diagnostics = Arc::new(StartupDiagnostics::new(
            paths.log_file.clone(),
            token.clone(),
        )?);
        let launched = match launch_backend(app, &paths, &token, Arc::clone(&diagnostics)) {
            Ok(launched) => launched,
            Err(error) => {
                diagnostics.persist();
                return Err(error);
            }
        };

        {
            let mut child = self
                .child
                .lock()
                .map_err(|_| StartupError::SupervisorState)?;
            if child.is_some() {
                terminate_owned_child(launched.child);
                return Err(StartupError::DuplicateSpawn);
            }
            *child = Some(launched.child);
        }
        if let Some(job) = launched.job {
            match self.job.lock() {
                Ok(mut owned_job) => *owned_job = Some(job),
                Err(_) => {
                    drop(job);
                    self.terminate_child();
                    diagnostics.persist();
                    return Err(StartupError::SupervisorState);
                }
            }
        }

        let result = self.wait_for_readiness(launched.events, token);
        if result.is_err() {
            diagnostics.persist();
            self.terminate_child();
        }
        result
    }

    pub(crate) fn endpoint(&self) -> Option<BackendEndpoint> {
        self.endpoint.lock().ok().and_then(|value| value.clone())
    }

    pub(crate) fn shutdown(&self) {
        self.shutting_down.store(true, Ordering::SeqCst);
        self.terminate_child();
    }

    pub(crate) fn terminate_child(&self) {
        if let Ok(mut endpoint) = self.endpoint.lock() {
            *endpoint = None;
        }
        let child = self.child.lock().ok().and_then(|mut value| value.take());
        if let Some(child) = child {
            terminate_owned_child(child);
        }
        if let Ok(mut job) = self.job.lock() {
            *job = None;
        }
    }

    fn wait_for_readiness(
        &self,
        events: Receiver<BackendEvent>,
        token: String,
    ) -> Result<(), StartupError> {
        let deadline = Instant::now() + STARTUP_TIMEOUT;
        let mut port = None;
        while Instant::now() < deadline {
            if self.shutting_down.load(Ordering::SeqCst) {
                return Err(StartupError::Cancelled);
            }
            match events.recv_timeout(POLL_INTERVAL) {
                Ok(BackendEvent::Stdout(line)) => {
                    if port.is_some() {
                        return Err(StartupError::DuplicateStartupMessage);
                    }
                    port = Some(parse_startup_port(&line)?);
                }
                Ok(BackendEvent::StdoutInvalid) => {
                    return Err(StartupError::MalformedStartupMessage)
                }
                #[cfg(not(debug_assertions))]
                Ok(BackendEvent::Terminated(code)) => return Err(StartupError::EarlyExit(code)),
                Ok(BackendEvent::InternalError) => return Err(StartupError::ChildStatus),
                Err(RecvTimeoutError::Disconnected) => {
                    self.ensure_debug_child_is_running()?;
                }
                Err(RecvTimeoutError::Timeout) => {}
            }
            self.ensure_debug_child_is_running()?;

            if let Some(port) = port {
                let address = SocketAddr::from(([127, 0, 0, 1], port));
                if authenticated_health_check(address, &token) {
                    for event in events.try_iter() {
                        match event {
                            BackendEvent::Stdout(_) => {
                                return Err(StartupError::DuplicateStartupMessage)
                            }
                            BackendEvent::StdoutInvalid => {
                                return Err(StartupError::MalformedStartupMessage)
                            }
                            #[cfg(not(debug_assertions))]
                            BackendEvent::Terminated(code) => {
                                return Err(StartupError::EarlyExit(code))
                            }
                            BackendEvent::InternalError => return Err(StartupError::ChildStatus),
                        }
                    }
                    self.ensure_debug_child_is_running()?;
                    *self
                        .endpoint
                        .lock()
                        .map_err(|_| StartupError::SupervisorState)? =
                        Some(BackendEndpoint { address, token });
                    return Ok(());
                }
            }
        }
        Err(if port.is_some() {
            StartupError::HealthTimeout(STARTUP_TIMEOUT)
        } else {
            StartupError::StartupMessageTimeout(STARTUP_TIMEOUT)
        })
    }

    #[cfg(debug_assertions)]
    fn ensure_debug_child_is_running(&self) -> Result<(), StartupError> {
        let mut child = self
            .child
            .lock()
            .map_err(|_| StartupError::SupervisorState)?;
        let exit_code = match child.as_mut() {
            Some(OwnedChild::Debug(process)) => match process.try_wait() {
                Ok(None) => None,
                Ok(Some(status)) => Some(status.code()),
                Err(_) => return Err(StartupError::ChildStatus),
            },
            _ => None,
        };
        if let Some(code) = exit_code {
            *child = None;
            return Err(StartupError::EarlyExit(code));
        }
        Ok(())
    }

    #[cfg(not(debug_assertions))]
    fn ensure_debug_child_is_running(&self) -> Result<(), StartupError> {
        Ok(())
    }
}

struct DesktopPaths {
    data_dir: PathBuf,
    log_file: PathBuf,
    #[cfg(debug_assertions)]
    debug_backend: BackendPaths,
}

impl DesktopPaths {
    fn resolve(app: &AppHandle) -> Result<Self, StartupError> {
        let data_root = app
            .path()
            .app_local_data_dir()
            .map_err(|_| StartupError::ApplicationData)?;
        let log_root = app
            .path()
            .app_log_dir()
            .map_err(|_| StartupError::ApplicationData)?;
        #[cfg(debug_assertions)]
        let (data_dir, log_dir) = (
            data_root.join("development").join("data"),
            log_root.join("development"),
        );
        #[cfg(not(debug_assertions))]
        let (data_dir, log_dir) = (data_root.join("data"), log_root);

        fs::create_dir_all(&data_dir).map_err(|_| StartupError::ApplicationData)?;
        fs::create_dir_all(&log_dir).map_err(|_| StartupError::ApplicationData)?;
        Ok(Self {
            data_dir,
            log_file: log_dir.join("backend-startup.log"),
            #[cfg(debug_assertions)]
            debug_backend: resolve_backend_paths(Path::new(env!("CARGO_MANIFEST_DIR")))?,
        })
    }
}

#[cfg(debug_assertions)]
struct BackendPaths {
    backend: PathBuf,
    python: PathBuf,
}

#[cfg(debug_assertions)]
struct BackendCommand {
    executable: PathBuf,
    working_directory: PathBuf,
    arguments: [&'static str; 2],
}

struct LaunchedBackend {
    child: OwnedChild,
    events: Receiver<BackendEvent>,
    job: Option<JobObject>,
}

enum OwnedChild {
    #[cfg(debug_assertions)]
    Debug(Child),
    #[cfg(not(debug_assertions))]
    Sidecar(CommandChild),
}

enum BackendEvent {
    Stdout(Vec<u8>),
    StdoutInvalid,
    #[cfg(not(debug_assertions))]
    Terminated(Option<i32>),
    InternalError,
}

#[cfg(debug_assertions)]
fn launch_backend(
    _app: &AppHandle,
    paths: &DesktopPaths,
    token: &str,
    diagnostics: Arc<StartupDiagnostics>,
) -> Result<LaunchedBackend, StartupError> {
    let mut command = authenticated_backend_command(&paths.debug_backend, token, &paths.data_dir);
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x0800_0000);
    }
    let mut child = command.spawn().map_err(|_| StartupError::Spawn)?;
    let Some(stdout) = child.stdout.take() else {
        let _ = child.kill();
        let _ = child.wait();
        return Err(StartupError::Spawn);
    };
    let Some(stderr) = child.stderr.take() else {
        let _ = child.kill();
        let _ = child.wait();
        return Err(StartupError::Spawn);
    };
    let (sender, events) = mpsc::channel();
    spawn_bounded_stdout_reader(stdout, sender);
    spawn_diagnostic_reader(stderr, diagnostics);
    Ok(LaunchedBackend {
        child: OwnedChild::Debug(child),
        events,
        job: None,
    })
}

#[cfg(not(debug_assertions))]
fn launch_backend(
    app: &AppHandle,
    paths: &DesktopPaths,
    token: &str,
    diagnostics: Arc<StartupDiagnostics>,
) -> Result<LaunchedBackend, StartupError> {
    let command = app
        .shell()
        .sidecar(SIDECAR_NAME)
        .map_err(|_| StartupError::MissingSidecar)?
        .env(AUTH_TOKEN_ENV, token)
        .env(DATA_DIR_ENV, &paths.data_dir);
    let (mut receiver, child) = command.spawn().map_err(|_| StartupError::Spawn)?;
    let process_id = child.pid();
    let job = match JobObject::assign_process(process_id) {
        Ok(job) => job,
        Err(_) => {
            terminate_owned_child(OwnedChild::Sidecar(child));
            return Err(StartupError::Containment);
        }
    };

    let (sender, events) = mpsc::channel();
    tauri::async_runtime::spawn(async move {
        let mut startup_output = StartupOutputDecoder::new();
        'events: while let Some(event) = receiver.recv().await {
            let forwarded = match event {
                CommandEvent::Stdout(chunk) => {
                    let lines = match startup_output.push(&chunk) {
                        Ok(lines) => lines,
                        Err(()) => {
                            let _ = sender.send(BackendEvent::StdoutInvalid);
                            break;
                        }
                    };
                    for line in lines {
                        if sender.send(BackendEvent::Stdout(line)).is_err() {
                            break 'events;
                        }
                    }
                    continue;
                }
                CommandEvent::Stderr(line) => {
                    diagnostics.record(&line);
                    continue;
                }
                CommandEvent::Terminated(status) => {
                    if let Some(line) = startup_output.finish() {
                        if sender.send(BackendEvent::Stdout(line)).is_err() {
                            break;
                        }
                    }
                    sender.send(BackendEvent::Terminated(status.code))
                }
                CommandEvent::Error(message) => {
                    diagnostics.record(message.as_bytes());
                    sender.send(BackendEvent::InternalError)
                }
                _ => continue,
            };
            if forwarded.is_err() {
                break;
            }
        }
    });
    Ok(LaunchedBackend {
        child: OwnedChild::Sidecar(child),
        events,
        job: Some(job),
    })
}

#[cfg(any(not(debug_assertions), test))]
struct StartupOutputDecoder {
    line: Vec<u8>,
}

#[cfg(any(not(debug_assertions), test))]
impl StartupOutputDecoder {
    fn new() -> Self {
        Self { line: Vec::new() }
    }

    fn push(&mut self, chunk: &[u8]) -> Result<Vec<Vec<u8>>, ()> {
        let mut lines = Vec::new();
        for byte in chunk {
            if matches!(byte, b'\r' | b'\n') {
                if !self.line.is_empty() {
                    lines.push(std::mem::take(&mut self.line));
                }
                continue;
            }
            self.line.push(*byte);
            if self.line.len() > MAX_STARTUP_MESSAGE_BYTES {
                return Err(());
            }
        }
        Ok(lines)
    }

    fn finish(&mut self) -> Option<Vec<u8>> {
        (!self.line.is_empty()).then(|| std::mem::take(&mut self.line))
    }
}

#[cfg(debug_assertions)]
fn resolve_backend_paths(manifest_dir: &Path) -> Result<BackendPaths, StartupError> {
    let manifest_dir = manifest_dir
        .canonicalize()
        .map_err(|_| StartupError::RepositoryLayout)?;
    let frontend = manifest_dir
        .parent()
        .ok_or(StartupError::RepositoryLayout)?;
    let repository = frontend
        .parent()
        .ok_or(StartupError::RepositoryLayout)?
        .canonicalize()
        .map_err(|_| StartupError::RepositoryLayout)?;
    let backend = repository
        .join("backend")
        .canonicalize()
        .map_err(|_| StartupError::RepositoryLayout)?;
    if !backend.starts_with(&repository) {
        return Err(StartupError::RepositoryLayout);
    }
    let expected_python = backend.join(".venv").join("Scripts").join("python.exe");
    if !expected_python.is_file() {
        return Err(StartupError::MissingPython);
    }
    let python = expected_python
        .canonicalize()
        .map_err(|_| StartupError::MissingPython)?;
    if !python.starts_with(&backend) {
        return Err(StartupError::RepositoryLayout);
    }
    Ok(BackendPaths { backend, python })
}

#[cfg(debug_assertions)]
fn backend_command(paths: &BackendPaths) -> BackendCommand {
    BackendCommand {
        executable: paths.python.clone(),
        working_directory: paths.backend.clone(),
        arguments: ["-m", "app.desktop_entry"],
    }
}

#[cfg(debug_assertions)]
fn authenticated_backend_command(paths: &BackendPaths, token: &str, data_dir: &Path) -> Command {
    let specification = backend_command(paths);
    let mut command = Command::new(&specification.executable);
    command
        .args(specification.arguments)
        .current_dir(&specification.working_directory)
        .env(AUTH_TOKEN_ENV, token)
        .env(DATA_DIR_ENV, data_dir);
    command
}

#[cfg(debug_assertions)]
fn spawn_bounded_stdout_reader(
    mut reader: impl Read + Send + 'static,
    sender: Sender<BackendEvent>,
) {
    thread::spawn(move || {
        let mut line = Vec::new();
        let mut byte = [0_u8; 1];
        loop {
            match reader.read(&mut byte) {
                Ok(0) => {
                    if !line.is_empty() {
                        let _ = sender.send(BackendEvent::Stdout(line));
                    }
                    break;
                }
                Ok(_) if matches!(byte[0], b'\r' | b'\n') => {
                    if !line.is_empty()
                        && sender
                            .send(BackendEvent::Stdout(std::mem::take(&mut line)))
                            .is_err()
                    {
                        break;
                    }
                }
                Ok(_) => {
                    line.push(byte[0]);
                    if line.len() > MAX_STARTUP_MESSAGE_BYTES {
                        let _ = sender.send(BackendEvent::StdoutInvalid);
                        break;
                    }
                }
                Err(_) => {
                    let _ = sender.send(BackendEvent::InternalError);
                    break;
                }
            }
        }
    });
}

#[cfg(debug_assertions)]
fn spawn_diagnostic_reader(
    mut reader: impl Read + Send + 'static,
    diagnostics: Arc<StartupDiagnostics>,
) {
    thread::spawn(move || {
        let mut chunk = [0_u8; 4096];
        while let Ok(count) = reader.read(&mut chunk) {
            if count == 0 {
                break;
            }
            diagnostics.record(&chunk[..count]);
        }
    });
}

fn parse_startup_port(line: &[u8]) -> Result<u16, StartupError> {
    if line.is_empty() || line.len() > MAX_STARTUP_MESSAGE_BYTES {
        return Err(StartupError::MalformedStartupMessage);
    }
    let message = std::str::from_utf8(line).map_err(|_| StartupError::MalformedStartupMessage)?;
    let payload = message
        .strip_prefix(STARTUP_PREFIX)
        .and_then(|value| value.strip_prefix("{\"port\":"))
        .and_then(|value| value.strip_suffix('}'))
        .ok_or(StartupError::MalformedStartupMessage)?;
    if payload.is_empty() || !payload.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(StartupError::MalformedStartupMessage);
    }
    let port = payload
        .parse::<u16>()
        .map_err(|_| StartupError::MalformedStartupMessage)?;
    if port == 0 || message != format!("{STARTUP_PREFIX}{{\"port\":{port}}}") {
        return Err(StartupError::MalformedStartupMessage);
    }
    Ok(port)
}

fn authenticated_health_check(address: SocketAddr, token: &str) -> bool {
    let mut stream = match TcpStream::connect_timeout(&address, HEALTH_IO_TIMEOUT) {
        Ok(stream) => stream,
        Err(_) => return false,
    };
    if stream.set_read_timeout(Some(HEALTH_IO_TIMEOUT)).is_err()
        || stream.set_write_timeout(Some(HEALTH_IO_TIMEOUT)).is_err()
    {
        return false;
    }
    let request = format!(
        "GET /api/health HTTP/1.1\r\nHost: {address}\r\nAuthorization: Bearer {token}\r\nConnection: close\r\n\r\n"
    );
    if stream.write_all(request.as_bytes()).is_err() {
        return false;
    }
    let mut response = Vec::new();
    let mut chunk = [0_u8; 1024];
    loop {
        let count = match stream.read(&mut chunk) {
            Ok(count) => count,
            Err(_) => return false,
        };
        if count == 0 {
            break;
        }
        if response.len().saturating_add(count) > 4096 {
            return false;
        }
        response.extend_from_slice(&chunk[..count]);
    }
    valid_health_response(&response)
}

fn valid_health_response(response: &[u8]) -> bool {
    let response = match std::str::from_utf8(response) {
        Ok(response) => response,
        Err(_) => return false,
    };
    let Some((headers, body)) = response.split_once("\r\n\r\n") else {
        return false;
    };
    headers
        .lines()
        .next()
        .is_some_and(|status| status.starts_with("HTTP/1.1 200 "))
        && body
            .chars()
            .filter(|character| !character.is_whitespace())
            .collect::<String>()
            == r#"{"status":"ok"}"#
}

fn generate_auth_token() -> Result<String, StartupError> {
    let mut bytes = [0_u8; 32];
    let status = unsafe {
        BCryptGenRandom(
            std::ptr::null_mut(),
            bytes.as_mut_ptr(),
            bytes.len() as u32,
            BCRYPT_USE_SYSTEM_PREFERRED_RNG,
        )
    };
    if status < 0 {
        return Err(StartupError::RandomToken);
    }
    let mut token = String::with_capacity(64);
    for byte in bytes {
        use fmt::Write as _;
        write!(token, "{byte:02x}").map_err(|_| StartupError::RandomToken)?;
    }
    Ok(token)
}

fn terminate_owned_child(child: OwnedChild) {
    match child {
        #[cfg(debug_assertions)]
        OwnedChild::Debug(mut child) => {
            if child.try_wait().ok().flatten().is_none() {
                let _ = child.kill();
            }
            let _ = child.wait();
        }
        #[cfg(not(debug_assertions))]
        OwnedChild::Sidecar(child) => {
            let wait = ProcessWaitHandle::open(child.pid()).ok();
            let _ = child.kill();
            if let Some(wait) = wait {
                let _ = wait.wait(PROCESS_WAIT_MILLIS);
            }
        }
    }
}

struct StartupDiagnostics {
    path: PathBuf,
    token: String,
    buffer: Mutex<Vec<u8>>,
}

impl StartupDiagnostics {
    fn new(path: PathBuf, token: String) -> Result<Self, StartupError> {
        fs::write(&path, []).map_err(|_| StartupError::Diagnostics)?;
        Ok(Self {
            path,
            token,
            buffer: Mutex::new(Vec::new()),
        })
    }

    fn record(&self, value: &[u8]) {
        if let Ok(mut buffer) = self.buffer.lock() {
            let remaining = MAX_DIAGNOSTIC_BYTES.saturating_sub(buffer.len());
            buffer.extend_from_slice(&value[..value.len().min(remaining)]);
        }
    }

    fn persist(&self) {
        let Ok(buffer) = self.buffer.lock() else {
            return;
        };
        let text = String::from_utf8_lossy(&buffer).replace(&self.token, "[REDACTED]");
        let privacy_safe = sanitize_diagnostic_text(&text);
        let sanitized: String = privacy_safe
            .chars()
            .map(|character| {
                if character == '\n'
                    || character == '\r'
                    || character == '\t'
                    || !character.is_control()
                {
                    character
                } else {
                    '\u{FFFD}'
                }
            })
            .collect();
        let mut end = sanitized.len().min(MAX_DIAGNOSTIC_BYTES);
        while !sanitized.is_char_boundary(end) {
            end -= 1;
        }
        let _ = fs::write(&self.path, &sanitized.as_bytes()[..end]);
    }
}

fn sanitize_diagnostic_text(value: &str) -> String {
    value
        .replace("\r\n", "\n")
        .replace('\r', "\n")
        .split('\n')
        .map(sanitize_diagnostic_line)
        .collect::<Vec<_>>()
        .join("\n")
}

fn sanitize_diagnostic_line(value: &str) -> String {
    let lower = value.to_ascii_lowercase();
    if [
        "authorization:",
        "authorization=",
        "bearer ",
        "password=",
        "password:",
        "passwd=",
        "token=",
        "token:",
        "secret=",
        "secret:",
        "api_key=",
        "api-key=",
        "private key",
        "github_pat_",
        "ghp_",
    ]
    .iter()
    .any(|marker| lower.contains(marker))
        || value.contains("AKIA")
        || value.contains("ASIA")
    {
        return "[REDACTED SENSITIVE DIAGNOSTIC]".to_string();
    }

    value
        .split_whitespace()
        .map(|item| {
            let candidate = item.trim_matches(|character: char| {
                matches!(character, '"' | '\'' | '(' | ')' | '[' | ']' | '{' | '}' | ',' | ';')
            });
            if looks_like_absolute_host_path(candidate) {
                "<HOST_PATH>".to_string()
            } else if contains_bounded_hex_token(candidate) {
                redact_bounded_hex_tokens(item)
            } else if looks_like_secret_token(candidate) {
                "[REDACTED]".to_string()
            } else {
                item.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn contains_bounded_hex_token(value: &str) -> bool {
    redact_bounded_hex_tokens(value) != value
}

fn redact_bounded_hex_tokens(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut result = String::with_capacity(value.len());
    let mut copied_until = 0;
    let mut index = 0;
    while index < bytes.len() {
        if !bytes[index].is_ascii_hexdigit() {
            index += 1;
            continue;
        }
        let start = index;
        while index < bytes.len() && bytes[index].is_ascii_hexdigit() {
            index += 1;
        }
        let bounded_left = start == 0 || !bytes[start - 1].is_ascii_alphanumeric();
        let bounded_right = index == bytes.len() || !bytes[index].is_ascii_alphanumeric();
        if (40..=128).contains(&(index - start)) && bounded_left && bounded_right {
            result.push_str(&value[copied_until..start]);
            result.push_str("[REDACTED]");
            copied_until = index;
        }
    }
    if copied_until == 0 {
        return value.to_string();
    }
    result.push_str(&value[copied_until..]);
    result
}

fn looks_like_absolute_host_path(value: &str) -> bool {
    let bytes = value.as_bytes();
    let windows_drive = bytes.len() >= 3
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && matches!(bytes[2], b'\\' | b'/');
    let unc = value.starts_with(r"\\") || value.starts_with("\\\\?\\");
    let posix = [
        "/Users/",
        "/home/",
        "/tmp/",
        "/var/tmp/",
        "/private/tmp/",
        "/opt/",
        "/srv/",
        "/mnt/",
        "/media/",
    ]
    .iter()
    .any(|prefix| value.starts_with(prefix));
    windows_drive || unc || posix
}

fn looks_like_secret_token(value: &str) -> bool {
    if value.len() < 32 {
        return false;
    }
    let has_letter = value.bytes().any(|byte| byte.is_ascii_alphabetic());
    let has_digit = value.bytes().any(|byte| byte.is_ascii_digit());
    let has_symbol = value
        .bytes()
        .any(|byte| matches!(byte, b'.' | b'_' | b'~' | b'+' | b'/' | b'=' | b'-'));
    let mut distinct = [false; 256];
    for byte in value.bytes() {
        distinct[usize::from(byte)] = true;
    }
    has_letter
        && (has_digit || has_symbol)
        && distinct.into_iter().filter(|present| *present).count() >= 10
}

#[derive(Debug)]
pub(crate) enum StartupError {
    ApplicationData,
    #[cfg(debug_assertions)]
    RepositoryLayout,
    #[cfg(debug_assertions)]
    MissingPython,
    #[cfg(not(debug_assertions))]
    MissingSidecar,
    Spawn,
    DuplicateSpawn,
    RandomToken,
    #[cfg(not(debug_assertions))]
    Containment,
    MalformedStartupMessage,
    DuplicateStartupMessage,
    StartupMessageTimeout(Duration),
    EarlyExit(Option<i32>),
    ChildStatus,
    HealthTimeout(Duration),
    Diagnostics,
    SupervisorState,
    Cancelled,
}

impl fmt::Display for StartupError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ApplicationData => write!(
                formatter,
                "Glacial could not prepare its private desktop data directory."
            ),
            #[cfg(debug_assertions)]
            Self::RepositoryLayout => write!(
                formatter,
                "Glacial could not resolve its development backend safely."
            ),
            #[cfg(debug_assertions)]
            Self::MissingPython => write!(
                formatter,
                "Glacial's development backend Python executable was not found."
            ),
            #[cfg(not(debug_assertions))]
            Self::MissingSidecar => write!(
                formatter,
                "Glacial's packaged backend sidecar was not found."
            ),
            Self::Spawn => write!(
                formatter,
                "Glacial could not start its owned backend process."
            ),
            Self::DuplicateSpawn => write!(formatter, "Glacial refused a duplicate backend start."),
            Self::RandomToken => write!(
                formatter,
                "Glacial could not generate secure desktop API credentials."
            ),
            #[cfg(not(debug_assertions))]
            Self::Containment => write!(
                formatter,
                "Glacial could not contain its backend process safely, so startup was stopped."
            ),
            Self::MalformedStartupMessage => write!(
                formatter,
                "The Glacial backend returned an invalid startup message."
            ),
            Self::DuplicateStartupMessage => write!(
                formatter,
                "The Glacial backend returned more than one startup message."
            ),
            Self::StartupMessageTimeout(timeout) => write!(
                formatter,
                "The Glacial backend did not report its owned port within {} seconds.",
                timeout.as_secs()
            ),
            Self::EarlyExit(Some(code)) => write!(
                formatter,
                "The Glacial backend exited before becoming healthy (exit code {code})."
            ),
            Self::EarlyExit(None) => write!(
                formatter,
                "The Glacial backend exited before becoming healthy."
            ),
            Self::ChildStatus => write!(
                formatter,
                "Glacial could not safely inspect its backend process."
            ),
            Self::HealthTimeout(timeout) => write!(
                formatter,
                "The Glacial backend did not pass authenticated /api/health within {} seconds.",
                timeout.as_secs()
            ),
            Self::Diagnostics => write!(
                formatter,
                "Glacial could not create its bounded backend startup log."
            ),
            Self::SupervisorState => write!(
                formatter,
                "Glacial could not safely access its backend process state."
            ),
            Self::Cancelled => write!(formatter, "Glacial shut down during backend startup."),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn development_command_uses_the_supervisor_token_without_serializing_it() {
        let paths = BackendPaths {
            backend: PathBuf::from(r"Z:\repo\backend"),
            python: PathBuf::from(r"Z:\repo\backend\.venv\Scripts\python.exe"),
        };
        let data_dir = PathBuf::from(r"C:\Users\developer\AppData\Local\Glacial\data");
        let token = "a".repeat(64);
        let command = authenticated_backend_command(&paths, &token, &data_dir);
        assert_eq!(command.get_program(), paths.python.as_os_str());
        assert_eq!(command.get_current_dir(), Some(paths.backend.as_path()));
        assert_eq!(
            command.get_args().collect::<Vec<_>>(),
            [
                std::ffi::OsStr::new("-m"),
                std::ffi::OsStr::new("app.desktop_entry")
            ],
        );
        assert!(command.get_envs().any(|(name, value)| {
            name == std::ffi::OsStr::new(AUTH_TOKEN_ENV)
                && value == Some(std::ffi::OsStr::new(&token))
        }));
        assert!(command.get_envs().any(|(name, value)| {
            name == std::ffi::OsStr::new(DATA_DIR_ENV) && value == Some(data_dir.as_os_str())
        }));
    }

    #[test]
    fn startup_message_parser_is_exact_and_bounded() {
        assert_eq!(
            parse_startup_port(b"GLACIAL_BACKEND_READY {\"port\":49152}").unwrap(),
            49152
        );
        for invalid in [
            b"GLACIAL_BACKEND_READY {\"port\":0}".as_slice(),
            b"GLACIAL_BACKEND_READY {\"port\":8000,\"port\":8001}".as_slice(),
            b"GLACIAL_BACKEND_READY {\"port\":8000,\"token\":\"secret\"}".as_slice(),
            b"http://127.0.0.1:8000".as_slice(),
        ] {
            assert!(parse_startup_port(invalid).is_err());
        }
        assert!(parse_startup_port(&vec![b'x'; MAX_STARTUP_MESSAGE_BYTES + 1]).is_err());
    }

    #[test]
    fn shell_stdout_chunks_are_framed_into_bounded_lines() {
        let mut decoder = StartupOutputDecoder::new();
        assert!(decoder
            .push(b"GLACIAL_BACKEND_READY {\"port\":")
            .unwrap()
            .is_empty());
        assert_eq!(
            decoder.push(b"49152}\r\n").unwrap(),
            vec![b"GLACIAL_BACKEND_READY {\"port\":49152}".to_vec()]
        );
        assert!(decoder.finish().is_none());

        assert!(decoder
            .push(&vec![b'x'; MAX_STARTUP_MESSAGE_BYTES + 1])
            .is_err());
    }

    #[test]
    fn secure_tokens_are_fresh_lowercase_256_bit_values() {
        let first = generate_auth_token().unwrap();
        let second = generate_auth_token().unwrap();
        assert_eq!(first.len(), 64);
        assert!(first
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()));
        assert_ne!(first, second);
    }

    #[test]
    fn accepts_only_the_expected_health_response() {
        assert!(valid_health_response(
            b"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n\r\n{\"status\":\"ok\"}"
        ));
        assert!(!valid_health_response(
            b"HTTP/1.1 401 Unauthorized\r\n\r\n{\"status\":\"ok\"}"
        ));
    }

    #[test]
    fn diagnostics_are_bounded_and_redact_secrets_paths_and_the_full_token() {
        let temporary = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("target")
            .join(format!("glacial-diagnostics-{}.log", std::process::id()));
        let token = "a".repeat(64);
        let diagnostics = StartupDiagnostics::new(temporary.clone(), token.clone()).unwrap();
        diagnostics.record(format!("before {token} after\n").as_bytes());
        diagnostics.record(b"error at C:\\Users\\privacy-canary\\AppData\\Local\\Temp\\trace.log\n");
        diagnostics.record(b"Authorization: Bearer fake-diagnostic-token\n");
        diagnostics.record(b"password=fake-password-canary\n");
        let hex_canaries = [
            "A1".repeat(20),
            "b2".repeat(32),
            "C3d4".repeat(24),
            "e5F6".repeat(32),
        ];
        diagnostics.record(
            format!(
                "{}\nprose {}\nevidence/{}.txt\nsha512:{}\n",
                hex_canaries[0], hex_canaries[1], hex_canaries[2], hex_canaries[3]
            )
            .as_bytes(),
        );
        diagnostics.record(&vec![b'x'; MAX_DIAGNOSTIC_BYTES * 2]);
        diagnostics.persist();
        let contents = fs::read_to_string(&temporary).unwrap();
        assert!(!contents.contains(&token));
        assert!(!contents.contains("privacy-canary"));
        assert!(!contents.contains("fake-diagnostic-token"));
        assert!(!contents.contains("fake-password-canary"));
        for canary in hex_canaries {
            assert!(!contents.contains(&canary));
        }
        assert!(contents.contains("[REDACTED]"));
        assert!(contents.contains("<HOST_PATH>"));
        assert!(contents.len() <= MAX_DIAGNOSTIC_BYTES);
        let _ = fs::remove_file(temporary);
    }
}
