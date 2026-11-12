//! Cemí Desktop: the window around [`backend`]. Each command here only moves
//! data between the interface and the backend; the decisions live there.

pub mod backend;

use std::path::PathBuf;
use std::sync::Mutex;
use std::time::Instant;

use serde::Serialize;
use tauri::{AppHandle, Manager, WebviewWindow};
use zeroize::Zeroizing;

use backend::{Auth, Grace, Limiter, Method, Opened, UnlockError, ValueRequest};

/// Seconds the clipboard keeps a copied value (like `cemi copy`).
const CLIPBOARD_SECONDS: u64 = 30;

struct AppState {
    global_dir: PathBuf,
    opened: Mutex<Option<Opened>>,
    limiter: Mutex<Limiter>,
    grace: Mutex<Option<Grace>>,
}

impl AppState {
    fn grace(&self) -> std::sync::MutexGuard<'_, Option<Grace>> {
        self.grace.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn opened(&self) -> std::sync::MutexGuard<'_, Option<Opened>> {
        self.opened.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn limiter(&self) -> std::sync::MutexGuard<'_, Limiter> {
        self.limiter.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Closes the vault if its time is over; returns whether it is open.
    fn still_open(&self) -> bool {
        let mut opened = self.opened();
        let ended = opened.as_ref().is_some_and(|o| o.expires().is_none());
        if ended && let Some(o) = opened.take() {
            o.close(true);
        }
        opened.is_some()
    }

    fn load(&self) -> Result<cemi::vault::Vault, String> {
        if !self.still_open() {
            return Err(backend::LOCKED.into());
        }
        let mut opened = self.opened();
        let o = opened.as_mut().ok_or(backend::LOCKED)?;
        o.load().map_err(text)
    }
}

fn text(e: anyhow::Error) -> String {
    format!("{e:#}")
}

/// Runs blocking work (Argon2, the vault files, the system's presence
/// dialog) away from the window's thread.
async fn blocking<T: Send + 'static>(
    app: AppHandle,
    work: impl FnOnce(&AppState) -> Result<T, String> + Send + 'static,
) -> Result<T, String> {
    tauri::async_runtime::spawn_blocking(move || work(&app.state::<AppState>()))
        .await
        .map_err(|e| e.to_string())?
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AppInfo {
    version: &'static str,
    vault: backend::VaultInfo,
    platform: &'static str,
}

#[tauri::command]
fn app_info(app: AppHandle) -> AppInfo {
    let state = app.state::<AppState>();
    AppInfo {
        version: env!("CARGO_PKG_VERSION"),
        vault: backend::vault_info(&state.global_dir),
        platform: std::env::consts::OS,
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SessionState {
    open: bool,
    remaining_secs: i64,
    shared: bool,
}

#[tauri::command]
fn session_state(app: AppHandle) -> SessionState {
    let state = app.state::<AppState>();
    let open = state.still_open();
    let opened = state.opened();
    SessionState {
        open,
        remaining_secs: opened.as_ref().map(Opened::remaining_secs).unwrap_or(0),
        shared: opened.as_ref().is_some_and(|o| o.shared),
    }
}

/// Uses a session that is already open (from the command line or an earlier
/// run), so the person does not type the password again.
#[tauri::command]
async fn resume(app: AppHandle) -> Result<bool, String> {
    blocking(app, |state| {
        if state.still_open() {
            return Ok(true);
        }
        let found = backend::resume(&state.global_dir);
        let open = found.is_some();
        *state.opened() = found;
        Ok(open)
    })
    .await
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct UnlockResult {
    /// "open", "wrong_password", "wait", "no_vault" or "error".
    status: &'static str,
    wait: Option<u64>,
    message: Option<String>,
}

#[tauri::command]
async fn unlock(app: AppHandle, password: String, keep: bool) -> Result<UnlockResult, String> {
    let password = Zeroizing::new(password);
    blocking(app, move |state| {
        let result = {
            let mut limiter = state.limiter();
            backend::unlock(
                &state.global_dir,
                &password,
                keep,
                &mut limiter,
                Instant::now(),
            )
        };
        Ok(match result {
            Ok(opened) => {
                if let Some(old) = state.opened().replace(opened) {
                    old.close(false);
                }
                UnlockResult {
                    status: "open",
                    wait: None,
                    message: None,
                }
            }
            Err(UnlockError::WrongPassword) => {
                std::thread::sleep(backend::WRONG_PASSWORD_DELAY);
                UnlockResult {
                    status: "wrong_password",
                    wait: state.limiter().check(Instant::now()).err(),
                    message: None,
                }
            }
            Err(UnlockError::Wait(secs)) => UnlockResult {
                status: "wait",
                wait: Some(secs),
                message: None,
            },
            Err(UnlockError::NoVault) => UnlockResult {
                status: "no_vault",
                wait: None,
                message: None,
            },
            Err(UnlockError::Other(m)) => UnlockResult {
                status: "error",
                wait: None,
                message: Some(m),
            },
        })
    })
    .await
}

/// "Close the vault": the key leaves memory and the session ends, for the
/// command line too (like `cemi lock`).
#[tauri::command]
fn lock(app: AppHandle) {
    let state = app.state::<AppState>();
    *state.grace() = None;
    if let Some(o) = state.opened().take() {
        o.close(true);
    }
}

/// The revealed value left the screen: copying it asks again.
#[tauri::command]
fn end_reveal(app: AppHandle) {
    *app.state::<AppState>().grace() = None;
}

#[tauri::command]
async fn vault_view(app: AppHandle) -> Result<backend::VaultView, String> {
    blocking(app, |state| Ok(backend::vault_view(&state.load()?))).await
}

#[tauri::command]
async fn record_view(
    app: AppHandle,
    record_id: String,
    env: Option<String>,
) -> Result<backend::RecordView, String> {
    blocking(app, move |state| {
        backend::record_view(&state.load()?, &record_id, env.as_deref()).map_err(text)
    })
    .await
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ValueOutcome {
    /// "granted", "need_password", "refused", "wrong_password" or "wait".
    status: &'static str,
    /// Only from `reveal`, only when granted.
    value: Option<Zeroizing<String>>,
    reference: Option<String>,
    env: Option<String>,
    version: Option<usize>,
    /// How the person confirmed: "none", "password" or "device".
    by: Option<&'static str>,
    device: &'static str,
    reason: Option<String>,
    wait: Option<u64>,
}

impl ValueOutcome {
    fn new(status: &'static str) -> ValueOutcome {
        ValueOutcome {
            status,
            value: None,
            reference: None,
            env: None,
            version: None,
            by: None,
            device: cemi::presence::name(),
            reason: None,
            wait: None,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Use {
    Reveal,
    Copy,
}

#[cfg(windows)]
fn window_handle(window: &WebviewWindow) -> Option<isize> {
    window.hwnd().ok().map(|h| h.0 as isize)
}

#[cfg(not(windows))]
fn window_handle(_window: &WebviewWindow) -> Option<isize> {
    None
}

/// The one path a value takes out of the vault: confirm as the vault asks
/// (Windows Hello / Touch ID, or the password), then show it or copy it.
async fn value(
    app: AppHandle,
    window: WebviewWindow,
    req: ValueRequest,
    password: Option<String>,
    lang: String,
    using: Use,
) -> Result<ValueOutcome, String> {
    let password = password.map(Zeroizing::new);
    let hwnd = window_handle(&window);
    blocking(app, move |state| {
        let method = {
            let v = state.load()?;
            backend::method_for(&v, &req.record_id, &req.field).map_err(text)?
            // The vault (and its lock) is let go while the person confirms.
        };
        let spanish = lang.starts_with("es");
        let reason = match (using, spanish) {
            (Use::Reveal, true) => "Cemí: mostrar un valor",
            (Use::Reveal, false) => "Cemí: show a value",
            (Use::Copy, true) => "Cemí: copiar un valor",
            (Use::Copy, false) => "Cemí: copy a value",
        };
        let dir = state.global_dir.clone();
        let covered = match using {
            Use::Copy => state
                .grace()
                .as_ref()
                .and_then(|g| g.covers(&req, Instant::now())),
            Use::Reveal => None,
        };
        let auth = if let Some(by) = covered {
            Auth::Granted { by }
        } else {
            // Not held during the dialog: only the password check takes it.
            let presence = || cemi::presence::verify_for_window(reason, hwnd);
            match password.as_deref() {
                None => backend::authorize(
                    method,
                    None,
                    &mut Limiter::default(),
                    Instant::now(),
                    presence,
                    |_| Ok(false),
                ),
                Some(pw) => {
                    let mut limiter = state.limiter();
                    backend::authorize(
                        method,
                        Some(pw),
                        &mut limiter,
                        Instant::now(),
                        presence,
                        |pw| backend::password_matches(&dir, pw),
                    )
                }
            }
            .map_err(text)?
        };
        let by = match auth {
            Auth::Granted { by } => by,
            Auth::NeedPassword { reason } => {
                let mut out = ValueOutcome::new("need_password");
                out.reason = reason;
                return Ok(out);
            }
            Auth::Refused => return Ok(ValueOutcome::new("refused")),
            Auth::WrongPassword => {
                std::thread::sleep(backend::WRONG_PASSWORD_DELAY);
                let mut out = ValueOutcome::new("wrong_password");
                out.wait = state.limiter().check(Instant::now()).err();
                return Ok(out);
            }
            Auth::Wait(secs) => {
                let mut out = ValueOutcome::new("wait");
                out.wait = Some(secs);
                return Ok(out);
            }
        };
        let v = state.load()?;
        let released = match using {
            Use::Reveal => backend::release(v, &req, "value.reveal", |_| Ok(())),
            Use::Copy => backend::release(v, &req, "value.copy", |text| {
                cemi::cmd::copy_with_helper(text, CLIPBOARD_SECONDS)
            }),
        }
        .map_err(text)?;
        let mut out = ValueOutcome::new("granted");
        out.by = Some(match by {
            Method::None => "none",
            Method::Password => "password",
            Method::Device => "device",
        });
        out.reference = Some(released.reference);
        out.env = released.env;
        out.version = released.version;
        if using == Use::Reveal {
            out.value = Some(released.text);
            *state.grace() = Some(Grace::new(&req, by, Instant::now()));
        }
        Ok(out)
    })
    .await
}

#[tauri::command]
async fn reveal(
    app: AppHandle,
    window: WebviewWindow,
    record_id: String,
    field: String,
    env: Option<String>,
    password: Option<String>,
    lang: String,
) -> Result<ValueOutcome, String> {
    let req = ValueRequest {
        record_id,
        field,
        env,
    };
    value(app, window, req, password, lang, Use::Reveal).await
}

/// Copies a value without it ever reaching the interface.
#[tauri::command]
async fn copy_value(
    app: AppHandle,
    window: WebviewWindow,
    record_id: String,
    field: String,
    env: Option<String>,
    password: Option<String>,
    lang: String,
) -> Result<ValueOutcome, String> {
    let req = ValueRequest {
        record_id,
        field,
        env,
    };
    value(app, window, req, password, lang, Use::Copy).await
}

pub fn run() {
    let global_dir = match cemi::workspace::global_dir() {
        Ok(d) => d,
        Err(e) => {
            eprintln!("{e:#}");
            std::process::exit(1);
        }
    };
    tauri::Builder::default()
        .manage(AppState {
            global_dir,
            opened: Mutex::new(None),
            limiter: Mutex::new(Limiter::default()),
            grace: Mutex::new(None),
        })
        .invoke_handler(tauri::generate_handler![
            app_info,
            session_state,
            resume,
            unlock,
            lock,
            end_reveal,
            vault_view,
            record_view,
            reveal,
            copy_value
        ])
        .build(tauri::generate_context!())
        .expect("the window could not be created")
        .run(|app, event| {
            if let tauri::RunEvent::Exit = event {
                // The key leaves memory; a shared session stays, like after
                // closing a terminal.
                if let Some(o) = app.state::<AppState>().opened().take() {
                    o.close(false);
                }
            }
        });
}
