//! `cemi tray`: an icon in the Windows notification area that tells you when
//! an AI client asks for approval, and opens `cemi approve` to review it.
//!
//! The tray never opens a vault. It reads only the `requests` file of each
//! vault folder it watches, which holds the number of requests waiting, so it
//! needs no password and keeps no session alive. Approving happens in the
//! terminal it opens, with the password or Windows Hello.

use std::path::{Path, PathBuf};

use anyhow::Result;

/// A vault folder to watch, and the folder where `cemi approve` should run
/// for it (the project for a local vault, the home folder for the global one).
#[derive(Debug, Clone)]
pub struct Watched {
    pub vault_dir: PathBuf,
    pub run_in: PathBuf,
}

/// Requests waiting in a vault folder (0 when there is no file).
pub fn waiting(vault_dir: &Path) -> usize {
    std::fs::read_to_string(vault_dir.join(crate::vault::REQUESTS_FILE))
        .ok()
        .and_then(|t| t.trim().parse().ok())
        .unwrap_or(0)
}

#[cfg(not(windows))]
pub fn run(_watched: Vec<Watched>, _foreground: bool) -> Result<i32> {
    Err(anyhow::anyhow!(
        "the tray icon is only available on Windows. Elsewhere, `cemi approve` lists the requests and `cemi status` mentions them"
    ))
}

#[cfg(windows)]
pub fn run(watched: Vec<Watched>, foreground: bool) -> Result<i32> {
    if !foreground {
        // Started from a terminal: run in the background and give it back.
        use std::os::windows::process::CommandExt;
        const DETACHED_PROCESS: u32 = 0x0000_0008;
        const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
        let mut cmd = std::process::Command::new(std::env::current_exe()?);
        cmd.args(["tray", "--foreground"]);
        // The first one is the global vault; the others are projects.
        for w in watched.iter().skip(1) {
            cmd.arg("--project").arg(&w.run_in);
        }
        cmd.creation_flags(DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()?;
        crate::ui::ok(
            "The Cemí icon is in the notification area. It tells you when an AI asks for approval",
        );
        return Ok(0);
    }
    win::run(watched)
}

#[cfg(windows)]
mod win {
    use std::cell::RefCell;

    use anyhow::{Result, anyhow};
    use windows::Win32::Foundation::{
        ERROR_ALREADY_EXISTS, GetLastError, HWND, LPARAM, LRESULT, POINT, WPARAM,
    };
    use windows::Win32::System::LibraryLoader::GetModuleHandleW;
    use windows::Win32::System::Threading::CreateMutexW;
    use windows::Win32::UI::Shell::{
        NIF_ICON, NIF_INFO, NIF_MESSAGE, NIF_TIP, NIIF_INFO, NIM_ADD, NIM_DELETE, NIM_MODIFY,
        NIN_BALLOONUSERCLICK, NOTIFYICONDATAW, Shell_NotifyIconW,
    };
    use windows::Win32::UI::WindowsAndMessaging::{
        AppendMenuW, CW_USEDEFAULT, CreatePopupMenu, CreateWindowExW, DefWindowProcW, DestroyMenu,
        DestroyWindow, DispatchMessageW, GetCursorPos, GetMessageW, IDI_SHIELD, LoadIconW,
        MF_GRAYED, MF_SEPARATOR, MF_STRING, MSG, PostQuitMessage, RegisterClassW,
        SetForegroundWindow, SetTimer, TPM_RETURNCMD, TPM_RIGHTBUTTON, TrackPopupMenu,
        TranslateMessage, WINDOW_EX_STYLE, WM_APP, WM_DESTROY, WM_LBUTTONUP, WM_RBUTTONUP,
        WM_TIMER, WNDCLASSW, WS_OVERLAPPED,
    };
    use windows::core::{PCWSTR, w};

    use super::{Watched, waiting};

    const CALLBACK: u32 = WM_APP + 1;
    const TIMER: usize = 1;
    const MENU_REVIEW: usize = 1;
    const MENU_QUIT: usize = 2;

    struct State {
        hwnd: HWND,
        watched: Vec<Watched>,
        last_total: usize,
    }

    thread_local! {
        static STATE: RefCell<Option<State>> = const { RefCell::new(None) };
    }

    fn wide<const N: usize>(text: &str) -> [u16; N] {
        let mut out = [0u16; N];
        for (i, c) in text.encode_utf16().take(N - 1).enumerate() {
            out[i] = c;
        }
        out
    }

    fn icon_data(hwnd: HWND) -> NOTIFYICONDATAW {
        NOTIFYICONDATAW {
            cbSize: std::mem::size_of::<NOTIFYICONDATAW>() as u32,
            hWnd: hwnd,
            uID: 1,
            ..Default::default()
        }
    }

    fn tip(total: usize) -> String {
        match total {
            0 => "Cemí: no requests waiting".into(),
            1 => "Cemí: 1 request waiting for your approval".into(),
            n => format!("Cemí: {n} requests waiting for your approval"),
        }
    }

    pub fn run(watched: Vec<Watched>) -> Result<i32> {
        unsafe {
            // One tray per user session.
            let _mutex = CreateMutexW(None, true, w!("Local\\cemi-tray"))?;
            if GetLastError() == ERROR_ALREADY_EXISTS {
                return Err(anyhow!("the Cemí tray icon is already running"));
            }
            let instance = GetModuleHandleW(None)?;
            let class = w!("CemiTrayWindow");
            let wc = WNDCLASSW {
                lpfnWndProc: Some(wndproc),
                hInstance: instance.into(),
                lpszClassName: class,
                ..Default::default()
            };
            if RegisterClassW(&wc) == 0 {
                return Err(anyhow!("cannot register the tray window"));
            }
            let hwnd = CreateWindowExW(
                WINDOW_EX_STYLE::default(),
                class,
                w!("Cemí"),
                WS_OVERLAPPED,
                CW_USEDEFAULT,
                CW_USEDEFAULT,
                CW_USEDEFAULT,
                CW_USEDEFAULT,
                None,
                None,
                Some(instance.into()),
                None,
            )?;
            let total: usize = watched.iter().map(|w| waiting(&w.vault_dir)).sum();
            let mut data = icon_data(hwnd);
            data.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
            data.uCallbackMessage = CALLBACK;
            data.hIcon = LoadIconW(None, IDI_SHIELD)?;
            data.szTip = wide(&tip(total));
            if !Shell_NotifyIconW(NIM_ADD, &data).as_bool() {
                let _ = DestroyWindow(hwnd);
                return Err(anyhow!("cannot add the icon to the notification area"));
            }
            STATE.with(|s| {
                *s.borrow_mut() = Some(State {
                    hwnd,
                    watched,
                    last_total: total,
                })
            });
            if total > 0 {
                notify(hwnd, total);
            }
            SetTimer(Some(hwnd), TIMER, 2000, None);
            let mut msg = MSG::default();
            while GetMessageW(&mut msg, None, 0, 0).as_bool() {
                let _ = TranslateMessage(&msg);
                DispatchMessageW(&msg);
            }
            let _ = Shell_NotifyIconW(NIM_DELETE, &icon_data(hwnd));
        }
        Ok(0)
    }

    fn notify(hwnd: HWND, total: usize) {
        let mut data = icon_data(hwnd);
        data.uFlags = NIF_INFO | NIF_TIP;
        data.szTip = wide(&tip(total));
        data.szInfoTitle = wide("Cemí");
        data.szInfo = wide(&format!(
            "{}. Click to review.",
            if total == 1 {
                "An AI asks for your approval".to_string()
            } else {
                format!("{total} requests wait for your approval")
            }
        ));
        data.dwInfoFlags = NIIF_INFO;
        unsafe {
            let _ = Shell_NotifyIconW(NIM_MODIFY, &data);
        }
    }

    fn set_tip(hwnd: HWND, total: usize) {
        let mut data = icon_data(hwnd);
        data.uFlags = NIF_TIP;
        data.szTip = wide(&tip(total));
        unsafe {
            let _ = Shell_NotifyIconW(NIM_MODIFY, &data);
        }
    }

    /// Opens `cemi approve` in its own console for each vault with requests.
    fn review() {
        let targets: Vec<Watched> = STATE.with(|s| {
            s.borrow()
                .as_ref()
                .map(|st| {
                    st.watched
                        .iter()
                        .filter(|w| waiting(&w.vault_dir) > 0)
                        .cloned()
                        .collect()
                })
                .unwrap_or_default()
        });
        let Ok(exe) = std::env::current_exe() else {
            return;
        };
        for t in targets {
            use std::os::windows::process::CommandExt;
            const CREATE_NEW_CONSOLE: u32 = 0x0000_0010;
            let _ = std::process::Command::new(crate::runner::resolve_program("cmd"))
                .arg("/K")
                .arg(&exe)
                .arg("approve")
                .current_dir(&t.run_in)
                .creation_flags(CREATE_NEW_CONSOLE)
                .spawn();
        }
    }

    fn menu(hwnd: HWND) {
        let total: usize = STATE.with(|s| {
            s.borrow()
                .as_ref()
                .map(|st| st.watched.iter().map(|w| waiting(&w.vault_dir)).sum())
                .unwrap_or(0)
        });
        unsafe {
            let Ok(m) = CreatePopupMenu() else { return };
            let label: Vec<u16> = format!("Review requests ({total})\0")
                .encode_utf16()
                .collect();
            let flags = if total > 0 {
                MF_STRING
            } else {
                MF_STRING | MF_GRAYED
            };
            let _ = AppendMenuW(m, flags, MENU_REVIEW, PCWSTR(label.as_ptr()));
            let _ = AppendMenuW(m, MF_SEPARATOR, 0, PCWSTR::null());
            let _ = AppendMenuW(m, MF_STRING, MENU_QUIT, w!("Quit"));
            let mut p = POINT::default();
            let _ = GetCursorPos(&mut p);
            // Needed so the menu closes when the user clicks elsewhere.
            let _ = SetForegroundWindow(hwnd);
            let chosen = TrackPopupMenu(
                m,
                TPM_RETURNCMD | TPM_RIGHTBUTTON,
                p.x,
                p.y,
                None,
                hwnd,
                None,
            );
            let _ = DestroyMenu(m);
            match chosen.0 as usize {
                MENU_REVIEW => review(),
                MENU_QUIT => {
                    let _ = DestroyWindow(hwnd);
                }
                _ => {}
            }
        }
    }

    fn tick() {
        let changed = STATE.with(|s| {
            let mut b = s.borrow_mut();
            let st = b.as_mut()?;
            let total: usize = st.watched.iter().map(|w| waiting(&w.vault_dir)).sum();
            let previous = st.last_total;
            st.last_total = total;
            (total != previous).then_some((st.hwnd, total, total > previous))
        });
        if let Some((hwnd, total, more)) = changed {
            if more {
                notify(hwnd, total);
            } else {
                set_tip(hwnd, total);
            }
        }
    }

    unsafe extern "system" fn wndproc(hwnd: HWND, msg: u32, wp: WPARAM, lp: LPARAM) -> LRESULT {
        match msg {
            WM_TIMER => {
                tick();
                LRESULT(0)
            }
            CALLBACK => {
                match lp.0 as u32 {
                    WM_LBUTTONUP | NIN_BALLOONUSERCLICK => review(),
                    WM_RBUTTONUP => menu(hwnd),
                    _ => {}
                }
                LRESULT(0)
            }
            WM_DESTROY => {
                unsafe { PostQuitMessage(0) };
                LRESULT(0)
            }
            _ => unsafe { DefWindowProcW(hwnd, msg, wp, lp) },
        }
    }
}
