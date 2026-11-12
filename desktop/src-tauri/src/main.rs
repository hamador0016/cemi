// No console window in release builds on Windows.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    // `cemi_desktop __clipboard <seconds>`: the hidden helper that keeps a
    // copied value on the clipboard and clears it afterwards (see
    // `cemi::cmd::copy_with_helper`). It runs on its own, so the clipboard is
    // cleared even if the app is closed first.
    let mut args = std::env::args().skip(1);
    if args.next().as_deref() == Some("__clipboard") {
        let seconds = args.next().and_then(|s| s.parse().ok()).unwrap_or(30);
        let code = cemi::cmd::clipboard_helper(seconds).unwrap_or(1);
        std::process::exit(code);
    }
    cemi_desktop::run();
}
