# Cemí Desktop

A desktop window for the global Cemí vault, built with [Tauri 2](https://tauri.app).
It shows the vault's entities and records, their notes and destinations, and
shows or copies a value only after the person confirms, the same way `cemi
reveal` and `cemi copy` do.

This is the first milestone. It works with the global vault only (`cemi init
--global`); it does not create vaults, edit them, or open local project
vaults yet. Attention, Approvals, Import and Connect AI are shown as "soon".

## Build and run

Requirements: the Rust toolchain of this repository (`rust-toolchain.toml`),
and on Linux the webview libraries listed in
[Tauri's prerequisites](https://tauri.app/start/prerequisites/)
(`libwebkit2gtk-4.1-dev`, `libgtk-3-dev`, `libayatana-appindicator3-dev`,
`librsvg2-dev`, `libxdo-dev`). Windows 10/11 already has WebView2; macOS uses
its own WebKit. No Node.js, npm or Tauri CLI is needed: the interface is static
HTML, CSS and JavaScript in `ui/`.

```sh
cd desktop/src-tauri
cargo run              # debug build
cargo run --release    # release build: no developer tools, no console window
cargo test             # backend tests, against temporary vaults
```

The desktop app is its own Cargo package (`cemi-desktop`, with its own
`Cargo.lock`). It uses the `cemi` crate of this repository as a library and is
not part of the `cemi` package on crates.io. Installers are not built yet.

### Looking at the interface in a browser

Open `desktop/ui/index.html` in a browser (or serve the folder, e.g.
`python -m http.server -d desktop/ui 8000` and open `http://localhost:8000`).
Without Tauri, the page loads `ui/mock.js`, a fake backend with made-up data;
its password is `demo`. Nothing in that mode touches a vault.

## How it works

- **Unlocking.** The password goes to the backend, which opens the vault key
  with Argon2id like `cemi` does. With "Keep it open N minutes" checked (N is
  `CEMI_SESSION_MINUTES`, 15 by default), the key goes to the system's
  credential store as a `cemi` session, so the command line and the app share
  one session and one countdown, and an open session from the command line
  opens the app directly. Unchecked, the key stays only in the app, for the
  same time. A wrong password waits 1 second; after 3 in a row, the app waits
  30 seconds before trying another.
- **Closing.** The status bar counts down to the end of the session; using the
  vault restarts the count, as on the command line. When it ends, when
  `cemi lock` ends the session, or with "Close the vault", the key is dropped
  (its text is zeroed) and the app returns to the unlock screen. "Close the
  vault" also ends the shared session, like `cemi lock`. Quitting the app drops
  the key but leaves a shared session open, like closing a terminal.
- **The vault is never kept open.** Each request loads it read-only, taking the
  vault's shared lock only for that request, so `cemi` can write to it while
  the app is open.
- **What reaches the window.** Names, notes, destinations, and the values of
  fields that are not secret. Secret fields and templates are always masked.
- **Showing a value** follows `cemi reveal`: for a secret field or a template,
  the vault's `approve_with` setting decides. With `device`, Windows Hello or
  Touch ID asks the person (with the password as a fallback when the device
  check is not available); otherwise the app asks for the vault password.
  Only then does the backend send the value to the window, which shows it for
  20 seconds and then removes it from the page. Each reveal is written to the
  vault's audit log as `value.reveal`, by `desktop`.
- **Copying a value** follows `cemi copy`: after the same confirmation, the
  backend puts the value on the clipboard without sending it to the window.
  A hidden copy of the app keeps it there for 30 seconds and then clears it if
  it is unchanged, also when the app is closed first. On Windows the value is
  kept out of clipboard history and cloud sync; on macOS out of clipboard
  history. Logged as `value.copy`. Copying the value that is on screen in the
  reveal dialog does not ask again while the dialog is open.
- **Unlocking with Windows Hello** is not available: Windows Hello confirms a
  person is present but cannot produce the vault key.

## Security choices

- The interface is local files only. The content security policy allows no
  remote origin: scripts, styles, fonts and images come from the app itself,
  and there are no inline scripts.
- No shell, file system, HTTP or other Tauri plugins. The window's only
  permissions are its own title bar actions (drag, minimize, maximize, close),
  in `src-tauri/capabilities/main.json`.
- Developer tools are only in debug builds.
- The backend keeps the vault key and the values it handles in zeroizing
  buffers and never logs a value. Once a value is in the window, the
  webview's JavaScript engine may keep copies in memory until it collects
  them; the app keeps no reference to it after the 20 seconds.
- `reveal` is the only command that returns a secret value to the window.

## Layout

```text
desktop/
  src-tauri/          Rust: the Tauri app
    src/backend.rs    unlocking, views and the reveal/copy decision (tested)
    src/lib.rs        Tauri commands around the backend
    src/main.rs       entry point, and the clipboard helper
    capabilities/     window permissions
    icons/            app icons
  ui/                 the interface: index.html, app.css, app.js, mock.js
    fonts/            Inter (SIL Open Font License, see OFL.txt)
```

## Licenses

The app is Apache-2.0, like the rest of Cemí. Its dependencies are permissively licensed
except for a few that Tauri itself depends on (cssparser, selectors, dtoa-short,
option-ext), which are MPL-2.0: a file-level copyleft that covers changes to those
libraries' own files, not this app's code. `deny.toml` in this folder allows MPL-2.0 for
the app only, and CI checks it on every push; the command-line tool stays permissive
only.
