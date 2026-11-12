//! Confirming that a person is at the computer with the operating system's
//! own check: Windows Hello (face, fingerprint or PIN) or Touch ID on macOS.
//! An AI that only has a terminal cannot pass it. Used, when the vault is set
//! to it (`cemi approve-with device`), instead of typing the password for
//! approvals and protected environments.

/// The result of asking the person.
#[derive(Debug, PartialEq, Eq)]
pub enum Check {
    Verified,
    /// The person cancelled, or the check failed.
    Refused,
    /// This computer cannot do it; the text says why.
    Unavailable(String),
}

/// The name people know the check by on this system.
pub fn name() -> &'static str {
    if cfg!(windows) {
        "Windows Hello"
    } else if cfg!(target_os = "macos") {
        "Touch ID"
    } else {
        "a device check"
    }
}

/// Debug builds only: `CEMI_TEST_PRESENCE=yes|no|none` stands in for the
/// person, so tests never open a system dialog. Release builds ignore it.
fn test_answer() -> Option<Check> {
    if !cfg!(debug_assertions) {
        return None;
    }
    match std::env::var("CEMI_TEST_PRESENCE").ok()?.as_str() {
        "yes" => Some(Check::Verified),
        "no" => Some(Check::Refused),
        _ => Some(Check::Unavailable("not available in this test".into())),
    }
}

/// Whether this computer can check for a person, without asking yet.
pub fn available() -> Result<(), String> {
    if let Some(answer) = test_answer() {
        return match answer {
            Check::Unavailable(why) => Err(why),
            _ => Ok(()),
        };
    }
    platform::available()
}

/// Asks the person to confirm `reason` (shown in the system dialog).
pub fn verify(reason: &str) -> Check {
    if let Some(answer) = test_answer() {
        return answer;
    }
    platform::verify(reason)
}

#[cfg(windows)]
mod platform {
    use super::Check;
    use windows::Security::Credentials::UI::{
        UserConsentVerificationResult, UserConsentVerifier, UserConsentVerifierAvailability,
    };
    use windows::Win32::System::Console::GetConsoleWindow;
    use windows::Win32::System::WinRT::IUserConsentVerifierInterop;
    use windows::core::{HSTRING, factory};
    use windows_future::IAsyncOperation;

    pub fn available() -> Result<(), String> {
        let state = UserConsentVerifier::CheckAvailabilityAsync()
            .and_then(|op| op.join())
            .map_err(|e| format!("Windows Hello did not answer: {e}"))?;
        match state {
            UserConsentVerifierAvailability::Available => Ok(()),
            UserConsentVerifierAvailability::DeviceNotPresent => {
                Err("this computer has no Windows Hello device".into())
            }
            UserConsentVerifierAvailability::NotConfiguredForUser => Err(
                "Windows Hello is not set up for this user (Settings > Accounts > Sign-in options)"
                    .into(),
            ),
            UserConsentVerifierAvailability::DisabledByPolicy => {
                Err("Windows Hello is turned off by a policy on this computer".into())
            }
            UserConsentVerifierAvailability::DeviceBusy => {
                Err("the Windows Hello device is busy; try again".into())
            }
            _ => Err("Windows Hello is not available".into()),
        }
    }

    pub fn verify(reason: &str) -> Check {
        if let Err(why) = available() {
            return Check::Unavailable(why);
        }
        let message = HSTRING::from(reason);
        // Tied to the console window, so the dialog comes up in front of it.
        let hwnd = unsafe { GetConsoleWindow() };
        let op: windows::core::Result<IAsyncOperation<UserConsentVerificationResult>> =
            if hwnd.is_invalid() {
                UserConsentVerifier::RequestVerificationAsync(&message)
            } else {
                factory::<UserConsentVerifier, IUserConsentVerifierInterop>().and_then(
                    |interop| unsafe { interop.RequestVerificationForWindowAsync(hwnd, &message) },
                )
            };
        match op.and_then(|op| op.join()) {
            Ok(UserConsentVerificationResult::Verified) => Check::Verified,
            Ok(UserConsentVerificationResult::DeviceNotPresent)
            | Ok(UserConsentVerificationResult::NotConfiguredForUser)
            | Ok(UserConsentVerificationResult::DisabledByPolicy) => {
                Check::Unavailable("Windows Hello is not available".into())
            }
            Ok(_) => Check::Refused,
            Err(e) => Check::Unavailable(format!("Windows Hello failed: {e}")),
        }
    }
}

#[cfg(target_os = "macos")]
mod platform {
    use super::Check;
    use block2::RcBlock;
    use objc2::runtime::Bool;
    use objc2_foundation::{NSError, NSString};
    use objc2_local_authentication::{LAContext, LAPolicy};

    pub fn available() -> Result<(), String> {
        let ctx = unsafe { LAContext::new() };
        unsafe { ctx.canEvaluatePolicy_error(LAPolicy::DeviceOwnerAuthentication) }
            .map_err(|e| format!("Touch ID is not available: {}", e.localizedDescription()))
    }

    pub fn verify(reason: &str) -> Check {
        if let Err(why) = available() {
            return Check::Unavailable(why);
        }
        let ctx = unsafe { LAContext::new() };
        let (tx, rx) = std::sync::mpsc::channel();
        let block = RcBlock::new(move |ok: Bool, _err: *mut NSError| {
            let _ = tx.send(ok.as_bool());
        });
        let text = NSString::from_str(reason);
        unsafe {
            ctx.evaluatePolicy_localizedReason_reply(
                LAPolicy::DeviceOwnerAuthentication,
                &text,
                &block,
            )
        };
        match rx.recv() {
            Ok(true) => Check::Verified,
            Ok(false) => Check::Refused,
            Err(_) => Check::Unavailable("Touch ID did not answer".into()),
        }
    }
}

#[cfg(not(any(windows, target_os = "macos")))]
mod platform {
    use super::Check;

    pub fn available() -> Result<(), String> {
        Err("this system has no device check that Cemí can use; approvals use the password".into())
    }

    pub fn verify(_reason: &str) -> Check {
        Check::Unavailable(available().unwrap_err())
    }
}
