//! Share files: anyone can send one.
#![no_main]

use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;

fn key() -> &'static cemi::crypto::AgeKey {
    static KEY: OnceLock<cemi::crypto::AgeKey> = OnceLock::new();
    KEY.get_or_init(cemi::crypto::AgeKey::generate)
}

fuzz_target!(|data: &[u8]| {
    let _ = cemi::share::open(data, key());
    let _ = serde_json::from_slice::<cemi::share::Bundle>(data);
});
