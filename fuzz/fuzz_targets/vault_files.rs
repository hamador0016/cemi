//! Vault files as they could arrive from a synced repository: the header
//! and decrypted objects (with and without a tag), and age files.
#![no_main]

use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;

fn key() -> &'static cemi::crypto::AgeKey {
    static KEY: OnceLock<cemi::crypto::AgeKey> = OnceLock::new();
    KEY.get_or_init(cemi::crypto::AgeKey::generate)
}

fuzz_target!(|data: &[u8]| {
    let mac = cemi::crypto::MacKey::for_vault(key());
    let _ = cemi::vault::open_object(&mac, "0123456789abcdef", data);
    if let Ok(h) = serde_json::from_slice::<cemi::vault::Header>(data) {
        let _ = h.signed_by(&mac);
    }
    let _ = cemi::crypto::age_decrypt_any(&[key()], data);
});
