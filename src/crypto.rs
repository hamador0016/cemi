//! Cryptographic building blocks. Nothing here is invented: Argon2id derives
//! the password key; XChaCha20-Poly1305 wraps the vault identity; age (X25519)
//! encrypts every stored object.

use std::io::Read;

use age::secrecy::ExposeSecret;
use anyhow::{Context, Result, anyhow, bail};
use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use data_encoding::{BASE32_NOPAD, BASE64};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

/// Argon2id parameters, stored next to the vault so they can grow over time.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct KdfParams {
    pub memory_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
}

impl KdfParams {
    /// About one second and 256 MiB on a typical laptop.
    pub const STRONG: KdfParams = KdfParams {
        memory_kib: 256 * 1024,
        iterations: 3,
        parallelism: 1,
    };

    /// Only for tests. Never used by release builds.
    pub const INSECURE_FAST: KdfParams = KdfParams {
        memory_kib: 64,
        iterations: 1,
        parallelism: 1,
    };

    /// Parameters for new vaults. Debug builds honor `CEMI_INSECURE_FAST_KDF=1`
    /// so the test suite does not spend seconds per vault.
    pub fn for_new_vault() -> KdfParams {
        if cfg!(debug_assertions) && std::env::var_os("CEMI_INSECURE_FAST_KDF").is_some() {
            Self::INSECURE_FAST
        } else {
            Self::STRONG
        }
    }
}

pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut buf = [0u8; N];
    getrandom::fill(&mut buf).expect("the operating system random generator failed");
    buf
}

/// Random object id: 128 bits, lowercase hex.
pub fn new_id() -> String {
    data_encoding::HEXLOWER.encode(&random_bytes::<16>())
}

pub fn derive_password_key(
    password: &str,
    salt: &[u8],
    params: KdfParams,
) -> Result<Zeroizing<[u8; 32]>> {
    let params = Params::new(
        params.memory_kib,
        params.iterations,
        params.parallelism,
        Some(32),
    )
    .map_err(|e| anyhow!("invalid key derivation parameters: {e}"))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = Zeroizing::new([0u8; 32]);
    argon
        .hash_password_into(password.as_bytes(), salt, out.as_mut())
        .map_err(|e| anyhow!("key derivation failed: {e}"))?;
    Ok(out)
}

/// Recovery codes carry 256 bits of randomness, so a plain hash is enough to
/// turn them into a key (no slow KDF needed).
pub fn derive_recovery_key(code: &str, salt: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    let raw = decode_recovery_code(code)?;
    let mut hasher = Sha256::new();
    hasher.update(b"cemi-recovery-v1");
    hasher.update(salt);
    hasher.update(raw.as_slice());
    let mut out = Zeroizing::new([0u8; 32]);
    out.copy_from_slice(&hasher.finalize());
    Ok(out)
}

/// A new recovery code, shown to the user once: 52 base32 characters in groups of 4.
pub fn new_recovery_code() -> Zeroizing<String> {
    let raw = Zeroizing::new(random_bytes::<32>());
    let encoded = Zeroizing::new(BASE32_NOPAD.encode(raw.as_ref()));
    let grouped: Vec<&str> = encoded
        .as_bytes()
        .chunks(4)
        .map(|c| std::str::from_utf8(c).expect("base32 is ascii"))
        .collect();
    Zeroizing::new(grouped.join("-"))
}

fn decode_recovery_code(code: &str) -> Result<Zeroizing<Vec<u8>>> {
    let cleaned: String = code
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| c.to_ascii_uppercase())
        .collect();
    let raw = BASE32_NOPAD
        .decode(cleaned.as_bytes())
        .map_err(|_| anyhow!("that is not a valid recovery code"))?;
    if raw.len() != 32 {
        bail!("that is not a valid recovery code");
    }
    Ok(Zeroizing::new(raw))
}

/// A secret sealed with XChaCha20-Poly1305. `aad` binds it to its vault and purpose.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Sealed {
    pub nonce: String,
    pub ciphertext: String,
}

pub fn seal(key: &[u8; 32], aad: &[u8], plaintext: &[u8]) -> Sealed {
    let cipher = XChaCha20Poly1305::new_from_slice(key).expect("key is 32 bytes");
    let nonce = random_bytes::<24>();
    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .expect("encryption with a valid key cannot fail");
    Sealed {
        nonce: BASE64.encode(&nonce),
        ciphertext: BASE64.encode(&ciphertext),
    }
}

/// Returns `None` when the key is wrong or the data was tampered with.
pub fn open(key: &[u8; 32], aad: &[u8], sealed: &Sealed) -> Result<Option<Zeroizing<Vec<u8>>>> {
    let nonce = BASE64
        .decode(sealed.nonce.as_bytes())
        .context("corrupt vault header (nonce)")?;
    let ciphertext = BASE64
        .decode(sealed.ciphertext.as_bytes())
        .context("corrupt vault header (ciphertext)")?;
    if nonce.len() != 24 {
        bail!("corrupt vault header (nonce length)");
    }
    let cipher = XChaCha20Poly1305::new_from_slice(key).expect("key is 32 bytes");
    Ok(cipher
        .decrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: &ciphertext,
                aad,
            },
        )
        .ok()
        .map(Zeroizing::new))
}

/// An age X25519 identity whose secret text is wiped from memory on drop.
pub struct AgeKey {
    identity: age::x25519::Identity,
}

impl AgeKey {
    pub fn generate() -> AgeKey {
        AgeKey {
            identity: age::x25519::Identity::generate(),
        }
    }

    pub fn parse(secret: &str) -> Result<AgeKey> {
        let identity = secret
            .trim()
            .parse::<age::x25519::Identity>()
            .map_err(|e| anyhow!("invalid age identity: {e}"))?;
        Ok(AgeKey { identity })
    }

    pub fn secret_text(&self) -> Zeroizing<String> {
        Zeroizing::new(self.identity.to_string().expose_secret().to_string())
    }

    pub fn recipient(&self) -> age::x25519::Recipient {
        self.identity.to_public()
    }

    pub fn identity(&self) -> &age::x25519::Identity {
        &self.identity
    }
}

impl Clone for AgeKey {
    fn clone(&self) -> Self {
        AgeKey::parse(&self.secret_text()).expect("round trip of a valid identity")
    }
}

pub fn parse_recipient(text: &str) -> Result<age::x25519::Recipient> {
    text.trim()
        .parse::<age::x25519::Recipient>()
        .map_err(|e| anyhow!("invalid age recipient: {e}"))
}

pub fn age_encrypt(recipient: &age::x25519::Recipient, plaintext: &[u8]) -> Result<Vec<u8>> {
    age::encrypt(recipient, plaintext).map_err(|e| anyhow!("encryption failed: {e}"))
}

/// Tries every known identity. `Ok(None)` means none of them can open it.
pub fn age_decrypt_any(keys: &[&AgeKey], ciphertext: &[u8]) -> Result<Option<Zeroizing<Vec<u8>>>> {
    let decryptor = age::Decryptor::new_buffered(ciphertext)
        .map_err(|e| anyhow!("not a valid age file: {e}"))?;
    let identities = keys.iter().map(|k| k.identity() as &dyn age::Identity);
    match decryptor.decrypt(identities) {
        Ok(mut reader) => {
            let mut out = Zeroizing::new(Vec::new());
            reader
                .read_to_end(&mut out)
                .map_err(|e| anyhow!("decryption failed (corrupt or tampered file): {e}"))?;
            Ok(Some(out))
        }
        Err(age::DecryptError::NoMatchingKeys) => Ok(None),
        Err(e) => Err(anyhow!("decryption failed: {e}")),
    }
}

pub fn sha256_hex(data: &[u8]) -> String {
    data_encoding::HEXLOWER.encode(&Sha256::digest(data))
}

/// Constant-time comparison for secrets of possibly different lengths.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_round_trip_and_tamper() {
        let key = random_bytes::<32>();
        let sealed = seal(&key, b"aad", b"hello");
        assert_eq!(
            open(&key, b"aad", &sealed).unwrap().unwrap().as_slice(),
            b"hello"
        );
        assert!(open(&key, b"other", &sealed).unwrap().is_none());
        let wrong = random_bytes::<32>();
        assert!(open(&wrong, b"aad", &sealed).unwrap().is_none());
    }

    #[test]
    fn recovery_code_round_trip() {
        let code = new_recovery_code();
        let salt = random_bytes::<16>();
        let a = derive_recovery_key(&code, &salt).unwrap();
        let b = derive_recovery_key(&code.to_lowercase().replace('-', " "), &salt).unwrap();
        assert_eq!(*a, *b);
        assert!(derive_recovery_key("not-a-code", &salt).is_err());
    }

    #[test]
    fn password_key_depends_on_password() {
        let salt = random_bytes::<16>();
        let a = derive_password_key("one", &salt, KdfParams::INSECURE_FAST).unwrap();
        let b = derive_password_key("two", &salt, KdfParams::INSECURE_FAST).unwrap();
        assert_ne!(*a, *b);
    }

    #[test]
    fn age_round_trip_with_several_keys() {
        let a = AgeKey::generate();
        let b = AgeKey::generate();
        let ct = age_encrypt(&b.recipient(), b"secret").unwrap();
        assert_eq!(
            age_decrypt_any(&[&a, &b], &ct).unwrap().unwrap().as_slice(),
            b"secret"
        );
        assert!(age_decrypt_any(&[&a], &ct).unwrap().is_none());
    }
}
