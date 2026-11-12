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

/// A key that proves an object or a header was written by someone holding
/// the vault key. age encrypts to the vault's public key, which anyone can
/// read in `vault.json`; this tag is what tells a real object from a forged
/// one (for example in a synced repository).
pub struct MacKey(Zeroizing<[u8; 32]>);

impl MacKey {
    pub fn for_vault(master: &AgeKey) -> MacKey {
        use hmac::{Hmac, Mac};
        let secret = master.secret_text();
        let mut m = <Hmac<Sha256> as Mac>::new_from_slice(secret.as_bytes())
            .expect("HMAC takes keys of any size");
        m.update(b"cemi-vault-mac-v1");
        let out: [u8; 32] = m.finalize().into_bytes().into();
        MacKey(Zeroizing::new(out))
    }

    /// The tag of `parts` (each one length-prefixed, so they cannot shift).
    pub fn tag(&self, parts: &[&[u8]]) -> String {
        use hmac::{Hmac, Mac};
        let mut m = <Hmac<Sha256> as Mac>::new_from_slice(self.0.as_slice())
            .expect("HMAC takes keys of any size");
        for p in parts {
            m.update(&(p.len() as u64).to_le_bytes());
            m.update(p);
        }
        data_encoding::HEXLOWER.encode(&m.finalize().into_bytes())
    }

    pub fn verify(&self, parts: &[&[u8]], tag: &str) -> bool {
        ct_eq(self.tag(parts).as_bytes(), tag.as_bytes())
    }
}

/// The raw X25519 secret of an age identity.
fn x25519_secret(key: &AgeKey) -> Result<Zeroizing<[u8; 32]>> {
    let text = key.secret_text();
    let (_, data) = bech32::decode(&text).map_err(|_| anyhow!("invalid age identity"))?;
    let data = Zeroizing::new(data);
    let bytes: [u8; 32] = data
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("invalid age identity"))?;
    Ok(Zeroizing::new(bytes))
}

/// The raw X25519 public key of an age recipient (`age1…`).
fn x25519_public(recipient: &str) -> Result<[u8; 32]> {
    parse_recipient(recipient)?;
    let (_, data) =
        bech32::decode(recipient.trim()).map_err(|_| anyhow!("invalid age recipient"))?;
    data.as_slice()
        .try_into()
        .map_err(|_| anyhow!("invalid age recipient"))
}

/// Proves to `receiver` that `message` comes from the holder of `sender`:
/// a NaCl box (X25519 + XSalsa20-Poly1305) of the message's SHA-256, which
/// only these two keys can make or open.
pub fn prove(sender: &AgeKey, receiver: &str, message: &[u8]) -> Result<String> {
    use crypto_box::aead::{Aead, AeadCore, OsRng};
    let sk = crypto_box::SecretKey::from(*x25519_secret(sender)?);
    let pk = crypto_box::PublicKey::from(x25519_public(receiver)?);
    let b = crypto_box::SalsaBox::new(&pk, &sk);
    let nonce = crypto_box::SalsaBox::generate_nonce(&mut OsRng);
    let digest = Sha256::digest(message);
    let sealed = b
        .encrypt(&nonce, digest.as_slice())
        .map_err(|_| anyhow!("cannot sign the share"))?;
    let mut out = nonce.to_vec();
    out.extend_from_slice(&sealed);
    Ok(BASE64.encode(&out))
}

/// Checks a proof made with [`prove`].
pub fn check_proof(receiver: &AgeKey, sender: &str, message: &[u8], proof: &str) -> bool {
    use crypto_box::aead::Aead;
    let (Ok(raw), Ok(sk), Ok(pk)) = (
        BASE64.decode(proof.as_bytes()),
        x25519_secret(receiver),
        x25519_public(sender),
    ) else {
        return false;
    };
    if raw.len() < 24 {
        return false;
    }
    let b = crypto_box::SalsaBox::new(
        &crypto_box::PublicKey::from(pk),
        &crypto_box::SecretKey::from(*sk),
    );
    let nonce = crypto_box::Nonce::from_slice(&raw[..24]);
    match b.decrypt(nonce, &raw[24..]) {
        Ok(digest) => ct_eq(&digest, Sha256::digest(message).as_slice()),
        Err(_) => false,
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
    fn proofs_name_the_sender() {
        let alice = AgeKey::generate();
        let bob = AgeKey::generate();
        let eve = AgeKey::generate();
        let bob_pub = bob.recipient().to_string();
        let alice_pub = alice.recipient().to_string();
        let p = prove(&alice, &bob_pub, b"bundle").unwrap();
        assert!(check_proof(&bob, &alice_pub, b"bundle", &p));
        assert!(!check_proof(&bob, &alice_pub, b"other", &p));
        // Eve cannot make a proof that says it is Alice's.
        let forged = prove(&eve, &bob_pub, b"bundle").unwrap();
        assert!(!check_proof(&bob, &alice_pub, b"bundle", &forged));
        let mac = MacKey::for_vault(&alice);
        let tag = mac.tag(&[b"a", b"bc"]);
        assert!(mac.verify(&[b"a", b"bc"], &tag));
        assert!(!mac.verify(&[b"ab", b"c"], &tag));
        assert!(!MacKey::for_vault(&bob).verify(&[b"a", b"bc"], &tag));
    }

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
