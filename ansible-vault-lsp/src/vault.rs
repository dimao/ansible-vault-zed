//! Native implementation of the Ansible Vault 1.1 / 1.2 payload format.
//!
//! Format (matching `ansible.parsing.vault.VaultAES256`):
//!   header:  `$ANSIBLE_VAULT;1.1;AES256` (or `;1.2;AES256;<vault-id>`)
//!   body:    hexlify( hexlify(salt) + b"\n" + hexlify(hmac) + b"\n" + hexlify(ciphertext) )
//!   keys:    PBKDF2-HMAC-SHA256(password, salt, 10_000 iters, 80 bytes)
//!            -> aes_key[0..32], hmac_key[32..64], iv[64..80]
//!   cipher:  AES-256-CTR over PKCS#7-padded plaintext
//!   mac:     HMAC-SHA256(hmac_key, ciphertext)

use aes::Aes256;
use ctr::cipher::{KeyIvInit, StreamCipher};
use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::Sha256;

type Aes256Ctr = ctr::Ctr128BE<Aes256>;
type HmacSha256 = Hmac<Sha256>;

pub const HEADER: &str = "$ANSIBLE_VAULT";
const ITERATIONS: u32 = 10_000;
const SALT_LEN: usize = 32;
const BLOCK: usize = 16;
const WRAP_WIDTH: usize = 80;

#[derive(Debug)]
pub enum VaultError {
    InvalidFormat(String),
    UnsupportedCipher(String),
    WrongPassword,
    Utf8,
}

impl std::fmt::Display for VaultError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VaultError::InvalidFormat(m) => write!(f, "invalid vault format: {m}"),
            VaultError::UnsupportedCipher(c) => write!(f, "unsupported vault cipher: {c}"),
            VaultError::WrongPassword => write!(f, "HMAC verification failed (wrong vault password?)"),
            VaultError::Utf8 => write!(f, "decrypted payload is not valid UTF-8"),
        }
    }
}

impl std::error::Error for VaultError {}

pub fn is_vault_data(s: &str) -> bool {
    s.trim_start().starts_with(HEADER)
}

fn derive_keys(password: &str, salt: &[u8]) -> ([u8; 32], [u8; 32], [u8; 16]) {
    let mut derived = [0u8; 80];
    pbkdf2::pbkdf2_hmac::<Sha256>(password.as_bytes(), salt, ITERATIONS, &mut derived);
    let mut aes_key = [0u8; 32];
    let mut hmac_key = [0u8; 32];
    let mut iv = [0u8; 16];
    aes_key.copy_from_slice(&derived[0..32]);
    hmac_key.copy_from_slice(&derived[32..64]);
    iv.copy_from_slice(&derived[64..80]);
    (aes_key, hmac_key, iv)
}

/// Encrypt `plaintext`, returning the full vault text (header + wrapped hex lines,
/// separated by `\n`, no trailing newline).
pub fn encrypt(plaintext: &str, password: &str, vault_id: Option<&str>) -> String {
    let mut salt = [0u8; SALT_LEN];
    rand::thread_rng().fill_bytes(&mut salt);
    encrypt_with_salt(plaintext, password, vault_id, &salt)
}

fn encrypt_with_salt(plaintext: &str, password: &str, vault_id: Option<&str>, salt: &[u8]) -> String {
    let (aes_key, hmac_key, iv) = derive_keys(password, salt);

    // PKCS#7 pad
    let pad = BLOCK - plaintext.len() % BLOCK;
    let mut data = plaintext.as_bytes().to_vec();
    data.extend(std::iter::repeat(pad as u8).take(pad));

    Aes256Ctr::new(&aes_key.into(), &iv.into()).apply_keystream(&mut data);

    let mut mac = HmacSha256::new_from_slice(&hmac_key).expect("hmac key");
    mac.update(&data);
    let digest = mac.finalize().into_bytes();

    let inner = format!("{}\n{}\n{}", hex::encode(salt), hex::encode(digest), hex::encode(&data));
    let outer = hex::encode(inner.as_bytes());

    let header = match vault_id {
        Some(id) if !id.is_empty() => format!("{HEADER};1.2;AES256;{id}"),
        _ => format!("{HEADER};1.1;AES256"),
    };

    let mut out = header;
    for chunk in outer.as_bytes().chunks(WRAP_WIDTH) {
        out.push('\n');
        out.push_str(std::str::from_utf8(chunk).expect("hex is ascii"));
    }
    out
}

/// Parse the envelope: returns (cipher_name, vault_id, hex_body).
fn parse_envelope(vaulttext: &str) -> Result<(String, Option<String>, String), VaultError> {
    let mut lines = vaulttext.trim().lines();
    let header = lines
        .next()
        .ok_or_else(|| VaultError::InvalidFormat("empty input".into()))?
        .trim();
    let parts: Vec<&str> = header.split(';').collect();
    if parts.len() < 3 || parts[0] != HEADER {
        return Err(VaultError::InvalidFormat("bad header".into()));
    }
    let version = parts[1];
    if version != "1.1" && version != "1.2" {
        return Err(VaultError::InvalidFormat(format!("unsupported version {version}")));
    }
    let cipher = parts[2].to_string();
    let vault_id = parts.get(3).map(|s| s.to_string());
    let body: String = lines.map(|l| l.trim()).collect();
    Ok((cipher, vault_id, body))
}

/// Decrypt full vault text (header included) with a single password.
pub fn decrypt(vaulttext: &str, password: &str) -> Result<String, VaultError> {
    let (cipher, _vault_id, body) = parse_envelope(vaulttext)?;
    if cipher != "AES256" {
        return Err(VaultError::UnsupportedCipher(cipher));
    }

    let inner = hex::decode(&body).map_err(|e| VaultError::InvalidFormat(e.to_string()))?;
    let inner = String::from_utf8(inner).map_err(|_| VaultError::InvalidFormat("inner not ascii".into()))?;
    let mut parts = inner.split('\n');
    let salt = hex::decode(parts.next().unwrap_or_default())
        .map_err(|e| VaultError::InvalidFormat(e.to_string()))?;
    let expected_mac = hex::decode(parts.next().unwrap_or_default())
        .map_err(|e| VaultError::InvalidFormat(e.to_string()))?;
    let mut data = hex::decode(parts.next().unwrap_or_default())
        .map_err(|e| VaultError::InvalidFormat(e.to_string()))?;

    let (aes_key, hmac_key, iv) = derive_keys(password, &salt);

    let mut mac = HmacSha256::new_from_slice(&hmac_key).expect("hmac key");
    mac.update(&data);
    mac.verify_slice(&expected_mac).map_err(|_| VaultError::WrongPassword)?;

    Aes256Ctr::new(&aes_key.into(), &iv.into()).apply_keystream(&mut data);

    // strip PKCS#7 padding
    let pad = *data.last().ok_or(VaultError::InvalidFormat("empty payload".into()))? as usize;
    if pad == 0 || pad > BLOCK || pad > data.len() {
        return Err(VaultError::WrongPassword);
    }
    data.truncate(data.len() - pad);

    String::from_utf8(data).map_err(|_| VaultError::Utf8)
}

/// Try several passwords in order; return the first successful decryption.
pub fn decrypt_any(vaulttext: &str, passwords: &[String]) -> Result<String, VaultError> {
    let mut last = VaultError::WrongPassword;
    for pw in passwords {
        match decrypt(vaulttext, pw) {
            Ok(pt) => return Ok(pt),
            Err(e) => last = e,
        }
    }
    Err(last)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let pt = "super secret value";
        let enc = encrypt(pt, "hunter2", None);
        assert!(enc.starts_with("$ANSIBLE_VAULT;1.1;AES256\n"));
        assert_eq!(decrypt(&enc, "hunter2").unwrap(), pt);
    }

    #[test]
    fn roundtrip_vault_id() {
        let pt = "another\nmultiline\nsecret";
        let enc = encrypt(pt, "pw", Some("dev"));
        assert!(enc.starts_with("$ANSIBLE_VAULT;1.2;AES256;dev\n"));
        assert_eq!(decrypt(&enc, "pw").unwrap(), pt);
    }

    #[test]
    fn wrong_password() {
        let enc = encrypt("x", "right", None);
        assert!(matches!(decrypt(&enc, "wrong"), Err(VaultError::WrongPassword)));
    }

    #[test]
    fn decrypt_any_tries_all() {
        let enc = encrypt("x", "second", None);
        let pws = vec!["first".to_string(), "second".to_string()];
        assert_eq!(decrypt_any(&enc, &pws).unwrap(), "x");
    }
}
