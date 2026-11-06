use aes::Aes256;
use argon2::{Algorithm, Argon2, Params, Version};
pub use base64::engine::general_purpose::STANDARD as BASE64;
pub use base64::Engine;
use cbc::cipher::block_padding::Pkcs7;
use cbc::cipher::{BlockDecryptMut, KeyIvInit};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use std::ops::RangeInclusive;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

use crate::locked::LockedKey32;

type Aes256CbcDec = cbc::Decryptor<Aes256>;
type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, PartialEq, Eq)]
pub enum CryptoError {
    InvalidKdfParams,
    KdfParametersRejected(String),
    InvalidEncString(String),
    UnsupportedCipherType(u32),
    MacMismatch,
    MacRequired,
    DecryptionFailed(String),
    InvalidKeyLength,
    Utf8Error,
}

impl std::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CryptoError::InvalidKdfParams => write!(f, "Invalid KDF parameters"),
            CryptoError::KdfParametersRejected(s) => write!(f, "KDF parameters rejected: {}", s),
            CryptoError::InvalidEncString(s) => write!(f, "Invalid EncString format: {}", s),
            CryptoError::UnsupportedCipherType(t) => write!(f, "Unsupported cipher type: {}", t),
            CryptoError::MacMismatch => write!(f, "MAC verification failed"),
            CryptoError::MacRequired => write!(f, "MAC required"),
            CryptoError::DecryptionFailed(s) => write!(f, "Decryption failed: {}", s),
            CryptoError::InvalidKeyLength => write!(f, "Invalid key length"),
            CryptoError::Utf8Error => write!(f, "UTF-8 decoding error"),
        }
    }
}

impl std::error::Error for CryptoError {}

/// Length in bytes of a Bitwarden AES-256-CBC-HMAC-SHA256 key: a 32-byte
/// encryption key followed by a 32-byte MAC key.
pub const AUTHENTICATED_SYMMETRIC_KEY_LENGTH: usize = 64;

/// PBKDF2-SHA256 iteration bounds. 100,000 is the lowest historical
/// Bitwarden default that existing accounts may still use.
pub const PBKDF2_ITERATIONS_RANGE: RangeInclusive<u32> = 100_000..=2_000_000;
pub const PBKDF2_DEFAULT_ITERATIONS: u32 = 600_000;

/// Argon2id bounds documented by Bitwarden.
pub const ARGON2_MEMORY_MIB_RANGE: RangeInclusive<u32> = 16..=1024;
pub const ARGON2_ITERATIONS_RANGE: RangeInclusive<u32> = 2..=10;
pub const ARGON2_PARALLELISM_RANGE: RangeInclusive<u32> = 1..=16;
pub const ARGON2_DEFAULT_MEMORY_MIB: u32 = 64;
pub const ARGON2_DEFAULT_ITERATIONS: u32 = 3;
pub const ARGON2_DEFAULT_PARALLELISM: u32 = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KdfType {
    Pbkdf2Sha256 = 0,
    Argon2id = 1,
}

impl KdfType {
    /// Interprets the KDF type reported by the server. An omitted value means
    /// PBKDF2-SHA256; an unknown value is refused rather than substituted.
    pub fn from_server_value(value: Option<u32>) -> Result<Self, CryptoError> {
        match value.unwrap_or(0) {
            0 => Ok(KdfType::Pbkdf2Sha256),
            1 => Ok(KdfType::Argon2id),
            other => Err(CryptoError::KdfParametersRejected(format!(
                "unsupported KDF type {}",
                other
            ))),
        }
    }
}

/// Key derivation parameters after server-omitted values are replaced by
/// their defaults. Values the server did send are never altered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KdfParameters {
    Pbkdf2Sha256 {
        iterations: u32,
    },
    Argon2id {
        iterations: u32,
        memory_mib: u32,
        parallelism: u32,
    },
}

impl KdfParameters {
    /// Builds the parameters from optional server values, applying defaults
    /// only to omitted values.
    pub fn resolve(
        kdf_type: KdfType,
        iterations: Option<u32>,
        memory_mib: Option<u32>,
        parallelism: Option<u32>,
    ) -> Self {
        match kdf_type {
            KdfType::Pbkdf2Sha256 => KdfParameters::Pbkdf2Sha256 {
                iterations: iterations.unwrap_or(PBKDF2_DEFAULT_ITERATIONS),
            },
            KdfType::Argon2id => KdfParameters::Argon2id {
                iterations: iterations.unwrap_or(ARGON2_DEFAULT_ITERATIONS),
                memory_mib: memory_mib.unwrap_or(ARGON2_DEFAULT_MEMORY_MIB),
                parallelism: parallelism.unwrap_or(ARGON2_DEFAULT_PARALLELISM),
            },
        }
    }

    /// Builds the parameters from the raw prelogin, token or storage fields.
    pub fn from_server_values(
        kdf: Option<u32>,
        iterations: Option<u32>,
        memory_mib: Option<u32>,
        parallelism: Option<u32>,
    ) -> Result<Self, CryptoError> {
        let kdf_type = KdfType::from_server_value(kdf)?;
        Ok(Self::resolve(kdf_type, iterations, memory_mib, parallelism))
    }

    /// Refuses parameters outside the accepted bounds instead of adjusting them.
    pub fn validate(&self) -> Result<(), CryptoError> {
        match *self {
            KdfParameters::Pbkdf2Sha256 { iterations } => {
                require_within_range("PBKDF2 iterations", iterations, &PBKDF2_ITERATIONS_RANGE)
            }
            KdfParameters::Argon2id {
                iterations,
                memory_mib,
                parallelism,
            } => {
                require_within_range("Argon2id memory MiB", memory_mib, &ARGON2_MEMORY_MIB_RANGE)?;
                require_within_range("Argon2id iterations", iterations, &ARGON2_ITERATIONS_RANGE)?;
                require_within_range(
                    "Argon2id parallelism",
                    parallelism,
                    &ARGON2_PARALLELISM_RANGE,
                )
            }
        }
    }
}

fn require_within_range(
    parameter_name: &str,
    value: u32,
    accepted_range: &RangeInclusive<u32>,
) -> Result<(), CryptoError> {
    if accepted_range.contains(&value) {
        return Ok(());
    }
    Err(CryptoError::KdfParametersRejected(format!(
        "{} {} is outside the accepted range {}-{}",
        parameter_name,
        value,
        accepted_range.start(),
        accepted_range.end()
    )))
}

pub fn derive_master_key(
    email: &str,
    password: &str,
    kdf_type: KdfType,
    iterations: u32,
    memory_mb: Option<u32>,
    parallelism: Option<u32>,
) -> Result<LockedKey32, CryptoError> {
    let parameters = KdfParameters::resolve(kdf_type, Some(iterations), memory_mb, parallelism);
    derive_master_key_with_parameters(email, password, &parameters)
}

/// Derives the master key, refusing out-of-range parameters.
pub fn derive_master_key_with_parameters(
    email: &str,
    password: &str,
    parameters: &KdfParameters,
) -> Result<LockedKey32, CryptoError> {
    parameters.validate()?;
    let email_normalized = email.trim().to_lowercase();

    match *parameters {
        KdfParameters::Pbkdf2Sha256 { iterations } => Ok(derive_pbkdf2_master_key(
            password,
            &email_normalized,
            iterations,
        )),
        KdfParameters::Argon2id {
            iterations,
            memory_mib,
            parallelism,
        } => derive_argon2id_master_key(
            password,
            &email_normalized,
            iterations,
            memory_mib,
            parallelism,
        ),
    }
}

fn derive_pbkdf2_master_key(
    password: &str,
    email_normalized: &str,
    iterations: u32,
) -> LockedKey32 {
    let mut master_key = LockedKey32::new_zeroed();
    pbkdf2::pbkdf2_hmac::<Sha256>(
        password.as_bytes(),
        email_normalized.as_bytes(),
        iterations,
        master_key.as_mut_slice(),
    );
    master_key
}

fn derive_argon2id_master_key(
    password: &str,
    email_normalized: &str,
    iterations: u32,
    memory_mib: u32,
    parallelism: u32,
) -> Result<LockedKey32, CryptoError> {
    let memory_kib = memory_mib.checked_mul(1024).ok_or_else(|| {
        CryptoError::KdfParametersRejected(format!("Argon2id memory MiB {} overflows", memory_mib))
    })?;
    let params = Params::new(memory_kib, iterations, parallelism, Some(32))
        .map_err(|_| CryptoError::InvalidKdfParams)?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut master_key = LockedKey32::new_zeroed();
    let email_hash = Sha256::digest(email_normalized.as_bytes());
    argon2
        .hash_password_into(password.as_bytes(), &email_hash, master_key.as_mut_slice())
        .map_err(|_| CryptoError::InvalidKdfParams)?;
    Ok(master_key)
}

pub fn derive_master_password_hash(master_key: &[u8], password: &str) -> String {
    let mut hash = Zeroizing::new([0u8; 32]);
    pbkdf2::pbkdf2_hmac::<Sha256>(master_key, password.as_bytes(), 1, hash.as_mut());
    BASE64.encode(hash.as_ref())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SymmetricCryptoKey {
    pub enc_key: LockedKey32,
    pub mac_key: Option<LockedKey32>,
}

impl Zeroize for SymmetricCryptoKey {
    fn zeroize(&mut self) {
        self.enc_key.zeroize();
        if let Some(ref mut mac) = self.mac_key {
            mac.zeroize();
        }
    }
}

impl SymmetricCryptoKey {
    /// Stretches a 32-byte master key into an encryption key and a MAC key with
    /// HKDF-Expand (RFC 5869 section 2.3, the master key used as the PRK) and
    /// the info strings "enc" and "mac", as Bitwarden clients do.
    pub fn stretch_master_key(master_key: &[u8]) -> Result<Self, CryptoError> {
        if master_key.len() != 32 {
            return Err(CryptoError::InvalidKeyLength);
        }
        let hkdf =
            Hkdf::<Sha256>::from_prk(master_key).map_err(|_| CryptoError::InvalidKeyLength)?;
        let mut enc_key = LockedKey32::new_zeroed();
        let mut mac_key = LockedKey32::new_zeroed();
        hkdf.expand(b"enc", enc_key.as_mut_slice())
            .map_err(|_| CryptoError::InvalidKeyLength)?;
        hkdf.expand(b"mac", mac_key.as_mut_slice())
            .map_err(|_| CryptoError::InvalidKeyLength)?;

        Ok(Self {
            enc_key,
            mac_key: Some(mac_key),
        })
    }

    /// Decrypts the protected user key with the master key.
    ///
    /// Type 2 user keys are decrypted with the stretched master key. Type 0
    /// user keys are the legacy format official clients still accept: the raw
    /// master key is the AES key and no MAC is present.
    pub fn decrypt_with_master_key(
        enc: &EncString,
        master_key: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        if master_key.len() != 32 {
            return Err(CryptoError::InvalidKeyLength);
        }
        if enc.enc_type == 0 {
            let legacy_key = SymmetricCryptoKey {
                enc_key: LockedKey32::from_slice(master_key)
                    .ok_or(CryptoError::InvalidKeyLength)?,
                mac_key: None,
            };
            return enc.decrypt(&legacy_key);
        }
        enc.decrypt(&Self::stretch_master_key(master_key)?)
    }

    /// Builds a key from a 64-byte enc+mac blob. MAC-less 32-byte keys are
    /// refused: every user, organization, item and attachment key issued by
    /// current Bitwarden clients is authenticated.
    pub fn from_raw_bytes(key_bytes: &[u8]) -> Result<Self, CryptoError> {
        if key_bytes.len() != AUTHENTICATED_SYMMETRIC_KEY_LENGTH {
            return Err(CryptoError::InvalidKeyLength);
        }
        let enc = LockedKey32::from_slice(&key_bytes[..32]).ok_or(CryptoError::InvalidKeyLength)?;
        let mac = LockedKey32::from_slice(&key_bytes[32..]).ok_or(CryptoError::InvalidKeyLength)?;
        Ok(Self {
            enc_key: enc,
            mac_key: Some(mac),
        })
    }

    pub fn encrypt_string(&self, plaintext: &str) -> Result<String, CryptoError> {
        self.encrypt(plaintext.as_bytes())
    }

    /// Raw-bytes counterpart of [Self::encrypt_string]. Bitwarden item keys
    /// are 64-byte key blobs, not UTF-8 text, so anything that must round-trip
    /// them needs this entry point.
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<String, CryptoError> {
        use cbc::cipher::{BlockEncryptMut, KeyIvInit};
        use rand_core::RngCore;
        type Aes256CbcEnc = cbc::Encryptor<Aes256>;

        let mut iv = [0u8; 16];
        rand_core::OsRng.fill_bytes(&mut iv);

        let enc = Aes256CbcEnc::new_from_slices(&self.enc_key, &iv)
            .map_err(|e| CryptoError::DecryptionFailed(format!("Invalid key/iv: {}", e)))?;
        let mut buf = vec![0u8; plaintext.len() + 32];
        let ct_len = enc
            .encrypt_padded_b2b_mut::<Pkcs7>(plaintext, &mut buf)
            .map_err(|e| CryptoError::DecryptionFailed(format!("Encryption failed: {}", e)))?
            .len();
        let ct = &buf[..ct_len];

        let mac_k = self.mac_key.as_ref().ok_or(CryptoError::MacMismatch)?;
        let mut hmac = HmacSha256::new_from_slice(mac_k)
            .map_err(|e| CryptoError::DecryptionFailed(format!("Invalid mac key: {}", e)))?;
        hmac.update(&iv);
        hmac.update(ct);
        let mac = hmac.finalize().into_bytes();

        Ok(format!(
            "2.{}|{}|{}",
            BASE64.encode(iv),
            BASE64.encode(ct),
            BASE64.encode(mac)
        ))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncString {
    pub enc_type: u32,
    pub iv: Vec<u8>,
    pub ciphertext: Vec<u8>,
    pub mac: Option<Vec<u8>>,
}

impl EncString {
    pub fn parse(raw: &str) -> Result<Self, CryptoError> {
        let raw = raw.trim();
        let (type_str, rest) = raw
            .split_once('.')
            .ok_or_else(|| CryptoError::InvalidEncString(raw.to_string()))?;

        let enc_type = type_str
            .parse::<u32>()
            .map_err(|_| CryptoError::InvalidEncString(raw.to_string()))?;

        let parts: Vec<&str> = rest.split('|').collect();
        if enc_type == 3 || enc_type == 4 || enc_type == 5 || enc_type == 6 || parts.len() == 1 {
            // RSA ciphertext format: <cipher_text_b64> or <cipher_text_b64>|<hmac>
            let ciphertext = BASE64
                .decode(parts[0])
                .map_err(|_| CryptoError::InvalidEncString(raw.to_string()))?;
            return Ok(Self {
                enc_type,
                iv: Vec::new(),
                ciphertext,
                mac: None,
            });
        }

        let iv = BASE64
            .decode(parts[0])
            .map_err(|_| CryptoError::InvalidEncString(raw.to_string()))?;
        let ciphertext = BASE64
            .decode(parts[1])
            .map_err(|_| CryptoError::InvalidEncString(raw.to_string()))?;

        let mac = if parts.len() >= 3 {
            Some(
                BASE64
                    .decode(parts[2])
                    .map_err(|_| CryptoError::InvalidEncString(raw.to_string()))?,
            )
        } else {
            None
        };

        Ok(Self {
            enc_type,
            iv,
            ciphertext,
            mac,
        })
    }

    pub fn decrypt_rsa(&self, rsa_key: &rsa::RsaPrivateKey) -> Result<Vec<u8>, CryptoError> {
        match self.enc_type {
            4 | 6 => {
                // Bitwarden type 4 (Rsa2048_OaepSha1_B64) & 6 (Rsa2048_OaepSha1_HmacSha256_B64) use SHA-1
                let padding = rsa::Oaep::new::<sha1::Sha1>();
                rsa_key
                    .decrypt(padding, &self.ciphertext)
                    .or_else(|_| {
                        let padding256 = rsa::Oaep::new::<Sha256>();
                        rsa_key.decrypt(padding256, &self.ciphertext)
                    })
                    .map_err(|e| CryptoError::DecryptionFailed(e.to_string()))
            }
            3 | 5 => {
                // Bitwarden type 3 (Rsa2048_OaepSha256_B64) & 5 (Rsa2048_OaepSha256_HmacSha256_B64) use SHA-256
                let padding256 = rsa::Oaep::new::<Sha256>();
                rsa_key
                    .decrypt(padding256, &self.ciphertext)
                    .or_else(|_| {
                        let padding = rsa::Oaep::new::<sha1::Sha1>();
                        rsa_key.decrypt(padding, &self.ciphertext)
                    })
                    .map_err(|e| CryptoError::DecryptionFailed(e.to_string()))
            }
            _ => Err(CryptoError::UnsupportedCipherType(self.enc_type)),
        }
    }

    pub fn decrypt(&self, key: &SymmetricCryptoKey) -> Result<Vec<u8>, CryptoError> {
        match self.enc_type {
            0 => self.decrypt_unauthenticated_aes_cbc(key),
            2 => self.decrypt_authenticated_aes_cbc(key),
            other => Err(CryptoError::UnsupportedCipherType(other)),
        }
    }

    /// enc_type 0: AesCbc256_B64 (legacy, unauthenticated CBC).
    ///
    /// Refused whenever the key has a MAC key or the EncString carries a MAC,
    /// as official Bitwarden clients do ("MAC required"). Otherwise a server
    /// could strip the MAC from an authenticated value and present malleable
    /// ciphertext under an authenticated key.
    fn decrypt_unauthenticated_aes_cbc(
        &self,
        key: &SymmetricCryptoKey,
    ) -> Result<Vec<u8>, CryptoError> {
        if key.mac_key.is_some() || self.mac.is_some() {
            return Err(CryptoError::MacRequired);
        }
        decrypt_aes_cbc_bytes(&self.ciphertext, &self.iv, &key.enc_key)
    }

    /// enc_type 2: AesCbc256_HmacSha256_B64. The MAC and the MAC key are
    /// mandatory and the MAC is verified before decryption (Encrypt-then-MAC).
    fn decrypt_authenticated_aes_cbc(
        &self,
        key: &SymmetricCryptoKey,
    ) -> Result<Vec<u8>, CryptoError> {
        if self.iv.len() != 16 {
            return Err(CryptoError::DecryptionFailed(
                "Invalid IV length".to_string(),
            ));
        }
        let expected_mac = self.mac.as_deref().ok_or(CryptoError::MacMismatch)?;
        let mac_key = key.mac_key.as_ref().ok_or(CryptoError::MacMismatch)?;
        verify_hmac_sha256(mac_key, &self.iv, &self.ciphertext, expected_mac)?;
        decrypt_aes_cbc_bytes(&self.ciphertext, &self.iv, &key.enc_key)
    }

    pub fn decrypt_string(&self, key: &SymmetricCryptoKey) -> Result<String, CryptoError> {
        let bytes = self.decrypt(key)?;
        String::from_utf8(bytes).map_err(|_| CryptoError::Utf8Error)
    }
}

/// Verifies an HMAC-SHA256 over `iv || ciphertext` in constant time.
fn verify_hmac_sha256(
    mac_key: &[u8],
    iv: &[u8],
    ciphertext: &[u8],
    expected_mac: &[u8],
) -> Result<(), CryptoError> {
    let mut hmac = HmacSha256::new_from_slice(mac_key)
        .map_err(|e| CryptoError::DecryptionFailed(format!("Invalid MAC key: {}", e)))?;
    hmac.update(iv);
    hmac.update(ciphertext);
    let calculated_mac = hmac.finalize().into_bytes();
    if expected_mac.ct_eq(&calculated_mac).unwrap_u8() != 1 {
        return Err(CryptoError::MacMismatch);
    }
    Ok(())
}

fn decrypt_aes_cbc_bytes(ciphertext: &[u8], iv: &[u8], key: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if iv.len() != 16 {
        return Err(CryptoError::DecryptionFailed(
            "Invalid IV length".to_string(),
        ));
    }
    let dec = Aes256CbcDec::new_from_slices(key, iv)
        .map_err(|e| CryptoError::DecryptionFailed(e.to_string()))?;
    // Decrypted in place. The buffer is zeroized on every path out (a
    // padding failure leaves plaintext in it), and on success it is
    // truncated to the plaintext and handed to the caller instead of being
    // copied, so no second plaintext copy is left behind.
    let mut buf = Zeroizing::new(ciphertext.to_vec());
    let plaintext_len = dec
        .decrypt_padded_mut::<Pkcs7>(&mut buf)
        .map_err(|e| CryptoError::DecryptionFailed(format!("{:?}", e)))?
        .len();
    buf[plaintext_len..].zeroize();
    buf.truncate(plaintext_len);
    Ok(std::mem::take(&mut *buf))
}

pub fn parse_rsa_private_key_der(der_bytes: &[u8]) -> Result<rsa::RsaPrivateKey, CryptoError> {
    use rsa::pkcs1::DecodeRsaPrivateKey;
    use rsa::pkcs8::DecodePrivateKey;

    if let Ok(key) = rsa::RsaPrivateKey::from_pkcs8_der(der_bytes) {
        return Ok(key);
    }
    if let Ok(key) = rsa::RsaPrivateKey::from_pkcs1_der(der_bytes) {
        return Ok(key);
    }

    // Try decoding if der_bytes is UTF-8 text (Base64 string or PEM formatted)
    if let Ok(text) = std::str::from_utf8(der_bytes) {
        let text_clean = text.trim();
        // 1. Try raw Base64 decode
        if let Ok(decoded_b64) = BASE64.decode(text_clean) {
            if let Ok(key) = rsa::RsaPrivateKey::from_pkcs8_der(&decoded_b64) {
                return Ok(key);
            }
            if let Ok(key) = rsa::RsaPrivateKey::from_pkcs1_der(&decoded_b64) {
                return Ok(key);
            }
        }
        // 2. Try PEM decode
        if let Ok(key) = rsa::RsaPrivateKey::from_pkcs8_pem(text_clean) {
            return Ok(key);
        }
        if let Ok(key) = rsa::RsaPrivateKey::from_pkcs1_pem(text_clean) {
            return Ok(key);
        }
    }

    Err(CryptoError::DecryptionFailed(
        "Invalid RSA private key (failed PKCS#8/PKCS#1 DER/Base64/PEM parsing)".to_string(),
    ))
}

/// Parses a decrypted organization, item or attachment key. Only 64-byte
/// enc+mac keys are accepted, either raw or Base64-encoded.
pub fn parse_symmetric_key_from_decrypted_bytes(bytes: &[u8]) -> Option<SymmetricCryptoKey> {
    if let Ok(key) = SymmetricCryptoKey::from_raw_bytes(bytes) {
        return Some(key);
    }
    let text = std::str::from_utf8(bytes).ok()?;
    let decoded = Zeroizing::new(BASE64.decode(text.trim()).ok()?);
    SymmetricCryptoKey::from_raw_bytes(&decoded).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pbkdf2_master_key_derivation() {
        let master_key = derive_master_key(
            "user@example.com",
            "password123",
            KdfType::Pbkdf2Sha256,
            100_000,
            None,
            None,
        )
        .unwrap();

        assert_eq!(master_key.len(), 32);

        let auth_hash = derive_master_password_hash(&master_key, "password123");
        assert!(!auth_hash.is_empty());
    }

    #[test]
    fn test_symmetric_key_and_encstring_roundtrip() {
        let raw_key = [7u8; 64];
        let key = SymmetricCryptoKey::from_raw_bytes(&raw_key).unwrap();

        // Sample encrypted string: type 2 (AES-256-CBC with HMAC-SHA256)
        // Let's create an encstring and verify decrypt
        let iv = [1u8; 16];
        let plaintext = b"Hello, Bitwarden Native Rust!";

        use cbc::cipher::BlockEncryptMut;
        type Aes256CbcEnc = cbc::Encryptor<Aes256>;
        let enc = Aes256CbcEnc::new_from_slices(&key.enc_key, &iv).unwrap();
        let mut buf = vec![0u8; 64];
        let ct_len = enc
            .encrypt_padded_b2b_mut::<Pkcs7>(plaintext, &mut buf)
            .unwrap()
            .len();
        let ct = &buf[..ct_len];

        let mut hmac = HmacSha256::new_from_slice(key.mac_key.as_ref().unwrap()).unwrap();
        hmac.update(&iv);
        hmac.update(ct);
        let mac = hmac.finalize().into_bytes();

        let enc_str_val = format!(
            "2.{}|{}|{}",
            BASE64.encode(iv),
            BASE64.encode(ct),
            BASE64.encode(mac)
        );

        let parsed = EncString::parse(&enc_str_val).unwrap();
        assert_eq!(parsed.enc_type, 2);

        let decrypted = parsed.decrypt_string(&key).unwrap();
        assert_eq!(decrypted, "Hello, Bitwarden Native Rust!");
    }

    #[test]
    fn test_hmac_verification_rejects_tampered_mac() {
        let raw_key = [7u8; 64];
        let key = SymmetricCryptoKey::from_raw_bytes(&raw_key).unwrap();

        let encrypted = key.encrypt_string("https://vault.bitwarden.com").unwrap();
        let mut parsed = EncString::parse(&encrypted).unwrap();

        // Corrupt MAC byte
        if let Some(ref mut mac) = parsed.mac {
            mac[0] ^= 0xFF;
        }

        assert_eq!(
            parsed.decrypt(&key).unwrap_err(),
            CryptoError::MacMismatch,
            "Altered MAC must be strictly rejected with MacMismatch"
        );
        assert_eq!(
            parsed.decrypt_string(&key).unwrap_err(),
            CryptoError::MacMismatch,
            "decrypt_string must not fall back to unauthenticated CBC decryption"
        );
    }

    #[test]
    fn test_hmac_verification_rejects_altered_iv_cbc_bit_flipping() {
        let raw_key = [11u8; 64];
        let key = SymmetricCryptoKey::from_raw_bytes(&raw_key).unwrap();

        // Plaintext: "https://good.example/login"
        let plaintext = "https://good.example/login";
        let encrypted = key.encrypt_string(plaintext).unwrap();
        let mut parsed = EncString::parse(&encrypted).unwrap();

        // CBC bit-flip: "https://" is 8 chars, 'g' is index 8 in plaintext block 0.
        // Changing IV[8] by ('g' ^ 'b') would flip 'g' to 'b' in CBC mode without MAC.
        parsed.iv[8] ^= b'g' ^ b'b';

        let res = parsed.decrypt_string(&key);
        assert!(
            res.is_err(),
            "CBC bit flipping attack on IV must be rejected by HMAC verification"
        );
        assert_eq!(res.unwrap_err(), CryptoError::MacMismatch);
    }

    #[test]
    fn test_hmac_verification_rejects_altered_ciphertext() {
        let raw_key = [13u8; 64];
        let key = SymmetricCryptoKey::from_raw_bytes(&raw_key).unwrap();

        let encrypted = key.encrypt_string("SuperSecretPassword123!").unwrap();
        let mut parsed = EncString::parse(&encrypted).unwrap();

        // Tamper ciphertext
        parsed.ciphertext[5] ^= 0xAA;

        let res = parsed.decrypt_string(&key);
        assert!(res.is_err());
        assert_eq!(res.unwrap_err(), CryptoError::MacMismatch);
    }

    #[test]
    fn test_hmac_verification_rejects_missing_mac_on_type_2() {
        let raw_key = [17u8; 64];
        let key = SymmetricCryptoKey::from_raw_bytes(&raw_key).unwrap();

        let encrypted = key.encrypt_string("Secret Data").unwrap();
        let mut parsed = EncString::parse(&encrypted).unwrap();
        parsed.mac = None; // Strip MAC

        let res = parsed.decrypt_string(&key);
        assert!(res.is_err());
        assert_eq!(res.unwrap_err(), CryptoError::MacMismatch);
    }

    #[test]
    fn test_hmac_verification_rejects_key_missing_mac_key() {
        let raw_key = [19u8; 64];
        let key = SymmetricCryptoKey::from_raw_bytes(&raw_key).unwrap();

        let encrypted = key.encrypt_string("Secret Data").unwrap();
        let parsed = EncString::parse(&encrypted).unwrap();

        let key_without_mac = SymmetricCryptoKey {
            enc_key: key.enc_key.clone(),
            mac_key: None,
        };

        let res = parsed.decrypt_string(&key_without_mac);
        assert!(res.is_err());
        assert_eq!(res.unwrap_err(), CryptoError::MacMismatch);
    }

    #[test]
    fn test_decrypt_with_master_key_rejects_tampered_mac() {
        let master_key = [23u8; 32];
        let sym_key = SymmetricCryptoKey::stretch_master_key(&master_key).unwrap();

        let user_key_raw = [42u8; 64];
        let encrypted_user_key = sym_key
            .encrypt_string(&BASE64.encode(user_key_raw))
            .unwrap();
        let mut parsed = EncString::parse(&encrypted_user_key).unwrap();

        // Tamper MAC
        if let Some(ref mut mac) = parsed.mac {
            mac[0] ^= 0xEE;
        }

        let res = SymmetricCryptoKey::decrypt_with_master_key(&parsed, &master_key);
        assert!(
            res.is_err(),
            "decrypt_with_master_key must reject tampered MAC without unauthenticated fallback"
        );
    }

    #[test]
    fn test_legacy_type_0_roundtrip() {
        let enc_key = [31u8; 32];
        let iv = [5u8; 16];
        let plaintext = b"Legacy Type 0 unauthenticated data";

        use cbc::cipher::BlockEncryptMut;
        let cipher = cbc::Encryptor::<Aes256>::new((&enc_key).into(), (&iv).into());
        let mut buf = vec![0u8; plaintext.len() + 16];
        buf[..plaintext.len()].copy_from_slice(plaintext);
        let ct_len = cipher
            .encrypt_padded_mut::<Pkcs7>(&mut buf, plaintext.len())
            .unwrap()
            .len();
        let ct = &buf[..ct_len];

        let enc_str_val = format!("0.{}|{}", BASE64.encode(iv), BASE64.encode(ct));
        let parsed = EncString::parse(&enc_str_val).unwrap();
        assert_eq!(parsed.enc_type, 0);
        assert!(parsed.mac.is_none());

        let key = SymmetricCryptoKey {
            enc_key: LockedKey32::from_array(enc_key),
            mac_key: None,
        };
        let decrypted = parsed.decrypt_string(&key).unwrap();
        assert_eq!(decrypted, "Legacy Type 0 unauthenticated data");
    }

    fn encrypt_type_0_for_test(enc_key: &[u8; 32], plaintext: &[u8]) -> EncString {
        use cbc::cipher::BlockEncryptMut;
        let iv = [3u8; 16];
        let cipher = cbc::Encryptor::<Aes256>::new(enc_key.into(), (&iv).into());
        let mut buf = vec![0u8; plaintext.len() + 16];
        buf[..plaintext.len()].copy_from_slice(plaintext);
        let ct_len = cipher
            .encrypt_padded_mut::<Pkcs7>(&mut buf, plaintext.len())
            .unwrap()
            .len();
        EncString {
            enc_type: 0,
            iv: iv.to_vec(),
            ciphertext: buf[..ct_len].to_vec(),
            mac: None,
        }
    }

    #[test]
    fn test_aes_cbc_decryption_returns_the_in_place_buffer_without_a_copy() {
        let enc_key = [17u8; 32];
        let plaintext = b"in-place plaintext of forty-one bytes....";
        let encrypted = encrypt_type_0_for_test(&enc_key, plaintext);
        let decrypted =
            decrypt_aes_cbc_bytes(&encrypted.ciphertext, &encrypted.iv, &enc_key).unwrap();
        assert_eq!(decrypted, plaintext);
        assert_eq!(
            decrypted.capacity(),
            encrypted.ciphertext.len(),
            "the plaintext is the truncated decryption buffer, not a second copy"
        );
        let mut damaged = encrypted.ciphertext.clone();
        let last = damaged.len() - 1;
        damaged[last] ^= 0xff;
        assert!(decrypt_aes_cbc_bytes(&damaged, &encrypted.iv, &enc_key).is_err());
    }

    #[test]
    fn test_type_0_downgrade_rejected_when_key_has_mac_key() {
        let raw_key = [29u8; 64];
        let key = SymmetricCryptoKey::from_raw_bytes(&raw_key).unwrap();
        let mut enc_key = [0u8; 32];
        enc_key.copy_from_slice(&raw_key[..32]);

        // A server strips the MAC and relabels the value as type 0 under the
        // same (authenticated) key.
        let downgraded = encrypt_type_0_for_test(&enc_key, b"attacker controlled");
        assert_eq!(
            downgraded.decrypt(&key).unwrap_err(),
            CryptoError::MacRequired
        );

        let serialized = format!(
            "0.{}|{}",
            BASE64.encode(&downgraded.iv),
            BASE64.encode(&downgraded.ciphertext)
        );
        let reparsed = EncString::parse(&serialized).unwrap();
        assert_eq!(
            reparsed.decrypt_string(&key).unwrap_err(),
            CryptoError::MacRequired
        );
    }

    #[test]
    fn test_type_0_rejected_when_encstring_carries_mac() {
        let enc_key = [37u8; 32];
        let mut with_mac = encrypt_type_0_for_test(&enc_key, b"legacy");
        with_mac.mac = Some(vec![0u8; 32]);
        let mac_less_key = SymmetricCryptoKey {
            enc_key: LockedKey32::from_array(enc_key),
            mac_key: None,
        };
        assert_eq!(
            with_mac.decrypt(&mac_less_key).unwrap_err(),
            CryptoError::MacRequired
        );
    }

    #[test]
    fn test_type_2_requires_mac_and_mac_key() {
        let key = SymmetricCryptoKey::from_raw_bytes(&[41u8; 64]).unwrap();
        let mut parsed = EncString::parse(&key.encrypt_string("value").unwrap()).unwrap();
        let mac_less_key = SymmetricCryptoKey {
            enc_key: key.enc_key.clone(),
            mac_key: None,
        };
        assert_eq!(
            parsed.decrypt(&mac_less_key).unwrap_err(),
            CryptoError::MacMismatch
        );
        parsed.mac = None;
        assert_eq!(parsed.decrypt(&key).unwrap_err(), CryptoError::MacMismatch);
    }

    #[test]
    fn test_mac_less_32_byte_keys_are_rejected() {
        assert_eq!(
            SymmetricCryptoKey::from_raw_bytes(&[1u8; 32]).unwrap_err(),
            CryptoError::InvalidKeyLength
        );
        assert!(parse_symmetric_key_from_decrypted_bytes(&[1u8; 32]).is_none());
        let encoded_short_key = BASE64.encode([1u8; 32]);
        assert!(parse_symmetric_key_from_decrypted_bytes(encoded_short_key.as_bytes()).is_none());

        let encoded_full_key = BASE64.encode([1u8; 64]);
        let parsed = parse_symmetric_key_from_decrypted_bytes(encoded_full_key.as_bytes()).unwrap();
        assert!(parsed.mac_key.is_some());
        assert!(parse_symmetric_key_from_decrypted_bytes(&[1u8; 64]).is_some());
    }

    #[test]
    fn test_decrypt_with_master_key_uses_hkdf_expand_stretch() {
        let master_key = [43u8; 32];
        let stretched = SymmetricCryptoKey::stretch_master_key(&master_key).unwrap();
        let protected_user_key =
            EncString::parse(&stretched.encrypt(&[44u8; 64]).unwrap()).unwrap();

        let decrypted =
            SymmetricCryptoKey::decrypt_with_master_key(&protected_user_key, &master_key).unwrap();
        assert_eq!(decrypted, vec![44u8; 64]);

        // A key derived with HKDF Extract+Expand (empty salt) is not accepted.
        let extract_then_expand = Hkdf::<Sha256>::new(Some(&[]), &master_key);
        let mut enc_key = [0u8; 32];
        let mut mac_key = [0u8; 32];
        extract_then_expand.expand(b"enc", &mut enc_key).unwrap();
        extract_then_expand.expand(b"mac", &mut mac_key).unwrap();
        let non_standard_key = SymmetricCryptoKey {
            enc_key: LockedKey32::from_array(enc_key),
            mac_key: Some(LockedKey32::from_array(mac_key)),
        };
        let non_standard =
            EncString::parse(&non_standard_key.encrypt(&[44u8; 64]).unwrap()).unwrap();
        assert_eq!(
            SymmetricCryptoKey::decrypt_with_master_key(&non_standard, &master_key).unwrap_err(),
            CryptoError::MacMismatch
        );
    }

    // Known-answer vectors below are copied from Bitwarden's SDK
    // (github.com/bitwarden/sdk-internal, crates/bitwarden-crypto/src/keys/
    // utils.rs `test_stretch_kdf_key` and master_key.rs tests).

    #[test]
    fn test_stretch_master_key_matches_bitwarden_known_answer() {
        let master_key = [
            31, 79, 104, 226, 150, 71, 177, 90, 194, 80, 172, 209, 17, 129, 132, 81, 138, 167, 69,
            167, 254, 149, 2, 27, 39, 197, 64, 42, 22, 195, 86, 75,
        ];
        let stretched = SymmetricCryptoKey::stretch_master_key(&master_key).unwrap();
        assert_eq!(
            stretched.enc_key.as_slice(),
            [
                111, 31, 178, 45, 238, 152, 37, 114, 143, 215, 124, 83, 135, 173, 195, 23, 142,
                134, 120, 249, 61, 132, 163, 182, 113, 197, 189, 204, 188, 21, 237, 96
            ]
        );
        assert_eq!(
            stretched.mac_key.as_ref().unwrap().as_slice(),
            [
                221, 127, 206, 234, 101, 27, 202, 38, 86, 52, 34, 28, 78, 28, 185, 16, 48, 61, 127,
                166, 209, 247, 194, 87, 232, 26, 48, 85, 193, 249, 179, 155
            ]
        );
    }

    #[test]
    fn test_pbkdf2_master_password_hash_matches_bitwarden_known_answer() {
        for salt in [
            "test@bitwarden.com",
            "TEST@bitwarden.com",
            " test@bitwarden.com",
        ] {
            let master_key =
                derive_master_key(salt, "asdfasdf", KdfType::Pbkdf2Sha256, 100_000, None, None)
                    .unwrap();
            assert_eq!(
                derive_master_password_hash(&master_key, "asdfasdf"),
                "wmyadRMyBZOH7P/a/ucTCbSghKgdzDpPqUnu/DAVtSw="
            );
        }
    }

    #[test]
    fn test_argon2id_master_password_hash_matches_bitwarden_known_answer() {
        let master_key = derive_master_key(
            "test_salt",
            "asdfasdf",
            KdfType::Argon2id,
            4,
            Some(32),
            Some(2),
        )
        .unwrap();
        assert_eq!(
            derive_master_password_hash(&master_key, "asdfasdf"),
            "PR6UjYmjmppTYcdyTiNbAhPJuQQOmynKbdEl1oyi/iQ="
        );
    }

    #[test]
    fn test_decrypt_legacy_type_0_user_key_matches_bitwarden_known_answer() {
        let master_key = BASE64
            .decode("hvBMMb1t79YssFZkpetYsM3deyVuQv4r88Uj9gvYe08=")
            .unwrap();
        let protected_user_key = EncString::parse("0.tn/heK4HLbbEe+yEkC+kvw==|8QM94f7aVTtjm/bmvRdVxOxiLiiZtHYYO7+oBdjFCkilncesx0iVrXPl+tMKqW+Jo7+FtZdPNsTrL6RdoG7i5QbCRVwK+9010+xm7MTQY8s=").unwrap();

        let raw_user_key =
            SymmetricCryptoKey::decrypt_with_master_key(&protected_user_key, &master_key).unwrap();
        let user_key = SymmetricCryptoKey::from_raw_bytes(&raw_user_key).unwrap();
        assert_eq!(
            user_key.enc_key.as_slice(),
            [
                116, 170, 187, 43, 80, 212, 193, 202, 234, 181, 57, 66, 151, 249, 59, 47, 70, 16,
                57, 4, 170, 78, 85, 241, 152, 232, 91, 57, 9, 87, 209, 245,
            ]
        );
        assert_eq!(
            user_key.mac_key.as_ref().unwrap().as_slice(),
            [
                40, 245, 106, 140, 2, 225, 138, 213, 98, 223, 92, 168, 135, 208, 22, 194, 31, 21,
                178, 252, 203, 198, 35, 174, 53, 218, 254, 151, 235, 57, 7, 98,
            ]
        );
    }

    fn assert_kdf_rejected(parameters: KdfParameters) {
        match parameters.validate() {
            Err(CryptoError::KdfParametersRejected(message)) => {
                assert!(message.contains("outside the accepted range"), "{message}")
            }
            other => panic!("expected rejection for {parameters:?}, got {other:?}"),
        }
    }

    #[test]
    fn test_out_of_range_kdf_parameters_are_rejected() {
        for iterations in [0, 5_000, 99_999, 2_000_001, u32::MAX] {
            assert_kdf_rejected(KdfParameters::Pbkdf2Sha256 { iterations });
        }
        let valid_argon2 = (3, 64, 4);
        let invalid_argon2 = [
            (1, 64, 4),
            (11, 64, 4),
            (3, 15, 4),
            (3, 1025, 4),
            (3, u32::MAX, 4),
            (3, 64, 0),
            (3, 64, 17),
        ];
        for (iterations, memory_mib, parallelism) in invalid_argon2 {
            assert_kdf_rejected(KdfParameters::Argon2id {
                iterations,
                memory_mib,
                parallelism,
            });
        }
        let (iterations, memory_mib, parallelism) = valid_argon2;
        assert!(KdfParameters::Argon2id {
            iterations,
            memory_mib,
            parallelism
        }
        .validate()
        .is_ok());
    }

    #[test]
    fn test_kdf_parameter_bounds_are_inclusive() {
        for iterations in [100_000, 2_000_000] {
            assert!(KdfParameters::Pbkdf2Sha256 { iterations }
                .validate()
                .is_ok());
        }
        for (iterations, memory_mib, parallelism) in [(2, 16, 1), (10, 1024, 16)] {
            assert!(KdfParameters::Argon2id {
                iterations,
                memory_mib,
                parallelism
            }
            .validate()
            .is_ok());
        }
    }

    #[test]
    fn test_derive_master_key_refuses_instead_of_substituting() {
        let result = derive_master_key(
            "user@example.com",
            "password",
            KdfType::Pbkdf2Sha256,
            5_000,
            None,
            None,
        );
        assert!(matches!(result, Err(CryptoError::KdfParametersRejected(_))));

        let result = derive_master_key(
            "user@example.com",
            "password",
            KdfType::Argon2id,
            3,
            Some(4_194_304),
            Some(4),
        );
        assert!(matches!(result, Err(CryptoError::KdfParametersRejected(_))));
    }

    #[test]
    fn test_kdf_defaults_apply_only_to_omitted_values() {
        assert_eq!(
            KdfParameters::from_server_values(None, None, None, None).unwrap(),
            KdfParameters::Pbkdf2Sha256 {
                iterations: PBKDF2_DEFAULT_ITERATIONS
            }
        );
        assert_eq!(
            KdfParameters::from_server_values(Some(1), None, None, None).unwrap(),
            KdfParameters::Argon2id {
                iterations: 3,
                memory_mib: 64,
                parallelism: 4
            }
        );
        assert_eq!(
            KdfParameters::from_server_values(Some(1), Some(1), Some(8), Some(32)).unwrap(),
            KdfParameters::Argon2id {
                iterations: 1,
                memory_mib: 8,
                parallelism: 32
            }
        );
        assert!(matches!(
            KdfParameters::from_server_values(Some(7), None, None, None),
            Err(CryptoError::KdfParametersRejected(_))
        ));
    }
}
