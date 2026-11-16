//! The Bitwarden client crypto Vord needs to read a vault.
//!
//! - The master key comes from the master password and the account's KDF:
//!   PBKDF2-SHA256 salted with the email, or Argon2id salted with the email's
//!   SHA-256.
//! - The server never sees the master key; it gets the master password hash,
//!   one more PBKDF2 round of the key salted with the password.
//! - The master key is stretched by HKDF-Expand into an encryption half and a
//!   MAC half, which open the account's symmetric "user key".
//! - Everything in the vault is an [`EncString`]: AES-256-CBC with an
//!   HMAC-SHA256 over IV and ciphertext (type 2), or RSA-OAEP (types 3 and 4)
//!   for organisation keys shared to the account's key pair.
//!
//! Keys zero their bytes when dropped.

#[cfg(test)]
use aes::cipher::BlockEncryptMut;
use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, KeyIvInit};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use std::fmt;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

type HmacSha256 = Hmac<Sha256>;
type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;
#[cfg(test)]
type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;

#[derive(Debug, PartialEq, Eq)]
pub enum CryptoError {
    /// The text is not an EncString Vord can read.
    Format(String),
    /// The MAC does not match: the wrong key (a wrong master password, when
    /// opening the user key), or damaged data.
    Mac,
    /// The key has no MAC half but the data needs one, or the other way round.
    KeyMismatch,
    /// Decryption itself failed (bad padding, a bad RSA block).
    Decrypt,
    /// The decrypted bytes are not UTF-8 text.
    Utf8,
    /// The KDF parameters are out of range.
    Kdf(String),
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Format(why) => write!(f, "unreadable encrypted value: {why}"),
            Self::Mac => f.write_str("the key does not fit (MAC mismatch)"),
            Self::KeyMismatch => f.write_str("the key does not fit this kind of encrypted value"),
            Self::Decrypt => f.write_str("decryption failed"),
            Self::Utf8 => f.write_str("decrypted text is not UTF-8"),
            Self::Kdf(why) => write!(f, "unusable key derivation settings: {why}"),
        }
    }
}

impl std::error::Error for CryptoError {}

/// How the account turns a master password into a master key, as the
/// server's prelogin reports it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum Kdf {
    Pbkdf2 {
        iterations: u32,
    },
    Argon2id {
        iterations: u32,
        /// In MiB, as Bitwarden states it.
        memory_mib: u32,
        parallelism: u32,
    },
}

impl Kdf {
    /// From the prelogin's numbers: `kdf` 0 is PBKDF2, 1 is Argon2id.
    pub fn from_prelogin(
        kind: u8,
        iterations: u32,
        memory: Option<u32>,
        parallelism: Option<u32>,
    ) -> Result<Self, CryptoError> {
        match kind {
            0 => Ok(Self::Pbkdf2 { iterations }),
            1 => Ok(Self::Argon2id {
                iterations,
                memory_mib: memory.unwrap_or(64),
                parallelism: parallelism.unwrap_or(4),
            }),
            other => Err(CryptoError::Kdf(format!("unknown KDF type {other}"))),
        }
    }
}

/// The salt Bitwarden derives from an email: trimmed and lower-cased.
pub fn normalize_email(email: &str) -> String {
    email.trim().to_lowercase()
}

/// A 32-byte master key. Never leaves the process.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct MasterKey([u8; 32]);

impl MasterKey {
    pub fn derive(password: &str, email: &str, kdf: Kdf) -> Result<Self, CryptoError> {
        let salt = normalize_email(email);
        let mut out = [0u8; 32];
        match kdf {
            Kdf::Pbkdf2 { iterations } => {
                if iterations == 0 {
                    return Err(CryptoError::Kdf("zero iterations".into()));
                }
                pbkdf2::pbkdf2_hmac::<Sha256>(
                    password.as_bytes(),
                    salt.as_bytes(),
                    iterations,
                    &mut out,
                );
            }
            Kdf::Argon2id {
                iterations,
                memory_mib,
                parallelism,
            } => {
                let salt = Sha256::digest(salt.as_bytes());
                let params = argon2::Params::new(
                    memory_mib.saturating_mul(1024),
                    iterations,
                    parallelism,
                    Some(32),
                )
                .map_err(|e| CryptoError::Kdf(e.to_string()))?;
                argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params)
                    .hash_password_into(password.as_bytes(), &salt, &mut out)
                    .map_err(|e| CryptoError::Kdf(e.to_string()))?;
            }
        }
        Ok(Self(out))
    }

    /// What the server checks at login, base64: one PBKDF2 round of the
    /// master key salted with the password.
    pub fn password_hash(&self, password: &str) -> String {
        let mut out = Zeroizing::new([0u8; 32]);
        pbkdf2::pbkdf2_hmac::<Sha256>(&self.0, password.as_bytes(), 1, &mut *out);
        B64.encode(*out)
    }

    /// HKDF-Expand into the encryption and MAC halves that open the user key.
    pub fn stretch(&self) -> SymmetricKey {
        let hk = hkdf::Hkdf::<Sha256>::from_prk(&self.0).expect("32-byte PRK");
        let mut enc = [0u8; 32];
        let mut mac = [0u8; 32];
        hk.expand(b"enc", &mut enc).expect("32 bytes");
        hk.expand(b"mac", &mut mac).expect("32 bytes");
        SymmetricKey {
            enc,
            mac: Some(mac),
        }
    }

    /// Open the account's encrypted user key. Very old accounts encrypted it
    /// with the bare master key (type 0); newer ones with the stretched key.
    pub fn open_user_key(&self, protected: &EncString) -> Result<SymmetricKey, CryptoError> {
        let bytes = match protected {
            EncString::AesCbc256 { .. } => protected.decrypt(&SymmetricKey {
                enc: self.0,
                mac: None,
            })?,
            _ => protected.decrypt(&self.stretch())?,
        };
        SymmetricKey::from_bytes(&bytes)
    }
}

/// An AES-256 key with its HMAC key: the user key, an organisation key, or a
/// single item's key.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SymmetricKey {
    enc: [u8; 32],
    mac: Option<[u8; 32]>,
}

impl fmt::Debug for SymmetricKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SymmetricKey(..)")
    }
}

impl SymmetricKey {
    /// 64 bytes (encryption then MAC), or 32 for a legacy key without a MAC.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        match bytes.len() {
            64 => {
                let mut enc = [0u8; 32];
                let mut mac = [0u8; 32];
                enc.copy_from_slice(&bytes[..32]);
                mac.copy_from_slice(&bytes[32..]);
                Ok(Self {
                    enc,
                    mac: Some(mac),
                })
            }
            32 => {
                let mut enc = [0u8; 32];
                enc.copy_from_slice(bytes);
                Ok(Self { enc, mac: None })
            }
            n => Err(CryptoError::Format(format!("a {n}-byte key"))),
        }
    }

    #[cfg(test)]
    pub fn generate() -> Self {
        use rand::RngCore;
        let mut bytes = Zeroizing::new([0u8; 64]);
        rand::rngs::OsRng.fill_bytes(&mut *bytes);
        Self::from_bytes(&*bytes).expect("64 bytes")
    }

    #[cfg(test)]
    pub fn to_bytes(&self) -> Zeroizing<Vec<u8>> {
        let mut out = Zeroizing::new(self.enc.to_vec());
        if let Some(mac) = &self.mac {
            out.extend_from_slice(mac);
        }
        out
    }

    /// Encrypt as a type 2 EncString. Vord only reads vaults; this is here
    /// for the tests.
    #[cfg(test)]
    pub fn encrypt(&self, plain: &[u8]) -> EncString {
        use rand::RngCore;
        let mac_key = self.mac.expect("type 2 needs a MAC key");
        let mut iv = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut iv);
        let data =
            Aes256CbcEnc::new(&self.enc.into(), &iv.into()).encrypt_padded_vec_mut::<Pkcs7>(plain);
        let mut hmac = HmacSha256::new_from_slice(&mac_key).expect("any key length");
        hmac.update(&iv);
        hmac.update(&data);
        EncString::AesCbc256HmacSha256 {
            iv,
            data,
            mac: hmac.finalize().into_bytes().into(),
        }
    }
}

/// An RSA private key: the account's, which opens organisation keys.
pub struct PrivateKey(rsa::RsaPrivateKey);

impl PrivateKey {
    /// From the PKCS#8 DER bytes the account stores (encrypted with the user
    /// key).
    pub fn from_der(der: &[u8]) -> Result<Self, CryptoError> {
        use rsa::pkcs8::DecodePrivateKey;
        rsa::RsaPrivateKey::from_pkcs8_der(der)
            .map(Self)
            .map_err(|e| CryptoError::Format(format!("private key: {e}")))
    }
}

/// Bitwarden's encrypted string: `<type>.<base64 parts joined by |>`.
#[derive(Clone, PartialEq, Eq)]
pub enum EncString {
    /// 0: AES-256-CBC without a MAC (legacy).
    AesCbc256 { iv: [u8; 16], data: Vec<u8> },
    /// 2: AES-256-CBC, HMAC-SHA256 over IV and ciphertext.
    AesCbc256HmacSha256 {
        iv: [u8; 16],
        data: Vec<u8>,
        mac: [u8; 32],
    },
    /// 3: RSA-2048 OAEP with SHA-256.
    RsaOaepSha256(Vec<u8>),
    /// 4: RSA-2048 OAEP with SHA-1.
    RsaOaepSha1(Vec<u8>),
}

impl fmt::Debug for EncString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let kind = match self {
            Self::AesCbc256 { .. } => 0,
            Self::AesCbc256HmacSha256 { .. } => 2,
            Self::RsaOaepSha256(_) => 3,
            Self::RsaOaepSha1(_) => 4,
        };
        write!(f, "EncString(type {kind})")
    }
}

fn b64(part: &str) -> Result<Vec<u8>, CryptoError> {
    B64.decode(part.trim())
        .map_err(|e| CryptoError::Format(format!("base64: {e}")))
}

fn fixed<const N: usize>(part: &str, what: &str) -> Result<[u8; N], CryptoError> {
    b64(part)?
        .try_into()
        .map_err(|v: Vec<u8>| CryptoError::Format(format!("{what} is {} bytes, not {N}", v.len())))
}

impl std::str::FromStr for EncString {
    type Err = CryptoError;

    fn from_str(text: &str) -> Result<Self, CryptoError> {
        let (kind, body) = match text.split_once('.') {
            Some((kind, body)) => (
                kind.parse::<u8>()
                    .map_err(|_| CryptoError::Format(format!("type {kind:?}")))?,
                body,
            ),
            // No type: the oldest clients wrote type 0 bare.
            None => (0, text),
        };
        let parts: Vec<&str> = body.split('|').collect();
        match (kind, parts.as_slice()) {
            (0, [iv, data]) => Ok(Self::AesCbc256 {
                iv: fixed(iv, "IV")?,
                data: b64(data)?,
            }),
            (2, [iv, data, mac]) => Ok(Self::AesCbc256HmacSha256 {
                iv: fixed(iv, "IV")?,
                data: b64(data)?,
                mac: fixed(mac, "MAC")?,
            }),
            // 5 and 6 append an HMAC that clients never checked; read as 3/4.
            (3 | 5, [data, ..]) => Ok(Self::RsaOaepSha256(b64(data)?)),
            (4 | 6, [data, ..]) => Ok(Self::RsaOaepSha1(b64(data)?)),
            (kind, parts) => Err(CryptoError::Format(format!(
                "type {kind} with {} part(s)",
                parts.len()
            ))),
        }
    }
}

impl fmt::Display for EncString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AesCbc256 { iv, data } => write!(f, "0.{}|{}", B64.encode(iv), B64.encode(data)),
            Self::AesCbc256HmacSha256 { iv, data, mac } => write!(
                f,
                "2.{}|{}|{}",
                B64.encode(iv),
                B64.encode(data),
                B64.encode(mac)
            ),
            Self::RsaOaepSha256(data) => write!(f, "3.{}", B64.encode(data)),
            Self::RsaOaepSha1(data) => write!(f, "4.{}", B64.encode(data)),
        }
    }
}

impl EncString {
    /// Decrypt with a symmetric key. The MAC is checked, in constant time,
    /// before anything is decrypted.
    pub fn decrypt(&self, key: &SymmetricKey) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
        let (iv, data) = match self {
            Self::AesCbc256 { iv, data } => {
                if key.mac.is_some() {
                    return Err(CryptoError::KeyMismatch);
                }
                (iv, data)
            }
            Self::AesCbc256HmacSha256 { iv, data, mac } => {
                let mac_key = key.mac.as_ref().ok_or(CryptoError::KeyMismatch)?;
                let mut hmac = HmacSha256::new_from_slice(mac_key).expect("any key length");
                hmac.update(iv);
                hmac.update(data);
                hmac.verify_slice(mac).map_err(|_| CryptoError::Mac)?;
                (iv, data)
            }
            Self::RsaOaepSha256(_) | Self::RsaOaepSha1(_) => return Err(CryptoError::KeyMismatch),
        };
        Aes256CbcDec::new(&key.enc.into(), &(*iv).into())
            .decrypt_padded_vec_mut::<Pkcs7>(data)
            .map(Zeroizing::new)
            .map_err(|_| CryptoError::Decrypt)
    }

    pub fn decrypt_text(&self, key: &SymmetricKey) -> Result<String, CryptoError> {
        let bytes = self.decrypt(key)?;
        String::from_utf8(bytes.to_vec()).map_err(|_| CryptoError::Utf8)
    }

    /// Decrypt an RSA EncString with the account's private key.
    pub fn decrypt_rsa(&self, key: &PrivateKey) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
        let result = match self {
            Self::RsaOaepSha256(data) => key.0.decrypt(rsa::Oaep::new::<Sha256>(), data),
            Self::RsaOaepSha1(data) => key.0.decrypt(rsa::Oaep::new::<sha1::Sha1>(), data),
            _ => return Err(CryptoError::KeyMismatch),
        };
        result.map(Zeroizing::new).map_err(|_| CryptoError::Decrypt)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// Values computed independently with Node's crypto module (see
    /// tests/vectors.js), for "hunter2" / " Test@Example.com ".
    #[test]
    fn pbkdf2_master_key_hash_and_stretch() {
        let key = MasterKey::derive(
            "hunter2",
            " Test@Example.com ",
            Kdf::Pbkdf2 { iterations: 5000 },
        )
        .unwrap();
        assert_eq!(
            hex(&key.0),
            include_str!("../tests/vectors/pbkdf2_master_key").trim()
        );
        assert_eq!(
            key.password_hash("hunter2"),
            include_str!("../tests/vectors/pbkdf2_password_hash").trim()
        );
        let stretched = key.stretch();
        assert_eq!(
            hex(&stretched.to_bytes()),
            include_str!("../tests/vectors/pbkdf2_stretched").trim()
        );
    }

    #[test]
    fn argon2id_master_key() {
        let key = MasterKey::derive(
            "hunter2",
            "test@example.com",
            Kdf::Argon2id {
                iterations: 3,
                memory_mib: 16,
                parallelism: 4,
            },
        )
        .unwrap();
        assert_eq!(
            hex(&key.0),
            include_str!("../tests/vectors/argon2id_master_key").trim()
        );
    }

    /// An EncString made by Node with the stretched key
    /// above opens, and so does the 64-byte user key inside it.
    #[test]
    fn opens_a_foreign_user_key() {
        let key = MasterKey::derive(
            "hunter2",
            "test@example.com",
            Kdf::Pbkdf2 { iterations: 5000 },
        )
        .unwrap();
        let protected: EncString = include_str!("../tests/vectors/protected_user_key")
            .trim()
            .parse()
            .unwrap();
        let user_key = key.open_user_key(&protected).unwrap();
        assert_eq!(
            hex(&user_key.to_bytes()),
            include_str!("../tests/vectors/user_key").trim()
        );
        let name: EncString = include_str!("../tests/vectors/encrypted_name")
            .trim()
            .parse()
            .unwrap();
        assert_eq!(name.decrypt_text(&user_key).unwrap(), "Ünïcode name ✓");
    }

    #[test]
    fn round_trip_and_tamper() {
        let key = SymmetricKey::generate();
        let enc = key.encrypt(b"correct horse battery staple");
        let text = enc.to_string();
        assert!(text.starts_with("2."));
        let parsed: EncString = text.parse().unwrap();
        assert_eq!(parsed, enc);
        assert_eq!(
            parsed.decrypt_text(&key).unwrap(),
            "correct horse battery staple"
        );
        assert_eq!(
            parsed.decrypt(&SymmetricKey::generate()).unwrap_err(),
            CryptoError::Mac
        );
        let EncString::AesCbc256HmacSha256 { iv, mut data, mac } = parsed else {
            unreachable!()
        };
        data[0] ^= 1;
        let tampered = EncString::AesCbc256HmacSha256 { iv, data, mac };
        assert_eq!(tampered.decrypt(&key).unwrap_err(), CryptoError::Mac);
    }

    #[test]
    fn wrong_password_is_a_mac_error() {
        let kdf = Kdf::Pbkdf2 { iterations: 1000 };
        let right = MasterKey::derive("right", "a@b.c", kdf).unwrap();
        let user_key = SymmetricKey::generate();
        let protected = right.stretch().encrypt(&user_key.to_bytes());
        assert!(right.open_user_key(&protected).is_ok());
        let wrong = MasterKey::derive("wrong", "a@b.c", kdf).unwrap();
        assert_eq!(
            wrong.open_user_key(&protected).unwrap_err(),
            CryptoError::Mac
        );
    }

    #[test]
    fn rsa_opens_an_org_key() {
        use rsa::pkcs8::EncodePrivateKey;
        let mut rng = rand::rngs::OsRng;
        let private = rsa::RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let public = rsa::RsaPublicKey::from(&private);
        let der = private.to_pkcs8_der().unwrap();
        let key = PrivateKey::from_der(der.as_bytes()).unwrap();
        let org_key = SymmetricKey::generate();
        let sealed = public
            .encrypt(
                &mut rng,
                rsa::Oaep::new::<sha1::Sha1>(),
                &org_key.to_bytes(),
            )
            .unwrap();
        let enc: EncString = EncString::RsaOaepSha1(sealed).to_string().parse().unwrap();
        let opened = SymmetricKey::from_bytes(&enc.decrypt_rsa(&key).unwrap()).unwrap();
        assert_eq!(opened.to_bytes(), org_key.to_bytes());
    }

    #[test]
    fn rejects_garbage() {
        for text in ["", "2.", "2.abc", "9.a|b|c", "2.AAAA|AAAA|AAAA", "x.y"] {
            assert!(text.parse::<EncString>().is_err(), "{text}");
        }
    }
}
