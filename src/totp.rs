//! One-time codes from a login's authenticator key, as Bitwarden reads it:
//! an `otpauth://totp/...` URI, a `steam://` secret, or a bare base32 secret
//! (30 seconds, 6 digits, SHA-1).

use hmac::{Hmac, Mac};
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::Zeroizing;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Algorithm {
    Sha1,
    Sha256,
    Sha512,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Kind {
    Digits(u32),
    /// Steam Guard: five characters from Steam's alphabet.
    Steam,
}

#[derive(Clone)]
pub struct Totp {
    secret: Zeroizing<Vec<u8>>,
    pub algorithm: Algorithm,
    pub period: u64,
    pub kind: Kind,
}

impl std::fmt::Debug for Totp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Totp")
            .field("algorithm", &self.algorithm)
            .field("period", &self.period)
            .field("kind", &self.kind)
            .finish_non_exhaustive()
    }
}

const STEAM_CHARS: &[u8] = b"23456789BCDFGHJKMNPQRTVWXY";

fn base32(text: &str) -> Option<Vec<u8>> {
    let clean: String = text
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-' && *c != '=')
        .map(|c| c.to_ascii_uppercase())
        .collect();
    if clean.is_empty() {
        return None;
    }
    data_encoding::BASE32_NOPAD.decode(clean.as_bytes()).ok()
}

fn percent_decode(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(byte) = u8::from_str_radix(&text[i + 1..i + 3], 16) {
                out.push(byte);
                i += 3;
                continue;
            }
        }
        out.push(if bytes[i] == b'+' { b' ' } else { bytes[i] });
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

impl Totp {
    /// Read whatever the login's TOTP field holds. `None` when it holds
    /// nothing usable.
    pub fn parse(text: &str) -> Option<Self> {
        let text = text.trim();
        let lower = text.to_ascii_lowercase();
        if lower.starts_with("steam://") {
            return Some(Self {
                secret: Zeroizing::new(base32(&text["steam://".len()..])?),
                algorithm: Algorithm::Sha1,
                period: 30,
                kind: Kind::Steam,
            });
        }
        if !lower.starts_with("otpauth://") {
            return Some(Self {
                secret: Zeroizing::new(base32(text)?),
                algorithm: Algorithm::Sha1,
                period: 30,
                kind: Kind::Digits(6),
            });
        }
        let query = text.split_once('?').map_or("", |(_, q)| q);
        let mut totp = Self {
            secret: Zeroizing::new(Vec::new()),
            algorithm: Algorithm::Sha1,
            period: 30,
            kind: Kind::Digits(6),
        };
        for pair in query.split('&') {
            let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
            let value = percent_decode(value);
            match key.to_ascii_lowercase().as_str() {
                "secret" => totp.secret = Zeroizing::new(base32(&value)?),
                "algorithm" => {
                    totp.algorithm = match value.to_ascii_uppercase().as_str() {
                        "SHA256" => Algorithm::Sha256,
                        "SHA512" => Algorithm::Sha512,
                        _ => Algorithm::Sha1,
                    }
                }
                "digits" => {
                    if let Ok(digits @ 1..=10) = value.parse() {
                        if totp.kind != Kind::Steam {
                            totp.kind = Kind::Digits(digits);
                        }
                    }
                }
                "period" => {
                    if let Ok(period @ 1..) = value.parse() {
                        totp.period = period;
                    }
                }
                "encoder" if value.eq_ignore_ascii_case("steam") => totp.kind = Kind::Steam,
                _ => {}
            }
        }
        // Bitwarden also treats an otpauth URI whose issuer is Steam as Steam.
        (!totp.secret.is_empty()).then_some(totp)
    }

    fn hotp(&self, counter: u64) -> u32 {
        let msg = counter.to_be_bytes();
        let digest: Vec<u8> = match self.algorithm {
            Algorithm::Sha1 => {
                let mut mac = Hmac::<sha1::Sha1>::new_from_slice(&self.secret).expect("any key");
                mac.update(&msg);
                mac.finalize().into_bytes().to_vec()
            }
            Algorithm::Sha256 => {
                let mut mac = Hmac::<sha2::Sha256>::new_from_slice(&self.secret).expect("any key");
                mac.update(&msg);
                mac.finalize().into_bytes().to_vec()
            }
            Algorithm::Sha512 => {
                let mut mac = Hmac::<sha2::Sha512>::new_from_slice(&self.secret).expect("any key");
                mac.update(&msg);
                mac.finalize().into_bytes().to_vec()
            }
        };
        let offset = (digest[digest.len() - 1] & 0x0f) as usize;
        u32::from_be_bytes([
            digest[offset] & 0x7f,
            digest[offset + 1],
            digest[offset + 2],
            digest[offset + 3],
        ])
    }

    /// The code for a Unix time in seconds.
    pub fn code_at(&self, unix: u64) -> String {
        let value = self.hotp(unix / self.period);
        match self.kind {
            Kind::Digits(digits) => {
                let modulus = 10u64.pow(digits);
                format!(
                    "{:0width$}",
                    value as u64 % modulus,
                    width = digits as usize
                )
            }
            Kind::Steam => {
                let mut value = value as usize;
                (0..5)
                    .map(|_| {
                        let ch = STEAM_CHARS[value % STEAM_CHARS.len()] as char;
                        value /= STEAM_CHARS.len();
                        ch
                    })
                    .collect()
            }
        }
    }

    /// The current code and the seconds it stays valid.
    pub fn now(&self) -> (String, u64) {
        let unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        (self.code_at(unix), self.period - unix % self.period)
    }
}

/// Split a code in two for reading: `123 456`. Steam's five stay whole.
pub fn grouped(code: &str) -> String {
    if code.len() >= 6 && code.chars().all(|c| c.is_ascii_digit()) {
        let mid = code.len() / 2;
        format!("{} {}", &code[..mid], &code[mid..])
    } else {
        code.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 6238 appendix B, 8 digits. The seeds are ASCII "12345678901234567890"
    /// repeated to the hash's length.
    #[test]
    fn rfc6238_vectors() {
        let seed = |len: usize| -> String {
            let ascii: Vec<u8> = b"1234567890".iter().cycle().take(len).copied().collect();
            data_encoding::BASE32_NOPAD.encode(&ascii)
        };
        let cases = [
            (
                "SHA1",
                20,
                [
                    (59, "94287082"),
                    (1111111109, "07081804"),
                    (20000000000, "65353130"),
                ],
            ),
            (
                "SHA256",
                32,
                [
                    (59, "46119246"),
                    (1111111109, "68084774"),
                    (20000000000, "77737706"),
                ],
            ),
            (
                "SHA512",
                64,
                [
                    (59, "90693936"),
                    (1111111109, "25091201"),
                    (20000000000, "47863826"),
                ],
            ),
        ];
        for (algorithm, len, codes) in cases {
            let uri = format!(
                "otpauth://totp/Test:me?secret={}&algorithm={algorithm}&digits=8&period=30",
                seed(len)
            );
            let totp = Totp::parse(&uri).unwrap();
            for (time, expected) in codes {
                assert_eq!(totp.code_at(time), expected, "{algorithm} at {time}");
            }
        }
    }

    #[test]
    fn bare_secret_is_six_digit_sha1() {
        let totp = Totp::parse("gezd gnbv gy3t qojq gezd gnbv gy3t qojq").unwrap();
        assert_eq!(totp.kind, Kind::Digits(6));
        assert_eq!(totp.period, 30);
        assert_eq!(totp.code_at(59), "287082");
    }

    #[test]
    fn steam() {
        let totp = Totp::parse("steam://GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ").unwrap();
        assert_eq!(totp.kind, Kind::Steam);
        let code = totp.code_at(59);
        assert_eq!(code.len(), 5);
        assert!(code.bytes().all(|c| STEAM_CHARS.contains(&c)));
        let uri =
            Totp::parse("otpauth://totp/Steam:me?secret=GEZDGNBVGY3TQOJQ&encoder=steam").unwrap();
        assert_eq!(uri.kind, Kind::Steam);
    }

    #[test]
    fn percent_encoded_and_garbage() {
        let totp = Totp::parse("otpauth://totp/A%20B?secret=GEZD%47NBV&period=60").unwrap();
        assert_eq!(totp.period, 60);
        assert!(Totp::parse("").is_none());
        assert!(Totp::parse("otpauth://totp/x?issuer=y").is_none());
        assert!(Totp::parse("not base32 !!").is_none());
    }

    #[test]
    fn grouping() {
        assert_eq!(grouped("123456"), "123 456");
        assert_eq!(grouped("12345678"), "1234 5678");
        assert_eq!(grouped("B2C4D"), "B2C4D");
    }
}
