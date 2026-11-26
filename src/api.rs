//! The Bitwarden server endpoints Vord uses, as Vaultwarden serves them:
//! prelogin (the account's KDF), the password and refresh-token grants (with
//! a second step when the account asks for one), sync, website icons, and
//! [`Client::call`] for the rest (saving items and folders).
//!
//! Calls block; the UI runs them on a worker thread.
//!
//! Servers disagree on JSON key case (Vaultwarden and older Bitwarden answer
//! `PascalCase`, newer ones `camelCase`), so every response goes through
//! [`camel`] before it is read.

use crate::crypto::Kdf;
use serde::Deserialize;
use serde_json::Value;
use std::time::Duration;

/// Linux desktop, in Bitwarden's DeviceType enum.
const DEVICE_TYPE: &str = "8";
const CLIENT_ID: &str = "desktop";
/// Servers hide item types from clients too old to know them (Vaultwarden
/// leaves SSH keys out of a sync for clients before 2024.12), so Vord states
/// the desktop release whose item types it reads.
const CLIENT_VERSION: &str = "2025.6.0";
/// How long a file upload or download may take.
const TRANSFER: Duration = Duration::from_secs(15 * 60);

#[derive(Debug)]
pub enum ApiError {
    /// The server could not be reached, or answered with something that
    /// isn't Bitwarden.
    Network(String),
    /// The server refused the login, with its own message.
    Rejected(String),
    /// The account wants a second login step, one of these.
    TwoFactor(TwoFactorChallenge),
    /// The session is over: the refresh token was revoked or expired.
    SessionExpired,
    Other(String),
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Network(why) => write!(f, "Could not reach the server: {why}"),
            Self::Rejected(why) => f.write_str(why),
            Self::TwoFactor(_) => f.write_str("This account needs a second login step."),
            Self::SessionExpired => f.write_str("The session has expired. Log in again."),
            Self::Other(why) => f.write_str(why),
        }
    }
}

impl std::error::Error for ApiError {}

/// The second login steps Vord can answer, in Bitwarden's
/// `TwoFactorProviderType` numbering. Each one is a code the user types (a
/// YubiKey in OTP mode types its own).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TwoFactorMethod {
    YubiKey,
    Authenticator,
    Email,
    /// Not a two-step method: bitwarden.com emails a code the first time a
    /// device logs in to an account without two-step login. The code is
    /// tied to the device id, and the server sends it on its own.
    NewDevice,
}

impl TwoFactorMethod {
    /// The two-step methods, most preferred first, the order Bitwarden's
    /// apps pick a default in.
    pub const ALL: [Self; 3] = [Self::YubiKey, Self::Authenticator, Self::Email];

    /// The provider id; a new device's code has none.
    pub fn id(self) -> Option<u8> {
        match self {
            Self::Authenticator => Some(0),
            Self::Email => Some(1),
            Self::YubiKey => Some(3),
            Self::NewDevice => None,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Authenticator => "Authenticator app",
            Self::Email => "Email",
            Self::YubiKey => "YubiKey",
            Self::NewDevice => "New device code",
        }
    }

    /// The word the CLI takes for it.
    pub fn name(self) -> &'static str {
        match self {
            Self::Authenticator => "authenticator",
            Self::Email => "email",
            Self::YubiKey => "yubikey",
            Self::NewDevice => "new-device",
        }
    }
}

/// The remembered-device token, sent in place of a code.
const REMEMBER: u8 = 5;

/// What the server asks for when a login needs a second step.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TwoFactorChallenge {
    /// The steps Vord can answer, most preferred first.
    pub methods: Vec<TwoFactorMethod>,
    /// The ones it can't (Duo, FIDO2 security keys), by name.
    pub unsupported: Vec<&'static str>,
    /// The masked address an email code goes to.
    pub email_hint: Option<String>,
    /// How many steps the server offered. With email the only one, the
    /// server has already sent the code.
    pub offered: usize,
}

impl TwoFactorChallenge {
    /// Read from a refused login, if that's why it was refused.
    fn from_body(body: &Value) -> Option<Self> {
        if asks_for_new_device_code(body) {
            return Some(Self {
                methods: vec![TwoFactorMethod::NewDevice],
                offered: 1,
                ..Self::default()
            });
        }
        let detailed = body.get("twoFactorProviders2").and_then(Value::as_object);
        let listed = body.get("twoFactorProviders").and_then(Value::as_array);
        if detailed.is_none() && listed.is_none() {
            return None;
        }
        // The detailed map's keys are the ids; the plain list holds numbers
        // or strings, depending on the server.
        let ids: Vec<u8> = match detailed {
            Some(map) => map.keys().filter_map(|k| k.parse().ok()).collect(),
            None => listed
                .into_iter()
                .flatten()
                .filter_map(|v| match v {
                    Value::Number(n) => n.as_u64().and_then(|n| u8::try_from(n).ok()),
                    Value::String(s) => s.parse().ok(),
                    _ => None,
                })
                .collect(),
        };
        let methods = TwoFactorMethod::ALL
            .into_iter()
            .filter(|m| m.id().is_some_and(|id| ids.contains(&id)))
            .collect();
        let mut unsupported = Vec::new();
        for id in &ids {
            let name = match id {
                2 | 6 => "Duo",
                4 | 7 => "a security key (FIDO2)",
                _ => continue,
            };
            if !unsupported.contains(&name) {
                unsupported.push(name);
            }
        }
        let email_hint = body
            .pointer("/twoFactorProviders2/1/email")
            .and_then(Value::as_str)
            .map(str::to_string);
        Some(Self {
            methods,
            unsupported,
            email_hint,
            offered: ids.len(),
        })
    }
}

/// Whether a refused login wants the code bitwarden.com emails to a new
/// device. Its clients go by these words, so they don't change.
fn asks_for_new_device_code(body: &Value) -> bool {
    body.pointer("/errorModel/message")
        .or_else(|| body.get("error_description"))
        .and_then(Value::as_str)
        .is_some_and(|message| message.eq_ignore_ascii_case("new device verification required"))
}

/// The second step sent with a login.
pub enum SecondFactor<'a> {
    /// A code for one of the account's methods; `remember` asks the server
    /// for a token that skips the step on this device next time.
    Code {
        method: TwoFactorMethod,
        code: &'a str,
        remember: bool,
    },
    /// The token a remembered device got.
    Remembered(&'a str),
}

/// Lower-case the first letter of every object key, recursively.
pub fn camel(value: Value) -> Value {
    match value {
        Value::Object(map) => Value::Object(
            map.into_iter()
                .map(|(key, value)| {
                    let mut chars = key.chars();
                    let key = match chars.next() {
                        Some(first) => first.to_lowercase().chain(chars).collect(),
                        None => key,
                    };
                    (key, camel(value))
                })
                .collect(),
        ),
        Value::Array(items) => Value::Array(items.into_iter().map(camel).collect()),
        other => other,
    }
}

/// Make what the user typed into a base URL: a scheme, no trailing slash.
pub fn normalize_server(input: &str) -> Result<String, String> {
    let input = input.trim().trim_end_matches('/');
    if input.is_empty() {
        return Err("Enter your server's address.".into());
    }
    let with_scheme = if input.contains("://") {
        input.to_string()
    } else {
        format!("https://{input}")
    };
    let url = url::Url::parse(&with_scheme).map_err(|e| format!("Not a web address: {e}"))?;
    match url.scheme() {
        "https" => {}
        // Plain HTTP only on this machine (a local test server).
        "http" if is_loopback(&url) => {}
        "http" => return Err("The server address must use https://.".into()),
        other => return Err(format!("Unsupported address scheme {other}://.")),
    }
    if url.host_str().is_none() {
        return Err("The address has no host name.".into());
    }
    Ok(url.as_str().trim_end_matches('/').to_string())
}

fn is_loopback(url: &url::Url) -> bool {
    match url.host() {
        Some(url::Host::Domain(host)) => host == "localhost",
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        None => false,
    }
}

pub struct Client {
    http: reqwest::blocking::Client,
    pub server: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Prelogin {
    kdf: u8,
    kdf_iterations: u32,
    kdf_memory: Option<u32>,
    kdf_parallelism: Option<u32>,
}

/// What a successful login or refresh hands back.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Tokens {
    #[serde(rename = "access_token")]
    pub access_token: String,
    #[serde(rename = "expires_in", default)]
    pub expires_in: u64,
    #[serde(rename = "refresh_token")]
    pub refresh_token: Option<String>,
    /// The user key, encrypted with the stretched master key (login only).
    pub key: Option<String>,
    /// The account's RSA private key, encrypted with the user key.
    pub private_key: Option<String>,
    /// A new remembered-device token, when one was asked for.
    pub two_factor_token: Option<String>,
}

impl Client {
    pub fn new(server: &str) -> Self {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert("Bitwarden-Client-Name", CLIENT_ID.parse().expect("ASCII"));
        headers.insert(
            "Bitwarden-Client-Version",
            CLIENT_VERSION.parse().expect("ASCII"),
        );
        headers.insert("Device-Type", DEVICE_TYPE.parse().expect("ASCII"));
        let http = reqwest::blocking::Client::builder()
            .user_agent(concat!("Vord/", env!("CARGO_PKG_VERSION")))
            .default_headers(headers)
            .timeout(Duration::from_secs(30))
            .connect_timeout(Duration::from_secs(10))
            .build()
            .expect("HTTP client");
        Self {
            http,
            server: server.to_string(),
        }
    }

    fn url(&self, path: &str) -> String {
        format!("{}{path}", self.server)
    }

    fn read(
        response: reqwest::blocking::Response,
    ) -> Result<(reqwest::StatusCode, Value), ApiError> {
        let status = response.status();
        let text = response
            .text()
            .map_err(|e| ApiError::Network(e.to_string()))?;
        let value = if text.trim().is_empty() {
            Value::Null
        } else {
            match serde_json::from_str(&text) {
                Ok(value) => camel(value),
                Err(_) if status.is_success() => {
                    return Err(ApiError::Network(
                        "the answer was not JSON — is this a Bitwarden or Vaultwarden server?"
                            .into(),
                    ))
                }
                Err(_) => Value::Null,
            }
        };
        Ok((status, value))
    }

    /// The account's KDF settings, needed before the password can be hashed.
    pub fn prelogin(&self, email: &str) -> Result<Kdf, ApiError> {
        let response = self
            .http
            .post(self.url("/identity/accounts/prelogin"))
            .json(&serde_json::json!({ "email": email.trim() }))
            .send()
            .map_err(network)?;
        let (status, body) = Self::read(response)?;
        if !status.is_success() {
            return Err(error_from(status, &body));
        }
        let prelogin: Prelogin = serde_json::from_value(body)
            .map_err(|e| ApiError::Network(format!("unexpected prelogin answer: {e}")))?;
        Kdf::from_prelogin(
            prelogin.kdf,
            prelogin.kdf_iterations,
            prelogin.kdf_memory,
            prelogin.kdf_parallelism,
        )
        .map_err(|e| ApiError::Other(e.to_string()))
    }

    /// Log in with the master password hash, and a second step when the
    /// account wants one. Without the right one the answer is
    /// [`ApiError::TwoFactor`], saying which steps the account has.
    pub fn login(
        &self,
        email: &str,
        password_hash: &str,
        device_id: &str,
        second: Option<SecondFactor<'_>>,
    ) -> Result<Tokens, ApiError> {
        let device_name = format!("Vord on {}", hostname());
        let mut form = vec![
            ("grant_type", "password".to_string()),
            ("username", email.trim().to_string()),
            ("password", password_hash.to_string()),
            ("scope", "api offline_access".to_string()),
            ("client_id", CLIENT_ID.to_string()),
            ("deviceType", DEVICE_TYPE.to_string()),
            ("deviceIdentifier", device_id.to_string()),
            ("deviceName", device_name),
        ];
        let (provider, token, remember) = match second {
            Some(SecondFactor::Code {
                method: TwoFactorMethod::NewDevice,
                code,
                ..
            }) => {
                form.push(("newDeviceOtp", code.to_string()));
                (None, None, false)
            }
            Some(SecondFactor::Code {
                method,
                code,
                remember,
            }) => (method.id(), Some(code), remember),
            Some(SecondFactor::Remembered(token)) => (Some(REMEMBER), Some(token), false),
            None => (None, None, false),
        };
        if let (Some(provider), Some(token)) = (provider, token) {
            form.push(("twoFactorProvider", provider.to_string()));
            form.push(("twoFactorToken", token.to_string()));
            form.push(("twoFactorRemember", u8::from(remember).to_string()));
        }
        let response = self
            .http
            .post(self.url("/identity/connect/token"))
            .header(
                "Auth-Email",
                base64::Engine::encode(
                    &base64::engine::general_purpose::URL_SAFE_NO_PAD,
                    email.trim(),
                ),
            )
            .form(&form)
            .send()
            .map_err(network)?;
        let (status, body) = Self::read(response)?;
        if !status.is_success() {
            if let Some(challenge) = TwoFactorChallenge::from_body(&body) {
                return Err(ApiError::TwoFactor(challenge));
            }
            return Err(error_from(status, &body));
        }
        serde_json::from_value(body)
            .map_err(|e| ApiError::Network(format!("unexpected login answer: {e}")))
    }

    /// Ask the server to email a login code. The master password hash
    /// proves the request comes from someone who has the password.
    pub fn send_email_code(
        &self,
        email: &str,
        password_hash: &str,
        device_id: &str,
    ) -> Result<(), ApiError> {
        let response = self
            .http
            .post(self.url("/api/two-factor/send-email-login"))
            .json(&serde_json::json!({
                "email": email.trim(),
                "masterPasswordHash": password_hash,
                "deviceIdentifier": device_id,
            }))
            .send()
            .map_err(network)?;
        let (status, body) = Self::read(response)?;
        if status.is_success() {
            Ok(())
        } else {
            Err(error_from(status, &body))
        }
    }

    /// Ask bitwarden.com to email a new device's code again. The code is
    /// tied to the device, which the server reads from a header.
    pub fn send_new_device_code(
        &self,
        email: &str,
        password_hash: &str,
        device_id: &str,
    ) -> Result<(), ApiError> {
        let response = self
            .http
            .post(self.url("/api/accounts/resend-new-device-otp"))
            .header("Device-Identifier", device_id)
            .json(&serde_json::json!({
                "email": email.trim(),
                "masterPasswordHash": password_hash,
            }))
            .send()
            .map_err(network)?;
        let (status, body) = Self::read(response)?;
        if status.is_success() {
            Ok(())
        } else {
            Err(error_from(status, &body))
        }
    }

    /// Trade the refresh token for a new access token.
    pub fn refresh(&self, refresh_token: &str) -> Result<Tokens, ApiError> {
        let form = [
            ("grant_type", "refresh_token"),
            ("client_id", CLIENT_ID),
            ("refresh_token", refresh_token),
        ];
        let response = self
            .http
            .post(self.url("/identity/connect/token"))
            .form(&form)
            .send()
            .map_err(network)?;
        let (status, body) = Self::read(response)?;
        match status.as_u16() {
            200..=299 => serde_json::from_value(body)
                .map_err(|e| ApiError::Network(format!("unexpected refresh answer: {e}"))),
            400 | 401 => Err(ApiError::SessionExpired),
            _ => Err(error_from(status, &body)),
        }
    }

    /// The whole vault, still encrypted, keys in camelCase.
    pub fn sync(&self, access_token: &str) -> Result<Value, ApiError> {
        let response = self
            .http
            .get(self.url("/api/sync?excludeDomains=true"))
            .bearer_auth(access_token)
            .send()
            .map_err(network)?;
        let (status, body) = Self::read(response)?;
        match status.as_u16() {
            200..=299 => Ok(body),
            401 => Err(ApiError::SessionExpired),
            _ => Err(error_from(status, &body)),
        }
    }

    /// Any other API call, with a JSON body or none. An empty answer is
    /// `Null`.
    pub fn call(
        &self,
        method: reqwest::Method,
        path: &str,
        access_token: &str,
        body: Option<&Value>,
    ) -> Result<Value, ApiError> {
        let mut request = self
            .http
            .request(method, self.url(path))
            .bearer_auth(access_token);
        if let Some(body) = body {
            request = request.json(body);
        }
        let (status, body) = Self::read(request.send().map_err(network)?)?;
        match status.as_u16() {
            200..=299 => Ok(body),
            401 => Err(ApiError::SessionExpired),
            _ => Err(error_from(status, &body)),
        }
    }

    /// Upload a file in a multipart form, as a field called `data`.
    pub fn upload(
        &self,
        path: &str,
        access_token: &str,
        file_name: &str,
        data: Vec<u8>,
    ) -> Result<(), ApiError> {
        let part = reqwest::blocking::multipart::Part::bytes(data)
            .file_name(file_name.to_string())
            .mime_str("application/octet-stream")
            .expect("a valid type");
        let form = reqwest::blocking::multipart::Form::new().part("data", part);
        let response = self
            .http
            .post(self.url(path))
            .bearer_auth(access_token)
            .multipart(form)
            .timeout(TRANSFER)
            .send()
            .map_err(network)?;
        let (status, body) = Self::read(response)?;
        match status.as_u16() {
            200..=299 => Ok(()),
            401 => Err(ApiError::SessionExpired),
            _ => Err(error_from(status, &body)),
        }
    }

    /// Put a file to the blob storage bitwarden.com hands out (Azure); the
    /// URL carries its own permission, so no token goes with it.
    pub fn put_blob(&self, url: &str, data: Vec<u8>) -> Result<(), ApiError> {
        let response = self
            .http
            .put(url)
            .header("x-ms-blob-type", "BlockBlob")
            .header("x-ms-version", "2020-04-08")
            .body(data)
            .timeout(TRANSFER)
            .send()
            .map_err(network)?;
        if response.status().is_success() {
            Ok(())
        } else {
            Err(ApiError::Other(format!(
                "The file store answered {}.",
                response.status()
            )))
        }
    }

    /// Fetch a file from the address the server gave for it. It's on the
    /// server, or on a file store whose URL carries its own permission, so
    /// no token goes with it.
    pub fn fetch(&self, url: &str) -> Result<Vec<u8>, ApiError> {
        let url = if url.starts_with('/') {
            self.url(url)
        } else {
            url.to_string()
        };
        let response = self
            .http
            .get(url)
            .timeout(TRANSFER)
            .send()
            .map_err(network)?;
        if !response.status().is_success() {
            return Err(ApiError::Other(format!(
                "The file couldn't be fetched ({}).",
                response.status()
            )));
        }
        response
            .bytes()
            .map(|b| b.to_vec())
            .map_err(|e| ApiError::Network(e.to_string()))
    }

    /// A website's icon from the server's icon service. `None` when it has
    /// none.
    pub fn icon(&self, host: &str) -> Option<Vec<u8>> {
        let response = self
            .http
            .get(self.url(&format!("/icons/{host}/icon.png")))
            .timeout(Duration::from_secs(10))
            .send()
            .ok()?;
        if !response.status().is_success() {
            return None;
        }
        let bytes = response.bytes().ok()?;
        (!bytes.is_empty() && bytes.len() < 512 * 1024).then(|| bytes.to_vec())
    }
}

fn network(error: reqwest::Error) -> ApiError {
    let mut message = error.to_string();
    let mut source = std::error::Error::source(&error);
    while let Some(inner) = source {
        message = format!("{message}: {inner}");
        source = inner.source();
    }
    ApiError::Network(message)
}

/// The server's own words for a failure, wherever it put them.
fn error_from(status: reqwest::StatusCode, body: &Value) -> ApiError {
    let message = body
        .pointer("/errorModel/message")
        .or_else(|| body.get("message"))
        .or_else(|| body.get("error_description"))
        .or_else(|| body.get("error"))
        .and_then(Value::as_str)
        .map(str::to_string);
    match (status.as_u16(), message) {
        (400 | 401, Some(message)) => ApiError::Rejected(message),
        (_, Some(message)) => ApiError::Other(format!("{message} ({status})")),
        (404, None) => {
            ApiError::Network("the server has no Bitwarden API at this address (404)".into())
        }
        (_, None) => ApiError::Other(format!("The server answered {status}.")),
    }
}

fn hostname() -> String {
    std::fs::read_to_string("/etc/hostname")
        .ok()
        .map(|name| name.trim().to_string())
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| "Linux".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn camel_cases_keys_deeply() {
        let value = camel(serde_json::json!({
            "Profile": { "Key": "k", "Organizations": [{ "Id": 1 }] },
            "access_token": "x",
            "": 0
        }));
        assert_eq!(value["profile"]["key"], "k");
        assert_eq!(value["profile"]["organizations"][0]["id"], 1);
        assert_eq!(value["access_token"], "x");
    }

    #[test]
    fn server_addresses() {
        assert_eq!(
            normalize_server(" vault.example.com/ ").unwrap(),
            "https://vault.example.com"
        );
        assert_eq!(
            normalize_server("https://example.com/vw/").unwrap(),
            "https://example.com/vw"
        );
        assert_eq!(
            normalize_server("http://localhost:8222").unwrap(),
            "http://localhost:8222"
        );
        assert!(normalize_server("http://vault.example.com").is_err());
        assert!(normalize_server("").is_err());
        assert!(normalize_server("ftp://x").is_err());
    }

    #[test]
    fn two_factor_challenges() {
        // Vaultwarden: ids as strings, details per id, PascalCase.
        let body = camel(serde_json::json!({
            "error": "invalid_grant",
            "error_description": "Two factor required.",
            "TwoFactorProviders": ["0", "1", "7"],
            "TwoFactorProviders2": { "0": null, "1": { "Email": "t***@vord.test" }, "7": {} }
        }));
        let challenge = TwoFactorChallenge::from_body(&body).unwrap();
        assert_eq!(
            challenge.methods,
            [TwoFactorMethod::Authenticator, TwoFactorMethod::Email]
        );
        assert_eq!(challenge.unsupported, ["a security key (FIDO2)"]);
        assert_eq!(challenge.email_hint.as_deref(), Some("t***@vord.test"));
        assert_eq!(challenge.offered, 3);

        // A bare list of numbers; Duo twice is named once.
        let body = serde_json::json!({ "twoFactorProviders": [2, 6, 3] });
        let challenge = TwoFactorChallenge::from_body(&body).unwrap();
        assert_eq!(challenge.methods, [TwoFactorMethod::YubiKey]);
        assert_eq!(challenge.unsupported, ["Duo"]);

        let wrong_password = serde_json::json!({ "error": "invalid_grant" });
        assert_eq!(TwoFactorChallenge::from_body(&wrong_password), None);

        // bitwarden.com wants the code it emailed to a new device.
        let body = camel(serde_json::json!({
            "error": "device_error",
            "error_description": "New device verification required",
            "ErrorModel": { "Message": "new device verification required", "Object": "error" }
        }));
        let challenge = TwoFactorChallenge::from_body(&body).unwrap();
        assert_eq!(challenge.methods, [TwoFactorMethod::NewDevice]);
        assert_eq!(challenge.offered, 1);

        // A wrong code is just refused.
        let body = camel(serde_json::json!({
            "error": "device_error",
            "error_description": "Invalid New Device OTP",
            "ErrorModel": { "Message": "invalid new device otp" }
        }));
        assert_eq!(TwoFactorChallenge::from_body(&body), None);
    }

    #[test]
    fn server_errors_are_read_in_any_case() {
        let body = camel(serde_json::json!({
            "error": "invalid_grant",
            "ErrorModel": { "Message": "Username or password is incorrect. Try again" }
        }));
        let error = error_from(reqwest::StatusCode::BAD_REQUEST, &body);
        assert_eq!(
            error.to_string(),
            "Username or password is incorrect. Try again"
        );
    }
}
