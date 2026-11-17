//! What Vord keeps on disk, under `$XDG_DATA_HOME/vord` (mode 0700):
//!
//! - `account.json`: the server, the email, the KDF settings, this device's
//!   id, the refresh token, and the user key and private key exactly as the
//!   server sent them (encrypted; only the master password opens them).
//! - `vault.json`: the last sync, as the server sent it. Every name and
//!   secret in it is still encrypted.
//! - `device.json`: this device's id and, per account, the token that lets
//!   a remembered device skip two-step login. It outlives logging out, as
//!   the official apps' do: the server ties the token to the device id, and
//!   a new id each login would read as a new device.
//!
//! Nothing decrypted is ever written. This is what the official desktop app
//! keeps too, and it is what lets Vord unlock without the network.

use crate::crypto::Kdf;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

#[derive(Clone, Serialize, Deserialize)]
pub struct Account {
    pub server: String,
    pub email: String,
    pub kdf: Kdf,
    pub device_id: String,
    pub refresh_token: Option<String>,
    #[serde(default)]
    pub access_token: Option<String>,
    /// Unix seconds when the access token stops working.
    #[serde(default)]
    pub access_expires: u64,
    /// The user key, encrypted with the stretched master key.
    pub user_key: String,
    /// The RSA private key, encrypted with the user key.
    pub private_key: Option<String>,
}

impl std::fmt::Debug for Account {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Account")
            .field("server", &self.server)
            .field("email", &self.email)
            .field("kdf", &self.kdf)
            .finish_non_exhaustive()
    }
}

/// Where the files live. `VORD_DATA_DIR` overrides it, for tests and for a
/// throwaway profile.
pub fn dir() -> PathBuf {
    if let Some(dir) = std::env::var_os("VORD_DATA_DIR") {
        return PathBuf::from(dir);
    }
    directories::ProjectDirs::from("io.github", "turbinebmw", "vord")
        .map(|dirs| dirs.data_dir().to_path_buf())
        .unwrap_or_else(|| PathBuf::from(".vord"))
}

fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(parent)?;
    }
    // Write beside and rename, so a crash never leaves half a file.
    let tmp = path.with_extension("tmp");
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&tmp)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    fs::rename(tmp, path)
}

impl Account {
    pub fn load_from(dir: &Path) -> Option<Self> {
        let bytes = fs::read(dir.join("account.json")).ok()?;
        match serde_json::from_slice(&bytes) {
            Ok(account) => Some(account),
            Err(error) => {
                log::warn!("ignoring unreadable account.json: {error}");
                None
            }
        }
    }

    pub fn load() -> Option<Self> {
        Self::load_from(&dir())
    }

    pub fn save_to(&self, dir: &Path) -> std::io::Result<()> {
        let bytes = serde_json::to_vec_pretty(self).expect("serialisable");
        write_private(&dir.join("account.json"), &bytes)
    }

    pub fn save(&self) {
        if let Err(error) = self.save_to(&dir()) {
            log::error!("could not save the account to {}: {error}", dir().display());
        }
    }
}

/// This device, as the server knows it. No `Debug`: it holds tokens.
#[derive(Default, Serialize, Deserialize)]
struct Device {
    id: String,
    /// Remembered-device tokens, by [`remember_key`].
    #[serde(default)]
    remember: BTreeMap<String, String>,
}

impl Device {
    fn load_from(dir: &Path) -> Option<Self> {
        let bytes = fs::read(dir.join("device.json")).ok()?;
        serde_json::from_slice::<Self>(&bytes)
            .ok()
            .filter(|d| !d.id.is_empty())
    }

    /// The device, made the first time. An account logged in before
    /// `device.json` existed lends it its id.
    fn get_from(dir: &Path) -> Self {
        Self::load_from(dir).unwrap_or_else(|| {
            let id = Account::load_from(dir)
                .map(|a| a.device_id)
                .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
            let device = Self {
                id,
                remember: BTreeMap::new(),
            };
            device.save_to(dir);
            device
        })
    }

    fn save_to(&self, dir: &Path) {
        let bytes = serde_json::to_vec_pretty(self).expect("serialisable");
        if let Err(error) = write_private(&dir.join("device.json"), &bytes) {
            log::error!("could not save device.json: {error}");
        }
    }
}

fn remember_key(server: &str, email: &str) -> String {
    format!("{} on {server}", email.trim().to_lowercase())
}

/// This device's id, the same across logins.
pub fn device_id() -> String {
    Device::get_from(&dir()).id
}

/// The token that skips two-step login for this account, if it has one.
pub fn remembered_two_factor(server: &str, email: &str) -> Option<String> {
    Device::load_from(&dir())?
        .remember
        .get(&remember_key(server, email))
        .cloned()
}

/// Keep (`Some`) or drop (`None`) the account's remembered-device token.
pub fn set_remembered_two_factor(server: &str, email: &str, token: Option<String>) {
    let dir = dir();
    let mut device = Device::get_from(&dir);
    let key = remember_key(server, email);
    let changed = match token {
        Some(token) => device.remember.insert(key, token.clone()) != Some(token),
        None => device.remember.remove(&key).is_some(),
    };
    if changed {
        device.save_to(&dir);
    }
}

/// The last sync, still encrypted.
pub fn load_vault() -> Option<serde_json::Value> {
    let bytes = fs::read(dir().join("vault.json")).ok()?;
    serde_json::from_slice(&bytes).ok()
}

pub fn save_vault(sync: &serde_json::Value) {
    let bytes = serde_json::to_vec(sync).expect("serialisable");
    if let Err(error) = write_private(&dir().join("vault.json"), &bytes) {
        log::error!("could not save the vault cache: {error}");
    }
}

/// Log out: forget the account and the cached vault. Settings, the icon
/// cache and the device (see the module notes) stay.
pub fn forget() {
    for name in ["account.json", "vault.json"] {
        let path = dir().join(name);
        if let Err(error) = fs::remove_file(&path) {
            if error.kind() != std::io::ErrorKind::NotFound {
                log::warn!("could not remove {}: {error}", path.display());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn account_round_trips_privately() {
        let dir = tempfile::tempdir().unwrap();
        let dir = dir.path().join("vord");
        let account = Account {
            server: "https://vault.example.com".into(),
            email: "me@example.com".into(),
            kdf: Kdf::Argon2id {
                iterations: 3,
                memory_mib: 64,
                parallelism: 4,
            },
            device_id: "d".into(),
            refresh_token: Some("r".into()),
            access_token: None,
            access_expires: 0,
            user_key: "2.a|b|c".into(),
            private_key: None,
        };
        account.save_to(&dir).unwrap();
        let mode = fs::metadata(dir.join("account.json"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
        let mode = fs::metadata(&dir).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o700);
        let loaded = Account::load_from(&dir).unwrap();
        assert_eq!(loaded.kdf, account.kdf);
        assert_eq!(loaded.refresh_token.as_deref(), Some("r"));
        assert!(!format!("{loaded:?}").contains("2.a|b|c"));
    }

    #[test]
    fn device_keeps_its_id_and_tokens() {
        let dir = tempfile::tempdir().unwrap();
        let dir = dir.path().join("vord");
        let id = Device::get_from(&dir).id;
        assert_eq!(Device::get_from(&dir).id, id);

        let mut device = Device::get_from(&dir);
        device.remember.insert(
            remember_key("https://v.example", " Me@Example.com"),
            "t".into(),
        );
        device.save_to(&dir);
        let loaded = Device::load_from(&dir).unwrap();
        assert_eq!(loaded.id, id);
        assert_eq!(
            loaded
                .remember
                .get(&remember_key("https://v.example", "me@example.com")),
            Some(&"t".to_string())
        );
        let mode = fs::metadata(dir.join("device.json"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[test]
    fn device_adopts_an_existing_accounts_id() {
        let dir = tempfile::tempdir().unwrap();
        let account = Account {
            server: "https://v.example".into(),
            email: "me@example.com".into(),
            kdf: Kdf::Pbkdf2 {
                iterations: 600_000,
            },
            device_id: "older-id".into(),
            refresh_token: None,
            access_token: None,
            access_expires: 0,
            user_key: String::new(),
            private_key: None,
        };
        account.save_to(dir.path()).unwrap();
        assert_eq!(Device::get_from(dir.path()).id, "older-id");
    }
}
