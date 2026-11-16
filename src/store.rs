//! What Vord keeps on disk, under `$XDG_DATA_HOME/vord` (mode 0700):
//!
//! - `account.json`: the server, the email, the KDF settings, this device's
//!   id, the refresh token, and the user key and private key exactly as the
//!   server sent them (encrypted; only the master password opens them).
//! - `vault.json`: the last sync, as the server sent it. Every name and
//!   secret in it is still encrypted.
//!
//! Nothing decrypted is ever written. This is what the official desktop app
//! keeps too, and it is what lets Vord unlock without the network.

use crate::crypto::Kdf;
use serde::{Deserialize, Serialize};
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

/// Log out: forget the account and the cached vault. Settings and the icon
/// cache stay.
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
}
