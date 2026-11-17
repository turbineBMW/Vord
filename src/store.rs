//! What Vord keeps on disk, under `$XDG_DATA_HOME/vord` (mode 0700). Each
//! account has a directory of its own, `accounts/<id>/` (the id is made
//! from the server and the email), and `active` names the one in use:
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
//! - `pin.json`, when PIN unlock is on: the PIN encrypted with the user key
//!   and, only if the user chose to keep PIN unlock across restarts, the
//!   user key sealed with a key made from the PIN.
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

/// Most accounts kept at once, as Bitwarden's apps allow.
pub const MAX_ACCOUNTS: usize = 5;

impl Account {
    /// A short id from the server and the email: the account's directory.
    pub fn id(&self) -> String {
        use sha2::Digest;
        let key = format!("{}\n{}", self.server, self.email.trim().to_lowercase());
        let hash = sha2::Sha256::digest(key.as_bytes());
        hash[..8].iter().map(|b| format!("{b:02x}")).collect()
    }

    /// Where this account's files are.
    pub fn dir(&self) -> PathBuf {
        dir().join("accounts").join(self.id())
    }

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

    /// The account in use: the one `active` names, or else the first.
    pub fn load() -> Option<Self> {
        migrate();
        let active = fs::read_to_string(dir().join("active")).unwrap_or_default();
        let accounts = accounts();
        accounts
            .iter()
            .find(|a| a.id() == active.trim())
            .or(accounts.first())
            .cloned()
    }

    pub fn save_to(&self, dir: &Path) -> std::io::Result<()> {
        let bytes = serde_json::to_vec_pretty(self).expect("serialisable");
        write_private(&dir.join("account.json"), &bytes)
    }

    /// Whether the account is still kept (it hasn't been logged out of).
    pub fn exists(&self) -> bool {
        self.dir().join("account.json").exists()
    }

    /// Save a change to a kept account. A worker that finishes after its
    /// account was logged out of must not bring it back.
    pub fn save(&self) {
        if self.exists() {
            self.create();
        }
    }

    /// Keep a newly logged-in account.
    pub fn create(&self) {
        if let Err(error) = self.save_to(&self.dir()) {
            log::error!(
                "could not save the account to {}: {error}",
                self.dir().display()
            );
        }
    }

    /// Make this the account in use.
    pub fn set_active(&self) {
        if let Err(error) = write_private(&dir().join("active"), self.id().as_bytes()) {
            log::error!("could not save which account is in use: {error}");
        }
    }
}

/// Every account kept, by email.
pub fn accounts() -> Vec<Account> {
    migrate();
    let mut accounts: Vec<Account> = fs::read_dir(dir().join("accounts"))
        .map(|entries| {
            entries
                .flatten()
                .filter_map(|entry| Account::load_from(&entry.path()))
                .collect()
        })
        .unwrap_or_default();
    accounts.sort_by_key(|a| (a.email.to_lowercase(), a.server.clone()));
    accounts
}

/// Before accounts had directories of their own, the one account's files
/// sat at the top: move them into its directory.
fn migrate() {
    let top = dir();
    let Some(account) = Account::load_from(&top) else {
        return;
    };
    let into = account.dir();
    if let Err(error) = fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&into)
    {
        log::error!("could not make {}: {error}", into.display());
        return;
    }
    for name in ["vault.json", "pin.json", "account.json"] {
        match fs::rename(top.join(name), into.join(name)) {
            Err(error) if error.kind() != std::io::ErrorKind::NotFound => {
                log::error!("could not move {name}: {error}");
                return;
            }
            _ => {}
        }
    }
    account.set_active();
    log::info!("moved the account's files into {}", into.display());
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

/// The account's last sync, still encrypted.
pub fn load_vault(account: &Account) -> Option<serde_json::Value> {
    let bytes = fs::read(account.dir().join("vault.json")).ok()?;
    serde_json::from_slice(&bytes).ok()
}

fn write_vault(account: &Account, sync: &serde_json::Value) {
    if !account.exists() {
        return;
    }
    let bytes = serde_json::to_vec(sync).expect("serialisable");
    if let Err(error) = write_private(&account.dir().join("vault.json"), &bytes) {
        log::error!("could not save the vault cache: {error}");
    }
}

/// Bumped by every change Vord makes to the cache, so a sync that was on
/// the wire meanwhile doesn't put the old copy back.
static VAULT_GENERATION: std::sync::Mutex<u64> = std::sync::Mutex::new(0);

fn generation() -> std::sync::MutexGuard<'static, u64> {
    VAULT_GENERATION
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Read before a sync goes out; see [`save_synced_vault`].
pub fn vault_generation() -> u64 {
    *generation()
}

/// Keep a fresh sync, unless Vord changed the vault since `since` (then
/// the sync is already out of date: false).
pub fn save_synced_vault(account: &Account, sync: &serde_json::Value, since: u64) -> bool {
    let generation = generation();
    if *generation != since {
        return false;
    }
    write_vault(account, sync);
    true
}

/// Change the cached vault after a write the server accepted, and return
/// it as it now is.
pub fn update_vault(
    account: &Account,
    change: impl FnOnce(&mut serde_json::Value),
) -> serde_json::Value {
    let mut generation = generation();
    let mut sync = load_vault(account).unwrap_or_else(|| serde_json::json!({}));
    change(&mut sync);
    write_vault(account, &sync);
    *generation += 1;
    sync
}

/// PIN unlock's state, kept apart from `account.json` so a sync saving the
/// account can't undo a change to it.
#[derive(Clone, Default, Serialize, Deserialize)]
pub struct PinState {
    /// The PIN, encrypted with the user key: what turns PIN unlock back on
    /// after the master password. Present while PIN unlock is on.
    pub pin: Option<String>,
    /// The user key sealed with the PIN's key, kept across restarts.
    pub sealed: Option<String>,
    /// Whether the user chose to keep it across restarts; `sealed` can be
    /// gone meanwhile (too many wrong PINs) until the master password
    /// seals it again.
    #[serde(default)]
    pub keep: bool,
}

pub fn load_pin(account: &Account) -> PinState {
    fs::read(account.dir().join("pin.json"))
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .unwrap_or_default()
}

pub fn save_pin(account: &Account, state: &PinState) {
    if !account.exists() {
        return;
    }
    let path = account.dir().join("pin.json");
    let result = if state.pin.is_none() && state.sealed.is_none() {
        match fs::remove_file(&path) {
            Err(error) if error.kind() != std::io::ErrorKind::NotFound => Err(error),
            _ => Ok(()),
        }
    } else {
        write_private(
            &path,
            &serde_json::to_vec_pretty(state).expect("serialisable"),
        )
    };
    if let Err(error) = result {
        log::error!("could not save {}: {error}", path.display());
    }
}

/// Log out of an account: forget it, its cached vault and its PIN.
/// Other accounts, settings, the icon cache and the device (see the module
/// notes) stay.
pub fn forget(account: &Account) {
    let dir = account.dir();
    if let Err(error) = fs::remove_dir_all(&dir) {
        if error.kind() != std::io::ErrorKind::NotFound {
            log::warn!("could not remove {}: {error}", dir.display());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn account(email: &str) -> Account {
        Account {
            server: "https://vault.example.com".into(),
            email: email.into(),
            kdf: Kdf::Pbkdf2 { iterations: 1 },
            device_id: "d".into(),
            refresh_token: None,
            access_token: None,
            access_expires: 0,
            user_key: "2.a|b|c".into(),
            private_key: None,
        }
    }

    /// The one test that moves `VORD_DATA_DIR`; nothing else reads it.
    #[test]
    fn accounts_keep_apart_and_old_files_move_in() {
        let data = tempfile::tempdir().unwrap();
        std::env::set_var("VORD_DATA_DIR", data.path());
        // One account, as Vord kept it before accounts had directories.
        let old = account("Old@example.com");
        old.save_to(data.path()).unwrap();
        fs::write(data.path().join("vault.json"), b"{\"ciphers\":[]}").unwrap();
        assert_eq!(Account::load().unwrap().email, "Old@example.com");
        assert!(!data.path().join("account.json").exists());
        assert!(load_vault(&old).is_some());

        let new = account("new@example.com");
        new.create();
        new.set_active();
        update_vault(&new, |sync| sync["mine"] = serde_json::json!(true));
        assert_eq!(accounts().len(), 2);
        assert_eq!(Account::load().unwrap().id(), new.id());
        assert!(load_vault(&old).unwrap().get("mine").is_none());

        // Logged out of: gone, and a late save doesn't bring it back.
        forget(&new);
        new.save();
        update_vault(&new, |_| {});
        save_pin(
            &new,
            &PinState {
                pin: Some("p".into()),
                ..Default::default()
            },
        );
        assert!(!new.dir().exists());
        assert_eq!(accounts().len(), 1);
        assert_eq!(Account::load().unwrap().id(), old.id());
        assert_ne!(
            account("a@b.c").id(),
            Account {
                server: "https://other".into(),
                ..account("a@b.c")
            }
            .id()
        );
        assert_eq!(account("A@B.c ").id(), account("a@b.c").id());
    }

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
