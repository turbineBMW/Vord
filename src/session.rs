//! Logging in, unlocking and syncing, without any UI. Every function here
//! blocks (key derivation, network) and runs on a worker thread.

use crate::api::{ApiError, Client};
use crate::crypto::{CryptoError, EncString, MasterKey, SymmetricKey};
use crate::store::{self, Account};
use crate::vault::{Keys, Vault};
use serde_json::Value;
use std::time::{SystemTime, UNIX_EPOCH};

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

#[derive(Debug)]
pub enum Error {
    WrongPassword,
    Api(ApiError),
    Crypto(CryptoError),
    Other(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::WrongPassword => f.write_str("Wrong master password."),
            Self::Api(error) => error.fmt(f),
            Self::Crypto(error) => write!(f, "Could not open the vault: {error}"),
            Self::Other(why) => f.write_str(why),
        }
    }
}

impl From<ApiError> for Error {
    fn from(error: ApiError) -> Self {
        Self::Api(error)
    }
}

impl From<CryptoError> for Error {
    fn from(error: CryptoError) -> Self {
        Self::Crypto(error)
    }
}

/// The unlocked state: the keys, and the vault they opened.
pub struct Unlocked {
    pub keys: Keys,
    pub vault: Vault,
}

/// Open the stored user key with the master password. Works offline.
pub fn unlock_key(account: &Account, password: &str) -> Result<SymmetricKey, Error> {
    let master = MasterKey::derive(password, &account.email, account.kdf)?;
    let protected: EncString = account.user_key.parse()?;
    master
        .open_user_key(&protected)
        .map_err(|error| match error {
            CryptoError::Mac | CryptoError::Decrypt => Error::WrongPassword,
            other => Error::Crypto(other),
        })
}

/// Open the cached vault with a user key. `None` when there is no cache yet.
pub fn open_cached(account: &Account, user_key: SymmetricKey) -> (Keys, Option<Vault>) {
    let cache = store::load_vault();
    let keys = Keys::new(
        user_key,
        cache.as_ref().unwrap_or(&Value::Null),
        account.private_key.as_deref(),
    );
    let vault = cache.map(|sync| Vault::open(&sync, &keys));
    (keys, vault)
}

/// Log in for the first time: prelogin, derive, authenticate. Saves the
/// account and returns it with the opened user key.
pub fn login(server: &str, email: &str, password: &str) -> Result<(Account, SymmetricKey), Error> {
    let client = Client::new(server);
    let kdf = client.prelogin(email)?;
    let master = MasterKey::derive(password, email, kdf)?;
    let device_id = Account::load()
        .filter(|a| a.server == server)
        .map(|a| a.device_id)
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
    let tokens = client.login(email, &master.password_hash(password), &device_id)?;
    let user_key_text = tokens.key.ok_or_else(|| {
        Error::Other(
            "The server sent no vault key. Accounts that sign in with SSO or Key Connector are not supported."
                .into(),
        )
    })?;
    let user_key = master.open_user_key(&user_key_text.parse()?)?;
    let account = Account {
        server: server.to_string(),
        email: email.trim().to_string(),
        kdf,
        device_id,
        refresh_token: tokens.refresh_token,
        access_token: Some(tokens.access_token),
        access_expires: now() + tokens.expires_in,
        user_key: user_key_text,
        private_key: tokens.private_key,
    };
    // A different account's cache must not be shown under this one.
    store::forget();
    account.save();
    Ok((account, user_key))
}

/// A usable access token, refreshing it first when it's about to expire.
fn access_token(client: &Client, account: &mut Account, force: bool) -> Result<String, Error> {
    if !force && account.access_expires > now() + 60 {
        if let Some(token) = &account.access_token {
            return Ok(token.clone());
        }
    }
    let refresh = account
        .refresh_token
        .clone()
        .ok_or(Error::Api(ApiError::SessionExpired))?;
    let tokens = client.refresh(&refresh)?;
    account.access_token = Some(tokens.access_token.clone());
    account.access_expires = now() + tokens.expires_in;
    if let Some(refresh) = tokens.refresh_token {
        account.refresh_token = Some(refresh);
    }
    Ok(tokens.access_token)
}

/// Fetch the vault, still encrypted, and keep it. Returns the updated
/// account (new tokens, a changed user key) for the caller to hold.
pub fn sync(mut account: Account) -> Result<(Account, Value), Error> {
    let client = Client::new(&account.server);
    let token = access_token(&client, &mut account, false)?;
    let sync = match client.sync(&token) {
        Err(ApiError::SessionExpired) => {
            let token = access_token(&client, &mut account, true)?;
            client.sync(&token)?
        }
        other => other?,
    };
    if let Some(key) = sync.pointer("/profile/key").and_then(Value::as_str) {
        account.user_key = key.to_string();
    }
    if let Some(key) = sync.pointer("/profile/privateKey").and_then(Value::as_str) {
        account.private_key = Some(key.to_string());
    }
    account.save();
    store::save_vault(&sync);
    Ok((account, sync))
}

/// Open a fresh sync with the user key in hand.
pub fn open_sync(account: &Account, user_key: SymmetricKey, sync: &Value) -> Unlocked {
    let keys = Keys::new(user_key, sync, account.private_key.as_deref());
    let vault = Vault::open(sync, &keys);
    Unlocked { keys, vault }
}
