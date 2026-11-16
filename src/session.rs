//! Logging in, unlocking and syncing, without any UI. Every function here
//! blocks (key derivation, network) and runs on a worker thread.

use crate::api::{ApiError, Client, SecondFactor, TwoFactorMethod};
use crate::crypto::{CryptoError, EncString, Kdf, MasterKey, SymmetricKey};
use crate::store::{self, Account};
use crate::vault::{Keys, Vault};
use serde_json::Value;
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::Zeroizing;

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

/// How a login went: done, or waiting for its second step.
pub enum Login {
    Done(Account, SymmetricKey),
    SecondStep(PendingLogin),
}

/// A login that has passed the password and waits for a second step. It
/// holds what the retry needs, so the password isn't derived again; the
/// master key and its hash are zeroed when it's dropped.
pub struct PendingLogin {
    server: String,
    email: String,
    kdf: Kdf,
    master: MasterKey,
    password_hash: Zeroizing<String>,
    device_id: String,
    /// The steps the account offers that Vord can answer, most preferred
    /// first. Never empty.
    pub methods: Vec<TwoFactorMethod>,
    /// The masked address email codes go to.
    pub email_hint: Option<String>,
    /// Whether the server emailed a code on its own (it does when email is
    /// the account's only second step).
    pub email_sent: bool,
}

impl std::fmt::Debug for PendingLogin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PendingLogin")
            .field("server", &self.server)
            .field("email", &self.email)
            .field("methods", &self.methods)
            .finish_non_exhaustive()
    }
}

impl PendingLogin {
    pub fn email(&self) -> &str {
        &self.email
    }

    pub fn server(&self) -> &str {
        &self.server
    }
}

/// Log in for the first time: prelogin, derive, authenticate, with a
/// remembered device's token if this account has one. Saves the account
/// once the server lets it in.
pub fn login(server: &str, email: &str, password: &str) -> Result<Login, Error> {
    let client = Client::new(server);
    let kdf = client.prelogin(email)?;
    let master = MasterKey::derive(password, email, kdf)?;
    let password_hash = Zeroizing::new(master.password_hash(password));
    let device_id = store::device_id();
    let remembered = store::remembered_two_factor(server, email);
    let second = remembered.as_deref().map(SecondFactor::Remembered);
    match client.login(email, &password_hash, &device_id, second) {
        Ok(tokens) => {
            let (account, user_key) = finish(server, email, kdf, &master, device_id, tokens)?;
            Ok(Login::Done(account, user_key))
        }
        Err(ApiError::TwoFactor(challenge)) => {
            if remembered.is_some() {
                log::info!("the remembered-device token was refused; asking for a code");
                store::set_remembered_two_factor(server, email, None);
            }
            if challenge.methods.is_empty() {
                let names = if challenge.unsupported.is_empty() {
                    "a method".to_string()
                } else {
                    challenge.unsupported.join(" or ")
                };
                return Err(Error::Other(format!(
                    "This account's two-step login uses {names}, which Vord can't do yet. \
                     Add an authenticator app or email as a second method in the web vault to log in here."
                )));
            }
            let email_sent =
                challenge.offered == 1 && challenge.methods == [TwoFactorMethod::Email];
            Ok(Login::SecondStep(PendingLogin {
                server: server.to_string(),
                email: email.trim().to_string(),
                kdf,
                master,
                password_hash,
                device_id,
                methods: challenge.methods,
                email_hint: challenge.email_hint,
                email_sent,
            }))
        }
        Err(error) => Err(error.into()),
    }
}

/// Finish a login with a code. On a wrong code the pending login stays
/// good for another try.
pub fn second_step(
    pending: &PendingLogin,
    method: TwoFactorMethod,
    code: &str,
    remember: bool,
) -> Result<(Account, SymmetricKey), Error> {
    let code: String = code.chars().filter(|c| !c.is_whitespace()).collect();
    if code.is_empty() {
        return Err(Error::Other("Enter the code.".into()));
    }
    let client = Client::new(&pending.server);
    let second = SecondFactor::Code {
        method,
        code: &code,
        remember,
    };
    let tokens = client
        .login(
            &pending.email,
            &pending.password_hash,
            &pending.device_id,
            Some(second),
        )
        .map_err(|error| match error {
            // Vaultwarden's words carry the server time and the caller's IP;
            // they go to the log. Some servers answer by asking again.
            ApiError::Rejected(_) | ApiError::TwoFactor(_) => {
                log::warn!("the server refused the code: {error}");
                Error::Other("That code wasn't accepted. Check it and try again.".into())
            }
            other => other.into(),
        })?;
    finish(
        &pending.server,
        &pending.email,
        pending.kdf,
        &pending.master,
        pending.device_id.clone(),
        tokens,
    )
}

/// Ask the server to email a login code.
pub fn send_email_code(pending: &PendingLogin) -> Result<(), Error> {
    Client::new(&pending.server).send_email_code(
        &pending.email,
        &pending.password_hash,
        &pending.device_id,
    )?;
    Ok(())
}

/// The server let us in: open the user key, save the account.
fn finish(
    server: &str,
    email: &str,
    kdf: Kdf,
    master: &MasterKey,
    device_id: String,
    tokens: crate::api::Tokens,
) -> Result<(Account, SymmetricKey), Error> {
    let user_key_text = tokens.key.ok_or_else(|| {
        Error::Other(
            "The server sent no vault key. Accounts that sign in with SSO or Key Connector are not supported."
                .into(),
        )
    })?;
    let user_key = master.open_user_key(&user_key_text.parse()?)?;
    if let Some(token) = tokens.two_factor_token {
        store::set_remembered_two_factor(server, email, Some(token));
    }
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
