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
    WrongPin,
    Api(ApiError),
    Crypto(CryptoError),
    Other(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::WrongPassword => f.write_str("Wrong master password."),
            Self::WrongPin => f.write_str("Wrong PIN."),
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

/// The key a PIN makes, as Bitwarden's apps make it: the account's KDF over
/// the PIN, salted with the email, stretched as a master key is.
fn pin_key(account: &Account, pin: &str) -> Result<SymmetricKey, Error> {
    Ok(MasterKey::derive(pin, &account.email, account.kdf)?.stretch())
}

/// Seal the user key with a PIN's key, for unlocking with the PIN.
pub fn seal_with_pin(
    account: &Account,
    pin: &str,
    user_key: &SymmetricKey,
) -> Result<String, Error> {
    Ok(pin_key(account, pin)?
        .encrypt(&user_key.to_bytes())
        .to_string())
}

/// After the master password: seal the user key again with the PIN kept
/// (encrypted with the user key) in `encrypted_pin`.
pub fn reseal_with_pin(
    account: &Account,
    encrypted_pin: &str,
    user_key: &SymmetricKey,
) -> Result<String, Error> {
    let pin = Zeroizing::new(encrypted_pin.parse::<EncString>()?.decrypt_text(user_key)?);
    seal_with_pin(account, &pin, user_key)
}

/// Open the user key with a PIN. A sealed key that opens but no longer
/// fits the account (its key was rotated elsewhere) is refused.
pub fn unlock_with_pin(account: &Account, sealed: &str, pin: &str) -> Result<SymmetricKey, Error> {
    let bytes = sealed
        .parse::<EncString>()?
        .decrypt(&pin_key(account, pin)?)
        .map_err(|error| match error {
            CryptoError::Mac | CryptoError::Decrypt => Error::WrongPin,
            other => Error::Crypto(other),
        })?;
    let user_key = SymmetricKey::from_bytes(&bytes)?;
    if let Some(private) = &account.private_key {
        if private.parse::<EncString>()?.decrypt(&user_key).is_err() {
            return Err(Error::Other(
                "The PIN no longer opens this vault. Unlock with the master password.".into(),
            ));
        }
    }
    Ok(user_key)
}

/// Open the cached vault with a user key. `None` when there is no cache yet.
pub fn open_cached(account: &Account, user_key: SymmetricKey) -> (Keys, Option<Vault>) {
    let cache = store::load_vault(account);
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
    /// the account's only second step, and for a new device's code).
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
            let new_device = challenge.methods == [TwoFactorMethod::NewDevice];
            let email_sent = new_device
                || challenge.offered == 1 && challenge.methods == [TwoFactorMethod::Email];
            // A new device's code goes to the account's own address.
            let email_hint = if new_device {
                Some(email.trim().to_string())
            } else {
                challenge.email_hint
            };
            Ok(Login::SecondStep(PendingLogin {
                server: server.to_string(),
                email: email.trim().to_string(),
                kdf,
                master,
                password_hash,
                device_id,
                methods: challenge.methods,
                email_hint,
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

/// Ask the server to email a login code (again, for a new device's code).
pub fn send_email_code(pending: &PendingLogin) -> Result<(), Error> {
    let client = Client::new(&pending.server);
    if pending.methods == [TwoFactorMethod::NewDevice] {
        client.send_new_device_code(&pending.email, &pending.password_hash, &pending.device_id)?;
    } else {
        client.send_email_code(&pending.email, &pending.password_hash, &pending.device_id)?;
    }
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
    // An earlier login's cache and PIN of this account start over.
    store::forget(&account);
    account.create();
    account.set_active();
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

/// Run an API call with a usable access token, refreshing it and trying
/// once more if the server says it has expired. The account's tokens are
/// saved when they change.
fn authed<T>(
    account: &mut Account,
    run: impl Fn(&Client, &str) -> Result<T, ApiError>,
) -> Result<T, Error> {
    let client = Client::new(&account.server);
    let before = account.access_token.clone();
    let token = access_token(&client, account, false)?;
    let result = match run(&client, &token) {
        Err(ApiError::SessionExpired) => {
            let token = access_token(&client, account, true)?;
            run(&client, &token)
        }
        other => other,
    };
    if account.access_token != before {
        account.save();
    }
    Ok(result?)
}

/// A usable access token for the notifications hub, refreshed if it's
/// about to expire. Returns the account, whose tokens may be new.
pub fn hub_token(mut account: Account) -> Result<(Account, String), Error> {
    let client = Client::new(&account.server);
    let before = account.access_token.clone();
    let token = access_token(&client, &mut account, false)?;
    if account.access_token != before {
        account.save();
    }
    Ok((account, token))
}

/// Fetch the vault, still encrypted, and keep it. Returns the updated
/// account (new tokens, a changed user key) for the caller to hold.
pub fn sync(mut account: Account) -> Result<(Account, Value), Error> {
    // A change Vord saves while the sync is on the wire makes the sync
    // stale before it lands; fetch again rather than keep it.
    let mut tries = 0;
    let sync = loop {
        let since = store::vault_generation();
        let sync = authed(&mut account, |client, token| client.sync(token))?;
        tries += 1;
        if store::save_synced_vault(&account, &sync, since) || tries == 3 {
            break sync;
        }
    };
    if let Some(key) = sync.pointer("/profile/key").and_then(Value::as_str) {
        account.user_key = key.to_string();
    }
    if let Some(key) = sync.pointer("/profile/privateKey").and_then(Value::as_str) {
        account.private_key = Some(key.to_string());
    }
    account.save();
    Ok((account, sync))
}

/// The time now, as Bitwarden writes it (ISO 8601, UTC).
pub fn now_iso() -> String {
    gtk::glib::DateTime::now_utc()
        .and_then(|t| t.format("%Y-%m-%dT%H:%M:%S.%fZ"))
        .map(|t| t.to_string())
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".into())
}

/// A change to the vault, already encrypted.
pub enum Change {
    /// Create (`id` is `None`) or update an item; the body comes from
    /// [`crate::edit::request`]. A new organization item goes into
    /// `collections`; a saved one moves to them when `move_collections`.
    SaveItem {
        id: Option<String>,
        body: Value,
        collections: Vec<String>,
        move_collections: bool,
    },
    /// Move a personal item into an organization's `collections`; the body
    /// is already encrypted for it ([`crate::edit::into_organization`]).
    Share {
        id: String,
        body: Value,
        collections: Vec<String>,
    },
    /// Favorite or not, which (like the folder) is the user's own and
    /// needs no re-encryption.
    Favorite {
        id: String,
        folder_id: Option<String>,
        favorite: bool,
    },
    Trash(String),
    Restore(String),
    /// Delete for good.
    Purge(String),
    /// Attach a file to an item: read, encrypted with a new key of its own
    /// (sealed with `item_key`) and uploaded, all on the worker.
    AddAttachment {
        id: String,
        path: std::path::PathBuf,
        item_key: SymmetricKey,
    },
    DeleteAttachment {
        id: String,
        attachment: String,
    },
    /// Create (`id` is `None`) or rename a folder; `name` is encrypted.
    SaveFolder {
        id: Option<String>,
        name: String,
    },
    DeleteFolder(String),
    /// Create (`id` is `None`) or update a Send; the body comes from
    /// [`crate::send::request`]. A new file Send's file is read, encrypted
    /// with the Send's key and uploaded on the worker.
    SaveSend {
        id: Option<String>,
        body: Value,
        file: Option<(std::path::PathBuf, SymmetricKey)>,
    },
    DeleteSend(String),
    RemoveSendPassword(String),
}

/// Create a file Send: make room for it, then upload the file. A Send
/// whose file didn't arrive is deleted again, as Bitwarden's apps do.
fn create_file_send(
    client: &Client,
    token: &str,
    body: &Value,
    path: &std::path::Path,
    key: &SymmetricKey,
) -> Result<Value, ApiError> {
    let plain = Zeroizing::new(
        std::fs::read(path)
            .map_err(|e| ApiError::Other(format!("Could not read the file: {e}")))?,
    );
    let data = key.encrypt_file(&plain);
    drop(plain);
    let file_name = body
        .pointer("/file/fileName")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let mut body = body.clone();
    body["fileLength"] = serde_json::json!(data.len());
    let slot = client.call(
        reqwest::Method::POST,
        "/api/sends/file/v2",
        token,
        Some(&body),
    )?;
    let send = slot
        .get("sendResponse")
        .cloned()
        .ok_or_else(|| ApiError::Other("The server didn't make room for the file.".into()))?;
    let (Some(id), Some(file_id)) = (
        send.get("id").and_then(Value::as_str),
        send.pointer("/file/id").and_then(Value::as_str),
    ) else {
        return Err(ApiError::Other(
            "The server didn't make room for the file.".into(),
        ));
    };
    // 0: straight to the server (Vaultwarden); 1: to Azure (bitwarden.com).
    // The server checks the upload's file name against the encrypted one.
    let uploaded = match slot.get("fileUploadType").and_then(Value::as_u64) {
        Some(1) => match slot.get("url").and_then(Value::as_str) {
            Some(url) => client.put_blob(url, data),
            None => Err(ApiError::Other(
                "The server gave no address for the file.".into(),
            )),
        },
        _ => client.upload(
            &format!("/api/sends/{id}/file/{file_id}"),
            token,
            &file_name,
            data,
        ),
    };
    if let Err(error) = uploaded {
        let _ = client.call(
            reqwest::Method::DELETE,
            &format!("/api/sends/{id}"),
            token,
            None,
        );
        return Err(error);
    }
    client.call(
        reqwest::Method::GET,
        &format!("/api/sends/{id}"),
        token,
        None,
    )
}

fn upload_attachment(
    client: &Client,
    token: &str,
    id: &str,
    path: &std::path::Path,
    item_key: &SymmetricKey,
) -> Result<(), ApiError> {
    let plain = Zeroizing::new(
        std::fs::read(path)
            .map_err(|e| ApiError::Other(format!("Could not read the file: {e}")))?,
    );
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "attachment".into());
    let key = SymmetricKey::generate();
    let data = key.encrypt_file(&plain);
    drop(plain);
    let file_name = item_key.encrypt_text(&name);
    let body = serde_json::json!({
        "key": item_key.encrypt(&key.to_bytes()).to_string(),
        "fileName": file_name,
        "fileSize": data.len(),
        "adminRequest": false,
    });
    let slot = client.call(
        reqwest::Method::POST,
        &format!("/api/ciphers/{id}/attachment/v2"),
        token,
        Some(&body),
    )?;
    let attachment = slot
        .get("attachmentId")
        .and_then(Value::as_str)
        .ok_or_else(|| ApiError::Other("The server didn't make room for the file.".into()))?;
    // 0: straight to the server (Vaultwarden); 1: to Azure (bitwarden.com).
    match slot.get("fileUploadType").and_then(Value::as_u64) {
        Some(1) => {
            let url = slot.get("url").and_then(Value::as_str).ok_or_else(|| {
                ApiError::Other("The server gave no address for the file.".into())
            })?;
            client.put_blob(url, data)
        }
        _ => client.upload(
            &format!("/api/ciphers/{id}/attachment/{attachment}"),
            token,
            &file_name,
            data,
        ),
    }
}

/// Fetch an attachment and decrypt it. `item_key` is the key the item's
/// fields are encrypted with ([`crate::edit::item_key`]).
pub fn download_attachment(
    mut account: Account,
    id: &str,
    attachment: &str,
    item_key: &SymmetricKey,
) -> Result<(Account, Zeroizing<Vec<u8>>), Error> {
    let (info, data) = authed(&mut account, |client, token| {
        let path = format!("/api/ciphers/{id}/attachment/{attachment}");
        let info = client.call(reqwest::Method::GET, &path, token, None)?;
        let url = info
            .get("url")
            .and_then(Value::as_str)
            .ok_or_else(|| ApiError::Other("The server gave no address for the file.".into()))?;
        let data = client.fetch(url)?;
        Ok((info, data))
    })?;
    // A file from an older app has no key of its own: the item's opens it.
    let key = match info
        .get("key")
        .and_then(Value::as_str)
        .filter(|k| !k.is_empty())
    {
        Some(sealed) => SymmetricKey::from_bytes(&sealed.parse::<EncString>()?.decrypt(item_key)?)?,
        None => item_key.clone(),
    };
    Ok((account, key.decrypt_file(&data)?))
}

/// What a change touched, for the view to select.
pub enum Touched {
    Item(String),
    Send(String),
    Nothing,
}

fn replace_by_id(list: &mut Value, id: &str, with: Option<Value>) {
    if !list.is_array() {
        *list = Value::Array(Vec::new());
    }
    let list = list.as_array_mut().expect("an array");
    let at = list
        .iter()
        .position(|v| v.get("id").and_then(Value::as_str) == Some(id));
    match (at, with) {
        (Some(i), Some(with)) => list[i] = with,
        (Some(i), None) => {
            list.remove(i);
        }
        (None, Some(with)) => list.push(with),
        (None, None) => {}
    }
}

fn id_of(value: &Value) -> Result<String, Error> {
    value
        .get("id")
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| Error::Other("The server's answer had no id.".into()))
}

/// Send a change, then fold the server's answer into the cached vault.
/// Returns the account (its tokens may be new), the vault as it now is,
/// and what changed.
pub fn change(mut account: Account, change: Change) -> Result<(Account, Value, Touched), Error> {
    use reqwest::Method;
    let result = authed(&mut account, |client, token| {
        let call = |method: Method, path: &str, body: Option<&Value>| {
            client.call(method, path, token, body)
        };
        Ok(match &change {
            Change::SaveItem {
                id: Some(id),
                body,
                collections,
                move_collections,
            } => {
                let saved = call(Method::PUT, &format!("/api/ciphers/{id}"), Some(body))?;
                Some(if *move_collections {
                    let body = serde_json::json!({ "collectionIds": collections });
                    call(
                        Method::PUT,
                        &format!("/api/ciphers/{id}/collections"),
                        Some(&body),
                    )?;
                    call(Method::GET, &format!("/api/ciphers/{id}"), None)?
                } else {
                    saved
                })
            }
            Change::Share {
                id,
                body,
                collections,
            } => {
                let wrapped = serde_json::json!({ "cipher": body, "collectionIds": collections });
                Some(call(
                    Method::PUT,
                    &format!("/api/ciphers/{id}/share"),
                    Some(&wrapped),
                )?)
            }
            Change::SaveItem {
                id: None,
                body,
                collections,
                ..
            } => Some(
                if body.get("organizationId").is_some_and(Value::is_string) {
                    let wrapped =
                        serde_json::json!({ "cipher": body, "collectionIds": collections });
                    call(Method::POST, "/api/ciphers/create", Some(&wrapped))?
                } else {
                    call(Method::POST, "/api/ciphers", Some(body))?
                },
            ),
            Change::Favorite {
                id,
                folder_id,
                favorite,
            } => {
                let body = serde_json::json!({ "folderId": folder_id, "favorite": favorite });
                Some(call(
                    Method::PUT,
                    &format!("/api/ciphers/{id}/partial"),
                    Some(&body),
                )?)
            }
            Change::Trash(id) => {
                call(Method::PUT, &format!("/api/ciphers/{id}/delete"), None)?;
                Some(call(Method::GET, &format!("/api/ciphers/{id}"), None)?)
            }
            Change::Restore(id) => Some(call(
                Method::PUT,
                &format!("/api/ciphers/{id}/restore"),
                None,
            )?),
            Change::Purge(id) => {
                call(Method::DELETE, &format!("/api/ciphers/{id}"), None)?;
                None
            }
            Change::SaveFolder { id, name } => {
                let body = serde_json::json!({ "name": name });
                Some(match id {
                    Some(id) => call(Method::PUT, &format!("/api/folders/{id}"), Some(&body))?,
                    None => call(Method::POST, "/api/folders", Some(&body))?,
                })
            }
            Change::DeleteFolder(id) => {
                call(Method::DELETE, &format!("/api/folders/{id}"), None)?;
                None
            }
            Change::AddAttachment { id, path, item_key } => {
                upload_attachment(client, token, id, path, item_key)?;
                Some(call(Method::GET, &format!("/api/ciphers/{id}"), None)?)
            }
            Change::DeleteAttachment { id, attachment } => {
                let path = format!("/api/ciphers/{id}/attachment/{attachment}");
                call(Method::DELETE, &path, None)?;
                Some(call(Method::GET, &format!("/api/ciphers/{id}"), None)?)
            }
            Change::SaveSend { id, body, file } => Some(match (id, file) {
                (Some(id), _) => call(Method::PUT, &format!("/api/sends/{id}"), Some(body))?,
                (None, Some((path, key))) => create_file_send(client, token, body, path, key)?,
                (None, None) => call(Method::POST, "/api/sends", Some(body))?,
            }),
            Change::DeleteSend(id) => {
                call(Method::DELETE, &format!("/api/sends/{id}"), None)?;
                None
            }
            Change::RemoveSendPassword(id) => Some(call(
                Method::PUT,
                &format!("/api/sends/{id}/remove-password"),
                None,
            )?),
        })
    })
    .map_err(|error| match error {
        // Vaultwarden: "The client copy of this cipher is out of date."
        Error::Api(ApiError::Rejected(why)) if why.contains("out of date") => Error::Other(
            "This item changed elsewhere since Vord last synced. Sync, then make the change again."
                .into(),
        ),
        other => other,
    })?;

    let touched = match (&change, &result) {
        (
            Change::SaveFolder { .. }
            | Change::DeleteFolder(_)
            | Change::Purge(_)
            | Change::DeleteSend(_),
            _,
        ) => Touched::Nothing,
        (Change::SaveSend { .. } | Change::RemoveSendPassword(_), Some(send)) => {
            Touched::Send(id_of(send)?)
        }
        (_, Some(cipher)) => Touched::Item(id_of(cipher)?),
        (_, None) => Touched::Nothing,
    };
    let sync = store::update_vault(&account, |sync| match (&change, result) {
        (Change::Purge(id), _) => replace_by_id(&mut sync["ciphers"], id, None),
        (Change::DeleteFolder(id), _) => {
            replace_by_id(&mut sync["folders"], id, None);
            // The server moves its items to No Folder; so does the copy.
            if let Some(ciphers) = sync["ciphers"].as_array_mut() {
                for cipher in ciphers {
                    if cipher.get("folderId").and_then(Value::as_str) == Some(id) {
                        cipher["folderId"] = Value::Null;
                    }
                }
            }
        }
        (Change::SaveFolder { .. }, Some(folder)) => {
            let id = folder["id"].as_str().unwrap_or_default().to_string();
            replace_by_id(&mut sync["folders"], &id, Some(folder));
        }
        (Change::DeleteSend(id), _) => replace_by_id(&mut sync["sends"], id, None),
        (Change::SaveSend { .. } | Change::RemoveSendPassword(_), Some(send)) => {
            let id = send["id"].as_str().unwrap_or_default().to_string();
            replace_by_id(&mut sync["sends"], &id, Some(send));
        }
        (_, Some(cipher)) => {
            let id = cipher["id"].as_str().unwrap_or_default().to_string();
            replace_by_id(&mut sync["ciphers"], &id, Some(cipher));
        }
        (_, None) => {}
    });
    Ok((account, sync, touched))
}

/// Check the master password again, as Bitwarden's apps do before an
/// export. Works offline.
pub fn check_master_password(account: &Account, password: &str) -> Result<(), Error> {
    unlock_key(account, password).map(|_| ())
}

/// Export the cached vault to `path`, readable only by the user. The one
/// place besides a saved attachment where Vord writes decrypted data, and
/// only where the user chose. `file_password` is for
/// [`crate::export::Format::PasswordJson`].
pub fn export(
    account: &Account,
    user_key: &SymmetricKey,
    format: crate::export::Format,
    file_password: &str,
    path: &std::path::Path,
) -> Result<(), Error> {
    use std::io::Write;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    let sync = store::load_vault(account)
        .ok_or_else(|| Error::Other("There's no synced vault to export yet.".into()))?;
    let data = crate::export::build(&sync, user_key, format, file_password, account.kdf)
        .map_err(|why| Error::Other(format!("Could not export the vault: {why}")))?;
    let written = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .and_then(|mut file| {
            // A file that was there keeps its old mode: tighten it first.
            file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
            file.write_all(data.as_bytes())?;
            file.sync_all()
        });
    written.map_err(|e| Error::Other(format!("Could not write the file: {e}")))
}

/// Open a fresh sync with the user key in hand.
pub fn open_sync(account: &Account, user_key: SymmetricKey, sync: &Value) -> Unlocked {
    let keys = Keys::new(user_key, sync, account.private_key.as_deref());
    let vault = Vault::open(sync, &keys);
    Unlocked { keys, vault }
}

/// Against the local test server from `tests/seed.js`, one run at a time:
/// `cargo test -- --ignored live_changes`.
#[cfg(test)]
mod live {
    use super::*;
    use crate::edit::{self, Draft};
    use crate::vault::Kind;

    fn open(account: &Account, user_key: &SymmetricKey, sync: &Value) -> Vault {
        open_sync(account, user_key.clone(), sync).vault
    }

    #[test]
    #[ignore]
    fn live_changes() {
        let dir = tempfile::tempdir().unwrap();
        std::env::set_var("VORD_DATA_DIR", dir.path());
        let Login::Done(account, user_key) = login(
            "http://localhost:8222",
            "test@vord.test",
            "vord test password 1",
        )
        .unwrap() else {
            panic!("the seeded account has no second step");
        };
        let (account, sync) = super::sync(account).unwrap();
        let vault = open(&account, &user_key, &sync);
        let saver = edit::Saver {
            user_id: vault.user_id.as_deref(),
            now: &now_iso(),
        };

        // A folder, renamed.
        let name = user_key.encrypt_text("Live test");
        let (account, sync, _) = change(account, Change::SaveFolder { id: None, name }).unwrap();
        let vault = open(&account, &user_key, &sync);
        let folder = vault
            .folders
            .iter()
            .find(|f| f.name == "Live test")
            .unwrap()
            .id
            .clone();
        let name = user_key.encrypt_text("Live test renamed");
        let change_folder = Change::SaveFolder {
            id: Some(folder.clone()),
            name,
        };
        let (account, sync, _) = change(account, change_folder).unwrap();
        let vault = open(&account, &user_key, &sync);
        assert!(vault.folders.iter().any(|f| f.name == "Live test renamed"));

        // A note in it, favorited.
        let mut draft = Draft::new(Kind::Note);
        draft.name = "Live note".to_string().into();
        draft.notes = "line one\nline two".to_string().into();
        draft.folder_id = Some(folder.clone());
        let body = edit::request(&draft, None, &user_key, &saver);
        let save = Change::SaveItem {
            id: None,
            body,
            collections: Vec::new(),
            move_collections: false,
        };
        let (account, sync, touched) = change(account, save).unwrap();
        let Touched::Item(id) = touched else {
            panic!("no item")
        };
        let favorite = Change::Favorite {
            id: id.clone(),
            folder_id: Some(folder.clone()),
            favorite: true,
        };
        let stale = open(&account, &user_key, &sync);
        let (account, sync, _) = change(account, favorite).unwrap();
        let vault = open(&account, &user_key, &sync);
        let note = vault.item(&id).unwrap();
        assert!(note.favorite && note.folder_id.as_deref() == Some(folder.as_str()));
        assert_eq!(
            note.notes.as_deref().map(String::as_str),
            Some("line one\nline two")
        );

        // An edit; then another from the copy before it is refused (the
        // server allows a second's slack).
        let edit_from = |vault: &Vault, name: &str| {
            let raw = vault.raw(&id).unwrap();
            let original = Draft::open(raw, &user_key).unwrap();
            let mut edited = original.clone();
            edited.name = name.to_string().into();
            let base = edit::Base {
                raw,
                original: &original,
            };
            Change::SaveItem {
                id: Some(id.clone()),
                body: edit::request(&edited, Some(base), &user_key, &saver),
                collections: Vec::new(),
                move_collections: false,
            }
        };
        std::thread::sleep(std::time::Duration::from_millis(2100));
        let (account, sync, _) = change(account, edit_from(&vault, "Live note 2")).unwrap();
        assert_eq!(
            open(&account, &user_key, &sync).item(&id).unwrap().name,
            "Live note 2"
        );
        let refused = change(account.clone(), edit_from(&stale, "From a stale copy"))
            .err()
            .unwrap();
        assert!(
            refused.to_string().contains("changed elsewhere"),
            "{refused}"
        );

        // Trash, restore, trash, delete for good.
        let (account, sync, _) = change(account, Change::Trash(id.clone())).unwrap();
        assert!(open(&account, &user_key, &sync).item(&id).unwrap().deleted);
        let (account, sync, _) = change(account, Change::Restore(id.clone())).unwrap();
        assert!(!open(&account, &user_key, &sync).item(&id).unwrap().deleted);
        let (account, _, _) = change(account, Change::Trash(id.clone())).unwrap();
        let (account, sync, _) = change(account, Change::Purge(id.clone())).unwrap();
        assert!(open(&account, &user_key, &sync).item(&id).is_none());

        // A personal login moves into the organization, then to another
        // of its collections.
        let unlocked = open_sync(&account, user_key.clone(), &sync);
        let family = unlocked
            .vault
            .organizations
            .iter()
            .find(|o| o.name == "Family")
            .unwrap();
        let org_key = unlocked.keys.orgs.get(&family.id).unwrap().clone();
        let first = unlocked
            .vault
            .collections
            .iter()
            .find(|c| c.org_id == family.id)
            .unwrap();
        let (first, family) = (first.id.clone(), family.id.clone());
        let mut account = account;
        let second = authed(&mut account, |client, token| {
            let body = serde_json::json!({
                "name": org_key.encrypt_text("Second"), "groups": [], "users": []
            });
            let path = format!("/api/organizations/{family}/collections");
            client.call(reqwest::Method::POST, &path, token, Some(&body))
        })
        .unwrap()["id"]
            .as_str()
            .unwrap()
            .to_string();
        let mut draft = Draft::new(Kind::Login);
        draft.name = "Moving login".to_string().into();
        draft.values[0] = "mover".to_string().into();
        draft.uris.push(edit::Uri {
            uri: "https://move.example".to_string().into(),
            origin: None,
        });
        let save = Change::SaveItem {
            id: None,
            body: edit::request(&draft, None, &user_key, &saver),
            collections: Vec::new(),
            move_collections: false,
        };
        let (account, sync, touched) = change(account, save).unwrap();
        let Touched::Item(id) = touched else {
            panic!("no item")
        };
        let raw = sync["ciphers"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["id"] == id.as_str())
            .unwrap()
            .clone();
        let original = Draft::open(&raw, &user_key).unwrap();
        let base = edit::Base {
            raw: &raw,
            original: &original,
        };
        let mut body = edit::request(&original, Some(base), &user_key, &saver);
        edit::into_organization(&mut body, &raw, &user_key, &family, &org_key).unwrap();
        let share = Change::Share {
            id: id.clone(),
            body,
            collections: vec![first.clone()],
        };
        let (account, sync, _) = change(account, share).unwrap();
        let unlocked = open_sync(&account, user_key.clone(), &sync);
        let moved = unlocked.vault.item(&id).unwrap();
        assert_eq!(moved.org_id.as_deref(), Some(family.as_str()));
        assert_eq!(moved.collection_ids, std::slice::from_ref(&first));
        assert!(!moved.damaged);
        assert_eq!(
            moved.login.as_ref().unwrap().uris[0].uri,
            "https://move.example"
        );

        let raw = unlocked.vault.raw(&id).unwrap().clone();
        let key = edit::item_key(&raw, &unlocked.keys).unwrap();
        let original = Draft::open(&raw, &key).unwrap();
        let base = edit::Base {
            raw: &raw,
            original: &original,
        };
        let save = Change::SaveItem {
            id: Some(id.clone()),
            body: edit::request(&original, Some(base), &key, &saver),
            collections: vec![second.clone()],
            move_collections: true,
        };
        let (account, sync, _) = change(account, save).unwrap();
        let vault = open(&account, &user_key, &sync);
        assert_eq!(vault.item(&id).unwrap().collection_ids, [second]);

        // An attachment: up, down again unchanged, deleted.
        let file = dir.path().join("receipt.txt");
        let contents = b"Vord attachment test\n".repeat(1000);
        std::fs::write(&file, &contents).unwrap();
        let unlocked = open_sync(&account, user_key.clone(), &sync);
        let raw = unlocked.vault.raw(&id).unwrap().clone();
        let item_key = edit::item_key(&raw, &unlocked.keys).unwrap();
        let add = Change::AddAttachment {
            id: id.clone(),
            path: file,
            item_key: item_key.clone(),
        };
        let (account, sync, _) = change(account, add).unwrap();
        let vault = open(&account, &user_key, &sync);
        let attached = &vault.item(&id).unwrap().attachments;
        assert_eq!(attached.len(), 1);
        assert_eq!(attached[0].name, "receipt.txt");
        let attachment = attached[0].id.clone();
        let (account, data) = download_attachment(account, &id, &attachment, &item_key).unwrap();
        assert_eq!(*data, contents);
        let delete = Change::DeleteAttachment {
            id: id.clone(),
            attachment,
        };
        let (account, sync, _) = change(account, delete).unwrap();
        assert!(open(&account, &user_key, &sync)
            .item(&id)
            .unwrap()
            .attachments
            .is_empty());

        // Files other apps made open (tests/seed.js puts one on GitHub);
        // one Vord makes stays on Router admin, to open in another client.
        let vault = open(&account, &user_key, &sync);
        let keys = open_sync(&account, user_key.clone(), &sync).keys;
        let github = vault.items.iter().find(|i| i.name == "GitHub").unwrap();
        let codes = github
            .attachments
            .iter()
            .find(|a| a.name == "recovery-codes.txt");
        let codes = codes.expect("tests/seed.js's attachment").id.clone();
        let github_key = edit::item_key(vault.raw(&github.id).unwrap(), &keys).unwrap();
        let (account, data) =
            download_attachment(account, &github.id, &codes, &github_key).unwrap();
        assert_eq!(*data, b"1111-2222\n3333-4444\n");
        let router = vault
            .items
            .iter()
            .find(|i| i.name == "Router admin")
            .unwrap();
        let file = dir.path().join("vord-upload.txt");
        std::fs::write(&file, "made by Vord\n").unwrap();
        let add = Change::AddAttachment {
            id: router.id.clone(),
            path: file,
            item_key: edit::item_key(vault.raw(&router.id).unwrap(), &keys).unwrap(),
        };
        let (account, _, _) = change(account, add).unwrap();

        // Sends other apps made open (tests/seed.js makes two).
        use crate::send::{self, SendKind};
        let vault = open(&account, &user_key, &sync);
        let door = vault.sends.iter().find(|s| s.name == "Door code").unwrap();
        assert!(!door.damaged && door.hidden && door.has_password);
        assert_eq!(door.text.as_deref().map(String::as_str), Some("4711"));
        assert_eq!(
            door.notes.as_deref().map(String::as_str),
            Some("For the plumber")
        );
        assert_eq!(door.max_access_count, Some(5));
        let plan = vault.sends.iter().find(|s| s.name == "Floor plan").unwrap();
        assert_eq!(plan.kind, SendKind::File);
        assert_eq!(plan.file_name.as_deref(), Some("floor-plan.txt"));

        // A text Send: made, changed, its password set and taken off.
        let week = gtk::glib::DateTime::now_utc()
            .unwrap()
            .add_days(7)
            .unwrap()
            .format("%Y-%m-%dT%H:%M:%S.%fZ")
            .unwrap()
            .to_string();
        let mut draft = send::Draft::new(SendKind::Text);
        draft.name = "Live test Send".to_string().into();
        draft.text = "made by Vord".to_string().into();
        draft.deletes = Some(week.clone());
        let (body, _) = send::request(&draft, None, &user_key).unwrap();
        let save = Change::SaveSend {
            id: None,
            body,
            file: None,
        };
        let (account, sync, touched) = change(account, save).unwrap();
        let Touched::Send(made) = touched else {
            panic!("a new Send is touched");
        };
        let vault = open(&account, &user_key, &sync);
        let original = send::Draft::open(vault.send(&made).unwrap());
        let mut edited = original.clone();
        edited.notes = "edited".to_string().into();
        edited.password = "open sesame".to_string().into();
        edited.max_access_count = Some(2);
        let raw = vault.raw_sends.get(&made).unwrap();
        let (body, _) = send::request(&edited, Some((raw, &original)), &user_key).unwrap();
        let save = Change::SaveSend {
            id: Some(made.clone()),
            body,
            file: None,
        };
        let (account, sync, _) = change(account, save).unwrap();
        let vault = open(&account, &user_key, &sync);
        let saved = vault.send(&made).unwrap();
        assert!(saved.has_password && !saved.damaged);
        assert_eq!(saved.notes.as_deref().map(String::as_str), Some("edited"));
        assert_eq!(
            saved.text.as_deref().map(String::as_str),
            Some("made by Vord")
        );
        assert_eq!(saved.max_access_count, Some(2));
        // Saving again without a new password keeps it.
        let original = send::Draft::open(saved);
        let raw = vault.raw_sends.get(&made).unwrap();
        let (body, _) = send::request(&original, Some((raw, &original)), &user_key).unwrap();
        let save = Change::SaveSend {
            id: Some(made.clone()),
            body,
            file: None,
        };
        let (account, sync, _) = change(account, save).unwrap();
        assert!(
            open(&account, &user_key, &sync)
                .send(&made)
                .unwrap()
                .has_password
        );
        let (account, sync, _) = change(account, Change::RemoveSendPassword(made.clone())).unwrap();
        assert!(
            !open(&account, &user_key, &sync)
                .send(&made)
                .unwrap()
                .has_password
        );
        let (account, sync, _) = change(account, Change::DeleteSend(made.clone())).unwrap();
        assert!(open(&account, &user_key, &sync).send(&made).is_none());

        // A file Send, and a text one with a password, stay, to open their
        // links in the web vault.
        let file = dir.path().join("vord-send.txt");
        std::fs::write(&file, "sent by Vord\n").unwrap();
        let mut draft = send::Draft::new(SendKind::File);
        draft.name = "Vord file Send".to_string().into();
        draft.file_name = Some("vord-send.txt".into());
        draft.deletes = Some(week.clone());
        let (body, key) = send::request(&draft, None, &user_key).unwrap();
        let save = Change::SaveSend {
            id: None,
            body,
            file: Some((file, key)),
        };
        let (account, sync, touched) = change(account, save).unwrap();
        let Touched::Send(made) = touched else {
            panic!("a new Send is touched");
        };
        let sent = open(&account, &user_key, &sync);
        let sent = sent.send(&made).unwrap();
        assert_eq!(sent.file_name.as_deref(), Some("vord-send.txt"));
        assert!(sent.file_size.is_some());
        let mut draft = send::Draft::new(SendKind::Text);
        draft.name = "Vord text Send".to_string().into();
        draft.text = "sent by Vord, with a password".to_string().into();
        draft.password = "open sesame".to_string().into();
        draft.deletes = Some(week);
        let (body, _) = send::request(&draft, None, &user_key).unwrap();
        let save = Change::SaveSend {
            id: None,
            body,
            file: None,
        };
        let (account, _, _) = change(account, save).unwrap();

        // The folder goes; the cache matches a fresh sync.
        let (account, sync, _) = change(account, Change::DeleteFolder(folder.clone())).unwrap();
        assert!(!open(&account, &user_key, &sync)
            .folders
            .iter()
            .any(|f| f.id == folder));
        let (_, fresh) = super::sync(account).unwrap();
        let ids = |s: &Value, key: &str| -> Vec<String> {
            let mut ids: Vec<String> = s[key]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| v["id"].as_str().unwrap().to_string())
                .collect();
            ids.sort();
            ids
        };
        assert_eq!(ids(&sync, "ciphers"), ids(&fresh, "ciphers"));
        assert_eq!(ids(&sync, "folders"), ids(&fresh, "folders"));
        assert_eq!(ids(&sync, "sends"), ids(&fresh, "sends"));
    }
}

#[cfg(test)]
mod pin_tests {
    use super::*;

    fn account(user_key: &SymmetricKey) -> Account {
        Account {
            server: "https://vw.example.org".into(),
            email: "Me@Example.org".into(),
            kdf: Kdf::Pbkdf2 { iterations: 1000 },
            device_id: "d".into(),
            refresh_token: None,
            access_token: None,
            access_expires: 0,
            user_key: String::new(),
            private_key: Some(user_key.encrypt(b"a private key").to_string()),
        }
    }

    #[test]
    fn a_pin_opens_the_user_key_and_a_wrong_one_does_not() {
        let user_key = SymmetricKey::generate();
        let account = account(&user_key);
        let sealed = seal_with_pin(&account, "2468", &user_key).unwrap();
        let opened = unlock_with_pin(&account, &sealed, "2468").unwrap();
        assert_eq!(*opened.to_bytes(), *user_key.to_bytes());
        assert!(matches!(
            unlock_with_pin(&account, &sealed, "1357"),
            Err(Error::WrongPin)
        ));

        // After the master password, the PIN kept with the user key seals
        // it again.
        let encrypted_pin = user_key.encrypt_text("2468");
        let resealed = reseal_with_pin(&account, &encrypted_pin, &user_key).unwrap();
        assert!(unlock_with_pin(&account, &resealed, "2468").is_ok());

        // A key rotated elsewhere: the old seal opens, but doesn't fit.
        let rotated = SymmetricKey::generate();
        let moved_on = Account {
            private_key: Some(rotated.encrypt(b"a private key").to_string()),
            ..account
        };
        assert!(matches!(
            unlock_with_pin(&moved_on, &sealed, "2468"),
            Err(Error::Other(_))
        ));
    }
}
