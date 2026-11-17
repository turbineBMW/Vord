//! Bitwarden Send: a text or a file shared by a link that carries its key.
//!
//! Each Send has a 16-byte seed, sealed with the user key in `key`. The
//! link carries the seed; HKDF-SHA256 of it (salt "bitwarden-send", info
//! "send") gives the 64-byte key the name, notes, text, file name and file
//! are encrypted with. A password goes to the server as PBKDF2-SHA256 of
//! it, salted with the seed, 100 000 rounds; the server hashes that again
//! and sends back only its own hash, which must never be sent as a
//! password.

use crate::crypto::{EncString, SymmetricKey};
use crate::vault::Secret;
use base64::Engine;
use serde_json::{json, Map, Value};
use sha2::Sha256;
use zeroize::Zeroizing;

const SEED_LEN: usize = 16;
const PASSWORD_ROUNDS: u32 = 100_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SendKind {
    Text,
    File,
}

impl SendKind {
    fn from_number(n: u64) -> Option<Self> {
        match n {
            0 => Some(Self::Text),
            1 => Some(Self::File),
            _ => None,
        }
    }

    pub fn number(self) -> u64 {
        match self {
            Self::Text => 0,
            Self::File => 1,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Text => "Text Send",
            Self::File => "File Send",
        }
    }

    pub fn icon(self) -> &'static str {
        match self {
            Self::Text => "text-x-generic-symbolic",
            Self::File => "mail-attachment-symbolic",
        }
    }
}

/// A Send, decrypted.
#[derive(Clone)]
pub struct Send {
    pub id: String,
    pub access_id: String,
    pub kind: SendKind,
    pub name: String,
    /// Private notes, for the sender only.
    pub notes: Option<Secret>,
    pub text: Option<Secret>,
    /// The recipient sees the text masked until they reveal it.
    pub hidden: bool,
    pub file_name: Option<String>,
    /// "1.2 MB", as the server puts it.
    pub file_size: Option<String>,
    /// What the link carries; `None` when the key won't open.
    pub seed: Option<Zeroizing<Vec<u8>>>,
    pub max_access_count: Option<u64>,
    pub access_count: u64,
    pub has_password: bool,
    pub disabled: bool,
    pub hide_email: bool,
    pub revised: Option<String>,
    pub expires: Option<String>,
    pub deletes: Option<String>,
    /// Some part would not decrypt.
    pub damaged: bool,
}

impl Send {
    /// What a search looks through, lower-cased.
    pub fn search_text(&self) -> String {
        let mut text = self.name.to_lowercase();
        if let Some(file) = &self.file_name {
            text.push('\n');
            text.push_str(&file.to_lowercase());
        }
        text.push('\n');
        text.push_str(&self.kind.label().to_lowercase());
        text
    }

    /// Whether the views it allows are used up.
    pub fn used_up(&self) -> bool {
        self.max_access_count
            .is_some_and(|max| self.access_count >= max)
    }

    /// The link to share, when the key opened.
    pub fn link(&self, server: &str) -> Option<String> {
        Some(link(server, &self.access_id, self.seed.as_ref()?))
    }
}

/// The key a Send's contents are encrypted with, from its seed.
pub fn key_from_seed(seed: &[u8]) -> SymmetricKey {
    let hk = hkdf::Hkdf::<Sha256>::new(Some(b"bitwarden-send"), seed);
    let mut out = Zeroizing::new([0u8; 64]);
    hk.expand(b"send", &mut *out)
        .expect("64 bytes is a valid length");
    SymmetricKey::from_bytes(&*out).expect("64 bytes")
}

/// What goes to the server for a Send's password.
pub fn password_hash(password: &str, seed: &[u8]) -> String {
    let mut out = Zeroizing::new([0u8; 32]);
    pbkdf2::pbkdf2_hmac::<Sha256>(password.as_bytes(), seed, PASSWORD_ROUNDS, &mut *out);
    base64::engine::general_purpose::STANDARD.encode(*out)
}

/// The link a recipient opens: the server's web vault (bitwarden.com has
/// its own address for them), the access id and the seed.
pub fn link(server: &str, access_id: &str, seed: &[u8]) -> String {
    let key = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(seed);
    let host = url::Url::parse(server)
        .ok()
        .and_then(|u| u.host_str().map(str::to_string));
    match host.as_deref() {
        Some("bitwarden.com" | "vault.bitwarden.com") => {
            format!("https://send.bitwarden.com/#{access_id}/{key}")
        }
        _ => format!("{}/#/send/{access_id}/{key}", server.trim_end_matches('/')),
    }
}

fn str_at<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    value
        .get(key)
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
}

/// The seed in a Send as the server keeps it.
fn open_seed(raw: &Value, user: &SymmetricKey) -> Option<Zeroizing<Vec<u8>>> {
    let seed = str_at(raw, "key")?
        .parse::<EncString>()
        .ok()?
        .decrypt(user)
        .ok()?;
    (seed.len() == SEED_LEN).then_some(seed)
}

/// Open one Send from a sync. `None` for one Vord can't make sense of.
pub fn open(raw: &Value, user: &SymmetricKey) -> Option<Send> {
    let id = str_at(raw, "id")?.to_string();
    let kind = SendKind::from_number(raw.get("type")?.as_u64()?)?;
    let seed = open_seed(raw, user);
    let key = seed.as_ref().map(|s| key_from_seed(s));
    let mut failed = seed.is_none();
    let mut secret = |value: Option<&Value>, field: &str| -> Option<Secret> {
        let text = str_at(value?, field)?;
        let opened = key
            .as_ref()
            .and_then(|key| text.parse::<EncString>().ok()?.decrypt_text(key).ok());
        if opened.is_none() {
            failed = true;
        }
        opened.map(Zeroizing::new)
    };
    let name = secret(Some(raw), "name")
        .map(|s| s.to_string())
        .unwrap_or_else(|| "Unreadable Send".into());
    let notes = secret(Some(raw), "notes");
    let text = secret(raw.get("text"), "text");
    let file_name = secret(raw.get("file"), "fileName").map(|s| s.to_string());
    let date = |key: &str| str_at(raw, key).map(str::to_string);
    let flag = |value: Option<&Value>, key: &str| {
        value
            .and_then(|v| v.get(key))
            .and_then(Value::as_bool)
            .unwrap_or(false)
    };
    Some(Send {
        access_id: str_at(raw, "accessId").unwrap_or_default().to_string(),
        kind,
        name,
        notes,
        text,
        hidden: flag(raw.get("text"), "hidden"),
        file_name,
        file_size: raw
            .get("file")
            .and_then(|f| str_at(f, "sizeName"))
            .map(str::to_string),
        max_access_count: raw.get("maxAccessCount").and_then(Value::as_u64),
        access_count: raw.get("accessCount").and_then(Value::as_u64).unwrap_or(0),
        has_password: str_at(raw, "password").is_some(),
        disabled: flag(Some(raw), "disabled"),
        hide_email: flag(Some(raw), "hideEmail"),
        revised: date("revisionDate"),
        expires: date("expirationDate"),
        deletes: date("deletionDate"),
        damaged: failed,
        seed,
        id,
    })
}

/// A Send as the editor holds it.
#[derive(Clone)]
pub struct Draft {
    pub kind: SendKind,
    pub name: Secret,
    pub notes: Secret,
    pub text: Secret,
    pub hidden: bool,
    /// A new file Send's file name; the file is read when it's sent.
    pub file_name: Option<String>,
    /// ISO 8601, UTC.
    pub deletes: Option<String>,
    pub expires: Option<String>,
    pub max_access_count: Option<u64>,
    /// A new password; empty keeps the one it has, or none.
    pub password: Secret,
    pub hide_email: bool,
    pub disabled: bool,
}

impl Draft {
    pub fn new(kind: SendKind) -> Self {
        Self {
            kind,
            name: Secret::default(),
            notes: Secret::default(),
            text: Secret::default(),
            hidden: false,
            file_name: None,
            deletes: None,
            expires: None,
            max_access_count: None,
            password: Secret::default(),
            hide_email: false,
            disabled: false,
        }
    }

    /// A saved Send, for editing.
    pub fn open(send: &Send) -> Self {
        Self {
            kind: send.kind,
            name: Secret::new(send.name.clone()),
            notes: send.notes.clone().unwrap_or_default(),
            text: send.text.clone().unwrap_or_default(),
            hidden: send.hidden,
            file_name: send.file_name.clone(),
            deletes: send.deletes.clone(),
            expires: send.expires.clone(),
            max_access_count: send.max_access_count,
            password: Secret::default(),
            hide_email: send.hide_email,
            disabled: send.disabled,
        }
    }

    /// Why it can't be saved, if it can't.
    pub fn problem(&self) -> Option<&'static str> {
        if self.name.trim().is_empty() {
            return Some("Give the Send a name.");
        }
        match self.kind {
            SendKind::Text if self.text.is_empty() => Some("Type the text to send."),
            SendKind::File if self.file_name.is_none() => Some("Choose a file to send."),
            _ if self.deletes.is_none() => Some("Choose when the Send is deleted."),
            _ => None,
        }
    }
}

fn optional(key: &SymmetricKey, text: &str) -> Value {
    if text.is_empty() {
        Value::Null
    } else {
        Value::String(key.encrypt_text(text))
    }
}

/// The body that creates (`base` is `None`) or updates a Send, and the
/// key a new file is to be encrypted with. An update starts from the Send
/// as the server sent it, so what isn't changed keeps its ciphertext.
pub fn request(
    draft: &Draft,
    base: Option<(&Value, &Draft)>,
    user: &SymmetricKey,
) -> Result<(Value, SymmetricKey), String> {
    let (seed, sealed) = match base {
        Some((raw, _)) => {
            let seed = open_seed(raw, user).ok_or("This Send's key won't open.")?;
            let sealed = raw["key"].clone();
            (seed, sealed)
        }
        None => {
            let mut seed = Zeroizing::new(vec![0u8; SEED_LEN]);
            rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut seed);
            let sealed = Value::String(user.encrypt(&seed).to_string());
            (seed, sealed)
        }
    };
    let key = key_from_seed(&seed);
    let raw = base.map(|(raw, _)| raw);
    let original = base.map(|(_, original)| original);
    let kept = |field: &str| raw.and_then(|r| r.get(field)).cloned();

    let mut body = Map::new();
    body.insert("type".into(), json!(draft.kind.number()));
    body.insert("key".into(), sealed);
    let name = match (kept("name"), original) {
        (Some(name), Some(o)) if o.name == draft.name => name,
        _ => Value::String(key.encrypt_text(draft.name.trim())),
    };
    body.insert("name".into(), name);
    let notes = match (kept("notes"), original) {
        (Some(notes), Some(o)) if o.notes == draft.notes => notes,
        _ => optional(&key, &draft.notes),
    };
    body.insert("notes".into(), notes);
    match draft.kind {
        SendKind::Text => {
            let mut text = kept("text")
                .filter(Value::is_object)
                .unwrap_or_else(|| json!({}));
            if original.is_none_or(|o| o.text != draft.text) {
                text["text"] = optional(&key, &draft.text);
            }
            text["hidden"] = json!(draft.hidden);
            text.as_object_mut().map(|t| t.remove("response"));
            body.insert("text".into(), text);
            body.insert("file".into(), Value::Null);
        }
        SendKind::File => {
            // A file can't change; only its encrypted name goes back.
            let file_name = match kept("file").as_ref().and_then(|f| f.get("fileName")) {
                Some(name) => name.clone(),
                None => Value::String(key.encrypt_text(draft.file_name.as_deref().unwrap_or(""))),
            };
            body.insert("file".into(), json!({ "fileName": file_name }));
            body.insert("text".into(), Value::Null);
        }
    }
    body.insert("deletionDate".into(), json!(draft.deletes));
    body.insert("expirationDate".into(), json!(draft.expires));
    body.insert("maxAccessCount".into(), json!(draft.max_access_count));
    // Null keeps the password the Send has.
    body.insert(
        "password".into(),
        if draft.password.is_empty() {
            Value::Null
        } else {
            Value::String(password_hash(&draft.password, &seed))
        },
    );
    body.insert("disabled".into(), json!(draft.disabled));
    body.insert("hideEmail".into(), json!(draft.hide_email));
    Ok((Value::Object(body), key))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    const SEED: [u8; 16] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];

    #[test]
    fn keys_and_passwords_match_node() {
        assert_eq!(
            hex(&key_from_seed(&SEED).to_bytes()),
            include_str!("../tests/vectors/send_key").trim()
        );
        assert_eq!(
            password_hash("open sesame", &SEED),
            include_str!("../tests/vectors/send_password_hash").trim()
        );
    }

    #[test]
    fn links() {
        assert_eq!(
            link("https://vw.example.org/", "abc", &SEED),
            "https://vw.example.org/#/send/abc/AAECAwQFBgcICQoLDA0ODw"
        );
        assert_eq!(
            link("https://vault.bitwarden.com", "abc", &SEED),
            "https://send.bitwarden.com/#abc/AAECAwQFBgcICQoLDA0ODw"
        );
    }

    #[test]
    fn a_new_send_opens_and_an_edit_keeps_what_it_did_not_touch() {
        let user = SymmetricKey::generate();
        let mut draft = Draft::new(SendKind::Text);
        draft.name = Secret::new("Door code".into());
        draft.text = Secret::new("4711".into());
        draft.hidden = true;
        draft.deletes = Some("2026-12-01T00:00:00.000Z".into());
        draft.password = Secret::new("open sesame".into());
        assert!(draft.problem().is_none());
        let (body, _) = request(&draft, None, &user).unwrap();
        assert_eq!(body["file"], Value::Null);
        assert_eq!(body["notes"], Value::Null);

        // As the server answers: ids added, the password its own hash.
        let mut raw = body.clone();
        raw["id"] = json!("s1");
        raw["accessId"] = json!("acc");
        raw["password"] = json!("c2VydmVyIGhhc2g");
        raw["accessCount"] = json!(2);
        let send = open(&raw, &user).unwrap();
        assert!(!send.damaged && send.hidden && send.has_password);
        assert_eq!(send.name, "Door code");
        assert_eq!(send.text.as_deref().map(String::as_str), Some("4711"));
        let seed = send.seed.clone().unwrap();
        assert_eq!(body["password"], json!(password_hash("open sesame", &seed)));

        let original = Draft::open(&send);
        let mut edited = original.clone();
        edited.notes = Secret::new("for the plumber".into());
        edited.max_access_count = Some(3);
        let (update, _) = request(&edited, Some((&raw, &original)), &user).unwrap();
        assert_eq!(update["name"], raw["name"]);
        assert_eq!(update["key"], raw["key"]);
        assert_eq!(update["text"]["text"], raw["text"]["text"]);
        assert_eq!(update["maxAccessCount"], json!(3));
        // The server's hash never goes back as a password.
        assert_eq!(update["password"], Value::Null);
        let mut update = update;
        update["id"] = json!("s1");
        let reopened = open(&update, &user).unwrap();
        assert_eq!(
            reopened.notes.as_deref().map(String::as_str),
            Some("for the plumber")
        );
    }

    #[test]
    fn a_file_send_and_a_damaged_one() {
        let user = SymmetricKey::generate();
        let mut draft = Draft::new(SendKind::File);
        draft.name = Secret::new("Scan".into());
        draft.deletes = Some("2026-12-01T00:00:00.000Z".into());
        assert_eq!(draft.problem(), Some("Choose a file to send."));
        draft.file_name = Some("scan.pdf".into());
        let (body, key) = request(&draft, None, &user).unwrap();
        let name: EncString = body["file"]["fileName"].as_str().unwrap().parse().unwrap();
        assert_eq!(name.decrypt_text(&key).unwrap(), "scan.pdf");
        assert_eq!(body["text"], Value::Null);

        let mut raw = body.clone();
        raw["id"] = json!("s2");
        raw["key"] = json!(SymmetricKey::generate().encrypt(&SEED).to_string());
        let send = open(&raw, &user).unwrap();
        assert!(send.damaged && send.seed.is_none());
        assert_eq!(send.name, "Unreadable Send");
        assert!(request(
            &Draft::open(&send),
            Some((&raw, &Draft::open(&send))),
            &user
        )
        .is_err());
    }
}
