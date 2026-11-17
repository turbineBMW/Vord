//! Changing items: what an editor holds (a [`Draft`]), and the request that
//! saves it.
//!
//! An edit changes only what was changed. The server's encrypted copy of
//! the item is the starting point: every field left alone keeps its
//! ciphertext, and what Vord doesn't model (passkeys, attachments, URI match
//! rules, linked fields, anything newer) goes back as it came.
//!
//! As Bitwarden's apps do, a changed password goes into the item's password
//! history (the last five), and so does a hidden field's old value.

use crate::crypto::{CryptoError, EncString, SymmetricKey};
use crate::vault::{FieldKind, Keys, Kind, Secret};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

/// How many earlier passwords an item keeps.
const HISTORY: usize = 5;

/// One of a type's own text fields.
pub struct Spec {
    /// Its key in the type's object.
    pub key: &'static str,
    pub label: &'static str,
    pub secret: bool,
}

const fn spec(key: &'static str, label: &'static str, secret: bool) -> Spec {
    Spec { key, label, secret }
}

const LOGIN: &[Spec] = &[
    spec("username", "Username", false),
    spec("password", "Password", true),
    spec("totp", "Authenticator key (TOTP)", true),
];
const CARD: &[Spec] = &[
    spec("cardholderName", "Cardholder name", false),
    spec("brand", "Brand", false),
    spec("number", "Number", true),
    spec("expMonth", "Expiration month", false),
    spec("expYear", "Expiration year", false),
    spec("code", "Security code", true),
];
const IDENTITY: &[Spec] = &[
    spec("title", "Title", false),
    spec("firstName", "First name", false),
    spec("middleName", "Middle name", false),
    spec("lastName", "Last name", false),
    spec("username", "Username", false),
    spec("company", "Company", false),
    spec("ssn", "Social security number", true),
    spec("passportNumber", "Passport number", true),
    spec("licenseNumber", "License number", true),
    spec("email", "Email", false),
    spec("phone", "Phone", false),
    spec("address1", "Address 1", false),
    spec("address2", "Address 2", false),
    spec("address3", "Address 3", false),
    spec("city", "City / Town", false),
    spec("state", "State / Province", false),
    spec("postalCode", "Zip / Postal code", false),
    spec("country", "Country", false),
];
const SSH_KEY: &[Spec] = &[
    spec("privateKey", "Private key", true),
    spec("publicKey", "Public key", false),
    spec("keyFingerprint", "Fingerprint", false),
];

/// A type's own text fields, in the order they're edited.
pub fn specs(kind: Kind) -> &'static [Spec] {
    match kind {
        Kind::Login => LOGIN,
        Kind::Card => CARD,
        Kind::Identity => IDENTITY,
        Kind::SshKey => SSH_KEY,
        Kind::Note => &[],
    }
}

/// The position of a type's field in [`specs`].
pub fn position(kind: Kind, key: &str) -> Option<usize> {
    specs(kind).iter().position(|s| s.key == key)
}

#[derive(Clone, Default)]
pub struct Uri {
    pub uri: Secret,
    /// Its index in the item as saved, for one that was already there.
    pub origin: Option<usize>,
}

#[derive(Clone)]
pub struct Field {
    pub name: Secret,
    /// Empty for a linked field.
    pub value: Secret,
    pub kind: FieldKind,
    /// Its index in the item as saved, for one that was already there.
    pub origin: Option<usize>,
}

/// An item as an editor holds it: decrypted, every field as text.
#[derive(Clone)]
pub struct Draft {
    pub kind: Kind,
    pub name: Secret,
    pub notes: Secret,
    pub folder_id: Option<String>,
    pub org_id: Option<String>,
    pub collection_ids: Vec<String>,
    pub favorite: bool,
    pub reprompt: bool,
    /// The type's own fields, in [`specs`] order.
    pub values: Vec<Secret>,
    pub uris: Vec<Uri>,
    pub fields: Vec<Field>,
}

fn str_at<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    value
        .get(key)
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
}

fn array(value: Option<&Value>) -> &[Value] {
    value.and_then(Value::as_array).map_or(&[], Vec::as_slice)
}

fn open_text(value: Option<&str>, key: &SymmetricKey) -> Result<Secret, CryptoError> {
    match value.filter(|s| !s.is_empty()) {
        None => Ok(Secret::default()),
        Some(text) => Ok(Secret::new(text.parse::<EncString>()?.decrypt_text(key)?)),
    }
}

/// The key an item's fields are encrypted with: its own key when it has
/// one, else its owner's (the organisation's, or the user key).
pub fn item_key(raw: &Value, keys: &Keys) -> Result<SymmetricKey, CryptoError> {
    let owner = keys
        .for_org(str_at(raw, "organizationId"))
        .ok_or_else(|| CryptoError::Format("no key for this item's organization".into()))?;
    let key = match str_at(raw, "key") {
        Some(sealed) => SymmetricKey::from_bytes(&sealed.parse::<EncString>()?.decrypt(owner)?)?,
        None => owner.clone(),
    };
    if key.can_encrypt() {
        Ok(key)
    } else {
        Err(CryptoError::KeyMismatch)
    }
}

impl Draft {
    /// An empty item of a type.
    pub fn new(kind: Kind) -> Self {
        Self {
            kind,
            name: Secret::default(),
            notes: Secret::default(),
            folder_id: None,
            org_id: None,
            collection_ids: Vec::new(),
            favorite: false,
            reprompt: false,
            values: specs(kind).iter().map(|_| Secret::default()).collect(),
            uris: Vec::new(),
            fields: Vec::new(),
        }
    }

    /// Open an item for editing. Any field that won't decrypt refuses the
    /// whole item: saving would lose it.
    pub fn open(raw: &Value, key: &SymmetricKey) -> Result<Self, CryptoError> {
        let kind = raw
            .get("type")
            .and_then(Value::as_u64)
            .and_then(|n| Kind::ALL.into_iter().find(|k| k.number() == n))
            .ok_or_else(|| CryptoError::Format("an item type Vord doesn't know".into()))?;
        let object = raw.get(kind.object()).unwrap_or(&Value::Null);
        let values = specs(kind)
            .iter()
            .map(|spec| open_text(object.get(spec.key).and_then(Value::as_str), key))
            .collect::<Result<_, _>>()?;
        let uris = array(object.get("uris"))
            .iter()
            .enumerate()
            .map(|(i, u)| {
                Ok(Uri {
                    uri: open_text(u.get("uri").and_then(Value::as_str), key)?,
                    origin: Some(i),
                })
            })
            .collect::<Result<_, CryptoError>>()?;
        let fields = array(raw.get("fields"))
            .iter()
            .enumerate()
            .map(|(i, f)| {
                Ok(Field {
                    name: open_text(f.get("name").and_then(Value::as_str), key)?,
                    value: open_text(f.get("value").and_then(Value::as_str), key)?,
                    kind: match f.get("type").and_then(Value::as_u64) {
                        Some(1) => FieldKind::Hidden,
                        Some(2) => FieldKind::Boolean,
                        Some(3) => FieldKind::Linked,
                        _ => FieldKind::Text,
                    },
                    origin: Some(i),
                })
            })
            .collect::<Result<_, CryptoError>>()?;
        Ok(Self {
            kind,
            name: open_text(str_at(raw, "name"), key)?,
            notes: open_text(str_at(raw, "notes"), key)?,
            folder_id: str_at(raw, "folderId").map(str::to_string),
            org_id: str_at(raw, "organizationId").map(str::to_string),
            collection_ids: array(raw.get("collectionIds"))
                .iter()
                .filter_map(|c| c.as_str().map(str::to_string))
                .collect(),
            favorite: raw
                .get("favorite")
                .and_then(Value::as_bool)
                .unwrap_or(false),
            reprompt: raw.get("reprompt").and_then(Value::as_u64).unwrap_or(0) == 1,
            values,
            uris,
            fields,
        })
    }

    /// A copy to save as a new item: "<name> - Clone", without the
    /// passkeys, attachments and history that belong to the original.
    pub fn cloned(&self) -> Self {
        let mut copy = self.clone();
        copy.name = Secret::new(format!("{} - Clone", *self.name));
        for uri in &mut copy.uris {
            uri.origin = None;
        }
        // A linked field points into the original's own fields.
        copy.fields.retain(|f| f.kind != FieldKind::Linked);
        for field in &mut copy.fields {
            field.origin = None;
        }
        copy
    }

    pub fn value(&self, key: &str) -> &str {
        position(self.kind, key).map_or("", |i| &self.values[i])
    }

    /// What's wrong with it, if it can't be saved.
    pub fn problem(&self) -> Option<&'static str> {
        if self.name.trim().is_empty() {
            return Some("Give the item a name.");
        }
        if self.org_id.is_some() && self.collection_ids.is_empty() {
            return Some("Choose at least one collection.");
        }
        None
    }
}

/// A new Ed25519 key for an SSH key item, as Bitwarden's apps make one:
/// OpenSSH private and public keys and the SHA-256 fingerprint.
pub fn new_ssh_key(draft: &mut Draft) -> Result<(), String> {
    use ssh_key::{rand_core::OsRng, Algorithm, HashAlg, LineEnding, PrivateKey};
    let key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).map_err(|e| e.to_string())?;
    let private = key.to_openssh(LineEnding::LF).map_err(|e| e.to_string())?;
    let public = key.public_key().to_openssh().map_err(|e| e.to_string())?;
    let fingerprint = key.fingerprint(HashAlg::Sha256).to_string();
    for (field, value) in [
        ("privateKey", private.to_string()),
        ("publicKey", public),
        ("keyFingerprint", fingerprint),
    ] {
        if let Some(i) = position(draft.kind, field) {
            draft.values[i] = Secret::new(value);
        }
    }
    Ok(())
}

/// The saved item an edit starts from.
pub struct Base<'a> {
    /// As the server sent it, still encrypted.
    pub raw: &'a Value,
    /// As it opened.
    pub original: &'a Draft,
}

/// Encrypt `new`, or keep `old_cipher` when the text is unchanged.
fn put(key: &SymmetricKey, old_cipher: Option<&Value>, old: Option<&str>, new: &str) -> Value {
    if old == Some(new) {
        if let Some(cipher) = old_cipher {
            return cipher.clone();
        }
    }
    if new.is_empty() {
        Value::Null
    } else {
        Value::String(key.encrypt_text(new))
    }
}

/// What Bitwarden's apps store beside a URI so a server can't swap it
/// unnoticed: the SHA-256 of the URI, base64, encrypted.
fn uri_checksum(key: &SymmetricKey, uri: &str) -> String {
    key.encrypt_text(&B64.encode(Sha256::digest(uri.as_bytes())))
}

/// Who saves, and when.
pub struct Saver<'a> {
    /// The account's user id: newer servers want to be told whose key an
    /// item is encrypted for.
    pub user_id: Option<&'a str>,
    /// An ISO 8601 time, for the password history.
    pub now: &'a str,
}

/// The body that creates (no `base`) or updates an item.
pub fn request(draft: &Draft, base: Option<Base>, key: &SymmetricKey, saver: &Saver) -> Value {
    let raw = base.as_ref().map(|b| b.raw);
    let original = base.as_ref().map(|b| b.original);
    let kind = draft.kind;
    let now = saver.now;
    let mut out = Map::new();
    if let Some(user) = saver.user_id {
        out.insert("encryptedFor".into(), json!(user));
    }
    out.insert("type".into(), json!(kind.number()));
    out.insert("organizationId".into(), json!(draft.org_id));
    out.insert("folderId".into(), json!(draft.folder_id));
    out.insert("favorite".into(), json!(draft.favorite));
    out.insert("reprompt".into(), json!(u8::from(draft.reprompt)));
    if let Some(sealed) = raw.and_then(|r| r.get("key")).filter(|k| k.is_string()) {
        out.insert("key".into(), sealed.clone());
    }
    if let Some(revision) = raw.and_then(|r| r.get("revisionDate")) {
        // The server refuses the save if the item changed since.
        out.insert("lastKnownRevisionDate".into(), revision.clone());
    }
    out.insert(
        "name".into(),
        put(
            key,
            raw.and_then(|r| r.get("name")),
            original.map(|o| o.name.as_str()),
            &draft.name,
        ),
    );
    out.insert(
        "notes".into(),
        put(
            key,
            raw.and_then(|r| r.get("notes")),
            original.map(|o| o.notes.as_str()),
            &draft.notes,
        ),
    );

    let mut history: Vec<Value> = array(raw.and_then(|r| r.get("passwordHistory"))).to_vec();
    let mut past =
        |cipher: Value| history.insert(0, json!({ "lastUsedDate": now, "password": cipher }));

    // The type's own object, starting from the saved one.
    let mut object = raw
        .and_then(|r| r.get(kind.object()))
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    for (i, spec) in specs(kind).iter().enumerate() {
        let old = original.map(|o| o.values[i].as_str());
        let value = put(key, object.get(spec.key), old, &draft.values[i]);
        object.insert(spec.key.into(), value);
    }
    match kind {
        Kind::Login => {
            let old = original.map_or("", |o| o.value("password"));
            if !old.is_empty() && old != draft.value("password") {
                let saved = raw
                    .and_then(|r| r.pointer("/login/password"))
                    .cloned()
                    .unwrap_or_else(|| json!(key.encrypt_text(old)));
                past(saved);
                object.insert("passwordRevisionDate".into(), json!(now));
            }
            let saved_uris = array(raw.and_then(|r| r.pointer("/login/uris")));
            let originals = original.map_or(&[][..], |o| o.uris.as_slice());
            let uris: Vec<Value> = draft
                .uris
                .iter()
                .filter(|u| !u.uri.trim().is_empty())
                .map(|u| {
                    let saved = u.origin.and_then(|i| saved_uris.get(i));
                    let before = u
                        .origin
                        .and_then(|i| originals.get(i))
                        .map(|o| o.uri.as_str());
                    match saved {
                        Some(saved) if before == Some(u.uri.as_str()) => saved.clone(),
                        _ => {
                            let mut entry = saved
                                .and_then(Value::as_object)
                                .cloned()
                                .unwrap_or_else(|| {
                                    let mut m = Map::new();
                                    m.insert("match".into(), Value::Null);
                                    m
                                });
                            entry.insert("uri".into(), json!(key.encrypt_text(&u.uri)));
                            entry.insert("uriChecksum".into(), json!(uri_checksum(key, &u.uri)));
                            Value::Object(entry)
                        }
                    }
                })
                .collect();
            object.insert("uris".into(), Value::Array(uris));
            // The old single-URI field would override the list on some
            // servers.
            object.remove("uri");
        }
        Kind::Note => {
            object.entry("type").or_insert(json!(0));
        }
        _ => {}
    }

    // Custom fields.
    let saved_fields = array(raw.and_then(|r| r.get("fields")));
    let originals = original.map_or(&[][..], |o| o.fields.as_slice());
    let fields: Vec<Value> = draft
        .fields
        .iter()
        .map(|f| {
            let saved = f.origin.and_then(|i| saved_fields.get(i));
            let before = f.origin.and_then(|i| originals.get(i));
            let mut entry = saved
                .and_then(Value::as_object)
                .cloned()
                .unwrap_or_else(|| {
                    let mut m = Map::new();
                    m.insert("linkedId".into(), Value::Null);
                    m
                });
            let number = match f.kind {
                FieldKind::Text => 0,
                FieldKind::Hidden => 1,
                FieldKind::Boolean => 2,
                FieldKind::Linked => 3,
            };
            entry.insert("type".into(), json!(number));
            let name = put(
                key,
                saved.and_then(|s| s.get("name")),
                before.map(|b| b.name.as_str()),
                &f.name,
            );
            entry.insert("name".into(), name);
            if f.kind != FieldKind::Linked {
                let value = put(
                    key,
                    saved.and_then(|s| s.get("value")),
                    before.map(|b| b.value.as_str()),
                    &f.value,
                );
                entry.insert("value".into(), value);
            }
            Value::Object(entry)
        })
        .collect();
    out.insert("fields".into(), Value::Array(fields));

    // A hidden field that changed or went keeps its old value in the
    // history, "name: value", as Bitwarden's apps do.
    for old in originals
        .iter()
        .filter(|f| f.kind == FieldKind::Hidden && !f.name.is_empty() && !f.value.is_empty())
    {
        let kept = draft
            .fields
            .iter()
            .any(|f| f.kind == FieldKind::Hidden && f.name == old.name && f.value == old.value);
        if !kept {
            past(json!(
                key.encrypt_text(&format!("{}: {}", *old.name, *old.value))
            ));
        }
    }
    history.truncate(HISTORY);
    out.insert(
        "passwordHistory".into(),
        if history.is_empty() {
            Value::Null
        } else {
            Value::Array(history)
        },
    );
    out.insert(kind.object().into(), Value::Object(object));
    Value::Object(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: Saver = Saver {
        user_id: None,
        now: "now",
    };

    fn enc(key: &SymmetricKey, text: &str) -> String {
        key.encrypt_text(text)
    }

    fn dec(key: &SymmetricKey, value: &Value) -> String {
        value
            .as_str()
            .unwrap()
            .parse::<EncString>()
            .unwrap()
            .decrypt_text(key)
            .unwrap()
    }

    #[test]
    fn an_edit_keeps_what_it_did_not_touch() {
        let key = SymmetricKey::generate();
        let passkey = json!([{ "credentialId": enc(&key, "abc"), "counter": enc(&key, "0") }]);
        let raw = json!({
            "id": "c1", "type": 1, "revisionDate": "2026-01-01T00:00:00Z",
            "name": enc(&key, "GitHub"), "notes": null, "favorite": false, "reprompt": 0,
            "folderId": null, "organizationId": null,
            "login": {
                "username": enc(&key, "octocat"),
                "password": enc(&key, "old-password"),
                "totp": null,
                "uri": enc(&key, "https://github.com"),
                "uris": [
                    { "uri": enc(&key, "https://github.com"), "match": 3 },
                    { "uri": enc(&key, "https://gist.github.com"), "match": null }
                ],
                "fido2Credentials": passkey,
                "autofillOnPageLoad": true
            },
            "fields": [
                { "type": 1, "name": enc(&key, "PIN"), "value": enc(&key, "1234"), "linkedId": null },
                { "type": 3, "name": enc(&key, "Linked"), "value": null, "linkedId": 100 }
            ],
            "passwordHistory": [{ "lastUsedDate": "2025-01-01T00:00:00Z", "password": enc(&key, "older") }],
            "attachments": [{ "id": "a1", "fileName": enc(&key, "x.pdf") }]
        });
        let original = Draft::open(&raw, &key).unwrap();
        assert_eq!(original.value("username"), "octocat");
        assert_eq!(original.uris.len(), 2);

        let mut draft = original.clone();
        draft.values[position(Kind::Login, "password").unwrap()] =
            Secret::new("new-password".into());
        draft.uris[1].uri = Secret::new("https://docs.github.com".into());
        draft.fields[0].value = Secret::new("9999".into());
        draft.favorite = true;
        let base = Base {
            raw: &raw,
            original: &original,
        };
        let saver = Saver {
            user_id: Some("u1"),
            now: "2026-11-17T00:00:00Z",
        };
        let body = request(&draft, Some(base), &key, &saver);

        // Untouched ciphertext is sent back as it was.
        assert_eq!(body["name"], raw["name"]);
        assert_eq!(body["login"]["username"], raw["login"]["username"]);
        assert_eq!(body["login"]["uris"][0], raw["login"]["uris"][0]);
        assert_eq!(body["fields"][1], raw["fields"][1]);
        assert_eq!(body["login"]["fido2Credentials"], passkey);
        assert_eq!(body["login"]["autofillOnPageLoad"], true);
        assert_eq!(body["lastKnownRevisionDate"], "2026-01-01T00:00:00Z");
        assert!(body["login"].get("uri").is_none());
        assert!(body.get("attachments").is_none());
        assert_eq!(body["favorite"], true);
        assert_eq!(body["encryptedFor"], "u1");

        // What changed is new ciphertext, with a checksum on a new URI.
        assert_eq!(dec(&key, &body["login"]["password"]), "new-password");
        let uri = &body["login"]["uris"][1];
        assert_eq!(dec(&key, &uri["uri"]), "https://docs.github.com");
        assert_eq!(
            dec(&key, &uri["uriChecksum"]),
            B64.encode(Sha256::digest(b"https://docs.github.com"))
        );
        assert_eq!(dec(&key, &body["fields"][0]["value"]), "9999");
        assert_eq!(
            body["login"]["passwordRevisionDate"],
            "2026-11-17T00:00:00Z"
        );

        // The old password and the old PIN went into the history, newest
        // first, the old password's ciphertext reused.
        let history = body["passwordHistory"].as_array().unwrap();
        assert_eq!(history.len(), 3);
        assert_eq!(dec(&key, &history[0]["password"]), "PIN: 1234");
        assert_eq!(history[1]["password"], raw["login"]["password"]);
        assert_eq!(dec(&key, &history[2]["password"]), "older");
    }

    #[test]
    fn a_new_item_and_a_clone() {
        let key = SymmetricKey::generate();
        let mut draft = Draft::new(Kind::Card);
        assert_eq!(draft.problem(), Some("Give the item a name."));
        draft.name = Secret::new("Visa".into());
        draft.values[position(Kind::Card, "number").unwrap()] = Secret::new("4111".into());
        assert_eq!(draft.problem(), None);
        let body = request(&draft, None, &key, &NOW);
        assert_eq!(body["type"], 3);
        assert_eq!(dec(&key, &body["card"]["number"]), "4111");
        assert_eq!(body["card"]["brand"], Value::Null);
        assert_eq!(body["passwordHistory"], Value::Null);
        assert!(body.get("lastKnownRevisionDate").is_none());

        let note = request(&Draft::new(Kind::Note), None, &key, &NOW);
        assert_eq!(note["secureNote"]["type"], 0);

        let mut org = Draft::new(Kind::Login);
        org.name = Secret::new("Shared".into());
        org.org_id = Some("o1".into());
        assert_eq!(org.problem(), Some("Choose at least one collection."));

        let raw = json!({
            "id": "c1", "type": 1, "name": enc(&key, "Mail"),
            "login": { "password": enc(&key, "pw"), "uris": [{ "uri": enc(&key, "a.example"), "match": 1 }],
                       "fido2Credentials": [{ "credentialId": "x" }] },
            "fields": [{ "type": 3, "name": enc(&key, "L"), "value": null, "linkedId": 101 }],
            "passwordHistory": [{ "lastUsedDate": "x", "password": enc(&key, "older") }]
        });
        let original = Draft::open(&raw, &key).unwrap();
        let copy = original.cloned();
        assert_eq!(&*copy.name, "Mail - Clone");
        assert!(copy.fields.is_empty());
        let body = request(&copy, None, &key, &NOW);
        assert!(body["login"].get("fido2Credentials").is_none());
        assert_eq!(body["passwordHistory"], Value::Null);
        assert_eq!(dec(&key, &body["login"]["password"]), "pw");
        assert_eq!(body["login"]["uris"][0]["match"], Value::Null);
    }

    #[test]
    fn new_ssh_keys() {
        let mut draft = Draft::new(Kind::SshKey);
        new_ssh_key(&mut draft).unwrap();
        assert!(draft
            .value("privateKey")
            .starts_with("-----BEGIN OPENSSH PRIVATE KEY-----"));
        assert!(draft.value("publicKey").starts_with("ssh-ed25519 "));
        assert!(draft.value("keyFingerprint").starts_with("SHA256:"));
        // The three parts are one key.
        let key = ssh_key::PrivateKey::from_openssh(draft.value("privateKey")).unwrap();
        assert_eq!(
            key.public_key().to_openssh().unwrap(),
            draft.value("publicKey")
        );
        assert_eq!(
            key.fingerprint(ssh_key::HashAlg::Sha256).to_string(),
            draft.value("keyFingerprint")
        );
    }

    #[test]
    fn an_item_that_will_not_open_is_not_edited() {
        let key = SymmetricKey::generate();
        let other = SymmetricKey::generate();
        let raw = json!({ "type": 2, "name": enc(&key, "ok"), "notes": enc(&other, "not ours") });
        assert!(Draft::open(&raw, &key).is_err());
        let raw = json!({ "type": 99, "name": enc(&key, "future") });
        assert!(Draft::open(&raw, &key).is_err());
    }
}
