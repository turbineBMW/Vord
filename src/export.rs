//! Exporting the vault in Bitwarden's own formats, so any Bitwarden app
//! (or Vord, later) can import it.
//!
//! As Bitwarden's apps do, an export holds the user's own items, not an
//! organization's, and nothing from the Trash. It's built from the cached
//! sync:
//!
//! - **JSON** and **CSV** are decrypted. CSV holds only logins and notes.
//! - **Encrypted JSON** keeps the ciphertext as the server has it; only
//!   this account's key opens it.
//! - **Password-protected JSON** is the decrypted JSON, encrypted with a
//!   key made from a password of its own (the account's KDF, salted with
//!   random text) and stretched as a master key is.

use crate::crypto::{EncString, Kdf, MasterKey, SymmetricKey};
use base64::Engine;
use serde_json::{json, Map, Value};
use zeroize::Zeroizing;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Format {
    Json,
    Csv,
    /// Encrypted with the account's own key.
    AccountJson,
    /// Encrypted with a password chosen for the file.
    PasswordJson,
}

impl Format {
    pub const ALL: [Format; 4] = [
        Format::Json,
        Format::Csv,
        Format::AccountJson,
        Format::PasswordJson,
    ];

    pub fn label(self) -> &'static str {
        match self {
            Self::Json => ".json",
            Self::Csv => ".csv",
            Self::AccountJson => ".json (encrypted for this account)",
            Self::PasswordJson => ".json (encrypted with a password)",
        }
    }

    /// Whether the file is readable without a key.
    pub fn decrypted(self) -> bool {
        matches!(self, Self::Json | Self::Csv)
    }

    /// The name Bitwarden's apps give the file, at `stamp` (YYYYMMDDHHMMSS).
    pub fn file_name(self, stamp: &str) -> String {
        match self {
            Self::Json | Self::PasswordJson => format!("bitwarden_export_{stamp}.json"),
            Self::Csv => format!("bitwarden_export_{stamp}.csv"),
            Self::AccountJson => format!("bitwarden_encrypted_export_{stamp}.json"),
        }
    }
}

/// The keys each kind of object keeps, in an export, from the item as the
/// server sent it.
const ITEM: &[&str] = &[
    "id",
    "organizationId",
    "folderId",
    "type",
    "reprompt",
    "name",
    "notes",
    "favorite",
    "fields",
    "passwordHistory",
    "revisionDate",
    "creationDate",
    "deletedDate",
    "archivedDate",
];
const LOGIN: &[&str] = &["uris", "username", "password", "totp", "fido2Credentials"];
const URI: &[&str] = &["uri", "uriChecksum", "match"];
const FIELD: &[&str] = &["name", "value", "type", "linkedId"];
const PAST_PASSWORD: &[&str] = &["password", "lastUsedDate"];
const PASSKEY: &[&str] = &[
    "credentialId",
    "keyType",
    "keyAlgorithm",
    "keyCurve",
    "keyValue",
    "rpId",
    "userHandle",
    "userName",
    "counter",
    "rpName",
    "userDisplayName",
    "discoverable",
    "creationDate",
];
const CARD: &[&str] = &[
    "cardholderName",
    "brand",
    "number",
    "expMonth",
    "expYear",
    "code",
];
const IDENTITY: &[&str] = &[
    "title",
    "firstName",
    "middleName",
    "lastName",
    "address1",
    "address2",
    "address3",
    "city",
    "state",
    "postalCode",
    "country",
    "company",
    "email",
    "phone",
    "ssn",
    "username",
    "passportNumber",
    "licenseNumber",
];
const NOTE: &[&str] = &["type"];
const SSH_KEY: &[&str] = &["privateKey", "publicKey", "keyFingerprint"];

/// The type's own object, by type number.
fn kind_object(kind: u64) -> Option<(&'static str, &'static [&'static str])> {
    Some(match kind {
        1 => ("login", LOGIN),
        2 => ("secureNote", NOTE),
        3 => ("card", CARD),
        4 => ("identity", IDENTITY),
        5 => ("sshKey", SSH_KEY),
        _ => return None,
    })
}

/// Turns server values into export values: decrypting them, or keeping
/// them as they are.
struct Out<'a> {
    /// `None` keeps the ciphertext.
    key: Option<&'a SymmetricKey>,
}

impl Out<'_> {
    fn value(&self, value: &Value) -> Result<Value, String> {
        let (Some(key), Some(text)) = (self.key, value.as_str()) else {
            return Ok(value.clone());
        };
        match text.parse::<EncString>() {
            Ok(enc) => enc
                .decrypt_text(key)
                .map(Value::String)
                .map_err(|e| format!("a value won't decrypt: {e}")),
            // Dates, ids and other plain text.
            Err(_) => Ok(value.clone()),
        }
    }

    fn object(&self, raw: &Value, keys: &[&str]) -> Result<Value, String> {
        let mut out = Map::new();
        for &key in keys {
            // A decrypted export has no checksums to check.
            if key == "uriChecksum" && self.key.is_some() {
                continue;
            }
            let Some(value) = raw.get(key) else { continue };
            let value = match key {
                "uris" => self.list(value, URI)?,
                "fido2Credentials" => self.list(value, PASSKEY)?,
                "fields" => self.list(value, FIELD)?,
                "passwordHistory" => self.list(value, PAST_PASSWORD)?,
                _ => self.value(value)?,
            };
            out.insert(key.to_string(), value);
        }
        Ok(Value::Object(out))
    }

    fn list(&self, value: &Value, keys: &[&str]) -> Result<Value, String> {
        match value.as_array() {
            Some(items) => items
                .iter()
                .map(|item| self.object(item, keys))
                .collect::<Result<Vec<_>, _>>()
                .map(Value::Array),
            None => Ok(Value::Null),
        }
    }
}

fn str_at<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    value
        .get(key)
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
}

/// The user's own items, not in the Trash.
fn own_items(sync: &Value) -> impl Iterator<Item = &Value> {
    sync.get("ciphers")
        .and_then(Value::as_array)
        .map_or(&[][..], Vec::as_slice)
        .iter()
        .filter(|c| str_at(c, "organizationId").is_none())
        .filter(|c| c.get("deletedDate").is_none_or(Value::is_null))
}

fn folders(sync: &Value) -> &[Value] {
    sync.get("folders")
        .and_then(Value::as_array)
        .map_or(&[], Vec::as_slice)
}

/// One item for a JSON export, decrypted (with `user`) or not (`None`).
fn item(cipher: &Value, user: Option<&SymmetricKey>) -> Result<Value, String> {
    let item_key = match (user, str_at(cipher, "key")) {
        (Some(user), Some(sealed)) => Some(
            sealed
                .parse::<EncString>()
                .and_then(|enc| enc.decrypt(user))
                .and_then(|bytes| SymmetricKey::from_bytes(&bytes))
                .map_err(|e| format!("an item's key won't open: {e}"))?,
        ),
        _ => None,
    };
    let out = Out {
        key: item_key.as_ref().or(user),
    };
    let mut item = out.object(cipher, ITEM)?;
    let kind = cipher.get("type").and_then(Value::as_u64).unwrap_or(0);
    if let Some((name, keys)) = kind_object(kind) {
        if let Some(raw) = cipher.get(name).filter(|v| v.is_object()) {
            item[name] = out.object(raw, keys)?;
        }
    }
    item["collectionIds"] = Value::Null;
    // An encrypted export keeps the sealed item key; it's what opens the rest.
    if user.is_none() {
        if let Some(key) = cipher.get("key").filter(|k| k.is_string()) {
            item["key"] = key.clone();
        }
    }
    Ok(item)
}

fn folder(raw: &Value, user: Option<&SymmetricKey>) -> Result<Value, String> {
    let out = Out { key: user };
    Ok(json!({
        "id": raw.get("id").cloned().unwrap_or(Value::Null),
        "name": out.value(raw.get("name").unwrap_or(&Value::Null))?,
    }))
}

fn pretty(value: &Value) -> Zeroizing<String> {
    Zeroizing::new(serde_json::to_string_pretty(value).expect("JSON"))
}

/// Bitwarden's decrypted JSON export.
pub fn json(sync: &Value, user: &SymmetricKey) -> Result<Zeroizing<String>, String> {
    let folders = folders(sync)
        .iter()
        .map(|f| folder(f, Some(user)))
        .collect::<Result<Vec<_>, _>>()?;
    let items = own_items(sync)
        .map(|c| item(c, Some(user)))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(pretty(
        &json!({ "encrypted": false, "folders": folders, "items": items }),
    ))
}

/// Bitwarden's encrypted JSON export, which only this account opens.
pub fn account_json(sync: &Value, user: &SymmetricKey) -> Result<Zeroizing<String>, String> {
    let folders = folders(sync)
        .iter()
        .map(|f| folder(f, None))
        .collect::<Result<Vec<_>, _>>()?;
    let items = own_items(sync)
        .map(|c| item(c, None))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(pretty(&json!({
        "encrypted": true,
        "encKeyValidation_DO_NOT_EDIT": user.encrypt_text(&uuid::Uuid::new_v4().to_string()),
        "folders": folders,
        "items": items,
    })))
}

/// The decrypted JSON export, encrypted with a key made from `password`
/// with the account's KDF.
pub fn password_json(clear: &str, password: &str, kdf: Kdf) -> Result<Zeroizing<String>, String> {
    let mut salt = [0u8; 16];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut salt);
    let salt = base64::engine::general_purpose::STANDARD.encode(salt);
    let key = MasterKey::derive_with_salt(password, &salt, kdf)
        .map_err(|e| e.to_string())?
        .stretch();
    let mut doc = json!({
        "encrypted": true,
        "passwordProtected": true,
        "salt": salt,
        "encKeyValidation_DO_NOT_EDIT": key.encrypt_text(&uuid::Uuid::new_v4().to_string()),
        "data": key.encrypt_text(clear),
    });
    match kdf {
        Kdf::Pbkdf2 { iterations } => {
            doc["kdfType"] = json!(0);
            doc["kdfIterations"] = json!(iterations);
        }
        Kdf::Argon2id {
            iterations,
            memory_mib,
            parallelism,
        } => {
            doc["kdfType"] = json!(1);
            doc["kdfIterations"] = json!(iterations);
            doc["kdfMemory"] = json!(memory_mib);
            doc["kdfParallelism"] = json!(parallelism);
        }
    }
    Ok(pretty(&doc))
}

/// A CSV cell, quoted when it has to be.
fn cell(text: &str) -> String {
    let quote =
        text.contains([',', '"', '\n', '\r']) || text.starts_with(' ') || text.ends_with(' ');
    if quote {
        format!("\"{}\"", text.replace('"', "\"\""))
    } else {
        text.to_string()
    }
}

/// Bitwarden's CSV export: logins and secure notes only.
pub fn csv(sync: &Value, user: &SymmetricKey) -> Result<Zeroizing<String>, String> {
    let folder_names: Vec<(String, String)> = folders(sync)
        .iter()
        .filter_map(|f| {
            let folder = folder(f, Some(user)).ok()?;
            Some((
                folder["id"].as_str()?.to_string(),
                folder["name"].as_str()?.to_string(),
            ))
        })
        .collect();
    let mut out = Zeroizing::new(String::from(
        "folder,favorite,type,name,notes,fields,reprompt,archivedDate,login_uri,login_username,login_password,login_totp\r\n",
    ));
    for cipher in own_items(sync) {
        let kind = match cipher.get("type").and_then(Value::as_u64) {
            Some(1) => "login",
            Some(2) => "note",
            _ => continue,
        };
        let item = item(cipher, Some(user))?;
        let text = |v: &Value| v.as_str().unwrap_or_default().to_string();
        let folder = str_at(cipher, "folderId")
            .and_then(|id| folder_names.iter().find(|(f, _)| f == id))
            .map(|(_, name)| name.clone())
            .unwrap_or_default();
        let fields = item["fields"]
            .as_array()
            .map(|fields| {
                fields
                    .iter()
                    .map(|f| format!("{}: {}", text(&f["name"]), text(&f["value"])))
                    .collect::<Vec<_>>()
                    .join("\n")
            })
            .unwrap_or_default();
        let login = &item["login"];
        let uris = login["uris"]
            .as_array()
            .map(|uris| {
                uris.iter()
                    .map(|u| text(&u["uri"]))
                    .collect::<Vec<_>>()
                    .join(",")
            })
            .unwrap_or_default();
        let row = [
            folder,
            if item["favorite"] == json!(true) {
                "1".into()
            } else {
                String::new()
            },
            kind.into(),
            text(&item["name"]),
            text(&item["notes"]),
            fields,
            item["reprompt"].as_u64().unwrap_or(0).to_string(),
            text(&item["archivedDate"]),
            uris,
            text(&login["username"]),
            text(&login["password"]),
            text(&login["totp"]),
        ];
        let line = Zeroizing::new(row.iter().map(|c| cell(c)).collect::<Vec<_>>().join(","));
        out.push_str(&line);
        out.push_str("\r\n");
    }
    Ok(out)
}

/// The export in `format`; `password` is the file's own, for
/// [`Format::PasswordJson`].
pub fn build(
    sync: &Value,
    user: &SymmetricKey,
    format: Format,
    password: &str,
    kdf: Kdf,
) -> Result<Zeroizing<String>, String> {
    match format {
        Format::Json => json(sync, user),
        Format::Csv => csv(sync, user),
        Format::AccountJson => account_json(sync, user),
        Format::PasswordJson => password_json(&json(sync, user)?, password, kdf),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn enc(key: &SymmetricKey, text: &str) -> String {
        key.encrypt_text(text)
    }

    fn sync(user: &SymmetricKey, item_key: &SymmetricKey) -> Value {
        let org = SymmetricKey::generate();
        json!({
            "folders": [{ "id": "f1", "name": enc(user, "Work, mostly"), "revisionDate": "x" }],
            "ciphers": [
                {
                    "id": "c1", "type": 1, "folderId": "f1", "favorite": true, "reprompt": 0,
                    "organizationId": null, "edit": true, "viewPassword": true,
                    "name": enc(user, "GitHub"), "notes": null,
                    "login": {
                        "username": enc(user, "octocat"), "password": enc(user, "pa\"ss"),
                        "totp": null, "passwordRevisionDate": "2026-01-01T00:00:00Z",
                        "uris": [
                            { "uri": enc(user, "https://github.com"), "uriChecksum": enc(user, "sum"), "match": null },
                            { "uri": enc(user, "github.io"), "match": 1 }
                        ]
                    },
                    "fields": [{ "name": enc(user, "PIN"), "value": enc(user, "4321"), "type": 1, "linkedId": null }],
                    "passwordHistory": [{ "password": enc(user, "old"), "lastUsedDate": "2025-01-01T00:00:00Z" }],
                    "attachments": [{ "id": "a1" }],
                    "creationDate": "2025-01-01T00:00:00Z", "revisionDate": "2026-01-01T00:00:00Z",
                    "deletedDate": null
                },
                {
                    "id": "c2", "type": 3, "favorite": false, "reprompt": 1,
                    "key": user.encrypt(&item_key.to_bytes()).to_string(),
                    "name": enc(item_key, "Visa"),
                    "card": { "number": enc(item_key, "4111"), "code": enc(item_key, "123") }
                },
                { "id": "c3", "type": 2, "name": enc(user, "Trashed"), "secureNote": { "type": 0 },
                  "deletedDate": "2026-01-01T00:00:00Z" },
                { "id": "c4", "type": 2, "organizationId": "o1", "name": enc(&org, "Shared"),
                  "secureNote": { "type": 0 } }
            ]
        })
    }

    #[test]
    fn decrypted_json_is_bitwardens() {
        let (user, item_key) = (SymmetricKey::generate(), SymmetricKey::generate());
        let out: Value =
            serde_json::from_str(&json(&sync(&user, &item_key), &user).unwrap()).unwrap();
        assert_eq!(out["encrypted"], json!(false));
        assert_eq!(
            out["folders"],
            json!([{ "id": "f1", "name": "Work, mostly" }])
        );
        let items = out["items"].as_array().unwrap();
        // Not the Trash, not the organization's.
        assert_eq!(items.len(), 2);
        let github = &items[0];
        assert_eq!(github["name"], "GitHub");
        assert_eq!(github["login"]["password"], "pa\"ss");
        assert_eq!(
            github["login"]["uris"],
            json!([{ "uri": "https://github.com", "match": null }, { "uri": "github.io", "match": 1 }])
        );
        assert_eq!(github["fields"][0]["value"], "4321");
        assert_eq!(github["passwordHistory"][0]["password"], "old");
        assert_eq!(github["collectionIds"], Value::Null);
        for gone in ["attachments", "edit", "viewPassword", "key"] {
            assert!(github.get(gone).is_none(), "{gone}");
        }
        assert!(github["login"].get("passwordRevisionDate").is_none());
        let visa = &items[1];
        assert_eq!(visa["card"]["number"], "4111");
        assert!(visa.get("key").is_none());
    }

    #[test]
    fn encrypted_json_keeps_the_ciphertext() {
        let (user, item_key) = (SymmetricKey::generate(), SymmetricKey::generate());
        let raw = sync(&user, &item_key);
        let out: Value = serde_json::from_str(&account_json(&raw, &user).unwrap()).unwrap();
        let check: EncString = out["encKeyValidation_DO_NOT_EDIT"]
            .as_str()
            .unwrap()
            .parse()
            .unwrap();
        assert!(check.decrypt_text(&user).is_ok());
        assert_eq!(out["folders"][0]["name"], raw["folders"][0]["name"]);
        assert_eq!(
            out["items"][0]["login"]["uris"][0],
            raw["ciphers"][0]["login"]["uris"][0]
        );
        assert_eq!(out["items"][1]["key"], raw["ciphers"][1]["key"]);
    }

    #[test]
    fn password_protected_json_opens_with_its_password() {
        let (user, item_key) = (SymmetricKey::generate(), SymmetricKey::generate());
        let kdf = Kdf::Pbkdf2 { iterations: 5000 };
        let clear = json(&sync(&user, &item_key), &user).unwrap();
        let out: Value =
            serde_json::from_str(&password_json(&clear, "file pass", kdf).unwrap()).unwrap();
        assert_eq!(out["kdfType"], json!(0));
        assert!(out.get("kdfMemory").is_none());
        let key = MasterKey::derive_with_salt("file pass", out["salt"].as_str().unwrap(), kdf)
            .unwrap()
            .stretch();
        let data: EncString = out["data"].as_str().unwrap().parse().unwrap();
        assert_eq!(data.decrypt_text(&key).unwrap(), *clear);
    }

    #[test]
    fn csv_has_logins_and_notes() {
        let (user, item_key) = (SymmetricKey::generate(), SymmetricKey::generate());
        let out = csv(&sync(&user, &item_key), &user).unwrap();
        let lines: Vec<&str> = out.split("\r\n").collect();
        assert_eq!(lines.len(), 3, "{lines:?}");
        assert_eq!(
            lines[1],
            "\"Work, mostly\",1,login,GitHub,,PIN: 4321,0,,\"https://github.com,github.io\",octocat,\"pa\"\"ss\","
        );
    }
}
