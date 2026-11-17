//! The decrypted vault: what a sync holds, opened with the account's keys.
//!
//! Each item is decrypted on its own; one that won't open is kept, marked,
//! and counted, so a single damaged entry never hides the rest of the vault.

use crate::crypto::{EncString, PrivateKey, SymmetricKey};
use serde_json::Value;
use std::collections::HashMap;
use zeroize::Zeroizing;

/// Decrypted text that may be secret. Zeroed when dropped.
pub type Secret = Zeroizing<String>;

/// The keys that open a vault: the user key, and each organisation's key.
pub struct Keys {
    pub user: SymmetricKey,
    pub orgs: HashMap<String, SymmetricKey>,
}

impl Keys {
    /// Open the organisation keys in a sync's profile with the account's
    /// private key.
    pub fn new(user: SymmetricKey, sync: &Value, private_key: Option<&str>) -> Self {
        let mut keys = Self {
            user,
            orgs: HashMap::new(),
        };
        let private_key = sync
            .pointer("/profile/privateKey")
            .and_then(Value::as_str)
            .or(private_key);
        let Some(private_key) = private_key else {
            return keys;
        };
        let private = private_key
            .parse::<EncString>()
            .and_then(|enc| enc.decrypt(&keys.user))
            .and_then(|der| PrivateKey::from_der(&der));
        let private = match private {
            Ok(private) => private,
            Err(error) => {
                log::warn!("cannot open the account's private key: {error}");
                return keys;
            }
        };
        for org in array(sync.pointer("/profile/organizations")) {
            let (Some(id), Some(key)) = (str_at(org, "id"), str_at(org, "key")) else {
                continue;
            };
            match key
                .parse::<EncString>()
                .and_then(|enc| enc.decrypt_rsa(&private))
                .and_then(|bytes| SymmetricKey::from_bytes(&bytes))
            {
                Ok(key) => {
                    keys.orgs.insert(id.to_string(), key);
                }
                Err(error) => log::warn!("cannot open the key of organisation {id}: {error}"),
            }
        }
        keys
    }

    /// The key that owns an item: its organisation's, or the user key.
    pub fn for_org(&self, org: Option<&str>) -> Option<&SymmetricKey> {
        match org {
            Some(org) => self.orgs.get(org),
            None => Some(&self.user),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Organization {
    pub id: String,
    pub name: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Folder {
    pub id: String,
    pub name: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Collection {
    pub id: String,
    pub org_id: String,
    pub name: String,
    /// The account may see its items but not add to it.
    pub read_only: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Kind {
    Login,
    Note,
    Card,
    Identity,
    SshKey,
}

impl Kind {
    fn from_number(n: u64) -> Option<Self> {
        Some(match n {
            1 => Self::Login,
            2 => Self::Note,
            3 => Self::Card,
            4 => Self::Identity,
            5 => Self::SshKey,
            _ => return None,
        })
    }

    /// Bitwarden's number for the type.
    pub fn number(self) -> u64 {
        match self {
            Self::Login => 1,
            Self::Note => 2,
            Self::Card => 3,
            Self::Identity => 4,
            Self::SshKey => 5,
        }
    }

    /// The key of the type's own object in an item.
    pub fn object(self) -> &'static str {
        match self {
            Self::Login => "login",
            Self::Note => "secureNote",
            Self::Card => "card",
            Self::Identity => "identity",
            Self::SshKey => "sshKey",
        }
    }

    pub const ALL: [Kind; 5] = [
        Kind::Login,
        Kind::Card,
        Kind::Identity,
        Kind::Note,
        Kind::SshKey,
    ];

    pub fn label(self) -> &'static str {
        match self {
            Self::Login => "Login",
            Self::Note => "Secure note",
            Self::Card => "Card",
            Self::Identity => "Identity",
            Self::SshKey => "SSH key",
        }
    }

    pub fn plural(self) -> &'static str {
        match self {
            Self::Login => "Logins",
            Self::Note => "Secure Notes",
            Self::Card => "Cards",
            Self::Identity => "Identities",
            Self::SshKey => "SSH Keys",
        }
    }

    pub fn icon(self) -> &'static str {
        match self {
            Self::Login => "dialog-password-symbolic",
            Self::Note => "text-x-generic-symbolic",
            Self::Card => "auth-smartcard-symbolic",
            Self::Identity => "contact-new-symbolic",
            Self::SshKey => "network-server-symbolic",
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct Uri {
    pub uri: String,
}

impl Uri {
    /// The host to show and to fetch an icon for, when the URI has one.
    pub fn host(&self) -> Option<String> {
        let text = self.uri.trim();
        let parsed = url::Url::parse(text)
            .ok()
            .filter(|u| u.has_host())
            .or_else(|| url::Url::parse(&format!("https://{text}")).ok())?;
        matches!(parsed.scheme(), "http" | "https")
            .then(|| parsed.host_str().map(str::to_string))
            .flatten()
            .filter(|host| host.contains('.') || host == "localhost")
    }

    /// The address to open in a browser.
    pub fn launch_url(&self) -> Option<String> {
        let text = self.uri.trim();
        if text.starts_with("http://") || text.starts_with("https://") {
            Some(text.to_string())
        } else {
            self.host().map(|_| format!("https://{text}"))
        }
    }
}

#[derive(Clone, Default)]
pub struct Login {
    pub username: Option<String>,
    pub password: Option<Secret>,
    pub totp: Option<Secret>,
    pub uris: Vec<Uri>,
    pub password_revision: Option<String>,
    /// How many passkeys the login holds; Vord can't use them, only say so.
    pub passkeys: usize,
}

#[derive(Clone, Default)]
pub struct Card {
    pub cardholder: Option<String>,
    pub brand: Option<String>,
    pub number: Option<Secret>,
    pub exp_month: Option<String>,
    pub exp_year: Option<String>,
    pub code: Option<Secret>,
}

impl Card {
    /// "Visa, *1234"
    pub fn summary(&self) -> Option<String> {
        let last4 = self.number.as_ref().and_then(|n| {
            let digits: String = n.chars().filter(char::is_ascii_digit).collect();
            (digits.len() >= 4).then(|| format!("*{}", &digits[digits.len() - 4..]))
        });
        match (self.brand.as_deref(), last4) {
            (Some(brand), Some(last4)) => Some(format!("{brand}, {last4}")),
            (Some(brand), None) => Some(brand.to_string()),
            (None, last4) => last4,
        }
    }

    pub fn expiry(&self) -> Option<String> {
        match (self.exp_month.as_deref(), self.exp_year.as_deref()) {
            (Some(m), Some(y)) => Some(format!("{:0>2} / {y}", m)),
            (None, Some(y)) => Some(y.to_string()),
            (Some(m), None) => Some(format!("{:0>2}", m)),
            (None, None) => None,
        }
    }
}

/// An identity's fields, in the order they're shown, with their labels.
#[derive(Clone, Default)]
pub struct Identity {
    pub fields: Vec<(&'static str, Secret)>,
    pub full_name: Option<String>,
    pub address: Option<String>,
}

#[derive(Clone, Default)]
pub struct SshKey {
    pub private_key: Option<Secret>,
    pub public_key: Option<String>,
    pub fingerprint: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FieldKind {
    Text,
    Hidden,
    Boolean,
    Linked,
}

#[derive(Clone)]
pub struct Field {
    pub name: String,
    pub value: Secret,
    pub kind: FieldKind,
}

#[derive(Clone)]
pub struct Attachment {
    pub id: String,
    pub name: String,
    /// "1.2 MB", as the server puts it.
    pub size: Option<String>,
}

/// A password the item had before, or a hidden field's earlier value
/// ("name: value").
#[derive(Clone)]
pub struct PastPassword {
    pub password: Secret,
    pub until: Option<String>,
}

#[derive(Clone)]
pub struct Item {
    pub id: String,
    pub org_id: Option<String>,
    pub folder_id: Option<String>,
    pub collection_ids: Vec<String>,
    pub kind: Kind,
    pub name: String,
    pub notes: Option<Secret>,
    pub favorite: bool,
    pub deleted: bool,
    /// Ask for the master password again before showing secrets.
    pub reprompt: bool,
    pub created: Option<String>,
    pub revised: Option<String>,
    pub login: Option<Login>,
    pub card: Option<Card>,
    pub identity: Option<Identity>,
    pub ssh_key: Option<SshKey>,
    pub fields: Vec<Field>,
    pub attachments: Vec<Attachment>,
    /// Newest first.
    pub password_history: Vec<PastPassword>,
    /// Some field would not decrypt; what showed is what opened.
    pub damaged: bool,
    /// Whether this account may change it (an organization can say no).
    pub edit: bool,
}

impl Item {
    /// The second line under the name in the list.
    pub fn subtitle(&self) -> Option<String> {
        match self.kind {
            Kind::Login => self.login.as_ref().and_then(|l| {
                l.username
                    .clone()
                    .filter(|u| !u.is_empty())
                    .or_else(|| l.uris.iter().find_map(Uri::host))
            }),
            Kind::Card => self.card.as_ref().and_then(Card::summary),
            Kind::Identity => self.identity.as_ref().and_then(|i| i.full_name.clone()),
            Kind::SshKey => self.ssh_key.as_ref().and_then(|k| k.fingerprint.clone()),
            Kind::Note => self.notes.as_ref().map(|n| {
                let first = n.lines().find(|l| !l.trim().is_empty()).unwrap_or("");
                first.chars().take(80).collect()
            }),
        }
    }

    /// The website an icon should come from.
    pub fn icon_host(&self) -> Option<String> {
        self.login
            .as_ref()
            .and_then(|l| l.uris.iter().find_map(Uri::host))
    }

    /// What a search looks through, lower-cased: name, subtitle (username,
    /// card, ...), websites and the type.
    pub fn search_text(&self) -> String {
        let mut text = self.name.to_lowercase();
        if let Some(sub) = self.subtitle() {
            text.push('\n');
            text.push_str(&sub.to_lowercase());
        }
        if let Some(login) = &self.login {
            for uri in &login.uris {
                text.push('\n');
                text.push_str(&uri.uri.to_lowercase());
            }
        }
        text.push('\n');
        text.push_str(&self.kind.label().to_lowercase());
        text
    }
}

/// Whether every word of `query` appears in a [`Item::search_text`].
pub fn search_matches(haystack: &str, query: &str) -> bool {
    query
        .to_lowercase()
        .split_whitespace()
        .all(|word| haystack.contains(word))
}

pub struct Vault {
    pub organizations: Vec<Organization>,
    pub folders: Vec<Folder>,
    pub collections: Vec<Collection>,
    pub items: Vec<Item>,
    /// Items with at least one field that would not decrypt.
    pub damaged: usize,
    /// Each item as the server sent it, still encrypted: an edit starts
    /// from it, so what Vord doesn't model survives a save.
    pub raw: HashMap<String, Value>,
    /// The account's id on the server.
    pub user_id: Option<String>,
}

fn array(value: Option<&Value>) -> &[Value] {
    value.and_then(Value::as_array).map_or(&[], Vec::as_slice)
}

fn str_at<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    value
        .get(key)
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
}

/// Decrypts one item's strings, remembering whether any failed.
struct Opener<'a> {
    key: Option<&'a SymmetricKey>,
    failed: bool,
}

impl Opener<'_> {
    fn secret(&mut self, value: &Value, field: &str) -> Option<Secret> {
        let text = str_at(value, field)?;
        let Some(key) = self.key else {
            self.failed = true;
            return None;
        };
        match text
            .parse::<EncString>()
            .and_then(|enc| enc.decrypt_text(key))
        {
            Ok(plain) => Some(Zeroizing::new(plain)),
            Err(_) => {
                self.failed = true;
                None
            }
        }
    }

    fn text(&mut self, value: &Value, field: &str) -> Option<String> {
        self.secret(value, field).map(|s| s.to_string())
    }
}

fn decrypt_name(text: Option<&str>, key: Option<&SymmetricKey>) -> Option<String> {
    let key = key?;
    text?.parse::<EncString>().ok()?.decrypt_text(key).ok()
}

impl Vault {
    pub fn open(sync: &Value, keys: &Keys) -> Self {
        let organizations = array(sync.pointer("/profile/organizations"))
            .iter()
            .filter_map(|org| {
                Some(Organization {
                    id: str_at(org, "id")?.to_string(),
                    // Organisation names are plain text.
                    name: str_at(org, "name").unwrap_or("Organization").to_string(),
                })
            })
            .collect();

        let mut folders: Vec<Folder> = array(sync.get("folders"))
            .iter()
            .filter_map(|folder| {
                let id = str_at(folder, "id")?.to_string();
                let name = decrypt_name(str_at(folder, "name"), Some(&keys.user))
                    .unwrap_or_else(|| "Unreadable folder".into());
                Some(Folder { id, name })
            })
            .collect();
        folders.sort_by_key(|f| f.name.to_lowercase());

        let mut collections: Vec<Collection> = array(sync.get("collections"))
            .iter()
            .filter_map(|collection| {
                let id = str_at(collection, "id")?.to_string();
                let org_id = str_at(collection, "organizationId")?.to_string();
                let name = decrypt_name(str_at(collection, "name"), keys.orgs.get(&org_id))
                    .unwrap_or_else(|| "Unreadable collection".into());
                let read_only = collection
                    .get("readOnly")
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
                Some(Collection {
                    id,
                    org_id,
                    name,
                    read_only,
                })
            })
            .collect();
        collections.sort_by_key(|c| c.name.to_lowercase());

        let mut items: Vec<Item> = array(sync.get("ciphers"))
            .iter()
            .filter_map(|cipher| open_item(cipher, keys))
            .collect();
        items.sort_by_cached_key(|i| i.name.to_lowercase());
        let damaged = items.iter().filter(|i| i.damaged).count();
        if damaged > 0 {
            log::warn!("{damaged} item(s) did not fully decrypt");
        }
        let raw = array(sync.get("ciphers"))
            .iter()
            .filter_map(|cipher| Some((str_at(cipher, "id")?.to_string(), cipher.clone())))
            .collect();
        Self {
            organizations,
            folders,
            collections,
            items,
            damaged,
            raw,
            user_id: sync
                .pointer("/profile/id")
                .and_then(Value::as_str)
                .map(str::to_string),
        }
    }

    pub fn item(&self, id: &str) -> Option<&Item> {
        self.items.iter().find(|i| i.id == id)
    }

    /// An item as the server sent it, still encrypted.
    pub fn raw(&self, id: &str) -> Option<&Value> {
        self.raw.get(id)
    }
}

fn open_item(cipher: &Value, keys: &Keys) -> Option<Item> {
    let id = str_at(cipher, "id")?.to_string();
    let kind = Kind::from_number(cipher.get("type")?.as_u64()?)?;
    let org_id = str_at(cipher, "organizationId").map(str::to_string);

    // A per-item key, when the item has one, is sealed with the owner's key.
    let owner_key = keys.for_org(org_id.as_deref());
    let item_key = str_at(cipher, "key").and_then(|sealed| {
        let key = owner_key?;
        let bytes = sealed.parse::<EncString>().ok()?.decrypt(key).ok()?;
        SymmetricKey::from_bytes(&bytes).ok()
    });
    let item_key_failed = str_at(cipher, "key").is_some() && item_key.is_none();
    let mut open = Opener {
        key: item_key
            .as_ref()
            .or(if item_key_failed { None } else { owner_key }),
        failed: false,
    };

    let name = open
        .text(cipher, "name")
        .unwrap_or_else(|| "Unreadable item".into());
    let notes = open.secret(cipher, "notes");

    let login = cipher
        .get("login")
        .filter(|l| l.is_object())
        .map(|l| Login {
            username: open.text(l, "username"),
            password: open.secret(l, "password"),
            totp: open.secret(l, "totp"),
            uris: array(l.get("uris"))
                .iter()
                .filter_map(|u| open.text(u, "uri"))
                .map(|uri| Uri { uri })
                .collect(),
            password_revision: str_at(l, "passwordRevisionDate").map(str::to_string),
            passkeys: array(l.get("fido2Credentials")).len(),
        });

    let card = cipher.get("card").filter(|c| c.is_object()).map(|c| Card {
        cardholder: open.text(c, "cardholderName"),
        brand: open.text(c, "brand"),
        number: open.secret(c, "number"),
        exp_month: open.text(c, "expMonth"),
        exp_year: open.text(c, "expYear"),
        code: open.secret(c, "code"),
    });

    let identity = cipher.get("identity").filter(|i| i.is_object()).map(|i| {
        let mut get = |field| open.secret(i, field);
        let title = get("title");
        let first = get("firstName");
        let middle = get("middleName");
        let last = get("lastName");
        let address: Vec<Secret> = ["address1", "address2", "address3"]
            .into_iter()
            .filter_map(&mut get)
            .collect();
        let city = get("city");
        let state = get("state");
        let postal = get("postalCode");
        let country = get("country");
        let mut fields = Vec::new();
        let full_name = [&title, &first, &middle, &last]
            .iter()
            .filter_map(|p| p.as_deref().map(String::as_str))
            .collect::<Vec<_>>()
            .join(" ");
        let full_name = (!full_name.is_empty()).then_some(full_name);
        for (label, field) in [
            ("Username", "username"),
            ("Company", "company"),
            ("Email", "email"),
            ("Phone", "phone"),
            ("Social security number", "ssn"),
            ("Passport number", "passportNumber"),
            ("License number", "licenseNumber"),
        ] {
            if let Some(value) = get(field) {
                fields.push((label, value));
            }
        }
        let mut lines: Vec<String> = address.iter().map(|a| a.to_string()).collect();
        let locality = [city.as_deref(), state.as_deref(), postal.as_deref()]
            .into_iter()
            .flatten()
            .map(String::as_str)
            .collect::<Vec<_>>()
            .join(", ");
        if !locality.is_empty() {
            lines.push(locality);
        }
        if let Some(country) = country {
            lines.push(country.to_string());
        }
        let address = (!lines.is_empty()).then(|| lines.join("\n"));
        Identity {
            fields,
            full_name,
            address,
        }
    });

    let ssh_key = cipher
        .get("sshKey")
        .filter(|k| k.is_object())
        .map(|k| SshKey {
            private_key: open.secret(k, "privateKey"),
            public_key: open.text(k, "publicKey"),
            fingerprint: open.text(k, "keyFingerprint"),
        });

    let fields = array(cipher.get("fields"))
        .iter()
        .map(|f| Field {
            name: open.text(f, "name").unwrap_or_default(),
            value: open.secret(f, "value").unwrap_or_default(),
            kind: match f.get("type").and_then(Value::as_u64) {
                Some(1) => FieldKind::Hidden,
                Some(2) => FieldKind::Boolean,
                Some(3) => FieldKind::Linked,
                _ => FieldKind::Text,
            },
        })
        .collect();

    let attachments = array(cipher.get("attachments"))
        .iter()
        .filter_map(|a| {
            Some(Attachment {
                id: str_at(a, "id")?.to_string(),
                name: open
                    .text(a, "fileName")
                    .unwrap_or_else(|| "Attachment".into()),
                size: str_at(a, "sizeName").map(str::to_string),
            })
        })
        .collect();

    Some(Item {
        id,
        folder_id: str_at(cipher, "folderId").map(str::to_string),
        collection_ids: array(cipher.get("collectionIds"))
            .iter()
            .filter_map(|c| c.as_str().map(str::to_string))
            .collect(),
        kind,
        name,
        notes,
        favorite: cipher
            .get("favorite")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        deleted: cipher.get("deletedDate").is_some_and(|d| !d.is_null()),
        reprompt: cipher.get("reprompt").and_then(Value::as_u64).unwrap_or(0) == 1,
        created: str_at(cipher, "creationDate").map(str::to_string),
        revised: str_at(cipher, "revisionDate").map(str::to_string),
        login,
        card,
        identity,
        ssh_key,
        fields,
        attachments,
        password_history: array(cipher.get("passwordHistory"))
            .iter()
            .filter_map(|p| {
                Some(PastPassword {
                    password: open.secret(p, "password")?,
                    until: str_at(p, "lastUsedDate").map(str::to_string),
                })
            })
            .collect(),
        damaged: open.failed || item_key_failed,
        edit: cipher.get("edit").and_then(Value::as_bool).unwrap_or(true),
        org_id,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn enc(key: &SymmetricKey, text: &str) -> String {
        key.encrypt(text.as_bytes()).to_string()
    }

    #[test]
    fn opens_items_folders_and_item_keys() {
        let user = SymmetricKey::generate();
        let item_key = SymmetricKey::generate();
        let sync = json!({
            "profile": { "organizations": [] },
            "folders": [{ "id": "f1", "name": enc(&user, "Work") }],
            "collections": [],
            "ciphers": [
                {
                    "id": "c1", "type": 1, "folderId": "f1", "favorite": true,
                    "name": enc(&user, "GitHub"),
                    "login": {
                        "username": enc(&user, "octocat"),
                        "password": enc(&user, "s3cret"),
                        "uris": [{ "uri": enc(&user, "https://github.com/login"), "match": null }]
                    },
                    "fields": [{ "name": enc(&user, "PIN"), "value": enc(&user, "1234"), "type": 1 }]
                },
                {
                    "id": "c2", "type": 3,
                    "key": user.encrypt(&item_key.to_bytes()).to_string(),
                    "name": enc(&item_key, "Visa"),
                    "card": { "brand": enc(&item_key, "Visa"), "number": enc(&item_key, "4111 1111 1111 1234") },
                    "deletedDate": "2026-01-01T00:00:00Z"
                },
                { "id": "c3", "type": 2, "name": "2.AAAAAAAAAAAAAAAAAAAAAA==|AAAA|AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" },
                { "id": "c4", "type": 99, "name": enc(&user, "future type") }
            ]
        });
        let keys = Keys::new(user, &sync, None);
        let vault = Vault::open(&sync, &keys);
        assert_eq!(vault.folders[0].name, "Work");
        assert_eq!(vault.items.len(), 3);
        assert_eq!(vault.damaged, 1);

        let github = vault.item("c1").unwrap();
        assert!(github.favorite && !github.deleted && !github.damaged);
        assert_eq!(github.subtitle().as_deref(), Some("octocat"));
        assert_eq!(github.icon_host().as_deref(), Some("github.com"));
        assert_eq!(github.fields[0].kind, FieldKind::Hidden);
        assert_eq!(&*github.fields[0].value, "1234");
        let text = github.search_text();
        assert!(search_matches(&text, "Git OCTO"));
        assert!(search_matches(&text, "github.com/login"));
        assert!(search_matches(&text, ""));
        assert!(!search_matches(&text, "gitlab"));

        let visa = vault.item("c2").unwrap();
        assert!(visa.deleted);
        assert_eq!(visa.subtitle().as_deref(), Some("Visa, *1234"));

        let broken = vault.item("c3").unwrap();
        assert!(broken.damaged);
        assert_eq!(broken.name, "Unreadable item");
    }

    #[test]
    fn uri_hosts() {
        let host = |u: &str| Uri { uri: u.into() }.host();
        assert_eq!(
            host("https://accounts.google.com/x").as_deref(),
            Some("accounts.google.com")
        );
        assert_eq!(host("example.org").as_deref(), Some("example.org"));
        assert_eq!(host("androidapp://com.example"), None);
        assert_eq!(host("not a url"), None);
        assert_eq!(
            Uri {
                uri: "example.org/login".into()
            }
            .launch_url()
            .as_deref(),
            Some("https://example.org/login")
        );
    }
}
