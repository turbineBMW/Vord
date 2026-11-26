//! Bitwarden Secrets Manager: an organization's secrets and projects.
//!
//! None of it comes with the vault sync. Each organization the account may
//! use Secrets Manager in has its own lists: its secrets (names only),
//! its projects, and, for its owners and admins, its trash. A secret's
//! value and note come one secret at a time (`GET /api/secrets/{id}`), as
//! in Bitwarden's web app: every fetch is in the organization's event log,
//! so values are fetched when one is shown, not on every sync.
//!
//! Names, values, notes and project names are encrypted with the
//! organization's key (EncString type 2). A secret is in at most one
//! project. Nothing here is kept on disk.

use crate::crypto::{EncString, SymmetricKey};
use crate::vault::Secret;
use serde_json::{json, Value};
use std::collections::HashMap;
use zeroize::Zeroizing;

/// An organization the account may use Secrets Manager in.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SmOrg {
    pub id: String,
    pub name: String,
    /// An owner or admin: sees every secret, and the trash.
    pub admin: bool,
}

/// The organizations in a sync's profile with Secrets Manager on for this
/// account.
pub fn organizations(sync: &Value) -> Vec<SmOrg> {
    let flag = |org: &Value, key: &str| org.get(key).and_then(Value::as_bool).unwrap_or(false);
    let mut orgs: Vec<SmOrg> = sync
        .pointer("/profile/organizations")
        .and_then(Value::as_array)
        .map_or(&[][..], Vec::as_slice)
        .iter()
        .filter(|org| {
            flag(org, "useSecretsManager")
                && flag(org, "accessSecretsManager")
                && org.get("enabled").and_then(Value::as_bool) != Some(false)
        })
        .filter_map(|org| {
            Some(SmOrg {
                id: str_at(org, "id")?.to_string(),
                name: str_at(org, "name").unwrap_or("Organization").to_string(),
                // OrganizationUserType: 0 owner, 1 admin.
                admin: matches!(org.get("type").and_then(Value::as_u64), Some(0 | 1)),
            })
        })
        .collect();
    orgs.sort_by_key(|o| o.name.to_lowercase());
    orgs
}

/// One organization's lists, as the server sent them (still encrypted).
#[derive(Clone, Debug, PartialEq)]
pub struct RawOrg {
    pub org: SmOrg,
    /// `GET /api/organizations/{id}/secrets`.
    pub secrets: Value,
    /// `GET /api/organizations/{id}/projects`.
    pub projects: Value,
    /// `GET /api/secrets/{id}/trash`, for owners and admins.
    pub trash: Option<Value>,
}

#[derive(Clone, Debug)]
pub struct Project {
    pub id: String,
    pub org_id: String,
    pub name: String,
    /// Whether this account may change it and put secrets in it.
    pub write: bool,
}

/// A secret as the lists show it: its name and project, not its value.
#[derive(Clone, Debug)]
pub struct SecretRow {
    pub id: String,
    pub org_id: String,
    pub name: String,
    pub project: Option<String>,
    pub revised: Option<String>,
    pub write: bool,
    /// In the trash.
    pub deleted: bool,
    /// Its name would not decrypt.
    pub damaged: bool,
}

impl SecretRow {
    pub fn search_text(&self, project: Option<&str>) -> String {
        format!("{} {}", self.name, project.unwrap_or_default()).to_lowercase()
    }
}

/// Every Secrets Manager organization's secrets and projects, decrypted.
#[derive(Debug, Default)]
pub struct Secrets {
    pub orgs: Vec<SmOrg>,
    /// By name.
    pub projects: Vec<Project>,
    /// Live and trashed, by name.
    pub secrets: Vec<SecretRow>,
}

impl Secrets {
    pub fn open(raw: &[RawOrg], keys: &HashMap<String, SymmetricKey>) -> Self {
        let mut opened = Self::default();
        for org in raw {
            let key = keys.get(&org.org.id);
            if key.is_none() {
                log::warn!(
                    "no key for organization {}; its secrets stay closed",
                    org.org.id
                );
            }
            opened.orgs.push(org.org.clone());
            for project in array(org.projects.get("data")) {
                let Some(id) = str_at(project, "id") else {
                    continue;
                };
                opened.projects.push(Project {
                    id: id.to_string(),
                    org_id: org.org.id.clone(),
                    name: decrypt(str_at(project, "name"), key)
                        .map_or_else(|| "Unreadable project".into(), |n| n.to_string()),
                    write: flag(project, "write"),
                });
            }
            // A secret's own list names its project, which a member may
            // not otherwise see.
            for listed in [&org.secrets, org.trash.as_ref().unwrap_or(&Value::Null)] {
                for project in array(listed.get("projects")) {
                    let Some(id) = str_at(project, "id") else {
                        continue;
                    };
                    if opened.projects.iter().any(|p| p.id == id) {
                        continue;
                    }
                    opened.projects.push(Project {
                        id: id.to_string(),
                        org_id: org.org.id.clone(),
                        name: decrypt(str_at(project, "name"), key)
                            .map_or_else(|| "Unreadable project".into(), |n| n.to_string()),
                        write: false,
                    });
                }
            }
            let rows = |list: &Value, deleted: bool| -> Vec<SecretRow> {
                array(list.get("secrets"))
                    .iter()
                    .filter_map(|secret| {
                        let name = decrypt(str_at(secret, "key"), key);
                        Some(SecretRow {
                            id: str_at(secret, "id")?.to_string(),
                            org_id: org.org.id.clone(),
                            damaged: name.is_none(),
                            name: name
                                .map_or_else(|| "Unreadable secret".into(), |n| n.to_string()),
                            project: array(secret.get("projects"))
                                .first()
                                .and_then(|p| str_at(p, "id"))
                                .map(str::to_string),
                            revised: str_at(secret, "revisionDate").map(str::to_string),
                            // The trash list has no permissions: only
                            // admins see it, and they may change anything.
                            write: deleted || flag(secret, "write"),
                            deleted,
                        })
                    })
                    .collect()
            };
            opened.secrets.extend(rows(&org.secrets, false));
            if let Some(trash) = &org.trash {
                opened.secrets.extend(rows(trash, true));
            }
        }
        opened
            .projects
            .sort_by_cached_key(|p| p.name.to_lowercase());
        opened.secrets.sort_by_cached_key(|s| s.name.to_lowercase());
        opened
    }

    pub fn secret(&self, id: &str) -> Option<&SecretRow> {
        self.secrets.iter().find(|s| s.id == id)
    }

    pub fn project(&self, id: &str) -> Option<&Project> {
        self.projects.iter().find(|p| p.id == id)
    }

    pub fn org(&self, id: &str) -> Option<&SmOrg> {
        self.orgs.iter().find(|o| o.id == id)
    }

    /// The name of a secret's project, if it has one.
    pub fn project_name(&self, secret: &SecretRow) -> Option<&str> {
        secret
            .project
            .as_deref()
            .and_then(|id| self.project(id))
            .map(|p| p.name.as_str())
    }
}

/// One secret, opened: what `GET /api/secrets/{id}` answers, decrypted.
pub struct Opened {
    pub id: String,
    pub org_id: String,
    pub name: Secret,
    pub value: Secret,
    pub note: Secret,
    pub project: Option<String>,
    pub created: Option<String>,
    pub revised: Option<String>,
    pub write: bool,
}

impl std::fmt::Debug for Opened {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Opened")
            .field("id", &self.id)
            .field("org_id", &self.org_id)
            .finish_non_exhaustive()
    }
}

impl Opened {
    pub fn open(body: &Value, key: &SymmetricKey) -> Result<Self, String> {
        let field = |name: &str| -> Result<Secret, String> {
            match str_at(body, name) {
                None => Ok(Secret::default()),
                Some(text) => text
                    .parse::<EncString>()
                    .and_then(|enc| enc.decrypt_text(key))
                    .map(Zeroizing::new)
                    .map_err(|e| format!("the secret's {name} would not decrypt: {e}")),
            }
        };
        Ok(Self {
            id: str_at(body, "id")
                .ok_or("the server's answer had no id")?
                .to_string(),
            org_id: str_at(body, "organizationId")
                .unwrap_or_default()
                .to_string(),
            name: field("key")?,
            value: field("value")?,
            note: field("note")?,
            project: array(body.get("projects"))
                .first()
                .and_then(|p| str_at(p, "id"))
                .map(str::to_string),
            created: str_at(body, "creationDate").map(str::to_string),
            revised: str_at(body, "revisionDate").map(str::to_string),
            write: flag(body, "write"),
        })
    }

    pub fn draft(&self) -> Draft {
        Draft {
            name: self.name.clone(),
            value: self.value.clone(),
            note: self.note.clone(),
            project: self.project.clone(),
        }
    }
}

/// A secret as an editor holds it. No `Debug`: it holds the value.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct Draft {
    pub name: Secret,
    pub value: Secret,
    pub note: Secret,
    pub project: Option<String>,
}

impl Draft {
    /// Why it can't be saved, if it can't. Bitwarden's apps want a name
    /// and a value.
    pub fn problem(&self) -> Option<&'static str> {
        if self.name.trim().is_empty() {
            Some("Give the secret a name.")
        } else if self.value.is_empty() {
            Some("Give the secret a value.")
        } else {
            None
        }
    }
}

/// The body that creates a secret or saves one, as Bitwarden's web app
/// sends it. `value_changed` asks the server to keep the old value in the
/// secret's history.
pub fn request(draft: &Draft, key: &SymmetricKey, value_changed: bool) -> Value {
    json!({
        "key": key.encrypt_text(draft.name.trim()),
        "value": key.encrypt_text(&draft.value),
        "note": key.encrypt_text(&draft.note),
        "projectIds": draft.project.iter().collect::<Vec<_>>(),
        "valueChanged": value_changed,
        "accessPoliciesRequests": null,
    })
}

/// The body that creates or renames a project.
pub fn project_request(name: &str, key: &SymmetricKey) -> Value {
    json!({ "name": key.encrypt_text(name.trim()) })
}

/// What a bulk delete says went wrong, if anything did.
pub fn bulk_errors(answer: &Value) -> Option<String> {
    let errors: Vec<&str> = array(answer.get("data"))
        .iter()
        .filter_map(|result| str_at(result, "error"))
        .collect();
    (!errors.is_empty()).then(|| format!("The server refused: {}.", errors.join(", ")))
}

fn decrypt(text: Option<&str>, key: Option<&SymmetricKey>) -> Option<Secret> {
    let plain = text?.parse::<EncString>().ok()?.decrypt_text(key?).ok()?;
    Some(Zeroizing::new(plain))
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

fn flag(value: &Value, key: &str) -> bool {
    value.get(key).and_then(Value::as_bool).unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> SymmetricKey {
        SymmetricKey::from_bytes(&[7u8; 64]).unwrap()
    }

    #[test]
    fn organizations_with_secrets_manager() {
        let sync = serde_json::json!({ "profile": { "organizations": [
            { "id": "a", "name": "Work", "type": 2, "useSecretsManager": true, "accessSecretsManager": true },
            { "id": "b", "name": "Family", "type": 0, "useSecretsManager": true, "accessSecretsManager": false },
            { "id": "c", "name": "Test", "type": 0, "useSecretsManager": true, "accessSecretsManager": true },
            { "id": "d", "name": "Old", "type": 0, "useSecretsManager": true,
              "accessSecretsManager": true, "enabled": false },
        ] } });
        let orgs = organizations(&sync);
        assert_eq!(
            orgs.iter()
                .map(|o| (o.id.as_str(), o.admin))
                .collect::<Vec<_>>(),
            [("c", true), ("a", false)]
        );
    }

    #[test]
    fn lists_open_with_the_org_key() {
        let key = key();
        let org = SmOrg {
            id: "o".into(),
            name: "Test".into(),
            admin: true,
        };
        let raw = [RawOrg {
            org: org.clone(),
            secrets: crate::api::camel(json!({
                "Secrets": [
                    { "Id": "s2", "Key": key.encrypt_text("b secret"), "Projects": [{ "Id": "p1", "Name": key.encrypt_text("Web") }], "Write": true },
                    { "Id": "s1", "Key": key.encrypt_text("A secret"), "Projects": [], "Write": false },
                    { "Id": "s3", "Key": "2.garbage|x|y", "Projects": null },
                ],
                "Projects": [{ "Id": "p1", "Name": key.encrypt_text("Web") }],
            })),
            projects: json!({ "data": [
                { "id": "p1", "name": key.encrypt_text("Web"), "write": true },
                { "id": "p2", "name": key.encrypt_text("Empty"), "write": true },
            ] }),
            trash: Some(json!({ "secrets": [
                { "id": "t1", "key": key.encrypt_text("Gone"), "projects": [] },
            ] })),
        }];
        let keys = HashMap::from([("o".to_string(), key.clone())]);
        let secrets = Secrets::open(&raw, &keys);
        let names: Vec<_> = secrets.secrets.iter().map(|s| s.name.as_str()).collect();
        assert_eq!(names, ["A secret", "b secret", "Gone", "Unreadable secret"]);
        let b = secrets.secret("s2").unwrap();
        assert_eq!(secrets.project_name(b), Some("Web"));
        assert!(b.write && !b.deleted);
        assert!(secrets.secret("t1").unwrap().deleted);
        assert!(secrets.secret("s3").unwrap().damaged);
        let projects: Vec<_> = secrets.projects.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(projects, ["Empty", "Web"]);
    }

    #[test]
    fn a_saved_secret_opens_again() {
        let key = key();
        let draft = Draft {
            name: Zeroizing::new(" DB_PASSWORD ".into()),
            value: Zeroizing::new("hunter2\nline two".into()),
            note: Zeroizing::new(String::new()),
            project: Some("p1".into()),
        };
        let body = request(&draft, &key, true);
        assert_eq!(body["projectIds"], json!(["p1"]));
        assert_eq!(body["valueChanged"], json!(true));
        // The server answers with what it was sent, and more.
        let mut answer = body.clone();
        answer["id"] = json!("s1");
        answer["organizationId"] = json!("o");
        answer["projects"] = json!([{ "id": "p1", "name": "x" }]);
        answer["write"] = json!(true);
        let opened = Opened::open(&answer, &key).unwrap();
        assert_eq!(opened.name.as_str(), "DB_PASSWORD");
        assert_eq!(opened.value.as_str(), "hunter2\nline two");
        assert_eq!(opened.note.as_str(), "");
        assert_eq!(opened.project.as_deref(), Some("p1"));
        let wrong = SymmetricKey::from_bytes(&[8u8; 64]).unwrap();
        assert!(Opened::open(&answer, &wrong).is_err());

        let none = Draft {
            project: None,
            ..draft
        };
        assert_eq!(request(&none, &key, false)["projectIds"], json!([]));
        assert!(Draft::default().problem().is_some());
    }

    #[test]
    fn bulk_delete_errors() {
        let fine = json!({ "data": [{ "id": "a", "error": "" }] });
        assert_eq!(bulk_errors(&fine), None);
        let refused = json!({ "data": [{ "id": "a", "error": "access denied" }] });
        assert_eq!(
            bulk_errors(&refused).as_deref(),
            Some("The server refused: access denied.")
        );
    }
}
