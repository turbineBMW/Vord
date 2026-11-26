//! The SSH agent's side in the window: which keys it offers, asking the
//! user before one is used, and handing over the private key for that one
//! signature.
//!
//! The public halves (and the items' names) stay after locking, so `ssh`
//! can still offer a key; using one then raises Vord to be unlocked first.
//! Logging out forgets them. Before the first unlock nothing is known (no
//! decrypted name or key is kept on disk), so a request for the list waits
//! for that unlock.
//!
//! With "Ask in the password dialog" on, the unlock (PIN or master password)
//! and Allow/Deny go through `$SSH_ASKPASS` (see `askpass.rs`), and the window
//! stays where it is, hidden or not.

use super::Ui;
use crate::agent::{self, Identity, Request};
use crate::settings;
use crate::vault::{Kind, Vault};
use adw::prelude::*;
use gtk::{gio, glib};
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc};
use zeroize::Zeroizing;

/// A key the agent offers.
#[derive(Clone)]
pub struct AgentKey {
    pub blob: Vec<u8>,
    pub name: String,
    pub item_id: String,
}

/// A request for the key list that waits for the first unlock.
pub struct Listing {
    since: std::time::Instant,
    reply: mpsc::Sender<Vec<Identity>>,
}

/// After the unlock dialog is cancelled, requests are refused without asking
/// for this long, so a retrying program doesn't bring the dialog straight back.
const QUIET: std::time::Duration = std::time::Duration::from_secs(30);

/// A request to sign that waits for the vault to be unlocked.
pub struct Waiting {
    since: std::time::Instant,
    key: AgentKey,
    process: String,
    reply: mpsc::Sender<Zeroizing<String>>,
}

/// Start listening, if the user turned the agent on.
pub fn start(ui: &Rc<Ui>) {
    if !settings::get().ssh_agent || ui.agent.borrow().is_some() {
        return;
    }
    let stop: Arc<AtomicBool> = Default::default();
    let started = agent::serve(stop.clone(), |request| {
        glib::idle_add_once(move || {
            if let Some(ui) = super::THE_UI.with(|w| w.borrow().upgrade()) {
                on_request(&ui, request);
            }
        });
    });
    match started {
        Ok(path) => {
            log::info!("ssh agent: listening on {}", path.display());
            ui.agent.replace(Some(stop));
        }
        Err(error) => {
            log::warn!("ssh agent: could not start: {error}");
            ui.toast(&format!("The SSH agent couldn't start: {error}"));
        }
    }
}

pub fn stop(ui: &Ui) {
    if let Some(stop) = ui.agent.take() {
        stop.store(true, Ordering::Relaxed);
    }
    ui.agent_waiting.borrow_mut().clear();
    ui.agent_listing.borrow_mut().clear();
}

/// The askpass program, when the user chose to be asked through it.
fn askpass() -> Option<std::path::PathBuf> {
    settings::get()
        .ssh_agent_askpass
        .then(crate::askpass::program)
        .flatten()
}

/// The SSH keys in a vault just shown.
pub fn refresh_keys(ui: &Ui, vault: &Vault) {
    let keys = vault
        .items
        .iter()
        .filter(|i| i.kind == Kind::SshKey && !i.deleted && !i.damaged)
        .filter_map(|item| {
            let public = item.ssh_key.as_ref()?.public_key.as_deref()?;
            Some(AgentKey {
                blob: agent::public_blob(public)?,
                name: item.name.clone(),
                item_id: item.id.clone(),
            })
        })
        .collect();
    ui.agent_keys.replace(keys);
    ui.agent_keys_known.set(true);
}

/// Logged out (or switched account): nothing to offer.
pub fn forget(ui: &Ui) {
    ui.agent_keys.borrow_mut().clear();
    ui.agent_keys_known.set(false);
    ui.agent_allowed.borrow_mut().clear();
    ui.agent_waiting.borrow_mut().clear();
    ui.agent_listing.borrow_mut().clear();
}

fn identities(ui: &Ui) -> Vec<Identity> {
    ui.agent_keys
        .borrow()
        .iter()
        .map(|k| Identity {
            blob: k.blob.clone(),
            comment: k.name.clone(),
        })
        .collect()
}

/// Locked: what was allowed until now needs asking again.
pub fn locked(ui: &Ui) {
    ui.agent_allowed.borrow_mut().clear();
}

/// Unlocked: answer what waited for it.
pub fn unlocked(ui: &Rc<Ui>) {
    ui.agent_quiet_until.set(None);
    let listing: Vec<Listing> = ui.agent_listing.take();
    for request in listing
        .into_iter()
        .filter(|l| l.since.elapsed() < agent::WAIT)
    {
        let _ = request.reply.send(identities(ui));
    }
    let waiting: Vec<Waiting> = ui.agent_waiting.take();
    // One that waited longer than its program did has nobody to answer.
    for request in waiting
        .into_iter()
        .filter(|w| w.since.elapsed() < agent::WAIT)
    {
        approve(ui, request.key, request.process, request.reply);
    }
}

fn on_request(ui: &Rc<Ui>, request: Request) {
    match request {
        Request::List { process, reply } => {
            let unknown =
                !ui.agent_keys_known.get() && !ui.is_unlocked() && ui.account.borrow().is_some();
            if !unknown || quiet(ui) {
                let _ = reply.send(identities(ui));
                return;
            }
            // Locked since Vord started: which keys there are is in the
            // encrypted vault. Answer once it opens.
            ui.agent_listing.borrow_mut().push(Listing {
                since: std::time::Instant::now(),
                reply,
            });
            need_unlock(ui, &format!("{process} wants the vault's SSH keys"));
        }
        Request::Sign {
            blob,
            process,
            reply,
        } => {
            let Some(key) = ui
                .agent_keys
                .borrow()
                .iter()
                .find(|k| k.blob == blob)
                .cloned()
            else {
                // Not one of Vord's keys: the reply drops, a refusal.
                return;
            };
            if ui.is_unlocked() {
                approve(ui, key, process, reply);
            } else if quiet(ui) {
                // The unlock was just cancelled: the reply drops, a refusal.
            } else {
                let why = format!("{process} wants to sign with the SSH key “{}”", key.name);
                ui.agent_waiting.borrow_mut().push(Waiting {
                    since: std::time::Instant::now(),
                    key,
                    process,
                    reply,
                });
                need_unlock(ui, &why);
            }
        }
    }
}

/// Whether the unlock dialog was cancelled a moment ago.
fn quiet(ui: &Ui) -> bool {
    ui.agent_quiet_until
        .get()
        .is_some_and(|until| std::time::Instant::now() < until)
}

/// The vault must open before a request can be answered: ask through
/// askpass, or bring up the window.
fn need_unlock(ui: &Rc<Ui>, why: &str) {
    match askpass() {
        Some(program) => {
            if !ui.agent_asking.get() {
                ask_unlock(ui, program, why.to_string(), None);
            }
        }
        None => {
            ui.toast(&format!("Unlock Vord: {why}"));
            ui.window.present();
        }
    }
}

/// Ask for the PIN (or, without one, the master password) through askpass
/// and unlock with it; ask again after a wrong one. Cancelling refuses what
/// waits and keeps quiet for a while.
fn ask_unlock(ui: &Rc<Ui>, program: std::path::PathBuf, why: String, error: Option<String>) {
    let Some(email) = ui.account.borrow().as_ref().map(|a| a.email.clone()) else {
        return refuse_waiting(ui);
    };
    let pin = ui.pin_sealed.borrow().is_some();
    let prompt = if pin {
        "Vord PIN"
    } else {
        "Vord master password"
    };
    let mut reason = format!("{why}. Unlock Vord ({email}) to let it.");
    if let Some(error) = error {
        reason = format!("{error} {reason}");
    }
    ui.agent_asking.set(true);
    let weak = Rc::downgrade(ui);
    glib::spawn_future_local(async move {
        let asked = program.clone();
        let answer = gio::spawn_blocking(move || crate::askpass::secret(&asked, prompt, &reason))
            .await
            .ok()
            .flatten();
        let Some(ui) = weak.upgrade() else { return };
        if ui.is_unlocked() {
            // Unlocked in the window meanwhile; `unlocked` answered.
            ui.agent_asking.set(false);
            return;
        }
        let Some(secret) = answer else {
            ui.agent_asking.set(false);
            return refuse_waiting(&ui);
        };
        let weak = Rc::downgrade(&ui);
        let done = move |result: Result<(), String>| {
            let Some(ui) = weak.upgrade() else { return };
            match result {
                // `opened` ran `unlocked`, which answered what waited.
                Ok(()) => ui.agent_asking.set(false),
                Err(message) => ask_unlock(&ui, program, why, Some(message)),
            }
        };
        let secret = secret.to_string();
        if pin {
            ui.unlock_with_pin(secret, done);
        } else {
            ui.unlock(secret, done);
        }
    });
}

/// The unlock was cancelled: refuse what waits for it (dropping the replies)
/// and don't ask again for a while.
fn refuse_waiting(ui: &Ui) {
    ui.agent_waiting.borrow_mut().clear();
    ui.agent_listing.borrow_mut().clear();
    ui.agent_quiet_until
        .set(Some(std::time::Instant::now() + QUIET));
}

/// Ask (as the settings say) before a key is used.
fn approve(ui: &Rc<Ui>, key: AgentKey, process: String, reply: mpsc::Sender<Zeroizing<String>>) {
    let ask = settings::get().ssh_agent_ask;
    let allowed = ask == 2 || (ask == 1 && ui.agent_allowed.borrow().contains(&key.item_id));
    if allowed {
        return hand_over(ui, &key, reply);
    }
    if let Some(program) = askpass() {
        let reason = format!(
            "{process} wants to sign with the SSH key “{}”.{}",
            key.name,
            if ask == 1 {
                " Vord won't ask again for this key until the vault locks."
            } else {
                ""
            }
        );
        let weak = Rc::downgrade(ui);
        let epoch = ui.epoch.get();
        glib::spawn_future_local(async move {
            let yes = gio::spawn_blocking(move || {
                crate::askpass::confirm(&program, "Use SSH key?", &reason)
            })
            .await
            .unwrap_or(false);
            let Some(ui) = weak.upgrade().filter(|ui| ui.epoch.get() == epoch) else {
                return;
            };
            if !yes {
                return;
            }
            if settings::get().ssh_agent_ask == 1 {
                ui.agent_allowed.borrow_mut().insert(key.item_id.clone());
            }
            hand_over(&ui, &key, reply);
        });
        return;
    }
    let dialog = adw::AlertDialog::new(
        Some("Use SSH Key?"),
        Some(&format!(
            "{process} wants to sign with “{}”.{}",
            key.name,
            if ask == 1 {
                " Vord won't ask again for this key until the vault locks."
            } else {
                ""
            }
        )),
    );
    dialog.add_responses(&[("deny", "_Deny"), ("allow", "_Allow")]);
    dialog.set_response_appearance("allow", adw::ResponseAppearance::Suggested);
    dialog.set_default_response(Some("allow"));
    dialog.set_close_response("deny");
    let weak = Rc::downgrade(ui);
    let epoch = ui.epoch.get();
    // The reply moves out once; a refusal or a lock just drops it.
    let reply = std::cell::RefCell::new(Some(reply));
    dialog.connect_response(Some("allow"), move |_, _| {
        let (Some(ui), Some(reply)) = (
            weak.upgrade().filter(|ui| ui.epoch.get() == epoch),
            reply.take(),
        ) else {
            return;
        };
        if settings::get().ssh_agent_ask == 1 {
            ui.agent_allowed.borrow_mut().insert(key.item_id.clone());
        }
        hand_over(&ui, &key, reply);
    });
    ui.window.present();
    ui.present_dialog(&dialog);
}

/// Give the connection the private key, after the master password for an
/// item that asks for it.
fn hand_over(ui: &Rc<Ui>, key: &AgentKey, reply: mpsc::Sender<Zeroizing<String>>) {
    let Some(item) = ui
        .vault
        .current_vault()
        .and_then(|v| v.item(&key.item_id).cloned())
    else {
        return;
    };
    let Some(private) = item.ssh_key.and_then(|k| k.private_key) else {
        return;
    };
    let private = Zeroizing::new(private.to_string());
    if item.reprompt {
        let reply = std::cell::RefCell::new(Some(reply));
        ui.reprompt(&item.id, move || {
            if let Some(reply) = reply.take() {
                let _ = reply.send(private.clone());
            }
        });
    } else {
        let _ = reply.send(private);
    }
}
