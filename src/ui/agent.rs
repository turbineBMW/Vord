//! The SSH agent's side in the window: which keys it offers, asking the
//! user before one is used, and handing over the private key for that one
//! signature.
//!
//! The public halves (and the items' names) stay after locking, so `ssh`
//! can still offer a key; using one then raises Vord to be unlocked first.
//! Logging out forgets them.

use super::Ui;
use crate::agent::{self, Identity, Request};
use crate::settings;
use crate::vault::{Kind, Vault};
use adw::prelude::*;
use gtk::glib;
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
            if let Some(ui) = super::LIVE_UI.with(|w| w.borrow().upgrade()) {
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
}

/// Logged out: nothing to offer.
pub fn forget(ui: &Ui) {
    ui.agent_keys.borrow_mut().clear();
    ui.agent_allowed.borrow_mut().clear();
    ui.agent_waiting.borrow_mut().clear();
}

/// Locked: what was allowed until now needs asking again.
pub fn locked(ui: &Ui) {
    ui.agent_allowed.borrow_mut().clear();
}

/// Unlocked: answer what waited for it.
pub fn unlocked(ui: &Rc<Ui>) {
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
        Request::List(reply) => {
            let keys = ui
                .agent_keys
                .borrow()
                .iter()
                .map(|k| Identity {
                    blob: k.blob.clone(),
                    comment: k.name.clone(),
                })
                .collect();
            let _ = reply.send(keys);
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
            } else {
                ui.toast(&format!(
                    "Unlock Vord to let {process} use the SSH key “{}”",
                    key.name
                ));
                ui.agent_waiting.borrow_mut().push(Waiting {
                    since: std::time::Instant::now(),
                    key,
                    process,
                    reply,
                });
                ui.window.present();
            }
        }
    }
}

/// Ask (as the settings say) before a key is used.
fn approve(ui: &Rc<Ui>, key: AgentKey, process: String, reply: mpsc::Sender<Zeroizing<String>>) {
    let ask = settings::get().ssh_agent_ask;
    let allowed = ask == 2 || (ask == 1 && ui.agent_allowed.borrow().contains(&key.item_id));
    if allowed {
        return hand_over(ui, &key, reply);
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
