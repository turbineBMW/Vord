//! The window: a stack of the login page, the unlock page and the vault, and
//! the state behind them.
//!
//! Locked, Vord holds only what's on disk (all encrypted). Unlocked, it holds
//! the keys and the decrypted vault in [`Ui::session`]; locking drops both,
//! empties every widget that showed decrypted text, and clears a copied
//! secret from the clipboard.
//!
//! Key derivation and network calls run on worker threads
//! (`gio::spawn_blocking`); their results come back to the main loop, which
//! is the only place state and widgets change. A result that arrives after
//! the vault was locked again is dropped (see [`Ui::epoch`]).

mod detail;
mod editor;
mod export;
mod generator;
mod pages;
mod prefs;
mod send;
mod vault;

use crate::crypto::SymmetricKey;
use crate::edit;
use crate::session;
use crate::settings;
use crate::store::{self, Account};
use crate::vault::{Keys, Vault};
use adw::prelude::*;
use gtk::{gio, glib};
use std::cell::{Cell, RefCell};
use std::rc::Rc;
use std::sync::Arc;
use std::time::Duration;

thread_local! {
    /// Mirrors [`Ui::is_unlocked`] for code outside the window.
    pub static UNLOCKED: Cell<bool> = const { Cell::new(false) };
}

/// How often an unlocked vault syncs on its own.
const AUTO_SYNC: Duration = Duration::from_secs(10 * 60);

/// What only an unlocked vault has. The decrypted vault itself lives in
/// the view that shows it.
pub struct Session {
    pub keys: Keys,
    /// What was copied from the generator, oldest first.
    pub generated: Vec<generator::Generated>,
}

pub struct Ui {
    pub window: adw::ApplicationWindow,
    toasts: adw::ToastOverlay,
    stack: gtk::Stack,
    login: pages::LoginPage,
    two_factor: pages::TwoFactorPage,
    unlock: pages::UnlockPage,
    vault: vault::VaultView,
    account: RefCell<Option<Account>>,
    session: RefCell<Option<Session>>,
    /// A login waiting for its second step. Shared with the worker that
    /// tries a code; a result for any other login is dropped.
    pending: RefCell<Option<Arc<session::PendingLogin>>>,
    /// Bumped on every lock, so work started before it is thrown away.
    epoch: Cell<u64>,
    syncing: Cell<bool>,
    lock_timer: RefCell<Option<glib::SourceId>>,
    sync_timer: RefCell<Option<glib::SourceId>>,
    /// The reprompt item whose secrets the master password was re-entered
    /// for. Cleared when another item is shown.
    reprompt_passed: RefCell<Option<String>>,
    /// The generator dialog, while it's open.
    generator: RefCell<Option<adw::Dialog>>,
    /// Other dialogs over an unlocked vault (confirmations, folder
    /// names); locking closes them.
    dialogs: RefCell<Vec<glib::WeakRef<adw::Dialog>>>,
}

pub fn build(app: &adw::Application) -> Rc<Ui> {
    let window = adw::ApplicationWindow::builder()
        .application(app)
        .title("Vord")
        .default_width(1180)
        .default_height(760)
        .width_request(360)
        .height_request(360)
        .build();
    let stack = gtk::Stack::builder()
        .transition_type(gtk::StackTransitionType::Crossfade)
        .build();
    let toasts = adw::ToastOverlay::new();
    toasts.set_child(Some(&stack));
    window.set_content(Some(&toasts));

    let login = pages::LoginPage::new();
    let two_factor = pages::TwoFactorPage::new();
    let unlock = pages::UnlockPage::new();
    let vault = vault::VaultView::new();
    stack.add_named(&login.root, Some("login"));
    stack.add_named(&two_factor.root, Some("two-factor"));
    stack.add_named(&unlock.root, Some("unlock"));
    stack.add_named(&vault.root, Some("vault"));
    vault.add_breakpoints(&window);

    let ui = Rc::new(Ui {
        window,
        toasts,
        stack,
        login,
        two_factor,
        unlock,
        vault,
        account: RefCell::new(None),
        session: RefCell::new(None),
        pending: RefCell::new(None),
        epoch: Cell::new(0),
        syncing: Cell::new(false),
        lock_timer: RefCell::new(None),
        sync_timer: RefCell::new(None),
        reprompt_passed: RefCell::new(None),
        generator: RefCell::new(None),
        dialogs: RefCell::new(Vec::new()),
    });
    ui.login.connect(&ui);
    ui.two_factor.connect(&ui);
    ui.unlock.connect(&ui);
    ui.vault.connect(&ui);
    ui.add_actions(app);
    ui.watch_focus();
    crate::sidebar::sync(&ui.window);
    {
        let weak = Rc::downgrade(&ui);
        crate::screenlock::watch(move || {
            if let Some(ui) = weak.upgrade() {
                if settings::get().lock_with_screen && ui.is_unlocked() {
                    log::info!("the session locked; locking the vault");
                    ui.lock();
                }
                // A half-done login holds the master key; don't leave it
                // waiting behind a locked screen.
                if ui.pending.borrow().is_some() {
                    log::info!("the session locked; dropping the unfinished login");
                    ui.cancel_two_factor();
                }
            }
        });
    }
    ui.start();
    ui.window.present();
    ui
}

impl Ui {
    fn start(self: &Rc<Self>) {
        match Account::load() {
            Some(account) => {
                self.unlock.show_account(&account);
                self.account.replace(Some(account));
                self.show_page("unlock");
            }
            None => {
                let settings = settings::get();
                self.login
                    .prefill(&settings.last_server, &settings.last_email);
                self.show_page("login");
            }
        }
    }

    fn show_page(&self, name: &str) {
        self.stack.set_visible_child_name(name);
        let vault = name == "vault";
        for action in [
            "lock",
            "sync",
            "generator",
            "search",
            "edit-item",
            "clone-item",
            "add-attachment",
            "favorite",
            "trash-item",
            "restore-item",
            "purge-item",
            "new-item",
            "new-folder",
            "rename-folder",
            "delete-folder",
            "save-item",
            "cancel-edit",
            "copy-username",
            "copy-password",
            "copy-totp",
            "open-website",
        ] {
            self.set_action_enabled(action, vault);
        }
        self.set_action_enabled("logout", matches!(name, "unlock" | "vault"));
        match name {
            "login" => self.login.focus(),
            "two-factor" => self.two_factor.focus(),
            "unlock" => self.unlock.focus(),
            _ => {}
        }
        if vault {
            self.vault.update_item_actions(self);
        }
    }

    pub fn set_action_enabled(&self, name: &str, enabled: bool) {
        if let Some(action) = self
            .window
            .lookup_action(name)
            .and_downcast::<gio::SimpleAction>()
        {
            action.set_enabled(enabled);
        }
    }

    pub fn is_unlocked(&self) -> bool {
        self.session.borrow().is_some()
    }

    pub fn server(&self) -> Option<String> {
        self.account.borrow().as_ref().map(|a| a.server.clone())
    }

    pub fn toast(&self, text: &str) {
        let toast = adw::Toast::builder().title(text).timeout(3).build();
        self.toasts.add_toast(toast);
    }

    /// Copy, say so, and say when it will be cleared.
    pub fn copy(&self, what: &str, text: &str, secret: bool) {
        let clear = settings::get().clear_clipboard_seconds;
        crate::clipboard::copy(&self.window, text, secret, clear);
        let message = if secret && clear > 0 {
            format!("{what} copied · clears in {}", duration_text(clear))
        } else {
            format!("{what} copied")
        };
        self.toast(&message);
    }

    // ---- logging in and unlocking -------------------------------------

    fn login(self: &Rc<Self>, server: String, email: String, password: String) {
        let server = match crate::api::normalize_server(&server) {
            Ok(server) => server,
            Err(why) => return self.login.fail(&why),
        };
        if email.trim().is_empty() || !email.contains('@') {
            return self.login.fail("Enter the email address of your account.");
        }
        if password.is_empty() {
            return self.login.fail("Enter your master password.");
        }
        self.login.set_busy(true);
        let ui = self.clone();
        glib::spawn_future_local(async move {
            let result = gio::spawn_blocking(move || {
                Ok::<_, session::Error>(match session::login(&server, &email, &password)? {
                    session::Login::Done(account, user_key) => {
                        let (keys, vault) = session::open_cached(&account, user_key);
                        LoginStep::Opened(account, keys, vault)
                    }
                    session::Login::SecondStep(pending) => LoginStep::SecondStep(pending),
                })
            })
            .await
            .unwrap_or_else(|_| Err(session::Error::Other("The login crashed.".into())));
            ui.login.set_busy(false);
            match result {
                Ok(LoginStep::Opened(account, keys, vault)) => ui.logged_in(account, keys, vault),
                Ok(LoginStep::SecondStep(pending)) => {
                    ui.login.clear_password();
                    let pending = Arc::new(pending);
                    ui.pending.replace(Some(pending.clone()));
                    ui.two_factor.show(&pending);
                    ui.show_page("two-factor");
                    ui.two_factor_method_changed();
                }
                Err(error) => {
                    log::warn!("login failed: {error}");
                    ui.login.fail(&error.to_string());
                }
            }
        });
    }

    /// The server let us in, with or without a second step.
    fn logged_in(self: &Rc<Self>, account: Account, keys: Keys, vault: Option<Vault>) {
        settings::update(|s| {
            s.last_server.clone_from(&account.server);
            s.last_email.clone_from(&account.email);
        });
        self.pending.replace(None);
        self.login.clear_password();
        self.unlock.show_account(&account);
        self.account.replace(Some(account));
        self.opened(keys, vault);
    }

    /// The pending login, if `pending` is still it.
    fn still_pending(&self, pending: &Arc<session::PendingLogin>) -> bool {
        self.pending
            .borrow()
            .as_ref()
            .is_some_and(|current| Arc::ptr_eq(current, pending))
    }

    /// Another method picked (or the page just shown): say what to do, and
    /// email a code if that's the method and none is on its way.
    fn two_factor_method_changed(self: &Rc<Self>) {
        self.two_factor.show_method();
        if self.two_factor.selected_method() == Some(crate::api::TwoFactorMethod::Email)
            && !self.two_factor.email_sent.get()
        {
            self.send_email_code();
        }
        self.two_factor.focus();
    }

    fn send_email_code(self: &Rc<Self>) {
        let Some(pending) = self.pending.borrow().clone() else {
            return;
        };
        self.two_factor.email_sent.set(true);
        self.two_factor.set_sending(true);
        let ui = self.clone();
        glib::spawn_future_local(async move {
            let worker = pending.clone();
            let result = gio::spawn_blocking(move || session::send_email_code(&worker))
                .await
                .unwrap_or_else(|_| Err(session::Error::Other("Sending crashed.".into())));
            if !ui.still_pending(&pending) {
                return;
            }
            ui.two_factor.set_sending(false);
            match result {
                Ok(()) => ui.toast(&match ui.two_factor.email_hint() {
                    Some(address) => format!("Code sent to {address}"),
                    None => "Code sent".to_string(),
                }),
                Err(error) => {
                    log::warn!("could not send a login code: {error}");
                    ui.two_factor.email_sent.set(false);
                    ui.two_factor
                        .fail(&format!("The code could not be sent. {error}"));
                }
            }
        });
    }

    fn second_step(self: &Rc<Self>) {
        let Some(pending) = self.pending.borrow().clone() else {
            return;
        };
        let Some(method) = self.two_factor.selected_method() else {
            return;
        };
        let code = self.two_factor.code();
        if code.trim().is_empty() {
            return self.two_factor.fail("Enter the code.");
        }
        let remember = self.two_factor.remember();
        self.two_factor.set_busy(true);
        let ui = self.clone();
        glib::spawn_future_local(async move {
            let worker = pending.clone();
            let result = gio::spawn_blocking(move || {
                let (account, user_key) = session::second_step(&worker, method, &code, remember)?;
                let (keys, vault) = session::open_cached(&account, user_key);
                Ok::<_, session::Error>((account, keys, vault))
            })
            .await
            .unwrap_or_else(|_| Err(session::Error::Other("The login crashed.".into())));
            if !ui.still_pending(&pending) {
                return;
            }
            ui.two_factor.set_busy(false);
            match result {
                Ok((account, keys, vault)) => ui.logged_in(account, keys, vault),
                Err(error) => {
                    log::warn!("the second login step failed: {error}");
                    ui.two_factor.fail(&error.to_string());
                }
            }
        });
    }

    /// Back to the login page; the half-done login (and its master key)
    /// is dropped.
    fn cancel_two_factor(&self) {
        self.pending.replace(None);
        self.two_factor.set_busy(false);
        if self.stack.visible_child_name().as_deref() == Some("two-factor") {
            self.show_page("login");
        }
    }

    fn unlock(self: &Rc<Self>, password: String) {
        let Some(account) = self.account.borrow().clone() else {
            return;
        };
        if password.is_empty() {
            return;
        }
        self.unlock.set_busy(true);
        let ui = self.clone();
        glib::spawn_future_local(async move {
            let result = gio::spawn_blocking(move || {
                let user_key = session::unlock_key(&account, &password)?;
                Ok::<_, session::Error>(session::open_cached(&account, user_key))
            })
            .await
            .unwrap_or_else(|_| Err(session::Error::Other("Unlocking crashed.".into())));
            ui.unlock.set_busy(false);
            match result {
                Ok((keys, vault)) => {
                    ui.unlock.clear_password();
                    ui.opened(keys, vault);
                }
                Err(error) => {
                    if !matches!(error, session::Error::WrongPassword) {
                        log::warn!("unlock failed: {error}");
                    }
                    ui.unlock.fail(&error.to_string());
                }
            }
        });
    }

    /// Unlocked: show what's cached at once, then sync.
    fn opened(self: &Rc<Self>, keys: Keys, vault: Option<Vault>) {
        let have_cache = vault.is_some();
        let vault = Rc::new(vault.unwrap_or_else(empty_vault));
        self.session.replace(Some(Session {
            keys,
            generated: Vec::new(),
        }));
        UNLOCKED.with(|u| u.set(true));
        self.vault.show_vault(self, vault, !have_cache);
        self.show_page("vault");
        self.sync();
        let weak = Rc::downgrade(self);
        let timer = glib::timeout_add_local(AUTO_SYNC, move || match weak.upgrade() {
            Some(ui) if ui.is_unlocked() => {
                ui.sync();
                glib::ControlFlow::Continue
            }
            Some(ui) => {
                ui.sync_timer.take();
                glib::ControlFlow::Break
            }
            None => glib::ControlFlow::Break,
        });
        if let Some(old) = self.sync_timer.replace(Some(timer)) {
            old.remove();
        }
    }

    pub fn sync(self: &Rc<Self>) {
        if self.syncing.get() || !self.is_unlocked() {
            return;
        }
        let Some(account) = self.account.borrow().clone() else {
            return;
        };
        let user_key: SymmetricKey = match self.session.borrow().as_ref() {
            Some(session) => session.keys.user.clone(),
            None => return,
        };
        self.syncing.set(true);
        self.vault.set_syncing(true);
        let epoch = self.epoch.get();
        let ui = self.clone();
        glib::spawn_future_local(async move {
            let result = gio::spawn_blocking(move || {
                // An unchanged vault isn't redrawn: that would hide revealed
                // secrets and lose the scroll position every ten minutes.
                let before = store::load_vault();
                let (account, sync) = session::sync(account)?;
                let unlocked = (before.as_ref() != Some(&sync))
                    .then(|| session::open_sync(&account, user_key, &sync));
                Ok::<_, session::Error>((account, unlocked))
            })
            .await
            .unwrap_or_else(|_| Err(session::Error::Other("Syncing crashed.".into())));
            ui.syncing.set(false);
            ui.vault.set_syncing(false);
            if ui.epoch.get() != epoch || !ui.is_unlocked() {
                // Locked meanwhile: the account's new tokens still count.
                if let Ok((account, _)) = result {
                    ui.account.replace(Some(account));
                }
                return;
            }
            match result {
                Ok((account, None)) => {
                    ui.account.replace(Some(account));
                    ui.vault.sync_ok();
                }
                Ok((account, Some(unlocked))) => {
                    ui.account.replace(Some(account));
                    let vault = Rc::new(unlocked.vault);
                    // New keys (a rotated key, a new organization); the
                    // rest of the session stays.
                    if let Some(session) = ui.session.borrow_mut().as_mut() {
                        session.keys = unlocked.keys;
                    }
                    ui.vault.show_vault(&ui, vault, false);
                }
                Err(session::Error::Api(crate::api::ApiError::SessionExpired)) => {
                    ui.vault.set_offline(
                        &ui,
                        Some("The server ended this session. Log out and in again to sync."),
                    );
                }
                Err(error) => {
                    log::warn!("sync failed: {error}");
                    ui.vault
                        .set_offline(&ui, Some(&format!("Showing the last synced copy. {error}")));
                }
            }
        });
    }

    pub fn lock(self: &Rc<Self>) {
        if !self.is_unlocked() {
            return;
        }
        self.epoch.set(self.epoch.get() + 1);
        self.vault.clear();
        if let Some(dialog) = self.generator.take() {
            dialog.force_close();
        }
        for dialog in self.dialogs.take() {
            if let Some(dialog) = dialog.upgrade() {
                dialog.force_close();
            }
        }
        self.session.replace(None);
        UNLOCKED.with(|u| u.set(false));
        self.reprompt_passed.replace(None);
        crate::clipboard::clear_now(&self.window);
        for timer in [&self.lock_timer, &self.sync_timer] {
            if let Some(timer) = timer.take() {
                timer.remove();
            }
        }
        self.show_page("unlock");
    }

    fn confirm_logout(self: &Rc<Self>) {
        let dialog = adw::AlertDialog::new(
            Some("Log Out?"),
            Some("Vord forgets this account and its offline copy of the vault. You'll need your master password to log in again."),
        );
        dialog.add_responses(&[("cancel", "_Cancel"), ("logout", "_Log Out")]);
        dialog.set_response_appearance("logout", adw::ResponseAppearance::Destructive);
        dialog.set_default_response(Some("cancel"));
        dialog.set_close_response("cancel");
        let ui = self.clone();
        dialog.connect_response(Some("logout"), move |_, _| ui.logout());
        dialog.present(Some(&self.window));
    }

    fn logout(self: &Rc<Self>) {
        self.lock();
        store::forget();
        if let Some(account) = self.account.take() {
            self.login.prefill(&account.server, &account.email);
        }
        self.show_page("login");
        self.toast("Logged out");
    }

    /// Run `then` once the master password has been re-entered for an item
    /// that asks for it (Bitwarden's "master password re-prompt").
    pub fn reprompt(self: &Rc<Self>, item_id: &str, then: impl Fn() + 'static) {
        if self.reprompt_passed.borrow().as_deref() == Some(item_id) {
            then();
            return;
        }
        let Some(account) = self.account.borrow().clone() else {
            return;
        };
        let entry = gtk::PasswordEntry::builder()
            .show_peek_icon(true)
            .activates_default(true)
            .placeholder_text("Master password")
            .build();
        let error = gtk::Label::builder()
            .css_classes(["form-error", "caption"])
            .visible(false)
            .wrap(true)
            .build();
        let body = gtk::Box::new(gtk::Orientation::Vertical, 8);
        body.append(&entry);
        body.append(&error);
        let dialog = adw::AlertDialog::new(
            Some("Master Password Required"),
            Some("This item is protected. Enter your master password to see or copy its secrets."),
        );
        dialog.set_extra_child(Some(&body));
        dialog.add_responses(&[("cancel", "_Cancel"), ("ok", "_Continue")]);
        dialog.set_response_appearance("ok", adw::ResponseAppearance::Suggested);
        dialog.set_default_response(Some("ok"));
        dialog.set_close_response("cancel");
        // Checked before the dialog closes, so a wrong password can be retyped.
        dialog.set_response_enabled("ok", true);
        let focus = entry.clone();
        let ui = self.clone();
        let item_id = item_id.to_string();
        let then = Rc::new(then);
        dialog.connect_response(Some("ok"), move |dialog, _| {
            let password = entry.text().to_string();
            entry.set_text("");
            let (ui, account, item_id, then, dialog, error) = (
                ui.clone(),
                account.clone(),
                item_id.clone(),
                then.clone(),
                dialog.clone(),
                error.clone(),
            );
            glib::spawn_future_local(async move {
                let ok =
                    gio::spawn_blocking(move || session::unlock_key(&account, &password).is_ok())
                        .await
                        .unwrap_or(false);
                if ok {
                    ui.reprompt_passed.replace(Some(item_id));
                    then();
                } else {
                    error.set_label("Wrong master password.");
                    error.set_visible(true);
                    dialog.present(Some(&ui.window));
                }
            });
        });
        dialog.present(Some(&self.window));
        // Typing goes to the password, not to the Continue button.
        dialog.set_focus(Some(&focus));
    }

    pub fn reprompt_cleared_for(&self, item_id: &str) -> bool {
        self.reprompt_passed.borrow().as_deref() == Some(item_id)
    }

    pub fn forget_reprompt(&self) {
        self.reprompt_passed.replace(None);
    }

    // ---- changing the vault ---------------------------------------------

    /// Show a dialog over the vault; locking closes it.
    fn present_dialog(&self, dialog: &impl IsA<adw::Dialog>) {
        let mut dialogs = self.dialogs.borrow_mut();
        dialogs.retain(|d| d.upgrade().is_some());
        dialogs.push(dialog.upcast_ref::<adw::Dialog>().downgrade());
        dialog.present(Some(&self.window));
    }

    /// Ask before doing something; `then` runs on yes.
    fn confirm(
        self: &Rc<Self>,
        heading: &str,
        body: &str,
        yes: &str,
        then: impl Fn(&Rc<Ui>) + 'static,
    ) {
        let dialog = adw::AlertDialog::new(Some(heading), Some(body));
        dialog.add_responses(&[("cancel", "_Cancel"), ("yes", yes)]);
        dialog.set_response_appearance("yes", adw::ResponseAppearance::Destructive);
        dialog.set_default_response(Some("cancel"));
        dialog.set_close_response("cancel");
        let ui = Rc::downgrade(self);
        let epoch = self.epoch.get();
        dialog.connect_response(Some("yes"), move |_, _| {
            if let Some(ui) = ui.upgrade().filter(|ui| ui.epoch.get() == epoch) {
                then(&ui);
            }
        });
        self.present_dialog(&dialog);
    }

    /// The selected item, opened for editing: its draft, raw copy and key.
    fn open_selected(&self) -> Option<(String, edit::Draft, serde_json::Value, SymmetricKey)> {
        let id = self.vault.selected_id()?;
        let vault = self.vault.current_vault()?;
        let raw = vault.raw(&id)?.clone();
        let session = self.session.borrow();
        let keys = &session.as_ref()?.keys;
        let opened =
            edit::item_key(&raw, keys).and_then(|key| Ok((edit::Draft::open(&raw, &key)?, key)));
        match opened {
            Ok((draft, key)) => Some((id, draft, raw, key)),
            Err(error) => {
                log::warn!("cannot open item {id} for editing: {error}");
                self.toast("This item can't be edited: part of it won't decrypt.");
                None
            }
        }
    }

    /// Run `then` now, or once the master password is re-entered when the
    /// selected item asks for it.
    fn with_selected_unlocked(self: &Rc<Self>, then: fn(&Rc<Ui>)) {
        let Some(id) = self.vault.selected_id() else {
            return;
        };
        let reprompt = self
            .vault
            .current_vault()
            .and_then(|v| v.item(&id).map(|i| i.reprompt))
            .unwrap_or(false);
        if reprompt {
            let ui = Rc::downgrade(self);
            self.reprompt(&id, move || {
                if let Some(ui) = ui.upgrade() {
                    then(&ui);
                }
            });
        } else {
            then(self);
        }
    }

    fn start_edit(self: &Rc<Self>) {
        if let Some(id) = self.vault.selected_send_id() {
            return self.start_send_edit(&id);
        }
        self.with_selected_unlocked(|ui| {
            let Some((id, draft, _, _)) = ui.open_selected() else {
                return;
            };
            let Some(vault) = ui.vault.current_vault() else {
                return;
            };
            let editor = editor::Editor::new(&vault, &draft, Some(id), Some(draft.clone()));
            ui.vault.show_editor(ui, editor);
        });
    }

    fn start_clone(self: &Rc<Self>) {
        self.with_selected_unlocked(|ui| {
            let Some((_, draft, _, _)) = ui.open_selected() else {
                return;
            };
            let Some(vault) = ui.vault.current_vault() else {
                return;
            };
            let editor = editor::Editor::new(&vault, &draft.cloned(), None, None);
            ui.vault.show_editor(ui, editor);
        });
    }

    fn start_new(self: &Rc<Self>, kind: crate::vault::Kind) {
        if !self.is_unlocked() || self.vault.editing() {
            return;
        }
        let Some(vault) = self.vault.current_vault() else {
            return;
        };
        let mut draft = editor::starting_draft(kind, &self.vault.current_filter(), &vault);
        if kind == crate::vault::Kind::SshKey {
            if let Err(error) = edit::new_ssh_key(&mut draft) {
                log::warn!("could not make an SSH key: {error}");
                return self.toast("Could not make a new SSH key.");
            }
        }
        let editor = editor::Editor::new(&vault, &draft, None, None);
        self.vault.show_editor(self, editor);
    }

    fn save_edit(self: &Rc<Self>) {
        if self.vault.send_editor().is_some() {
            return self.save_send();
        }
        let Some(editor) = self.vault.editor() else {
            return;
        };
        let draft = editor.draft();
        if let Some(problem) = draft.problem(editor.original.as_ref()) {
            return self.toast(problem);
        }
        let change = {
            let session = self.session.borrow();
            let Some(keys) = session.as_ref().map(|s| &s.keys) else {
                return;
            };
            let vault = self.vault.current_vault();
            let now = session::now_iso();
            let saver = edit::Saver {
                user_id: vault.as_ref().and_then(|v| v.user_id.as_deref()),
                now: &now,
            };
            match (&editor.id, &editor.original) {
                (Some(id), Some(original)) => {
                    let Some(raw) = vault.as_ref().and_then(|v| v.raw(id)) else {
                        return self.toast("This item is no longer in the vault.");
                    };
                    let key = match edit::item_key(raw, keys) {
                        Ok(key) => key,
                        Err(error) => {
                            log::warn!("cannot save item {id}: {error}");
                            return self.toast("This item can't be saved: its key won't open.");
                        }
                    };
                    // The body is made as for the item's current owner; a
                    // move then encrypts it for the organization.
                    let mut saved = draft.clone();
                    saved.org_id.clone_from(&original.org_id);
                    let base = edit::Base { raw, original };
                    let mut body = edit::request(&saved, Some(base), &key, &saver);
                    match (&original.org_id, &draft.org_id) {
                        (None, Some(org_id)) => {
                            let Some(org) = keys.orgs.get(org_id) else {
                                return self.toast("Vord has no key for that organization.");
                            };
                            if let Err(why) =
                                edit::into_organization(&mut body, raw, &keys.user, org_id, org)
                            {
                                return self.toast(&why);
                            }
                            session::Change::Share {
                                id: id.clone(),
                                body,
                                collections: draft.collection_ids.clone(),
                            }
                        }
                        _ => {
                            let mut before = original.collection_ids.clone();
                            let mut after = draft.collection_ids.clone();
                            before.sort();
                            after.sort();
                            session::Change::SaveItem {
                                id: Some(id.clone()),
                                body,
                                collections: draft.collection_ids.clone(),
                                move_collections: before != after,
                            }
                        }
                    }
                }
                _ => {
                    let Some(key) = keys.for_org(draft.org_id.as_deref()) else {
                        return self.toast("Vord has no key for that organization.");
                    };
                    session::Change::SaveItem {
                        id: None,
                        body: edit::request(&draft, None, key, &saver),
                        collections: draft.collection_ids.clone(),
                        move_collections: false,
                    }
                }
            }
        };
        self.vault.set_saving(true);
        let message = if editor.id.is_some() {
            "Item saved"
        } else {
            "Item added"
        };
        self.run_change(change, message, |ui, _, touched| {
            ui.vault.end_edit(ui);
            match touched {
                session::Touched::Item(id) => Some(Some(id)),
                _ => None,
            }
        });
    }

    // ---- Sends ----------------------------------------------------------

    fn start_new_send(self: &Rc<Self>, kind: crate::send::SendKind) {
        if !self.is_unlocked() || self.vault.editing() {
            return;
        }
        let editor = send::SendEditor::new(&crate::send::Draft::new(kind), None);
        self.vault.show_send_editor(self, editor);
    }

    fn start_send_edit(self: &Rc<Self>, id: &str) {
        let Some(vault) = self.vault.current_vault() else {
            return;
        };
        let Some(send) = vault.send(id).filter(|s| !s.damaged) else {
            return self.toast("This Send can't be edited: part of it won't decrypt.");
        };
        let editor = send::SendEditor::new(&crate::send::Draft::open(send), Some(send));
        self.vault.show_send_editor(self, editor);
    }

    fn save_send(self: &Rc<Self>) {
        let Some(editor) = self.vault.send_editor() else {
            return;
        };
        let draft = editor.draft();
        if let Some(problem) = draft.problem() {
            return self.toast(problem);
        }
        let change = {
            let session = self.session.borrow();
            let Some(user) = session.as_ref().map(|s| &s.keys.user) else {
                return;
            };
            let vault = self.vault.current_vault();
            let base = match (&editor.id, &editor.original) {
                (Some(id), Some(original)) => {
                    let Some(raw) = vault.as_ref().and_then(|v| v.raw_sends.get(id)) else {
                        return self.toast("This Send is no longer there.");
                    };
                    Some((raw, original))
                }
                _ => None,
            };
            let (body, key) = match crate::send::request(&draft, base, user) {
                Ok(made) => made,
                Err(why) => return self.toast(&why),
            };
            let file = match (&editor.id, draft.kind) {
                (None, crate::send::SendKind::File) => editor.file().map(|path| (path, key)),
                _ => None,
            };
            if file.is_some() {
                self.toast("Uploading…");
            }
            session::Change::SaveSend {
                id: editor.id.clone(),
                body,
                file,
            }
        };
        self.vault.set_saving(true);
        let new = editor.id.is_none();
        let message = if new { "Send created" } else { "Send saved" };
        self.run_change(change, message, move |ui, vault, touched| {
            ui.vault.end_edit(ui);
            match touched {
                session::Touched::Send(id) => {
                    // As Bitwarden's apps do: a new Send's link is copied,
                    // ready to share.
                    let server = ui.server().unwrap_or_default();
                    if let Some(link) = vault
                        .send(&id)
                        .filter(|_| new)
                        .and_then(|s| s.link(&server))
                    {
                        ui.copy("Link", &link, true);
                    }
                    Some(Some(id))
                }
                _ => None,
            }
        });
    }

    fn copy_send_link(self: &Rc<Self>) {
        let Some(id) = self.vault.selected_send_id() else {
            return;
        };
        let server = self.server().unwrap_or_default();
        let link = self
            .vault
            .current_vault()
            .and_then(|v| v.send(&id).and_then(|s| s.link(&server)));
        if let Some(link) = link {
            self.copy("Link", &link, true);
        }
    }

    fn remove_send_password(self: &Rc<Self>) {
        let Some(id) = self.vault.selected_send_id() else {
            return;
        };
        self.confirm(
            "Remove Password?",
            "Anyone with the link can then open the Send.",
            "_Remove",
            move |ui| {
                let change = session::Change::RemoveSendPassword(id.clone());
                ui.run_change(change, "Password removed", |_, _, _| None);
            },
        );
    }

    fn delete_send(self: &Rc<Self>) {
        let Some(id) = self.vault.selected_send_id() else {
            return;
        };
        self.confirm(
            "Delete Send?",
            "Its link stops working at once. This can't be undone.",
            "_Delete",
            move |ui| {
                let change = session::Change::DeleteSend(id.clone());
                ui.run_change(change, "Send deleted", |_, _, _| Some(None));
            },
        );
    }

    fn toggle_favorite(self: &Rc<Self>) {
        let Some(id) = self.vault.selected_id() else {
            return;
        };
        let Some(item) = self
            .vault
            .current_vault()
            .and_then(|v| v.item(&id).cloned())
        else {
            return;
        };
        let change = session::Change::Favorite {
            id,
            folder_id: item.folder_id.clone(),
            favorite: !item.favorite,
        };
        let message = if item.favorite {
            "Removed from favorites"
        } else {
            "Added to favorites"
        };
        self.run_change(change, message, |_, _, _| None);
    }

    fn trash_item(self: &Rc<Self>) {
        let Some(id) = self.vault.selected_id() else {
            return;
        };
        self.confirm(
            "Move to Trash?",
            "You can restore it from the Trash.",
            "_Move to Trash",
            move |ui| {
                let change = session::Change::Trash(id.clone());
                ui.run_change(change, "Moved to the Trash", |_, _, _| Some(None));
            },
        );
    }

    fn restore_item(self: &Rc<Self>) {
        let Some(id) = self.vault.selected_id() else {
            return;
        };
        self.run_change(session::Change::Restore(id), "Item restored", |_, _, _| {
            Some(None)
        });
    }

    fn purge_item(self: &Rc<Self>) {
        let Some(id) = self.vault.selected_id() else {
            return;
        };
        self.confirm(
            "Delete Permanently?",
            "The item and its attachments are deleted for good. This can't be undone.",
            "_Delete Permanently",
            move |ui| {
                let change = session::Change::Purge(id.clone());
                ui.run_change(change, "Item deleted", |_, _, _| Some(None));
            },
        );
    }

    /// The key an item's fields (and its attachments' keys) are encrypted with.
    fn key_of(&self, item_id: &str) -> Option<SymmetricKey> {
        let vault = self.vault.current_vault()?;
        let raw = vault.raw(item_id)?;
        let session = self.session.borrow();
        match edit::item_key(raw, &session.as_ref()?.keys) {
            Ok(key) => Some(key),
            Err(error) => {
                log::warn!("cannot open the key of item {item_id}: {error}");
                self.toast("This item's key won't open.");
                None
            }
        }
    }

    /// Ask where to save an attachment, then fetch, decrypt and write it
    /// there. The decrypted file goes only where the user chose.
    pub fn save_attachment(self: &Rc<Self>, item_id: &str, attachment: &crate::vault::Attachment) {
        let reprompt = self
            .vault
            .current_vault()
            .and_then(|v| v.item(item_id).map(|i| i.reprompt))
            .unwrap_or(false);
        let ui = Rc::downgrade(self);
        let (id, attachment) = (item_id.to_string(), attachment.clone());
        let ask = move || {
            let Some(ui) = ui.upgrade() else { return };
            let dialog = gtk::FileDialog::builder()
                .title("Save Attachment")
                .initial_name(attachment.name.as_str())
                .modal(true)
                .build();
            let (weak, id, attachment) = (Rc::downgrade(&ui), id.clone(), attachment.clone());
            let epoch = ui.epoch.get();
            dialog.save(Some(&ui.window), None::<&gio::Cancellable>, move |file| {
                let Some(ui) = weak.upgrade().filter(|ui| ui.epoch.get() == epoch) else {
                    return;
                };
                let Some(path) = file.ok().and_then(|f| f.path()) else {
                    return;
                };
                ui.download_to(&id, &attachment, path);
            });
        };
        if reprompt {
            self.reprompt(item_id, ask);
        } else {
            ask();
        }
    }

    fn download_to(
        self: &Rc<Self>,
        item_id: &str,
        attachment: &crate::vault::Attachment,
        path: std::path::PathBuf,
    ) {
        let Some(account) = self.account.borrow().clone() else {
            return;
        };
        let Some(key) = self.key_of(item_id) else {
            return;
        };
        let (id, attachment_id) = (item_id.to_string(), attachment.id.clone());
        let name = attachment.name.clone();
        self.toast(&format!("Saving {name}…"));
        let epoch = self.epoch.get();
        let ui = self.clone();
        glib::spawn_future_local(async move {
            let result = gio::spawn_blocking(move || {
                let (account, data) =
                    session::download_attachment(account, &id, &attachment_id, &key)?;
                std::fs::write(&path, &*data)
                    .map_err(|e| session::Error::Other(format!("Could not write the file: {e}")))?;
                Ok::<_, session::Error>(account)
            })
            .await
            .unwrap_or_else(|_| Err(session::Error::Other("Saving crashed.".into())));
            match result {
                Ok(account) => {
                    ui.account.replace(Some(account));
                    if ui.epoch.get() == epoch {
                        ui.toast(&format!("Saved {name}"));
                    }
                }
                Err(error) => {
                    log::warn!("could not save an attachment: {error}");
                    if ui.epoch.get() == epoch {
                        ui.toast(&error.to_string());
                    }
                }
            }
        });
    }

    fn add_attachment(self: &Rc<Self>) {
        let Some(id) = self.vault.selected_id() else {
            return;
        };
        let dialog = gtk::FileDialog::builder()
            .title("Add Attachment")
            .modal(true)
            .build();
        let ui = Rc::downgrade(self);
        let epoch = self.epoch.get();
        dialog.open(Some(&self.window), None::<&gio::Cancellable>, move |file| {
            let Some(ui) = ui.upgrade().filter(|ui| ui.epoch.get() == epoch) else {
                return;
            };
            let Some(path) = file.ok().and_then(|f| f.path()) else {
                return;
            };
            let Some(item_key) = ui.key_of(&id) else {
                return;
            };
            ui.toast("Uploading…");
            let change = session::Change::AddAttachment {
                id: id.clone(),
                path,
                item_key,
            };
            ui.run_change(change, "Attachment added", |_, _, _| None);
        });
    }

    pub fn delete_attachment(self: &Rc<Self>, item_id: &str, attachment: &str) {
        let (id, attachment) = (item_id.to_string(), attachment.to_string());
        self.confirm(
            "Delete Attachment?",
            "The file is deleted for good. This can't be undone.",
            "_Delete",
            move |ui| {
                let change = session::Change::DeleteAttachment {
                    id: id.clone(),
                    attachment: attachment.clone(),
                };
                ui.run_change(change, "Attachment deleted", |_, _, _| None);
            },
        );
    }

    /// Ask for a folder's name: a new folder, or a new name for `id`.
    fn folder_name_dialog(self: &Rc<Self>, folder: Option<(String, String)>) {
        if !self.is_unlocked() {
            return;
        }
        let entry = gtk::Entry::builder()
            .activates_default(true)
            .placeholder_text("Name")
            .text(folder.as_ref().map_or("", |(_, name)| name.as_str()))
            .build();
        let (heading, yes) = match folder {
            Some(_) => ("Rename Folder", "_Rename"),
            None => ("New Folder", "_Create"),
        };
        let dialog = adw::AlertDialog::new(Some(heading), None);
        dialog.set_extra_child(Some(&entry));
        dialog.add_responses(&[("cancel", "_Cancel"), ("yes", yes)]);
        dialog.set_response_appearance("yes", adw::ResponseAppearance::Suggested);
        dialog.set_default_response(Some("yes"));
        dialog.set_close_response("cancel");
        let ui = Rc::downgrade(self);
        let epoch = self.epoch.get();
        let typed = entry.clone();
        dialog.connect_response(Some("yes"), move |_, _| {
            let Some(ui) = ui.upgrade().filter(|ui| ui.epoch.get() == epoch) else {
                return;
            };
            let name = typed.text().trim().to_string();
            if name.is_empty() {
                return;
            }
            let Some(sealed) = ui
                .session
                .borrow()
                .as_ref()
                .map(|s| s.keys.user.encrypt_text(&name))
            else {
                return;
            };
            let id = folder.as_ref().map(|(id, _)| id.clone());
            let message = if id.is_some() {
                "Folder renamed"
            } else {
                "Folder created"
            };
            let change = session::Change::SaveFolder { id, name: sealed };
            ui.run_change(change, message, |_, _, _| None);
        });
        self.present_dialog(&dialog);
        entry.grab_focus();
    }

    fn current_folder(&self) -> Option<(String, String)> {
        let vault::Filter::Folder(Some(id)) = self.vault.current_filter() else {
            return None;
        };
        let vault = self.vault.current_vault()?;
        let folder = vault.folders.iter().find(|f| f.id == id)?;
        Some((folder.id.clone(), folder.name.clone()))
    }

    fn rename_folder(self: &Rc<Self>) {
        if let Some(folder) = self.current_folder() {
            self.folder_name_dialog(Some(folder));
        }
    }

    fn delete_folder(self: &Rc<Self>) {
        let Some((id, _)) = self.current_folder() else {
            return;
        };
        self.confirm(
            "Delete Folder?",
            "Its items stay in the vault, in No Folder.",
            "_Delete",
            move |ui| {
                let change = session::Change::DeleteFolder(id.clone());
                ui.run_change(change, "Folder deleted", |_, _, _| None);
            },
        );
    }

    /// Send a change on a worker; on success show the vault as it now is
    /// and say `done`. `after` runs first, with the vault as it now is, and
    /// may pick the item (or Send) to select
    /// (`Some(None)` selects nothing; `None` keeps the selection).
    fn run_change(
        self: &Rc<Self>,
        change: session::Change,
        done: &'static str,
        after: impl Fn(&Rc<Ui>, &Vault, session::Touched) -> Option<Option<String>> + 'static,
    ) {
        let Some(account) = self.account.borrow().clone() else {
            return;
        };
        let Some(user_key) = self.session.borrow().as_ref().map(|s| s.keys.user.clone()) else {
            return;
        };
        let epoch = self.epoch.get();
        let ui = self.clone();
        glib::spawn_future_local(async move {
            let result = gio::spawn_blocking(move || {
                let (account, sync, touched) = session::change(account, change)?;
                let unlocked = session::open_sync(&account, user_key, &sync);
                Ok::<_, session::Error>((account, unlocked, touched))
            })
            .await
            .unwrap_or_else(|_| Err(session::Error::Other("Saving crashed.".into())));
            ui.vault.set_saving(false);
            if ui.epoch.get() != epoch || !ui.is_unlocked() {
                if let Ok((account, ..)) = result {
                    ui.account.replace(Some(account));
                }
                return;
            }
            match result {
                Ok((account, unlocked, touched)) => {
                    ui.account.replace(Some(account));
                    if let Some(session) = ui.session.borrow_mut().as_mut() {
                        session.keys = unlocked.keys;
                    }
                    let vault = Rc::new(unlocked.vault);
                    if let Some(select) = after(&ui, &vault, touched) {
                        ui.vault.select(&vault, select);
                    }
                    ui.vault.show_vault(&ui, vault, false);
                    ui.toast(done);
                }
                Err(session::Error::Api(crate::api::ApiError::SessionExpired)) => {
                    ui.toast(
                        "The server ended this session. Log out and in again to make changes.",
                    );
                }
                Err(error) => {
                    log::warn!("a change failed: {error}");
                    ui.toast(&error.to_string());
                }
            }
        });
    }

    // ---- lock when left alone -----------------------------------------

    fn watch_focus(self: &Rc<Self>) {
        let weak = Rc::downgrade(self);
        self.window.connect_is_active_notify(move |window| {
            let Some(ui) = weak.upgrade() else { return };
            if let Some(timer) = ui.lock_timer.take() {
                timer.remove();
            }
            let minutes = settings::get().lock_after_minutes;
            if window.is_active() || minutes == 0 || !ui.is_unlocked() {
                return;
            }
            let weak = Rc::downgrade(&ui);
            let timer = glib::timeout_add_local_once(
                Duration::from_secs(u64::from(minutes) * 60),
                move || {
                    if let Some(ui) = weak.upgrade() {
                        ui.lock_timer.take();
                        log::info!("locking after {minutes} minute(s) in the background");
                        ui.lock();
                    }
                },
            );
            ui.lock_timer.replace(Some(timer));
        });
    }

    // ---- actions --------------------------------------------------------

    fn add_actions(self: &Rc<Self>, app: &adw::Application) {
        let action = |name: &str, accels: &[&str], run: fn(&Rc<Ui>)| {
            let action = gio::SimpleAction::new(name, None);
            let weak = Rc::downgrade(self);
            action.connect_activate(move |_, _| {
                if let Some(ui) = weak.upgrade() {
                    run(&ui);
                }
            });
            self.window.add_action(&action);
            if !accels.is_empty() {
                app.set_accels_for_action(&format!("win.{name}"), accels);
            }
        };
        action("lock", &["<Control>l"], |ui| ui.lock());
        action("sync", &["<Control>r", "F5"], |ui| ui.sync());
        action("search", &["<Control>f"], |ui| ui.vault.focus_search());
        action("copy-username", &["<Control>u"], |ui| {
            ui.vault.copy_field(ui, vault::Quick::Username)
        });
        action("copy-password", &["<Control>p"], |ui| {
            ui.vault.copy_field(ui, vault::Quick::Password)
        });
        action("copy-totp", &["<Control>t"], |ui| {
            ui.vault.copy_field(ui, vault::Quick::Totp)
        });
        action("open-website", &["<Control>o"], |ui| {
            ui.vault.copy_field(ui, vault::Quick::Website)
        });
        action("generator", &["<Control>g"], generator::show);
        action("export", &[], export::show);
        action("edit-item", &["<Control>e"], |ui| ui.start_edit());
        action("clone-item", &[], |ui| ui.start_clone());
        action("add-attachment", &[], |ui| ui.add_attachment());
        action("save-item", &["<Control>s"], |ui| ui.save_edit());
        action("cancel-edit", &[], |ui| ui.vault.end_edit(ui));
        action("trash-item", &[], |ui| ui.trash_item());
        action("restore-item", &[], |ui| ui.restore_item());
        action("purge-item", &[], |ui| ui.purge_item());
        action("new-folder", &[], |ui| ui.folder_name_dialog(None));
        action("rename-folder", &[], |ui| ui.rename_folder());
        action("delete-folder", &[], |ui| ui.delete_folder());
        action("copy-send-link", &[], |ui| ui.copy_send_link());
        action("remove-send-password", &[], |ui| ui.remove_send_password());
        action("delete-send", &[], |ui| ui.delete_send());
        {
            let favorite = gio::SimpleAction::new_stateful("favorite", None, &false.to_variant());
            let weak = Rc::downgrade(self);
            favorite.connect_activate(move |_, _| {
                if let Some(ui) = weak.upgrade() {
                    ui.toggle_favorite();
                }
            });
            self.window.add_action(&favorite);
            let new_item = gio::SimpleAction::new("new-item", Some(glib::VariantTy::STRING));
            let weak = Rc::downgrade(self);
            new_item.connect_activate(move |_, kind| {
                let (Some(ui), Some(kind)) = (weak.upgrade(), kind.and_then(|k| k.str())) else {
                    return;
                };
                let kind = match kind {
                    "card" => crate::vault::Kind::Card,
                    "identity" => crate::vault::Kind::Identity,
                    "note" => crate::vault::Kind::Note,
                    "ssh-key" => crate::vault::Kind::SshKey,
                    _ => crate::vault::Kind::Login,
                };
                ui.start_new(kind);
            });
            self.window.add_action(&new_item);
            app.set_accels_for_action("win.new-item::login", &["<Control>n"]);
            let new_send = gio::SimpleAction::new("new-send", Some(glib::VariantTy::STRING));
            let weak = Rc::downgrade(self);
            new_send.connect_activate(move |_, kind| {
                let (Some(ui), Some(kind)) = (weak.upgrade(), kind.and_then(|k| k.str())) else {
                    return;
                };
                ui.start_new_send(match kind {
                    "file" => crate::send::SendKind::File,
                    _ => crate::send::SendKind::Text,
                });
            });
            self.window.add_action(&new_send);
        }
        action("logout", &[], |ui| ui.confirm_logout());
        action("preferences", &["<Control>comma"], prefs::show);
        action("about", &[], |ui| ui.show_about());
    }

    fn show_about(&self) {
        let about = adw::AboutDialog::builder()
            .application_name("Vord")
            .application_icon(crate::APP_ID)
            .version(env!("CARGO_PKG_VERSION"))
            .comments("A Bitwarden and Vaultwarden vault for the Linux desktop.\n\nVörðr, in Old Norse lore, is a warden spirit that follows a person and guards them.")
            .developers(vec!["Brandon Williams"])
            .copyright("© 2026 Brandon Williams")
            .license_type(gtk::License::Gpl30)
            .build();
        about.present(Some(&self.window));
    }
}

/// Where a login's first attempt left off.
// Made once per login and moved once; its size doesn't matter.
#[allow(clippy::large_enum_variant)]
enum LoginStep {
    Opened(Account, Keys, Option<Vault>),
    SecondStep(session::PendingLogin),
}

fn empty_vault() -> Vault {
    Vault {
        organizations: Vec::new(),
        folders: Vec::new(),
        collections: Vec::new(),
        items: Vec::new(),
        damaged: 0,
        raw: Default::default(),
        user_id: None,
        sends: Vec::new(),
        raw_sends: Default::default(),
    }
}

pub fn duration_text(seconds: u32) -> String {
    if seconds >= 60 && seconds.is_multiple_of(60) {
        let minutes = seconds / 60;
        format!("{minutes} min")
    } else {
        format!("{seconds} s")
    }
}
