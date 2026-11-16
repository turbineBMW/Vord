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
mod pages;
mod prefs;
mod vault;

use crate::crypto::SymmetricKey;
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
            "search",
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
        self.session.replace(Some(Session { keys }));
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
                    ui.session.replace(Some(Session {
                        keys: unlocked.keys,
                    }));
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
    }

    pub fn reprompt_cleared_for(&self, item_id: &str) -> bool {
        self.reprompt_passed.borrow().as_deref() == Some(item_id)
    }

    pub fn forget_reprompt(&self) {
        self.reprompt_passed.replace(None);
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
