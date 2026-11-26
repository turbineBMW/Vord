//! The pages before the vault: logging in to a server, its second step
//! when the account has two-step login, and unlocking.

use super::Ui;
use crate::api::TwoFactorMethod;
use crate::session::PendingLogin;
use crate::store::Account;
use adw::prelude::*;
use std::cell::{Cell, RefCell};
use std::rc::Rc;

/// "me@example.com on vault.example.com"
fn account_line(email: &str, server: &str) -> String {
    let host = url::Url::parse(server)
        .ok()
        .and_then(|u| u.host_str().map(str::to_string))
        .unwrap_or_else(|| server.to_string());
    format!("{email} on {host}")
}

/// The brand block both pages start with: the icon, the name, a line.
fn brand(subtitle: &str) -> (gtk::Box, gtk::Label) {
    let column = gtk::Box::builder()
        .orientation(gtk::Orientation::Vertical)
        .spacing(6)
        .halign(gtk::Align::Center)
        .margin_bottom(18)
        .build();
    let icon = gtk::Image::builder()
        .icon_name(crate::APP_ID)
        .pixel_size(112)
        .margin_bottom(12)
        .build();
    let name = gtk::Label::builder()
        .label("Vord")
        .css_classes(["vord-brand"])
        .build();
    let line = gtk::Label::builder()
        .label(subtitle)
        .css_classes(["dim-label"])
        .wrap(true)
        .justify(gtk::Justification::Center)
        .build();
    column.append(&icon);
    column.append(&name);
    column.append(&line);
    (column, line)
}

/// A page centred in the window, under a bare header bar.
fn frame(content: &impl IsA<gtk::Widget>) -> adw::ToolbarView {
    let clamp = adw::Clamp::builder()
        .maximum_size(420)
        .child(content)
        .margin_start(16)
        .margin_end(16)
        .margin_top(24)
        .margin_bottom(24)
        .build();
    let scroller = gtk::ScrolledWindow::builder()
        .hscrollbar_policy(gtk::PolicyType::Never)
        .child(&clamp)
        .vexpand(true)
        .build();
    let center = gtk::Box::builder()
        .orientation(gtk::Orientation::Vertical)
        .valign(gtk::Align::Center)
        .build();
    center.append(&scroller);
    scroller.set_propagate_natural_height(true);
    let view = adw::ToolbarView::builder()
        .content(&center)
        .css_classes(["vord-surface"])
        .build();
    let header = adw::HeaderBar::builder().show_title(false).build();
    let menu = gtk::gio::Menu::new();
    menu.append(Some("_Preferences"), Some("win.preferences"));
    menu.append(Some("_About Vord"), Some("win.about"));
    header.pack_end(
        &gtk::MenuButton::builder()
            .icon_name("open-menu-symbolic")
            .menu_model(&menu)
            .tooltip_text("Main Menu")
            .build(),
    );
    view.add_top_bar(&header);
    view
}

fn action_button(label: &str) -> (gtk::Button, adw::Spinner, gtk::Label) {
    let text = gtk::Label::new(Some(label));
    let spinner = adw::Spinner::builder().visible(false).build();
    let inner = gtk::Box::builder()
        .spacing(8)
        .halign(gtk::Align::Center)
        .build();
    inner.append(&spinner);
    inner.append(&text);
    let button = gtk::Button::builder()
        .child(&inner)
        .css_classes(["suggested-action", "pill"])
        .halign(gtk::Align::Center)
        .width_request(200)
        .margin_top(18)
        .build();
    (button, spinner, text)
}

fn error_label() -> gtk::Label {
    gtk::Label::builder()
        .css_classes(["form-error"])
        .wrap(true)
        .justify(gtk::Justification::Center)
        .visible(false)
        .margin_top(12)
        .build()
}

pub struct LoginPage {
    pub root: adw::ToolbarView,
    /// Back to the account in use, while adding another.
    cancel: gtk::Button,
    server: adw::EntryRow,
    email: adw::EntryRow,
    password: adw::PasswordEntryRow,
    button: gtk::Button,
    spinner: adw::Spinner,
    label: gtk::Label,
    error: gtk::Label,
}

impl LoginPage {
    pub fn new() -> Self {
        let (brand, _) = brand("Log in to your Vaultwarden or Bitwarden server.");
        let group = adw::PreferencesGroup::new();
        let server = adw::EntryRow::builder()
            .title("Server address")
            .input_purpose(gtk::InputPurpose::Url)
            .build();
        let email = adw::EntryRow::builder()
            .title("Email")
            .input_purpose(gtk::InputPurpose::Email)
            .build();
        let password = adw::PasswordEntryRow::builder()
            .title("Master password")
            .build();
        group.add(&server);
        group.add(&email);
        group.add(&password);
        let (button, spinner, label) = action_button("Log In");
        let error = error_label();
        let note = gtk::Label::builder()
            .label("Your master password never leaves this computer. Vord sends the server a hash of it, as every Bitwarden app does.")
            .css_classes(["dim-label", "caption"])
            .wrap(true)
            .justify(gtk::Justification::Center)
            .margin_top(24)
            .build();
        let column = gtk::Box::new(gtk::Orientation::Vertical, 0);
        column.append(&brand);
        column.append(&group);
        column.append(&error);
        let cancel = gtk::Button::builder()
            .label("_Cancel")
            .use_underline(true)
            .action_name("win.cancel-add-account")
            .css_classes(["flat"])
            .halign(gtk::Align::Center)
            .margin_top(6)
            .visible(false)
            .build();
        column.append(&button);
        column.append(&cancel);
        column.append(&note);
        Self {
            root: frame(&column),
            cancel,
            server,
            email,
            password,
            button,
            spinner,
            label,
            error,
        }
    }

    pub fn connect(&self, ui: &Rc<Ui>) {
        let submit = {
            let weak = Rc::downgrade(ui);
            move || {
                let Some(ui) = weak.upgrade() else { return };
                let page = &ui.login;
                if !page.button.is_sensitive() {
                    return;
                }
                page.error.set_visible(false);
                ui.login(
                    page.server.text().to_string(),
                    page.email.text().to_string(),
                    page.password.text().to_string(),
                );
            }
        };
        let submit = Rc::new(submit);
        let s = submit.clone();
        self.button.connect_clicked(move |_| s());
        self.password.connect_entry_activated(move |_| submit());
        let weak_ui = Rc::downgrade(ui);
        self.server.connect_entry_activated(move |_| {
            if let Some(ui) = weak_ui.upgrade() {
                ui.login.email.grab_focus();
            }
        });
        let weak_ui = Rc::downgrade(ui);
        self.email.connect_entry_activated(move |_| {
            if let Some(ui) = weak_ui.upgrade() {
                ui.login.password.grab_focus();
            }
        });
    }

    /// Whether this login adds an account beside one already kept.
    pub fn set_adding(&self, adding: bool) {
        self.cancel.set_visible(adding);
    }

    pub fn prefill(&self, server: &str, email: &str) {
        self.server.set_text(server);
        self.email.set_text(email);
        self.password.set_text("");
        self.error.set_visible(false);
    }

    pub fn focus(&self) {
        if self.server.text().is_empty() {
            self.server.grab_focus();
        } else if self.email.text().is_empty() {
            self.email.grab_focus();
        } else {
            self.password.grab_focus();
        }
    }

    pub fn set_busy(&self, busy: bool) {
        self.button.set_sensitive(!busy);
        self.spinner.set_visible(busy);
        self.label
            .set_label(if busy { "Logging In…" } else { "Log In" });
        for row in [
            self.server.upcast_ref::<gtk::Widget>(),
            self.email.upcast_ref(),
            self.password.upcast_ref(),
        ] {
            row.set_sensitive(!busy);
        }
    }

    pub fn fail(&self, message: &str) {
        self.error.set_label(message);
        self.error.set_visible(true);
        self.password.grab_focus();
    }

    pub fn clear_password(&self) {
        self.password.set_text("");
    }
}

pub struct TwoFactorPage {
    pub root: adw::ToolbarView,
    who: gtk::Label,
    title: gtk::Label,
    hint: gtk::Label,
    method: adw::ComboRow,
    code: adw::EntryRow,
    remember: adw::SwitchRow,
    button: gtk::Button,
    spinner: adw::Spinner,
    label: gtk::Label,
    error: gtk::Label,
    resend: gtk::Button,
    cancel: gtk::Button,
    /// The account's methods, in the order `method` lists them.
    methods: RefCell<Vec<TwoFactorMethod>>,
    email_hint: RefCell<Option<String>>,
    /// Whether a code has been emailed for this login.
    pub email_sent: Cell<bool>,
}

impl TwoFactorPage {
    pub fn new() -> Self {
        let (brand, who) = brand("");
        who.add_css_class("accent");
        let title = gtk::Label::builder()
            .label("Two-Step Login")
            .css_classes(["title-4"])
            .margin_bottom(6)
            .build();
        let hint = gtk::Label::builder()
            .css_classes(["dim-label"])
            .wrap(true)
            .justify(gtk::Justification::Center)
            .margin_bottom(18)
            .build();
        let group = adw::PreferencesGroup::new();
        let method = adw::ComboRow::builder().title("Method").build();
        let code = adw::EntryRow::builder().title("Verification code").build();
        let remember = adw::SwitchRow::builder()
            .title("Remember this device")
            .subtitle("Skip this step on this computer next time")
            .build();
        group.add(&method);
        group.add(&code);
        group.add(&remember);
        let (button, spinner, label) = action_button("Continue");
        let error = error_label();
        let flat = |label: &str| {
            gtk::Button::builder()
                .label(label)
                .css_classes(["flat"])
                .halign(gtk::Align::Center)
                .build()
        };
        let resend = flat("Send Code Again");
        resend.set_margin_top(12);
        let cancel = flat("Cancel");
        cancel.set_margin_top(6);
        let column = gtk::Box::new(gtk::Orientation::Vertical, 0);
        column.append(&brand);
        column.append(&title);
        column.append(&hint);
        column.append(&group);
        column.append(&error);
        column.append(&button);
        column.append(&resend);
        column.append(&cancel);
        Self {
            root: frame(&column),
            who,
            title,
            hint,
            method,
            code,
            remember,
            button,
            spinner,
            label,
            error,
            resend,
            cancel,
            methods: RefCell::default(),
            email_hint: RefCell::default(),
            email_sent: Cell::new(false),
        }
    }

    pub fn connect(&self, ui: &Rc<Ui>) {
        let submit = Rc::new({
            let weak = Rc::downgrade(ui);
            move || {
                let Some(ui) = weak.upgrade() else { return };
                if ui.two_factor.button.is_sensitive() {
                    ui.two_factor.error.set_visible(false);
                    ui.second_step();
                }
            }
        });
        let s = submit.clone();
        self.button.connect_clicked(move |_| s());
        self.code.connect_entry_activated(move |_| submit());
        let weak = Rc::downgrade(ui);
        self.method.connect_selected_notify(move |_| {
            if let Some(ui) = weak.upgrade() {
                ui.two_factor_method_changed();
            }
        });
        let weak = Rc::downgrade(ui);
        self.resend.connect_clicked(move |_| {
            if let Some(ui) = weak.upgrade() {
                ui.send_email_code();
            }
        });
        let weak = Rc::downgrade(ui);
        self.cancel.connect_clicked(move |_| {
            if let Some(ui) = weak.upgrade() {
                ui.cancel_two_factor();
            }
        });
    }

    /// Ready the page for a login's second step. The caller then runs
    /// [`Ui::two_factor_method_changed`], which may email a code.
    pub fn show(&self, pending: &PendingLogin) {
        self.who
            .set_label(&account_line(pending.email(), pending.server()));
        self.methods.replace(pending.methods.clone());
        self.email_hint.replace(pending.email_hint.clone());
        self.email_sent.set(pending.email_sent);
        let labels: Vec<&str> = pending.methods.iter().map(|m| m.label()).collect();
        self.method.set_model(Some(&gtk::StringList::new(&labels)));
        self.method.set_selected(0);
        self.method.set_visible(labels.len() > 1);
        self.remember.set_active(false);
        self.code.set_text("");
        self.error.set_visible(false);
        self.set_busy(false);
        self.set_sending(false);
    }

    pub fn selected_method(&self) -> Option<TwoFactorMethod> {
        let index = usize::try_from(self.method.selected()).ok()?;
        self.methods.borrow().get(index).copied()
    }

    /// Say what to do for the selected method.
    pub fn show_method(&self) {
        let Some(method) = self.selected_method() else {
            return;
        };
        let new_device = method == TwoFactorMethod::NewDevice;
        let hint = match method {
            TwoFactorMethod::NewDevice => {
                let address = self.email_hint.borrow();
                format!(
                    "This is the first login from this computer. Enter the code Bitwarden sent to {}.",
                    address.as_deref().unwrap_or("your email")
                )
            }
            TwoFactorMethod::Authenticator => {
                "Enter the 6-digit code from your authenticator app.".to_string()
            }
            TwoFactorMethod::Email => match self.email_hint.borrow().as_deref() {
                Some(address) => format!("Enter the code sent to {address}."),
                None => "Enter the code sent to your email.".to_string(),
            },
            TwoFactorMethod::YubiKey => "Insert your YubiKey, then touch its button.".to_string(),
        };
        self.title.set_label(if new_device {
            "Verify This Device"
        } else {
            "Two-Step Login"
        });
        self.hint.set_label(&hint);
        // A new device's code has no remembered-device token to ask for.
        self.remember.set_visible(!new_device);
        self.code.set_input_purpose(match method {
            TwoFactorMethod::YubiKey => gtk::InputPurpose::FreeForm,
            _ => gtk::InputPurpose::Digits,
        });
        self.resend.set_visible(matches!(
            method,
            TwoFactorMethod::Email | TwoFactorMethod::NewDevice
        ));
        self.code.set_text("");
        self.error.set_visible(false);
    }

    pub fn code(&self) -> String {
        self.code.text().to_string()
    }

    pub fn remember(&self) -> bool {
        self.remember.is_active()
    }

    pub fn email_hint(&self) -> Option<String> {
        self.email_hint.borrow().clone()
    }

    pub fn focus(&self) {
        self.code.grab_focus();
    }

    pub fn set_busy(&self, busy: bool) {
        self.button.set_sensitive(!busy);
        self.spinner.set_visible(busy);
        self.label
            .set_label(if busy { "Verifying…" } else { "Continue" });
        for row in [
            self.method.upcast_ref::<gtk::Widget>(),
            self.code.upcast_ref(),
            self.remember.upcast_ref(),
        ] {
            row.set_sensitive(!busy);
        }
    }

    /// While an email is being asked for.
    pub fn set_sending(&self, sending: bool) {
        self.resend.set_sensitive(!sending);
        self.resend.set_label(if sending {
            "Sending…"
        } else {
            "Send Code Again"
        });
    }

    pub fn fail(&self, message: &str) {
        self.error.set_label(message);
        self.error.set_visible(true);
        self.code.grab_focus();
        self.code.select_region(0, -1);
    }
}

pub struct UnlockPage {
    pub root: adw::ToolbarView,
    pub accounts: gtk::MenuButton,
    who: gtk::Label,
    password: adw::PasswordEntryRow,
    pin: adw::PasswordEntryRow,
    /// Between the PIN and the master password.
    switch: gtk::Button,
    /// Whether the PIN is asked for (it can be, and the user hasn't
    /// switched to the master password).
    pin_mode: std::cell::Cell<bool>,
    button: gtk::Button,
    spinner: adw::Spinner,
    label: gtk::Label,
    error: gtk::Label,
}

impl UnlockPage {
    pub fn new() -> Self {
        let (brand, who) = brand("");
        who.add_css_class("accent");
        let locked = gtk::Label::builder()
            .label("Your vault is locked.")
            .css_classes(["title-4"])
            .margin_bottom(12)
            .build();
        let group = adw::PreferencesGroup::new();
        let password = adw::PasswordEntryRow::builder()
            .title("Master password")
            .build();
        group.add(&password);
        let pin = adw::PasswordEntryRow::builder()
            .title("PIN")
            .visible(false)
            .build();
        group.add(&pin);
        let switch = gtk::Button::builder()
            .label("Use Master Password")
            .css_classes(["flat"])
            .halign(gtk::Align::Center)
            .margin_top(6)
            .visible(false)
            .build();
        let (button, spinner, label) = action_button("Unlock");
        let error = error_label();
        let logout = gtk::Button::builder()
            .label("Log Out…")
            .action_name("win.logout")
            .css_classes(["flat"])
            .halign(gtk::Align::Center)
            .build();
        let column = gtk::Box::new(gtk::Orientation::Vertical, 0);
        column.append(&brand);
        column.append(&locked);
        column.append(&group);
        column.append(&error);
        column.append(&button);
        let accounts = gtk::MenuButton::builder()
            .label("Accounts")
            .css_classes(["flat"])
            .halign(gtk::Align::Center)
            .margin_top(12)
            .build();
        column.append(&switch);
        column.append(&accounts);
        column.append(&logout);
        Self {
            root: frame(&column),
            accounts,
            who,
            password,
            pin,
            switch,
            pin_mode: std::cell::Cell::new(false),
            button,
            spinner,
            label,
            error,
        }
    }

    pub fn connect(&self, ui: &Rc<Ui>) {
        let submit = Rc::new({
            let weak = Rc::downgrade(ui);
            move || {
                let Some(ui) = weak.upgrade() else { return };
                if !ui.unlock.button.is_sensitive() {
                    return;
                }
                ui.unlock.error.set_visible(false);
                if ui.unlock.pin_mode.get() {
                    ui.unlock_with_pin(ui.unlock.pin.text().to_string(), |_| {});
                } else {
                    ui.unlock(ui.unlock.password.text().to_string(), |_| {});
                }
            }
        });
        let s = submit.clone();
        self.button.connect_clicked(move |_| s());
        let s = submit.clone();
        self.password.connect_entry_activated(move |_| s());
        self.pin.connect_entry_activated(move |_| submit());
        let weak = Rc::downgrade(ui);
        self.switch.connect_clicked(move |_| {
            if let Some(ui) = weak.upgrade() {
                let page = &ui.unlock;
                page.show_mode(!page.pin_mode.get());
                page.error.set_visible(false);
                page.focus();
            }
        });
    }

    /// Ask for the PIN when it can open the vault, else the master password.
    pub fn set_pin_available(&self, available: bool) {
        self.switch.set_visible(available);
        self.show_mode(available);
    }

    fn show_mode(&self, pin: bool) {
        self.pin_mode.set(pin);
        self.pin.set_visible(pin);
        self.password.set_visible(!pin);
        self.switch.set_label(if pin {
            "Use Master Password"
        } else {
            "Use PIN"
        });
    }

    pub fn show_account(&self, account: &Account) {
        self.who
            .set_label(&account_line(&account.email, &account.server));
    }

    pub fn focus(&self) {
        if self.pin_mode.get() {
            self.pin.grab_focus();
        } else {
            self.password.grab_focus();
        }
    }

    pub fn set_busy(&self, busy: bool) {
        self.button.set_sensitive(!busy);
        self.password.set_sensitive(!busy);
        self.pin.set_sensitive(!busy);
        self.switch.set_sensitive(!busy);
        self.spinner.set_visible(busy);
        self.label
            .set_label(if busy { "Unlocking…" } else { "Unlock" });
    }

    pub fn fail(&self, message: &str) {
        self.error.set_label(message);
        self.error.set_visible(true);
        let entry = if self.pin_mode.get() {
            &self.pin
        } else {
            &self.password
        };
        entry.grab_focus();
        entry.select_region(0, -1);
    }

    pub fn clear_password(&self) {
        self.password.set_text("");
        self.pin.set_text("");
        self.error.set_visible(false);
    }
}
