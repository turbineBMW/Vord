//! The two pages before the vault: logging in to a server, and unlocking.

use super::Ui;
use crate::store::Account;
use adw::prelude::*;
use std::rc::Rc;

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
        column.append(&button);
        column.append(&note);
        Self {
            root: frame(&column),
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

pub struct UnlockPage {
    pub root: adw::ToolbarView,
    who: gtk::Label,
    password: adw::PasswordEntryRow,
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
        let (button, spinner, label) = action_button("Unlock");
        let error = error_label();
        let logout = gtk::Button::builder()
            .label("Log Out…")
            .action_name("win.logout")
            .css_classes(["flat"])
            .halign(gtk::Align::Center)
            .margin_top(12)
            .build();
        let column = gtk::Box::new(gtk::Orientation::Vertical, 0);
        column.append(&brand);
        column.append(&locked);
        column.append(&group);
        column.append(&error);
        column.append(&button);
        column.append(&logout);
        Self {
            root: frame(&column),
            who,
            password,
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
                ui.unlock(ui.unlock.password.text().to_string());
            }
        });
        let s = submit.clone();
        self.button.connect_clicked(move |_| s());
        self.password.connect_entry_activated(move |_| submit());
    }

    pub fn show_account(&self, account: &Account) {
        let host = url::Url::parse(&account.server)
            .ok()
            .and_then(|u| u.host_str().map(str::to_string))
            .unwrap_or_else(|| account.server.clone());
        self.who.set_label(&format!("{} on {host}", account.email));
    }

    pub fn focus(&self) {
        self.password.grab_focus();
    }

    pub fn set_busy(&self, busy: bool) {
        self.button.set_sensitive(!busy);
        self.password.set_sensitive(!busy);
        self.spinner.set_visible(busy);
        self.label
            .set_label(if busy { "Unlocking…" } else { "Unlock" });
    }

    pub fn fail(&self, message: &str) {
        self.error.set_label(message);
        self.error.set_visible(true);
        self.password.grab_focus();
        self.password.select_region(0, -1);
    }

    pub fn clear_password(&self) {
        self.password.set_text("");
        self.error.set_visible(false);
    }
}
