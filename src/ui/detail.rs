//! One item, laid out for reading and copying.
//!
//! Secrets start hidden; each has a reveal toggle and a copy button. An item
//! with Bitwarden's master-password re-prompt asks for the master password
//! before either. The widget tree is rebuilt for every item shown and
//! dropped when the vault locks, taking the decrypted text with it.

use super::Ui;
use crate::totp::{self, Totp};
use crate::vault::{FieldKind, Item, Kind, Vault};
use adw::prelude::*;
use gtk::glib;
use std::rc::Rc;
use std::time::Duration;

const MASK: &str = "••••••••••••";

pub fn open_url(ui: &Rc<Ui>, url: &str) {
    let launcher = gtk::UriLauncher::new(url);
    let ui = Rc::downgrade(ui);
    launcher.launch(
        None::<&gtk::Window>,
        None::<&gtk::gio::Cancellable>,
        move |result| {
            if let (Err(error), Some(ui)) = (result, ui.upgrade()) {
                if !error.matches(gtk::DialogError::Dismissed) {
                    ui.toast(&format!("Could not open the website: {}", error.message()));
                }
            }
        },
    );
}

fn icon_button(icon: &str, tooltip: &str) -> gtk::Button {
    gtk::Button::builder()
        .icon_name(icon)
        .tooltip_text(tooltip)
        .valign(gtk::Align::Center)
        .css_classes(["flat"])
        .build()
}

/// Escape for the subtitle, which libadwaita reads as Pango markup.
fn plain(text: &str) -> String {
    glib::markup_escape_text(text).to_string()
}

struct Builder<'a> {
    ui: &'a Rc<Ui>,
    item: &'a Item,
    column: gtk::Box,
}

impl Builder<'_> {
    fn group(&self, title: &str) -> adw::PreferencesGroup {
        let group = adw::PreferencesGroup::builder().title(title).build();
        self.column.append(&group);
        group
    }

    /// Run `then` now, or after the re-prompt for a protected item.
    fn guarded(&self, then: impl Fn() + 'static) -> impl Fn() + 'static {
        let ui = Rc::downgrade(self.ui);
        let id = self.item.id.clone();
        let reprompt = self.item.reprompt;
        let then = Rc::new(then);
        move || {
            let Some(ui) = ui.upgrade() else { return };
            if reprompt {
                let then = then.clone();
                ui.reprompt(&id, move || then());
            } else {
                then();
            }
        }
    }

    /// A plain value with a copy button.
    fn text_row(&self, group: &adw::PreferencesGroup, title: &str, value: &str, copy_what: &str) {
        if value.is_empty() {
            return;
        }
        let row = adw::ActionRow::builder()
            .title(title)
            .subtitle(plain(value))
            .subtitle_selectable(true)
            .css_classes(["property"])
            .build();
        let copy = icon_button("edit-copy-symbolic", &format!("Copy {copy_what}"));
        let ui = Rc::downgrade(self.ui);
        let (what, text) = (copy_what.to_string(), value.to_string());
        copy.connect_clicked(move |_| {
            if let Some(ui) = ui.upgrade() {
                ui.copy(&capitalise(&what), &text, false);
            }
        });
        row.add_suffix(&copy);
        group.add(&row);
    }

    /// A hidden value: masked until revealed, copyable.
    fn secret_row(&self, group: &adw::PreferencesGroup, title: &str, value: &str, copy_what: &str) {
        if !value.is_empty() {
            group.add(&self.secret(title, value, copy_what));
        }
    }

    fn secret(&self, title: &str, value: &str, copy_what: &str) -> adw::ActionRow {
        let row = adw::ActionRow::builder()
            .title(title)
            .subtitle(MASK)
            .css_classes(["property", "monospace-value"])
            .build();
        let reveal = gtk::ToggleButton::builder()
            .icon_name("view-reveal-symbolic")
            .tooltip_text("Show")
            .valign(gtk::Align::Center)
            .css_classes(["flat"])
            .build();
        let secret = value.to_string();
        {
            let row = row.downgrade();
            let secret = secret.clone();
            let reprompt = self.item.reprompt;
            let ui = Rc::downgrade(self.ui);
            let id = self.item.id.clone();
            reveal.connect_toggled(move |button| {
                let (Some(row), Some(ui)) = (row.upgrade(), ui.upgrade()) else {
                    return;
                };
                let shown = button.is_active();
                if shown && reprompt && !ui.reprompt_cleared_for(&id) {
                    // Back up until the master password has been re-entered;
                    // then press it again, which lands in the branch below.
                    button.set_active(false);
                    let button = button.downgrade();
                    ui.reprompt(&id, move || {
                        if let Some(button) = button.upgrade() {
                            button.set_active(true);
                        }
                    });
                    return;
                }
                button.set_icon_name(if shown {
                    "view-conceal-symbolic"
                } else {
                    "view-reveal-symbolic"
                });
                button.set_tooltip_text(Some(if shown { "Hide" } else { "Show" }));
                row.set_subtitle(&if shown {
                    plain(&secret)
                } else {
                    MASK.to_string()
                });
                row.set_subtitle_selectable(shown);
            });
        }
        let copy = icon_button("edit-copy-symbolic", &format!("Copy {copy_what}"));
        let copy_action = {
            let ui = Rc::downgrade(self.ui);
            let what = capitalise(copy_what);
            self.guarded(move || {
                if let Some(ui) = ui.upgrade() {
                    ui.copy(&what, &secret, true);
                }
            })
        };
        copy.connect_clicked(move |_| copy_action());
        row.add_suffix(&reveal);
        row.add_suffix(&copy);
        row
    }

    fn totp_row(&self, group: &adw::PreferencesGroup, totp: Totp) {
        let row = adw::ActionRow::builder()
            .title("Verification code (TOTP)")
            .css_classes(["property"])
            .build();
        let code = gtk::Label::builder()
            .css_classes(["totp-code"])
            .valign(gtk::Align::Center)
            .build();
        let timer = gtk::Label::builder()
            .css_classes(["totp-timer", "dim-label"])
            .valign(gtk::Align::Center)
            .build();
        let copy = icon_button("edit-copy-symbolic", "Copy Verification Code");
        let show_codes = !self.item.reprompt;
        let refresh = {
            let (code, timer) = (code.downgrade(), timer.downgrade());
            let totp = totp.clone();
            let ui = Rc::downgrade(self.ui);
            let id = self.item.id.clone();
            move || -> bool {
                let (Some(code), Some(timer)) = (code.upgrade(), timer.upgrade()) else {
                    return false;
                };
                let visible =
                    show_codes || ui.upgrade().is_some_and(|ui| ui.reprompt_cleared_for(&id));
                let (now, left) = totp.now();
                code.set_label(&if visible {
                    totp::grouped(&now)
                } else {
                    "••• •••".into()
                });
                timer.set_label(&format!("{left}s"));
                if left <= 5 {
                    timer.add_css_class("expiring");
                } else {
                    timer.remove_css_class("expiring");
                }
                true
            }
        };
        refresh();
        glib::timeout_add_local(Duration::from_millis(500), move || {
            if refresh() {
                glib::ControlFlow::Continue
            } else {
                glib::ControlFlow::Break
            }
        });
        let copy_action = {
            let ui = Rc::downgrade(self.ui);
            self.guarded(move || {
                if let Some(ui) = ui.upgrade() {
                    ui.copy("Verification code", &totp.now().0, true);
                }
            })
        };
        copy.connect_clicked(move |_| copy_action());
        row.add_suffix(&code);
        row.add_suffix(&timer);
        row.add_suffix(&copy);
        group.add(&row);
    }

    fn website_row(&self, group: &adw::PreferencesGroup, uri: &str, launch: Option<String>) {
        let row = adw::ActionRow::builder()
            .title("Website")
            .subtitle(plain(uri))
            .subtitle_selectable(true)
            .css_classes(["property"])
            .build();
        if let Some(url) = launch {
            let open = icon_button("adw-external-link-symbolic", "Open in Browser");
            let ui = Rc::downgrade(self.ui);
            open.connect_clicked(move |_| {
                if let Some(ui) = ui.upgrade() {
                    open_url(&ui, &url);
                }
            });
            row.add_suffix(&open);
        }
        let copy = icon_button("edit-copy-symbolic", "Copy Website");
        let ui = Rc::downgrade(self.ui);
        let text = uri.to_string();
        copy.connect_clicked(move |_| {
            if let Some(ui) = ui.upgrade() {
                ui.copy("Website", &text, false);
            }
        });
        row.add_suffix(&copy);
        group.add(&row);
    }

    fn info_row(&self, group: &adw::PreferencesGroup, title: &str, value: &str) {
        group.add(
            &adw::ActionRow::builder()
                .title(title)
                .subtitle(plain(value))
                .css_classes(["property"])
                .build(),
        );
    }

    fn text_card(&self, title: &str, text: &str) {
        let group = self.group(title);
        let label = gtk::Label::builder()
            .label(text)
            .xalign(0.0)
            .wrap(true)
            .wrap_mode(gtk::pango::WrapMode::WordChar)
            .selectable(true)
            .css_classes(["notes-card"])
            .build();
        let card = gtk::Box::builder().css_classes(["card"]).build();
        card.append(&label);
        group.add(&card);
    }
}

fn capitalise(text: &str) -> String {
    let mut chars = text.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().chain(chars).collect(),
        None => String::new(),
    }
}

/// "12 Mar 2026, 14:05", in local time.
fn when(iso: &str) -> Option<String> {
    let time = glib::DateTime::from_iso8601(iso, Some(&glib::TimeZone::utc())).ok()?;
    let local = time.to_local().ok()?;
    Some(local.format("%e %b %Y, %H:%M").ok()?.trim().to_string())
}

pub fn build(ui: &Rc<Ui>, vault: &Vault, item: &Item) -> gtk::Widget {
    let outer = gtk::Box::new(gtk::Orientation::Vertical, 0);

    // -- The header block: icon, name, where it lives.
    let header = gtk::Box::builder()
        .spacing(18)
        .css_classes(["detail-header"])
        .build();
    let server = ui.server().unwrap_or_default();
    header.append(&super::vault::item_icon(
        item,
        &server,
        crate::settings::get().show_icons,
        64,
    ));
    let titles = gtk::Box::builder()
        .orientation(gtk::Orientation::Vertical)
        .spacing(4)
        .valign(gtk::Align::Center)
        .hexpand(true)
        .build();
    let name_line = gtk::Box::builder().spacing(8).build();
    name_line.append(
        &gtk::Label::builder()
            .label(&item.name)
            .xalign(0.0)
            .wrap(true)
            .css_classes(["detail-title"])
            .build(),
    );
    if item.favorite {
        name_line.append(
            &gtk::Image::builder()
                .icon_name("starred-symbolic")
                .tooltip_text("Favorite")
                .css_classes(["favorite-star"])
                .build(),
        );
    }
    titles.append(&name_line);
    let mut meta = vec![item.kind.label().to_string()];
    if let Some(folder) = item
        .folder_id
        .as_deref()
        .and_then(|id| vault.folders.iter().find(|f| f.id == id))
    {
        meta.push(folder.name.clone());
    }
    if let Some(org) = item
        .org_id
        .as_deref()
        .and_then(|id| vault.organizations.iter().find(|o| o.id == id))
    {
        let collections: Vec<&str> = vault
            .collections
            .iter()
            .filter(|c| item.collection_ids.contains(&c.id))
            .map(|c| c.name.as_str())
            .collect();
        if collections.is_empty() {
            meta.push(org.name.clone());
        } else {
            meta.push(format!("{} › {}", org.name, collections.join(", ")));
        }
    }
    if item.deleted {
        meta.push("In Trash".into());
    }
    titles.append(
        &gtk::Label::builder()
            .label(meta.join("  ·  "))
            .xalign(0.0)
            .wrap(true)
            .css_classes(["detail-meta", "dim-label"])
            .build(),
    );
    header.append(&titles);
    outer.append(&header);

    let column = gtk::Box::builder()
        .orientation(gtk::Orientation::Vertical)
        .spacing(24)
        .margin_top(24)
        .margin_bottom(32)
        .margin_start(12)
        .margin_end(12)
        .build();
    let clamp = adw::Clamp::builder()
        .maximum_size(720)
        .child(&column)
        .build();
    outer.append(&clamp);
    let b = Builder {
        ui,
        item,
        column: column.clone(),
    };

    if item.damaged {
        let banner = gtk::Label::builder()
            .label("Part of this item could not be decrypted, so some fields may be missing.")
            .wrap(true)
            .xalign(0.0)
            .css_classes(["damaged-banner"])
            .build();
        column.append(&banner);
    }
    if item.reprompt {
        let note = gtk::Box::builder().spacing(8).build();
        note.append(&gtk::Image::from_icon_name("system-lock-screen-symbolic"));
        note.append(
            &gtk::Label::builder()
                .label("Protected: Vord asks for your master password before showing or copying this item's secrets.")
                .wrap(true)
                .xalign(0.0)
                .css_classes(["dim-label", "caption"])
                .build(),
        );
        column.append(&note);
    }

    match item.kind {
        Kind::Login => {
            if let Some(login) = &item.login {
                let group = b.group("Login");
                if let Some(username) = &login.username {
                    b.text_row(&group, "Username", username, "username");
                }
                if let Some(password) = &login.password {
                    b.secret_row(&group, "Password", password, "password");
                }
                if let Some(totp) = login.totp.as_deref() {
                    match Totp::parse(totp) {
                        Some(totp) => b.totp_row(&group, totp),
                        None => {
                            b.secret_row(&group, "Authenticator key", totp, "authenticator key")
                        }
                    }
                }
                if login.passkeys > 0 {
                    b.info_row(
                        &group,
                        "Passkey",
                        "Saved (use it from a Bitwarden browser extension or app)",
                    );
                }
                if group.first_child().is_some()
                    && login.username.is_none()
                    && login.password.is_none()
                    && login.totp.is_none()
                    && login.passkeys == 0
                {
                    group.set_visible(false);
                }
                if !login.uris.is_empty() {
                    let sites = b.group(if login.uris.len() == 1 {
                        "Website"
                    } else {
                        "Websites"
                    });
                    for uri in &login.uris {
                        b.website_row(&sites, &uri.uri, uri.launch_url());
                    }
                }
            }
        }
        Kind::Card => {
            if let Some(card) = &item.card {
                let group = b.group("Card");
                if let Some(name) = &card.cardholder {
                    b.text_row(&group, "Cardholder name", name, "name");
                }
                if let Some(number) = &card.number {
                    b.secret_row(&group, "Number", number, "card number");
                }
                if let Some(brand) = &card.brand {
                    b.info_row(&group, "Brand", brand);
                }
                if let Some(expiry) = card.expiry() {
                    b.text_row(&group, "Expiration", &expiry, "expiration date");
                }
                if let Some(code) = &card.code {
                    b.secret_row(&group, "Security code", code, "security code");
                }
            }
        }
        Kind::Identity => {
            if let Some(identity) = &item.identity {
                let group = b.group("Identity");
                if let Some(name) = &identity.full_name {
                    b.text_row(&group, "Name", name, "name");
                }
                for (label, value) in &identity.fields {
                    if matches!(
                        *label,
                        "Social security number" | "Passport number" | "License number"
                    ) {
                        b.secret_row(&group, label, value, &label.to_lowercase());
                    } else {
                        b.text_row(&group, label, value, &label.to_lowercase());
                    }
                }
                if let Some(address) = &identity.address {
                    let group = b.group("Address");
                    b.text_row(&group, "Address", address, "address");
                }
            }
        }
        Kind::SshKey => {
            if let Some(key) = &item.ssh_key {
                let group = b.group("SSH key");
                if let Some(public) = &key.public_key {
                    b.text_row(&group, "Public key", public, "public key");
                }
                if let Some(fingerprint) = &key.fingerprint {
                    b.text_row(&group, "Fingerprint", fingerprint, "fingerprint");
                }
                if let Some(private) = &key.private_key {
                    b.secret_row(&group, "Private key", private, "private key");
                }
            }
        }
        Kind::Note => {}
    }

    if let Some(notes) = item.notes.as_deref().filter(|n| !n.trim().is_empty()) {
        b.text_card("Notes", notes);
    }

    if !item.fields.is_empty() {
        let group = b.group("Custom fields");
        for field in &item.fields {
            let title = if field.name.is_empty() {
                "Field"
            } else {
                field.name.as_str()
            };
            match field.kind {
                FieldKind::Text => b.text_row(&group, title, &field.value, title),
                FieldKind::Hidden => b.secret_row(&group, title, &field.value, title),
                FieldKind::Boolean => {
                    let on = field.value.eq_ignore_ascii_case("true");
                    let row = adw::ActionRow::builder().title(title).build();
                    row.add_suffix(
                        &gtk::Image::builder()
                            .icon_name(if on {
                                "object-select-symbolic"
                            } else {
                                "window-close-symbolic"
                            })
                            .tooltip_text(if on { "Yes" } else { "No" })
                            .css_classes(if on {
                                vec!["accent"]
                            } else {
                                vec!["dim-label"]
                            })
                            .build(),
                    );
                    group.add(&row);
                }
                FieldKind::Linked => b.info_row(&group, title, "Linked to another field"),
            }
        }
    }

    if !item.attachments.is_empty() {
        let group = b.group("Attachments");
        group.set_description(Some("Vord can't download attachments yet."));
        for name in &item.attachments {
            let row = adw::ActionRow::builder().title(plain(name)).build();
            row.add_prefix(&gtk::Image::from_icon_name("mail-attachment-symbolic"));
            group.add(&row);
        }
    }

    // -- When it changed.
    let mut history = Vec::new();
    if let Some(revised) = item.revised.as_deref().and_then(when) {
        history.push(format!("Updated {revised}"));
    }
    if let Some(created) = item.created.as_deref().and_then(when) {
        history.push(format!("Created {created}"));
    }
    if let Some(changed) = item
        .login
        .as_ref()
        .and_then(|l| l.password_revision.as_deref())
        .and_then(when)
    {
        history.push(format!("Password changed {changed}"));
    }
    if !item.password_history.is_empty() {
        let group = b.group("");
        let count = item.password_history.len();
        let expander = adw::ExpanderRow::builder()
            .title("Password history")
            .subtitle(format!(
                "{count} earlier password{}",
                if count == 1 { "" } else { "s" }
            ))
            .build();
        for past in &item.password_history {
            let title = past
                .until
                .as_deref()
                .and_then(when)
                .map_or("Earlier".to_string(), |w| format!("Until {w}"));
            expander.add_row(&b.secret(&title, &past.password, "password"));
        }
        group.add(&expander);
    }
    if !history.is_empty() {
        column.append(
            &gtk::Label::builder()
                .label(history.join("\n"))
                .xalign(0.0)
                .css_classes(["dim-label", "caption"])
                .margin_start(12)
                .build(),
        );
    }
    outer.upcast()
}
