//! Export Vault…: pick a format, re-enter the master password (as
//! Bitwarden's apps ask), choose where the file goes.

use super::Ui;
use crate::export::Format;
use crate::session;
use adw::prelude::*;
use gtk::{gio, glib};
use std::rc::Rc;
use zeroize::Zeroizing;

pub fn show(ui: &Rc<Ui>) {
    if !ui.is_unlocked() {
        return;
    }
    let format = adw::ComboRow::builder()
        .title("File format")
        .model(&gtk::StringList::new(
            Format::ALL.map(Format::label).as_ref(),
        ))
        .build();
    let file_password = adw::PasswordEntryRow::builder()
        .title("File password")
        .build();
    let confirm = adw::PasswordEntryRow::builder()
        .title("Confirm file password")
        .build();
    let master = adw::PasswordEntryRow::builder()
        .title("Master password")
        .activates_default(true)
        .build();
    let options = gtk::ListBox::builder()
        .selection_mode(gtk::SelectionMode::None)
        .css_classes(["boxed-list"])
        .build();
    options.append(&format);
    options.append(&file_password);
    options.append(&confirm);
    let check = gtk::ListBox::builder()
        .selection_mode(gtk::SelectionMode::None)
        .css_classes(["boxed-list"])
        .build();
    check.append(&master);
    let warning = gtk::Label::builder()
        .wrap(true)
        .xalign(0.0)
        .css_classes(["caption"])
        .build();
    let column = gtk::Box::builder()
        .orientation(gtk::Orientation::Vertical)
        .spacing(12)
        .build();
    column.append(&options);
    column.append(&warning);
    column.append(&check);

    let dialog = adw::AlertDialog::new(
        Some("Export Vault"),
        Some("Your own items and folders, as Bitwarden's apps export them. Items in organizations, the Trash and attachments aren't included."),
    );
    dialog.set_extra_child(Some(&column));
    dialog.add_responses(&[("cancel", "_Cancel"), ("export", "_Export…")]);
    dialog.set_response_appearance("export", adw::ResponseAppearance::Suggested);
    dialog.set_default_response(Some("export"));
    dialog.set_close_response("cancel");

    let chosen = {
        let format = format.clone();
        move || Format::ALL[format.selected() as usize % Format::ALL.len()]
    };
    let update = {
        let (dialog, chosen) = (dialog.downgrade(), chosen.clone());
        let (file_password, confirm, master, warning) = (
            file_password.clone(),
            confirm.clone(),
            master.clone(),
            warning.clone(),
        );
        move || {
            let Some(dialog) = dialog.upgrade() else {
                return;
            };
            let format = chosen();
            let protected = format == Format::PasswordJson;
            file_password.set_visible(protected);
            confirm.set_visible(protected);
            warning.set_label(match format {
                Format::Json | Format::Csv => {
                    "This file isn't encrypted: anyone who can read it sees your passwords. Keep it somewhere safe, and delete it once you've used it."
                }
                Format::AccountJson => {
                    "Only this account can import it, and only while its encryption key stays the same."
                }
                Format::PasswordJson => {
                    "Anyone with the file password can open it, in any Bitwarden app. It isn't your master password."
                }
            });
            if format.decrypted() {
                warning.add_css_class("warning");
                warning.remove_css_class("dim-label");
            } else {
                warning.remove_css_class("warning");
                warning.add_css_class("dim-label");
            }
            let passwords_ok = !protected
                || (!file_password.text().is_empty() && file_password.text() == confirm.text());
            dialog.set_response_enabled("export", passwords_ok && !master.text().is_empty());
        }
    };
    update();
    let update = Rc::new(update);
    {
        let update = update.clone();
        format.connect_selected_notify(move |_| update());
    }
    for entry in [&file_password, &confirm, &master] {
        let update = update.clone();
        entry.connect_changed(move |_| update());
    }

    let weak = Rc::downgrade(ui);
    let epoch = ui.epoch.get();
    let typed = master.clone();
    dialog.connect_response(Some("export"), move |_, _| {
        let Some(ui) = weak.upgrade().filter(|ui| ui.epoch.get() == epoch) else {
            return;
        };
        let format = chosen();
        let master = Zeroizing::new(typed.text().to_string());
        let file_password = Zeroizing::new(file_password.text().to_string());
        check_then_save(&ui, format, master, file_password);
    });
    ui.present_dialog(&dialog);
    master.grab_focus();
}

/// Check the master password on a worker; then ask where the file goes.
fn check_then_save(
    ui: &Rc<Ui>,
    format: Format,
    master: Zeroizing<String>,
    file_password: Zeroizing<String>,
) {
    let Some(account) = ui.account.borrow().clone() else {
        return;
    };
    let epoch = ui.epoch.get();
    let ui = ui.clone();
    glib::spawn_future_local(async move {
        let checked = {
            let account = account.clone();
            gio::spawn_blocking(move || session::check_master_password(&account, &master))
                .await
                .unwrap_or_else(|_| Err(session::Error::Other("Checking crashed.".into())))
        };
        if ui.epoch.get() != epoch || !ui.is_unlocked() {
            return;
        }
        if let Err(error) = checked {
            return ui.toast(&error.to_string());
        }
        let stamp = glib::DateTime::now_local()
            .ok()
            .and_then(|t| t.format("%Y%m%d%H%M%S").ok())
            .map(|t| t.to_string())
            .unwrap_or_default();
        let dialog = gtk::FileDialog::builder()
            .title("Export Vault")
            .initial_name(format.file_name(&stamp))
            .modal(true)
            .build();
        let weak = Rc::downgrade(&ui);
        dialog.save(Some(&ui.window), None::<&gio::Cancellable>, move |file| {
            let Some(ui) = weak.upgrade().filter(|ui| ui.epoch.get() == epoch) else {
                return;
            };
            let Some(path) = file.ok().and_then(|f| f.path()) else {
                return;
            };
            write(&ui, account.clone(), format, file_password.clone(), path);
        });
    });
}

fn write(
    ui: &Rc<Ui>,
    account: crate::store::Account,
    format: Format,
    file_password: Zeroizing<String>,
    path: std::path::PathBuf,
) {
    let Some(user_key) = ui.session.borrow().as_ref().map(|s| s.keys.user.clone()) else {
        return;
    };
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_default();
    let epoch = ui.epoch.get();
    let ui = ui.clone();
    glib::spawn_future_local(async move {
        let result = gio::spawn_blocking(move || {
            session::export(&account, &user_key, format, &file_password, &path)
        })
        .await
        .unwrap_or_else(|_| Err(session::Error::Other("Exporting crashed.".into())));
        if ui.epoch.get() != epoch {
            return;
        }
        match result {
            Ok(()) => ui.toast(&format!("Vault exported to {name}")),
            Err(error) => {
                log::warn!("export failed: {error}");
                ui.toast(&error.to_string());
            }
        }
    });
}
