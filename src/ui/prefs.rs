//! Preferences: appearance and the security timers.

use super::Ui;
use crate::settings;
use adw::prelude::*;
use std::rc::Rc;

/// A combo row over fixed choices, saved through `save`.
fn choice_row(
    title: &str,
    subtitle: &str,
    choices: &[(u32, &str)],
    current: u32,
    save: impl Fn(u32) + 'static,
) -> adw::ComboRow {
    let labels: Vec<&str> = choices.iter().map(|(_, label)| *label).collect();
    let model = gtk::StringList::new(&labels);
    let row = adw::ComboRow::builder()
        .title(title)
        .subtitle(subtitle)
        .model(&model)
        .build();
    let selected = choices
        .iter()
        .position(|(value, _)| *value == current)
        .unwrap_or(0);
    row.set_selected(selected as u32);
    let values: Vec<u32> = choices.iter().map(|(value, _)| *value).collect();
    row.connect_selected_notify(move |row| {
        if let Some(value) = values.get(row.selected() as usize) {
            save(*value);
        }
    });
    row
}

pub fn show(ui: &Rc<Ui>) {
    let current = settings::get();
    let dialog = adw::PreferencesDialog::new();
    let page = adw::PreferencesPage::new();
    dialog.add(&page);

    let appearance = adw::PreferencesGroup::builder().title("Appearance").build();
    let omarchy_row = adw::SwitchRow::builder()
        .title("Follow Omarchy theme")
        .subtitle(match crate::omarchy::theme_name() {
            Some(name) => format!("Colours from the current theme, {name}"),
            None if crate::omarchy::detected() => "Colours from the current Omarchy theme".into(),
            None => "Omarchy is not installed".into(),
        })
        .active(current.follow_omarchy_theme)
        .sensitive(crate::omarchy::detected())
        .build();
    omarchy_row.connect_active_notify(|row| {
        let on = row.is_active();
        settings::update(|s| s.follow_omarchy_theme = on);
        crate::omarchy::set_follow(on);
    });
    appearance.add(&omarchy_row);
    let icons_row = adw::SwitchRow::builder()
        .title("Show website icons")
        .subtitle("Fetched through your own server's icon service")
        .active(current.show_icons)
        .build();
    let weak = Rc::downgrade(ui);
    icons_row.connect_active_notify(move |row| {
        let on = row.is_active();
        settings::update(|s| s.show_icons = on);
        if let Some(ui) = weak.upgrade() {
            if ui.is_unlocked() {
                ui.vault.rebuild_items(&ui);
            }
        }
    });
    appearance.add(&icons_row);
    page.add(&appearance);

    let security = adw::PreferencesGroup::builder().title("Security").build();
    security.add(&choice_row(
        "Lock in the background",
        "Lock after the window has been unfocused this long",
        &[
            (1, "1 minute"),
            (5, "5 minutes"),
            (15, "15 minutes"),
            (30, "30 minutes"),
            (60, "1 hour"),
            (240, "4 hours"),
            (0, "Never"),
        ],
        current.lock_after_minutes,
        |value| settings::update(|s| s.lock_after_minutes = value),
    ));
    let screen_row = adw::SwitchRow::builder()
        .title("Lock with the screen")
        .subtitle("Lock when the screen locks or the computer sleeps")
        .active(current.lock_with_screen)
        .build();
    screen_row.connect_active_notify(|row| {
        let on = row.is_active();
        settings::update(|s| s.lock_with_screen = on);
    });
    security.add(&screen_row);
    security.add(&choice_row(
        "Clear clipboard",
        "Empty the clipboard this long after copying a secret",
        &[
            (10, "10 seconds"),
            (20, "20 seconds"),
            (30, "30 seconds"),
            (60, "1 minute"),
            (120, "2 minutes"),
            (0, "Never"),
        ],
        current.clear_clipboard_seconds,
        |value| settings::update(|s| s.clear_clipboard_seconds = value),
    ));
    page.add(&security);
    if ui.is_unlocked() {
        page.add(&pin_group(ui, &dialog));
    }

    if let Some(account) = ui.account.borrow().as_ref() {
        let group = adw::PreferencesGroup::builder().title("Account").build();
        group.add(
            &adw::ActionRow::builder()
                .title("Email")
                .subtitle(glib_escape(&account.email))
                .css_classes(["property"])
                .build(),
        );
        group.add(
            &adw::ActionRow::builder()
                .title("Server")
                .subtitle(glib_escape(&account.server))
                .css_classes(["property"])
                .build(),
        );
        let kdf = match account.kdf {
            crate::crypto::Kdf::Pbkdf2 { iterations } => {
                format!("PBKDF2-SHA256, {iterations} iterations")
            }
            crate::crypto::Kdf::Argon2id {
                iterations,
                memory_mib,
                parallelism,
            } => format!(
                "Argon2id, {iterations} iterations, {memory_mib} MiB, parallelism {parallelism}"
            ),
        };
        group.add(
            &adw::ActionRow::builder()
                .title("Key derivation")
                .subtitle(kdf)
                .css_classes(["property"])
                .build(),
        );
        page.add(&group);
    }
    dialog.present(Some(&ui.window));
}

/// Unlock with PIN: turning it on asks for the PIN; keeping it across
/// restarts puts the sealed key on disk.
fn pin_group(ui: &Rc<Ui>, prefs: &adw::PreferencesDialog) -> adw::PreferencesGroup {
    let state = crate::store::load_pin();
    let group = adw::PreferencesGroup::builder()
        .title("PIN")
        .description("Five wrong PINs in a row, and the master password is needed again.")
        .build();
    let on = adw::SwitchRow::builder()
        .title("Unlock with PIN")
        .subtitle("Instead of the master password")
        .active(state.pin.is_some())
        .build();
    let keep = adw::SwitchRow::builder()
        .title("Keep after a restart")
        .subtitle("Otherwise the master password is needed once each time Vord starts. Kept on disk, a PIN is only as strong as it is long: someone with a copy of your files could try every one.")
        .active(state.keep)
        .sensitive(state.pin.is_some())
        .build();
    group.add(&on);
    group.add(&keep);

    // Set while the switches are moved back from code.
    let quiet = Rc::new(std::cell::Cell::new(false));
    let undo = {
        let (on, keep, quiet) = (on.downgrade(), keep.downgrade(), quiet.clone());
        move || {
            let (Some(on), Some(keep)) = (on.upgrade(), keep.upgrade()) else {
                return;
            };
            quiet.set(true);
            on.set_active(false);
            keep.set_active(false);
            keep.set_sensitive(false);
            quiet.set(false);
        }
    };
    let weak = Rc::downgrade(ui);
    let prefs = prefs.downgrade();
    let keep_row = keep.clone();
    on.connect_active_notify(move |row| {
        let Some(ui) = weak.upgrade() else { return };
        if quiet.get() {
            return;
        }
        if !row.is_active() {
            ui.clear_pin();
            undo();
            ui.toast("PIN unlock is off");
            return;
        }
        let (Some(prefs), keep) = (prefs.upgrade(), keep_row.clone()) else {
            return;
        };
        ask_pin(&ui, &prefs, keep, undo.clone());
    });
    let weak = Rc::downgrade(ui);
    keep.connect_active_notify(move |row| {
        if let Some(ui) = weak.upgrade() {
            ui.keep_pin(row.is_active());
        }
    });
    group
}

/// Ask for a new PIN, twice. `undo` turns the switches back off when it's
/// not set.
fn ask_pin(
    ui: &Rc<Ui>,
    prefs: &adw::PreferencesDialog,
    keep: adw::SwitchRow,
    undo: impl Fn() + Clone + 'static,
) {
    let pin = adw::PasswordEntryRow::builder().title("PIN").build();
    let again = adw::PasswordEntryRow::builder()
        .title("PIN again")
        .activates_default(true)
        .build();
    let list = gtk::ListBox::builder()
        .selection_mode(gtk::SelectionMode::None)
        .css_classes(["boxed-list"])
        .build();
    list.append(&pin);
    list.append(&again);
    let dialog = adw::AlertDialog::new(
        Some("Set a PIN"),
        Some("Four or more characters, used only on this computer."),
    );
    dialog.set_extra_child(Some(&list));
    dialog.add_responses(&[("cancel", "_Cancel"), ("set", "_Set PIN")]);
    dialog.set_response_appearance("set", adw::ResponseAppearance::Suggested);
    dialog.set_default_response(Some("set"));
    dialog.set_close_response("cancel");
    dialog.set_response_enabled("set", false);
    let check = {
        let (dialog, pin, again) = (dialog.downgrade(), pin.clone(), again.clone());
        move || {
            if let Some(dialog) = dialog.upgrade() {
                let ok = pin.text().chars().count() >= 4 && pin.text() == again.text();
                dialog.set_response_enabled("set", ok);
            }
        }
    };
    let check = Rc::new(check);
    for entry in [&pin, &again] {
        let check = check.clone();
        entry.connect_changed(move |_| check());
    }
    let weak = Rc::downgrade(ui);
    let typed = pin.clone();
    let cancel = undo.clone();
    dialog.connect_response(None, move |_, response| {
        if response != "set" {
            return cancel();
        }
        let Some(ui) = weak.upgrade() else {
            return cancel();
        };
        let undo = undo.clone();
        let keep = keep.clone();
        ui.set_pin(typed.text().to_string(), keep.is_active(), move |ok| {
            if ok {
                keep.set_sensitive(true);
            } else {
                undo();
            }
        });
    });
    dialog.present(Some(prefs));
    pin.grab_focus();
}

fn glib_escape(text: &str) -> String {
    gtk::glib::markup_escape_text(text).to_string()
}
