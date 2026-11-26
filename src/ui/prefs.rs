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
    let transparent_row = adw::SwitchRow::builder()
        .title("Transparent sidebar")
        .subtitle("Show the desktop behind the vaults and the item list")
        .active(current.transparent_sidebar)
        .build();
    let opacity_row = adw::ActionRow::builder().title("Sidebar opacity").build();
    let scale = gtk::Scale::with_range(gtk::Orientation::Horizontal, 0.0, 1.0, 0.05);
    scale.set_value(current.sidebar_opacity as f64);
    scale.set_draw_value(true);
    scale.set_value_pos(gtk::PositionType::Left);
    scale.set_hexpand(true);
    scale.set_width_request(160);
    scale.set_valign(gtk::Align::Center);
    scale.set_format_value_func(|_, value| format!("{}%", (value * 100.0).round()));
    opacity_row.add_suffix(&scale);
    opacity_row.set_activatable_widget(Some(&scale));
    transparent_row
        .bind_property("active", &opacity_row, "sensitive")
        .sync_create()
        .build();
    transparent_row.connect_active_notify(|row| {
        let on = row.is_active();
        settings::update(|s| s.transparent_sidebar = on);
        crate::sidebar::apply();
    });
    scale.connect_value_changed(|scale| {
        let value = ((scale.value() * 100.0).round() / 100.0) as f32;
        settings::update(|s| s.sidebar_opacity = value);
        crate::sidebar::apply();
    });
    appearance.add(&transparent_row);
    appearance.add(&opacity_row);
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
    page.add(&background_group(ui, &current));
    page.add(&tray_group(ui, &current));
    page.add(&agent_group(ui, &current));

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

/// Running without a window (and without a tray icon), and starting at login.
fn background_group(ui: &Rc<Ui>, current: &settings::Settings) -> adw::PreferencesGroup {
    let group = adw::PreferencesGroup::builder()
        .title("Background")
        .description("Keeps the SSH agent there when no window is open. Open Vord from the app launcher to show it again.")
        .build();
    let run = adw::SwitchRow::builder()
        .title("Run in background")
        .subtitle("Closing the window keeps Vord running; quit with Ctrl+Q")
        .active(current.run_in_background)
        .build();
    run.connect_active_notify(|row| {
        let on = row.is_active();
        settings::update(|s| s.run_in_background = on);
    });
    group.add(&run);
    let login = adw::SwitchRow::builder()
        .title("Start at login")
        .subtitle("Starts without a window, locked")
        .active(current.start_at_login)
        .build();
    let weak = Rc::downgrade(ui);
    login.connect_active_notify(move |row| {
        let on = row.is_active();
        match crate::autostart::set(on) {
            Ok(()) => settings::update(|s| s.start_at_login = on),
            Err(error) => {
                log::warn!("autostart entry: {error}");
                if let Some(ui) = weak.upgrade() {
                    ui.toast(&format!("Couldn't change starting at login: {error}"));
                }
            }
        }
    });
    group.add(&login);
    group
}

/// The tray icon, and whether closing the window leaves Vord in it.
fn tray_group(ui: &Rc<Ui>, current: &settings::Settings) -> adw::PreferencesGroup {
    let group = adw::PreferencesGroup::builder().title("Tray").build();
    let on = adw::SwitchRow::builder()
        .title("Show in the tray")
        .subtitle("An icon to show, hide or lock Vord")
        .active(current.tray)
        .build();
    let weak = Rc::downgrade(ui);
    on.connect_active_notify(move |row| {
        let on = row.is_active();
        settings::update(|s| s.tray = on);
        if let Some(ui) = weak.upgrade() {
            if on {
                ui.start_tray();
            } else {
                ui.stop_tray();
            }
        }
    });
    group.add(&on);
    let close = adw::SwitchRow::builder()
        .title("Close to the tray")
        .subtitle("Closing the window keeps Vord running; quit from the tray or with Ctrl+Q")
        .active(current.close_to_tray)
        .build();
    close.connect_active_notify(|row| {
        let on = row.is_active();
        settings::update(|s| s.close_to_tray = on);
    });
    on.bind_property("active", &close, "sensitive")
        .sync_create()
        .build();
    group.add(&close);
    group
}

/// The SSH agent: on or off, where it listens, when it asks.
fn agent_group(ui: &Rc<Ui>, current: &settings::Settings) -> adw::PreferencesGroup {
    let path = crate::agent::socket_path();
    let group = adw::PreferencesGroup::builder()
        .title("SSH Agent")
        .description("Lets ssh and git use the vault's SSH keys, as Bitwarden's desktop app does.")
        .build();
    let on = adw::SwitchRow::builder()
        .title("Serve SSH keys")
        .subtitle("Point SSH_AUTH_SOCK at the socket below")
        .active(current.ssh_agent)
        .build();
    let weak = Rc::downgrade(ui);
    on.connect_active_notify(move |row| {
        let on = row.is_active();
        settings::update(|s| s.ssh_agent = on);
        if let Some(ui) = weak.upgrade() {
            if on {
                super::agent::start(&ui);
            } else {
                super::agent::stop(&ui);
            }
        }
    });
    group.add(&on);
    let line = format!("export SSH_AUTH_SOCK={}", path.display());
    let socket = adw::ActionRow::builder()
        .title("Socket")
        .subtitle(glib_escape(&line))
        .subtitle_selectable(true)
        .css_classes(["property", "monospace-value"])
        .build();
    let copy = gtk::Button::builder()
        .icon_name("edit-copy-symbolic")
        .tooltip_text("Copy")
        .valign(gtk::Align::Center)
        .css_classes(["flat"])
        .build();
    let weak = Rc::downgrade(ui);
    copy.connect_clicked(move |_| {
        if let Some(ui) = weak.upgrade() {
            ui.copy("Line", &line, false);
        }
    });
    socket.add_suffix(&copy);
    on.bind_property("active", &socket, "sensitive")
        .sync_create()
        .build();
    group.add(&socket);
    let ask = choice_row(
        "Ask before using a key",
        "Vord shows which program wants it",
        &[(0, "Every time"), (1, "Once until locked"), (2, "Never")],
        current.ssh_agent_ask,
        |value| settings::update(|s| s.ssh_agent_ask = value),
    );
    on.bind_property("active", &ask, "sensitive")
        .sync_create()
        .build();
    group.add(&ask);
    let program = crate::askpass::program();
    let askpass = adw::SwitchRow::builder()
        .title("Ask in the password dialog")
        .subtitle(match &program {
            Some(program) => glib_escape(&format!(
                "Unlock and allow keys through {} ($SSH_ASKPASS), without Vord's window",
                program.file_name().map_or_else(
                    || program.display().to_string(),
                    |n| n.to_string_lossy().into_owned()
                )
            )),
            None => "Needs $SSH_ASKPASS, which this session doesn't set".into(),
        })
        .active(current.ssh_agent_askpass)
        .build();
    askpass.connect_active_notify(|row| {
        let on = row.is_active();
        settings::update(|s| s.ssh_agent_askpass = on);
    });
    if program.is_some() {
        on.bind_property("active", &askpass, "sensitive")
            .sync_create()
            .build();
    } else {
        askpass.set_sensitive(false);
    }
    group.add(&askpass);
    group
}

/// Unlock with PIN: turning it on asks for the PIN; keeping it across
/// restarts puts the sealed key on disk.
fn pin_group(ui: &Rc<Ui>, prefs: &adw::PreferencesDialog) -> adw::PreferencesGroup {
    let state = ui
        .account
        .borrow()
        .as_ref()
        .map(crate::store::load_pin)
        .unwrap_or_default();
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
