//! The generator dialog: a password, passphrase or username, made afresh
//! whenever an option changes, with this session's copied values one page
//! over. Options are saved; values never are. History lives in the
//! unlocked session, so locking forgets it, and the dialog closes on lock.

use super::Ui;
use crate::generator::{self, Kind, Options, UsernameKind};
use crate::settings;
use adw::prelude::*;
use gtk::glib;
use std::cell::RefCell;
use std::rc::{Rc, Weak};

/// Bitwarden keeps this many.
const HISTORY_LIMIT: usize = 100;

/// One value copied from the generator.
pub struct Generated {
    pub kind: Kind,
    pub value: String,
    pub when: glib::DateTime,
}

fn kind_name(kind: Kind) -> &'static str {
    match kind {
        Kind::Password => "password",
        Kind::Passphrase => "passphrase",
        Kind::Username => "username",
    }
}

fn kind_label(kind: Kind) -> &'static str {
    match kind {
        Kind::Password => "Password",
        Kind::Passphrase => "Passphrase",
        Kind::Username => "Username",
    }
}

struct State {
    ui: Weak<Ui>,
    options: RefCell<Options>,
    value: RefCell<Option<String>>,
    label: gtk::Label,
    copy: gtk::Button,
}

impl State {
    fn change(&self, edit: impl FnOnce(&mut Options)) {
        edit(&mut self.options.borrow_mut());
        let options = self.options.borrow().clone();
        settings::update(|s| s.generator = options);
        self.generate();
    }

    fn generate(&self) {
        let options = self.options.borrow().clone();
        let made = match options.kind {
            Kind::Password => Ok(generator::password(&options.password)),
            Kind::Passphrase => Ok(generator::passphrase(&options.passphrase)),
            Kind::Username => {
                let email = self
                    .ui
                    .upgrade()
                    .and_then(|ui| ui.account.borrow().as_ref().map(|a| a.email.clone()))
                    .unwrap_or_default();
                generator::username(&options.username, &email)
            }
        };
        match made {
            Ok(value) => {
                self.label.set_label(&value);
                self.label.remove_css_class("error");
                self.copy.set_sensitive(true);
                self.value.replace(Some(value));
            }
            Err(why) => {
                self.label.set_label(&why);
                self.label.add_css_class("error");
                self.copy.set_sensitive(false);
                self.value.replace(None);
            }
        }
    }

    fn copy(&self) {
        let (Some(ui), Some(value)) = (self.ui.upgrade(), self.value.borrow().clone()) else {
            return;
        };
        let kind = self.options.borrow().kind;
        ui.copy(kind_label(kind), &value, kind != Kind::Username);
        let mut session = ui.session.borrow_mut();
        if let Some(session) = session.as_mut() {
            let history = &mut session.generated;
            history.retain(|g| g.value != value);
            history.push(Generated {
                kind,
                value,
                when: glib::DateTime::now_local().expect("local time"),
            });
            if history.len() > HISTORY_LIMIT {
                history.remove(0);
            }
        }
    }
}

fn switch(title: &str, active: bool) -> adw::SwitchRow {
    // Titles aren't markup: "!@#$%^&*" has an ampersand.
    adw::SwitchRow::builder()
        .title(title)
        .use_markup(false)
        .active(active)
        .build()
}

fn spin(title: &str, range: std::ops::RangeInclusive<u32>, value: u32) -> adw::SpinRow {
    let row = adw::SpinRow::with_range(f64::from(*range.start()), f64::from(*range.end()), 1.0);
    row.set_title(title);
    row.set_value(f64::from(value));
    row
}

fn as_count(row: &adw::SpinRow) -> u32 {
    row.value().round() as u32
}

fn password_group(state: &Rc<State>) -> adw::PreferencesGroup {
    let o = state.options.borrow().password.clone();
    let group = adw::PreferencesGroup::new();
    let length = spin("Length", generator::LENGTH, o.length);
    let upper = switch("Uppercase (A–Z)", o.uppercase);
    let lower = switch("Lowercase (a–z)", o.lowercase);
    let digits = switch("Numbers (0–9)", o.digits);
    let special = switch(&format!("Special ({})", generator::SPECIAL), o.special);
    let min_digits = spin("Minimum numbers", generator::MINIMUM, o.min_digits);
    let min_special = spin("Minimum special", generator::MINIMUM, o.min_special);
    let ambiguous = switch("Avoid ambiguous characters", o.avoid_ambiguous);
    min_digits.set_sensitive(o.digits);
    min_special.set_sensitive(o.special);
    for row in [
        length.upcast_ref::<gtk::Widget>(),
        upper.upcast_ref(),
        lower.upcast_ref(),
        digits.upcast_ref(),
        special.upcast_ref(),
        min_digits.upcast_ref(),
        min_special.upcast_ref(),
        ambiguous.upcast_ref(),
    ] {
        group.add(row);
    }
    let s = state.clone();
    length.connect_value_notify(move |row| s.change(|o| o.password.length = as_count(row)));
    let s = state.clone();
    min_digits.connect_value_notify(move |row| s.change(|o| o.password.min_digits = as_count(row)));
    let s = state.clone();
    min_special
        .connect_value_notify(move |row| s.change(|o| o.password.min_special = as_count(row)));
    let s = state.clone();
    upper.connect_active_notify(move |row| s.change(|o| o.password.uppercase = row.is_active()));
    let s = state.clone();
    lower.connect_active_notify(move |row| s.change(|o| o.password.lowercase = row.is_active()));
    let s = state.clone();
    let min = min_digits.clone();
    digits.connect_active_notify(move |row| {
        min.set_sensitive(row.is_active());
        s.change(|o| o.password.digits = row.is_active());
    });
    let s = state.clone();
    let min = min_special.clone();
    special.connect_active_notify(move |row| {
        min.set_sensitive(row.is_active());
        s.change(|o| o.password.special = row.is_active());
    });
    let s = state.clone();
    ambiguous.connect_active_notify(move |row| {
        s.change(|o| o.password.avoid_ambiguous = row.is_active())
    });
    group
}

fn passphrase_group(state: &Rc<State>) -> adw::PreferencesGroup {
    let o = state.options.borrow().passphrase.clone();
    let group = adw::PreferencesGroup::new();
    let words = spin("Number of words", generator::WORDS, o.words);
    let separator = adw::EntryRow::builder()
        .title("Word separator")
        .text(&o.separator)
        .build();
    let capitalize = switch("Capitalize", o.capitalize);
    let number = switch("Include number", o.include_number);
    group.add(&words);
    group.add(&separator);
    group.add(&capitalize);
    group.add(&number);
    let s = state.clone();
    words.connect_value_notify(move |row| s.change(|o| o.passphrase.words = as_count(row)));
    let s = state.clone();
    separator.connect_changed(move |row| {
        let text = row.text();
        if text.chars().count() > 1 {
            // One character: keep the newest. Not inside the signal.
            let last: String = text.chars().last().into_iter().collect();
            let row = row.clone();
            glib::idle_add_local_once(move || {
                row.set_text(&last);
                row.set_position(-1);
            });
            return;
        }
        s.change(|o| o.passphrase.separator = text.to_string());
    });
    let s = state.clone();
    capitalize
        .connect_active_notify(move |row| s.change(|o| o.passphrase.capitalize = row.is_active()));
    let s = state.clone();
    number.connect_active_notify(move |row| {
        s.change(|o| o.passphrase.include_number = row.is_active())
    });
    group
}

const USERNAME_KINDS: [(UsernameKind, &str); 3] = [
    (UsernameKind::RandomWord, "Random word"),
    (UsernameKind::PlusAddressed, "Plus-addressed email"),
    (UsernameKind::CatchAll, "Catch-all email"),
];

fn username_group(state: &Rc<State>) -> adw::PreferencesGroup {
    let o = state.options.borrow().username.clone();
    let group = adw::PreferencesGroup::new();
    let labels: Vec<&str> = USERNAME_KINDS.iter().map(|(_, label)| *label).collect();
    let kind = adw::ComboRow::builder()
        .title("Type")
        .model(&gtk::StringList::new(&labels))
        .build();
    let selected = USERNAME_KINDS
        .iter()
        .position(|(k, _)| *k == o.kind)
        .unwrap_or(0);
    kind.set_selected(selected as u32);
    let capitalize = switch("Capitalize", o.capitalize);
    let number = switch("Include number", o.include_number);
    let email = adw::EntryRow::builder()
        .title("Email")
        .text(&o.email)
        .input_purpose(gtk::InputPurpose::Email)
        .build();
    if let Some(ui) = state.ui.upgrade() {
        if let Some(account) = ui.account.borrow().as_ref() {
            // Empty means the account's own address; say which.
            email.set_tooltip_text(Some(&format!("Leave empty to use {}", account.email)));
            if o.email.is_empty() {
                email.set_text(&account.email);
            }
        }
    }
    let domain = adw::EntryRow::builder()
        .title("Domain")
        .text(&o.domain)
        .input_purpose(gtk::InputPurpose::Url)
        .build();
    group.add(&kind);
    group.add(&capitalize);
    group.add(&number);
    group.add(&email);
    group.add(&domain);
    let show = {
        let (capitalize, number, email, domain) = (
            capitalize.clone(),
            number.clone(),
            email.clone(),
            domain.clone(),
        );
        move |which: UsernameKind| {
            capitalize.set_visible(which == UsernameKind::RandomWord);
            number.set_visible(which == UsernameKind::RandomWord);
            email.set_visible(which == UsernameKind::PlusAddressed);
            domain.set_visible(which == UsernameKind::CatchAll);
        }
    };
    show(o.kind);
    let s = state.clone();
    kind.connect_selected_notify(move |row| {
        let which = USERNAME_KINDS
            .get(row.selected() as usize)
            .map_or(UsernameKind::RandomWord, |(k, _)| *k);
        show(which);
        s.change(|o| o.username.kind = which);
    });
    let s = state.clone();
    capitalize
        .connect_active_notify(move |row| s.change(|o| o.username.capitalize = row.is_active()));
    let s = state.clone();
    number.connect_active_notify(move |row| {
        s.change(|o| o.username.include_number = row.is_active())
    });
    let s = state.clone();
    email.connect_changed(move |row| {
        let text = row.text().trim().to_string();
        let account =
            s.ui.upgrade()
                .and_then(|ui| ui.account.borrow().as_ref().map(|a| a.email.clone()));
        // The account's own address is saved as "use the account's".
        let text = if account.as_deref() == Some(text.as_str()) {
            String::new()
        } else {
            text
        };
        s.change(|o| o.username.email = text);
    });
    let s = state.clone();
    domain.connect_changed(move |row| s.change(|o| o.username.domain = row.text().trim().into()));
    group
}

/// The history page, made fresh each time it's opened.
fn history_page(ui: &Rc<Ui>) -> adw::NavigationPage {
    let view = adw::ToolbarView::new();
    view.add_top_bar(&adw::HeaderBar::new());
    let entries: Vec<(Kind, String, String)> = ui
        .session
        .borrow()
        .as_ref()
        .map(|s| {
            s.generated
                .iter()
                .rev()
                .map(|g| {
                    let when = g.when.format("%H:%M").map(|t| t.to_string());
                    (g.kind, g.value.clone(), when.unwrap_or_default())
                })
                .collect()
        })
        .unwrap_or_default();
    if entries.is_empty() {
        view.set_content(Some(
            &adw::StatusPage::builder()
                .icon_name("document-open-recent-symbolic")
                .title("No History")
                .description("Values you copy from the generator show here until Vord locks.")
                .build(),
        ));
    } else {
        let list = gtk::ListBox::builder()
            .selection_mode(gtk::SelectionMode::None)
            .css_classes(["boxed-list"])
            .valign(gtk::Align::Start)
            .build();
        for (kind, value, when) in entries {
            let row = adw::ActionRow::builder()
                .title(&value)
                .subtitle(format!("{} · {when}", kind_label(kind)))
                .use_markup(false)
                .title_selectable(true)
                .build();
            row.add_css_class("generated-history");
            let copy = gtk::Button::builder()
                .icon_name("edit-copy-symbolic")
                .tooltip_text("Copy")
                .valign(gtk::Align::Center)
                .css_classes(["flat"])
                .build();
            let weak = Rc::downgrade(ui);
            copy.connect_clicked(move |_| {
                if let Some(ui) = weak.upgrade() {
                    ui.copy(kind_label(kind), &value, kind != Kind::Username);
                }
            });
            row.add_suffix(&copy);
            list.append(&row);
        }
        let scroller = gtk::ScrolledWindow::builder()
            .hscrollbar_policy(gtk::PolicyType::Never)
            .propagate_natural_height(true)
            .child(
                &adw::Clamp::builder()
                    .child(&list)
                    .margin_top(12)
                    .margin_bottom(18)
                    .margin_start(12)
                    .margin_end(12)
                    .build(),
            )
            .build();
        view.set_content(Some(&scroller));
    }
    adw::NavigationPage::builder()
        .title("History")
        .tag("history")
        .child(&view)
        .build()
}

pub fn show(ui: &Rc<Ui>) {
    if !ui.is_unlocked() {
        return;
    }
    if let Some(dialog) = ui.generator.borrow().as_ref() {
        dialog.present(Some(&ui.window));
        return;
    }
    let label = gtk::Label::builder()
        .css_classes(["monospace", "generated-value"])
        .wrap(true)
        .wrap_mode(gtk::pango::WrapMode::WordChar)
        .selectable(true)
        .xalign(0.0)
        .hexpand(true)
        .build();
    let copy = gtk::Button::builder()
        .icon_name("edit-copy-symbolic")
        .tooltip_text("Copy")
        .valign(gtk::Align::Center)
        .css_classes(["flat", "circular"])
        .build();
    let regenerate = gtk::Button::builder()
        .icon_name("view-refresh-symbolic")
        .tooltip_text("Generate Again")
        .valign(gtk::Align::Center)
        .css_classes(["flat", "circular"])
        .build();
    let state = Rc::new(State {
        ui: Rc::downgrade(ui),
        options: RefCell::new(settings::get().generator),
        value: RefCell::default(),
        label: label.clone(),
        copy: copy.clone(),
    });
    let s = state.clone();
    copy.connect_clicked(move |_| s.copy());
    let s = state.clone();
    regenerate.connect_clicked(move |_| s.generate());

    let card = gtk::Box::builder()
        .spacing(6)
        .css_classes(["card", "generated-card"])
        .build();
    card.append(&label);
    card.append(&regenerate);
    card.append(&copy);

    let toggles = adw::ToggleGroup::builder().homogeneous(true).build();
    let stack = gtk::Stack::builder()
        .transition_type(gtk::StackTransitionType::Crossfade)
        .vhomogeneous(false)
        .interpolate_size(true)
        .build();
    for (kind, group) in [
        (Kind::Password, password_group(&state)),
        (Kind::Passphrase, passphrase_group(&state)),
        (Kind::Username, username_group(&state)),
    ] {
        toggles.add(
            adw::Toggle::builder()
                .name(kind_name(kind))
                .label(kind_label(kind))
                .build(),
        );
        stack.add_named(&group, Some(kind_name(kind)));
    }
    let current = state.options.borrow().kind;
    toggles.set_active_name(Some(kind_name(current)));
    stack.set_visible_child_name(kind_name(current));
    let s = state.clone();
    let st = stack.clone();
    toggles.connect_active_name_notify(move |toggles| {
        let kind = match toggles.active_name().as_deref() {
            Some("passphrase") => Kind::Passphrase,
            Some("username") => Kind::Username,
            _ => Kind::Password,
        };
        st.set_visible_child_name(kind_name(kind));
        s.change(|o| o.kind = kind);
    });

    let column = gtk::Box::builder()
        .orientation(gtk::Orientation::Vertical)
        .spacing(18)
        .margin_top(6)
        .margin_bottom(24)
        .margin_start(18)
        .margin_end(18)
        .build();
    column.append(&toggles);
    column.append(&card);
    column.append(&stack);
    let scroller = gtk::ScrolledWindow::builder()
        .hscrollbar_policy(gtk::PolicyType::Never)
        .propagate_natural_height(true)
        .child(&column)
        .build();

    let nav = adw::NavigationView::new();
    let header = adw::HeaderBar::new();
    let history = gtk::Button::builder()
        .icon_name("document-open-recent-symbolic")
        .tooltip_text("History")
        .build();
    let (weak, n) = (Rc::downgrade(ui), nav.clone());
    history.connect_clicked(move |_| {
        if let Some(ui) = weak.upgrade() {
            n.push(&history_page(&ui));
        }
    });
    header.pack_start(&history);
    let view = adw::ToolbarView::new();
    view.add_top_bar(&header);
    view.set_content(Some(&scroller));
    nav.add(
        &adw::NavigationPage::builder()
            .title("Generator")
            .tag("generator")
            .child(&view)
            .build(),
    );

    let dialog = adw::Dialog::builder()
        .title("Generator")
        .content_width(440)
        .child(&nav)
        .build();
    // The window's shortcuts don't reach into a dialog; locking must.
    let shortcuts = gtk::ShortcutController::new();
    shortcuts.add_shortcut(gtk::Shortcut::new(
        gtk::ShortcutTrigger::parse_string("<Control>l"),
        Some(gtk::NamedAction::new("win.lock")),
    ));
    dialog.add_controller(shortcuts);
    let weak = Rc::downgrade(ui);
    dialog.connect_closed(move |_| {
        if let Some(ui) = weak.upgrade() {
            ui.generator.replace(None);
        }
    });
    state.generate();
    ui.generator.replace(Some(dialog.clone()));
    dialog.present(Some(&ui.window));
    copy.grab_focus();
}
