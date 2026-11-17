//! Sends in the vault view: a row in the list, the details, and the form
//! that makes or changes one.
//!
//! Like the item details and editor, these widgets hold decrypted text and
//! live in the list and the details scroller, so locking
//! (`VaultView::clear`) drops them.

use super::detail::{capitalise, icon_button, plain, when, MASK};
use super::Ui;
use crate::send::{Draft, Send, SendKind};
use crate::vault::Secret;
use adw::prelude::*;
use gtk::{gio, glib};
use std::cell::RefCell;
use std::path::PathBuf;
use std::rc::Rc;

/// Whether an ISO 8601 time has passed.
fn past(iso: &str) -> bool {
    let (Ok(time), Ok(now)) = (
        glib::DateTime::from_iso8601(iso, Some(&glib::TimeZone::utc())),
        glib::DateTime::now_utc(),
    ) else {
        return false;
    };
    time <= now
}

/// The time `seconds` from now, as Bitwarden writes it.
fn iso_after(seconds: i64) -> Option<String> {
    let time = glib::DateTime::now_utc()
        .ok()?
        .add_seconds(seconds as f64)
        .ok()?;
    Some(time.format("%Y-%m-%dT%H:%M:%S.%fZ").ok()?.to_string())
}

/// Why no one can open it right now, if no one can.
fn closed(send: &Send) -> Option<&'static str> {
    if send.disabled {
        Some("Deactivated")
    } else if send.expires.as_deref().is_some_and(past) {
        Some("Expired")
    } else if send.used_up() {
        Some("Out of views")
    } else {
        None
    }
}

fn tile(kind: SendKind, size: i32) -> gtk::CenterBox {
    let tile = gtk::CenterBox::builder()
        .width_request(size)
        .height_request(size)
        .hexpand(false)
        .halign(gtk::Align::Start)
        .valign(gtk::Align::Center)
        .css_classes([
            if size > 40 {
                "detail-icon"
            } else {
                "item-icon"
            },
            "glyph",
        ])
        .build();
    tile.set_center_widget(Some(
        &gtk::Image::builder()
            .icon_name(kind.icon())
            .pixel_size(size * 5 / 8)
            .build(),
    ));
    tile
}

/// A Send in the list: its name, and when it goes or why it's closed.
pub fn row(send: &Send) -> gtk::ListBoxRow {
    let line = gtk::Box::builder()
        .spacing(12)
        .css_classes(["item-row"])
        .build();
    line.append(&tile(send.kind, 32));
    let text = gtk::Box::builder()
        .orientation(gtk::Orientation::Vertical)
        .spacing(2)
        .hexpand(true)
        .valign(gtk::Align::Center)
        .build();
    text.append(
        &gtk::Label::builder()
            .label(&send.name)
            .xalign(0.0)
            .ellipsize(gtk::pango::EllipsizeMode::End)
            .css_classes(["item-name"])
            .build(),
    );
    let subtitle = match (closed(send), send.deletes.as_deref().and_then(when)) {
        (Some(why), _) => Some(why.to_string()),
        (None, Some(date)) => Some(format!("Deletes {date}")),
        (None, None) => None,
    };
    if let Some(subtitle) = subtitle {
        text.append(
            &gtk::Label::builder()
                .label(&subtitle)
                .xalign(0.0)
                .ellipsize(gtk::pango::EllipsizeMode::End)
                .css_classes(["item-subtitle", "dim-label"])
                .build(),
        );
    }
    line.append(&text);
    if send.has_password {
        line.append(
            &gtk::Image::builder()
                .icon_name("changes-prevent-symbolic")
                .tooltip_text("Needs a password")
                .css_classes(["dim-label"])
                .build(),
        );
    }
    if send.damaged {
        line.append(
            &gtk::Image::builder()
                .icon_name("dialog-warning-symbolic")
                .tooltip_text("Part of this Send could not be decrypted")
                .css_classes(["damaged-banner"])
                .build(),
        );
    }
    gtk::ListBoxRow::builder().child(&line).build()
}

fn group(column: &gtk::Box, title: &str) -> adw::PreferencesGroup {
    let group = adw::PreferencesGroup::builder().title(title).build();
    column.append(&group);
    group
}

fn info(group: &adw::PreferencesGroup, title: &str, value: &str) {
    group.add(
        &adw::ActionRow::builder()
            .title(title)
            .subtitle(plain(value))
            .css_classes(["property"])
            .build(),
    );
}

fn copy_button(ui: &Rc<Ui>, what: &str, value: &str, secret: bool) -> gtk::Button {
    let button = icon_button("edit-copy-symbolic", &format!("Copy {what}"));
    let ui = Rc::downgrade(ui);
    let (what, value) = (capitalise(what), value.to_string());
    button.connect_clicked(move |_| {
        if let Some(ui) = ui.upgrade() {
            ui.copy(&what, &value, secret);
        }
    });
    button
}

/// One Send, laid out for reading and copying.
pub fn detail(ui: &Rc<Ui>, send: &Send) -> gtk::Widget {
    let outer = gtk::Box::new(gtk::Orientation::Vertical, 0);
    let header = gtk::Box::builder()
        .spacing(18)
        .css_classes(["detail-header"])
        .build();
    header.append(&tile(send.kind, 64));
    let titles = gtk::Box::builder()
        .orientation(gtk::Orientation::Vertical)
        .spacing(4)
        .valign(gtk::Align::Center)
        .hexpand(true)
        .build();
    titles.append(
        &gtk::Label::builder()
            .label(&send.name)
            .xalign(0.0)
            .wrap(true)
            .css_classes(["detail-title"])
            .build(),
    );
    let mut meta = vec![send.kind.label().to_string()];
    if let Some(why) = closed(send) {
        meta.push(why.to_string());
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
    outer.append(
        &adw::Clamp::builder()
            .maximum_size(720)
            .child(&column)
            .build(),
    );

    if send.damaged {
        column.append(
            &gtk::Label::builder()
                .label("Part of this Send could not be decrypted, so some of it may be missing.")
                .wrap(true)
                .xalign(0.0)
                .css_classes(["damaged-banner"])
                .build(),
        );
    }

    // -- The link, which carries the key.
    let server = ui.server().unwrap_or_default();
    if let Some(link) = send.link(&server) {
        let share = group(&column, "Share");
        let row = adw::ActionRow::builder()
            .title("Link")
            .subtitle(plain(&link))
            .subtitle_lines(1)
            .css_classes(["property"])
            .build();
        row.add_suffix(&copy_button(ui, "link", &link, true));
        share.add(&row);
        share.set_description(Some(
            "Anyone with the link can open it, so share it only with the people it's for.",
        ));
    }

    // -- What it shares.
    match send.kind {
        SendKind::Text => {
            if let Some(text) = &send.text {
                let shared = group(&column, "Text");
                shared.set_header_suffix(Some(&copy_button(ui, "text", text, true)));
                if send.hidden {
                    shared.set_description(Some("Recipients see it hidden until they show it."));
                }
                let label = gtk::Label::builder()
                    .label(if send.hidden { MASK } else { text.as_str() })
                    .xalign(0.0)
                    .wrap(true)
                    .wrap_mode(gtk::pango::WrapMode::WordChar)
                    .selectable(!send.hidden)
                    .hexpand(true)
                    .css_classes(["notes-card"])
                    .build();
                let card = gtk::Box::builder().css_classes(["card"]).build();
                card.append(&label);
                if send.hidden {
                    let reveal = gtk::ToggleButton::builder()
                        .icon_name("view-reveal-symbolic")
                        .tooltip_text("Show")
                        .valign(gtk::Align::Start)
                        .margin_top(6)
                        .margin_end(6)
                        .css_classes(["flat"])
                        .build();
                    let (label, text) = (label.downgrade(), text.to_string());
                    reveal.connect_toggled(move |button| {
                        let Some(label) = label.upgrade() else { return };
                        let shown = button.is_active();
                        label.set_label(if shown { &text } else { MASK });
                        label.set_selectable(shown);
                        button.set_icon_name(if shown {
                            "view-conceal-symbolic"
                        } else {
                            "view-reveal-symbolic"
                        });
                        button.set_tooltip_text(Some(if shown { "Hide" } else { "Show" }));
                    });
                    card.append(&reveal);
                }
                shared.add(&card);
            }
        }
        SendKind::File => {
            let shared = group(&column, "File");
            let row = adw::ActionRow::builder()
                .title(plain(send.file_name.as_deref().unwrap_or("File")))
                .subtitle(send.file_size.as_deref().map(plain).unwrap_or_default())
                .build();
            row.add_prefix(&gtk::Image::from_icon_name("mail-attachment-symbolic"));
            shared.add(&row);
        }
    }

    // -- Who can open it, and until when.
    let access = group(&column, "Access");
    if let Some(deletes) = send.deletes.as_deref().and_then(when) {
        info(&access, "Deletion date", &deletes);
    }
    let expires = match send.expires.as_deref() {
        Some(iso) => when(iso).map(|w| {
            if past(iso) {
                format!("{w} (expired)")
            } else {
                w
            }
        }),
        None => Some("Never".into()),
    };
    if let Some(expires) = expires {
        info(&access, "Expires", &expires);
    }
    let views = match send.max_access_count {
        Some(max) => format!("{} of {max}", send.access_count),
        None => format!("{} (no limit)", send.access_count),
    };
    info(&access, "Views", &views);
    info(
        &access,
        "Password",
        if send.has_password {
            "Needed to open it"
        } else {
            "None"
        },
    );
    if send.hide_email {
        info(&access, "Your email", "Hidden from recipients");
    }
    if send.disabled {
        info(&access, "Deactivated", "No one can open it");
    }

    if let Some(notes) = send.notes.as_deref().filter(|n| !n.is_empty()) {
        let private = group(&column, "Notes");
        private.set_description(Some("Only you see these."));
        let label = gtk::Label::builder()
            .label(notes.as_str())
            .xalign(0.0)
            .wrap(true)
            .wrap_mode(gtk::pango::WrapMode::WordChar)
            .selectable(true)
            .css_classes(["notes-card"])
            .build();
        let card = gtk::Box::builder().css_classes(["card"]).build();
        card.append(&label);
        private.add(&card);
    }

    if let Some(revised) = send.revised.as_deref().and_then(when) {
        column.append(
            &gtk::Label::builder()
                .label(format!("Updated {revised}"))
                .xalign(0.0)
                .css_classes(["dim-label", "caption"])
                .margin_start(12)
                .build(),
        );
    }
    outer.upcast()
}

/// A choice of time: keep the one it has, none, or some time from now.
#[derive(Clone)]
enum When {
    Keep(String),
    Never,
    In(i64),
}

struct DateChoice {
    row: adw::ComboRow,
    choices: Vec<When>,
}

impl DateChoice {
    /// `current` is kept by default; without it, `default` is chosen.
    fn new(title: &str, current: Option<&str>, never: bool, default: When) -> Self {
        let mut choices = Vec::new();
        let mut labels = Vec::new();
        if let Some(current) = current {
            let shown = when(current).unwrap_or_else(|| current.to_string());
            labels.push(if past(current) {
                format!("{shown} (passed)")
            } else {
                shown
            });
            choices.push(When::Keep(current.to_string()));
        }
        if never {
            labels.push("Never".into());
            choices.push(When::Never);
        }
        const DAY: i64 = 24 * 60 * 60;
        for (label, seconds) in [
            ("In 1 hour", 60 * 60),
            ("In 1 day", DAY),
            ("In 2 days", 2 * DAY),
            ("In 3 days", 3 * DAY),
            ("In 7 days", 7 * DAY),
            ("In 14 days", 14 * DAY),
            ("In 30 days", 30 * DAY),
        ] {
            labels.push(label.into());
            choices.push(When::In(seconds));
        }
        let row = adw::ComboRow::builder()
            .title(title)
            .model(&gtk::StringList::new(
                &labels.iter().map(String::as_str).collect::<Vec<_>>(),
            ))
            .build();
        let at = if current.is_some() {
            0
        } else {
            choices
                .iter()
                .position(|c| match (c, &default) {
                    (When::Never, When::Never) => true,
                    (When::In(a), When::In(b)) => a == b,
                    _ => false,
                })
                .unwrap_or(0)
        };
        row.set_selected(at as u32);
        Self { row, choices }
    }

    fn value(&self) -> Option<String> {
        match self.choices.get(self.row.selected() as usize)? {
            When::Keep(iso) => Some(iso.clone()),
            When::Never => None,
            When::In(seconds) => iso_after(*seconds),
        }
    }
}

fn text_view(text: &str, height: i32) -> (gtk::TextView, gtk::Frame) {
    let view = gtk::TextView::builder()
        .wrap_mode(gtk::WrapMode::WordChar)
        .accepts_tab(false)
        .top_margin(12)
        .bottom_margin(12)
        .left_margin(12)
        .right_margin(12)
        .height_request(height)
        .css_classes(["notes-editor"])
        .build();
    view.buffer().set_text(text);
    let frame = gtk::Frame::builder()
        .child(&view)
        .css_classes(["card"])
        .build();
    (view, frame)
}

fn buffer_text(view: &gtk::TextView) -> Secret {
    let buffer = view.buffer();
    Secret::new(
        buffer
            .text(&buffer.start_iter(), &buffer.end_iter(), false)
            .to_string(),
    )
}

/// The form for a new Send or a saved one.
pub struct SendEditor {
    pub root: gtk::Widget,
    /// The Send being changed; `None` for a new one.
    pub id: Option<String>,
    pub title: String,
    pub original: Option<Draft>,
    kind: SendKind,
    name: adw::EntryRow,
    text: Option<(gtk::TextView, adw::SwitchRow)>,
    /// A saved Send's file, which can't change.
    kept_file: Option<String>,
    /// A new Send's file, once chosen.
    file: Rc<RefCell<Option<PathBuf>>>,
    deletes: DateChoice,
    expires: DateChoice,
    max_views: adw::SpinRow,
    password: adw::PasswordEntryRow,
    hide_email: adw::SwitchRow,
    disabled: adw::SwitchRow,
    notes: gtk::TextView,
}

impl SendEditor {
    /// A form over `draft`; `send` is the saved Send it came from.
    pub fn new(draft: &Draft, send: Option<&Send>) -> Rc<Self> {
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
        let title = match (send, draft.kind) {
            (Some(_), _) => "Edit Send".to_string(),
            (None, kind) => format!("New {}", kind.label()),
        };

        let what = group(&column, "Send");
        let name = adw::EntryRow::builder().title("Name").build();
        name.set_use_markup(false);
        name.set_text(&draft.name);
        what.add(&name);

        let file: Rc<RefCell<Option<PathBuf>>> = Rc::new(RefCell::new(None));
        let mut text = None;
        let mut kept_file = None;
        match (draft.kind, send) {
            (SendKind::Text, _) => {
                let shared = group(&column, "Text");
                let (view, frame) = text_view(&draft.text, 140);
                shared.add(&frame);
                let hidden = adw::SwitchRow::builder()
                    .title("Hide the text by default")
                    .subtitle("Recipients press Show to see it")
                    .active(draft.hidden)
                    .build();
                let options = adw::PreferencesGroup::new();
                options.add(&hidden);
                column.append(&options);
                text = Some((view, hidden));
            }
            (SendKind::File, Some(send)) => {
                let row = adw::ActionRow::builder()
                    .title("File")
                    .subtitle(plain(send.file_name.as_deref().unwrap_or("File")))
                    .css_classes(["property"])
                    .build();
                what.add(&row);
                what.set_description(Some("A Send's file can't be changed."));
                kept_file = send.file_name.clone();
            }
            (SendKind::File, None) => {
                let row = adw::ActionRow::builder()
                    .title("File")
                    .subtitle("None chosen")
                    .css_classes(["property"])
                    .build();
                let choose = gtk::Button::builder()
                    .label("_Choose…")
                    .use_underline(true)
                    .valign(gtk::Align::Center)
                    .build();
                row.add_suffix(&choose);
                row.set_activatable_widget(Some(&choose));
                what.add(&row);
                what.set_description(Some("Up to 500 MB. It's encrypted before it leaves."));
                let (file, row, name) = (file.clone(), row.downgrade(), name.downgrade());
                choose.connect_clicked(move |button| {
                    let window = button.root().and_downcast::<gtk::Window>();
                    let dialog = gtk::FileDialog::builder()
                        .title("Choose a File to Send")
                        .modal(true)
                        .build();
                    let (file, row, name) = (file.clone(), row.clone(), name.clone());
                    dialog.open(window.as_ref(), None::<&gio::Cancellable>, move |chosen| {
                        let Some(path) = chosen.ok().and_then(|f| f.path()) else {
                            return;
                        };
                        let (Some(row), Some(name)) = (row.upgrade(), name.upgrade()) else {
                            return;
                        };
                        let file_name = path
                            .file_name()
                            .map(|n| n.to_string_lossy().to_string())
                            .unwrap_or_default();
                        row.set_subtitle(&plain(&file_name));
                        if name.text().trim().is_empty() {
                            name.set_text(&file_name);
                        }
                        file.replace(Some(path));
                    });
                });
            }
        }

        // -- Who can open it, and until when.
        let access = group(&column, "Access");
        let deletes = DateChoice::new(
            "Deletion date",
            draft.deletes.as_deref(),
            false,
            When::In(7 * 24 * 60 * 60),
        );
        deletes
            .row
            .set_subtitle("Gone for good then, from the server too");
        access.add(&deletes.row);
        let expires = DateChoice::new("Expires", draft.expires.as_deref(), true, When::Never);
        expires.row.set_subtitle("No one can open it after this");
        access.add(&expires.row);
        let max_views = adw::SpinRow::with_range(0.0, 1_000_000.0, 1.0);
        max_views.set_title("Maximum views");
        max_views.set_subtitle(&match send {
            Some(send) => format!(
                "0 for no limit · viewed {} time{}",
                send.access_count,
                if send.access_count == 1 { "" } else { "s" }
            ),
            None => "0 for no limit".into(),
        });
        max_views.set_value(draft.max_access_count.unwrap_or(0) as f64);
        access.add(&max_views);
        let hide_email = adw::SwitchRow::builder()
            .title("Hide my email address")
            .subtitle("From the people who open it")
            .active(draft.hide_email)
            .build();
        access.add(&hide_email);
        let disabled = adw::SwitchRow::builder()
            .title("Deactivate")
            .subtitle("No one can open it until it's turned back on")
            .active(draft.disabled)
            .build();
        access.add(&disabled);

        let lock = group(&column, "Password");
        let password = adw::PasswordEntryRow::builder()
            .title(if send.is_some_and(|s| s.has_password) {
                "New password"
            } else {
                "Password"
            })
            .build();
        lock.add(&password);
        lock.set_description(Some(if send.is_some_and(|s| s.has_password) {
            "It has a password. Type a new one to replace it, or leave this empty to keep it."
        } else {
            "Optional. Recipients need it to open the Send; share it some other way than the link."
        }));

        let private = group(&column, "Notes");
        private.set_description(Some("Only you see these."));
        let (notes, frame) = text_view(&draft.notes, 96);
        private.add(&frame);

        Rc::new(Self {
            root: clamp.upcast(),
            id: send.map(|s| s.id.clone()),
            title,
            original: send.map(|_| draft.clone()),
            kind: draft.kind,
            name,
            text,
            kept_file,
            file,
            deletes,
            expires,
            max_views,
            password,
            hide_email,
            disabled,
            notes,
        })
    }

    pub fn focus(&self) {
        self.name.grab_focus();
    }

    /// A new file Send's file.
    pub fn file(&self) -> Option<PathBuf> {
        self.file.borrow().clone()
    }

    /// The form, read back.
    pub fn draft(&self) -> Draft {
        let chosen = self.file.borrow().as_ref().map(|path| {
            path.file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_else(|| "file".into())
        });
        let max = self.max_views.value() as u64;
        Draft {
            kind: self.kind,
            name: Secret::new(self.name.text().to_string()),
            notes: buffer_text(&self.notes),
            text: self
                .text
                .as_ref()
                .map(|(view, _)| buffer_text(view))
                .unwrap_or_default(),
            hidden: self.text.as_ref().is_some_and(|(_, h)| h.is_active()),
            file_name: self.kept_file.clone().or(chosen),
            deletes: self.deletes.value(),
            expires: self.expires.value(),
            max_access_count: (max > 0).then_some(max),
            password: Secret::new(self.password.text().to_string()),
            hide_email: self.hide_email.is_active(),
            disabled: self.disabled.is_active(),
        }
    }
}
