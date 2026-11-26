//! Secrets Manager in the vault view: a secret's row, its details, and the
//! form that makes or changes one.
//!
//! A secret's value is fetched when it's shown (see [`crate::secrets`]);
//! until then the details say so. Like the item widgets, these hold
//! decrypted text and live in the list and the details scroller, so
//! locking (`VaultView::clear`) drops them.

use super::detail::{icon_button, plain, when, MASK};
use super::Ui;
use crate::secrets::{Draft, Opened, SecretRow, Secrets};
use crate::vault::Secret;
use adw::prelude::*;
use std::rc::Rc;

pub const ICON: &str = "preferences-system-privacy-symbolic";
pub const PROJECT_ICON: &str = "folder-documents-symbolic";

fn tile(size: i32) -> gtk::CenterBox {
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
            .icon_name(ICON)
            .pixel_size(size * 5 / 8)
            .build(),
    ));
    tile
}

/// A secret in the list: its name and project.
pub fn row(secrets: &Secrets, secret: &SecretRow) -> gtk::ListBoxRow {
    let line = gtk::Box::builder()
        .spacing(12)
        .css_classes(["item-row"])
        .build();
    line.append(&tile(32));
    let text = gtk::Box::builder()
        .orientation(gtk::Orientation::Vertical)
        .spacing(2)
        .hexpand(true)
        .valign(gtk::Align::Center)
        .build();
    text.append(
        &gtk::Label::builder()
            .label(&secret.name)
            .xalign(0.0)
            .ellipsize(gtk::pango::EllipsizeMode::End)
            .css_classes(["item-name"])
            .build(),
    );
    text.append(
        &gtk::Label::builder()
            .label(secrets.project_name(secret).unwrap_or("No project"))
            .xalign(0.0)
            .ellipsize(gtk::pango::EllipsizeMode::End)
            .css_classes(["item-subtitle", "dim-label"])
            .build(),
    );
    line.append(&text);
    if !secret.write {
        line.append(
            &gtk::Image::builder()
                .icon_name("changes-prevent-symbolic")
                .tooltip_text("Read only")
                .css_classes(["dim-label"])
                .build(),
        );
    }
    if secret.damaged {
        line.append(
            &gtk::Image::builder()
                .icon_name("dialog-warning-symbolic")
                .tooltip_text("Its name could not be decrypted")
                .css_classes(["damaged-banner"])
                .build(),
        );
    }
    gtk::ListBoxRow::builder().child(&line).build()
}

/// What the details show while the value is on its way, or why it isn't.
pub fn placeholder(secret: &SecretRow, failed: Option<&str>) -> gtk::Widget {
    let page = adw::StatusPage::builder()
        .title(&secret.name)
        .vexpand(true)
        .build();
    match failed {
        Some(why) => {
            page.set_icon_name(Some("dialog-warning-symbolic"));
            page.set_description(Some(&plain(why)));
        }
        None => {
            let spinner = adw::SpinnerPaintable::new(Some(&page));
            page.set_paintable(Some(&spinner));
            page.set_description(Some("Opening…"));
        }
    }
    page.upcast()
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

/// A card of text, hidden until shown when `hidden`.
fn text_card(text: &str, hidden: bool, monospace: bool) -> gtk::Box {
    let label = gtk::Label::builder()
        .label(if hidden { MASK } else { text })
        .xalign(0.0)
        .wrap(true)
        .wrap_mode(gtk::pango::WrapMode::WordChar)
        .selectable(!hidden)
        .hexpand(true)
        .css_classes(["notes-card"])
        .build();
    if monospace {
        label.add_css_class("secret-value");
    }
    let card = gtk::Box::builder().css_classes(["card"]).build();
    card.append(&label);
    if hidden {
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
    card
}

/// One secret, opened, laid out for reading and copying.
pub fn detail(ui: &Rc<Ui>, secrets: &Secrets, opened: &Opened) -> gtk::Widget {
    let outer = gtk::Box::new(gtk::Orientation::Vertical, 0);
    let header = gtk::Box::builder()
        .spacing(18)
        .css_classes(["detail-header"])
        .build();
    header.append(&tile(64));
    let titles = gtk::Box::builder()
        .orientation(gtk::Orientation::Vertical)
        .spacing(4)
        .valign(gtk::Align::Center)
        .hexpand(true)
        .build();
    titles.append(
        &gtk::Label::builder()
            .label(opened.name.as_str())
            .xalign(0.0)
            .wrap(true)
            .selectable(true)
            .css_classes(["detail-title"])
            .build(),
    );
    let mut meta = vec!["Secret".to_string()];
    if let Some(org) = secrets.org(&opened.org_id) {
        meta.push(org.name.clone());
    }
    if !opened.write {
        meta.push("Read only".into());
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

    let value = group(&column, "Value");
    let copy = icon_button("edit-copy-symbolic", "Copy Value (Ctrl+P)");
    copy.set_action_name(Some("win.copy-password"));
    value.set_header_suffix(Some(&copy));
    value.add(&text_card(&opened.value, true, true));

    let place = group(&column, "Project");
    let project = opened
        .project
        .as_deref()
        .and_then(|id| secrets.project(id))
        .map_or("No project", |p| p.name.as_str());
    info(&place, "Project", project);

    if !opened.note.trim().is_empty() {
        let note = group(&column, "Note");
        note.add(&text_card(&opened.note, false, false));
    }

    let mut dates = Vec::new();
    if let Some(revised) = opened.revised.as_deref().and_then(when) {
        dates.push(format!("Updated {revised}"));
    }
    if let Some(created) = opened.created.as_deref().and_then(when) {
        dates.push(format!("Created {created}"));
    }
    if !dates.is_empty() {
        column.append(
            &gtk::Label::builder()
                .label(dates.join("  ·  "))
                .xalign(0.0)
                .css_classes(["dim-label", "caption"])
                .margin_start(12)
                .build(),
        );
    }
    column.append(
        &gtk::Label::builder()
            .label(format!("Id {}", opened.id))
            .xalign(0.0)
            .selectable(true)
            .css_classes(["dim-label", "caption"])
            .margin_start(12)
            .build(),
    );
    let _ = ui;
    outer.upcast()
}

fn text_view(text: &str, height: i32, monospace: bool) -> (gtk::TextView, gtk::Frame) {
    let view = gtk::TextView::builder()
        .wrap_mode(gtk::WrapMode::WordChar)
        .accepts_tab(false)
        .top_margin(12)
        .bottom_margin(12)
        .left_margin(12)
        .right_margin(12)
        .height_request(height)
        .monospace(monospace)
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

/// The form for a new secret or a saved one.
pub struct SecretEditor {
    pub root: gtk::Widget,
    /// The secret being changed; `None` for a new one.
    pub id: Option<String>,
    pub org_id: String,
    pub title: String,
    /// The value it had, to tell the server whether it changed.
    original_value: Option<Secret>,
    name: adw::EntryRow,
    value: gtk::TextView,
    note: gtk::TextView,
    project: adw::ComboRow,
    /// Parallel to `project`'s choices.
    projects: Vec<Option<String>>,
}

impl SecretEditor {
    /// A form over `draft`, for a secret in `org_id`; `id` is the saved
    /// secret's.
    pub fn new(secrets: &Secrets, org_id: &str, draft: &Draft, id: Option<String>) -> Rc<Self> {
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
        let title = if id.is_some() {
            "Edit Secret"
        } else {
            "New Secret"
        };

        let what = group(&column, "Secret");
        let name = adw::EntryRow::builder().title("Name").build();
        name.set_use_markup(false);
        name.set_text(&draft.name);
        what.add(&name);
        if let Some(org) = secrets.org(org_id).filter(|_| secrets.orgs.len() > 1) {
            what.set_description(Some(&format!("In {}", plain(&org.name))));
        }

        let value_group = group(&column, "Value");
        let (value, frame) = text_view(&draft.value, 96, true);
        value_group.add(&frame);

        // A project this account may write to, or none; the secret's own
        // project stays a choice even when it may not.
        let mut projects = vec![None];
        let mut labels = vec!["No project".to_string()];
        for project in secrets.projects.iter().filter(|p| p.org_id == org_id) {
            if project.write || draft.project.as_deref() == Some(project.id.as_str()) {
                projects.push(Some(project.id.clone()));
                labels.push(project.name.clone());
            }
        }
        let project = adw::ComboRow::builder()
            .title("Project")
            .model(&gtk::StringList::new(
                &labels.iter().map(String::as_str).collect::<Vec<_>>(),
            ))
            .build();
        let at = projects
            .iter()
            .position(|p| *p == draft.project)
            .unwrap_or(0);
        project.set_selected(at as u32);
        let place = group(&column, "Project");
        place.add(&project);
        place.set_description(Some(
            "Machine accounts and people with access to the project can read the secret.",
        ));

        let note_group = group(&column, "Note");
        let (note, frame) = text_view(&draft.note, 96, false);
        note_group.add(&frame);

        Rc::new(Self {
            root: clamp.upcast(),
            original_value: id.as_ref().map(|_| draft.value.clone()),
            id,
            org_id: org_id.to_string(),
            title: title.to_string(),
            name,
            value,
            note,
            project,
            projects,
        })
    }

    pub fn focus(&self) {
        self.name.grab_focus();
    }

    /// The form, read back.
    pub fn draft(&self) -> Draft {
        Draft {
            name: Secret::new(self.name.text().to_string()),
            value: buffer_text(&self.value),
            note: buffer_text(&self.note),
            project: self
                .projects
                .get(self.project.selected() as usize)
                .cloned()
                .flatten(),
        }
    }

    /// Whether a saved secret's value differs from the one it had.
    pub fn value_changed(&self, draft: &Draft) -> bool {
        self.original_value
            .as_ref()
            .is_some_and(|v| *v != draft.value)
    }
}
