//! The item editor: a form over a [`Draft`], shown in the details pane in
//! place of the item.
//!
//! The form holds decrypted text in its widgets, as the details do; it
//! lives in the same scroller, so locking (`VaultView::clear`) drops it.

use crate::edit::{self, Draft};
use crate::vault::{FieldKind, Kind, Secret, Vault};
use adw::prelude::*;
use gtk::glib;
use std::cell::RefCell;
use std::rc::Rc;

/// One of the type's own fields: typed in, or shown and kept as it is.
enum ValueRow {
    Entry(adw::EntryRow),
    Fixed(Secret),
}

struct UriRow {
    row: adw::EntryRow,
    origin: Option<usize>,
}

struct FieldRow {
    kind: FieldKind,
    origin: Option<usize>,
    /// Its own boxed list: the name, then the value.
    list: gtk::ListBox,
    name: adw::EntryRow,
    value: Option<adw::EntryRow>,
    toggle: Option<adw::SwitchRow>,
}

pub struct Editor {
    pub root: gtk::Widget,
    /// The item being changed; `None` for a new one.
    pub id: Option<String>,
    pub title: String,
    /// The item as it opened, to tell what changed.
    pub original: Option<Draft>,
    kind: Kind,
    /// An existing item's owner, which the editor doesn't change.
    fixed_owner: Option<Option<String>>,
    fixed_collections: Vec<String>,
    name: adw::EntryRow,
    folder: adw::ComboRow,
    folder_ids: Vec<Option<String>>,
    owner: Option<adw::ComboRow>,
    owner_ids: Vec<Option<String>>,
    collections: Vec<(String, String, adw::SwitchRow)>,
    favorite: adw::SwitchRow,
    reprompt: adw::SwitchRow,
    values: Vec<ValueRow>,
    uris: Rc<RefCell<Vec<UriRow>>>,
    fields: Rc<RefCell<Vec<FieldRow>>>,
    notes: gtk::TextView,
}

fn text(row: &impl IsA<gtk::Editable>) -> Secret {
    Secret::new(row.text().to_string())
}

fn entry(title: &str, value: &str, secret: bool) -> adw::EntryRow {
    let row: adw::EntryRow = if secret {
        adw::PasswordEntryRow::builder()
            .title(title)
            .build()
            .upcast()
    } else {
        adw::EntryRow::builder().title(title).build()
    };
    row.set_use_markup(false);
    row.set_text(value);
    row
}

fn remove_button(tooltip: &str) -> gtk::Button {
    gtk::Button::builder()
        .icon_name("list-remove-symbolic")
        .tooltip_text(tooltip)
        .valign(gtk::Align::Center)
        .css_classes(["flat"])
        .build()
}

fn group(column: &gtk::Box, title: &str) -> adw::PreferencesGroup {
    let group = adw::PreferencesGroup::builder().title(title).build();
    column.append(&group);
    group
}

/// A new password (or passphrase) from the generator's saved options.
fn generated() -> String {
    let options = crate::settings::get().generator;
    match options.kind {
        crate::generator::Kind::Passphrase => crate::generator::passphrase(&options.passphrase),
        _ => crate::generator::password(&options.password),
    }
}

impl Editor {
    pub fn new(
        vault: &Vault,
        draft: &Draft,
        id: Option<String>,
        original: Option<Draft>,
    ) -> Rc<Self> {
        let kind = draft.kind;
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
        let title = match &id {
            Some(_) => "Edit Item".to_string(),
            None => format!("New {}", kind.label()),
        };

        // -- The item itself.
        let details = group(&column, "Item");
        let name = entry("Name", &draft.name, false);
        details.add(&name);

        let mut folder_ids = vec![None];
        let mut folder_names = vec!["No Folder".to_string()];
        for folder in &vault.folders {
            folder_ids.push(Some(folder.id.clone()));
            folder_names.push(folder.name.clone());
        }
        let folder = adw::ComboRow::builder()
            .title("Folder")
            .model(&gtk::StringList::new(
                &folder_names.iter().map(String::as_str).collect::<Vec<_>>(),
            ))
            .build();
        folder.set_use_markup(false);
        let at = folder_ids
            .iter()
            .position(|f| *f == draft.folder_id)
            .unwrap_or(0);
        folder.set_selected(at as u32);
        details.add(&folder);

        // A new item can go to an organization the account can write to.
        let mut owner = None;
        let mut owner_ids = vec![None];
        let mut collections = Vec::new();
        let (fixed_owner, fixed_collections) = if id.is_some() {
            (Some(draft.org_id.clone()), draft.collection_ids.clone())
        } else {
            let writable: Vec<_> = vault
                .organizations
                .iter()
                .filter(|o| {
                    vault
                        .collections
                        .iter()
                        .any(|c| c.org_id == o.id && !c.read_only)
                })
                .collect();
            if !writable.is_empty() {
                let mut names = vec!["Me (personal vault)".to_string()];
                for org in &writable {
                    owner_ids.push(Some(org.id.clone()));
                    names.push(org.name.clone());
                }
                let row = adw::ComboRow::builder()
                    .title("Owner")
                    .model(&gtk::StringList::new(
                        &names.iter().map(String::as_str).collect::<Vec<_>>(),
                    ))
                    .build();
                row.set_use_markup(false);
                let at = owner_ids
                    .iter()
                    .position(|o| *o == draft.org_id)
                    .unwrap_or(0);
                row.set_selected(at as u32);
                details.add(&row);
                let chosen = group(&column, "Collections");
                for collection in vault.collections.iter().filter(|c| !c.read_only) {
                    let switch = adw::SwitchRow::builder()
                        .title(&collection.name)
                        .active(draft.collection_ids.contains(&collection.id))
                        .build();
                    switch.set_use_markup(false);
                    chosen.add(&switch);
                    collections.push((collection.id.clone(), collection.org_id.clone(), switch));
                }
                // Only the chosen organization's collections show.
                let show = {
                    let owner_ids = owner_ids.clone();
                    let rows: Vec<_> = collections
                        .iter()
                        .map(|(_, org, row)| (org.clone(), row.clone()))
                        .collect();
                    let chosen = chosen.clone();
                    move |row: &adw::ComboRow| {
                        let org = owner_ids.get(row.selected() as usize).cloned().flatten();
                        chosen.set_visible(org.is_some());
                        for (owner, switch) in &rows {
                            switch.set_visible(Some(owner) == org.as_ref());
                        }
                    }
                };
                show(&row);
                row.connect_selected_notify(show);
                owner = Some(row);
            }
            (None, Vec::new())
        };

        let favorite = adw::SwitchRow::builder()
            .title("Favorite")
            .active(draft.favorite)
            .build();
        details.add(&favorite);
        let reprompt = adw::SwitchRow::builder()
            .title("Ask for master password")
            .subtitle("Before showing or copying this item's secrets")
            .active(draft.reprompt)
            .build();
        details.add(&reprompt);

        // -- The type's own fields.
        let mut values = Vec::new();
        let specs = edit::specs(kind);
        let section = |title: &str| -> adw::PreferencesGroup { group(&column, title) };
        let mut current = match kind {
            Kind::Login => Some(section("Login")),
            Kind::Card => Some(section("Card")),
            Kind::Identity => Some(section("Name")),
            Kind::SshKey => Some(section("SSH key")),
            Kind::Note => None,
        };
        for (i, spec) in specs.iter().enumerate() {
            if kind == Kind::Identity {
                match spec.key {
                    "username" => current = Some(section("Identification")),
                    "email" => current = Some(section("Contact")),
                    "address1" => current = Some(section("Address")),
                    _ => {}
                }
            }
            if kind == Kind::SshKey {
                // The parts of a key belong together; Vord makes them, the
                // user doesn't type them.
                let value = &draft.values[i];
                let shown = if spec.secret && !value.is_empty() {
                    "••••••••••••".to_string()
                } else {
                    glib::markup_escape_text(value).to_string()
                };
                let row = adw::ActionRow::builder()
                    .title(spec.label)
                    .subtitle(shown)
                    .subtitle_lines(1)
                    .css_classes(["property"])
                    .build();
                if let Some(group) = &current {
                    group.add(&row);
                }
                values.push(ValueRow::Fixed(value.clone()));
                continue;
            }
            let row = entry(spec.label, &draft.values[i], spec.secret);
            if spec.key == "password" {
                let generate = gtk::Button::builder()
                    .icon_name("view-refresh-symbolic")
                    .tooltip_text("Generate Password")
                    .valign(gtk::Align::Center)
                    .css_classes(["flat"])
                    .build();
                let target = row.downgrade();
                generate.connect_clicked(move |_| {
                    if let Some(row) = target.upgrade() {
                        row.set_text(&generated());
                    }
                });
                row.add_suffix(&generate);
            }
            if let Some(group) = &current {
                group.add(&row);
            }
            values.push(ValueRow::Entry(row));
        }
        if let (Kind::SshKey, Some(group)) = (kind, &current) {
            group.set_description(Some(if id.is_some() {
                "The parts of a key can't be changed one by one."
            } else {
                "A new Ed25519 key, made for this item."
            }));
        }

        // -- Websites.
        let uris: Rc<RefCell<Vec<UriRow>>> = Rc::new(RefCell::new(Vec::new()));
        if kind == Kind::Login {
            let sites = group(&column, "Websites");
            let add = adw::ButtonRow::builder()
                .title("Add Website")
                .start_icon_name("list-add-symbolic")
                .build();
            let add_row = {
                let sites = sites.clone();
                let add = add.clone();
                let uris = uris.clone();
                move |value: &str, origin: Option<usize>| -> adw::EntryRow {
                    let row = entry("Website", value, false);
                    let remove = remove_button("Remove Website");
                    {
                        let (sites, uris, target) = (sites.clone(), uris.clone(), row.clone());
                        remove.connect_clicked(move |_| {
                            sites.remove(&target);
                            uris.borrow_mut().retain(|u| u.row != target);
                        });
                    }
                    row.add_suffix(&remove);
                    sites.remove(&add);
                    sites.add(&row);
                    sites.add(&add);
                    uris.borrow_mut().push(UriRow {
                        row: row.clone(),
                        origin,
                    });
                    row
                }
            };
            sites.add(&add);
            for uri in &draft.uris {
                add_row(&uri.uri, uri.origin);
            }
            let add_row = Rc::new(add_row);
            add.connect_activated(move |_| {
                add_row("", None).grab_focus();
            });
        }

        // -- Notes.
        let notes_group = group(&column, "Notes");
        let notes = gtk::TextView::builder()
            .wrap_mode(gtk::WrapMode::WordChar)
            .accepts_tab(false)
            .top_margin(12)
            .bottom_margin(12)
            .left_margin(12)
            .right_margin(12)
            .height_request(if kind == Kind::Note { 220 } else { 96 })
            .css_classes(["notes-editor"])
            .build();
        notes.buffer().set_text(&draft.notes);
        let frame = gtk::Frame::builder()
            .child(&notes)
            .css_classes(["card"])
            .build();
        notes_group.add(&frame);

        // -- Custom fields.
        let fields_group = group(&column, "Custom fields");
        let fields_box = gtk::Box::builder()
            .orientation(gtk::Orientation::Vertical)
            .spacing(12)
            .build();
        fields_group.add(&fields_box);
        let fields: Rc<RefCell<Vec<FieldRow>>> = Rc::new(RefCell::new(Vec::new()));
        let add_field = {
            let fields_box = fields_box.clone();
            let fields = fields.clone();
            move |field: &edit::Field| -> adw::EntryRow {
                let list = gtk::ListBox::builder()
                    .selection_mode(gtk::SelectionMode::None)
                    .css_classes(["boxed-list"])
                    .build();
                let name = entry("Field name", &field.name, false);
                let remove = remove_button("Remove Field");
                name.add_suffix(&remove);
                list.append(&name);
                let (mut value, mut toggle) = (None, None);
                match field.kind {
                    FieldKind::Text | FieldKind::Hidden => {
                        let row = entry("Value", &field.value, field.kind == FieldKind::Hidden);
                        list.append(&row);
                        value = Some(row);
                    }
                    FieldKind::Boolean => {
                        let row = adw::SwitchRow::builder()
                            .title("Value")
                            .active(field.value.eq_ignore_ascii_case("true"))
                            .build();
                        list.append(&row);
                        toggle = Some(row);
                    }
                    FieldKind::Linked => {
                        list.append(
                            &adw::ActionRow::builder()
                                .title("Linked to another field")
                                .css_classes(["dim-label"])
                                .build(),
                        );
                    }
                }
                {
                    let (fields_box, fields, target) =
                        (fields_box.clone(), fields.clone(), list.clone());
                    remove.connect_clicked(move |_| {
                        fields_box.remove(&target);
                        fields.borrow_mut().retain(|f| f.list != target);
                    });
                }
                fields_box.append(&list);
                fields.borrow_mut().push(FieldRow {
                    kind: field.kind,
                    origin: field.origin,
                    list,
                    name: name.clone(),
                    value,
                    toggle,
                });
                name
            }
        };
        for field in &draft.fields {
            add_field(field);
        }
        let add_field = Rc::new(add_field);
        let menu = gtk::Box::builder()
            .orientation(gtk::Orientation::Vertical)
            .build();
        let popover = gtk::Popover::builder().child(&menu).build();
        popover.add_css_class("menu");
        for (label, kind) in [
            ("Text", FieldKind::Text),
            ("Hidden", FieldKind::Hidden),
            ("Checkbox", FieldKind::Boolean),
        ] {
            let button = gtk::Button::builder()
                .label(label)
                .css_classes(["flat"])
                .build();
            if let Some(child) = button.child().and_downcast::<gtk::Label>() {
                child.set_xalign(0.0);
            }
            let (add_field, popover) = (add_field.clone(), popover.downgrade());
            button.connect_clicked(move |_| {
                if let Some(popover) = popover.upgrade() {
                    popover.popdown();
                }
                add_field(&edit::Field {
                    name: Secret::default(),
                    value: Secret::default(),
                    kind,
                    origin: None,
                })
                .grab_focus();
            });
            menu.append(&button);
        }
        fields_group.set_header_suffix(Some(
            &gtk::MenuButton::builder()
                .label("Add Field")
                .popover(&popover)
                .css_classes(["flat"])
                .valign(gtk::Align::Center)
                .build(),
        ));

        Rc::new(Self {
            root: clamp.upcast(),
            id,
            title,
            original,
            kind,
            fixed_owner,
            fixed_collections,
            name,
            folder,
            folder_ids,
            owner,
            owner_ids,
            collections,
            favorite,
            reprompt,
            values,
            uris,
            fields,
            notes,
        })
    }

    pub fn focus(&self) {
        self.name.grab_focus();
    }

    /// The form, read back.
    pub fn draft(&self) -> Draft {
        let org_id = match &self.fixed_owner {
            Some(owner) => owner.clone(),
            None => self
                .owner
                .as_ref()
                .and_then(|row| self.owner_ids.get(row.selected() as usize).cloned())
                .flatten(),
        };
        let collection_ids = if self.fixed_owner.is_some() {
            self.fixed_collections.clone()
        } else {
            self.collections
                .iter()
                .filter(|(_, org, row)| Some(org) == org_id.as_ref() && row.is_active())
                .map(|(id, ..)| id.clone())
                .collect()
        };
        let buffer = self.notes.buffer();
        let notes = buffer.text(&buffer.start_iter(), &buffer.end_iter(), false);
        Draft {
            kind: self.kind,
            name: text(&self.name),
            notes: Secret::new(notes.to_string()),
            folder_id: self
                .folder_ids
                .get(self.folder.selected() as usize)
                .cloned()
                .flatten(),
            org_id,
            collection_ids,
            favorite: self.favorite.is_active(),
            reprompt: self.reprompt.is_active(),
            values: self
                .values
                .iter()
                .map(|v| match v {
                    ValueRow::Entry(row) => text(row),
                    ValueRow::Fixed(value) => value.clone(),
                })
                .collect(),
            uris: self
                .uris
                .borrow()
                .iter()
                .map(|u| edit::Uri {
                    uri: Secret::new(u.row.text().trim().to_string()),
                    origin: u.origin,
                })
                .collect(),
            fields: self
                .fields
                .borrow()
                .iter()
                .map(|f| edit::Field {
                    name: text(&f.name),
                    value: match (&f.value, &f.toggle) {
                        (Some(row), _) => text(row),
                        (_, Some(toggle)) => {
                            Secret::new(if toggle.is_active() { "true" } else { "false" }.into())
                        }
                        _ => Secret::default(),
                    },
                    kind: f.kind,
                    origin: f.origin,
                })
                .collect(),
        }
    }
}

/// What a new item starts with, given where the user is in the vault.
pub fn starting_draft(kind: Kind, filter: &super::vault::Filter, vault: &Vault) -> Draft {
    use super::vault::Filter;
    let mut draft = Draft::new(kind);
    match filter {
        Filter::Favorites => draft.favorite = true,
        Filter::Folder(Some(id)) => draft.folder_id = Some(id.clone()),
        Filter::Collection(id) => {
            if let Some(collection) = vault.collections.iter().find(|c| &c.id == id) {
                if !collection.read_only {
                    draft.org_id = Some(collection.org_id.clone());
                    draft.collection_ids = vec![id.clone()];
                }
            }
        }
        _ => {}
    }
    if kind == Kind::Login {
        draft.uris.push(edit::Uri::default());
    }
    draft
}
