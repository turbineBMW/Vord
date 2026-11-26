//! The unlocked vault: three panes, as in Rustle.
//!
//! ```text
//! overlay split (.vault-split)
//! ├── sidebar: Vault — All Items, Favorites, types, folders, collections,
//! │   Secrets Manager (per organization: its secrets, projects, trash),
//! │   Sends, Trash
//! └── navigation split (.item-split)
//!     ├── sidebar: Items — search, the list
//!     └── content: Details
//! ```
//!
//! Lists are never changed from inside their own selection signals (a GTK
//! rule Rustle learned the hard way): rebuilding waits for an idle.

use super::{detail, editor::Editor, secret::SecretEditor, send::SendEditor, Ui};
use crate::secrets::{Opened, SecretRow, Secrets};
use crate::vault::{Item, Kind, Vault};
use adw::prelude::*;
use gtk::{gio, glib};
use std::cell::{Cell, RefCell};
use std::rc::Rc;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Filter {
    All,
    Favorites,
    Kind(Kind),
    Folder(Option<String>),
    Collection(String),
    Trash,
    /// Sends, not items.
    Sends,
    /// An organization's secrets (Secrets Manager): all, or one project's.
    Secrets {
        org: String,
        project: Option<String>,
    },
    /// An organization's deleted secrets.
    SecretsTrash(String),
}

impl Filter {
    fn accepts(&self, item: &Item) -> bool {
        if matches!(self, Filter::Sends) || self.is_secrets() {
            return false;
        }
        if matches!(self, Filter::Trash) {
            return item.deleted;
        }
        if item.deleted {
            return false;
        }
        match self {
            Filter::All => true,
            Filter::Favorites => item.favorite,
            Filter::Kind(kind) => item.kind == *kind,
            Filter::Folder(None) => item.folder_id.is_none() && item.org_id.is_none(),
            Filter::Folder(Some(id)) => item.folder_id.as_deref() == Some(id),
            Filter::Collection(id) => item.collection_ids.iter().any(|c| c == id),
            Filter::Trash | Filter::Sends | Filter::Secrets { .. } | Filter::SecretsTrash(_) => {
                unreachable!()
            }
        }
    }

    pub fn is_secrets(&self) -> bool {
        matches!(self, Filter::Secrets { .. } | Filter::SecretsTrash(_))
    }

    /// The Secrets Manager organization it shows, if it shows one.
    pub fn secrets_org(&self) -> Option<&str> {
        match self {
            Filter::Secrets { org, .. } | Filter::SecretsTrash(org) => Some(org),
            _ => None,
        }
    }

    fn accepts_secret(&self, secret: &SecretRow) -> bool {
        match self {
            Filter::Secrets { org, project } => {
                !secret.deleted
                    && secret.org_id == *org
                    && project
                        .as_ref()
                        .is_none_or(|p| secret.project.as_ref() == Some(p))
            }
            Filter::SecretsTrash(org) => secret.deleted && secret.org_id == *org,
            _ => false,
        }
    }
}

/// What the details show, for the header's buttons and menu.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Shown {
    Item,
    Send,
    Secret,
}

/// What the quick-copy actions (and their header buttons) take from the
/// selected item.
#[derive(Clone, Copy)]
pub enum Quick {
    Username,
    Password,
    Totp,
    Website,
}

pub struct VaultView {
    pub root: adw::OverlaySplitView,
    /// The accounts, one item each (a radio of `win.switch-account`).
    pub accounts: gio::Menu,
    /// The accounts and "Add Account…": the main menu's submenu, and the
    /// lock screen's switcher.
    pub switcher: gio::Menu,
    inner: adw::NavigationSplitView,
    sidebar_list: gtk::ListBox,
    sidebar_rows: RefCell<Vec<Option<Filter>>>,
    item_list: gtk::ListBox,
    /// Parallel to the list's rows: each one's item id and search text.
    rows: RefCell<Vec<(String, String)>>,
    list_title: adw::WindowTitle,
    list_stack: gtk::Stack,
    list_empty: adw::StatusPage,
    search: gtk::SearchEntry,
    sync_button: gtk::Button,
    sync_spinner: adw::Spinner,
    banner: adw::Banner,
    detail_stack: gtk::Stack,
    detail_scroller: gtk::ScrolledWindow,
    detail_page: adw::NavigationPage,
    detail_title: adw::WindowTitle,
    /// The details' own buttons, hidden while an item is edited.
    view_buttons: Vec<gtk::Widget>,
    /// The ones only an item has, hidden for a Send.
    item_buttons: Vec<gtk::Widget>,
    more: gtk::MenuButton,
    item_menu: gio::Menu,
    send_menu: gio::Menu,
    secret_menu: gio::Menu,
    edit_cancel: gtk::Button,
    edit_save: gtk::Button,
    new_button: gtk::MenuButton,
    folder_menu: gtk::MenuButton,
    project_menu: gtk::MenuButton,
    /// The open editor. While there is one, the lists can't be used.
    editor: RefCell<Option<Rc<Editor>>>,
    send_editor: RefCell<Option<Rc<SendEditor>>>,
    secret_editor: RefCell<Option<Rc<SecretEditor>>>,
    /// Secrets Manager's lists, once fetched.
    secrets: RefCell<Option<Rc<Secrets>>>,
    /// The secret whose value the details show (or are fetching, or
    /// could not fetch, and why).
    opened_secret: RefCell<Option<Rc<Opened>>>,
    fetching_secret: RefCell<Option<String>>,
    secret_failed: RefCell<Option<(String, String)>>,
    vault: RefCell<Option<Rc<Vault>>>,
    filter: RefCell<Filter>,
    selected: RefCell<Option<String>>,
    /// Set while the lists are rebuilt, so their signals are ignored.
    rebuilding: Cell<bool>,
}

fn header_toggle(split: &adw::OverlaySplitView) -> gtk::ToggleButton {
    let toggle = gtk::ToggleButton::builder()
        .icon_name("sidebar-show-symbolic")
        .tooltip_text("Show Sidebar")
        .build();
    split
        .bind_property("show-sidebar", &toggle, "active")
        .sync_create()
        .bidirectional()
        .build();
    toggle
}

impl VaultView {
    pub fn new() -> Self {
        let root = adw::OverlaySplitView::builder()
            .min_sidebar_width(200.0)
            .max_sidebar_width(280.0)
            .sidebar_width_fraction(0.2)
            .css_classes(["vault-split"])
            .build();

        // -- Vault sidebar
        let sidebar_list = gtk::ListBox::builder()
            .css_classes(["navigation-sidebar"])
            .selection_mode(gtk::SelectionMode::Single)
            .build();
        let sidebar_scroller = gtk::ScrolledWindow::builder()
            .hscrollbar_policy(gtk::PolicyType::Never)
            .child(&sidebar_list)
            .vexpand(true)
            .build();
        let sidebar_header = adw::HeaderBar::builder()
            .title_widget(&adw::WindowTitle::new("Vault", ""))
            .show_end_title_buttons(false)
            .build();
        sidebar_header.pack_start(&header_toggle(&root));
        let accounts = gio::Menu::new();
        let switcher = gio::Menu::new();
        switcher.append_section(None, &accounts);
        let adding = gio::Menu::new();
        adding.append(Some("_Add Account…"), Some("win.add-account"));
        switcher.append_section(None, &adding);
        let menu = gtk::gio::Menu::new();
        let section = gtk::gio::Menu::new();
        section.append(Some("_Generator"), Some("win.generator"));
        section.append(Some("New _Folder…"), Some("win.new-folder"));
        section.append(Some("_Export Vault…"), Some("win.export"));
        section.append(Some("_Sync Now"), Some("win.sync"));
        section.append(Some("_Lock"), Some("win.lock"));
        menu.append_section(None, &section);
        let section = gtk::gio::Menu::new();
        section.append(Some("_Preferences"), Some("win.preferences"));
        section.append(Some("_About Vord"), Some("win.about"));
        menu.append_section(None, &section);
        let section = gtk::gio::Menu::new();
        section.append_submenu(Some("A_ccounts"), &switcher);
        section.append(Some("Log _Out…"), Some("win.logout"));
        menu.append_section(None, &section);
        sidebar_header.pack_end(
            &gtk::MenuButton::builder()
                .icon_name("open-menu-symbolic")
                .menu_model(&menu)
                .tooltip_text("Main Menu")
                .primary(true)
                .build(),
        );
        let sidebar_view = adw::ToolbarView::builder()
            .content(&sidebar_scroller)
            .build();
        sidebar_view.add_top_bar(&sidebar_header);
        root.set_sidebar(Some(&sidebar_view));

        // -- Item list
        let item_list = gtk::ListBox::builder()
            .css_classes(["navigation-sidebar", "item-list"])
            .selection_mode(gtk::SelectionMode::Single)
            .build();
        let list_scroller = gtk::ScrolledWindow::builder()
            .hscrollbar_policy(gtk::PolicyType::Never)
            .child(&item_list)
            .vexpand(true)
            .build();
        let list_empty = adw::StatusPage::builder()
            .icon_name("dialog-password-symbolic")
            .title("No Items")
            .css_classes(["compact"])
            .build();
        let list_loading = adw::StatusPage::builder()
            .title("Syncing…")
            .paintable(&adw::SpinnerPaintable::new(None::<&gtk::Widget>))
            .css_classes(["compact"])
            .build();
        let list_stack = gtk::Stack::new();
        list_stack.add_named(&list_scroller, Some("list"));
        list_stack.add_named(&list_empty, Some("empty"));
        list_stack.add_named(&list_loading, Some("loading"));
        if let Some(paintable) = list_loading
            .paintable()
            .and_downcast::<adw::SpinnerPaintable>()
        {
            paintable.set_widget(Some(&list_loading));
        }

        let list_title = adw::WindowTitle::new("Items", "");
        let list_header = adw::HeaderBar::builder()
            .title_widget(&list_title)
            .show_end_title_buttons(false)
            .show_start_title_buttons(false)
            .build();
        let list_toggle = header_toggle(&root);
        root.bind_property("show-sidebar", &list_toggle, "visible")
            .invert_boolean()
            .sync_create()
            .build();
        list_header.pack_start(&list_toggle);
        let sync_spinner = adw::Spinner::builder().visible(false).build();
        let sync_button = gtk::Button::builder()
            .icon_name("view-refresh-symbolic")
            .tooltip_text("Sync Now (Ctrl+R)")
            .action_name("win.sync")
            .build();
        list_header.pack_start(&sync_button);
        list_header.pack_start(&sync_spinner);
        list_header.pack_end(
            &gtk::Button::builder()
                .icon_name("system-lock-screen-symbolic")
                .tooltip_text("Lock (Ctrl+L)")
                .action_name("win.lock")
                .build(),
        );
        let new_menu = gio::Menu::new();
        for (label, kind) in [
            ("_Login", "login"),
            ("_Card", "card"),
            ("_Identity", "identity"),
            ("Secure _Note", "note"),
            ("_SSH Key", "ssh-key"),
        ] {
            new_menu.append(Some(label), Some(&format!("win.new-item::{kind}")));
        }
        let sends_section = gio::Menu::new();
        sends_section.append(Some("_Text Send"), Some("win.new-send::text"));
        sends_section.append(Some("_File Send"), Some("win.new-send::file"));
        let secrets_section = gio::Menu::new();
        for (label, action, target) in [
            ("S_ecret", "win.new-secret", None),
            // An empty target: the organization the list shows.
            ("_Project…", "win.new-project", Some("".to_variant())),
        ] {
            let entry = gio::MenuItem::new(Some(label), None);
            entry.set_action_and_target_value(Some(action), target.as_ref());
            entry.set_attribute_value("hidden-when", Some(&"action-disabled".to_variant()));
            secrets_section.append_item(&entry);
        }
        let new_menu = {
            let menu = gio::Menu::new();
            menu.append_section(None, &new_menu);
            menu.append_section(None, &sends_section);
            menu.append_section(None, &secrets_section);
            menu
        };
        let new_button = gtk::MenuButton::builder()
            .icon_name("list-add-symbolic")
            .tooltip_text("New Item (Ctrl+N for a login)")
            .menu_model(&new_menu)
            .build();
        list_header.pack_end(&new_button);
        let folder_actions = gio::Menu::new();
        folder_actions.append(Some("_Rename Folder…"), Some("win.rename-folder"));
        folder_actions.append(Some("_Delete Folder…"), Some("win.delete-folder"));
        let folder_menu = gtk::MenuButton::builder()
            .icon_name("view-more-symbolic")
            .tooltip_text("Folder")
            .menu_model(&folder_actions)
            .visible(false)
            .build();
        list_header.pack_end(&folder_menu);
        let project_actions = gio::Menu::new();
        project_actions.append(Some("_Rename Project…"), Some("win.rename-project"));
        project_actions.append(Some("_Delete Project…"), Some("win.delete-project"));
        let project_menu = gtk::MenuButton::builder()
            .icon_name("view-more-symbolic")
            .tooltip_text("Project")
            .menu_model(&project_actions)
            .visible(false)
            .build();
        list_header.pack_end(&project_menu);
        let search = gtk::SearchEntry::builder()
            .placeholder_text("Search vault")
            .css_classes(["list-search"])
            .build();
        let list_view = adw::ToolbarView::builder().content(&list_stack).build();
        list_view.add_top_bar(&list_header);
        list_view.add_top_bar(&search);
        let banner = adw::Banner::builder().revealed(false).build();
        list_view.add_bottom_bar(&banner);
        let list_page = adw::NavigationPage::builder()
            .title("Items")
            .child(&list_view)
            .build();

        // -- Details
        let detail_empty = adw::StatusPage::builder()
            .icon_name(format!("{}-symbolic", crate::APP_ID))
            .title("No Item Selected")
            .description("Pick an item to see its details.")
            .build();
        let detail_scroller = gtk::ScrolledWindow::builder()
            .hscrollbar_policy(gtk::PolicyType::Never)
            .vexpand(true)
            .build();
        let detail_stack = gtk::Stack::new();
        detail_stack.add_named(&detail_empty, Some("empty"));
        detail_stack.add_named(&detail_scroller, Some("item"));
        let detail_title = adw::WindowTitle::new("Details", "");
        let detail_header = adw::HeaderBar::builder()
            .title_widget(&detail_title)
            .build();
        let quick = gtk::Box::builder().css_classes(["linked"]).build();
        for (icon, tip, action) in [
            (
                "avatar-default-symbolic",
                "Copy Username (Ctrl+U)",
                "win.copy-username",
            ),
            (
                "dialog-password-symbolic",
                "Copy Password (Ctrl+P)",
                "win.copy-password",
            ),
            (
                "preferences-system-time-symbolic",
                "Copy Verification Code (Ctrl+T)",
                "win.copy-totp",
            ),
        ] {
            quick.append(
                &gtk::Button::builder()
                    .icon_name(icon)
                    .tooltip_text(tip)
                    .action_name(action)
                    .build(),
            );
        }
        detail_header.pack_start(&quick);
        let open_website = gtk::Button::builder()
            .icon_name("web-browser-symbolic")
            .tooltip_text("Open Website (Ctrl+O)")
            .action_name("win.open-website")
            .build();
        detail_header.pack_start(&open_website);
        let item_menu = gio::Menu::new();
        let section = gio::Menu::new();
        section.append(Some("_Favorite"), Some("win.favorite"));
        section.append(Some("_Clone"), Some("win.clone-item"));
        section.append(Some("Add _Attachment…"), Some("win.add-attachment"));
        item_menu.append_section(None, &section);
        let section = gio::Menu::new();
        for (label, action) in [
            ("Move to _Trash", "win.trash-item"),
            ("_Restore", "win.restore-item"),
            ("_Delete Permanently…", "win.purge-item"),
        ] {
            let entry = gio::MenuItem::new(Some(label), Some(action));
            entry.set_attribute_value("hidden-when", Some(&"action-disabled".to_variant()));
            section.append_item(&entry);
        }
        item_menu.append_section(None, &section);
        let send_menu = gio::Menu::new();
        let section = gio::Menu::new();
        section.append(Some("_Copy Link"), Some("win.copy-send-link"));
        let entry = gio::MenuItem::new(Some("_Remove Password"), Some("win.remove-send-password"));
        entry.set_attribute_value("hidden-when", Some(&"action-disabled".to_variant()));
        section.append_item(&entry);
        send_menu.append_section(None, &section);
        let section = gio::Menu::new();
        section.append(Some("_Delete Send…"), Some("win.delete-send"));
        send_menu.append_section(None, &section);
        let secret_menu = gio::Menu::new();
        let section = gio::Menu::new();
        for (label, action) in [
            ("_Delete Secret…", "win.delete-secret"),
            ("_Restore", "win.restore-secret"),
            ("Delete _Permanently…", "win.purge-secret"),
        ] {
            let entry = gio::MenuItem::new(Some(label), Some(action));
            entry.set_attribute_value("hidden-when", Some(&"action-disabled".to_variant()));
            section.append_item(&entry);
        }
        secret_menu.append_section(None, &section);
        let more = gtk::MenuButton::builder()
            .icon_name("view-more-symbolic")
            .tooltip_text("More")
            .menu_model(&item_menu)
            .build();
        detail_header.pack_end(&more);
        let edit = gtk::Button::builder()
            .icon_name("document-edit-symbolic")
            .tooltip_text("Edit (Ctrl+E)")
            .action_name("win.edit-item")
            .build();
        detail_header.pack_end(&edit);
        let edit_cancel = gtk::Button::builder()
            .label("_Cancel")
            .use_underline(true)
            .action_name("win.cancel-edit")
            .visible(false)
            .build();
        detail_header.pack_start(&edit_cancel);
        let edit_save = gtk::Button::builder()
            .label("_Save")
            .use_underline(true)
            .tooltip_text("Save (Ctrl+S)")
            .action_name("win.save-item")
            .css_classes(["suggested-action"])
            .visible(false)
            .build();
        detail_header.pack_end(&edit_save);
        let detail_view = adw::ToolbarView::builder().content(&detail_stack).build();
        detail_view.add_top_bar(&detail_header);
        let detail_page = adw::NavigationPage::builder()
            .title("Details")
            .child(&detail_view)
            .build();

        let inner = adw::NavigationSplitView::builder()
            .sidebar(&list_page)
            .content(&detail_page)
            .min_sidebar_width(280.0)
            .max_sidebar_width(400.0)
            .sidebar_width_fraction(0.36)
            .css_classes(["item-split"])
            .build();
        root.set_content(Some(&inner));

        root.connect_collapsed_notify(|split| {
            if split.is_collapsed() {
                split.add_css_class("collapsed");
                split.set_show_sidebar(false);
            } else {
                split.remove_css_class("collapsed");
                split.set_show_sidebar(true);
            }
        });

        Self {
            root,
            accounts,
            switcher,
            inner,
            sidebar_list,
            sidebar_rows: RefCell::new(Vec::new()),
            item_list,
            rows: RefCell::new(Vec::new()),
            list_title,
            list_stack,
            list_empty,
            search,
            sync_button,
            sync_spinner,
            banner,
            detail_stack,
            detail_scroller,
            detail_page,
            detail_title,
            view_buttons: vec![
                quick.clone().upcast(),
                open_website.clone().upcast(),
                edit.upcast(),
                more.clone().upcast(),
            ],
            item_buttons: vec![quick.upcast(), open_website.upcast()],
            more,
            item_menu,
            send_menu,
            secret_menu,
            edit_cancel,
            edit_save,
            new_button,
            folder_menu,
            project_menu,
            editor: RefCell::new(None),
            send_editor: RefCell::new(None),
            secret_editor: RefCell::new(None),
            secrets: RefCell::new(None),
            opened_secret: RefCell::new(None),
            fetching_secret: RefCell::new(None),
            secret_failed: RefCell::new(None),
            vault: RefCell::new(None),
            filter: RefCell::new(Filter::All),
            selected: RefCell::new(None),
            rebuilding: Cell::new(false),
        }
    }

    /// Fold the panes away as the window narrows: first the vault sidebar,
    /// then the list and details into one column.
    pub fn add_breakpoints(&self, window: &adw::ApplicationWindow) {
        let medium = adw::Breakpoint::new(
            adw::BreakpointCondition::parse("max-width: 900sp").expect("valid condition"),
        );
        medium.add_setter(&self.root, "collapsed", Some(&true.to_value()));
        window.add_breakpoint(medium);
        let narrow = adw::Breakpoint::new(
            adw::BreakpointCondition::parse("max-width: 600sp").expect("valid condition"),
        );
        narrow.add_setter(&self.root, "collapsed", Some(&true.to_value()));
        narrow.add_setter(&self.inner, "collapsed", Some(&true.to_value()));
        window.add_breakpoint(narrow);
    }

    pub fn connect(&self, ui: &Rc<Ui>) {
        let weak = Rc::downgrade(ui);
        self.sidebar_list.connect_row_selected(move |_, row| {
            let (Some(ui), Some(row)) = (weak.upgrade(), row) else {
                return;
            };
            let view = &ui.vault;
            if view.rebuilding.get() {
                return;
            }
            let filter = view
                .sidebar_rows
                .borrow()
                .get(row.index() as usize)
                .cloned()
                .flatten();
            let Some(filter) = filter else { return };
            if *view.filter.borrow() == filter {
                return;
            }
            view.filter.replace(filter);
            if view.root.is_collapsed() {
                view.root.set_show_sidebar(false);
            }
            let weak = Rc::downgrade(&ui);
            glib::idle_add_local_once(move || {
                if let Some(ui) = weak.upgrade() {
                    ui.vault.rebuild_items(&ui);
                }
            });
        });

        let weak = Rc::downgrade(ui);
        self.item_list.connect_row_selected(move |_, row| {
            let Some(ui) = weak.upgrade() else { return };
            let view = &ui.vault;
            if view.rebuilding.get() {
                return;
            }
            let id = row.and_then(|row| {
                view.rows
                    .borrow()
                    .get(row.index() as usize)
                    .map(|(id, _)| id.clone())
            });
            view.selected.replace(id);
            ui.forget_reprompt();
            let weak = Rc::downgrade(&ui);
            glib::idle_add_local_once(move || {
                if let Some(ui) = weak.upgrade() {
                    ui.vault.show_detail(&ui);
                }
            });
        });
        let weak = Rc::downgrade(ui);
        self.item_list.connect_row_activated(move |_, _| {
            if let Some(ui) = weak.upgrade() {
                ui.vault.inner.set_show_content(true);
            }
        });

        // Search filters the rows in place.
        let weak = Rc::downgrade(ui);
        self.item_list.set_filter_func(move |row| {
            let Some(ui) = weak.upgrade() else {
                return true;
            };
            let query = ui.vault.search.text();
            if query.trim().is_empty() {
                return true;
            }
            let rows = ui.vault.rows.borrow();
            let Some((_, haystack)) = rows.get(row.index() as usize) else {
                return true;
            };
            crate::vault::search_matches(haystack, &query)
        });
        let weak = Rc::downgrade(ui);
        self.search.connect_search_changed(move |_| {
            if let Some(ui) = weak.upgrade() {
                ui.vault.item_list.invalidate_filter();
                ui.vault.update_empty();
            }
        });
        let weak = Rc::downgrade(ui);
        self.search.connect_stop_search(move |entry| {
            entry.set_text("");
            if let Some(ui) = weak.upgrade() {
                ui.vault.item_list.grab_focus();
            }
        });
        // Down from the search field goes to the first match.
        let weak = Rc::downgrade(ui);
        self.search.connect_activate(move |_| {
            let Some(ui) = weak.upgrade() else { return };
            let view = &ui.vault;
            let mut index = 0;
            while let Some(row) = view.item_list.row_at_index(index) {
                if row.is_child_visible() {
                    view.item_list.select_row(Some(&row));
                    row.grab_focus();
                    break;
                }
                index += 1;
            }
        });
    }

    pub fn focus_search(&self) {
        if self.root.is_collapsed() {
            self.inner.set_show_content(false);
        }
        self.search.grab_focus();
        self.search.select_region(0, -1);
    }

    pub fn set_syncing(&self, syncing: bool) {
        self.sync_button.set_visible(!syncing);
        self.sync_spinner.set_visible(syncing);
    }

    pub fn set_offline(&self, ui: &Rc<Ui>, message: Option<&str>) {
        match message {
            Some(message) => {
                self.banner.set_title(message);
                self.banner.set_revealed(true);
                if self.list_stack.visible_child_name().as_deref() == Some("loading") {
                    self.update_empty();
                }
            }
            None => self.banner.set_revealed(false),
        }
        let _ = ui;
    }

    /// Show a vault, keeping the filter and the selected item when they
    /// still exist.
    pub fn show_vault(&self, ui: &Rc<Ui>, vault: Rc<Vault>, loading: bool) {
        self.banner.set_revealed(false);
        super::agent::refresh_keys(ui, &vault);
        // An account used only for Secrets Manager opens on its secrets.
        // (First shown, or first synced after a login.)
        let first = self
            .vault
            .borrow()
            .as_ref()
            .is_none_or(|v| v.items.is_empty() && v.sm_orgs.is_empty());
        if first && *self.filter.borrow() == Filter::All && vault.items.is_empty() {
            if let Some(org) = vault.sm_orgs.first() {
                self.filter.replace(Filter::Secrets {
                    org: org.id.clone(),
                    project: None,
                });
            }
        }
        self.vault.replace(Some(vault));
        self.rebuild_sidebar(ui);
        self.rebuild_items(ui);
        if loading {
            self.list_stack.set_visible_child_name("loading");
        }
        self.show_damage();
    }

    /// A sync found nothing new: drop an earlier sync's error.
    pub fn sync_ok(&self) {
        self.banner.set_revealed(false);
        self.show_damage();
    }

    fn show_damage(&self) {
        let damaged = self.vault.borrow().as_ref().map_or(0, |v| v.damaged);
        if damaged > 0 {
            self.banner
                .set_title(&format!("{damaged} item(s) could not be fully decrypted."));
            self.banner.set_revealed(true);
        }
    }

    /// Forget everything decrypted: rows, details, the vault itself.
    pub fn clear(&self) {
        self.close_editor();
        self.rebuilding.set(true);
        self.item_list.remove_all();
        self.sidebar_list.remove_all();
        self.rebuilding.set(false);
        self.rows.borrow_mut().clear();
        self.sidebar_rows.borrow_mut().clear();
        self.detail_scroller.set_child(None::<&gtk::Widget>);
        self.detail_stack.set_visible_child_name("empty");
        self.search.set_text("");
        self.banner.set_revealed(false);
        self.vault.replace(None);
        self.secrets.replace(None);
        self.forget_opened_secret();
        self.selected.replace(None);
        self.filter.replace(Filter::All);
        self.inner.set_show_content(false);
    }

    /// Show Secrets Manager's lists as now fetched, keeping the filter and
    /// the selected secret when they still exist.
    pub fn show_secrets(&self, ui: &Rc<Ui>, secrets: Rc<Secrets>) {
        self.secrets.replace(Some(secrets));
        self.rebuild_sidebar(ui);
        self.rebuild_items(ui);
    }

    pub fn current_secrets(&self) -> Option<Rc<Secrets>> {
        self.secrets.borrow().clone()
    }

    /// Drop the opened secret's decrypted value, and any fetch of one.
    fn forget_opened_secret(&self) {
        self.opened_secret.replace(None);
        self.fetching_secret.replace(None);
        self.secret_failed.replace(None);
    }

    /// A fetched secret arrived (or failed): show it if it's still the
    /// one selected.
    pub fn secret_fetched(&self, ui: &Rc<Ui>, id: &str, result: Result<Opened, String>) {
        if self.fetching_secret.borrow().as_deref() != Some(id) {
            return;
        }
        self.fetching_secret.replace(None);
        match result {
            Ok(opened) => {
                self.opened_secret.replace(Some(Rc::new(opened)));
                self.secret_failed.replace(None);
            }
            Err(why) => {
                self.opened_secret.replace(None);
                self.secret_failed.replace(Some((id.to_string(), why)));
            }
        }
        if self.selected.borrow().as_deref() == Some(id) {
            self.show_detail(ui);
        }
    }

    /// The selected secret, if one is.
    pub fn selected_secret(&self) -> Option<(Rc<Secrets>, SecretRow)> {
        if !self.filter.borrow().is_secrets() {
            return None;
        }
        let secrets = self.secrets.borrow().clone()?;
        let id = self.selected.borrow().clone()?;
        let row = secrets.secret(&id)?.clone();
        Some((secrets, row))
    }

    /// The selected secret, opened, if its value is here.
    pub fn opened_selected_secret(&self) -> Option<Rc<Opened>> {
        let (_, row) = self.selected_secret()?;
        self.opened_secret
            .borrow()
            .clone()
            .filter(|o| o.id == row.id && !row.deleted)
    }

    /// The project the list shows, if it shows one.
    pub fn current_project(&self) -> Option<crate::secrets::Project> {
        let Filter::Secrets {
            project: Some(id), ..
        } = &*self.filter.borrow()
        else {
            return None;
        };
        self.secrets.borrow().as_ref()?.project(id).cloned()
    }

    fn rebuild_sidebar(&self, ui: &Rc<Ui>) {
        let vault = self.vault.borrow().clone();
        let Some(vault) = vault else { return };
        let count = |filter: &Filter| vault.items.iter().filter(|i| filter.accepts(i)).count();

        let mut entries: Vec<(Option<Filter>, String, String)> = vec![
            (
                Some(Filter::All),
                "view-grid-symbolic".into(),
                "All Items".into(),
            ),
            (
                Some(Filter::Favorites),
                "starred-symbolic".into(),
                "Favorites".into(),
            ),
            (None, String::new(), "TYPES".into()),
        ];
        for kind in Kind::ALL {
            let filter = Filter::Kind(kind);
            if kind == Kind::SshKey && count(&filter) == 0 {
                continue;
            }
            entries.push((Some(filter), kind.icon().into(), kind.plural().into()));
        }
        // A heading's + button: its label, action and the action's target.
        let mut heading_buttons: Vec<(String, &str, glib::Variant, &str)> = vec![(
            "FOLDERS".into(),
            "win.new-folder",
            ().to_variant(),
            "New Folder",
        )];
        entries.push((None, String::new(), "FOLDERS".into()));
        for folder in &vault.folders {
            entries.push((
                Some(Filter::Folder(Some(folder.id.clone()))),
                "folder-symbolic".into(),
                folder.name.clone(),
            ));
        }
        entries.push((
            Some(Filter::Folder(None)),
            "folder-symbolic".into(),
            "No Folder".into(),
        ));
        for org in &vault.organizations {
            let collections: Vec<_> = vault
                .collections
                .iter()
                .filter(|c| c.org_id == org.id)
                .collect();
            if collections.is_empty() {
                continue;
            }
            entries.push((None, String::new(), org.name.to_uppercase()));
            for collection in collections {
                entries.push((
                    Some(Filter::Collection(collection.id.clone())),
                    "system-users-symbolic".into(),
                    collection.name.clone(),
                ));
            }
        }
        let secrets = self.secrets.borrow().clone();
        for org in &vault.sm_orgs {
            let heading = if vault.sm_orgs.len() == 1 {
                "SECRETS MANAGER".to_string()
            } else {
                format!("SECRETS · {}", org.name.to_uppercase())
            };
            heading_buttons.push((
                heading.clone(),
                "win.new-project",
                org.id.to_variant(),
                "New Project",
            ));
            entries.push((None, String::new(), heading));
            entries.push((
                Some(Filter::Secrets {
                    org: org.id.clone(),
                    project: None,
                }),
                super::secret::ICON.into(),
                "All Secrets".into(),
            ));
            for project in secrets.iter().flat_map(|s| &s.projects) {
                if project.org_id == org.id {
                    entries.push((
                        Some(Filter::Secrets {
                            org: org.id.clone(),
                            project: Some(project.id.clone()),
                        }),
                        super::secret::PROJECT_ICON.into(),
                        project.name.clone(),
                    ));
                }
            }
            if org.admin {
                entries.push((
                    Some(Filter::SecretsTrash(org.id.clone())),
                    "user-trash-symbolic".into(),
                    "Deleted Secrets".into(),
                ));
            }
        }
        entries.push((None, String::new(), String::new()));
        entries.push((
            Some(Filter::Sends),
            "mail-send-symbolic".into(),
            "Sends".into(),
        ));
        entries.push((
            Some(Filter::Trash),
            "user-trash-symbolic".into(),
            "Trash".into(),
        ));

        // A filter that no longer exists (a deleted folder) falls back.
        let current = self.filter.borrow().clone();
        if !entries.iter().any(|(f, ..)| f.as_ref() == Some(&current)) {
            self.filter.replace(Filter::All);
        }
        let current = self.filter.borrow().clone();

        self.rebuilding.set(true);
        self.sidebar_list.remove_all();
        let mut rows = Vec::new();
        for (filter, icon, label) in entries {
            let row = gtk::ListBoxRow::new();
            match &filter {
                None => {
                    row.set_selectable(false);
                    row.set_activatable(false);
                    row.set_can_focus(false);
                    if label.is_empty() {
                        row.set_child(Some(&gtk::Box::builder().height_request(10).build()));
                    } else {
                        let heading = gtk::Box::new(gtk::Orientation::Horizontal, 0);
                        heading.append(
                            &gtk::Label::builder()
                                .label(&label)
                                .xalign(0.0)
                                .hexpand(true)
                                .css_classes(["vault-heading"])
                                .build(),
                        );
                        if let Some((_, action, target, tip)) =
                            heading_buttons.iter().find(|(l, ..)| *l == label)
                        {
                            let button = gtk::Button::builder()
                                .icon_name("list-add-symbolic")
                                .tooltip_text(*tip)
                                .action_name(*action)
                                .css_classes(["flat", "heading-button"])
                                .valign(gtk::Align::Center)
                                .build();
                            if target.type_() != glib::VariantTy::UNIT {
                                button.set_action_target_value(Some(target));
                            }
                            heading.append(&button);
                        }
                        row.set_child(Some(&heading));
                    }
                }
                Some(filter) => {
                    let line = gtk::Box::builder().spacing(12).build();
                    line.append(&gtk::Image::from_icon_name(&icon));
                    line.append(
                        &gtk::Label::builder()
                            .label(&label)
                            .xalign(0.0)
                            .hexpand(true)
                            .ellipsize(gtk::pango::EllipsizeMode::End)
                            .build(),
                    );
                    let n = match filter {
                        Filter::Sends => vault.sends.len(),
                        filter if filter.is_secrets() => secrets.as_ref().map_or(0, |s| {
                            s.secrets
                                .iter()
                                .filter(|r| filter.accepts_secret(r))
                                .count()
                        }),
                        filter => count(filter),
                    };
                    if n > 0 {
                        line.append(
                            &gtk::Label::builder()
                                .label(n.to_string())
                                .css_classes(["vault-count", "dim-label"])
                                .build(),
                        );
                    }
                    row.set_child(Some(&line));
                }
            }
            self.sidebar_list.append(&row);
            if filter.as_ref() == Some(&current) {
                self.sidebar_list.select_row(Some(&row));
            }
            rows.push(filter);
        }
        self.sidebar_rows.replace(rows);
        self.rebuilding.set(false);
        let _ = ui;
    }

    fn filter_title(&self, vault: &Vault) -> String {
        match &*self.filter.borrow() {
            Filter::All => "All Items".into(),
            Filter::Favorites => "Favorites".into(),
            Filter::Kind(kind) => kind.plural().into(),
            Filter::Folder(None) => "No Folder".into(),
            Filter::Folder(Some(id)) => vault
                .folders
                .iter()
                .find(|f| &f.id == id)
                .map_or("Folder".into(), |f| f.name.clone()),
            Filter::Collection(id) => vault
                .collections
                .iter()
                .find(|c| &c.id == id)
                .map_or("Collection".into(), |c| c.name.clone()),
            Filter::Trash => "Trash".into(),
            Filter::Sends => "Sends".into(),
            Filter::Secrets { project: None, .. } => "All Secrets".into(),
            Filter::Secrets {
                project: Some(id), ..
            } => self
                .secrets
                .borrow()
                .as_ref()
                .and_then(|s| s.project(id))
                .map_or("Project".into(), |p| p.name.clone()),
            Filter::SecretsTrash(_) => "Deleted Secrets".into(),
        }
    }

    pub fn rebuild_items(&self, ui: &Rc<Ui>) {
        let vault = self.vault.borrow().clone();
        let Some(vault) = vault else { return };
        let filter = self.filter.borrow().clone();
        let server = ui.server().unwrap_or_default();
        let show_icons = crate::settings::get().show_icons;
        let selected = self.selected.borrow().clone();

        self.rebuilding.set(true);
        self.item_list.remove_all();
        let mut rows = Vec::new();
        let mut selected_row = None;
        let secrets = self.secrets.borrow().clone();
        if let Some(secrets) = secrets.as_ref().filter(|_| filter.is_secrets()) {
            for secret in secrets.secrets.iter().filter(|s| filter.accepts_secret(s)) {
                let row = super::secret::row(secrets, secret);
                self.item_list.append(&row);
                if selected.as_deref() == Some(secret.id.as_str()) {
                    selected_row = Some(row);
                }
                rows.push((
                    secret.id.clone(),
                    secret.search_text(secrets.project_name(secret)),
                ));
            }
        }
        if filter == Filter::Sends {
            for send in &vault.sends {
                let row = super::send::row(send);
                self.item_list.append(&row);
                if selected.as_deref() == Some(send.id.as_str()) {
                    selected_row = Some(row);
                }
                rows.push((send.id.clone(), send.search_text()));
            }
        }
        // Favourites first in All Items, then by name (the vault is sorted).
        let mut items: Vec<&Item> = vault.items.iter().filter(|i| filter.accepts(i)).collect();
        if filter == Filter::All {
            items.sort_by_key(|i| !i.favorite);
        }
        for item in items {
            let row = item_row(item, &server, show_icons);
            self.item_list.append(&row);
            if selected.as_deref() == Some(item.id.as_str()) {
                selected_row = Some(row);
            }
            rows.push((item.id.clone(), item.search_text()));
        }
        self.rows.replace(rows);
        match &selected_row {
            Some(row) => self.item_list.select_row(Some(row)),
            None => self.item_list.unselect_all(),
        }
        self.rebuilding.set(false);

        self.list_title.set_title(&self.filter_title(&vault));
        self.folder_menu
            .set_visible(matches!(filter, Filter::Folder(Some(_))));
        self.project_menu.set_visible(matches!(
            filter,
            Filter::Secrets {
                project: Some(_),
                ..
            }
        ));
        if selected_row.is_none() {
            self.selected.replace(None);
        }
        self.item_list.invalidate_filter();
        self.update_empty();
        if filter.is_secrets() && secrets.is_none() {
            self.list_stack.set_visible_child_name("loading");
        }
        self.show_detail(ui);
    }

    /// The count under the list's title, and the empty page when nothing
    /// shows.
    fn update_empty(&self) {
        let rows = self.rows.borrow();
        let searching = !self.search.text().trim().is_empty();
        let visible = (0..rows.len() as i32)
            .filter(|&i| {
                self.item_list
                    .row_at_index(i)
                    .is_some_and(|row| row.is_child_visible())
            })
            .count();
        let any_visible = visible > 0;
        let filter = self.filter.borrow().clone();
        let sends = filter == Filter::Sends;
        let noun = match &filter {
            Filter::Sends => ("Send", "Sends"),
            f if f.is_secrets() => ("secret", "secrets"),
            _ => ("item", "items"),
        };
        let total = match rows.len() {
            1 => format!("1 {}", noun.0),
            n => format!("{n} {}", noun.1),
        };
        self.list_title.set_subtitle(&if searching {
            format!("{visible} of {total}")
        } else {
            total
        });
        if rows.is_empty() || (searching && !any_visible) {
            if searching {
                self.list_empty.set_icon_name(Some("edit-find-symbolic"));
                self.list_empty.set_title("No Results");
                self.list_empty
                    .set_description(Some("Nothing in this view matches."));
            } else if sends {
                self.list_empty.set_icon_name(Some("mail-send-symbolic"));
                self.list_empty.set_title("No Sends");
                self.list_empty.set_description(Some(
                    "A Send shares a text or a file by link, end-to-end encrypted. Make one with +.",
                ));
            } else if matches!(filter, Filter::Secrets { .. }) {
                self.list_empty.set_icon_name(Some(super::secret::ICON));
                self.list_empty.set_title("No Secrets");
                self.list_empty
                    .set_description(Some("Make one with +, under Secret."));
            } else if matches!(filter, Filter::Trash | Filter::SecretsTrash(_)) {
                self.list_empty.set_icon_name(Some("user-trash-symbolic"));
                self.list_empty.set_title("Trash Is Empty");
                self.list_empty.set_description(None);
            } else {
                self.list_empty
                    .set_icon_name(Some("dialog-password-symbolic"));
                self.list_empty.set_title("No Items");
                self.list_empty.set_description(None);
            }
            self.list_stack.set_visible_child_name("empty");
        } else {
            self.list_stack.set_visible_child_name("list");
        }
    }

    fn selected_item(&self) -> Option<(Rc<Vault>, String)> {
        let vault = self.vault.borrow().clone()?;
        let id = self.selected.borrow().clone()?;
        vault.item(&id)?;
        Some((vault, id))
    }

    fn selected_send(&self) -> Option<(Rc<Vault>, String)> {
        let vault = self.vault.borrow().clone()?;
        let id = self.selected.borrow().clone()?;
        vault.send(&id)?;
        Some((vault, id))
    }

    /// The selected Send's id, if it's still there.
    pub fn selected_send_id(&self) -> Option<String> {
        self.selected_send().map(|(_, id)| id)
    }

    /// The details' header as an item, a Send or a secret needs it.
    fn header_for(&self, shown: Shown) {
        for widget in &self.item_buttons {
            widget.set_visible(shown == Shown::Item);
        }
        self.more.set_menu_model(Some(match shown {
            Shown::Item => &self.item_menu,
            Shown::Send => &self.send_menu,
            Shown::Secret => &self.secret_menu,
        }));
    }

    /// The selected secret's details: its value once fetched.
    fn show_secret_detail(&self, ui: &Rc<Ui>) {
        self.header_for(Shown::Secret);
        let Some((secrets, row)) = self.selected_secret() else {
            self.forget_opened_secret();
            self.detail_scroller.set_child(None::<&gtk::Widget>);
            self.detail_stack.set_visible_child_name("empty");
            self.detail_page.set_title("Details");
            self.inner.set_show_content(false);
            self.update_item_actions(ui);
            return;
        };
        // A value fetched before the secret changed is fetched again.
        let opened = self
            .opened_secret
            .borrow()
            .clone()
            .filter(|o| o.id == row.id && o.revised == row.revised);
        let failed = self
            .secret_failed
            .borrow()
            .as_ref()
            .filter(|(id, _)| *id == row.id)
            .map(|(_, why)| why.clone());
        let widget = if let Some(opened) = opened {
            super::secret::detail(ui, &secrets, &opened)
        } else if row.deleted {
            self.forget_opened_secret();
            super::secret::placeholder(
                &row,
                Some("It's in the trash. Restore it to see its value."),
            )
        } else if let Some(why) = failed {
            super::secret::placeholder(&row, Some(&why))
        } else {
            if self.fetching_secret.borrow().as_deref() != Some(row.id.as_str()) {
                self.opened_secret.replace(None);
                self.fetching_secret.replace(Some(row.id.clone()));
                ui.fetch_secret(&row.id, &row.org_id);
            }
            super::secret::placeholder(&row, None)
        };
        self.detail_scroller.set_child(Some(&widget));
        self.detail_stack.set_visible_child_name("item");
        self.detail_page.set_title(&row.name);
        self.detail_title.set_title("Secret");
        self.update_item_actions(ui);
    }

    pub fn show_detail(&self, ui: &Rc<Ui>) {
        if self.editing() {
            // A sync while editing leaves the form alone; the save finds
            // out if the item changed meanwhile.
            self.update_item_actions(ui);
            return;
        }
        if self.filter.borrow().is_secrets() {
            return self.show_secret_detail(ui);
        }
        self.forget_opened_secret();
        let send = self.selected_send();
        self.header_for(if *self.filter.borrow() == Filter::Sends {
            Shown::Send
        } else {
            Shown::Item
        });
        if let Some((vault, id)) = send {
            let send = vault.send(&id).expect("checked");
            let widget = super::send::detail(ui, send);
            self.detail_scroller.set_child(Some(&widget));
            self.detail_stack.set_visible_child_name("item");
            self.detail_page.set_title(&send.name);
            self.detail_title.set_title("Send");
            self.update_item_actions(ui);
            return;
        }
        match self.selected_item() {
            Some((vault, id)) => {
                let item = vault.item(&id).expect("checked");
                let widget = detail::build(ui, &vault, item);
                self.detail_scroller.set_child(Some(&widget));
                self.detail_stack.set_visible_child_name("item");
                self.detail_page.set_title(&item.name);
                self.detail_title.set_title("Details");
            }
            None => {
                self.detail_scroller.set_child(None::<&gtk::Widget>);
                self.detail_stack.set_visible_child_name("empty");
                self.detail_page.set_title("Details");
                self.inner.set_show_content(false);
            }
        }
        self.update_item_actions(ui);
    }

    pub fn update_item_actions(&self, ui: &Ui) {
        let editing = self.editing();
        let selected = if editing { None } else { self.selected_item() };
        let item = selected.as_ref().and_then(|(vault, id)| vault.item(id));
        let live = item.filter(|i| !i.deleted);
        let trashed = item.filter(|i| i.deleted);
        let selected_send = if editing { None } else { self.selected_send() };
        let send = selected_send
            .as_ref()
            .and_then(|(vault, id)| vault.send(id));
        let secret = if editing {
            None
        } else {
            self.selected_secret().map(|(_, row)| row)
        };
        let opened_secret = if editing {
            None
        } else {
            self.opened_selected_secret()
        };
        let secrets_on = self
            .vault
            .borrow()
            .as_ref()
            .is_some_and(|v| !v.sm_orgs.is_empty());
        ui.set_action_enabled(
            "edit-item",
            live.is_some_and(|i| i.edit && !i.damaged)
                || send.is_some_and(|s| !s.damaged)
                || opened_secret.as_ref().is_some_and(|o| o.write),
        );
        ui.set_action_enabled("new-secret", secrets_on && !editing);
        ui.set_action_enabled("new-project", secrets_on && !editing);
        let project = self.current_project().filter(|p| p.write && !editing);
        ui.set_action_enabled("rename-project", project.is_some());
        ui.set_action_enabled("delete-project", project.is_some());
        ui.set_action_enabled(
            "delete-secret",
            secret.as_ref().is_some_and(|s| !s.deleted && s.write),
        );
        ui.set_action_enabled("restore-secret", secret.as_ref().is_some_and(|s| s.deleted));
        ui.set_action_enabled("purge-secret", secret.as_ref().is_some_and(|s| s.deleted));
        ui.set_action_enabled("copy-send-link", send.is_some_and(|s| s.seed.is_some()));
        ui.set_action_enabled("remove-send-password", send.is_some_and(|s| s.has_password));
        ui.set_action_enabled("delete-send", send.is_some());
        ui.set_action_enabled("new-send", !editing);
        ui.set_action_enabled("clone-item", live.is_some_and(|i| !i.damaged));
        ui.set_action_enabled("add-attachment", live.is_some_and(|i| i.edit && !i.damaged));
        ui.set_action_enabled("favorite", live.is_some());
        if let Some(action) = ui
            .window
            .lookup_action("favorite")
            .and_downcast::<gio::SimpleAction>()
        {
            action.set_state(&live.is_some_and(|i| i.favorite).to_variant());
        }
        ui.set_action_enabled("trash-item", live.is_some_and(|i| i.edit));
        ui.set_action_enabled("restore-item", trashed.is_some_and(|i| i.edit));
        ui.set_action_enabled("purge-item", trashed.is_some_and(|i| i.edit));
        ui.set_action_enabled("new-item", !editing);
        ui.set_action_enabled("new-folder", !editing);
        let in_folder = matches!(&*self.filter.borrow(), Filter::Folder(Some(_)));
        ui.set_action_enabled("rename-folder", in_folder && !editing);
        ui.set_action_enabled("delete-folder", in_folder && !editing);
        ui.set_action_enabled("save-item", editing);
        ui.set_action_enabled("cancel-edit", editing);
        let login = item.and_then(|i| i.login.as_ref());
        ui.set_action_enabled(
            "copy-username",
            login.is_some_and(|l| l.username.as_deref().is_some_and(|u| !u.is_empty())),
        );
        ui.set_action_enabled(
            "copy-password",
            login.is_some_and(|l| l.password.as_ref().is_some_and(|p| !p.is_empty()))
                || opened_secret.is_some(),
        );
        ui.set_action_enabled(
            "copy-totp",
            login.is_some_and(|l| {
                l.totp
                    .as_deref()
                    .is_some_and(|t| crate::totp::Totp::parse(t).is_some())
            }),
        );
        ui.set_action_enabled(
            "open-website",
            login.is_some_and(|l| l.uris.iter().any(|u| u.launch_url().is_some())),
        );
    }

    /// The selected item's id, if it's still in the vault.
    pub fn selected_id(&self) -> Option<String> {
        self.selected_item().map(|(_, id)| id)
    }

    pub fn current_vault(&self) -> Option<Rc<Vault>> {
        self.vault.borrow().clone()
    }

    pub fn current_filter(&self) -> Filter {
        self.filter.borrow().clone()
    }

    pub fn editor(&self) -> Option<Rc<Editor>> {
        self.editor.borrow().clone()
    }

    pub fn send_editor(&self) -> Option<Rc<SendEditor>> {
        self.send_editor.borrow().clone()
    }

    pub fn secret_editor(&self) -> Option<Rc<SecretEditor>> {
        self.secret_editor.borrow().clone()
    }

    /// Whether an item, a Send or a secret is being edited.
    pub fn editing(&self) -> bool {
        self.editor.borrow().is_some()
            || self.send_editor.borrow().is_some()
            || self.secret_editor.borrow().is_some()
    }

    /// Show `editor` in place of the details. The lists wait until it's
    /// saved or cancelled.
    pub fn show_editor(&self, ui: &Rc<Ui>, editor: Rc<Editor>) {
        self.show_form(&editor.root, &editor.title);
        self.editor.replace(Some(editor.clone()));
        self.update_item_actions(ui);
        editor.focus();
    }

    pub fn show_send_editor(&self, ui: &Rc<Ui>, editor: Rc<SendEditor>) {
        self.show_form(&editor.root, &editor.title);
        self.send_editor.replace(Some(editor.clone()));
        self.update_item_actions(ui);
        editor.focus();
    }

    pub fn show_secret_editor(&self, ui: &Rc<Ui>, editor: Rc<SecretEditor>) {
        self.show_form(&editor.root, &editor.title);
        self.secret_editor.replace(Some(editor.clone()));
        self.update_item_actions(ui);
        editor.focus();
    }

    fn show_form(&self, root: &gtk::Widget, title: &str) {
        self.detail_scroller.set_child(Some(root));
        self.detail_stack.set_visible_child_name("item");
        self.detail_title.set_title(title);
        self.detail_page.set_title(title);
        self.detail_page.set_can_pop(false);
        self.set_editing(true);
        self.inner.set_show_content(true);
    }

    fn set_editing(&self, editing: bool) {
        for widget in &self.view_buttons {
            widget.set_visible(!editing);
        }
        self.edit_cancel.set_visible(editing);
        self.edit_save.set_visible(editing);
        self.edit_save.set_sensitive(true);
        for widget in [
            self.sidebar_list.upcast_ref::<gtk::Widget>(),
            self.item_list.upcast_ref(),
            self.search.upcast_ref(),
            self.new_button.upcast_ref(),
            self.folder_menu.upcast_ref(),
            self.project_menu.upcast_ref(),
            self.sync_button.upcast_ref(),
        ] {
            widget.set_sensitive(!editing);
        }
    }

    /// While a save is on its way.
    pub fn set_saving(&self, saving: bool) {
        self.edit_save.set_sensitive(!saving);
        self.edit_cancel.set_sensitive(!saving);
    }

    fn close_editor(&self) {
        let item = self.editor.take().is_some();
        let send = self.send_editor.take().is_some();
        let secret = self.secret_editor.take().is_some();
        if item || send || secret {
            self.detail_scroller.set_child(None::<&gtk::Widget>);
            self.detail_page.set_can_pop(true);
            self.detail_title.set_title("Details");
            self.set_editing(false);
            self.edit_cancel.set_sensitive(true);
        }
    }

    /// Back to the details, the form dropped.
    pub fn end_edit(&self, ui: &Rc<Ui>) {
        self.close_editor();
        self.show_detail(ui);
    }

    /// Select an item (or none) once the vault shows it, switching to All
    /// Items (or the Trash) if the current view doesn't hold it.
    pub fn select(&self, vault: &Vault, id: Option<String>) {
        if id.as_deref().is_some_and(|id| vault.send(id).is_some()) {
            self.filter.replace(Filter::Sends);
        }
        if let Some(id) = &id {
            if let Some(item) = vault.item(id) {
                if !self.filter.borrow().accepts(item) {
                    self.filter.replace(if item.deleted {
                        Filter::Trash
                    } else {
                        Filter::All
                    });
                }
            }
        }
        self.selected.replace(id);
    }

    /// Select a secret (or none) once the lists show it, switching to its
    /// organization's secrets (or deleted secrets) if the current view
    /// doesn't hold it.
    pub fn select_secret(&self, secrets: &Secrets, id: Option<String>) {
        if let Some(secret) = id.as_deref().and_then(|id| secrets.secret(id)) {
            if !self.filter.borrow().accepts_secret(secret) {
                self.filter.replace(if secret.deleted {
                    Filter::SecretsTrash(secret.org_id.clone())
                } else {
                    Filter::Secrets {
                        org: secret.org_id.clone(),
                        project: None,
                    }
                });
            }
        }
        self.selected.replace(id);
    }

    /// Show a project's secrets.
    pub fn show_project(&self, org: &str, project: Option<String>) {
        self.filter.replace(Filter::Secrets {
            org: org.to_string(),
            project,
        });
    }

    pub fn copy_field(&self, ui: &Rc<Ui>, what: Quick) {
        if let (Quick::Password, Some(opened)) = (what, self.opened_selected_secret()) {
            ui.copy("Value", &opened.value, true);
            return;
        }
        let Some((vault, id)) = self.selected_item() else {
            return;
        };
        let item = vault.item(&id).expect("checked");
        let Some(login) = item.login.clone() else {
            return;
        };
        match what {
            Quick::Username => {
                if let Some(username) = &login.username {
                    ui.copy("Username", username, false);
                }
            }
            Quick::Website => {
                if let Some(url) = login.uris.iter().find_map(|u| u.launch_url()) {
                    detail::open_url(ui, &url);
                }
            }
            Quick::Password | Quick::Totp => {
                let run = {
                    let ui = Rc::downgrade(ui);
                    move || {
                        let Some(ui) = ui.upgrade() else { return };
                        match what {
                            Quick::Password => {
                                if let Some(password) = &login.password {
                                    ui.copy("Password", password, true);
                                }
                            }
                            _ => {
                                if let Some(totp) = login
                                    .totp
                                    .as_deref()
                                    .and_then(|t| crate::totp::Totp::parse(t))
                                {
                                    ui.copy("Verification code", &totp.now().0, true);
                                }
                            }
                        }
                    }
                };
                if item.reprompt {
                    ui.reprompt(&id, run);
                } else {
                    run();
                }
            }
        }
    }
}

/// The tile an item's icon sits on: the type's glyph, replaced by the
/// website's icon once it arrives.
pub fn item_icon(item: &Item, server: &str, show_icons: bool, size: i32) -> gtk::CenterBox {
    let image = gtk::Image::builder()
        .icon_name(item.kind.icon())
        .pixel_size(size * 5 / 8)
        .halign(gtk::Align::Center)
        .valign(gtk::Align::Center)
        .build();
    // A fixed square: the image centred in it, never stretching it.
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
    tile.set_center_widget(Some(&image));
    if let (true, Some(host)) = (show_icons && !server.is_empty(), item.icon_host()) {
        let weak_tile = tile.downgrade();
        let weak_image = image.downgrade();
        crate::icons::get(server, &host, move |texture| {
            let (Some(texture), Some(tile), Some(image)) =
                (texture, weak_tile.upgrade(), weak_image.upgrade())
            else {
                return;
            };
            image.set_paintable(Some(&texture));
            tile.remove_css_class("glyph");
            tile.add_css_class("favicon");
        });
    }
    tile
}

fn item_row(item: &Item, server: &str, show_icons: bool) -> gtk::ListBoxRow {
    let line = gtk::Box::builder()
        .spacing(12)
        .css_classes(["item-row"])
        .build();
    line.append(&item_icon(item, server, show_icons, 32));
    let text = gtk::Box::builder()
        .orientation(gtk::Orientation::Vertical)
        .spacing(2)
        .hexpand(true)
        .valign(gtk::Align::Center)
        .build();
    text.append(
        &gtk::Label::builder()
            .label(&item.name)
            .xalign(0.0)
            .ellipsize(gtk::pango::EllipsizeMode::End)
            .css_classes(["item-name"])
            .build(),
    );
    if let Some(sub) = item.subtitle().filter(|s| !s.is_empty()) {
        text.append(
            &gtk::Label::builder()
                .label(&sub)
                .xalign(0.0)
                .ellipsize(gtk::pango::EllipsizeMode::End)
                .css_classes(["item-subtitle", "dim-label"])
                .build(),
        );
    }
    line.append(&text);
    if item.org_id.is_some() {
        line.append(
            &gtk::Image::builder()
                .icon_name("system-users-symbolic")
                .tooltip_text("Shared with an organization")
                .css_classes(["dim-label"])
                .build(),
        );
    }
    if item.favorite {
        line.append(
            &gtk::Image::builder()
                .icon_name("starred-symbolic")
                .tooltip_text("Favorite")
                .css_classes(["favorite-star"])
                .build(),
        );
    }
    if item.damaged {
        line.append(
            &gtk::Image::builder()
                .icon_name("dialog-warning-symbolic")
                .tooltip_text("Part of this item could not be decrypted")
                .css_classes(["damaged-banner"])
                .build(),
        );
    }
    gtk::ListBoxRow::builder().child(&line).build()
}
