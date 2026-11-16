mod accent;
mod api;
mod clipboard;
mod crypto;
mod icons;
mod omarchy;
mod screenlock;
mod session;
mod settings;
mod sidebar;
mod store;
mod totp;
mod ui;
mod vault;

use adw::prelude::*;
use std::io::BufRead;

pub const APP_ID: &str = "io.github.turbinebmw.Vord";

fn main() -> anyhow::Result<()> {
    env_logger::Builder::from_env(env_logger::Env::new().filter_or("VORD_LOG", "vord=info")).init();
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("login") => cli_login(&args[2..]),
        Some("list") => cli_list(),
        Some("--help" | "-h" | "help") => {
            println!("Vord {}: a Bitwarden / Vaultwarden vault for the desktop.\n\n  vord                     open the app\n  vord login SERVER EMAIL  log in (master password on stdin)\n  vord list                unlock, sync and list items (master password on stdin)", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        _ => {
            run_app();
            Ok(())
        }
    }
}

/// Whether the window holds an unlocked vault (for the lock-screen watch).
pub fn ui_unlocked() -> bool {
    ui::UNLOCKED.with(std::cell::Cell::get)
}

fn run_app() {
    // One instance: a second launch raises the running window.
    let app = adw::Application::builder().application_id(APP_ID).build();
    app.connect_startup(|app| {
        gtk::Window::set_default_icon_name(APP_ID);
        if let Some(display) = gtk::gdk::Display::default() {
            let provider = gtk::CssProvider::new();
            provider.load_from_string(include_str!("style.css"));
            gtk::style_context_add_provider_for_display(
                &display,
                &provider,
                gtk::STYLE_PROVIDER_PRIORITY_APPLICATION,
            );
            accent::install_fallback(&display);
            sidebar::install(&display);
            omarchy::install(&display);
            // Running from a checkout: find the icons in data/.
            #[cfg(debug_assertions)]
            let theme = gtk::IconTheme::for_display(&display);
            #[cfg(debug_assertions)]
            let dev_icons = concat!(env!("CARGO_MANIFEST_DIR"), "/data/icons");
            #[cfg(debug_assertions)]
            if std::path::Path::new(dev_icons).is_dir() {
                theme.add_search_path(dev_icons);
            }
        }
        let quit = gtk::gio::SimpleAction::new("quit", None);
        let weak = app.downgrade();
        quit.connect_activate(move |_, _| {
            if let Some(app) = weak.upgrade() {
                app.quit();
            }
        });
        app.add_action(&quit);
        app.set_accels_for_action("app.quit", &["<Control>q"]);
        app.set_accels_for_action("window.close", &["<Control>w"]);
    });
    let window: std::rc::Rc<std::cell::RefCell<Option<std::rc::Rc<ui::Ui>>>> = Default::default();
    app.connect_activate(move |app| {
        if let Some(existing) = app.active_window() {
            existing.present();
            return;
        }
        window.replace(Some(ui::build(app)));
    });
    app.run_with_args::<&str>(&[]);
}

/// The master password, from the first line of stdin.
fn read_password() -> anyhow::Result<String> {
    eprint!("Master password: ");
    let mut line = String::new();
    std::io::stdin().lock().read_line(&mut line)?;
    Ok(line.trim_end_matches(['\r', '\n']).to_string())
}

/// `vord login SERVER EMAIL`, master password on stdin.
fn cli_login(args: &[String]) -> anyhow::Result<()> {
    let [server, email] = args else {
        anyhow::bail!("usage: vord login SERVER EMAIL  (master password on stdin)");
    };
    let server = api::normalize_server(server).map_err(anyhow::Error::msg)?;
    let password = read_password()?;
    let (account, _) =
        session::login(&server, email, &password).map_err(|e| anyhow::anyhow!("{e}"))?;
    println!("logged in as {} on {}", account.email, account.server);
    Ok(())
}

/// `vord list`: unlock, sync, and print every item's name and type.
fn cli_list() -> anyhow::Result<()> {
    let account = store::Account::load().ok_or_else(|| anyhow::anyhow!("not logged in"))?;
    let password = read_password()?;
    let user_key = session::unlock_key(&account, &password).map_err(|e| anyhow::anyhow!("{e}"))?;
    let (account, sync) = session::sync(account).map_err(|e| anyhow::anyhow!("{e}"))?;
    let unlocked = session::open_sync(&account, user_key, &sync);
    let vault = &unlocked.vault;
    for item in &vault.items {
        let folder = item
            .folder_id
            .as_deref()
            .and_then(|id| vault.folders.iter().find(|f| f.id == id))
            .map_or("", |f| f.name.as_str());
        println!(
            "{:<12} {:<32} {:<28} {}{}{}",
            item.kind.label(),
            item.name,
            item.subtitle().unwrap_or_default(),
            folder,
            if item.favorite { " ★" } else { "" },
            if item.deleted { " (trash)" } else { "" },
        );
    }
    println!(
        "{} items, {} folders, {} collections, {} organizations, {} unreadable",
        vault.items.len(),
        vault.folders.len(),
        vault.collections.len(),
        vault.organizations.len(),
        vault.damaged
    );
    Ok(())
}
