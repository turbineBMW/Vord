mod accent;
mod agent;
mod api;
mod askpass;
mod autostart;
mod clipboard;
mod crypto;
mod edit;
mod export;
mod generator;
mod icons;
mod live;
mod omarchy;
mod screenlock;
mod secrets;
mod send;
mod session;
mod settings;
mod sidebar;
mod store;
mod totp;
mod tray;
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
        Some("generate") => cli_generate(&args[2..]),
        Some("export") => cli_export(&args[2..]),
        Some("accounts") => cli_accounts(&args[2..]),
        Some("--hidden") => {
            run_app(true);
            Ok(())
        }
        Some("--help" | "-h" | "help") => {
            println!("Vord {}: a Bitwarden / Vaultwarden vault for the desktop.\n\n  vord                     open the app\n  vord --hidden            start without a window (Start at login uses this)\n  vord login SERVER EMAIL [--method authenticator|email|yubikey] [--remember]\n                           log in (master password, then any code, on stdin)\n  vord list                unlock, sync and list items (master password on stdin)\n  vord generate [password|passphrase|username]\n                           make one with the generator's saved options\n  vord accounts [EMAIL]     list the accounts kept, or switch to one\n  vord export json|csv|encrypted_json|password_json FILE\n                           unlock, sync and export (master password, then any\n                           file password, on stdin)", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        _ => {
            run_app(false);
            Ok(())
        }
    }
}

/// Whether the window holds an unlocked vault (for the lock-screen watch).
pub fn ui_unlocked() -> bool {
    ui::UNLOCKED.with(std::cell::Cell::get)
}

/// `hidden`: build the window without showing it (for Start at login).
/// Only the launch activation stays hidden; a later launch shows it.
fn run_app(hidden: bool) {
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
    let hidden = std::cell::Cell::new(hidden);
    app.connect_activate(move |app| {
        if let Some(existing) = app.active_window() {
            existing.present();
            return;
        }
        window.replace(Some(ui::build(app, !hidden.replace(false))));
    });
    app.run_with_args::<&str>(&[]);
}

/// One line of stdin, after a prompt on stderr.
fn read_line(prompt: &str) -> anyhow::Result<String> {
    eprint!("{prompt}: ");
    let mut line = String::new();
    std::io::stdin().lock().read_line(&mut line)?;
    Ok(line.trim_end_matches(['\r', '\n']).to_string())
}

/// The master password, from the first line of stdin.
fn read_password() -> anyhow::Result<String> {
    read_line("Master password")
}

/// `vord login SERVER EMAIL [--method NAME] [--remember]`: the master
/// password on stdin, then a code if the account wants a second step.
fn cli_login(args: &[String]) -> anyhow::Result<()> {
    const USAGE: &str =
        "usage: vord login SERVER EMAIL [--method authenticator|email|yubikey] [--remember]";
    let mut positional = Vec::new();
    let mut method = None;
    let mut remember = false;
    let mut args = args.iter();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--remember" => remember = true,
            "--method" => {
                let name = args.next().ok_or_else(|| anyhow::anyhow!(USAGE))?;
                method = Some(
                    api::TwoFactorMethod::ALL
                        .into_iter()
                        .find(|m| m.name() == name)
                        .ok_or_else(|| anyhow::anyhow!("unknown method {name}\n{USAGE}"))?,
                );
            }
            _ => positional.push(arg),
        }
    }
    let [server, email] = positional[..] else {
        anyhow::bail!(USAGE);
    };
    let server = api::normalize_server(server).map_err(anyhow::Error::msg)?;
    let password = read_password()?;
    let error = |e: session::Error| anyhow::anyhow!("{e}");
    let account = match session::login(&server, email, &password).map_err(error)? {
        session::Login::Done(account, _) => account,
        session::Login::SecondStep(pending) => {
            let method = method.unwrap_or(pending.methods[0]);
            if !pending.methods.contains(&method) {
                let offered: Vec<_> = pending.methods.iter().map(|m| m.name()).collect();
                anyhow::bail!(
                    "this account has no {} step; it offers {}",
                    method.name(),
                    offered.join(", ")
                );
            }
            if method == api::TwoFactorMethod::Email && !pending.email_sent {
                session::send_email_code(&pending).map_err(error)?;
            }
            let prompt = match method {
                api::TwoFactorMethod::Authenticator => "Code from the authenticator app".into(),
                api::TwoFactorMethod::Email => format!(
                    "Code sent to {}",
                    pending.email_hint.as_deref().unwrap_or("your email")
                ),
                api::TwoFactorMethod::YubiKey => "Touch the YubiKey".into(),
            };
            let code = read_line(&prompt)?;
            session::second_step(&pending, method, &code, remember)
                .map_err(error)?
                .0
        }
    };
    println!("logged in as {} on {}", account.email, account.server);
    Ok(())
}

/// `vord generate [KIND]`: one value, with the options the generator
/// dialog last used.
fn cli_generate(args: &[String]) -> anyhow::Result<()> {
    use generator::Kind;
    let options = settings::Settings::load().generator;
    let kind = match args.first().map(String::as_str) {
        None => options.kind,
        Some("password") => Kind::Password,
        Some("passphrase") => Kind::Passphrase,
        Some("username") => Kind::Username,
        Some(other) => anyhow::bail!(
            "unknown kind {other}\nusage: vord generate [password|passphrase|username]"
        ),
    };
    let value = match kind {
        Kind::Password => generator::password(&options.password),
        Kind::Passphrase => generator::passphrase(&options.passphrase),
        Kind::Username => {
            let email = store::Account::load().map(|a| a.email).unwrap_or_default();
            generator::username(&options.username, &email).map_err(anyhow::Error::msg)?
        }
    };
    println!("{value}");
    Ok(())
}

/// `vord accounts [EMAIL]`: the accounts kept, the one in use marked; with
/// an email, use that one.
fn cli_accounts(args: &[String]) -> anyhow::Result<()> {
    let accounts = store::accounts();
    if let Some(email) = args.first() {
        let found: Vec<_> = accounts
            .iter()
            .filter(|a| a.email.eq_ignore_ascii_case(email.trim()))
            .collect();
        match found[..] {
            [account] => {
                account.set_active();
                println!("using {} on {}", account.email, account.server);
                return Ok(());
            }
            [] => anyhow::bail!("no account {email}"),
            _ => anyhow::bail!("{email} has accounts on several servers"),
        }
    }
    let active = store::Account::load().map(|a| a.id());
    for account in &accounts {
        let mark = if Some(account.id()) == active {
            "*"
        } else {
            " "
        };
        println!("{mark} {:<32} {}", account.email, account.server);
    }
    if accounts.is_empty() {
        println!("no accounts; vord login SERVER EMAIL adds one");
    }
    Ok(())
}

/// `vord export FORMAT FILE`: unlock, sync, and export as the app does.
fn cli_export(args: &[String]) -> anyhow::Result<()> {
    const USAGE: &str = "usage: vord export json|csv|encrypted_json|password_json FILE";
    let [format, path] = args else {
        anyhow::bail!(USAGE);
    };
    let format = match format.as_str() {
        "json" => export::Format::Json,
        "csv" => export::Format::Csv,
        "encrypted_json" => export::Format::AccountJson,
        "password_json" => export::Format::PasswordJson,
        other => anyhow::bail!("unknown format {other}\n{USAGE}"),
    };
    let account = store::Account::load().ok_or_else(|| anyhow::anyhow!("not logged in"))?;
    let password = zeroize::Zeroizing::new(read_password()?);
    let file_password = zeroize::Zeroizing::new(if format == export::Format::PasswordJson {
        let typed = read_line("File password")?;
        if typed.is_empty() {
            anyhow::bail!("the file password can't be empty");
        }
        typed
    } else {
        String::new()
    });
    let user_key = session::unlock_key(&account, &password).map_err(|e| anyhow::anyhow!("{e}"))?;
    let (account, _) = session::sync(account).map_err(|e| anyhow::anyhow!("{e}"))?;
    session::export(
        &account,
        &user_key,
        format,
        &file_password,
        std::path::Path::new(path),
    )
    .map_err(|e| anyhow::anyhow!("{e}"))?;
    eprintln!("exported to {path}");
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
