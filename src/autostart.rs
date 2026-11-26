//! "Start at login": an XDG autostart entry that runs `vord --hidden`, so
//! Vord (and its SSH agent) is there from the start of the session without
//! a window. Hyprland and other compositors have no Background portal to ask,
//! and every desktop that runs autostart entries starts this once.

use std::path::{Path, PathBuf};

/// Where the desktop looks for it; uninstall.sh removes it by the same name.
pub fn entry_path() -> PathBuf {
    gtk::glib::user_config_dir()
        .join("autostart")
        .join(format!("{}.desktop", crate::APP_ID))
}

/// Write or remove the entry.
pub fn set(wanted: bool) -> std::io::Result<()> {
    let path = entry_path();
    if !wanted {
        return match std::fs::remove_file(&path) {
            Err(error) if error.kind() != std::io::ErrorKind::NotFound => Err(error),
            _ => Ok(()),
        };
    }
    let exe = std::env::current_exe()?;
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    std::fs::write(&path, entry(&exe))
}

/// The entry for `exe`, quoted as the Desktop Entry spec asks when the path
/// has a character the Exec line would otherwise split or expand on.
fn entry(exe: &Path) -> String {
    let exe = exe.to_string_lossy();
    let plain = exe
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || "/._-+".contains(c));
    let exec = if plain {
        exe.into_owned()
    } else {
        let mut quoted = String::from('"');
        for c in exe.chars() {
            if matches!(c, '"' | '`' | '$' | '\\') {
                // Escaped once for the Exec quoting, then once more as a
                // desktop-file string value.
                quoted.push_str("\\\\");
            }
            quoted.push(c);
        }
        quoted.push('"');
        quoted
    };
    format!(
        "[Desktop Entry]\nType=Application\nName=Vord\nIcon={id}\n\
         Exec={exec} --hidden\nNoDisplay=true\nX-GNOME-Autostart-enabled=true\n",
        id = crate::APP_ID
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entry_quotes_only_what_needs_it() {
        let plain = entry(Path::new("/home/ada/.local/bin/vord"));
        assert!(plain.contains("\nExec=/home/ada/.local/bin/vord --hidden\n"));
        let spaced = entry(Path::new("/opt/my apps/vord"));
        assert!(spaced.contains("\nExec=\"/opt/my apps/vord\" --hidden\n"));
        let dollar = entry(Path::new("/opt/$x/vord"));
        assert!(dollar.contains("\nExec=\"/opt/\\\\$x/vord\" --hidden\n"));
    }
}
