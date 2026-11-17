//! Preferences, as JSON in `~/.config/vord/settings.json`.

use serde::{Deserialize, Serialize};
use std::cell::RefCell;
use std::path::PathBuf;
use std::rc::Rc;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    pub follow_omarchy_theme: bool,
    /// Fetch website icons from the server's icon service.
    pub show_icons: bool,
    /// Lock after the window has been in the background this long; 0 never.
    pub lock_after_minutes: u32,
    /// Lock when the session locks (the lock screen) or the machine sleeps.
    pub lock_with_screen: bool,
    /// Empty the clipboard this long after copying a secret; 0 never.
    pub clear_clipboard_seconds: u32,
    /// What the login page fills in next time.
    pub last_server: String,
    pub last_email: String,
    /// The generator's options (never what it made).
    pub generator: crate::generator::Options,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            follow_omarchy_theme: true,
            show_icons: true,
            lock_after_minutes: 15,
            lock_with_screen: true,
            clear_clipboard_seconds: 30,
            last_server: String::new(),
            last_email: String::new(),
            generator: crate::generator::Options::default(),
        }
    }
}

pub fn path() -> PathBuf {
    directories::ProjectDirs::from("io.github", "turbinebmw", "vord")
        .map(|dirs| dirs.config_dir().join("settings.json"))
        .unwrap_or_else(|| PathBuf::from(".vord-settings.json"))
}

thread_local! {
    static SHARED: Rc<RefCell<Settings>> = Rc::new(RefCell::new(Settings::load()));
}

/// The UI's one copy. GTK thread only.
pub fn shared() -> Rc<RefCell<Settings>> {
    SHARED.with(Rc::clone)
}

/// Read the current settings.
pub fn get() -> Settings {
    shared().borrow().clone()
}

/// Change the settings and save them.
pub fn update(change: impl FnOnce(&mut Settings)) {
    let shared = shared();
    let mut settings = shared.borrow_mut();
    change(&mut settings);
    settings.save();
}

impl Settings {
    pub fn load() -> Self {
        std::fs::read(path())
            .ok()
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
            .unwrap_or_default()
    }

    pub fn save(&self) {
        let path = path();
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let bytes = serde_json::to_vec_pretty(self).expect("serialisable");
        if let Err(error) = std::fs::write(&path, bytes) {
            log::warn!("could not save settings to {}: {error}", path.display());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_keys_take_defaults() {
        let settings: Settings = serde_json::from_str(r#"{"show_icons":false}"#).unwrap();
        assert!(!settings.show_icons);
        assert!(settings.follow_omarchy_theme);
        assert_eq!(settings.lock_after_minutes, 15);
        assert_eq!(settings.clear_clipboard_seconds, 30);
    }
}
