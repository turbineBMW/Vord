//! Copying, and forgetting what was copied.
//!
//! A secret goes on the clipboard with `x-kde-passwordManagerHint: secret`
//! beside the text, which clipboard histories (cliphist, KDE's Klipper and
//! others) take as "don't keep this". After the configured delay Vord empties
//! the clipboard, but only if what's there is still what it put there.

use gtk::gdk;
use gtk::glib;
use gtk::prelude::*;
use std::cell::{Cell, RefCell};
use std::time::Duration;

thread_local! {
    /// What Vord last put on the clipboard, to recognise it later.
    static OURS: RefCell<Option<gdk::ContentProvider>> = const { RefCell::new(None) };
    static GENERATION: Cell<u64> = const { Cell::new(0) };
}

fn provider(text: &str, secret: bool) -> gdk::ContentProvider {
    let bytes = glib::Bytes::from(text.as_bytes());
    let mut providers = vec![
        gdk::ContentProvider::for_bytes("text/plain;charset=utf-8", &bytes),
        gdk::ContentProvider::for_bytes("text/plain", &bytes),
        gdk::ContentProvider::for_bytes("UTF8_STRING", &bytes),
        gdk::ContentProvider::for_bytes("TEXT", &bytes),
        gdk::ContentProvider::for_bytes("STRING", &bytes),
    ];
    if secret {
        providers.push(gdk::ContentProvider::for_bytes(
            "x-kde-passwordManagerHint",
            &glib::Bytes::from_static(b"secret"),
        ));
    }
    gdk::ContentProvider::new_union(&providers)
}

/// Copy `text`. A secret is cleared after `clear_after` seconds (0: never).
pub fn copy(widget: &impl IsA<gtk::Widget>, text: &str, secret: bool, clear_after: u32) {
    let clipboard = widget.as_ref().clipboard();
    let content = provider(text, secret);
    if let Err(error) = clipboard.set_content(Some(&content)) {
        log::warn!("could not set the clipboard: {error}");
        return;
    }
    OURS.with(|ours| ours.replace(Some(content)));
    let generation = GENERATION.with(|g| {
        g.set(g.get() + 1);
        g.get()
    });
    if secret && clear_after > 0 {
        glib::timeout_add_local_once(Duration::from_secs(clear_after.into()), move || {
            if GENERATION.with(Cell::get) == generation {
                clear(&clipboard);
            }
        });
    }
}

/// Empty the clipboard if it still holds what Vord put there.
pub fn clear(clipboard: &gdk::Clipboard) {
    let ours = OURS.with(|ours| ours.take());
    let Some(ours) = ours else { return };
    if clipboard.is_local() && clipboard.content().as_ref() == Some(&ours) {
        // An empty string rather than no content: a clipboard manager that
        // keeps the last entry alive would otherwise restore the secret.
        let _ = clipboard.set_content(Some(&provider("", false)));
    }
}

/// On lock: forget any secret Vord copied.
pub fn clear_now(widget: &impl IsA<gtk::Widget>) {
    clear(&widget.as_ref().clipboard());
}
