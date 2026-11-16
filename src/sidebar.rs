//! See-through sidebars.
//!
//! `--vord-sidebar-opacity`, a number from 0 to 1, fades the background of
//! the vault sidebar and the item list, but never their text. It defaults to 1
//! here, and an Omarchy theme's `vord.css` (see `omarchy::palette`) can lower
//! it with a one-line `:root { --vord-sidebar-opacity: 0.8; }`.
//!
//! A faded sidebar over the window's own background would only blend into
//! that colour, so below 1 the main window gets the `vord-transparent` class,
//! which clears the window background so the desktop shows through. Everything
//! else that was painted by that background is painted again here, so only the
//! sidebars turn translucent. GTK has no API to read a custom property back,
//! so the opacity that decides the class is worked out from the CSS text by
//! [`opacity_in`] whenever the theme reloads. (After Rustle and Bubo.)
use adw::prelude::*;
use gtk::gio;
use std::cell::Cell;

/// The custom property a theme sets.
pub const OPACITY: &str = "--vord-sidebar-opacity";

/// Below the Omarchy provider (`APPLICATION + 2`), so a theme's value wins
/// over the default of 1.
///
/// The vault sidebar is an overlay split view (`.vault-split`); floating over
/// the list in a narrow window (`.collapsed`, set in `ui::vault`) it stays
/// opaque. The item list is the sidebar of a nested navigation split view
/// (`.item-split`), which libadwaita paints in the secondary sidebar colour;
/// collapsed to one column it has no panes and its pages stay opaque.
const CSS: &str = "
:root { --vord-sidebar-opacity: 1; }
overlay-split-view.vault-split:not(.collapsed) > .sidebar-pane {
    background-color: alpha(var(--sidebar-bg-color), var(--vord-sidebar-opacity));
}
overlay-split-view.vault-split:not(.collapsed) > .sidebar-pane:backdrop {
    background-color: alpha(var(--sidebar-backdrop-color), var(--vord-sidebar-opacity));
}
navigation-split-view.item-split > .sidebar-pane {
    background-color: alpha(var(--secondary-sidebar-bg-color), var(--vord-sidebar-opacity));
}
navigation-split-view.item-split > .sidebar-pane:backdrop {
    background-color: alpha(var(--secondary-sidebar-backdrop-color), var(--vord-sidebar-opacity));
}
window.vord-transparent { background-color: transparent; }
/* What was drawn on the window background just cleared: the item details,
   both pages of a collapsed item split, and the sign-in and unlock pages.
   Dialogs, popovers and toasts paint their own backgrounds. */
window.vord-transparent .vord-surface,
window.vord-transparent navigation-split-view.item-split > .content-pane,
window.vord-transparent navigation-split-view.item-split > navigation-view > navigation-view-page {
    background-color: var(--window-bg-color);
    color: var(--window-fg-color);
}
";

const TRANSPARENT: &str = "vord-transparent";

thread_local! {
    /// The opacity the cascade currently resolves to.
    static CURRENT: Cell<f32> = const { Cell::new(1.0) };
}

/// Install once during application startup, before the Omarchy theme.
pub fn install(display: &gtk::gdk::Display) {
    let provider = gtk::CssProvider::new();
    provider.load_from_string(CSS);
    gtk::style_context_add_provider_for_display(
        display,
        &provider,
        gtk::STYLE_PROVIDER_PRIORITY_APPLICATION,
    );
}

/// Record the opacity now in force and bring the main window in line.
pub fn set_opacity(opacity: f32) {
    CURRENT.with(|current| current.set(opacity));
    let Some(app) = gio::Application::default().and_downcast::<gtk::Application>() else {
        return;
    };
    // Only the main window: the picture viewer is an application window too,
    // and keeps its own black background.
    for window in app.windows() {
        if let Some(window) = window.downcast_ref::<adw::ApplicationWindow>() {
            sync(window);
        }
    }
}

/// Clear `window`'s background while the sidebar is translucent, and restore
/// it once it isn't.
pub fn sync(window: &adw::ApplicationWindow) {
    if CURRENT.with(Cell::get) < 1.0 {
        window.add_css_class(TRANSPARENT);
    } else {
        window.remove_css_class(TRANSPARENT);
    }
}

/// The last value [`OPACITY`] is given anywhere in `css`, clamped to 0..=1.
/// Comments are skipped; selectors are not checked, since the built-in rule
/// reads the property wherever the cascade puts it. A custom property takes
/// any value, so the last declaration wins even when it isn't a plain number,
/// and then nothing is known about the opacity. That includes a percentage:
/// GTK's `alpha()` only takes a number, and drops the sidebar's background
/// altogether when given one.
pub fn opacity_in(css: &str) -> Option<f32> {
    let mut found = None;
    let mut at = 0;
    while let Some(offset) = css[at..].find(['/', '-']) {
        let start = at + offset;
        let tail = &css[start..];
        if let Some(comment) = tail.strip_prefix("/*") {
            let Some(end) = comment.find("*/") else { break };
            at = start + 2 + end + 2;
            continue;
        }
        // `--x--vord-sidebar-opacity` is a different property.
        let inside_a_name = css[..start]
            .chars()
            .next_back()
            .is_some_and(|ch| ch.is_alphanumeric() || matches!(ch, '-' | '_'));
        let value = tail
            .strip_prefix(OPACITY)
            .filter(|_| !inside_a_name)
            // So is `--vord-sidebar-opacity-x`, and `var(--vord-sidebar-opacity)`
            // reads it rather than setting it.
            .and_then(|rest| rest.trim_start().strip_prefix(':'));
        let Some(value) = value else {
            at = start + 1;
            continue;
        };
        let end = value.find([';', '}', '\n']).unwrap_or(value.len());
        let text = value[..end].trim();
        found = text
            .parse::<f32>()
            .ok()
            .filter(|o| o.is_finite())
            .map(|o| o.clamp(0.0, 1.0));
        at = css.len() - value.len() + end;
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_last_value_in_any_rule_wins() {
        let css = "/* --vord-sidebar-opacity: 0.1; */\n\
                   :root {\n  --vord-sidebar-opacity: 0.8;\n}\n\
                   window { --vord-sidebar-opacity:0.6 }\n";
        assert_eq!(opacity_in(css), Some(0.6));
        assert_eq!(
            opacity_in(":root { --vord-sidebar-opacity: 1; }"),
            Some(1.0)
        );
    }

    #[test]
    fn values_are_clamped() {
        assert_eq!(
            opacity_in(":root { --vord-sidebar-opacity: 2; }"),
            Some(1.0)
        );
        assert_eq!(
            opacity_in(":root { --vord-sidebar-opacity: -0.5; }"),
            Some(0.0)
        );
    }

    /// Anything GTK would not read as this property's value leaves it unset.
    #[test]
    fn garbage_and_look_alikes_are_ignored() {
        for css in [
            "",
            ":root { --vord-sidebar-opacity: lots; }",
            ":root { --vord-sidebar-opacity: NaN; }",
            // GTK's alpha() rejects a percentage.
            ":root { --vord-sidebar-opacity: 75%; }",
            ":root { --vord-sidebar-opacity-x: 0.5; }",
            ":root { --x--vord-sidebar-opacity: 0.5; }",
            ".sidebar-pane { opacity: var(--vord-sidebar-opacity); }",
            "/* --vord-sidebar-opacity: 0.5",
        ] {
            assert_eq!(opacity_in(css), None, "{css}");
        }
        // A later declaration replaces an earlier one, usable or not.
        assert_eq!(
            opacity_in(
                ":root { --vord-sidebar-opacity: 0.5; }\n\
                 :root { --vord-sidebar-opacity: lots; }"
            ),
            None
        );
    }

    /// The default the built-in stylesheet states is the one assumed when a
    /// theme states none.
    #[test]
    fn the_built_in_default_is_opaque() {
        assert_eq!(opacity_in(CSS), Some(1.0));
    }

    /// The stylesheet parses, and the split views name their panes the way
    /// it assumes.
    #[test]
    #[ignore = "requires a GTK display; run explicitly with --ignored"]
    fn the_stylesheet_matches_the_split_views() {
        adw::init().unwrap();
        let provider = gtk::CssProvider::new();
        let errors = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
        let errors_clone = errors.clone();
        provider.connect_parsing_error(move |_, _, error| {
            errors_clone.borrow_mut().push(error.to_string());
        });
        provider.load_from_string(CSS);
        assert!(
            errors.borrow().is_empty(),
            "CSS errors: {:?}",
            errors.borrow()
        );

        let list = adw::NavigationPage::builder().title("Items").build();
        let details = adw::NavigationPage::builder().title("Details").build();
        let inner = adw::NavigationSplitView::builder()
            .sidebar(&list)
            .content(&details)
            .build();
        assert_eq!(inner.css_name(), "navigation-split-view");
        let pane = |page: &adw::NavigationPage, class: &str| {
            let pane = page.parent().unwrap();
            assert!(pane.has_css_class(class), "{:?}", pane.css_classes());
        };
        pane(&list, "sidebar-pane");
        pane(&details, "content-pane");
        inner.set_collapsed(true);
        assert_eq!(list.parent().unwrap().css_name(), "navigation-view");

        let vault = gtk::Box::new(gtk::Orientation::Vertical, 0);
        let outer = adw::OverlaySplitView::builder()
            .sidebar(&vault)
            .content(&inner)
            .build();
        assert_eq!(outer.css_name(), "overlay-split-view");
        assert!(vault.parent().unwrap().has_css_class("sidebar-pane"));
    }
}
