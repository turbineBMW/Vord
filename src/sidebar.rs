//! See-through sidebars.
//!
//! **Preferences → Appearance → Transparent sidebar** fades the background of
//! the vault sidebar and the item list, never their text, to the opacity of
//! the slider below it. Both are Vord's own settings (`transparent_sidebar`,
//! `sidebar_opacity`), not the Omarchy theme's: the value is stated in a
//! provider above the theme's, so a theme's `vord.css` can no longer change
//! it. Themes used to set `--vord-sidebar-opacity`; [`opacity_in`] still reads
//! that once, so the first launch keeps the look (see `settings`).
//!
//! A faded sidebar over the window's own background would only blend into
//! that colour, so below 1 the main window gets the `vord-transparent` class,
//! which clears the window background so the desktop shows through. Everything
//! else that was painted by that background is painted again here, so only the
//! sidebars turn translucent. (After Rustle and Bubo.)
use adw::prelude::*;
use gtk::gio;
use std::cell::{Cell, RefCell};

/// The custom property the stylesheet reads.
pub const OPACITY: &str = "--vord-sidebar-opacity";

/// The vault sidebar is an overlay split view (`.vault-split`); floating over
/// the list in a narrow window (`.collapsed`, set in `ui::vault`) it stays
/// opaque. The item list is the sidebar of a nested navigation split view
/// (`.item-split`), which libadwaita paints in the secondary sidebar colour;
/// collapsed to one column it has no panes and its pages stay opaque.
const RULES: &str = "
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

/// The whole stylesheet at `opacity`.
fn css(opacity: f32) -> String {
    format!(":root {{ {OPACITY}: {opacity:.2}; }}\n{RULES}")
}

const TRANSPARENT: &str = "vord-transparent";

thread_local! {
    static PROVIDER: RefCell<Option<gtk::CssProvider>> = const { RefCell::new(None) };
    /// The opacity now in force: 1 while the setting is off.
    static CURRENT: Cell<f32> = const { Cell::new(1.0) };
}

/// Install once during application startup. Above the Omarchy provider
/// (`APPLICATION + 2`), so the setting wins over anything a theme states.
pub fn install(display: &gtk::gdk::Display) {
    let provider = gtk::CssProvider::new();
    gtk::style_context_add_provider_for_display(
        display,
        &provider,
        gtk::STYLE_PROVIDER_PRIORITY_APPLICATION + 3,
    );
    PROVIDER.with(|cell| cell.replace(Some(provider)));
    apply();
}

/// The opacity the settings ask for: 1 when the sidebar isn't transparent.
pub fn opacity(transparent: bool, opacity: f32) -> f32 {
    if transparent {
        opacity.clamp(0.0, 1.0)
    } else {
        1.0
    }
}

/// Bring the stylesheet and the main window in line with the settings.
pub fn apply() {
    let settings = crate::settings::get();
    let current = opacity(settings.transparent_sidebar, settings.sidebar_opacity);
    CURRENT.with(|cell| cell.set(current));
    PROVIDER.with(|cell| {
        if let Some(provider) = cell.borrow().as_ref() {
            provider.load_from_string(&css(current));
        }
    });
    let Some(app) = gio::Application::default().and_downcast::<gtk::Application>() else {
        return;
    };
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
    /// The stylesheet states the opacity it was built for, and the setting
    /// only takes effect while the switch is on.
    #[test]
    fn the_stylesheet_states_the_setting() {
        assert_eq!(opacity_in(&css(0.8)), Some(0.8));
        assert_eq!(opacity(true, 0.8), 0.8);
        assert_eq!(opacity(false, 0.3), 1.0);
        assert_eq!(opacity(true, 1.5), 1.0);
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
        provider.load_from_string(&css(0.8));
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
