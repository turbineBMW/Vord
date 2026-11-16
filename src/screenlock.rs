//! Noticing that the screen locked or the machine is going to sleep.
//!
//! - logind: the session's `Lock` signal (`loginctl lock-session`, idle
//!   daemons) and the manager's `PrepareForSleep(true)`.
//! - Omarchy locks through its own shell (ext-session-lock), which logind
//!   never hears about. `omarchy-hyprland-session-locked` asks Hyprland
//!   instead; Vord runs it every few seconds, and only while the vault is
//!   unlocked and the window is in the background, which is when a lock
//!   can happen unseen.

use gtk::gio;
use gtk::glib;
use gtk::prelude::*;
use std::rc::Rc;
use std::time::Duration;

const OMARCHY_PROBE: &str = "omarchy-hyprland-session-locked";
const POLL: Duration = Duration::from_secs(4);

pub fn watch(on_lock: impl Fn() + 'static) {
    let on_lock: Rc<dyn Fn()> = Rc::new(on_lock);
    watch_logind(on_lock.clone());
    watch_omarchy(on_lock);
}

fn own_uid() -> Option<u32> {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata("/proc/self").ok().map(|m| m.uid())
}

// `subscribe_to_signal` unsubscribes when its guard drops; these live for
// the whole process, which `signal_subscribe` says more plainly.
#[allow(deprecated)]
fn watch_logind(on_lock: Rc<dyn Fn()>) {
    glib::spawn_future_local(async move {
        let bus = match gio::bus_get_future(gio::BusType::System).await {
            Ok(bus) => bus,
            Err(error) => {
                log::info!("no system bus, so no lock-screen watch: {error}");
                return;
            }
        };
        // Our sessions' object paths, so another user's lock is ignored.
        let uid = own_uid();
        let sessions: Vec<String> = match bus
            .call_future(
                Some("org.freedesktop.login1"),
                "/org/freedesktop/login1",
                "org.freedesktop.login1.Manager",
                "ListSessions",
                None,
                None,
                gio::DBusCallFlags::NONE,
                5000,
            )
            .await
        {
            Ok(reply) => {
                let list = reply.child_value(0);
                (0..list.n_children())
                    .filter_map(|i| {
                        let entry = list.child_value(i);
                        let session_uid = entry.child_value(1).get::<u32>()?;
                        let path = entry.child_value(4).str()?.to_string();
                        (Some(session_uid) == uid).then_some(path)
                    })
                    .collect()
            }
            Err(error) => {
                log::info!("cannot list logind sessions: {error}");
                Vec::new()
            }
        };
        let lock = on_lock.clone();
        bus.signal_subscribe(
            Some("org.freedesktop.login1"),
            Some("org.freedesktop.login1.Session"),
            Some("Lock"),
            None,
            None,
            gio::DBusSignalFlags::NONE,
            move |_, _, path, _, _, _| {
                if sessions.iter().any(|s| s == path) {
                    lock();
                }
            },
        );
        bus.signal_subscribe(
            Some("org.freedesktop.login1"),
            Some("org.freedesktop.login1.Manager"),
            Some("PrepareForSleep"),
            Some("/org/freedesktop/login1"),
            None,
            gio::DBusSignalFlags::NONE,
            move |_, _, _, _, _, params| {
                if params.child_value(0).get::<bool>() == Some(true) {
                    on_lock();
                }
            },
        );
        // The subscriptions live as long as the connection, which is the
        // process's shared system bus.
    });
}

fn watch_omarchy(on_lock: Rc<dyn Fn()>) {
    if glib::find_program_in_path(OMARCHY_PROBE).is_none() {
        return;
    }
    glib::timeout_add_local(POLL, move || {
        let app = gio::Application::default().and_downcast::<gtk::Application>();
        let background = app
            .and_then(|app| app.active_window())
            .is_none_or(|window| !window.is_active());
        if background && crate::ui_unlocked() {
            let on_lock = on_lock.clone();
            glib::spawn_future_local(async move {
                let locked = gio::spawn_blocking(|| {
                    std::process::Command::new(OMARCHY_PROBE)
                        .stdin(std::process::Stdio::null())
                        .stdout(std::process::Stdio::null())
                        .stderr(std::process::Stdio::null())
                        .status()
                        .is_ok_and(|status| status.code() == Some(0))
                })
                .await
                .unwrap_or(false);
                if locked {
                    on_lock();
                }
            });
        }
        glib::ControlFlow::Continue
    });
}
