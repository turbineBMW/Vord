//! Website icons, from the server's own icon service (`/icons/<host>/icon.png`),
//! so the only party that learns which sites are in the vault is the server
//! that already holds it. Cached in memory and in `~/.cache/vord/icons`.

use gtk::gdk;
use gtk::glib;
use std::cell::RefCell;
use std::collections::HashMap;
use std::path::PathBuf;
use std::rc::Rc;
use std::time::{Duration, SystemTime};

/// How long a cached icon (or a known absence) is trusted.
const MAX_AGE: Duration = Duration::from_secs(14 * 24 * 3600);

type Waiter = Box<dyn FnOnce(Option<gdk::Texture>)>;

#[derive(Default)]
struct Cache {
    known: HashMap<String, Option<gdk::Texture>>,
    waiting: HashMap<String, Vec<Waiter>>,
}

thread_local! {
    static CACHE: Rc<RefCell<Cache>> = Rc::default();
}

fn dir() -> PathBuf {
    directories::ProjectDirs::from("io.github", "turbinebmw", "vord")
        .map(|dirs| dirs.cache_dir().join("icons"))
        .unwrap_or_else(|| PathBuf::from(".vord-icons"))
}

/// A host safe to use as a file name and in a URL path.
fn safe(host: &str) -> bool {
    !host.is_empty()
        && host.len() < 256
        && host
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
        && !host.starts_with('.')
}

fn fresh(path: &std::path::Path) -> bool {
    std::fs::metadata(path)
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| SystemTime::now().duration_since(t).ok())
        .is_some_and(|age| age < MAX_AGE)
}

/// Read from disk or fetch, on a worker thread. `Some(empty)` records that
/// the server has no icon for the host.
fn load(server: &str, host: &str) -> Option<Vec<u8>> {
    let path = dir().join(format!("{host}.png"));
    let missing = dir().join(format!("{host}.none"));
    if fresh(&path) {
        return std::fs::read(&path).ok();
    }
    if fresh(&missing) {
        return None;
    }
    let _ = std::fs::create_dir_all(dir());
    match crate::api::Client::new(server).icon(host) {
        Some(bytes) => {
            let _ = std::fs::write(&path, &bytes);
            let _ = std::fs::remove_file(&missing);
            Some(bytes)
        }
        None => {
            let _ = std::fs::write(&missing, b"");
            None
        }
    }
}

/// Call `done` with the host's icon, now or once it arrives.
pub fn get(server: &str, host: &str, done: impl FnOnce(Option<gdk::Texture>) + 'static) {
    let host = host.to_ascii_lowercase();
    if !safe(&host) {
        done(None);
        return;
    }
    let cache = CACHE.with(Rc::clone);
    {
        let mut cache = cache.borrow_mut();
        if let Some(known) = cache.known.get(&host) {
            let known = known.clone();
            drop(cache);
            done(known);
            return;
        }
        if let Some(waiting) = cache.waiting.get_mut(&host) {
            waiting.push(Box::new(done));
            return;
        }
        cache.waiting.insert(host.clone(), vec![Box::new(done)]);
    }
    let server = server.to_string();
    glib::spawn_future_local(async move {
        let fetch_host = host.clone();
        let bytes = gtk::gio::spawn_blocking(move || load(&server, &fetch_host))
            .await
            .ok()
            .flatten();
        let texture =
            bytes.and_then(|bytes| gdk::Texture::from_bytes(&glib::Bytes::from_owned(bytes)).ok());
        let waiting = {
            let mut cache = cache.borrow_mut();
            cache.known.insert(host.clone(), texture.clone());
            cache.waiting.remove(&host).unwrap_or_default()
        };
        for done in waiting {
            done(texture.clone());
        }
    });
}

#[cfg(test)]
mod tests {
    #[test]
    fn only_plain_hosts_are_fetched() {
        assert!(super::safe("github.com"));
        assert!(super::safe("xn--bcher-kva.example"));
        for bad in ["", "../etc", "a/b", ".hidden", "a b", "host:80"] {
            assert!(!super::safe(bad), "{bad}");
        }
    }
}
