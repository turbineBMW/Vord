//! Live sync: the server's notifications hub says when the vault changed
//! somewhere else, so Vord syncs then instead of at the next timed sync.
//!
//! The hub is SignalR over a websocket: a JSON handshake asking for the
//! MessagePack protocol, then binary frames, each holding messages that
//! start with their length (7 bits a byte, low bits first). A change is an
//! invocation of `ReceiveMessage` whose argument has the `ContextId` of
//! the device that made it and a `Type` (Bitwarden's push types). Nothing
//! secret travels on it: it only says that something changed.

use rmpv::Value;
use std::io::ErrorKind;
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tungstenite::Message;

/// How long a read waits before the stop flag is looked at again.
const POLL: Duration = Duration::from_secs(10);

/// What the hub said.
#[derive(Debug, PartialEq, Eq)]
pub enum Event {
    /// The handshake went through.
    Connected,
    /// Something changed, made by another device.
    Changed,
    /// The server logged this account out (a new key, a revoked session).
    LoggedOut,
}

/// Bitwarden's push type for a logout.
const LOG_OUT: i64 = 11;

/// The hub's address: bitwarden.com and .eu keep it on a host of its own;
/// Vaultwarden and self-hosted servers under `/notifications/hub`.
pub fn hub_url(server: &str, token: &str) -> Result<String, String> {
    let url = url::Url::parse(server).map_err(|e| e.to_string())?;
    let secure = url.scheme() == "https";
    let base = match url.host_str() {
        Some("vault.bitwarden.com" | "bitwarden.com") => {
            "wss://notifications.bitwarden.com/hub".to_string()
        }
        Some("vault.bitwarden.eu" | "bitwarden.eu") => {
            "wss://notifications.bitwarden.eu/hub".to_string()
        }
        _ => {
            let mut hub = url.clone();
            hub.set_scheme(if secure { "wss" } else { "ws" })
                .map_err(|_| "unusable server address".to_string())?;
            format!("{}/notifications/hub", hub.as_str().trim_end_matches('/'))
        }
    };
    let mut hub = url::Url::parse(&base).map_err(|e| e.to_string())?;
    hub.query_pairs_mut().append_pair("access_token", token);
    Ok(hub.into())
}

/// Split a binary frame into its messages and read what they say.
/// `device` is this device's id: its own changes are already in the cache.
pub fn read_frame(frame: &[u8], device: &str) -> Vec<Event> {
    let mut events = Vec::new();
    let mut rest = frame;
    while !rest.is_empty() {
        // The length: 7 bits a byte, low bits first, at most 5 bytes.
        let mut length = 0usize;
        let mut used = 0;
        loop {
            let Some(&byte) = rest.get(used) else {
                return events;
            };
            length |= usize::from(byte & 0x7f) << (7 * used);
            used += 1;
            if byte & 0x80 == 0 || used == 5 {
                break;
            }
        }
        let Some(body) = rest.get(used..used + length) else {
            return events;
        };
        rest = &rest[used + length..];
        if let Some(event) = read_message(body, device) {
            events.push(event);
        }
    }
    events
}

fn read_message(mut body: &[u8], device: &str) -> Option<Event> {
    let value = rmpv::decode::read_value(&mut body).ok()?;
    let parts = value.as_array()?;
    // 1 is an invocation; pings (6) and the rest say nothing.
    if parts.first()?.as_i64()? != 1 || parts.get(3)?.as_str()? != "ReceiveMessage" {
        return None;
    }
    let update = parts.get(4)?.as_array()?.first()?;
    let field = |name: &str| -> Option<&Value> {
        update
            .as_map()?
            .iter()
            .find(|(k, _)| k.as_str() == Some(name))
            .map(|(_, v)| v)
    };
    if field("ContextId").and_then(Value::as_str) == Some(device) {
        return None;
    }
    match field("Type").and_then(Value::as_i64) {
        Some(LOG_OUT) => Some(Event::LoggedOut),
        Some(_) => Some(Event::Changed),
        None => None,
    }
}

/// Listen to the hub until the connection drops or `stop` is set, calling
/// `on_event` (on this thread) for each event. Blocks: run it on a thread
/// of its own.
pub fn listen(
    server: &str,
    token: &str,
    device: &str,
    stop: &AtomicBool,
    on_event: impl Fn(Event),
) -> Result<(), String> {
    let url = hub_url(server, token)?;
    let parsed = url::Url::parse(&url).map_err(|e| e.to_string())?;
    let host = parsed.host_str().ok_or("no host")?.to_string();
    let port = parsed.port_or_known_default().ok_or("no port")?;
    // Each address in turn, as a browser does (localhost is often ::1
    // first, and a server may listen on 127.0.0.1 only).
    let mut stream = Err("the hub's address doesn't resolve".to_string());
    for address in (host.as_str(), port)
        .to_socket_addrs()
        .map_err(|e| e.to_string())?
    {
        stream = TcpStream::connect_timeout(&address, Duration::from_secs(10))
            .map_err(|e| e.to_string());
        if stream.is_ok() {
            break;
        }
    }
    let stream = stream?;
    // A read that waits too long hands back control, to look at `stop`.
    stream
        .set_read_timeout(Some(POLL))
        .map_err(|e| e.to_string())?;
    let mut request = tungstenite::client::IntoClientRequest::into_client_request(url.as_str())
        .map_err(|e| e.to_string())?;
    request.headers_mut().insert(
        "User-Agent",
        concat!("Vord/", env!("CARGO_PKG_VERSION"))
            .parse()
            .expect("ASCII"),
    );
    let (mut socket, _) = tungstenite::client_tls_with_config(request, stream, None, None)
        .map_err(|e| match e {
            tungstenite::HandshakeError::Failure(error) => error.to_string(),
            tungstenite::HandshakeError::Interrupted(_) => "the hub didn't answer".into(),
        })?;
    socket
        .send(Message::text(
            "{\"protocol\":\"messagepack\",\"version\":1}\u{1e}",
        ))
        .map_err(|e| e.to_string())?;
    let mut greeted = false;
    while !stop.load(Ordering::Relaxed) {
        match socket.read() {
            Ok(Message::Binary(frame)) => {
                // The handshake's answer is `{}` and a record separator.
                if !greeted && frame.first() == Some(&b'{') {
                    greeted = true;
                    on_event(Event::Connected);
                    continue;
                }
                for event in read_frame(&frame, device) {
                    on_event(event);
                }
            }
            Ok(Message::Close(_)) => return Err("the hub closed the connection".into()),
            // Pings are answered by tungstenite as it reads.
            Ok(_) => {}
            Err(tungstenite::Error::Io(e))
                if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) =>
            {
                // Send what tungstenite queued (pongs) while waiting.
                if let Err(error) = socket.flush() {
                    return Err(error.to_string());
                }
            }
            Err(error) => return Err(error.to_string()),
        }
    }
    let _ = socket.close(None);
    let _ = socket.flush();
    Ok(())
}

/// A listener's stop switch.
pub type Stop = Arc<AtomicBool>;

#[cfg(test)]
mod tests {
    use super::*;

    /// A message as Vaultwarden frames it.
    fn frame(value: &Value) -> Vec<u8> {
        let mut body = Vec::new();
        rmpv::encode::write_value(&mut body, value).unwrap();
        let mut out = Vec::new();
        let mut size = body.len();
        loop {
            let mut part = (size & 0x7f) as u8;
            size >>= 7;
            if size > 0 {
                part |= 0x80;
            }
            out.push(part);
            if size == 0 {
                break;
            }
        }
        out.extend(body);
        out
    }

    fn update(context: Option<&str>, kind: i64, padding: usize) -> Value {
        Value::Array(vec![
            1.into(),
            Value::Map(vec![]),
            Value::Nil,
            "ReceiveMessage".into(),
            Value::Array(vec![Value::Map(vec![
                ("ContextId".into(), context.map_or(Value::Nil, Value::from)),
                ("Type".into(), kind.into()),
                // Long enough to need a two-byte length.
                ("Payload".into(), Value::from("x".repeat(padding))),
            ])]),
        ])
    }

    #[test]
    fn frames_say_what_changed_and_who_changed_it() {
        let mut both = frame(&update(Some("other-device"), 0, 200));
        both.extend(frame(&update(Some("this-device"), 1, 0)));
        both.extend(frame(&Value::Array(vec![6.into()])));
        both.extend(frame(&update(None, 11, 0)));
        assert_eq!(
            read_frame(&both, "this-device"),
            vec![Event::Changed, Event::LoggedOut]
        );
        // A frame cut short yields what came whole.
        assert_eq!(read_frame(&both[..10], "this-device"), vec![]);
    }

    /// Against the local test server from `tests/seed.js`:
    /// `cargo test -- --ignored live_hub`.
    #[test]
    #[ignore]
    fn live_hub() {
        use crate::session::{self, Change, Login};
        use std::sync::mpsc;
        let dir = tempfile::tempdir().unwrap();
        std::env::set_var("VORD_DATA_DIR", dir.path());
        let Login::Done(account, user_key) = session::login(
            "http://localhost:8222",
            "test@vord.test",
            "vord test password 1",
        )
        .unwrap() else {
            panic!("the seeded account has no second step");
        };
        let (account, token) = session::hub_token(account).unwrap();

        // Two listeners: one as another device, one as this one.
        let listen_as = |device: &'static str| {
            let (tx, rx) = mpsc::channel();
            let stop: Stop = Default::default();
            let (server, token, flag) = (account.server.clone(), token.clone(), stop.clone());
            let thread = std::thread::spawn(move || {
                listen(&server, &token, device, &flag, |event| {
                    let _ = tx.send(event);
                })
            });
            match rx.recv_timeout(Duration::from_secs(10)) {
                Ok(event) => assert_eq!(event, Event::Connected),
                Err(_) => panic!("the hub: {:?}", thread.join().unwrap()),
            }
            (rx, stop, thread)
        };
        let (elsewhere, stop_elsewhere, thread_elsewhere) = listen_as("another-device");
        let (here, stop_here, thread_here) = listen_as(account.device_id.clone().leak());

        let name = user_key.encrypt_text("Live hub test");
        let (account, sync, _) =
            session::change(account, Change::SaveFolder { id: None, name }).unwrap();
        assert_eq!(
            elsewhere.recv_timeout(Duration::from_secs(10)).unwrap(),
            Event::Changed
        );
        // This device's own change is already in its cache.
        assert!(here.recv_timeout(Duration::from_secs(2)).is_err());

        let folder = sync["folders"]
            .as_array()
            .unwrap()
            .iter()
            .find(|f| {
                f["name"]
                    .as_str()
                    .and_then(|n| n.parse::<crate::crypto::EncString>().ok())
                    .and_then(|n| n.decrypt_text(&user_key).ok())
                    .as_deref()
                    == Some("Live hub test")
            })
            .unwrap()["id"]
            .as_str()
            .unwrap()
            .to_string();
        session::change(account, Change::DeleteFolder(folder)).unwrap();
        for (stop, thread) in [(stop_elsewhere, thread_elsewhere), (stop_here, thread_here)] {
            stop.store(true, Ordering::Relaxed);
            assert!(thread.join().unwrap().is_ok());
        }
    }

    #[test]
    fn hub_addresses() {
        assert_eq!(
            hub_url("https://vw.example.org", "t").unwrap(),
            "wss://vw.example.org/notifications/hub?access_token=t"
        );
        assert_eq!(
            hub_url("http://localhost:8222", "a b").unwrap(),
            "ws://localhost:8222/notifications/hub?access_token=a+b"
        );
        assert_eq!(
            hub_url("https://example.org/vault", "t").unwrap(),
            "wss://example.org/vault/notifications/hub?access_token=t"
        );
        assert_eq!(
            hub_url("https://vault.bitwarden.com", "t").unwrap(),
            "wss://notifications.bitwarden.com/hub?access_token=t"
        );
    }
}
