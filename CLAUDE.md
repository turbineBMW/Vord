# CLAUDE.md

Vord is a Bitwarden/Vaultwarden client: GTK 4 / libadwaita, Rust, one crate
(app id `io.github.turbinebmw.Vord`). Siblings: `~/Projects/Rustle`, `~/Projects/Bubo`,
`~/Projects/Gaze`. The look (three panes, Omarchy palette, see-through sidebars) is
theirs; `omarchy/`, `sidebar.rs` and `accent.rs` are ports of Bubo's, so keep them in step.

## Build & check

```
cargo run                                   # the app
cargo fmt && cargo clippy --all-targets -- -D warnings && cargo test   # keep all clean
cargo test -- --ignored <name>              # GTK tests need a display, one per run
                                            # (each test is its own thread; GTK allows one)
sh install.sh                               # ~/.local
```

CLI, handy against a test server: `vord login SERVER EMAIL` and `vord list` (master
password on stdin). `VORD_DATA_DIR=<dir>` keeps the account and cache out of the real
profile; `XDG_CONFIG_HOME`/`XDG_CACHE_HOME` do the same for settings and icons.
`VORD_LOG=vord=debug` turns logging up.

## Layout

```
src/crypto.rs    KDF (PBKDF2/Argon2id), master password hash, HKDF stretch, EncString
                 types 0/2 (AES-CBC + HMAC) and 3/4 (RSA-OAEP), attachment files
                 (type byte, IV, MAC, data); keys zeroize on drop
src/agent.rs     the SSH agent: socket in $XDG_RUNTIME_DIR/vord, list + sign (RSA by
                 hand: ssh-key 0.6 passes the first prime twice); ui/agent.rs keeps
                 the public keys, asks before signing, waits for an unlock
src/api.rs       prelogin, password + refresh grants (2FA: TwoFactorChallenge, SecondFactor),
                 send-email-login, sync, icons; `camel()` lower-cases the first letter of
                 every JSON key (Vaultwarden answers PascalCase)
src/session.rs   login (Done | SecondStep(PendingLogin)) / second_step / unlock_key / sync /
                 open_sync / change (save, favorite, trash, restore, purge, folders,
                 attachments, Sends):
                 blocking, run on workers; `change` folds the answer into vault.json
src/store.rs     account.json + vault.json (still encrypted) in $XDG_DATA_HOME/vord, 0600;
                 pin.json (the PIN sealed by the user key, and the user key sealed by
                 the PIN's key only if kept across restarts; apart from account.json,
                 which a sync rewrites from an older copy);
                 device.json (device id + remember-2FA tokens) outlives logout; a
                 generation counter keeps a sync from overwriting a change made meanwhile
src/vault.rs     the decrypted model; one bad item is marked `damaged`, never fatal;
                 `Vault::raw` keeps each item as the server sent it
src/edit.rs      Draft (an item as an editor holds it), `request` (the body that saves it),
                 `into_organization` (re-seal the item key, or re-encrypt it all, to share)
src/send.rs      Sends: the seed sealed in `key`, HKDF to the Send's key, the link,
                 the password hash, `Draft` and `request` (as edit.rs, for Sends)
src/export.rs    Bitwarden's export formats from the cached sync: JSON, CSV, encrypted
                 JSON (account key) and password-protected JSON; own items only
src/generator.rs passwords / passphrases / usernames, Bitwarden's rules; EFF list in data/
src/totp.rs      otpauth://, steam://, bare base32; RFC 6238 vectors in the tests
src/clipboard.rs secret copies carry x-kde-passwordManagerHint=secret; auto-clear
src/live.rs      live sync: the notifications hub (SignalR, MessagePack over a
                 websocket) on a thread of its own; a change by another device syncs
src/tray.rs      the tray icon (ksni, a StatusNotifierItem on its own thread);
                 commands reach the window through the main loop
src/icons.rs     /icons/<host>/icon.png from the user's own server, cached in ~/.cache/vord
src/screenlock.rs logind Lock + PrepareForSleep; Omarchy's shell lock is invisible to
                 logind, so `omarchy-hyprland-session-locked` is polled while unlocked and
                 unfocused
src/settings.rs  ~/.config/vord/settings.json
src/ui/mod.rs    Ui: stack (login | two-factor | unlock | vault), state, actions, auto-lock,
                 re-prompt
src/ui/vault.rs  the three panes; Filter; breakpoints (900sp folds the vault sidebar,
                 600sp folds list + details into one column)
src/ui/detail.rs one item's widgets, rebuilt per selection; TOTP ticks on a timer that
                 stops when its label is gone
src/ui/generator.rs the generator dialog; copied values live in Session.generated
src/ui/editor.rs the item editor, shown in the details pane while editing
src/ui/export.rs the Export Vault dialog
src/ui/send.rs   a Send's row, details and editor (the Sends view of the same panes)
src/ui/pages.rs  login, two-step and unlock pages;  src/ui/prefs.rs  preferences
src/style.css    app CSS; colours only from libadwaita variables
tests/vectors.js independent crypto vectors (Node) -> tests/vectors/*
tests/seed.js    fills a local Vaultwarden with a test vault (see its header)
tests/two-factor.js  turns on authenticator + email 2FA for it; prints TOTP / emailed codes
```

## Rules

- **Nothing decrypted touches disk or logs**, except an attachment the user saves or
  an export (after the master password is re-entered), to the path they picked,
  mode 0600. `Debug` on keys, `Account` and `Totp` hides
  secrets; don't `{:?}` a struct holding them.
- **A login waiting for its second step** holds the master key in `Ui::pending`
  (`Arc<PendingLogin>`). Cancel and screen lock drop it; worker results check
  `Ui::still_pending` before touching state.
- **Locking** bumps `Ui::epoch`, drops the session, calls `VaultView::clear` (removes every
  row and the detail tree), closes the generator dialog and clears our clipboard content.
  Window shortcuts don't reach into an `adw::Dialog`: a dialog that shows secrets needs
  its own Ctrl+L (see `ui/generator.rs`). Async results compare the
  epoch before touching state. Anything new that shows decrypted text must be reachable
  from `clear`.
- **Workers:** network and KDF run in `gio::spawn_blocking` with owned `Send` data; results
  come back in `glib::spawn_future_local`. Only the main loop touches state and widgets.
- **List boxes are never changed inside their own selection signals:** handlers defer
  through an idle, and rebuilds set `rebuilding` so the signals they cause are ignored.
- **Edits start from the raw item** (`Vault::raw`), never from the model: unchanged
  fields keep their ciphertext and unknown keys pass through, so a save can't drop
  what Vord doesn't model. Encrypt with `edit::item_key` (the item's own key when it
  has one). New URIs need a `uriChecksum`, or Bitwarden's apps drop them from items
  with their own key; Vaultwarden wants `encryptedFor` (the user id). A damaged item
  can't be edited. Check `request` changes against the web vault (see below).
- **While editing** the lists, search and sync button are insensitive and
  `show_detail` leaves the form alone; dialogs over the vault go through
  `Ui::present_dialog` so locking closes them.
- Servers hide item types from old clients (Vaultwarden drops SSH keys before 2024.12);
  `api::CLIENT_VERSION` is sent on every request for that reason.
- Commits: Conventional Commits, terse.

## Testing against a real server

```
docker run -d --name vord-test-vw -e I_REALLY_WANT_VOLATILE_STORAGE=true \
  -e SIGNUPS_ALLOWED=true -p 127.0.0.1:8222:80 vaultwarden/server
node tests/seed.js
VORD_DATA_DIR=/tmp/vord-test cargo run -- login http://localhost:8222 test@vord.test
```

Two-step login needs mail for its email codes, and a looser login rate limit
(the default refills one attempt a minute):

```
docker network create vord-test
docker run -d --name vord-test-mail --network vord-test -p 127.0.0.1:8025:8025 axllent/mailpit
docker run -d --name vord-test-vw --network vord-test -e I_REALLY_WANT_VOLATILE_STORAGE=true \
  -e SIGNUPS_ALLOWED=true -e LOGIN_RATELIMIT_MAX_BURST=1000 -e DOMAIN=http://localhost:8222 \
  -e SMTP_HOST=vord-test-mail -e SMTP_PORT=1025 -e SMTP_SECURITY=off -e SMTP_FROM=vw@vord.test \
  -p 127.0.0.1:8222:80 vaultwarden/server
node tests/seed.js && node tests/two-factor.js enable
cargo run -- login http://localhost:8222 test@vord.test [--method email] [--remember]
```

The hub: `cargo test -- --ignored live_hub` (a change is heard by another device's
listener, not by this device's). Writes against the seeded server: `cargo test -- --ignored live_changes` (folders,
favorite, trash, restore, purge, refusing a stale copy, moving into the organization
and between its collections, attachments both ways, Sends; it adds a collection, a
`vord-upload.txt` on Router admin and two Sends, to open in another client, each run).
tests/seed.js puts recovery-codes.txt on GitHub and makes two Sends (Door code, with
the password "open sesame", and Floor plan, a file), all encrypted independently, for
Vord to open. Vaultwarden only refuses a stale copy when the item changed more than a
second after it. A Send link opens in the web vault at
`https://localhost:8443/#/send/<accessId>/<key>`; a file Send's download address comes
from `DOMAIN` (http://localhost:8222), which the https page won't fetch.

Bitwarden's own web vault comes with Vaultwarden and is the check that what Vord
writes opens elsewhere, but it refuses plain http. Put TLS in front:
`docker run -d --name vord-test-tls --network vord-test -p 127.0.0.1:8443:8443 caddy:2
caddy reverse-proxy --from https://localhost:8443 --to http://vord-test-vw:80` and
open https://localhost:8443 in a browser that skips the certificate check
(Chromium's `--ignore-certificate-errors`, in a throwaway profile).

Plain http is accepted only for loopback addresses. To see the UI without putting a
window on screen, run it under GTK's Broadway backend (`gtk4-broadwayd :7`, then
`GDK_BACKEND=broadway BROADWAY_DISPLAY=:7`) and open http://127.0.0.1:8080 (or the
`--port` given). Broadway's canvas can stop repainting during a long session;
reconnect to refresh. Vord is single-instance over D-Bus: if Vord is already
running, a test launch just raises that window, so start it under
`dbus-run-session --`, with `GDK_DEBUG=no-portals` (portals started on that bus crash
and leave core dumps, and gtk4-broadwayd then tends to abort too). Broadway only
delivers a click where the pointer last moved: move before pressing. gtk4-broadwayd
often aborts (`append_node_ops: assertion failed: (!reused_node->consumed)`) a few
redraws after a list rebuild or a text change made from code; relaunch, and check
what a change did with the server rather than the screen.
