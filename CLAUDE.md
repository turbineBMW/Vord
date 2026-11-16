# CLAUDE.md

Vord is a read-only Bitwarden/Vaultwarden client: GTK 4 / libadwaita, Rust, one crate
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
                 types 0/2 (AES-CBC + HMAC) and 3/4 (RSA-OAEP); keys zeroize on drop
src/api.rs       prelogin, password + refresh grants (2FA: TwoFactorChallenge, SecondFactor),
                 send-email-login, sync, icons; `camel()` lower-cases the first letter of
                 every JSON key (Vaultwarden answers PascalCase)
src/session.rs   login (Done | SecondStep(PendingLogin)) / second_step / unlock_key / sync /
                 open_sync: blocking, run on workers
src/store.rs     account.json + vault.json (still encrypted) in $XDG_DATA_HOME/vord, 0600;
                 device.json (device id + remember-2FA tokens) outlives logout
src/vault.rs     the decrypted model; one bad item is marked `damaged`, never fatal
src/totp.rs      otpauth://, steam://, bare base32; RFC 6238 vectors in the tests
src/clipboard.rs secret copies carry x-kde-passwordManagerHint=secret; auto-clear
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
src/ui/pages.rs  login, two-step and unlock pages;  src/ui/prefs.rs  preferences
src/style.css    app CSS; colours only from libadwaita variables
tests/vectors.js independent crypto vectors (Node) -> tests/vectors/*
tests/seed.js    fills a local Vaultwarden with a test vault (see its header)
tests/two-factor.js  turns on authenticator + email 2FA for it; prints TOTP / emailed codes
```

## Rules

- **Nothing decrypted touches disk or logs.** `Debug` on keys, `Account` and `Totp` hides
  secrets; don't `{:?}` a struct holding them.
- **A login waiting for its second step** holds the master key in `Ui::pending`
  (`Arc<PendingLogin>`). Cancel and screen lock drop it; worker results check
  `Ui::still_pending` before touching state.
- **Locking** bumps `Ui::epoch`, drops the session, calls `VaultView::clear` (removes every
  row and the detail tree) and clears our clipboard content. Async results compare the
  epoch before touching state. Anything new that shows decrypted text must be reachable
  from `clear`.
- **Workers:** network and KDF run in `gio::spawn_blocking` with owned `Send` data; results
  come back in `glib::spawn_future_local`. Only the main loop touches state and widgets.
- **List boxes are never changed inside their own selection signals:** handlers defer
  through an idle, and rebuilds set `rebuilding` so the signals they cause are ignored.
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

Plain http is accepted only for loopback addresses. To see the UI without putting a
window on screen, run it under GTK's Broadway backend (`gtk4-broadwayd :7`, then
`GDK_BACKEND=broadway BROADWAY_DISPLAY=:7`) and open http://127.0.0.1:8080 (or the
`--port` given). Broadway's canvas can stop repainting during a long session;
reconnect to refresh. Vord is single-instance over D-Bus: if Vord is already
running, a test launch just raises that window, so start it under
`dbus-run-session --`.
