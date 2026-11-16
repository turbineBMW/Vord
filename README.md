# Vord

*Vörðr* (Old Norse): a warden spirit that follows a person through life and
guards them. A fitting name for the app that keeps your passwords.

Vord is a native vault for [Vaultwarden](https://github.com/dani-garcia/vaultwarden)
and Bitwarden on the Linux desktop, built with GTK 4 and libadwaita and written
in Rust. It looks like its siblings (Rustle, Bubo, Gaze) and follows the
Omarchy theme live.

![Vord showing the vault sidebar, the item list and a login](data/screenshots/main-window.png)

## Features

- Three panes: the vault (All Items, Favorites, types, folders, organization
  collections, Trash), the items, and the selected item.
- Logins, cards, identities, secure notes, SSH keys and custom fields, with
  copy buttons and reveal toggles; secrets start hidden.
- Live TOTP codes with a countdown, including Steam Guard codes.
- Search across names, usernames, websites and card brands.
- Website icons from your own server's icon service (nothing goes to a third
  party). They can be turned off.
- Copied secrets are marked so clipboard histories skip them, and the
  clipboard is emptied after 30 seconds (configurable).
- Locks after 15 minutes in the background (configurable), when the screen
  locks (logind and Omarchy's lock screen), before sleep, and with Ctrl+L.
- Honours Bitwarden's "master password re-prompt" on protected items.
- Works offline: unlocking needs no network. The vault syncs on unlock, every
  10 minutes and with Ctrl+R.
- Organization items, including per-item keys.

Vord is read-only for now. Edit items in the web vault or another Bitwarden
app, and Vord picks the change up on its next sync.

### Not yet

- Creating or editing items, and a password generator.
- Two-step login (authenticator, email or security key). Accounts that use it
  get a clear error at login.
- Downloading attachments. Their names are shown.
- SSO and Key Connector accounts.

## Keyboard

| Key | Action |
| --- | --- |
| Ctrl+F | Search |
| Ctrl+U | Copy the username |
| Ctrl+P | Copy the password |
| Ctrl+T | Copy the verification code |
| Ctrl+O | Open the website |
| Ctrl+R / F5 | Sync now |
| Ctrl+L | Lock |
| Ctrl+, | Preferences |
| Ctrl+Q | Quit |

## Security

Vord follows the Bitwarden client protocol and does all decryption locally:

- The master key comes from your master password with the account's own key
  derivation (PBKDF2-SHA256 or Argon2id). The server only ever receives a hash
  of it, the same one every Bitwarden app sends.
- Vault data is AES-256-CBC with HMAC-SHA256. MACs are checked, in constant
  time, before anything is decrypted. Organization keys are RSA-OAEP.
- On disk, `~/.local/share/vord` (mode 0700, files 0600) holds the server, the
  email, the KDF settings, the session's refresh token, and the vault exactly
  as the server sent it, still encrypted. This is what the official desktop
  app keeps too, and it is why unlocking works offline. Nothing decrypted is
  ever written.
- Keys are zeroed when the vault locks, and every widget that showed
  decrypted text is destroyed.

The crypto is checked against values computed independently with Node's
`crypto` module (`tests/vectors.js`) and the RFC 6238 TOTP vectors, and
end to end against a real Vaultwarden (`tests/seed.js`).

## Install

Needs GTK ≥ 4.18, libadwaita ≥ 1.8 and a Rust toolchain.

```sh
sh install.sh               # ~/.local; PREFIX=/usr for system-wide
sh uninstall.sh
```

Then open **Vord** from the app launcher and log in with your server's address
(for example `https://vault.example.com`), your email and your master
password.

## Theming

With "Follow Omarchy theme" on (the default), Vord takes its colours from the
current Omarchy theme and changes with it. A theme can also ship a `vord.css`,
layered over the derived palette. For example, to make the sidebars
translucent:

```css
:root { --vord-sidebar-opacity: 0.85; }
```

## Licence

GPL-3.0-or-later.
