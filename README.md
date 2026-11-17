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
- Works offline: unlocking needs no network. The vault syncs on unlock, the
  moment the server says it changed elsewhere (its notifications hub, as
  Bitwarden's apps use), every 10 minutes and with Ctrl+R.
- Organization items, including per-item keys.
- A generator for passwords, passphrases and usernames (random word,
  plus-addressed or catch-all email), with Bitwarden's options. What you copy
  from it is listed under History until the vault locks; `vord generate` makes
  one from the terminal.
- Two-step login with an authenticator app, an emailed code or a YubiKey
  (OTP), and "remember this device".
- Creating and editing every item type, in your own vault or an
  organization's collections: websites, custom fields, notes, folder,
  favorite and re-prompt. Your own items can move into an organization, and
  an organization's items between its collections. A new SSH key item gets a freshly made Ed25519 key.
- A changed password goes into the item's password history (the last five,
  shown under the item), as do a hidden field's old values.
- Attachments: save one where you choose, add files to an item, delete
  them. Each file is encrypted with a key of its own, as Bitwarden's apps
  do.
- Sends: share a text or a file by link, with a deletion date, an optional
  expiry, a view limit and a password; hide your email or deactivate one.
  The link is copied when a Send is made; everything in it, file included,
  is encrypted before it leaves, and the key travels only in the link.
- Up to five accounts, on one server or several: switch from the main
  menu or the lock screen (switching locks the one you leave), add one
  with Add Account…, and log out of one without touching the others.
  `vord accounts [EMAIL]` lists them or picks one from the terminal.
- A tray icon (Preferences → Tray), for Waybar, Omarchy's shell and any
  other StatusNotifierItem host: click to show or hide Vord, or lock and
  quit from its menu. Closing the window can leave Vord running there.
- An SSH agent for the vault's SSH keys (Ed25519, RSA, ECDSA), off until
  you turn it on in Preferences: point `SSH_AUTH_SOCK` at its socket and
  `ssh` and `git` use them. Vord asks before a key signs (every time, once
  until locking, or never) and says which program asked; a request while
  locked brings Vord up to be unlocked.
- Unlocking with a PIN, as Bitwarden's apps do: after the master password
  once per start, or across restarts if you choose. Five wrong PINs and
  the master password is needed again.
- Exporting the vault as Bitwarden's apps do: JSON, CSV, or JSON encrypted
  for this account or with a password of its own; Bitwarden and other
  password managers import them. `vord export` does it from the terminal.
- Cloning, moving to the Trash, restoring and deleting for good; creating,
  renaming and deleting folders.
- Saving changes only what you changed. Passkeys, attachments and anything
  Vord doesn't show yet are kept as they are, and a save made over a copy
  that changed elsewhere is refused rather than overwriting it.

## Roadmap

The aim is to do what the Bitwarden desktop app does, in this order:

1. ~~Two-step login with an authenticator app, email or a YubiKey.~~ Done.
2. ~~Password, passphrase and username generator.~~ Done.
3. ~~Creating and editing items: every item type, folders, favorites,
   cloning, the Trash, password history, moving items into an organization
   and between its collections.~~ Done.
4. ~~Attachments: downloading and uploading them.~~ Done.
5. ~~Sends: sharing text and files by link.~~ Done.
6. ~~Exporting the vault, unlocking with a PIN, syncing the moment
   something changes on the server, an SSH agent for the vault's SSH
   keys, a tray icon, more than one account.~~ Done.
7. Two-step login with Duo or a FIDO2 security key, logging in by approving
   from another device, and SSO.

Until then:

- An account whose only second step is Duo or a FIDO2 key gets a clear error
  at login; one that also has an authenticator app or email can use those.
- SSO and Key Connector accounts can't log in.

Not on the list yet: forwarded email aliases (SimpleLogin, addy.io and the
like) in the username generator, auto-type, and unlocking browser extensions
with Vord.

## Keyboard

| Key | Action |
| --- | --- |
| Ctrl+F | Search |
| Ctrl+N | New login (the + button has the other types) |
| Ctrl+E | Edit the item |
| Ctrl+S | Save the item being edited |
| Ctrl+G | Generator |
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
- On disk, `~/.local/share/vord/accounts/<id>` (mode 0700, files 0600)
  holds, for each account, the server, the email, the KDF settings, the
  session's refresh token, and the vault exactly as the server sent it,
  still encrypted. Logging out of an account deletes its directory. This is what the official desktop
  app keeps too, and it is why unlocking works offline. Nothing decrypted is
  ever written.
- `device.json` there holds this device's id and, if you ticked "Remember
  this device", the server's token for skipping two-step login. Like the
  official apps, Vord keeps it when you log out; delete the file to forget
  the device.
- Changes are encrypted on your machine, with the item's own key when it has
  one, before they're sent. Fields you didn't change keep their ciphertext.
  Websites carry the checksum Bitwarden's apps use to notice a URI swapped
  by a server.
- The decrypted things Vord writes are an attachment you save and a plain
  JSON or CSV export, which asks for your master password first; each goes
  only where you pick, readable only by you.
- A Send's key is in its link (after the `#`, which browsers don't send to
  the server), so Vord copies links as secrets: they're hidden from
  clipboard history and cleared like a password. A Send's password goes to
  the server only as a PBKDF2 hash salted with that key.
- With PIN unlock on, the user key is sealed with a key made from the PIN
  (your account's own KDF, as for the master password) and held in memory,
  so a restart asks for the master password. If you choose to keep it
  across restarts, that seal is written to `pin.json`; a short PIN then
  protects your vault from anyone who copies your files only as far as the
  KDF slows them down.
- The SSH agent's socket is in `$XDG_RUNTIME_DIR/vord` (mode 0700) and
  refuses other users' processes. A private key is decrypted for one
  signature at a time. The keys' public halves and names stay in memory
  after locking, so `ssh` can still offer one; logging out forgets them.
- Keys are zeroed when the vault locks, and every widget that showed
  decrypted text is destroyed, including an editor with unsaved changes.

The crypto is checked against values computed independently with Node's
`crypto` module (`tests/vectors.js`) and the RFC 6238 TOTP vectors, and
end to end against a real Vaultwarden (`tests/seed.js`). Items Vord saves
are checked to open in Bitwarden's own web vault.

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

Passphrases and usernames use the [EFF long word list](https://www.eff.org/dice)
(`data/eff_large_wordlist.txt`), by the Electronic Frontier Foundation, under
CC BY 3.0 US.
