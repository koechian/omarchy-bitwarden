# omarchy-bitwarden (hardened fork)

A Bitwarden / Vaultwarden overlay for the **Omarchy shell** on Hyprland: search the vault, copy passwords,
usernames and TOTP codes from the keyboard.

This is a security-hardened fork of [icyleaf/omarchy-bitwarden](https://github.com/icyleaf/omarchy-bitwarden).
It keeps the upstream overlay and its Rust engine (`omawarden`), removes features that are not needed for password
and TOTP lookup, and changes how secrets leave the engine. Upstream release packages (`omawarden-bin`,
`omawarden-git`) are **not** compatible: this fork's overlay requires engine 0.12.0 built from this repository.

![Preview](preview.png)

---

## What this fork changes

### Secrets leave the engine one field at a time

- `list`, `search` and `get_item` return **redacted items**: passwords, TOTP seeds, card numbers and security
  codes, identity numbers, notes, hidden custom fields and password history are replaced by `has_*` flags.
- A secret is released only by an explicit **reveal** or **copy** of one field. Copies are made by the engine
  itself (`wl-copy` over stdin, with the sensitive hint, auto-cleared), so the overlay never holds a copied secret.
- A **release budget** hard-locks the vault after more than 30 releases in 60 seconds or 120 in an hour.
- The overlay never releases a secret by itself: browsing, searching and reopening release nothing, and revealed
  values are cleared on selection change, hide, lock and after 30 seconds.
- The overlay refuses any vault listing that contains a secret value, so it fails closed against an engine that
  does not redact.

See [ADR 0027](docs/adr/0027-redacted-item-access-and-per-field-secret-release.md) and
[the engine contract](docs/agents/contracts.md).

### Cryptography and network

- Unauthenticated ciphertext (EncString type 0) is refused when a MAC key is present; organization and item keys
  must be 64-byte encryption-and-MAC keys; organization keys are accepted only RSA-wrapped; an item whose key is
  missing is skipped instead of being decrypted with the user key.
- Server-supplied KDF parameters outside Bitwarden's documented bounds are refused rather than substituted.
- TOTP parameters are validated (period 1–3600 s, 1–10 digits).
- The HTTP client follows no redirects and requires HTTPS except for loopback; the device identifier is a random
  UUID instead of `/etc/machine-id`; an unreadable `config.json` is an error instead of a silent fallback to
  bitwarden.com; WebAuthn relying-party IDs are validated.

### Daemon and lifecycle

- Peer checks on the socket (same user, same executable where visible), a 64 KiB request cap with a total read
  deadline, and a 16-connection cap.
- Clients cannot reset the idle timer or disable auto-lock; the 12-hour session ceiling stays.
- The vault locks **before** suspend (systemd-logind delay inhibitor) and when the desktop session ends.
- Decrypted items, keys, the master password and request buffers are zeroized.
- Quick unlock (fingerprint or system password after a soft lock) is off unless enabled.
- `wl-copy` is taken only from root-owned system locations, and locks withdraw only the engine's own clipboard
  offers.

### Overlay

- Every label that shows vault, server or settings data renders as plain text, enforced by
  `scripts/check-qml-text-format.py`.
- Only `http://` and `https://` links can be opened.

### Removed

The SSH agent and SSH key management, attachments, website icons (which sent every item's domain to an icon
service), the update check and release notes, and the one-click package installer.

### Known limits

A program running as your own user can still ask an unlocked engine for secrets one at a time; the budget and the
caller checks slow this down but cannot stop it, because Linux offers no isolation between processes of the same
user without a sandbox. Genuine engine processes are non-dumpable, which also hides their executable path, so the
executable check rejects visible foreign callers (scripts, `socat`) but not a caller that makes itself
non-dumpable. See ADR 0027 for the full threat model.

---

## Requirements

- Omarchy (Hyprland and the Omarchy shell)
- `libsecret` (`secret-tool`) and a running Secret Service keyring
- `wl-clipboard` in `/usr/bin`
- Rust (the repository pins 1.98.0 in `.mise.toml`)
- Optional: `libfido2` for WebAuthn / security-key two-factor login
- Optional: `polkit` and the bundled policy for quick unlock

## Installation

### 1. Build and install the engine

```bash
git clone https://github.com/koechian/omarchy-bitwarden.git
cd omarchy-bitwarden/omawarden
mise install            # or install Rust 1.98.0 another way
cargo build --release
install -Dm755 target/release/omawarden ~/.local/bin/omawarden
omawarden --version     # 0.12.0
```

The overlay finds the engine with `command -v omawarden`, so `~/.local/bin` must be on the shell's `PATH`.

### 2. Install the plugin

```bash
omarchy plugin add https://github.com/koechian/omarchy-bitwarden.git --enable
```

The plugin adds a lock icon to the bar (right section by default). Move it with
`omarchy bar move icyleaf.bitwarden --section <section>`.

- **Left click** opens a dropdown under the icon: type to search your logins. Each row has quick copy
  buttons for the username, password and verification code; a quick copy closes the dropdown so you can
  paste straight away, and the icon shows a check mark for a moment. Click a row (or press
  <kbd>Enter</kbd>) for its details page, where you can copy each value in turn without the dropdown
  closing. While the vault is locked the dropdown asks for the master password.
- **Password, then code**: for a login with both a password and a verification code, *Copy password,
  then code* (or <kbd>Shift</kbd> + <kbd>Enter</kbd>) stages both. Your first paste gives the password
  and the next paste gives the code, computed when you paste it. This suits sign-in prompts that ask for
  one after the other, such as `tsh login`. The engine serves the clipboard itself for this: it ignores
  the reads that clipboard watchers make the moment a value is copied, treats the next read as your
  paste, and swaps in the code. Copying something else in between cancels the sequence.
- **Right click** opens the full vault window (cards, identities, notes, generator, settings, sign-in).

### 3. Bind hotkeys (optional, in `~/.config/hypr/bindings.lua`)

```lua
o.bind("SUPER + B", "Bitwarden dropdown", "omarchy-shell icyleaf.bitwarden.quickaccess toggle")
o.bind("SUPER + SHIFT + B", "Bitwarden window", "omarchy-shell shell toggle icyleaf.bitwarden")
```

### Quick unlock (optional)

Install the polkit policy as root and enable the option:

```bash
sudo install -Dm644 packaging/org.omarchy.plugin.icyleaf.omarchy-bitwarden.policy \
  /usr/share/polkit-1/actions/org.omarchy.plugin.icyleaf.omarchy-bitwarden.policy
```

Then turn on quick unlock in Settings (<kbd>Ctrl</kbd>+<kbd>,</kbd>).

### Uninstall

```bash
pkill -x omawarden
omarchy plugin remove icyleaf.bitwarden
rm ~/.local/bin/omawarden
```

---

## Keyboard shortcuts

| Shortcut | Action |
| :-- | :-- |
| <kbd>Enter</kbd> | Copy the primary secret (password or card number) |
| <kbd>Ctrl</kbd> + <kbd>Enter</kbd> | Copy the current TOTP code |
| <kbd>Ctrl</kbd> + <kbd>U</kbd> | Copy the username |
| <kbd>Ctrl</kbd> + <kbd>T</kbd> | Reveal or hide the selected secret |
| <kbd>Ctrl</kbd> + <kbd>H</kbd> | Password history |
| <kbd>Ctrl</kbd> + <kbd>O</kbd> | Open the item's website (http and https only) |
| <kbd>Ctrl</kbd> + <kbd>K</kbd> | Action palette |
| <kbd>Ctrl</kbd> + <kbd>G</kbd> | Password and passphrase generator |
| <kbd>Ctrl</kbd> + <kbd>,</kbd> | Settings |
| <kbd>Ctrl</kbd> + <kbd>L</kbd> | Lock the vault |
| <kbd>Ctrl</kbd> + <kbd>R</kbd> | Sync with the server |
| <kbd>↓</kbd> / <kbd>↑</kbd> | Move through items or actions |
| <kbd>Tab</kbd> | Switch category (All, Logins, Cards, Identities, Secure Note) |
| <kbd>Alt</kbd> + <kbd>V</kbd> | Cycle the vault or organization filter |
| <kbd>Alt</kbd> + <kbd>F</kbd> | Cycle the folder filter |
| <kbd>Esc</kbd> | Close a dialog, or hide the overlay |

Held keys act once, so holding a chord cannot spend the release budget.

In the bar dropdown:

| Shortcut | List | Details page |
| :-- | :-- | :-- |
| <kbd>Enter</kbd> | Open the details page | Copy the password |
| <kbd>Shift</kbd> + <kbd>Enter</kbd> | Password, then code | Password, then code |
| <kbd>Ctrl</kbd> + <kbd>Enter</kbd> | Copy the code and close | Copy the code |
| <kbd>Ctrl</kbd> + <kbd>U</kbd> | Copy the username and close | Copy the username |
| <kbd>↓</kbd> / <kbd>↑</kbd> | Move through the list | |
| <kbd>Esc</kbd> | Close the dropdown | Back to the list |
| <kbd>Ctrl</kbd> + <kbd>L</kbd> / <kbd>Ctrl</kbd> + <kbd>O</kbd> | Lock / open the full window | Lock / open the full window |

---

## Signing in

- **Master password**, with two-factor authentication by authenticator app, email code, or security key
  (WebAuthn / FIDO2, needs `libfido2`). New-device email verification is supported. Because this fork uses a new
  random device identifier, Bitwarden treats the first login as a new device.
- **Personal API key** (`client_id` and `client_secret` from the web vault under Settings → Security → Keys), then
  the master password to unlock. Useful for accounts that use Duo.
- **Mutual TLS** client certificates for self-hosted servers behind an mTLS proxy:

```bash
omawarden config set --client-cert ~/.config/certs/client.crt --client-key ~/.config/certs/client.key
```

Tokens and the API key secret are kept in the system keyring. The master password is never stored.

## Password generator

<kbd>Ctrl</kbd>+<kbd>G</kbd> in the overlay, or from the command line:

```bash
omawarden generate -l 24 -c                              # 24 characters, copied with auto-clear
omawarden generate -l 18 --avoid-ambiguous
omawarden generate --passphrase -w 5 -s . --capitalize -c
```

---

## Development

```bash
cd omawarden
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test --all-targets
cd .. && ./scripts/test-qml.sh      # needs qmllint and qml6 (Qt 6) on PATH
```

Design decisions are recorded in [docs/adr](docs/adr). Notes on the removed features remain in their ADRs.

## Credits

All credit for the original overlay and engine goes to [icyleaf](https://github.com/icyleaf) and the upstream
contributors. The engine follows the protocol of the official [Bitwarden clients](https://github.com/bitwarden/clients)
and was inspired by [rbw](https://github.com/doy/rbw).

## License

[MIT](LICENSE), as upstream.
