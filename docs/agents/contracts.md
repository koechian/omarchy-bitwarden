# CLI & Frontend Contracts

Specifications and invariant rules governing the boundary between the `omawarden` backend (CLI & Daemon) and the Quickshell / QML frontend.

## 1. CLI Output & Error Contract

### Dual-Mode Output Architecture

Every `omawarden` subcommand that can be consumed by the frontend or external automation MUST support two output modes:

1. **Interactive Terminal Mode (Default)**:
   - **Success (Exit 0)**: Outputs clean human-readable value directly to `stdout` (suitable for piping to `wl-copy`, shells, or files).
   - **Error (Exit 1)**: Outputs formatted error text (`Error: <reason>`) to `stderr`.

2. **Machine/API Mode (`--json`)**:
   - Always enabled via the `--json` flag on the subcommand.
   - Outputs a unified JSON envelope to `stdout`.
   - **Success Envelope (Exit 0)**:
     ```json
     {
       "ok": true,
       "...": "payload data"
     }
     ```
   - **Failure Envelope (Exit 1)**:
     ```json
     {
       "ok": false,
       "error": "Friendly, actionable error description."
     }
     ```

### Validation vs. Silent Clamping Invariant

- **Rule**: Input options with bounded valid domains (e.g. password lengths `5..=128`, passphrase words `3..=20`, timeout intervals) **MUST be validated, NEVER silently clamped**.
- **Error Standard**:
  When a boundary is violated, reject immediately and return an explicit error stating the allowed range and recommended practice.
  Example:
  `Password length must be between 5 and 128 characters. Use 14 or more characters for a strong password.`

### Alignment with Daemon IPC

Daemon Unix Domain Socket requests and responses adhere to the same schema convention:
- Request: `{ "action": "<command_name>", ...args }`
- Response: `{ "ok": true, ... }` or `{ "ok": false, "error": "<msg>" }`

---

## 2. Frontend (QML) Invocation & Error Rules

### Machine-Readable Invocations

- When invoking `omawarden` through Quickshell's `Process` component, **always supply `--json`**.
- Never parse unstructured stdout/stderr as application state unless providing backwards-compatibility fallback for older engine versions.

### Required Process Error Handling Lifecycle

Every QML `Process` calling `omawarden` MUST implement the complete error-handling lifecycle:

1. **Stdout JSON Parsing**:
   Parse output as JSON. Check `data.ok`:
   - If `true`: Clear `errorMessage`, populate state properties.
   - If `false`: Bind `errorMessage = data.error`.

2. **Stderr Capture & Sanitization**:
   In `stderr: StdioCollector.onStreamFinished`, capture non-empty output.
   Strip common prefixes (e.g., `text.replace(/^Error:\s*/i, "")`) and assign to `errorMessage` if not already set.

3. **Exit Code Trapping**:
   In `onExited: function(code)`, verify `code === 0`. If `code !== 0` and `errorMessage` remains empty, set a sensible default error (e.g., `"Process exited with code " + code`).

4. **Visual Error Feedback**:
   Modals and views that trigger operations must expose an `errorMessage` property and render an **Error Alert Banner** (`Rectangle` with warning icon and red/amber contrast styling, matching `PasswordGeneratorModal`) whenever `Boolean(errorMessage)` is true. Never fail silently.

---

## 3. Daemon Item Access Contract (ADR 0027)

The daemon never hands out the decrypted vault in bulk. `list`, `search` and `get_item` return **redacted items**; a secret leaves the daemon only through `reveal_field` (value in the response), `copy_field` (the daemon writes it to the clipboard) or `copy_sequence` (the daemon stages several fields of one item on the clipboard, one per paste; ADR 0028), and every such release is counted against a **release budget**. Field and flag names below are exact.

### 3.1 Transport and caller rules

- Socket: `$XDG_RUNTIME_DIR/omawarden.sock`, mode `0600`. `XDG_RUNTIME_DIR` must be set, a real directory, owned by the user, mode `0700`; otherwise every command fails with an error naming the problem (there is no `/tmp` fallback).
- One request per connection: one JSON object on one line, at most **65536 bytes**, delivered in full within **5 seconds** of the connection being accepted (a total deadline, not a per-read timeout). One response line comes back. At most **16** connections are served at once; extra connections get `{"ok": false, "error": "Too many concurrent connections (limit 16); try again."}`.
- **Caller verification** in both directions: same UID (`SO_PEERCRED`) and, where the kernel exposes `/proc/<pid>/exe`, the same executable. **The overlay cannot talk to the socket itself** (Quickshell is not the omawarden executable); it must run the `omawarden` CLI commands in section 3.6. A refused caller gets `{"ok": false, "error": "Access denied: the client is not this omawarden executable running as the same user"}`.
- Generic errors (no `error_code`): `"Malformed JSON request"`, `"Request exceeds the 65536-byte limit"`, `"Request was not received within 5 seconds"`, `"Unknown action: <name>"`.

### 3.2 Redacted item

`list` and `search` return a JSON **array** of these objects; `get_item` returns `{"ok": true, "item": <object>}`. Keys marked *optional* are omitted when the item has no value for them.

```jsonc
{
  "id": "2f6c…",                    // Bitwarden cipher id
  "name": "GitHub",
  "type": 1,                        // 1 login, 2 secure note, 3 card, 4 identity
  "type_name": "login",             // "login" | "note" | "card" | "identity"
  "sub_title": "octocat",           // login: username; card: "Visa •••• 4444"; identity: full name or email; note: "Secure Note"
  "favorite": false,
  "created_at": "2024-01-01T00:00:00Z",      // optional
  "updated_at": "2024-02-01T00:00:00Z",      // optional
  "folder_id": "…", "folder_name": "Work",   // optional
  "organization_id": "…", "organization_name": "Acme", // optional
  "collection_ids": ["…"],                    // optional
  "has_notes": true,                // notes are secret: reveal with field "notes"
  "usage_score": 1.906,             // recent use (section 3.7): number, 3 decimals; 0 when never used
  "last_used_at": "2026-11-07T09:12:44Z", // latest recorded use, RFC 3339 UTC; null when never used

  // Only on type 1:
  "login": {
    "username": "octocat",          // string or null
    "uris": [{ "uri": "https://github.com" }],
    "has_passkey": false,
    "passkey_created_at": null,     // string or null
    "has_password": true,           // field "login.password"
    "has_totp": true,               // field "login.totp"
    "has_password_history": true,   // field "password_history"
    "password_history_count": 2
  },

  // Only on type 3:
  "card": {
    "cardholderName": "Alice Doe", "brand": "Visa", "expMonth": "12", "expYear": "2028", // each string or null
    "number_last_four": "4444",     // null unless the number has at least 12 digits
    "has_number": true,             // field "card.number"
    "has_code": true                // field "card.code"
  },

  // Only on type 4 (each of the 14 public values is a string or null):
  "identity": {
    "title": null, "firstName": "Alice", "middleName": null, "lastName": "Doe",
    "address1": "123 Tech Lane", "address2": null, "city": "San Francisco",
    "state": "CA", "postalCode": "94105", "country": "US", "company": "Acme Corp",
    "email": "alice@example.com", "phone": "+1-555-0199", "username": null,
    "has_ssn": true,                // field "identity.ssn"
    "has_passport_number": false,   // field "identity.passport_number"
    "has_license_number": false     // field "identity.license_number"
  },

  // Every type; index is the position to use in "custom.<index>":
  "fields": [
    { "index": 0, "name": "Account", "type": 0, "has_value": true, "value": "1234" }, // text: value included
    { "index": 1, "name": "PIN",     "type": 1, "has_value": true },                  // hidden: no value key
    { "index": 2, "name": "2FA on",  "type": 2, "has_value": true, "value": "true" }, // boolean: value included
    { "index": 3, "name": "Linked",  "type": 3, "has_value": false },                 // linked: no value key
    { "index": 4, "name": "Odd",     "type": 1, "has_value": true }                   // type missing or not an integer on the server: reported as hidden (1)
  ]
}
```

Never present in a redacted item: `notes`, `login.password`, `login.totp`, `login.password_history`, `card.number`, `card.code`, `identity.ssn`, `identity.passportNumber`, `identity.licenseNumber`, hidden custom field values (and values of any custom field type other than 0 and 2), and the internal `search_text`. `search` matches names, subtitles, usernames, URIs, card brand / holder / last four digits, identity name / email / phone / company / address, folder and organization names, custom field names and text/boolean values; it never matches secret content.

`usage_score` and `last_used_at` are on every redacted item from `list`, `search` and `get_item` (engine 0.14.0 and later). They are not secret: they say how often and how lately the user copied something from the item, never what.

### 3.3 Field identifiers

| Identifier | Released value |
|------------|----------------|
| `login.password` | the password (string) |
| `login.totp` | the **current code**, never the seed, plus `seconds_remaining` and `period` |
| `notes` | the notes (string) |
| `card.number` | the full card number (string) |
| `card.code` | the security code (string) |
| `identity.ssn` | the social security number (string) |
| `identity.passport_number` | the passport number (string) |
| `identity.license_number` | the licence number (string) |
| `custom.<index>` | the value of `fields[<index>]` (any type with a value; `index` is a decimal integer) |
| `password_history` | array of `{ "password": "…", "last_used_date": "…" \| null }` in the order Bitwarden stores them; `reveal_field` only |

### 3.4 `reveal_field`, `copy_field` and `copy_sequence`

Requests (`id` is the exact item id from a redacted item, not a name):

```json
{ "action": "reveal_field", "id": "2f6c…", "field": "login.password" }
{ "action": "copy_field",   "id": "2f6c…", "field": "login.password", "clear_after_seconds": 30 }
{ "action": "copy_sequence", "id": "2f6c…", "fields": ["login.password", "login.totp"], "clear_after_seconds": 30 }
```

`clear_after_seconds` is optional, an integer from 1 to 3600; the default is the configured `clipboard_clear_seconds`, or 30 when that is not in range. `copy_field` always uses `wl-copy --sensitive` and always schedules the auto-clear.

`copy_sequence` (ADR 0028) stages `fields` (1 to 8 identifiers from 3.3, in paste order; duplicates allowed; `password_history` refused) so that the first paste in any application yields the first field, the second paste the second field, and so on. The daemon serves the selection itself through the Wayland data-control protocol (`ext-data-control-v1`, else `wlr-data-control-unstable-v1`), offering `text/plain;charset=utf-8`, `text/plain`, `UTF8_STRING`, `TEXT`, `STRING` and `x-kde-passwordManagerHint` (`secret`). Reads within 400 ms of a stage becoming the selection are clipboard watchers and do not count; the first text read after that is the paste, reads within 300 ms after it get the same value, then the next field becomes the selection. A `login.totp` stage serves the code current at each read. After the last paste, or `clear_after_seconds` after the start, the selection is withdrawn if the sequence still owns it; when the user copies something else, the sequence ends and leaves the new content alone. Every lock, the end of the session, daemon exit and any new `copy`, `copy_field` or `copy_sequence` withdraw an active sequence; only one runs at a time. Every field is validated before anything is charged; the sequence costs one release per field, refunded in full when it cannot start. The response comes back as soon as the first field is the selection.

Responses:

```json
{ "ok": true, "id": "2f6c…", "field": "login.password", "value": "…" }
{ "ok": true, "id": "2f6c…", "field": "login.totp", "value": "123456", "seconds_remaining": 17, "period": 30 }
{ "ok": true, "id": "2f6c…", "field": "password_history", "value": [{ "password": "…", "last_used_date": "2023-12-01T00:00:00Z" }] }
{ "ok": true, "id": "2f6c…", "field": "card.code", "copied": true, "clear_after_seconds": 30 }
{ "ok": true, "id": "2f6c…", "fields": ["login.password", "login.totp"], "clear_after_seconds": 30 }
```

Errors carry a machine-readable `error_code` next to `error`:

| `error_code` | When |
|--------------|------|
| `invalid_request` | `id` or `field` missing, `fields` not an array of 1 to 8 strings, or `clear_after_seconds` out of range |
| `vault_locked` | the vault is locked (also returned by `list`, `search`, `get_item`, `sync`) |
| `item_not_found` | no item has that id (also `get_item` with no match) |
| `unknown_field` | the identifier is not in 3.3; the message lists the supported identifiers |
| `field_empty` | the item has no value for that field (including a field of another item type); for `copy_sequence`, any of its fields |
| `field_not_copyable` | `copy_field` or `copy_sequence` with `password_history` |
| `release_limit_exceeded` | the release budget is exhausted; the vault has just been hard-locked |
| `clipboard_failed` | `wl-copy` failed, or no trusted `wl-copy` is installed (only `/usr/bin/wl-copy` or `/usr/local/bin/wl-copy`, owned by root and not group- or world-writable, is used; `PATH` is never searched); for `copy_sequence`, the daemon could not reach the compositor, the compositor offers no data-control protocol or seat, or it did not accept the selection (the message says which) |

```json
{ "ok": false, "error": "Unknown field 'login.secret'. Supported fields: login.password, …, custom.<index>.", "error_code": "unknown_field" }
```

### 3.5 Release budget, idle timer and auto-lock

- **Budget**: successful releases (`reveal_field`, `copy_field` and `copy_sequence` together; a sequence counts one per field) are limited in two sliding windows: at most **30** in any **60 seconds** and at most **120** in any **hour**. Each release costs one, except `password_history`, which costs one per history entry (at least one). A request whose cost would exceed either limit is refused with `release_limit_exceeded`, the vault is hard-locked (keys and decrypted items zeroized, retained quick-unlock key wiped) and a warning is logged; a password history with more than 30 entries can never be released. Failed requests are not counted. A hard lock resets both windows. The overlay should fetch a TOTP code once and count `seconds_remaining` down locally (one release per period), and should reveal on explicit user action only.
- **Idle timer**: reset only by `search`, `get_item` and a successful `unlock` / `quick_unlock`. Not reset by `reveal_field`, `copy_field`, `copy_sequence` (so releasing secrets at a steady pace cannot keep the vault unlocked), `copy`, `generate_password`, `totp` (these work while locked), `ping`, `status`, `list`, `sync`, `lock`, `set_auto_lock`, `clear_item_usage`. There is no client override: a `"touch"` field is ignored. A user who only copies or reveals, without searching, is idle-locked after the configured interval.
- **`set_auto_lock`**: `{"action": "set_auto_lock", "auto_lock_seconds": n}` or `{"auto_lock_minutes": n}`; n must give 60 seconds to 12 hours (43200 s). Zero is refused: `{"ok": false, "error": "Auto-lock must be between 60 and 43200 seconds (1 minute to 12 hours); disabling it is not supported."}`. `omawarden config set --auto-lock` validates the same range (1 to 720 minutes). A configured value outside the range starts the daemon with 15 minutes and a warning. The 12-hour session ceiling is unchanged.
- **Other locks**: suspend and the end of the login session hard-lock (the latter also stops the daemon). An `unlock` still deriving its key when the system prepares to sleep fails with `{"ok": false, "status": "locked", "error": "The system went to sleep during unlock. Unlock again."}` and leaves the vault locked; the same error is returned for an unlock attempted between `PrepareForSleep(true)` and the resume. Quick unlock (`quick_unlock` config, default `false`) is the only way a key survives a screen or idle lock.
- **Clipboard on lock**: no lock clears the clipboard. Every lock withdraws the clipboard offers the daemon still serves (from `copy_field`, from `copy` with `sensitive: true` and a non-zero timeout, and an active `copy_sequence`); an offer another application has replaced has already ended, and that application's content is left alone. Non-sensitive copies without an auto-clear are not withdrawn.

### 3.7 Recent use (ADR 0029)

- **What counts as a use**: a successful `copy_field` of any field of the item (one use), and a successful `copy_sequence` (one use per sequence, not per field). Recorded only after the clipboard write succeeded or the sequence started. `reveal_field`, `copy` (caller-supplied text), refused or failed requests and refunded releases never count. `omawarden copy <id-or-name>` counts because it releases through `copy_field`.
- **Score**: `usage_score = Σ 0.5 ^ ((now − t) / 7 days)` over the item's kept use timestamps `t`, rounded to 3 decimals. A use counts 1.0 when it happens, 0.5 a week later, 0.25 after two weeks. Sorting by `usage_score` descending ranks items copied often and lately first. A timestamp in the future (clock moved back) counts 1.0.
- **Kept uses**: at most the **20** most recent per item; uses older than **90 days** are dropped on every write and when the daemon starts.
- **Storage**: `usage.json` in the directory of the vault cache (`data.json`), mode `0600`, directory `0700`, written atomically. Content: `{"version": 1, "items": {"<item id>": [<Unix seconds>, …]}}`, ascending per item. Item ids and timestamps only; never names, URIs or secret values. A file that cannot be read or parsed is treated as empty; a failed write is logged as a warning and never fails the copy.
- **Lifecycle**: a successful `sync` removes the entries of items no longer in the vault. Locking (hard, soft, idle, suspend, budget) keeps the record. Logout (`omawarden auth logout`) and a server change delete it: logout sends `{"action": "clear_item_usage"}` (accepted while locked; response `{"ok": true}`) so the daemon forgets its in-memory table and deletes the file, and removes the file itself when no daemon answers.

### 3.6 CLI commands for the overlay

All print JSON on stdout and exit non-zero when `ok` is false.

| Command | Output |
|---------|--------|
| `omawarden vault list [--filter <type_name>]` | array of redacted items, favorites first |
| `omawarden vault search --query <q> [--filter <type_name>]` | array of redacted items, best match first |
| `omawarden vault reveal --id <id> --field <identifier>` | the `reveal_field` response, unchanged |
| `omawarden vault copy-field --id <id> --field <identifier> [--clear-after <s>]` | the `copy_field` response, unchanged |
| `omawarden vault copy-sequence --id <id> --fields <identifier>,<identifier>[,…] [--clear-after <s>]` | the `copy_sequence` response, unchanged; returns once the first field is on the clipboard |
| `omawarden totp <id>` | `{"ok": true, "code", "ttl", "period", "id", "name"}` (a budgeted `login.totp` release) |
| `omawarden copy --stdin [--sensitive] [--timeout <s>]` with `{"text": "…"}` on stdin | for **non-secret** text only: usernames, URIs, and generated passwords (always with `--sensitive`) |
| `omawarden copy <id-or-name> [--password\|--totp\|--notes\|--public-key\|--private-key]` | `{"ok": true, "name", "copied", "timeout"}`; secrets are copied by the daemon (`copy_field`) |

`vault reveal`, `vault copy-field` and `vault copy-sequence` never read stdin. `copy <query>` and `totp <query>` read a master password from stdin only when the daemon is locked, and then unlock the daemon rather than decrypting locally.
