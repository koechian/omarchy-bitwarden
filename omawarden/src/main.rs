use clap::{Parser, Subcommand};
use omawarden::auth::AuthManager;
use omawarden::clipboard::ClipboardManager;
use omawarden::config::{ConfigManager, ConfigUpdateOptions};
use omawarden::daemon::{run_daemon_server, send_daemon_request, DaemonState};
use omawarden::health::check_system_health;
use omawarden::hook::install_lock_hook;
use omawarden::keyring::KeyringManager;
use omawarden::storage::StorageManager;
use omawarden::totp::generate_totp;
use omawarden::vault::VaultManager;
use serde_json::{json, Value};
use std::io::{self, BufRead, IsTerminal, Read, Write};
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use zeroize::Zeroizing;

/// Strict boolean for CLI flags: anything outside true/false/1/0/yes/no is a
/// parse error instead of silently becoming `false`. `--quick-unlock ture`
/// used to report success, persist `quick_unlock: false` and immediately
/// wipe the retained key.
fn parse_cli_bool(v: &str) -> Result<bool, String> {
    match v.trim().to_lowercase().as_str() {
        "true" | "1" | "yes" => Ok(true),
        "false" | "0" | "no" => Ok(false),
        other => Err(format!(
            "invalid boolean '{other}': expected one of true|false|1|0|yes|no"
        )),
    }
}

/// Auth output can carry a raw access token in `session`. Piped callers (the
/// QML helper) depend on it; an interactive terminal would only leave it
/// behind in scrollback, so redact it there.
fn print_json_redacting_session<T: serde::Serialize>(value: &T) {
    let mut val = serde_json::to_value(value).unwrap_or(Value::Null);
    if io::stdout().is_terminal() {
        if let Some(session) = val.get("session").and_then(Value::as_str) {
            if !session.is_empty() {
                val["session"] = json!("[redacted; pipe stdout to keep the token]");
            }
        }
    }
    println!("{}", serde_json::to_string_pretty(&val).unwrap());
}

#[derive(Parser)]
#[command(
    name = "omawarden",
    version = concat!(env!("CARGO_PKG_VERSION"), " (", env!("GIT_HASH"), " ", env!("BUILD_DATE"), ")"),
    about = "High-performance helper CLI and daemon for Omarchy Bitwarden Plugin"
)]
struct Cli {
    #[arg(long, value_name = "CONFIG_PATH", help = "Path to config.json")]
    config: Option<PathBuf>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
#[allow(clippy::large_enum_variant)]
enum Commands {
    #[command(about = "Manage configuration")]
    Config {
        #[command(subcommand)]
        action: ConfigAction,
    },
    #[command(about = "Check CLI health and installation")]
    Health,
    #[command(about = "Manage Bitwarden authentication and vault sessions")]
    Auth {
        #[command(subcommand)]
        action: AuthAction,
    },
    #[command(about = "Manage system integration hooks")]
    Hook {
        #[command(subcommand)]
        action: HookAction,
    },
    #[command(about = "Vault sync and search operations")]
    Vault {
        #[command(subcommand)]
        action: VaultAction,
    },
    #[command(
        about = "Wayland clipboard operations (copy vault item field, pipe stdin, or clear)"
    )]
    Copy {
        #[arg(index = 1, help = "Vault item ID or name query")]
        query: Option<String>,
        #[arg(long, help = "Clear Wayland clipboard immediately")]
        clear: bool,
        #[arg(long, help = "Read text to copy from standard input")]
        stdin: bool,
        #[arg(long, help = "Mark STDIN text as sensitive with auto-clear")]
        sensitive: bool,
        #[arg(long, help = "Copy password (default for login items)")]
        password: bool,
        #[arg(long, help = "Copy username")]
        username: bool,
        #[arg(long, help = "Copy TOTP code")]
        totp: bool,
        #[arg(long, help = "Copy notes")]
        notes: bool,
        #[arg(long, help = "Copy card security code")]
        private_key: bool,
        #[arg(long, help = "Copy card number")]
        public_key: bool,
        #[arg(long, help = "Auto-clear timeout in seconds (default: config value)")]
        timeout: Option<i64>,
        #[arg(
            long,
            hide = true,
            help = "Internal worker: clear clipboard after specified seconds"
        )]
        clear_after: Option<u64>,
        #[arg(
            long,
            hide = true,
            help = "Internal worker: PID of the wl-copy process serving the offer"
        )]
        owner_pid: Option<u32>,
        #[arg(
            long,
            hide = true,
            help = "Internal worker: start time of the wl-copy process serving the offer"
        )]
        owner_start_time: Option<u64>,
    },
    #[command(about = "Generate TOTP verification code from vault item ID/name, or via STDIN")]
    Totp {
        #[arg(
            index = 1,
            help = "Vault item ID or name query in the vault (use --stdin to pipe raw secrets/URIs)"
        )]
        query: Option<String>,
        #[arg(
            long,
            help = "Read secret, otpauth URI, or query JSON from standard input"
        )]
        stdin: bool,
        #[arg(long, help = "Copy generated code directly to clipboard")]
        copy: bool,
    },
    #[command(about = "Run omawarden background daemon")]
    Daemon {
        #[arg(long)]
        auto_lock: Option<u64>,
    },
    #[command(about = "Generate cryptographically secure passwords or Diceware passphrases")]
    Generate {
        #[arg(
            short = 'l',
            long,
            default_value = "20",
            help = "Length of the generated password (5-128, recommended: 14+)"
        )]
        length: usize,
        #[arg(long, help = "Do not include uppercase letters")]
        no_uppercase: bool,
        #[arg(long, help = "Do not include lowercase letters")]
        no_lowercase: bool,
        #[arg(long, help = "Do not include numbers")]
        no_numbers: bool,
        #[arg(long, help = "Do not include special symbols")]
        no_special: bool,
        #[arg(
            long,
            help = "Avoid visually ambiguous characters (0, O, o, 1, l, I, |)"
        )]
        avoid_ambiguous: bool,
        #[arg(long, default_value = "1", help = "Minimum number of numeric digits")]
        min_numbers: usize,
        #[arg(
            long,
            default_value = "1",
            help = "Minimum number of special characters"
        )]
        min_special: usize,
        #[arg(
            short = 'p',
            long,
            help = "Generate a Diceware passphrase instead of a character password"
        )]
        passphrase: bool,
        #[arg(
            short = 'w',
            long,
            default_value = "4",
            help = "Number of words in the passphrase (3-20)"
        )]
        words: usize,
        #[arg(
            short = 's',
            long,
            default_value = "-",
            help = "Word separator for passphrase"
        )]
        separator: String,
        #[arg(long, help = "Capitalize each word in the passphrase")]
        capitalize: bool,
        #[arg(
            short = 'c',
            long,
            help = "Copy generated secret to Wayland clipboard with auto-clear"
        )]
        copy: bool,
        #[arg(long, help = "Output generated secret as JSON")]
        json: bool,
    },
}

#[derive(Subcommand)]
#[allow(clippy::large_enum_variant)]
enum ConfigAction {
    #[command(about = "Get current configuration or a specific key")]
    Get {
        #[arg(help = "Optional configuration key to query")]
        key: Option<String>,
    },
    #[command(about = "Set configuration options")]
    Set {
        #[arg(long)]
        server_url: Option<String>,
        #[arg(long)]
        identity_url: Option<String>,
        #[arg(long)]
        auto_lock: Option<i64>,
        #[arg(long)]
        clipboard_clear: Option<i64>,
        #[arg(long)]
        email: Option<String>,
        #[arg(long)]
        remember_email: Option<String>,
        #[arg(long)]
        log_level: Option<String>,
        #[arg(long)]
        remember_last_search: Option<String>,
        #[arg(
            long,
            help = "Path to client certificate PEM file for mTLS (pass \"\" to clear)"
        )]
        client_cert: Option<String>,
        #[arg(long, help = "Path to separate client private key PEM file for mTLS")]
        client_key: Option<String>,
        #[arg(
            long,
            value_parser = parse_cli_bool,
            help = "Unlock via system authentication after a soft lock (true/false; ADR-0025)"
        )]
        quick_unlock: Option<bool>,
    },
}

#[derive(Subcommand)]
enum AuthAction {
    #[command(about = "Get current authentication and vault lock status")]
    Status,
    #[command(about = "Login using Master Password (credentials read from stdin)")]
    LoginPassword {
        #[arg(long, required = true)]
        email: String,
        #[arg(
            long,
            num_args = 0..=1,
            default_missing_value = "true",
            help = "Remember email address in configuration"
        )]
        remember_email: Option<String>,
    },
    #[command(about = "Login using API Key (client_secret read from stdin)")]
    LoginApikey {
        #[arg(long, required = true)]
        client_id: String,
    },
    #[command(
        about = "Send or resend two-factor verification code to email (password read from stdin)"
    )]
    SendTwoFactorEmail {
        #[arg(long, required = true)]
        email: String,
    },
    #[command(about = "Check current FIDO2 / WebAuthn environment and device status")]
    Fido2Status,
    #[command(about = "Unlock vault with master password (password read from stdin)")]
    Unlock,
    #[command(about = "Unlock vault via system authentication, polkit-backed (ADR-0025)")]
    QuickUnlock,
    #[command(about = "Report whether quick unlock is enabled and a retained key is available")]
    QuickUnlockCheck,
    #[command(about = "Lock vault and clear session")]
    Lock,
    #[command(about = "Logout from Bitwarden account")]
    Logout,
}

#[derive(Subcommand)]
enum HookAction {
    #[command(
        about = "Install optional system-lock hook into Omarchy hooks directory (daemon also auto-detects locks natively)"
    )]
    Install,
}

#[derive(Subcommand)]
enum VaultAction {
    #[command(about = "Sync vault from Bitwarden server")]
    Sync,
    #[command(about = "List all vault items")]
    List {
        #[arg(long = "filter")]
        category: Option<String>,
    },
    #[command(about = "Search vault items")]
    Search {
        #[arg(long, default_value = "")]
        query: String,
        #[arg(long = "filter")]
        category: Option<String>,
    },
    #[command(about = "Print one secret field of one item (counted against the release budget)")]
    Reveal {
        #[arg(long, help = "Vault item ID")]
        id: String,
        #[arg(
            long,
            help = "login.password, login.totp, notes, card.number, card.code, identity.ssn, identity.passport_number, identity.license_number, custom.<index> or password_history"
        )]
        field: String,
    },
    #[command(
        about = "Copy one secret field of one item to the clipboard from the daemon (counted against the release budget)"
    )]
    CopyField {
        #[arg(long, help = "Vault item ID")]
        id: String,
        #[arg(
            long,
            help = "Field identifier, as for 'vault reveal' (except password_history)"
        )]
        field: String,
        #[arg(long, help = "Seconds until the clipboard is cleared (1-3600)")]
        clear_after: Option<u64>,
    },
    #[command(
        about = "Stage several secret fields of one item on the clipboard from the daemon, one per paste, in order (counted against the release budget, one release per field)"
    )]
    CopySequence {
        #[arg(long, help = "Vault item ID")]
        id: String,
        #[arg(
            long,
            value_delimiter = ',',
            num_args = 1..,
            required = true,
            help = "Comma-separated field identifiers in paste order, as for 'vault copy-field' (for example login.password,login.totp)"
        )]
        fields: Vec<String>,
        #[arg(
            long,
            help = "Seconds until any stage not yet pasted is withdrawn from the clipboard (1-3600)"
        )]
        clear_after: Option<u64>,
    },
}

fn read_secret_stdin() -> String {
    let stdin = io::stdin();
    if stdin.is_terminal() {
        return String::new();
    }
    let mut buffer = String::new();
    if stdin.lock().read_line(&mut buffer).is_ok() {
        return buffer.trim_end_matches(&['\r', '\n'][..]).to_string();
    }
    String::new()
}

fn read_clipboard_stdin() -> String {
    let stdin = io::stdin();
    let mut raw = String::new();
    if stdin.lock().read_line(&mut raw).is_ok() {
        let trimmed = raw.trim_end_matches(&['\r', '\n'][..]);
        if let Ok(val) = serde_json::from_str::<Value>(trimmed) {
            if let Some(text) = val.get("text").and_then(|v| v.as_str()) {
                return text.to_string();
            }
        }
        let mut rest = String::new();
        let _ = stdin.lock().read_to_string(&mut rest);
        if rest.is_empty() {
            return trimmed.to_string();
        } else {
            return format!("{}{}", raw, rest);
        }
    }
    String::new()
}

/// Master password, 2FA code, 2FA provider, new-device OTP.
type AuthPayload = (
    Zeroizing<String>,
    Option<String>,
    Option<i32>,
    Option<String>,
);

fn empty_auth_payload() -> AuthPayload {
    (Zeroizing::new(String::new()), None, None, None)
}

fn parse_two_factor_provider(value: &Value) -> Option<i32> {
    if let Some(number) = value.as_i64() {
        return Some(number as i32);
    }
    value.as_str().and_then(|text| text.parse::<i32>().ok())
}

fn parse_auth_payload_object(map: &serde_json::Map<String, Value>) -> AuthPayload {
    let password = Zeroizing::new(
        map.get("password")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
    );
    let code = map
        .get("code")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let two_factor_provider = map
        .get("two_factor_provider")
        .or_else(|| map.get("twoFactorProvider"))
        .or_else(|| map.get("provider"))
        .and_then(parse_two_factor_provider);
    let new_device_otp = map
        .get("new_device_otp")
        .or_else(|| map.get("newDeviceOtp"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    (password, code, two_factor_provider, new_device_otp)
}

/// A plain-text password, unquoted when it was sent as a JSON string.
fn parse_plain_password(trimmed: &str) -> Zeroizing<String> {
    let quoted = trimmed.len() >= 2 && trimmed.starts_with('"') && trimmed.ends_with('"');
    if quoted {
        if let Ok(unescaped) = serde_json::from_str::<String>(trimmed) {
            return Zeroizing::new(unescaped);
        }
    }
    Zeroizing::new(trimmed.to_string())
}

/// Parses the stdin authentication payload: a JSON object with `password`
/// and optional 2FA fields, or the password as plain text. The parsed JSON
/// is zeroized before it is dropped because it holds the master password.
fn parse_auth_payload(raw: &str) -> AuthPayload {
    let trimmed = raw.trim_end_matches(&['\r', '\n'][..]).trim();
    if trimmed.is_empty() {
        return empty_auth_payload();
    }
    if let Ok(mut value) = serde_json::from_str::<Value>(trimmed) {
        let parsed = value.as_object().map(parse_auth_payload_object);
        omawarden::secret_memory::zeroize_json_value(&mut value);
        if let Some(payload) = parsed {
            return payload;
        }
    }
    (parse_plain_password(trimmed), None, None, None)
}

fn read_auth_payload() -> AuthPayload {
    let stdin = io::stdin();
    if stdin.is_terminal() {
        return empty_auth_payload();
    }
    let mut buffer = Zeroizing::new(String::new());
    if stdin.lock().read_line(&mut buffer).is_err() {
        return empty_auth_payload();
    }
    parse_auth_payload(&buffer)
}

/// Reads the master password from the terminal prompt, or the first line of
/// stdin when it is not a terminal, into memory that is zeroized on drop.
fn read_master_password() -> Zeroizing<String> {
    let stdin = io::stdin();
    if stdin.is_terminal() {
        return Zeroizing::new(
            rpassword::prompt_password("Enter Master Password: ").unwrap_or_default(),
        );
    }
    let mut buffer = Zeroizing::new(String::new());
    if stdin.lock().read_line(&mut buffer).is_err() {
        return Zeroizing::new(String::new());
    }
    while buffer.ends_with(['\r', '\n']) {
        buffer.pop();
    }
    buffer
}

fn print_pretty(value: &Value) {
    println!("{}", serde_json::to_string_pretty(value).unwrap());
}

fn print_failure(message: &str) -> ExitCode {
    print_pretty(&json!({ "ok": false, "error": message }));
    ExitCode::FAILURE
}

fn response_succeeded(response: &Value) -> bool {
    response.get("ok").and_then(Value::as_bool) == Some(true)
}

fn response_error(response: &Value) -> String {
    response
        .get("error")
        .and_then(Value::as_str)
        .unwrap_or("The omawarden daemon rejected the request.")
        .to_string()
}

const DAEMON_UNAVAILABLE: &str = "omawarden daemon is not running.";

fn daemon_reports_unlocked() -> bool {
    send_daemon_request(&json!({ "action": "status" }))
        .and_then(|status| status.get("is_unlocked").and_then(Value::as_bool))
        .unwrap_or(false)
}

/// Unlocks the daemon with a master password from stdin when it is locked,
/// so scripted callers (`echo pw | omawarden copy …`) keep working. The
/// secret is then released by the daemon, never decrypted by the CLI.
fn ensure_daemon_unlocked() -> Result<(), String> {
    if daemon_reports_unlocked() {
        return Ok(());
    }
    let (password, ..) = read_auth_payload();
    if password.is_empty() {
        return Err("Vault is locked. Please unlock the vault first using 'omawarden auth unlock' or provide Master Password.".to_string());
    }
    let response = omawarden::daemon::send_unlock_request(&password)
        .ok_or_else(|| DAEMON_UNAVAILABLE.to_string())?;
    if response_succeeded(&response) {
        return Ok(());
    }
    Err(response_error(&response))
}

/// Resolves an item ID or name to its redacted view through the daemon.
fn resolve_redacted_item(query: &str) -> Result<Value, String> {
    omawarden::daemon::ensure_daemon_running();
    ensure_daemon_unlocked()?;
    let response = send_daemon_request(&json!({ "action": "get_item", "query": query }))
        .ok_or_else(|| DAEMON_UNAVAILABLE.to_string())?;
    if !response_succeeded(&response) {
        return Err(response_error(&response));
    }
    response
        .get("item")
        .cloned()
        .ok_or_else(|| format!("Item '{}' not found in vault", query))
}

fn item_text<'a>(item: &'a Value, key: &str) -> &'a str {
    item.get(key).and_then(Value::as_str).unwrap_or("")
}

/// Sends `reveal_field` or `copy_field` for one field of one item. These
/// releases are counted by the daemon's release budget (ADR 0027).
fn request_field_release(
    action: &str,
    item_id: &str,
    field: &str,
    clear_after_seconds: Option<u64>,
) -> Result<Value, String> {
    let mut request = json!({ "action": action, "id": item_id, "field": field });
    if let Some(seconds) = clear_after_seconds {
        request["clear_after_seconds"] = json!(seconds);
    }
    let response = send_daemon_request(&request).ok_or_else(|| DAEMON_UNAVAILABLE.to_string())?;
    if response_succeeded(&response) {
        return Ok(response);
    }
    Err(response_error(&response))
}

/// Which field `omawarden copy` copies.
#[derive(Debug, PartialEq)]
enum CopyTarget {
    /// Not a secret: copied by the CLI itself without the sensitive hint.
    Username,
    /// A secret: copied by the daemon through `copy_field`.
    Secret {
        field: &'static str,
        label: &'static str,
    },
}

/// The flags of `omawarden copy` that choose a field.
#[derive(Debug, Default)]
struct CopySelection {
    password: bool,
    username: bool,
    totp: bool,
    notes: bool,
    card_code: bool,
    card_number: bool,
}

fn default_copy_target(type_name: &str) -> CopyTarget {
    match type_name {
        "card" => CopyTarget::Secret {
            field: "card.number",
            label: "card_number",
        },
        "note" => CopyTarget::Secret {
            field: "notes",
            label: "notes",
        },
        _ => CopyTarget::Secret {
            field: "login.password",
            label: "password",
        },
    }
}

/// The explicitly flagged field (first flag wins, in the historical order),
/// or the default field of the item type.
fn select_copy_target(selection: &CopySelection, type_name: &str) -> CopyTarget {
    if selection.username {
        return CopyTarget::Username;
    }
    let flagged = [
        (selection.totp, "login.totp", "totp"),
        (selection.notes, "notes", "notes"),
        (selection.card_number, "card.number", "public_key"),
        (selection.card_code, "card.code", "private_key"),
        (selection.password, "login.password", "password"),
    ];
    flagged
        .iter()
        .find(|(chosen, ..)| *chosen)
        .map(|(_, field, label)| CopyTarget::Secret { field, label })
        .unwrap_or_else(|| default_copy_target(type_name))
}

/// The username of a redacted item: login username, then identity
/// username, then identity email.
fn redacted_username(item: &Value) -> String {
    [
        ("login", "username"),
        ("identity", "username"),
        ("identity", "email"),
    ]
    .iter()
    .find_map(|(section, key)| item.get(*section)?.get(*key)?.as_str())
    .unwrap_or_default()
    .to_string()
}

fn copy_username(item: &Value, clip_mgr: &ClipboardManager, timeout_val: i64) -> ExitCode {
    let name = item_text(item, "name");
    let username = redacted_username(item);
    if username.is_empty() {
        return print_failure(&format!("Field 'username' is empty for item '{}'", name));
    }
    if !clip_mgr.copy(&username, false, timeout_val) {
        return print_failure("Failed to copy content to clipboard");
    }
    print_pretty(&json!({ "ok": true, "name": name, "copied": "username", "timeout": 0 }));
    ExitCode::SUCCESS
}

fn copy_secret_field(item: &Value, field: &str, label: &str, timeout_val: i64) -> ExitCode {
    let clear_after = u64::try_from(timeout_val)
        .ok()
        .filter(|seconds| omawarden::secret_access::COPY_CLEAR_SECONDS_RANGE.contains(seconds));
    match request_field_release("copy_field", item_text(item, "id"), field, clear_after) {
        Ok(response) => {
            print_pretty(&json!({
                "ok": true,
                "name": item_text(item, "name"),
                "copied": label,
                "timeout": response.get("clear_after_seconds").cloned().unwrap_or(json!(0)),
            }));
            ExitCode::SUCCESS
        }
        Err(error) => print_failure(&error),
    }
}

/// `omawarden copy <query>`: secrets are copied by the daemon itself.
fn copy_item_field(
    query: Option<String>,
    selection: CopySelection,
    timeout_val: i64,
    clip_mgr: &ClipboardManager,
) -> ExitCode {
    let Some(query) = query.filter(|q| !q.trim().is_empty()) else {
        return print_failure(
            "Missing item query or action flag (--clear / --stdin). See 'omawarden copy --help'.",
        );
    };
    let item = match resolve_redacted_item(&query) {
        Ok(item) => item,
        Err(error) => return print_failure(&error),
    };
    match select_copy_target(&selection, item_text(&item, "type_name")) {
        CopyTarget::Username => copy_username(&item, clip_mgr, timeout_val),
        CopyTarget::Secret { field, label } => copy_secret_field(&item, field, label, timeout_val),
    }
}

/// Hidden `copy --clear-after` worker: at the deadline, withdraws the
/// clipboard offer served by the given wl-copy process if that exact process
/// is still running (it exits by itself when another client takes the
/// selection), so content copied elsewhere in the meantime is never cleared.
fn run_clipboard_clear_worker(
    secs: u64,
    owner_pid: Option<u32>,
    owner_start_time: Option<u64>,
) -> ExitCode {
    let (Some(pid), Some(start_time)) = (owner_pid, owner_start_time) else {
        return ExitCode::SUCCESS;
    };
    std::thread::sleep(std::time::Duration::from_secs(secs));
    omawarden::clipboard::withdraw_offer_if_still_owned(omawarden::clipboard::OfferOwner {
        pid,
        start_time,
    });
    ExitCode::SUCCESS
}

/// The parsed `omawarden copy` invocation (worker flags excluded).
struct CopyCommand {
    query: Option<String>,
    clear: bool,
    stdin: bool,
    sensitive: bool,
    selection: CopySelection,
    timeout_val: i64,
}

fn exit_code_for(ok: bool) -> ExitCode {
    if ok {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

/// `omawarden copy`: clear the clipboard, copy stdin text the caller
/// supplies, or copy one field of a vault item (secrets via the daemon).
fn run_copy_command(request: CopyCommand) -> ExitCode {
    let clip_mgr = ClipboardManager::default();
    if !clip_mgr.is_available() {
        return print_failure(
            "Wayland clipboard utility 'wl-copy' not found. Please install 'wl-clipboard'.",
        );
    }
    if request.clear {
        let ok = clip_mgr.clear();
        print_pretty(&json!({ "ok": ok }));
        return exit_code_for(ok);
    }
    if request.stdin {
        let text_val = read_clipboard_stdin();
        let ok = clip_mgr.copy(&text_val, request.sensitive, request.timeout_val);
        print_pretty(&json!({
            "ok": ok,
            "copied": "stdin",
            "timeout": if request.sensitive { request.timeout_val } else { 0 }
        }));
        return exit_code_for(ok);
    }
    omawarden::daemon::ensure_daemon_running();
    copy_item_field(
        request.query,
        request.selection,
        request.timeout_val,
        &clip_mgr,
    )
}

/// A TOTP code and, for a vault item, its (id, name).
type TotpOutcome = (omawarden::totp::TotpResult, Option<(String, String)>);

/// Where `omawarden totp` takes its code from.
#[derive(Debug, PartialEq)]
enum TotpSource {
    Seed(String),
    Item(String),
    Missing,
}

fn totp_source_from_stdin(stdin_val: String) -> TotpSource {
    if stdin_val.is_empty() {
        return TotpSource::Missing;
    }
    let Ok(value) = serde_json::from_str::<Value>(&stdin_val) else {
        return TotpSource::Seed(stdin_val);
    };
    if let Some(secret) = value.get("secret").and_then(Value::as_str) {
        return TotpSource::Seed(secret.to_string());
    }
    match value
        .get("query")
        .or_else(|| value.get("id"))
        .and_then(Value::as_str)
    {
        Some(query) => TotpSource::Item(query.to_string()),
        None => TotpSource::Seed(stdin_val),
    }
}

fn seed_totp(seed: &str) -> Option<TotpOutcome> {
    generate_totp(seed, None, 6, 30).map(|result| (result, None))
}

/// The current code of an item, released through `reveal_field`.
fn item_totp(query: &str) -> Result<TotpOutcome, String> {
    let item = resolve_redacted_item(query)?;
    let id = item_text(&item, "id").to_string();
    let response = request_field_release("reveal_field", &id, "login.totp", None)?;
    let result = omawarden::totp::TotpResult {
        code: item_text(&response, "value").to_string(),
        ttl: response
            .get("seconds_remaining")
            .and_then(Value::as_u64)
            .unwrap_or(30),
        period: response.get("period").and_then(Value::as_u64).unwrap_or(30),
    };
    Ok((result, Some((id, item_text(&item, "name").to_string()))))
}

/// Item lookup first; an argument that names no item is tried as a seed,
/// as before.
fn item_or_seed_totp(query: &str) -> Option<TotpOutcome> {
    item_totp(query).ok().or_else(|| seed_totp(query))
}

fn print_totp_outcome(outcome: TotpOutcome, copy: bool, clip_mgr: &ClipboardManager) -> ExitCode {
    let (result, item_info) = outcome;
    let copied = copy && clip_mgr.copy(&result.code, true, 30);
    let mut resp = json!({
        "ok": !copy || copied,
        "code": result.code,
        "ttl": result.ttl,
        "period": result.period,
    });
    if copy {
        resp["copied"] = json!(true);
    }
    if let Some((id, name)) = item_info {
        resp["id"] = json!(id);
        resp["name"] = json!(name);
    }
    print_pretty(&resp);
    if !copy || copied {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

fn is_otpauth_uri(text: &str) -> bool {
    text.starts_with("otpauth://") || text.starts_with("otpauth-migration://")
}

/// `omawarden totp`: from a seed on stdin, or from a vault item whose code
/// is released by the daemon through `reveal_field` (budgeted).
fn run_totp_command(query: Option<String>, stdin: bool, copy: bool) -> ExitCode {
    let clip_mgr = ClipboardManager::default();
    let source = match query.filter(|_| !stdin) {
        Some(q) if is_otpauth_uri(&q) => {
            eprintln!(
                "Error: Passing otpauth URIs or secrets in CLI arguments is forbidden (violates Zero-Argv security policy).\nPipe secret via STDIN instead: echo '<otpauth_uri>' | omawarden totp --stdin"
            );
            return ExitCode::FAILURE;
        }
        Some(q) => {
            omawarden::daemon::ensure_daemon_running();
            return match item_or_seed_totp(&q) {
                Some(outcome) => print_totp_outcome(outcome, copy, &clip_mgr),
                None => {
                    print_failure("Failed to generate TOTP: item not found or secret is invalid")
                }
            };
        }
        None => totp_source_from_stdin(read_secret_stdin()),
    };
    let outcome = match source {
        TotpSource::Seed(seed) => seed_totp(&seed),
        TotpSource::Item(q) => item_totp(&q).ok(),
        TotpSource::Missing => None,
    };
    match outcome {
        Some(outcome) => print_totp_outcome(outcome, copy, &clip_mgr),
        None => print_failure("Failed to generate TOTP: item not found or secret is invalid"),
    }
}

/// `vault sync`: through the daemon, or directly when no daemon answers.
fn run_vault_sync(cfg: &omawarden::config::Config) -> ExitCode {
    let client_ctx = omawarden::api::resolve_effective_client_context(None);
    omawarden::daemon::ensure_daemon_running();
    let mut sync_req = json!({ "action": "sync" });
    if let Some(ref ctx) = client_ctx {
        sync_req["client"] = json!(ctx);
    }
    if let Some(response) = send_daemon_request(&sync_req) {
        print_pretty(&response);
        return exit_code_for(response_succeeded(&response));
    }
    let vault_mgr =
        VaultManager::with_identity_url(&cfg.server_url, cfg.identity_url.as_deref(), None, None);
    match vault_mgr.sync_with_client(client_ctx.as_ref()) {
        Ok(_) => {
            if let Ok(storage) = vault_mgr.storage.read() {
                omawarden::item_usage::retain_vault_items_on_disk(
                    &vault_mgr.storage_mgr.file_path,
                    &storage,
                );
            }
            print_pretty(&json!({ "ok": true }));
            ExitCode::SUCCESS
        }
        Err(e) => print_failure(&e),
    }
}

/// `vault reveal` / `vault copy-field`: prints the daemon's response to
/// `reveal_field` / `copy_field` unchanged. Never reads stdin, so a caller
/// that leaves stdin open is not blocked; a locked vault is reported as the
/// daemon's `vault_locked` error.
fn run_field_release(action: &str, id: &str, field: &str, clear_after: Option<u64>) -> ExitCode {
    let request = json!({ "action": action, "id": id, "field": field });
    run_release_request(request, clear_after)
}

/// `vault copy-sequence`: prints the daemon's response to `copy_sequence`
/// unchanged. The daemon answers once the first field is on the clipboard;
/// the later fields are staged by the daemon as the user pastes.
fn run_sequence_release(id: &str, fields: &[String], clear_after: Option<u64>) -> ExitCode {
    let request = json!({ "action": "copy_sequence", "id": id, "fields": fields });
    run_release_request(request, clear_after)
}

/// Sends a release request with the optional `clear_after_seconds` and
/// prints the daemon's response unchanged.
fn run_release_request(mut request: Value, clear_after: Option<u64>) -> ExitCode {
    omawarden::daemon::ensure_daemon_running();
    if let Some(seconds) = clear_after {
        request["clear_after_seconds"] = json!(seconds);
    }
    let Some(mut response) = send_daemon_request(&request) else {
        return print_failure(DAEMON_UNAVAILABLE);
    };
    let text = Zeroizing::new(serde_json::to_string_pretty(&response).unwrap());
    println!("{}", text.as_str());
    let ok = response_succeeded(&response);
    omawarden::secret_memory::zeroize_json_value(&mut response);
    exit_code_for(ok)
}

fn run_vault_command(action: VaultAction, cfg: &omawarden::config::Config) -> ExitCode {
    match action {
        VaultAction::Sync => run_vault_sync(cfg),
        VaultAction::List { category } => {
            run_vault_listing(json!({ "action": "list", "category": category }))
        }
        VaultAction::Search { query, category } => run_vault_listing(json!({
            "action": "search",
            "query": query,
            "category": category
        })),
        VaultAction::Reveal { id, field } => run_field_release("reveal_field", &id, &field, None),
        VaultAction::CopyField {
            id,
            field,
            clear_after,
        } => run_field_release("copy_field", &id, &field, clear_after),
        VaultAction::CopySequence {
            id,
            fields,
            clear_after,
        } => run_sequence_release(&id, &fields, clear_after),
    }
}

/// `vault list` / `vault search`: prints the daemon's redacted items.
fn run_vault_listing(request: Value) -> ExitCode {
    omawarden::daemon::ensure_daemon_running();
    let Some(response) = send_daemon_request(&request) else {
        return print_failure(
            "Vault is locked. Please unlock using 'omawarden auth unlock' first.",
        );
    };
    print_pretty(&response);
    if response.get("ok") == Some(&Value::Bool(false)) {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

/// `config set --auto-lock` must be inside the daemon's accepted range.
fn validate_auto_lock_option(minutes: Option<i64>) -> Result<(), String> {
    let Some(minutes) = minutes else {
        return Ok(());
    };
    let seconds = u64::try_from(minutes).unwrap_or(0).saturating_mul(60);
    omawarden::daemon_actions::validate_auto_lock(seconds).map(|_| ())
}

fn main() -> ExitCode {
    // Disable process tracing (ptrace) and core dump generation for memory
    // defense. Fail-open is accepted (a desktop helper should not refuse to
    // run over prctl), but never silently: without this the whole process
    // stays ptraceable and core-dumpable.
    if let Err(e) = omawarden::locked::disable_dumpable() {
        omawarden::log_error!(
            "omawarden:locked",
            "Could not disable ptrace/core dumps (prctl PR_SET_DUMPABLE: {e}); tracing protections are INACTIVE for this process"
        );
    }

    let cli = Cli::parse();
    let config_mgr = ConfigManager::new(cli.config.as_deref());
    let mut cfg = match config_mgr.try_load() {
        Ok(cfg) => cfg,
        Err(e) => {
            eprintln!("{}", e);
            return ExitCode::FAILURE;
        }
    };

    match cli.command {
        Commands::Daemon { auto_lock } => {
            let default_auto_lock = if cfg.auto_lock_minutes >= 0 {
                cfg.auto_lock_minutes as u64
            } else {
                15
            };
            let auto_lock_mins = auto_lock.unwrap_or(default_auto_lock);
            let storage_mgr = match cli.config.as_deref() {
                Some(cp) => {
                    if let Some(parent) = cp.parent() {
                        StorageManager::new(
                            parent.join(omawarden::storage::DEFAULT_STORAGE_FILENAME),
                        )
                    } else {
                        StorageManager::default()
                    }
                }
                None => StorageManager::default(),
            };
            let state = Arc::new(DaemonState::new(storage_mgr, auto_lock_mins));
            println!(
                "Starting omawarden daemon (auto_lock: {}m)...",
                auto_lock_mins
            );
            if let Err(e) = run_daemon_server(state) {
                eprintln!("Daemon server error: {}", e);
                ExitCode::FAILURE
            } else {
                ExitCode::SUCCESS
            }
        }

        Commands::Config { action } => match action {
            ConfigAction::Get { key } => {
                if let Some(k) = key {
                    match k.as_str() {
                        "server_url" => println!("{}", cfg.server_url),
                        "identity_url" => println!("{}", cfg.identity_url.as_deref().unwrap_or("")),
                        "auto_lock_minutes" | "auto_lock" => println!("{}", cfg.auto_lock_minutes),
                        "clipboard_clear_seconds" | "clipboard_clear" => {
                            println!("{}", cfg.clipboard_clear_seconds)
                        }
                        "email" => println!("{}", cfg.email),
                        "remember_email" => println!("{}", cfg.remember_email),
                        "log_level" => println!("{}", cfg.log_level),
                        "remember_last_search" => println!("{}", cfg.remember_last_search),
                        "client_cert_path" | "client_cert" => {
                            println!("{}", cfg.client_cert_path.as_deref().unwrap_or(""))
                        }
                        "client_key_path" | "client_key" => {
                            println!("{}", cfg.client_key_path.as_deref().unwrap_or(""))
                        }
                        "client_cert_server" => {
                            println!("{}", cfg.client_cert_server.as_deref().unwrap_or(""))
                        }
                        "quick_unlock" => println!("{}", cfg.quick_unlock),
                        _ => {
                            eprintln!("Unknown configuration key: {}", k);
                            return ExitCode::FAILURE;
                        }
                    }
                } else {
                    println!("{}", serde_json::to_string_pretty(&cfg).unwrap());
                }
                ExitCode::SUCCESS
            }
            ConfigAction::Set {
                server_url,
                identity_url,
                auto_lock,
                clipboard_clear,
                email,
                remember_email,
                log_level,
                remember_last_search,
                client_cert,
                client_key,
                quick_unlock,
            } => {
                let storage_mgr = match cli.config.as_deref() {
                    Some(cp) => {
                        if let Some(parent) = cp.parent() {
                            StorageManager::new(
                                parent.join(omawarden::storage::DEFAULT_STORAGE_FILENAME),
                            )
                        } else {
                            StorageManager::default()
                        }
                    }
                    None => StorageManager::default(),
                };
                let keyring_mgr = KeyringManager::default();
                if let Err(e) = validate_auto_lock_option(auto_lock) {
                    eprintln!("Error: {}", e);
                    return ExitCode::FAILURE;
                }

                let parsed_remember_email = remember_email.map(|v| {
                    let lower = v.trim().to_lowercase();
                    matches!(lower.as_str(), "true" | "1" | "yes")
                });
                let parsed_remember_last_search = remember_last_search.map(|v| {
                    let lower = v.trim().to_lowercase();
                    matches!(lower.as_str(), "true" | "1" | "yes")
                });

                if let Some(ref cert_str) = client_cert {
                    let trimmed = cert_str.trim();
                    if !trimmed.is_empty() {
                        let cert_path = std::path::Path::new(trimmed);
                        if !cert_path.exists() {
                            eprintln!(
                                "Error: Client certificate file not found: '{}'",
                                cert_path.display()
                            );
                            return ExitCode::FAILURE;
                        }
                        let key_target = if let Some(ref key_str) = client_key {
                            let key_trimmed = key_str.trim();
                            if !key_trimmed.is_empty() {
                                std::path::Path::new(key_trimmed)
                            } else {
                                cert_path
                            }
                        } else {
                            cert_path
                        };

                        if !key_target.exists() {
                            eprintln!(
                                "Error: Client private key file not found: '{}'",
                                key_target.display()
                            );
                            return ExitCode::FAILURE;
                        }

                        #[cfg(unix)]
                        {
                            use std::os::unix::fs::PermissionsExt;
                            if let Ok(meta) = std::fs::metadata(key_target) {
                                let mode = meta.permissions().mode() & 0o777;
                                if mode & 0o077 != 0 {
                                    eprintln!(
                                        "Error: Insecure permissions ({:#o}) on client private key '{}': file must be restricted to 0600 or 0400 (run `chmod 600 {}`)",
                                        mode,
                                        key_target.display(),
                                        key_target.display()
                                    );
                                    return ExitCode::FAILURE;
                                }
                            }
                        }
                    }
                }

                let options = ConfigUpdateOptions {
                    server_url,
                    identity_url,
                    auto_lock_minutes: auto_lock,
                    clipboard_clear_seconds: clipboard_clear,
                    email,
                    remember_email: parsed_remember_email,
                    log_level,
                    remember_last_search: parsed_remember_last_search,
                    client_cert_path: client_cert,
                    client_key_path: client_key,
                    quick_unlock,
                };

                let (updated_cfg, _server_changed) =
                    match config_mgr.update_config(options, &storage_mgr, &keyring_mgr) {
                        Ok(res) => res,
                        Err(e) => {
                            eprintln!("Failed to save configuration: {}", e);
                            return ExitCode::FAILURE;
                        }
                    };
                cfg = updated_cfg;
                if let Some(lock_mins) = auto_lock {
                    let _ = send_daemon_request(&json!({
                        "action": "set_auto_lock",
                        "auto_lock_minutes": lock_mins
                    }));
                }
                let safe_url = if cfg.server_url.is_empty() {
                    "default (official)".to_string()
                } else if let Ok(parsed) = url::Url::parse(&cfg.server_url) {
                    if let Some(host) = parsed.host_str() {
                        if host == "vault.bitwarden.com"
                            || host == "api.bitwarden.com"
                            || host == "bitwarden.com"
                            || host == "vault.bitwarden.eu"
                            || host == "api.bitwarden.eu"
                            || host == "bitwarden.eu"
                        {
                            format!("{}://{}", parsed.scheme(), host)
                        } else {
                            "<REDACTED_CUSTOM_HOST>".to_string()
                        }
                    } else {
                        "<REDACTED_CUSTOM_HOST>".to_string()
                    }
                } else {
                    "<REDACTED_CUSTOM_HOST>".to_string()
                };
                let safe_id_url = if let Some(ref u) = cfg.identity_url {
                    if let Ok(parsed) = url::Url::parse(u) {
                        if let Some(host) = parsed.host_str() {
                            if host == "identity.bitwarden.com" || host == "identity.bitwarden.eu" {
                                format!("{}://{}", parsed.scheme(), host)
                            } else {
                                "<REDACTED_CUSTOM_HOST>".to_string()
                            }
                        } else {
                            "<REDACTED_CUSTOM_HOST>".to_string()
                        }
                    } else {
                        "<REDACTED_CUSTOM_HOST>".to_string()
                    }
                } else {
                    "auto".to_string()
                };
                omawarden::log_info!(
                    "omawarden:config",
                    "Updated configuration (log_level: {}, server_url: {}, identity_url: {}).",
                    cfg.log_level,
                    safe_url,
                    safe_id_url
                );
                println!("{}", serde_json::to_string_pretty(&cfg).unwrap());
                ExitCode::SUCCESS
            }
        },

        Commands::Health => {
            let status = check_system_health(&cfg.server_url);
            println!("{}", serde_json::to_string_pretty(&status).unwrap());
            ExitCode::SUCCESS
        }

        Commands::Auth { action } => {
            let auth_mgr = AuthManager::with_config(
                &cfg.server_url,
                cfg.identity_url.as_deref(),
                None,
                None,
                Some(config_mgr.clone()),
            );
            match action {
                AuthAction::Status => {
                    omawarden::daemon::ensure_daemon_running();
                    let st = auth_mgr.get_status(false);
                    println!("{}", serde_json::to_string_pretty(&st).unwrap());
                    ExitCode::SUCCESS
                }
                AuthAction::LoginPassword {
                    email,
                    remember_email,
                } => {
                    let (pwd, stdin_code, stdin_provider, stdin_new_device_otp) =
                        if io::stdin().is_terminal() {
                            let p = rpassword::prompt_password("Enter Master Password: ")
                                .unwrap_or_default();
                            (Zeroizing::new(p), None, None, None)
                        } else {
                            read_auth_payload()
                        };
                    let mut effective_code = stdin_code;
                    let mut effective_provider = stdin_provider;
                    let mut effective_new_device_otp = stdin_new_device_otp;
                    let mut res = auth_mgr.login_password(
                        &email,
                        &pwd,
                        effective_code.as_deref(),
                        effective_provider,
                        effective_new_device_otp.as_deref(),
                    );
                    if !res.ok
                        && effective_code.is_none()
                        && effective_new_device_otp.is_none()
                        && io::stdin().is_terminal()
                    {
                        if res.new_device_verification_required == Some(true) {
                            let prompt_code = rpassword::prompt_password(
                                "Enter New Device Verification Code (check your email): ",
                            )
                            .unwrap_or_default();
                            if !prompt_code.trim().is_empty() {
                                effective_new_device_otp = Some(prompt_code.trim().to_string());
                                res = auth_mgr.login_password(
                                    &email,
                                    &pwd,
                                    None,
                                    None,
                                    effective_new_device_otp.as_deref(),
                                );
                            }
                        } else if res.two_factor_required == Some(true) {
                            let mut providers =
                                res.two_factor_providers.clone().unwrap_or_else(|| vec![0]);
                            // A server reporting two_factor_required with an empty
                            // providers list would panic on providers[default_idx]
                            // below; fall back to the authenticator-app provider.
                            if providers.is_empty() {
                                providers.push(0);
                            }
                            let default_idx = if let Some(pref) = res.two_factor_provider {
                                providers.iter().position(|p| *p == pref).unwrap_or(0)
                            } else {
                                0
                            };
                            let chosen_provider = if providers.len() == 1 {
                                providers[0]
                            } else {
                                eprintln!("\nTwo-Factor Authentication Methods:");
                                for (idx, p) in providers.iter().enumerate() {
                                    let label = match p {
                                        0 => "Authenticator App (TOTP)".to_string(),
                                        1 => "Email Verification Code".to_string(),
                                        3 => "YubiKey OTP".to_string(),
                                        7 => match res.fido2_status.as_deref() {
                                            Some("tool_not_found") => {
                                                "WebAuthn / Passkey / Security Key (libfido2 not installed)".to_string()
                                            }
                                            Some("no_device") => {
                                                "WebAuthn / Passkey / Security Key (no key detected)".to_string()
                                            }
                                            _ => "WebAuthn / Passkey / Security Key".to_string(),
                                        },
                                        _ => "Other".to_string(),
                                    };
                                    eprintln!("  [{}] {}", idx + 1, label);
                                }
                                eprint!(
                                    "Select method [1-{}, default: {}]: ",
                                    providers.len(),
                                    default_idx + 1
                                );
                                let _ = io::stderr().flush();
                                let mut choice = String::new();
                                let _ = io::stdin().read_line(&mut choice);
                                let idx = choice
                                    .trim()
                                    .parse::<usize>()
                                    .unwrap_or(default_idx + 1)
                                    .saturating_sub(1);
                                *providers.get(idx).unwrap_or(&providers[default_idx])
                            };

                            effective_provider = Some(chosen_provider);
                            if chosen_provider == 7 {
                                omawarden::log_info!(
                                    "omawarden:auth",
                                    "Requesting WebAuthn challenge from server..."
                                );
                                res = auth_mgr.login_password(&email, &pwd, None, Some(7), None);
                            } else {
                                let prompt_label = match chosen_provider {
                                    1 => {
                                        "Enter Email Two-Factor Verification Code (check your email): "
                                    }
                                    3 => "Touch your YubiKey or enter OTP: ",
                                    _ => "Enter Two-Factor (2FA) Code: ",
                                };
                                let prompt_code =
                                    rpassword::prompt_password(prompt_label).unwrap_or_default();
                                if !prompt_code.trim().is_empty() {
                                    effective_code = Some(prompt_code.trim().to_string());
                                    res = auth_mgr.login_password(
                                        &email,
                                        &pwd,
                                        effective_code.as_deref(),
                                        effective_provider,
                                        None,
                                    );
                                }
                            }
                        }
                    }
                    if res.ok {
                        if let Some(ref rem) = remember_email {
                            let should_remember =
                                matches!(rem.to_lowercase().as_str(), "true" | "1" | "yes");
                            if let Ok(mut latest_cfg) = config_mgr.try_load() {
                                latest_cfg.remember_email = should_remember;
                                if should_remember {
                                    latest_cfg.email = email.trim().to_lowercase();
                                } else {
                                    latest_cfg.email.clear();
                                }
                                let _ = config_mgr.save(&latest_cfg);
                            }
                        }
                    }
                    print_json_redacting_session(&res);
                    if res.ok {
                        ExitCode::SUCCESS
                    } else {
                        ExitCode::FAILURE
                    }
                }
                AuthAction::LoginApikey { client_id } => {
                    let actual_secret = if io::stdin().is_terminal() {
                        rpassword::prompt_password("Enter Client Secret: ").unwrap_or_default()
                    } else {
                        let raw_secret = read_secret_stdin();
                        let mut secret = raw_secret.clone();
                        if raw_secret.starts_with('{') && raw_secret.ends_with('}') {
                            if let Ok(val) = serde_json::from_str::<Value>(&raw_secret) {
                                if let Some(s) = val.get("client_secret").and_then(|v| v.as_str()) {
                                    secret = s.to_string();
                                }
                            }
                        }
                        secret
                    };
                    let res = auth_mgr.login_apikey(&client_id, &actual_secret);
                    print_json_redacting_session(&res);
                    if res.ok {
                        ExitCode::SUCCESS
                    } else {
                        ExitCode::FAILURE
                    }
                }
                AuthAction::SendTwoFactorEmail { email } => {
                    let (pwd, _, _, _) = if io::stdin().is_terminal() {
                        let p = rpassword::prompt_password("Enter Master Password: ")
                            .unwrap_or_default();
                        (Zeroizing::new(p), None, None, None)
                    } else {
                        read_auth_payload()
                    };
                    if pwd.is_empty() {
                        let res = serde_json::json!({
                            "ok": false,
                            "error": "Password is required to send verification code."
                        });
                        print_json_redacting_session(&res);
                        ExitCode::FAILURE
                    } else {
                        match auth_mgr.send_two_factor_email(&email, &pwd) {
                            Ok(()) => {
                                let res = serde_json::json!({
                                    "ok": true,
                                    "message": "Two-factor verification code sent to your email."
                                });
                                print_json_redacting_session(&res);
                                ExitCode::SUCCESS
                            }
                            Err(e) => {
                                let res = serde_json::json!({
                                    "ok": false,
                                    "error": e.to_string()
                                });
                                print_json_redacting_session(&res);
                                ExitCode::FAILURE
                            }
                        }
                    }
                }
                AuthAction::Fido2Status => {
                    let status = omawarden::webauthn::check_fido2_status();
                    let res = serde_json::json!({
                        "ok": true,
                        "status": status.as_str()
                    });
                    print_json_redacting_session(&res);
                    ExitCode::SUCCESS
                }
                AuthAction::Unlock => {
                    let pwd = read_master_password();
                    omawarden::daemon::ensure_daemon_running();
                    let res = auth_mgr.unlock(&pwd);
                    print_json_redacting_session(&res);
                    if res.ok {
                        ExitCode::SUCCESS
                    } else {
                        ExitCode::FAILURE
                    }
                }
                AuthAction::QuickUnlock => {
                    omawarden::daemon::ensure_daemon_running();
                    let resp = send_daemon_request(&json!({ "action": "quick_unlock" }))
                        .unwrap_or_else(|| {
                            json!({
                                "ok": false,
                                "status": "locked",
                                "error": "omawarden daemon is not running."
                            })
                        });
                    print_json_redacting_session(&resp);
                    if resp.get("ok").and_then(Value::as_bool).unwrap_or(false) {
                        ExitCode::SUCCESS
                    } else {
                        ExitCode::FAILURE
                    }
                }
                AuthAction::QuickUnlockCheck => {
                    // Prefer the daemon as the single source: its ping carries
                    // both the cached setting and the readiness it gates, so
                    // the two can no longer come from disagreeing files. The
                    // fields degrade independently: a daemon older than this
                    // feature reports readiness (quick_unlock) but not the
                    // cached setting (quick_unlock_enabled), which then falls
                    // back to the config file; no daemon at all means no
                    // readiness and a config-file setting.
                    let ping = send_daemon_request(&json!({ "action": "ping" }));
                    let field = |name: &str| {
                        ping.as_ref()
                            .and_then(|r| r.get(name))
                            .and_then(Value::as_bool)
                    };
                    let available = field("quick_unlock").unwrap_or(false);
                    let enabled = field("quick_unlock_enabled")
                        .unwrap_or_else(|| ConfigManager::default().load().quick_unlock);
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&json!({
                            "ok": true,
                            "enabled": enabled,
                            "available": available,
                        }))
                        .unwrap()
                    );
                    ExitCode::SUCCESS
                }
                AuthAction::Lock => {
                    let _ = send_daemon_request(&json!({ "action": "lock" }));
                    let res = auth_mgr.lock();
                    print_json_redacting_session(&res);
                    ExitCode::SUCCESS
                }
                AuthAction::Logout => {
                    let _ = send_daemon_request(&json!({ "action": "lock" }));
                    // ADR-0025 decision 4: logout must zeroize the retained
                    // quick-unlock key. The daemon's lock handler already
                    // hard-locks; the explicit wipe keeps that guarantee
                    // independent of how the lock handler is implemented.
                    let _ = send_daemon_request(&json!({ "action": "wipe_quick_unlock" }));
                    let res = auth_mgr.logout();
                    print_json_redacting_session(&res);
                    ExitCode::SUCCESS
                }
            }
        }

        Commands::Hook { action } => match action {
            HookAction::Install => match install_lock_hook(None, None) {
                Ok(path) => {
                    let json_val = serde_json::json!({
                        "ok": true,
                        "installed_path": path.to_string_lossy(),
                        "note": "Lock hook installed. omawarden daemon also natively auto-detects screen lock, sleep, and Omarchy shell lock."
                    });
                    println!("{}", serde_json::to_string_pretty(&json_val).unwrap());
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    let json_val = serde_json::json!({
                        "ok": false,
                        "error": e.to_string()
                    });
                    println!("{}", serde_json::to_string_pretty(&json_val).unwrap());
                    ExitCode::FAILURE
                }
            },
        },

        Commands::Vault { action } => run_vault_command(action, &cfg),

        Commands::Copy {
            query,
            clear,
            stdin,
            sensitive,
            password,
            username,
            totp,
            notes,
            private_key,
            public_key,
            timeout,
            clear_after,
            owner_pid,
            owner_start_time,
        } => {
            if let Some(secs) = clear_after {
                return run_clipboard_clear_worker(secs, owner_pid, owner_start_time);
            }
            let request = CopyCommand {
                query,
                clear,
                stdin,
                sensitive,
                selection: CopySelection {
                    password,
                    username,
                    totp,
                    notes,
                    card_code: private_key,
                    card_number: public_key,
                },
                timeout_val: timeout.unwrap_or(cfg.clipboard_clear_seconds),
            };
            run_copy_command(request)
        }

        Commands::Totp { query, stdin, copy } => run_totp_command(query, stdin, copy),

        Commands::Generate {
            length,
            no_uppercase,
            no_lowercase,
            no_numbers,
            no_special,
            avoid_ambiguous,
            min_numbers,
            min_special,
            passphrase,
            words,
            separator,
            capitalize,
            copy,
            json,
        } => {
            let secret_res = if passphrase {
                let options = omawarden::generator::PassphraseOptions {
                    words,
                    separator,
                    capitalize,
                };
                omawarden::generator::generate_passphrase(&options)
            } else {
                let options = omawarden::generator::PasswordOptions {
                    length,
                    uppercase: !no_uppercase,
                    lowercase: !no_lowercase,
                    numbers: !no_numbers,
                    special: !no_special,
                    avoid_ambiguous,
                    min_numbers,
                    min_special,
                };
                omawarden::generator::generate_password(&options)
            };

            let secret = match secret_res {
                Ok(s) => s,
                Err(e) => {
                    if json {
                        println!(
                            "{}",
                            serde_json::to_string_pretty(&json!({
                                "ok": false,
                                "error": e
                            }))
                            .unwrap()
                        );
                    } else {
                        eprintln!("Error: {}", e);
                    }
                    return ExitCode::FAILURE;
                }
            };

            let clip_mgr = ClipboardManager::default();
            let mut copied = false;
            if copy {
                let timeout = if cfg.clipboard_clear_seconds > 0 {
                    cfg.clipboard_clear_seconds
                } else {
                    30
                };
                if clip_mgr.copy(&secret.value, true, timeout) {
                    copied = true;
                    if !json {
                        println!(
                            "Generated secret copied to clipboard (auto-clears in {}s)",
                            timeout
                        );
                    }
                } else {
                    if json {
                        println!(
                            "{}",
                            serde_json::to_string_pretty(&json!({
                                "ok": false,
                                "error": "Failed to copy generated secret to clipboard"
                            }))
                            .unwrap()
                        );
                    } else {
                        eprintln!("Failed to copy generated secret to clipboard");
                    }
                    return ExitCode::FAILURE;
                }
            }

            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "ok": true,
                        "password": secret.value,
                        "entropy": secret.entropy,
                        "type": secret.secret_type,
                        "copied": copied
                    }))
                    .unwrap()
                );
                ExitCode::SUCCESS
            } else if !copy {
                println!("{}", secret.value);
                ExitCode::SUCCESS
            } else {
                ExitCode::SUCCESS
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_cli_bool_accepts_known_values() {
        for v in ["true", "TRUE", "1", "yes", " Yes "] {
            assert!(matches!(parse_cli_bool(v), Ok(true)), "{v}");
        }
        for v in ["false", "0", "NO", " no "] {
            assert!(matches!(parse_cli_bool(v), Ok(false)), "{v}");
        }
    }

    #[test]
    fn test_parse_cli_bool_rejects_typos() {
        // "ture" must be a hard error: coerced to false it would persist a
        // disabled setting and wipe the retained quick-unlock key.
        for v in ["ture", "flase", "on", "off", ""] {
            assert!(parse_cli_bool(v).is_err(), "{v} should not parse");
        }
    }

    #[test]
    fn test_cli_vault_reveal_and_copy_field_parsing() {
        let cli = Cli::try_parse_from([
            "omawarden",
            "vault",
            "reveal",
            "--id",
            "item-1",
            "--field",
            "card.code",
        ])
        .unwrap();
        match cli.command {
            Commands::Vault {
                action: VaultAction::Reveal { id, field },
            } => assert_eq!((id.as_str(), field.as_str()), ("item-1", "card.code")),
            _ => panic!("Expected vault reveal"),
        }
        let cli = Cli::try_parse_from([
            "omawarden",
            "vault",
            "copy-field",
            "--id",
            "item-1",
            "--field",
            "login.password",
            "--clear-after",
            "20",
        ])
        .unwrap();
        match cli.command {
            Commands::Vault {
                action:
                    VaultAction::CopyField {
                        id,
                        field,
                        clear_after,
                    },
            } => {
                assert_eq!((id.as_str(), field.as_str()), ("item-1", "login.password"));
                assert_eq!(clear_after, Some(20));
            }
            _ => panic!("Expected vault copy-field"),
        }
    }

    #[test]
    fn test_cli_vault_copy_sequence_parsing() {
        let cli = Cli::try_parse_from([
            "omawarden",
            "vault",
            "copy-sequence",
            "--id=item-1",
            "--fields=login.password,login.totp",
            "--clear-after=40",
        ])
        .unwrap();
        match cli.command {
            Commands::Vault {
                action:
                    VaultAction::CopySequence {
                        id,
                        fields,
                        clear_after,
                    },
            } => {
                assert_eq!(id, "item-1");
                assert_eq!(fields, vec!["login.password", "login.totp"]);
                assert_eq!(clear_after, Some(40));
            }
            _ => panic!("Expected vault copy-sequence"),
        }
        assert!(
            Cli::try_parse_from(["omawarden", "vault", "copy-sequence", "--id=item-1"]).is_err(),
            "--fields is required"
        );
    }

    #[test]
    fn test_select_copy_target_flags_and_type_defaults() {
        let flagged = |configure: fn(&mut CopySelection)| {
            let mut selection = CopySelection::default();
            configure(&mut selection);
            selection
        };
        assert_eq!(
            select_copy_target(&flagged(|s| s.username = true), "login"),
            CopyTarget::Username
        );
        let cases: [(CopySelection, &str, &str, &str); 8] = [
            (flagged(|s| s.totp = true), "login", "login.totp", "totp"),
            (flagged(|s| s.notes = true), "login", "notes", "notes"),
            (
                flagged(|s| s.card_number = true),
                "card",
                "card.number",
                "public_key",
            ),
            (
                flagged(|s| s.card_code = true),
                "card",
                "card.code",
                "private_key",
            ),
            (
                flagged(|s| s.password = true),
                "login",
                "login.password",
                "password",
            ),
            (
                CopySelection::default(),
                "login",
                "login.password",
                "password",
            ),
            (
                CopySelection::default(),
                "card",
                "card.number",
                "card_number",
            ),
            (CopySelection::default(), "note", "notes", "notes"),
        ];
        for (selection, type_name, field, label) in cases {
            assert_eq!(
                select_copy_target(&selection, type_name),
                CopyTarget::Secret { field, label },
                "{type_name} {field}"
            );
        }
    }

    #[test]
    fn test_redacted_username_fallbacks() {
        assert_eq!(
            redacted_username(&json!({ "login": { "username": "u" } })),
            "u"
        );
        assert_eq!(
            redacted_username(&json!({ "identity": { "email": "e@example.com" } })),
            "e@example.com"
        );
        assert_eq!(redacted_username(&json!({ "card": {} })), "");
    }

    #[test]
    fn test_totp_source_from_stdin() {
        assert_eq!(totp_source_from_stdin(String::new()), TotpSource::Missing);
        assert_eq!(
            totp_source_from_stdin("JBSWY3DPEHPK3PXP".into()),
            TotpSource::Seed("JBSWY3DPEHPK3PXP".into())
        );
        assert_eq!(
            totp_source_from_stdin(r#"{"secret":"JBSWY3DPEHPK3PXP"}"#.into()),
            TotpSource::Seed("JBSWY3DPEHPK3PXP".into())
        );
        assert_eq!(
            totp_source_from_stdin(r#"{"id":"item-1"}"#.into()),
            TotpSource::Item("item-1".into())
        );
        assert_eq!(
            totp_source_from_stdin(r#"{"query":"github"}"#.into()),
            TotpSource::Item("github".into())
        );
    }

    #[test]
    fn test_validate_auto_lock_option_range() {
        assert!(validate_auto_lock_option(None).is_ok());
        assert!(validate_auto_lock_option(Some(1)).is_ok());
        assert!(validate_auto_lock_option(Some(720)).is_ok());
        for minutes in [0, -5, 721] {
            assert!(
                validate_auto_lock_option(Some(minutes)).is_err(),
                "{minutes}"
            );
        }
    }

    #[test]
    fn test_parse_auth_payload_plain() {
        let (pwd, code, provider, ndv) = parse_auth_payload("mypassword\n");
        assert_eq!(pwd.as_str(), "mypassword");
        assert_eq!(code, None);
        assert_eq!(provider, None);
        assert_eq!(ndv, None);
    }

    #[test]
    fn test_parse_auth_payload_json_with_code() {
        let (pwd, code, provider, ndv) =
            parse_auth_payload("{\"password\": \"secret123\", \"code\": \"654321\"}\n");
        assert_eq!(pwd.as_str(), "secret123");
        assert_eq!(code.as_deref(), Some("654321"));
        assert_eq!(provider, None);
        assert_eq!(ndv, None);
    }

    #[test]
    fn test_parse_auth_payload_json_with_new_device_otp() {
        let (pwd, code, provider, ndv) = parse_auth_payload(
            "{\"password\": \"secret123\", \"code\": \"111222\", \"new_device_otp\": \"111222\"}\n",
        );
        assert_eq!(pwd.as_str(), "secret123");
        assert_eq!(code.as_deref(), Some("111222"));
        assert_eq!(provider, None);
        assert_eq!(ndv.as_deref(), Some("111222"));

        let (pwd2, code2, provider2, ndv2) =
            parse_auth_payload("{\"password\": \"secret123\", \"newDeviceOtp\": \"333444\"}\n");
        assert_eq!(pwd2.as_str(), "secret123");
        assert_eq!(code2, None);
        assert_eq!(provider2, None);
        assert_eq!(ndv2.as_deref(), Some("333444"));
    }

    #[test]
    fn test_parse_auth_payload_json_with_provider() {
        let (pwd, code, provider, ndv) = parse_auth_payload(
            "{\"password\": \"secret123\", \"code\": \"123456\", \"two_factor_provider\": 1}\n",
        );
        assert_eq!(pwd.as_str(), "secret123");
        assert_eq!(code.as_deref(), Some("123456"));
        assert_eq!(provider, Some(1));
        assert_eq!(ndv, None);

        let (pwd2, code2, provider2, ndv2) = parse_auth_payload(
            "{\"password\": \"secret123\", \"code\": \"999888\", \"provider\": \"3\"}\n",
        );
        assert_eq!(pwd2.as_str(), "secret123");
        assert_eq!(code2.as_deref(), Some("999888"));
        assert_eq!(provider2, Some(3));
        assert_eq!(ndv2, None);
    }

    #[test]
    fn test_parse_auth_payload_json_without_code() {
        let (pwd, code, provider, ndv) = parse_auth_payload("{\"password\": \"secret123\"}\n");
        assert_eq!(pwd.as_str(), "secret123");
        assert_eq!(code, None);
        assert_eq!(provider, None);
        assert_eq!(ndv, None);
    }

    #[test]
    fn test_parse_auth_payload_empty() {
        let (pwd, code, provider, ndv) = parse_auth_payload("  \r\n");
        assert_eq!(pwd.as_str(), "");
        assert_eq!(code, None);
        assert_eq!(provider, None);
        assert_eq!(ndv, None);
    }

    #[test]
    fn test_cli_daemon_auto_lock_arg_parsing() {
        // Without --auto-lock flag, auto_lock should be None so it can inherit from config
        let cli_default = Cli::try_parse_from(["omawarden", "daemon"]).unwrap();
        match cli_default.command {
            Commands::Daemon { auto_lock } => assert_eq!(auto_lock, None),
            _ => panic!("Expected Commands::Daemon"),
        }

        // With --auto-lock flag, auto_lock should be Some(N)
        let cli_explicit =
            Cli::try_parse_from(["omawarden", "daemon", "--auto-lock", "45"]).unwrap();
        match cli_explicit.command {
            Commands::Daemon { auto_lock } => assert_eq!(auto_lock, Some(45)),
            _ => panic!("Expected Commands::Daemon"),
        }
    }

    #[test]
    fn test_cli_client_cert_and_key_arg_parsing() {
        let cli_default = Cli::try_parse_from(["omawarden", "config", "set"]).unwrap();
        match cli_default.command {
            Commands::Config {
                action:
                    ConfigAction::Set {
                        client_cert,
                        client_key,
                        ..
                    },
            } => {
                assert_eq!(client_cert, None);
                assert_eq!(client_key, None);
            }
            _ => panic!("Expected Commands::Config with ConfigAction::Set"),
        }

        let cli_custom = Cli::try_parse_from([
            "omawarden",
            "config",
            "set",
            "--client-cert",
            "/path/to/cert.pem",
            "--client-key",
            "/path/to/key.pem",
        ])
        .unwrap();
        match cli_custom.command {
            Commands::Config {
                action:
                    ConfigAction::Set {
                        client_cert,
                        client_key,
                        ..
                    },
            } => {
                assert_eq!(client_cert, Some("/path/to/cert.pem".to_string()));
                assert_eq!(client_key, Some("/path/to/key.pem".to_string()));
            }
            _ => panic!("Expected Commands::Config with ConfigAction::Set"),
        }
    }

    #[test]
    fn test_cli_totp_stdin_and_query_arg_parsing() {
        let cli_stdin = Cli::try_parse_from(["omawarden", "totp", "--stdin"]).unwrap();
        match cli_stdin.command {
            Commands::Totp { stdin, query, .. } => {
                assert!(stdin);
                assert_eq!(query, None);
            }
            _ => panic!("Expected Commands::Totp"),
        }

        let cli_query = Cli::try_parse_from(["omawarden", "totp", "my-github-item"]).unwrap();
        match cli_query.command {
            Commands::Totp { stdin, query, .. } => {
                assert!(!stdin);
                assert_eq!(query.as_deref(), Some("my-github-item"));
            }
            _ => panic!("Expected Commands::Totp"),
        }
    }

    #[test]
    fn test_cli_zero_argv_sensitive_args_rejected() {
        // Assert --session is rejected
        assert!(
            Cli::try_parse_from(["omawarden", "--session", "dummy_token", "vault", "sync"])
                .is_err()
        );
        assert!(
            Cli::try_parse_from(["omawarden", "vault", "sync", "--session", "dummy_token"])
                .is_err()
        );

        // Assert --secret is rejected from totp
        assert!(
            Cli::try_parse_from(["omawarden", "totp", "--secret", "JBSWY3DPEHPK3PXP"]).is_err()
        );

        // Assert --code is rejected from auth login-password
        assert!(Cli::try_parse_from([
            "omawarden",
            "auth",
            "login-password",
            "--email",
            "test@example.com",
            "--code",
            "123456"
        ])
        .is_err());
    }

    #[test]
    fn test_cli_generate_password_default_and_flags() {
        let cli_default = Cli::try_parse_from(["omawarden", "generate"]).unwrap();
        match cli_default.command {
            Commands::Generate {
                length,
                no_uppercase,
                no_lowercase,
                no_numbers,
                no_special,
                avoid_ambiguous,
                passphrase,
                copy,
                ..
            } => {
                assert_eq!(length, 20);
                assert!(!no_uppercase);
                assert!(!no_lowercase);
                assert!(!no_numbers);
                assert!(!no_special);
                assert!(!avoid_ambiguous);
                assert!(!passphrase);
                assert!(!copy);
            }
            _ => panic!("Expected Commands::Generate"),
        }

        let cli_custom = Cli::try_parse_from([
            "omawarden",
            "generate",
            "-l",
            "32",
            "--no-special",
            "--avoid-ambiguous",
            "-c",
            "--json",
        ])
        .unwrap();
        match cli_custom.command {
            Commands::Generate {
                length,
                no_special,
                avoid_ambiguous,
                copy,
                json,
                ..
            } => {
                assert_eq!(length, 32);
                assert!(no_special);
                assert!(avoid_ambiguous);
                assert!(copy);
                assert!(json);
            }
            _ => panic!("Expected Commands::Generate"),
        }
    }

    #[test]
    fn test_cli_generate_passphrase_flags() {
        let cli = Cli::try_parse_from([
            "omawarden",
            "generate",
            "--passphrase",
            "-w",
            "6",
            "-s",
            ".",
            "--capitalize",
        ])
        .unwrap();
        match cli.command {
            Commands::Generate {
                passphrase,
                words,
                separator,
                capitalize,
                ..
            } => {
                assert!(passphrase);
                assert_eq!(words, 6);
                assert_eq!(separator, ".");
                assert!(capitalize);
            }
            _ => panic!("Expected Commands::Generate"),
        }
    }
}
