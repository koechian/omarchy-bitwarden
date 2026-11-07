use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::Write;
use std::process::{Command, Stdio};
use url::Url;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WebAuthnChallenge {
    pub challenge: String,
    pub rp_id: String,
    pub origin: String,
    pub allow_credentials: Vec<String>,
}

/// Converts a Base64URL string (RFC 4648 §5) to standard Base64.
pub fn base64url_to_base64(s: &str) -> String {
    let mut b64 = s.replace('-', "+").replace('_', "/");
    while !b64.len().is_multiple_of(4) {
        b64.push('=');
    }
    b64
}

/// Converts a standard Base64 string to unpadded Base64URL (RFC 4648 §5).
pub fn base64_to_base64url(s: &str) -> String {
    s.replace('+', "-")
        .replace('/', "_")
        .trim_end_matches('=')
        .to_string()
}

/// If data is wrapped in a CBOR byte string (major type 2), unwraps and returns the raw bytes.
/// `fido2-assert -G` outputs CBOR-encoded authenticatorData, whereas W3C WebAuthn requires
/// the raw authenticatorData bytes.
pub fn unwrap_cbor_bytestring(data: &[u8]) -> &[u8] {
    if data.is_empty() {
        return data;
    }
    let b0 = data[0];
    if (b0 & 0b111_00000) != 0x40 {
        // Not a CBOR byte string
        return data;
    }
    let info = b0 & 0x1F;
    let (header_len, payload_len) = match info {
        0..=23 => (1, info as usize),
        24 => {
            if data.len() < 2 {
                return data;
            }
            (2, data[1] as usize)
        }
        25 => {
            if data.len() < 3 {
                return data;
            }
            (3, ((data[1] as usize) << 8) | (data[2] as usize))
        }
        26 => {
            if data.len() < 5 {
                return data;
            }
            let len = u32::from_be_bytes([data[1], data[2], data[3], data[4]]) as usize;
            (5, len)
        }
        _ => return data,
    };

    if data.len() >= header_len + payload_len {
        &data[header_len..header_len + payload_len]
    } else {
        data
    }
}

/// Parses WebAuthn challenge parameters from Bitwarden/Vaultwarden `TwoFactorProviders2["7"]`.
///
/// Returns `None` when the server-supplied `rpId` is not acceptable for the
/// configured server (see [validate_rp_id]); the value is later written to
/// `fido2-assert` stdin, and a foreign rpId would make the security key sign
/// an assertion for another relying party.
pub fn parse_webauthn_challenge(
    val: &serde_json::Value,
    server_url: &str,
) -> Option<WebAuthnChallenge> {
    let target = val.get("7").unwrap_or(val);
    let obj = target.get("publicKey").unwrap_or(target);

    let challenge = obj
        .get("challenge")
        .or_else(|| obj.get("Challenge"))
        .and_then(|v| v.as_str())?
        .to_string();

    let server_host = configured_server_host(server_url)?;
    let rp_id = obj
        .get("rpId")
        .or_else(|| obj.get("RelyingPartyId"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .unwrap_or_else(|| server_host.clone());
    if let Err(reason) = validate_rp_id(&rp_id, &server_host) {
        crate::log_warn!("omawarden:auth", "Rejected WebAuthn challenge: {}", reason);
        return None;
    }

    let origin = Url::parse(server_url)
        .ok()
        .map(|u| u.origin().ascii_serialization())
        .filter(|o| o != "null")
        .unwrap_or_else(|| format!("https://{}", rp_id));

    Some(WebAuthnChallenge {
        challenge,
        rp_id,
        origin,
        allow_credentials: parse_allow_credentials(obj),
    })
}

/// Collects credential IDs, dropping any that are not Base64URL text so that
/// nothing but Base64 reaches `fido2-assert` stdin.
fn parse_allow_credentials(obj: &serde_json::Value) -> Vec<String> {
    let Some(entries) = obj
        .get("allowCredentials")
        .or_else(|| obj.get("AllowCredentials"))
        .and_then(|v| v.as_array())
    else {
        return Vec::new();
    };
    entries
        .iter()
        .filter_map(|item| item.as_str().or_else(|| item.get("id")?.as_str()))
        .filter(|id| is_base64url_text(id))
        .map(|id| id.to_string())
        .collect()
}

fn is_base64url_text(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'='))
}

/// Host of the configured server, lower-cased and without IPv6 brackets.
fn configured_server_host(server_url: &str) -> Option<String> {
    let trimmed = server_url.trim();
    let normalized = if trimmed.contains("://") {
        trimmed.to_string()
    } else {
        format!("https://{}", trimmed)
    };
    let parsed = Url::parse(&normalized).ok()?;
    let host = parsed.host_str()?;
    Some(
        host.trim_start_matches('[')
            .trim_end_matches(']')
            .to_ascii_lowercase(),
    )
}

/// Accepts an rpId only when it contains no control characters and either
/// equals the configured server host or is a parent domain of it.
///
/// No public suffix list is available, so a parent domain must have at least
/// two labels (`bitwarden.com` for `vault.bitwarden.com`, never `com`), and
/// IP-address hosts accept only an exact match.
pub fn validate_rp_id(rp_id: &str, server_host: &str) -> Result<(), String> {
    if rp_id.chars().any(char::is_control) {
        return Err("rpId contains control characters".to_string());
    }
    let rp_id = rp_id.to_ascii_lowercase();
    if rp_id == server_host {
        return Ok(());
    }
    if is_registrable_parent_domain(&rp_id, server_host) {
        return Ok(());
    }
    Err(format!(
        "rpId '{}' does not match the configured server host '{}'",
        rp_id, server_host
    ))
}

fn is_registrable_parent_domain(candidate: &str, host: &str) -> bool {
    if host.parse::<std::net::IpAddr>().is_ok() {
        return false;
    }
    let has_two_labels = candidate
        .split('.')
        .filter(|label| !label.is_empty())
        .count()
        >= 2;
    let well_formed = !candidate.starts_with('.') && !candidate.ends_with('.');
    has_two_labels && well_formed && host.ends_with(&format!(".{}", candidate))
}

/// Builds the three-line `fido2-assert -G` input. Every field must be a
/// single line; a line break would let one field inject further input.
fn build_fido2_assert_input(
    client_data_hash_b64: &str,
    rp_id: &str,
    credential_id_b64: &str,
) -> Result<String, String> {
    let fields = [client_data_hash_b64, rp_id, credential_id_b64];
    if fields
        .iter()
        .any(|f| f.is_empty() || f.chars().any(char::is_control))
    {
        return Err("Refusing malformed fido2-assert input".to_string());
    }
    Ok(format!(
        "{}\n{}\n{}\n",
        client_data_hash_b64, rp_id, credential_id_b64
    ))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Fido2Status {
    Available,
    NoDevice,
    ToolNotFound,
    OtherError,
}

impl Fido2Status {
    pub fn as_str(&self) -> &'static str {
        match self {
            Fido2Status::Available => "available",
            Fido2Status::NoDevice => "no_device",
            Fido2Status::ToolNotFound => "tool_not_found",
            Fido2Status::OtherError => "other_error",
        }
    }
}

/// Checks the operational status of the FIDO2 environment (tool presence and device detection).
pub fn check_fido2_status() -> Fido2Status {
    match Command::new("fido2-token").arg("-L").output() {
        Ok(output) => {
            if !output.status.success() {
                return Fido2Status::OtherError;
            }
            let text = String::from_utf8_lossy(&output.stdout);
            for line in text.lines() {
                let trimmed = line.trim();
                if let Some(pos) = trimmed.find(':') {
                    let dev = &trimmed[..pos];
                    if dev.starts_with("/dev/hidraw") {
                        return Fido2Status::Available;
                    }
                }
            }
            Fido2Status::NoDevice
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Fido2Status::ToolNotFound,
        Err(_) => Fido2Status::OtherError,
    }
}

/// Discovers connected FIDO2 USB devices using `fido2-token -L`.
pub fn find_fido2_device() -> Result<String, String> {
    let output = Command::new("fido2-token")
        .arg("-L")
        .output()
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                "libfido2 tools not found. Please install the 'libfido2' package (e.g. sudo pacman -S libfido2).".to_string()
            } else {
                format!("Failed to execute fido2-token: {}", e)
            }
        })?;

    if !output.status.success() {
        return Err(format!(
            "fido2-token exited with error: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    let text = String::from_utf8_lossy(&output.stdout);
    for line in text.lines() {
        let trimmed = line.trim();
        if let Some(pos) = trimmed.find(':') {
            let dev = &trimmed[..pos];
            if dev.starts_with("/dev/hidraw") {
                return Ok(dev.to_string());
            }
        }
    }

    Err("No FIDO2 security key found. Please insert your security key and try again.".to_string())
}

/// Runs `fido2-assert -G` against `device_path`, feeding `stdin_payload`.
/// With `user_presence` false the key answers without waiting for a touch.
fn run_fido2_assert(
    device_path: &str,
    stdin_payload: &str,
    user_presence: bool,
) -> Result<std::process::Output, String> {
    let mut cmd = Command::new("fido2-assert");
    cmd.arg("-G").arg("-t").arg("pin=false");
    if !user_presence {
        cmd.arg("-t").arg("up=false");
    }
    let mut child = cmd
        .arg(device_path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                "libfido2 tools not found. Please install the 'libfido2' package (e.g. sudo pacman -S libfido2).".to_string()
            } else {
                format!("Failed to execute fido2-assert: {}", e)
            }
        })?;

    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(stdin_payload.as_bytes())
            .map_err(|e| format!("Failed to write to fido2-assert stdin: {}", e))?;
    }

    child
        .wait_with_output()
        .map_err(|e| format!("Failed to wait for fido2-assert: {}", e))
}

/// Picks the credential from `allowCredentials` that lives on the connected key.
///
/// Accounts often register several keys, but `fido2-assert` accepts a single credential ID,
/// so each one is probed silently (`up=false`) and the first the key recognises is returned.
/// If the key cannot answer silent probes, falls back to the first unrejected credential.
fn select_credential(
    allow_credentials: &[String],
    rp_id: &str,
    device_path: &str,
) -> Result<String, String> {
    if allow_credentials.is_empty() {
        return Err("No credential ID found in WebAuthn challenge".to_string());
    }

    // Probes are never sent to the server, so any 32-byte client data hash will do.
    let probe_hash_b64 = BASE64.encode([0u8; 32]);
    let mut fallback = None;

    for cred_id_raw in allow_credentials {
        let cred_id_b64 = base64url_to_base64(cred_id_raw);
        let payload = build_fido2_assert_input(&probe_hash_b64, rp_id, &cred_id_b64)?;
        let output = run_fido2_assert(device_path, &payload, false)?;
        if output.status.success() {
            return Ok(cred_id_b64);
        }
        let stderr = String::from_utf8_lossy(&output.stderr);
        if !stderr.contains("FIDO_ERR_NO_CREDENTIALS") && fallback.is_none() {
            fallback = Some(cred_id_b64);
        }
    }

    fallback.ok_or_else(|| {
        format!(
            "This security key holds none of the {} credential(s) registered for {}. Try another key or method.",
            allow_credentials.len(),
            rp_id
        )
    })
}

/// Executes `fido2-assert -G` to perform a WebAuthn CTAP2 assertion with the physical key.
pub fn perform_fido2_assertion(
    challenge_data: &WebAuthnChallenge,
    device_path: &str,
) -> Result<serde_json::Value, String> {
    let origin = &challenge_data.origin;
    let client_data_json = serde_json::json!({
        "type": "webauthn.get",
        "challenge": challenge_data.challenge,
        "origin": origin,
        "crossOrigin": false,
    });
    let client_data_bytes = serde_json::to_vec(&client_data_json)
        .map_err(|e| format!("Failed to serialize clientDataJSON: {}", e))?;

    let mut hasher = Sha256::new();
    hasher.update(&client_data_bytes);
    let client_data_hash = hasher.finalize();
    let cd_hash_b64 = BASE64.encode(client_data_hash);

    let cred_id_b64 = select_credential(
        &challenge_data.allow_credentials,
        &challenge_data.rp_id,
        device_path,
    )?;

    let stdin_payload =
        build_fido2_assert_input(&cd_hash_b64, &challenge_data.rp_id, &cred_id_b64)?;

    crate::log_info!("omawarden:auth", "Waiting for security key touch...");
    let output = run_fido2_assert(device_path, &stdin_payload, true)?;

    if !output.status.success() {
        let err_msg = String::from_utf8_lossy(&output.stderr);
        return Err(format!("FIDO2 assertion failed: {}", err_msg.trim()));
    }

    crate::log_info!(
        "omawarden:auth",
        "Security key verified. Authenticating with server..."
    );

    let stdout_str = String::from_utf8_lossy(&output.stdout);
    let lines: Vec<&str> = stdout_str.lines().map(|s| s.trim()).collect();
    if lines.len() < 4 {
        return Err(format!(
            "Unexpected output format from fido2-assert: {:?}",
            lines
        ));
    }

    // Line 0: cd_hash
    // Line 1: rp_id
    // Line 2: authenticator_data (base64)
    let auth_data_raw = BASE64
        .decode(lines[2])
        .unwrap_or_else(|_| lines[2].as_bytes().to_vec());
    let unwrapped_auth_data = unwrap_cbor_bytestring(&auth_data_raw);
    let auth_data_b64url = base64_to_base64url(&BASE64.encode(unwrapped_auth_data));
    let signature_b64url = base64_to_base64url(lines[3]);
    let client_data_b64url = base64_to_base64url(&BASE64.encode(&client_data_bytes));
    let cred_id_b64url = base64_to_base64url(&cred_id_b64);

    let token_payload = serde_json::json!({
        "id": cred_id_b64url,
        "rawId": cred_id_b64url,
        "type": "public-key",
        "extensions": {},
        "clientExtensionResults": {},
        "response": {
            "authenticatorData": auth_data_b64url,
            "clientDataJSON": client_data_b64url,
            "signature": signature_b64url,
            "userHandle": null
        }
    });

    Ok(token_payload)
}

/// Convenience function to discover FIDO2 key, execute assertion, and generate WebAuthn 2FA token.
pub fn create_webauthn_two_factor_token(
    challenge_data: &WebAuthnChallenge,
) -> Result<String, String> {
    let device = find_fido2_device()?;
    let payload = perform_fido2_assertion(challenge_data, &device)?;
    Ok(payload.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_base64_base64url_roundtrip() {
        // Valid Base64 for 10 bytes: 14 chars + 2 padding '='
        let original_2pad = "SGVsbG8gV29ybA==";
        let url_safe_2pad = base64_to_base64url(original_2pad);
        assert_eq!(url_safe_2pad, "SGVsbG8gV29ybA");
        let restored_2pad = base64url_to_base64(&url_safe_2pad);
        assert_eq!(restored_2pad, original_2pad);

        // Valid Base64 with + and /
        let original_chars = "Hello+World/Te==";
        let url_safe_chars = base64_to_base64url(original_chars);
        assert_eq!(url_safe_chars, "Hello-World_Te");
        let restored_chars = base64url_to_base64(&url_safe_chars);
        assert_eq!(restored_chars, original_chars);
    }

    #[test]
    fn test_parse_webauthn_challenge_vaultwarden_format() {
        let json_val = serde_json::json!({
            "7": {
                "publicKey": {
                    "challenge": "dGVzdF9jaGFsbGVuZ2U",
                    "rpId": "vault.example.com",
                    "allowCredentials": [
                        { "id": "Y3JlZF8x", "type": "public-key" },
                        { "id": "Y3JlZF8y", "type": "public-key" }
                    ]
                }
            }
        });

        let parsed = parse_webauthn_challenge(&json_val, "https://vault.example.com").unwrap();
        assert_eq!(parsed.challenge, "dGVzdF9jaGFsbGVuZ2U");
        assert_eq!(parsed.rp_id, "vault.example.com");
        assert_eq!(parsed.origin, "https://vault.example.com");
        assert_eq!(parsed.allow_credentials, vec!["Y3JlZF8x", "Y3JlZF8y"]);
    }

    #[test]
    fn test_parse_webauthn_challenge_official_format() {
        let json_val = serde_json::json!({
            "7": {
                "Challenge": "b2ZmaWNpYWxfY2hhbGxlbmdl",
                "RelyingPartyId": "bitwarden.com",
                "AllowCredentials": ["Y3JlZF9h", "Y3JlZF9i"]
            }
        });

        let parsed = parse_webauthn_challenge(&json_val, "https://vault.bitwarden.com").unwrap();
        assert_eq!(parsed.challenge, "b2ZmaWNpYWxfY2hhbGxlbmdl");
        assert_eq!(parsed.rp_id, "bitwarden.com");
        assert_eq!(parsed.origin, "https://vault.bitwarden.com");
        assert_eq!(parsed.allow_credentials, vec!["Y3JlZF9h", "Y3JlZF9i"]);
    }

    #[test]
    fn test_parse_webauthn_challenge_rejects_foreign_or_malformed_rp_id() {
        let challenge_with_rp = |rp_id: &str| {
            serde_json::json!({
                "7": {
                    "challenge": "dGVzdA",
                    "rpId": rp_id,
                    "allowCredentials": ["Y3JlZF8x"]
                }
            })
        };
        let server = "https://vault.example.com";
        for rejected in [
            "evil.example.org",
            "example.com\nY3JlZF8y",
            "vault.example.com\r",
            "vault.example.com\u{0}",
            "com",
            ".example.com",
            "ample.com",
            "sub.vault.example.com",
            "",
        ] {
            assert!(
                parse_webauthn_challenge(&challenge_with_rp(rejected), server).is_none(),
                "{rejected:?} must be rejected"
            );
        }
        for accepted in ["vault.example.com", "example.com", "VAULT.example.com"] {
            assert!(
                parse_webauthn_challenge(&challenge_with_rp(accepted), server).is_some(),
                "{accepted:?} must be accepted"
            );
        }

        // Loopback self-hosted servers accept only their own host.
        let local = "http://localhost:8000";
        assert!(parse_webauthn_challenge(&challenge_with_rp("localhost"), local).is_some());
        assert!(parse_webauthn_challenge(&challenge_with_rp("example.com"), local).is_none());
        let ip = "http://127.0.0.1:8000";
        assert!(parse_webauthn_challenge(&challenge_with_rp("127.0.0.1"), ip).is_some());
        assert!(parse_webauthn_challenge(&challenge_with_rp("0.0.1"), ip).is_none());
    }

    #[test]
    fn test_parse_webauthn_challenge_drops_non_base64url_credentials() {
        let json_val = serde_json::json!({
            "7": {
                "challenge": "dGVzdA",
                "rpId": "vault.example.com",
                "allowCredentials": ["Y3JlZF8x", "Y3Jl\nvault.example.com", { "id": "Y3JlZF8y" }]
            }
        });
        let parsed = parse_webauthn_challenge(&json_val, "https://vault.example.com").unwrap();
        assert_eq!(parsed.allow_credentials, vec!["Y3JlZF8x", "Y3JlZF8y"]);
    }

    #[test]
    fn test_build_fido2_assert_input_rejects_line_breaks() {
        assert_eq!(
            build_fido2_assert_input("aGFzaA==", "example.com", "Y3JlZA==").unwrap(),
            "aGFzaA==\nexample.com\nY3JlZA==\n"
        );
        assert!(build_fido2_assert_input("aGFzaA==", "example.com\nx", "Y3JlZA==").is_err());
        assert!(build_fido2_assert_input("aGFzaA==", "", "Y3JlZA==").is_err());
    }

    #[test]
    fn test_vaultwarden_public_key_credential_deserialization() {
        #[derive(Debug, Deserialize)]
        #[serde(rename_all = "camelCase")]
        #[allow(dead_code)]
        struct MockVwPublicKeyCredential {
            id: String,
            raw_id: String,
            response: MockVwResponse,
            extensions: serde_json::Value,
            r#type: String,
        }

        #[derive(Debug, Deserialize)]
        #[serde(rename_all = "camelCase")]
        #[allow(dead_code)]
        struct MockVwResponse {
            authenticator_data: String,
            #[serde(rename = "clientDataJson", alias = "clientDataJSON")]
            client_data_json: String,
            signature: String,
            user_handle: Option<String>,
        }

        let token_payload = serde_json::json!({
            "id": "cred_id",
            "rawId": "cred_id",
            "type": "public-key",
            "extensions": {},
            "clientExtensionResults": {},
            "response": {
                "authenticatorData": "auth_data",
                "clientDataJSON": "client_data",
                "signature": "sig",
                "userHandle": null
            }
        });

        let json_str = token_payload.to_string();
        let deserialized: Result<MockVwPublicKeyCredential, _> = serde_json::from_str(&json_str);
        assert!(
            deserialized.is_ok(),
            "Deserialization failed: {:?}",
            deserialized.err()
        );
        let cred = deserialized.unwrap();
        assert_eq!(cred.id, "cred_id");
        assert_eq!(cred.response.client_data_json, "client_data");
    }

    #[test]
    fn test_unwrap_cbor_bytestring() {
        // CBOR major type 2 with length 37 (0x58, 0x25)
        let mut cbor_wrapped = vec![0x58, 37];
        let raw_expected = vec![0xAA; 37];
        cbor_wrapped.extend_from_slice(&raw_expected);

        let unwrapped = unwrap_cbor_bytestring(&cbor_wrapped);
        assert_eq!(unwrapped, &raw_expected[..]);

        // Non-CBOR raw bytes (e.g. SHA256 rpIdHash starting with non-0x40)
        let raw_unwrapped = vec![0x12, 0x34, 0x56];
        assert_eq!(unwrap_cbor_bytestring(&raw_unwrapped), &raw_unwrapped[..]);
    }
}
