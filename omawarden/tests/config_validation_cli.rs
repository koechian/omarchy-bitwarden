//! The binary must refuse to run with a configuration file that exists but
//! cannot be parsed, instead of falling back to the default server.

use std::process::{Command, Output};

fn run_with_config(config_dir: &std::path::Path, args: &[&str]) -> Output {
    let root = config_dir.parent().unwrap();
    Command::new(env!("CARGO_BIN_EXE_omawarden"))
        .args(args)
        .env("OMAWARDEN_CONFIG_DIR", config_dir)
        .env("OMAWARDEN_DATA_DIR", root.join("data"))
        .env("XDG_RUNTIME_DIR", root.join("runtime"))
        .env("HOME", root.join("home"))
        .output()
        .unwrap()
}

#[test]
fn invalid_config_file_is_a_hard_error() {
    let dir = tempfile::tempdir().unwrap();
    let config_dir = dir.path().join("config");
    for sub in ["config", "data", "runtime", "home"] {
        std::fs::create_dir(dir.path().join(sub)).unwrap();
    }
    std::fs::write(
        config_dir.join("config.json"),
        r#"{"server_url": "https://vault.example.com", "#,
    )
    .unwrap();

    let out = run_with_config(&config_dir, &["config", "get", "server_url"]);
    assert!(!out.status.success(), "{out:?}");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        !stdout.contains("vault.bitwarden.com"),
        "default server must not be used: {stdout}"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("is invalid"), "{stderr}");
}

#[test]
fn missing_config_file_uses_defaults() {
    let dir = tempfile::tempdir().unwrap();
    let config_dir = dir.path().join("config");
    for sub in ["config", "data", "runtime", "home"] {
        std::fs::create_dir(dir.path().join(sub)).unwrap();
    }

    let out = run_with_config(&config_dir, &["config", "get", "server_url"]);
    assert!(out.status.success(), "{out:?}");
    assert_eq!(
        String::from_utf8_lossy(&out.stdout).trim(),
        "https://vault.bitwarden.com"
    );
}
