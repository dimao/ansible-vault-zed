//! Vault password resolution, mirroring ansible's precedence:
//!
//! 1. LSP `initialization_options`: `{"password": "...", "passwordFile": "..."}`
//! 2. `ANSIBLE_VAULT_PASSWORD_FILE` environment variable
//! 3. `ansible.cfg` discovery: `$ANSIBLE_CONFIG`, then `ansible.cfg` walking up
//!    from the document's directory, then `~/.ansible.cfg`, then
//!    `/etc/ansible/ansible.cfg` — honoring `vault_password_file` and
//!    `vault_identity_list` under `[defaults]`.
//!
//! Password files with the executable bit set are executed and their stdout is
//! used (like ansible's script sources).

use serde::Deserialize;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct InitOptions {
    /// Literal vault password (avoid committing this to settings!).
    pub password: Option<String>,
    /// Path to a vault password file (may be an executable script).
    pub password_file: Option<String>,
    /// Vault id label to use when encrypting (produces a 1.2 header).
    pub encrypt_vault_id: Option<String>,
}

#[derive(Debug, Default)]
pub struct Resolved {
    /// Candidate passwords, tried in order for decryption. First one is used
    /// for encryption.
    pub passwords: Vec<String>,
    /// Human-readable description of where the password came from.
    pub sources: Vec<String>,
}

pub fn resolve(opts: &InitOptions, document_dir: Option<&Path>) -> Resolved {
    let mut out = Resolved::default();

    if let Some(pw) = &opts.password {
        out.passwords.push(pw.clone());
        out.sources.push("initialization_options.password".into());
    }
    if let Some(file) = &opts.password_file {
        if let Some(pw) = read_password_file(Path::new(&expand_tilde(file))) {
            out.passwords.push(pw);
            out.sources.push(format!("initialization_options.passwordFile ({file})"));
        }
    }

    if let Ok(file) = std::env::var("ANSIBLE_VAULT_PASSWORD_FILE") {
        if !file.is_empty() {
            if let Some(pw) = read_password_file(Path::new(&expand_tilde(&file))) {
                out.passwords.push(pw);
                out.sources.push(format!("ANSIBLE_VAULT_PASSWORD_FILE ({file})"));
            }
        }
    }

    for cfg in candidate_configs(document_dir) {
        if let Some((files, cfg_dir)) = parse_ansible_cfg(&cfg) {
            for f in files {
                let path = resolve_relative(&expand_tilde(&f), &cfg_dir);
                if let Some(pw) = read_password_file(&path) {
                    out.passwords.push(pw);
                    out.sources.push(format!("{} ({})", cfg.display(), f));
                }
            }
            if !out.passwords.is_empty() {
                break; // first config wins, like ansible
            }
        }
    }

    out.passwords.dedup();
    out
}

fn candidate_configs(document_dir: Option<&Path>) -> Vec<PathBuf> {
    let mut cfgs = Vec::new();
    if let Ok(env_cfg) = std::env::var("ANSIBLE_CONFIG") {
        if !env_cfg.is_empty() {
            cfgs.push(PathBuf::from(expand_tilde(&env_cfg)));
        }
    }
    // Walk up from the document directory looking for ansible.cfg
    if let Some(mut dir) = document_dir.map(Path::to_path_buf) {
        loop {
            cfgs.push(dir.join("ansible.cfg"));
            if !dir.pop() {
                break;
            }
        }
    }
    if let Some(home) = dirs::home_dir() {
        cfgs.push(home.join(".ansible.cfg"));
    }
    cfgs.push(PathBuf::from("/etc/ansible/ansible.cfg"));
    cfgs.retain(|p| p.is_file());
    cfgs
}

/// Returns (password file paths, config dir) from `vault_password_file` and
/// `vault_identity_list` in the `[defaults]` section.
fn parse_ansible_cfg(path: &Path) -> Option<(Vec<String>, PathBuf)> {
    let content = std::fs::read_to_string(path).ok()?;
    let cfg_dir = path.parent()?.to_path_buf();
    let mut in_defaults = false;
    let mut files = Vec::new();

    for raw in content.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if line.starts_with('[') {
            in_defaults = line.eq_ignore_ascii_case("[defaults]");
            continue;
        }
        if !in_defaults {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else { continue };
        let key = key.trim();
        let value = value.trim();
        match key {
            "vault_password_file" => files.push(value.to_string()),
            "vault_identity_list" => {
                // "label1@/path/one, label2@/path/two"
                for entry in value.split(',') {
                    let entry = entry.trim();
                    if entry.is_empty() {
                        continue;
                    }
                    let file = entry.split_once('@').map(|(_, f)| f).unwrap_or(entry);
                    files.push(file.trim().to_string());
                }
            }
            _ => {}
        }
    }

    if files.is_empty() {
        None
    } else {
        Some((files, cfg_dir))
    }
}

fn resolve_relative(path: &str, base: &Path) -> PathBuf {
    let p = Path::new(path);
    if p.is_absolute() {
        p.to_path_buf()
    } else {
        base.join(p)
    }
}

fn expand_tilde(path: &str) -> String {
    if let Some(rest) = path.strip_prefix("~/") {
        if let Some(home) = dirs::home_dir() {
            return home.join(rest).to_string_lossy().into_owned();
        }
    }
    path.to_string()
}

fn read_password_file(path: &Path) -> Option<String> {
    if !path.is_file() {
        return None;
    }
    if is_executable(path) {
        let output = std::process::Command::new(path).output().ok()?;
        if !output.status.success() {
            return None;
        }
        let stdout = String::from_utf8_lossy(&output.stdout);
        let pw = stdout.lines().next().unwrap_or_default().to_string();
        (!pw.is_empty()).then_some(pw)
    } else {
        let content = std::fs::read_to_string(path).ok()?;
        let pw = content.trim_end_matches(['\r', '\n']).to_string();
        (!pw.is_empty()).then_some(pw)
    }
}

#[cfg(unix)]
fn is_executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path)
        .map(|m| m.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
}

#[cfg(not(unix))]
fn is_executable(_path: &Path) -> bool {
    false
}
