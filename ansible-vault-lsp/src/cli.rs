//! Alternative backend: shell out to the real `ansible-vault` executable for
//! users who prefer not to trust the built-in crypto implementation.
//!
//! Password handling:
//! - password *files* we resolved (passwordFile, ANSIBLE_VAULT_PASSWORD_FILE,
//!   ansible.cfg) are passed via `--vault-password-file <path>` — nothing is
//!   ever written to disk by us
//! - a literal `password` option is rejected in CLI mode: ansible-vault can
//!   only read passwords from a file/script/prompt, and we refuse to write
//!   secrets to temp files
//! - if we resolved nothing, ansible-vault performs its own ansible.cfg /
//!   environment discovery (we set the working directory to the document dir)

use crate::password::Resolved;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

fn password_files(resolved: &Resolved) -> Result<Vec<PathBuf>, String> {
    if !resolved.literals.is_empty() {
        return Err(
            "a literal `password` cannot be used with `ansibleVaultPath`: ansible-vault \
             only reads passwords from files, and writing it to a temp file would defeat \
             the purpose of the CLI backend. Use `passwordFile` instead."
                .into(),
        );
    }
    // Dedup while preserving resolution order.
    let mut files: Vec<PathBuf> = Vec::new();
    for f in &resolved.files {
        if !files.contains(f) {
            files.push(f.clone());
        }
    }
    Ok(files)
}

/// When we pass password files explicitly, drop the inherited env var so
/// ansible-vault doesn't see the same password as a second vault identity.
fn set_password_args(cmd: &mut Command, files: &[PathBuf]) {
    if !files.is_empty() {
        cmd.env_remove("ANSIBLE_VAULT_PASSWORD_FILE");
    }
    for f in files {
        cmd.arg("--vault-password-file").arg(f);
    }
}



fn run(mut cmd: Command, cwd: Option<&Path>, stdin_data: &str) -> Result<String, String> {
    if let Some(dir) = cwd.filter(|d| d.is_dir()) {
        cmd.current_dir(dir);
    }
    let mut child = cmd
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("failed to run {:?}: {e}", cmd.get_program()))?;

    child
        .stdin
        .take()
        .expect("stdin piped")
        .write_all(stdin_data.as_bytes())
        .map_err(|e| format!("failed to write to ansible-vault stdin: {e}"))?;

    let output = child
        .wait_with_output()
        .map_err(|e| format!("ansible-vault did not exit cleanly: {e}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!(
            "ansible-vault failed ({}): {}",
            output.status,
            stderr.trim()
        ));
    }
    String::from_utf8(output.stdout).map_err(|_| "ansible-vault output is not UTF-8".into())
}

pub fn encrypt(
    program: &str,
    plaintext: &str,
    encrypt_vault_id: Option<&str>,
    cwd: Option<&Path>,
    resolved: &Resolved,
) -> Result<String, String> {
    let files = password_files(resolved)?;
    let mut cmd = Command::new(program);
    cmd.args(["encrypt", "--output", "-"]);

    // Encryption uses exactly one identity (the first resolved password file,
    // same precedence as the native backend) to avoid --encrypt-vault-id
    // ambiguity when several identities are known.
    let encrypt_files: Vec<PathBuf> = files.into_iter().take(1).collect();
    match encrypt_vault_id {
        Some(id) if !id.is_empty() => {
            if let Some(first) = encrypt_files.first() {
                // Label the identity so --encrypt-vault-id can select it.
                cmd.env_remove("ANSIBLE_VAULT_PASSWORD_FILE");
                cmd.arg("--vault-id").arg(format!("{id}@{}", first.display()));
            }
            cmd.args(["--encrypt-vault-id", id]);
        }
        _ => set_password_args(&mut cmd, &encrypt_files),
    }

    let out = run(cmd, cwd, plaintext)?;
    let text = out.trim_end().to_string();
    if !crate::vault::is_vault_data(&text) {
        return Err("ansible-vault encrypt produced unexpected output".into());
    }
    Ok(text)
}

pub fn decrypt(
    program: &str,
    vaulttext: &str,
    cwd: Option<&Path>,
    resolved: &Resolved,
) -> Result<String, String> {
    let files = password_files(resolved)?;
    let mut cmd = Command::new(program);
    cmd.args(["decrypt", "--output", "-"]);
    set_password_args(&mut cmd, &files);
    run(cmd, cwd, vaulttext)
}
