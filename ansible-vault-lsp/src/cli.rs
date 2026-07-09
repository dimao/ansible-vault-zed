//! Alternative backend: shell out to the real `ansible-vault` executable for
//! users who prefer not to trust the built-in crypto implementation.
//!
//! Password handling:
//! - password *files* we resolved are passed via `--vault-id <path>`
//! - a literal password (from initialization_options) is written to a 0600
//!   temp file for the duration of the call and removed immediately after
//! - if we resolved nothing, ansible-vault performs its own ansible.cfg /
//!   environment discovery (we set the working directory to the document dir)

use crate::password::Resolved;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// Temp password file that is deleted on drop.
pub struct TempPasswordFile {
    path: PathBuf,
}

impl TempPasswordFile {
    fn create(password: &str) -> std::io::Result<Self> {
        let path = std::env::temp_dir().join(format!(
            "ansible-vault-lsp-{}-{:x}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts.open(&path)?;
        f.write_all(password.as_bytes())?;
        f.write_all(b"\n")?;
        Ok(Self { path })
    }
}

impl Drop for TempPasswordFile {
    fn drop(&mut self) {
        std::fs::remove_file(&self.path).ok();
    }
}

/// Password files to pass on the command line (+ guards keeping temp files alive).
fn materialize(resolved: &Resolved) -> Result<(Vec<PathBuf>, Vec<TempPasswordFile>), String> {
    let mut files = Vec::new();
    let mut guards = Vec::new();
    for literal in &resolved.literals {
        let tmp = TempPasswordFile::create(literal)
            .map_err(|e| format!("failed to create temp password file: {e}"))?;
        files.push(tmp.path.clone());
        guards.push(tmp);
    }
    files.extend(resolved.files.iter().cloned());
    Ok((files, guards))
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
    let (files, _guards) = materialize(resolved)?;
    let mut cmd = Command::new(program);
    cmd.args(["encrypt", "--output", "-"]);

    match encrypt_vault_id {
        Some(id) if !id.is_empty() => {
            // Label the first identity so --encrypt-vault-id can select it.
            let mut iter = files.iter();
            if let Some(first) = iter.next() {
                cmd.arg("--vault-id").arg(format!("{id}@{}", first.display()));
            }
            for f in iter {
                cmd.arg("--vault-id").arg(f);
            }
            cmd.args(["--encrypt-vault-id", id]);
        }
        _ => {
            for f in &files {
                cmd.arg("--vault-id").arg(f);
            }
        }
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
    let (files, _guards) = materialize(resolved)?;
    let mut cmd = Command::new(program);
    cmd.args(["decrypt", "--output", "-"]);
    for f in &files {
        cmd.arg("--vault-id").arg(f);
    }
    run(cmd, cwd, vaulttext)
}
