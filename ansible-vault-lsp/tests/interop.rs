//! Interop tests against the real `ansible-vault` CLI. Skipped automatically
//! when ansible-vault is not installed.

use std::io::Write;
use std::process::{Command, Stdio};

// Re-compile the vault module directly into the test binary.
#[path = "../src/vault.rs"]
mod vault;

fn ansible_vault_available() -> bool {
    Command::new("ansible-vault")
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn write_password_file(dir: &std::path::Path, pw: &str) -> std::path::PathBuf {
    let path = dir.join("vault-pass.txt");
    std::fs::write(&path, format!("{pw}\n")).unwrap();
    path
}

#[test]
fn ansible_vault_decrypts_our_ciphertext() {
    if !ansible_vault_available() {
        eprintln!("skipping: ansible-vault not installed");
        return;
    }
    let tmp = std::env::temp_dir().join(format!("avlsp-test-{}", std::process::id()));
    std::fs::create_dir_all(&tmp).unwrap();
    let pw_file = write_password_file(&tmp, "interop-pw");

    let plaintext = "s3cret from rust";
    let encrypted = vault::encrypt(plaintext, "interop-pw", None);
    let enc_file = tmp.join("secret.vault");
    std::fs::write(&enc_file, format!("{encrypted}\n")).unwrap();

    let out = Command::new("ansible-vault")
        .args(["decrypt", "--vault-password-file"])
        .arg(&pw_file)
        .args(["--output", "-"])
        .arg(&enc_file)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "ansible-vault decrypt failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&out.stdout), plaintext);

    std::fs::remove_dir_all(&tmp).ok();
}

#[test]
fn we_decrypt_ansible_vault_ciphertext() {
    if !ansible_vault_available() {
        eprintln!("skipping: ansible-vault not installed");
        return;
    }
    let tmp = std::env::temp_dir().join(format!("avlsp-test2-{}", std::process::id()));
    std::fs::create_dir_all(&tmp).unwrap();
    let pw_file = write_password_file(&tmp, "interop-pw");

    let plaintext = "s3cret from ansible";
    let mut child = Command::new("ansible-vault")
        .args(["encrypt_string", "--vault-password-file"])
        .arg(&pw_file)
        .args(["--stdin-name", "x"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(plaintext.as_bytes()).unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success());

    // Output looks like: `x: !vault |\n          $ANSIBLE_VAULT;1.1;AES256\n          ...`
    let stdout = String::from_utf8(out.stdout).unwrap();
    let vaulttext: String = stdout
        .lines()
        .skip(1)
        .map(str::trim)
        .collect::<Vec<_>>()
        .join("\n");
    assert!(vaulttext.starts_with("$ANSIBLE_VAULT"));

    assert_eq!(vault::decrypt(&vaulttext, "interop-pw").unwrap(), plaintext);
    assert!(matches!(
        vault::decrypt(&vaulttext, "wrong"),
        Err(vault::VaultError::WrongPassword)
    ));

    std::fs::remove_dir_all(&tmp).ok();
}
