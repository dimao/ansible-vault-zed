# Ansible Vault Inline for Zed

Inline `ansible-vault` encrypt/decrypt for [Zed](https://zed.dev), similar to the VSCode
[ansible-vault-inline](https://marketplace.visualstudio.com/items?itemName=wolfmah.ansible-vault-inline)
extension.

Since Zed extensions are WASM-sandboxed, the functionality is delivered as **LSP code
actions** provided by a small native language server.

## Components

| Directory            | What it is |
|----------------------|------------|
| `ansible-vault-lsp/` | Rust LSP server. Native implementation of the Ansible Vault 1.1/1.2 format (PBKDF2-SHA256 → AES-256-CTR + HMAC-SHA256). No `ansible` installation required. |
| `zed-ansible-vault/` | Zed extension (WASM) that launches the LSP for YAML / Ansible files. |

## Features

Put the cursor on a value and open code actions (`cmd-.` / `ctrl-.`):

- **Encrypt with Ansible Vault** — on a plain `key: value` line, replaces the value with a
  `!vault |` inline block.
- **Decrypt with Ansible Vault** — anywhere on a `!vault |` block (tag line or payload),
  replaces it with the plaintext value (quoted / block-scalar formatted as needed).
- **Hover preview** — hover over any `!vault |` block to see the decrypted plaintext in a
  tooltip without modifying the file.

Works for mapping values and list items (`- !vault |`). Multiline plaintext round-trips via
literal block scalars. Compatibility with the real `ansible-vault` CLI is covered by
integration tests (both directions).

## Vault password resolution (in order)

1. Zed LSP `initialization_options`: `password`, `passwordFile`
2. `ANSIBLE_VAULT_PASSWORD_FILE` environment variable
3. `ansible.cfg` discovery like ansible itself: `$ANSIBLE_CONFIG`, `ansible.cfg` walking up
   from the edited file, `~/.ansible.cfg`, `/etc/ansible/ansible.cfg` — honoring
   `vault_password_file` and `vault_identity_list` under `[defaults]`

Executable password files are run and their stdout is used (script sources). With multiple
identities, **all** passwords are tried for decryption; the first one is used for encryption.

## Installation

### 1. Install the Zed extension

Once published: Zed → Extensions → search “Ansible Vault Inline”.

Until then (dev extension): command palette → `zed: install dev extension` → select the
`zed-ansible-vault/` directory. (Dev install only: requires rustup with the `wasm32-wasip2`
target so Zed can compile the extension.)

**No manual LSP install is needed** — the extension resolves `ansible-vault-lsp` in this order:

1. `lsp.ansible-vault-lsp.binary.path` from Zed settings
2. `ansible-vault-lsp` on `$PATH`
3. Auto-download of a prebuilt binary from
   [GitHub releases](https://github.com/dimao/ansible-vault-zed/releases)
   (linux/macos x86_64 + aarch64, windows x86_64)

Release binaries are built by CI (`.github/workflows/release.yml`) on every `v*` tag.

### 2. Enable the server for YAML in Zed `settings.json`

```jsonc
{
  "languages": {
    "YAML": {
      "language_servers": ["yaml-language-server", "ansible-vault-lsp"]
    },
    "Ansible": {
      "language_servers": ["ansible-language-server", "ansible-vault-lsp"]
    }
  },
  "lsp": {
    "ansible-vault-lsp": {
      // Optional — only needed if you don't use ansible.cfg / env var:
      "initialization_options": {
        "passwordFile": "~/.vault-pass.txt",
        // "password": "inline-password",   // avoid committing this
        // "encryptVaultId": "dev"          // emit $ANSIBLE_VAULT;1.2;AES256;dev headers
      },
      // Optional — explicit binary location:
      "binary": { "path": "/home/you/.cargo/bin/ansible-vault-lsp" }
    }
  }
}
```

## Development

```sh
# unit + interop tests (interop auto-skips without ansible-vault on PATH)
cd ansible-vault-lsp && cargo test

# extension WASM build check
cd zed-ansible-vault && cargo build --target wasm32-wasip1 --release
```

## Releasing

```sh
git tag v0.1.0 && git push origin v0.1.0
# CI builds ansible-vault-lsp-v0.1.0-<target>.{tar.gz,zip} and attaches them to the release
```

## Roadmap

- Whole-file encrypt/decrypt code actions
- Diagnostics for undecryptable blocks
- Publish to the Zed extensions registry
