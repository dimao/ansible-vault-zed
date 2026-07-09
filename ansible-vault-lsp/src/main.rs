mod actions;
mod cli;
mod password;
mod vault;

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::RwLock;

use tower_lsp::jsonrpc::Result;
use tower_lsp::lsp_types::*;
use tower_lsp::{Client, LanguageServer, LspService, Server};

const TITLE_ENCRYPT: &str = "Encrypt with Ansible Vault";
const TITLE_DECRYPT: &str = "Decrypt with Ansible Vault";

struct Backend {
    client: Client,
    documents: RwLock<HashMap<Url, String>>,
    init_options: RwLock<password::InitOptions>,
    supports_resolve: AtomicBool,
}

impl Backend {
    fn document_dir(uri: &Url) -> Option<PathBuf> {
        uri.to_file_path().ok().and_then(|p| p.parent().map(|d| d.to_path_buf()))
    }

    fn resolve_passwords(&self, uri: &Url) -> password::Resolved {
        let opts = self.init_options.read().unwrap().clone();
        password::resolve(&opts, Self::document_dir(uri).as_deref())
    }

    /// Path to the ansible-vault executable, if the CLI backend is enabled.
    fn cli_program(&self) -> Option<String> {
        self.init_options
            .read()
            .unwrap()
            .ansible_vault_path
            .clone()
            .filter(|p| !p.is_empty())
    }

    fn do_decrypt(&self, uri: &Url, vaulttext: &str) -> std::result::Result<String, String> {
        let resolved = self.resolve_passwords(uri);
        if let Some(program) = self.cli_program() {
            cli::decrypt(&program, vaulttext, Self::document_dir(uri).as_deref(), &resolved)
        } else {
            if resolved.passwords.is_empty() {
                return Err(no_password_message());
            }
            vault::decrypt_any(vaulttext, &resolved.passwords).map_err(|e| e.to_string())
        }
    }

    fn do_encrypt(&self, uri: &Url, plaintext: &str) -> std::result::Result<String, String> {
        let resolved = self.resolve_passwords(uri);
        let vault_id = self.init_options.read().unwrap().encrypt_vault_id.clone();
        if let Some(program) = self.cli_program() {
            cli::encrypt(
                &program,
                plaintext,
                vault_id.as_deref(),
                Self::document_dir(uri).as_deref(),
                &resolved,
            )
        } else {
            let Some(pw) = resolved.passwords.first() else {
                return Err(no_password_message());
            };
            Ok(vault::encrypt(plaintext, pw, vault_id.as_deref()))
        }
    }

    /// Compute the (title, edit) for the action at `cursor`, running crypto.
    fn compute_action(
        &self,
        uri: &Url,
        cursor: usize,
    ) -> std::result::Result<Option<(&'static str, WorkspaceEdit)>, String> {
        let text = match self.documents.read().unwrap().get(uri) {
            Some(t) => t.clone(),
            None => return Ok(None),
        };
        let lines: Vec<&str> = text.lines().collect();
        let total = lines.len();

        if let Some(block) = actions::find_vault_block(&lines, cursor) {
            let plaintext = self.do_decrypt(uri, &block.vaulttext)?;
            let new_text = actions::render_decrypted(&block, &plaintext);
            let edit = full_line_edit(uri, block.start_line, block.end_line, new_text, total);
            Ok(Some((TITLE_DECRYPT, edit)))
        } else if let Some(plain) = actions::find_plain_value(&lines, cursor) {
            let vaulttext = self.do_encrypt(uri, &plain.value)?;
            let new_text = actions::render_encrypted(&plain, &vaulttext);
            let edit = full_line_edit(uri, plain.line, plain.line, new_text, total);
            Ok(Some((TITLE_ENCRYPT, edit)))
        } else {
            Ok(None)
        }
    }

    /// Cheap detection (no crypto) of which action applies at `cursor`.
    fn available_action(&self, uri: &Url, cursor: usize) -> Option<&'static str> {
        let text = self.documents.read().unwrap().get(uri).cloned()?;
        let lines: Vec<&str> = text.lines().collect();
        if actions::find_vault_block(&lines, cursor).is_some() {
            Some(TITLE_DECRYPT)
        } else if actions::find_plain_value(&lines, cursor).is_some() {
            Some(TITLE_ENCRYPT)
        } else {
            None
        }
    }
}

fn no_password_message() -> String {
    "no vault password found (checked initialization_options, \
     ANSIBLE_VAULT_PASSWORD_FILE, ansible.cfg)"
        .to_string()
}

fn full_line_edit(
    uri: &Url,
    start_line: usize,
    end_line: usize,
    new_text: String,
    total_lines: usize,
) -> WorkspaceEdit {
    // Replace lines start..=end. If there is a following line, span up to its
    // column 0 and keep a trailing newline; otherwise replace to end of file.
    let (range, new_text) = if end_line + 1 < total_lines {
        (
            Range::new(
                Position::new(start_line as u32, 0),
                Position::new(end_line as u32 + 1, 0),
            ),
            format!("{new_text}\n"),
        )
    } else {
        (
            Range::new(
                Position::new(start_line as u32, 0),
                Position::new(end_line as u32, u32::MAX),
            ),
            new_text,
        )
    };

    let mut changes = HashMap::new();
    changes.insert(uri.clone(), vec![TextEdit { range, new_text }]);
    WorkspaceEdit {
        changes: Some(changes),
        ..Default::default()
    }
}

#[tower_lsp::async_trait]
impl LanguageServer for Backend {
    async fn initialize(&self, params: InitializeParams) -> Result<InitializeResult> {
        if let Some(opts) = params.initialization_options {
            match serde_json::from_value::<password::InitOptions>(opts) {
                Ok(parsed) => *self.init_options.write().unwrap() = parsed,
                Err(e) => {
                    self.client
                        .log_message(MessageType::WARNING, format!("bad initialization_options: {e}"))
                        .await;
                }
            }
        }

        let client_resolves = params
            .capabilities
            .text_document
            .as_ref()
            .and_then(|t| t.code_action.as_ref())
            .and_then(|c| c.resolve_support.as_ref())
            .map(|r| r.properties.iter().any(|p| p == "edit"))
            .unwrap_or(false);
        self.supports_resolve.store(client_resolves, Ordering::Relaxed);

        let hover_enabled = self
            .init_options
            .read()
            .unwrap()
            .hover_preview
            .unwrap_or(true);

        Ok(InitializeResult {
            server_info: Some(ServerInfo {
                name: "ansible-vault-lsp".into(),
                version: Some(env!("CARGO_PKG_VERSION").into()),
            }),
            capabilities: ServerCapabilities {
                text_document_sync: Some(TextDocumentSyncCapability::Kind(TextDocumentSyncKind::FULL)),
                code_action_provider: Some(CodeActionProviderCapability::Options(CodeActionOptions {
                    resolve_provider: Some(true),
                    ..Default::default()
                })),
                hover_provider: hover_enabled.then_some(HoverProviderCapability::Simple(true)),
                ..Default::default()
            },
        })
    }

    async fn initialized(&self, _: InitializedParams) {
        self.client
            .log_message(MessageType::INFO, "ansible-vault-lsp ready")
            .await;
    }

    async fn shutdown(&self) -> Result<()> {
        Ok(())
    }

    async fn did_open(&self, params: DidOpenTextDocumentParams) {
        self.documents
            .write()
            .unwrap()
            .insert(params.text_document.uri, params.text_document.text);
    }

    async fn did_change(&self, params: DidChangeTextDocumentParams) {
        if let Some(change) = params.content_changes.into_iter().next_back() {
            self.documents
                .write()
                .unwrap()
                .insert(params.text_document.uri, change.text);
        }
    }

    async fn did_close(&self, params: DidCloseTextDocumentParams) {
        self.documents.write().unwrap().remove(&params.text_document.uri);
    }

    async fn hover(&self, params: HoverParams) -> Result<Option<Hover>> {
        // Belt-and-braces: also honor the setting if a client ignores capabilities.
        if !self.init_options.read().unwrap().hover_preview.unwrap_or(true) {
            return Ok(None);
        }
        let uri = params.text_document_position_params.text_document.uri;
        let position = params.text_document_position_params.position;
        let text = match self.documents.read().unwrap().get(&uri) {
            Some(t) => t.clone(),
            None => return Ok(None),
        };
        let lines: Vec<&str> = text.lines().collect();

        let Some(block) = actions::find_vault_block(&lines, position.line as usize) else {
            return Ok(None);
        };

        let value = match self.do_decrypt(&uri, &block.vaulttext) {
            Ok(plaintext) => {
                // Use a longer fence if the plaintext itself contains one.
                let fence = if plaintext.contains("```") { "`````" } else { "```" };
                format!("**Ansible Vault** (decrypted)\n\n{fence}text\n{plaintext}\n{fence}")
            }
            Err(e) => format!("**Ansible Vault**: {e}"),
        };

        Ok(Some(Hover {
            contents: HoverContents::Markup(MarkupContent {
                kind: MarkupKind::Markdown,
                value,
            }),
            range: Some(Range::new(
                Position::new(block.start_line as u32, 0),
                Position::new(block.end_line as u32, u32::MAX),
            )),
        }))
    }

    async fn code_action(&self, params: CodeActionParams) -> Result<Option<CodeActionResponse>> {
        let uri = params.text_document.uri;
        let cursor = params.range.start.line as usize;

        if self.supports_resolve.load(Ordering::Relaxed) {
            // Lazy: only detect availability here; crypto runs in resolve.
            let Some(title) = self.available_action(&uri, cursor) else {
                return Ok(None);
            };
            let action = CodeAction {
                title: title.to_string(),
                kind: Some(CodeActionKind::REFACTOR_REWRITE),
                data: Some(serde_json::json!({ "uri": uri, "line": cursor })),
                ..Default::default()
            };
            return Ok(Some(vec![CodeActionOrCommand::CodeAction(action)]));
        }

        // Eager fallback for clients without codeAction/resolve support.
        match self.compute_action(&uri, cursor) {
            Ok(Some((title, edit))) => Ok(Some(vec![CodeActionOrCommand::CodeAction(CodeAction {
                title: title.to_string(),
                kind: Some(CodeActionKind::REFACTOR_REWRITE),
                edit: Some(edit),
                ..Default::default()
            })])),
            Ok(None) => Ok(None),
            Err(e) => {
                self.client
                    .show_message(MessageType::ERROR, format!("ansible-vault-lsp: {e}"))
                    .await;
                Ok(None)
            }
        }
    }

    async fn code_action_resolve(&self, mut action: CodeAction) -> Result<CodeAction> {
        let Some(data) = action.data.take() else {
            return Ok(action);
        };
        let (Some(uri), Some(line)) = (
            data.get("uri")
                .and_then(|v| v.as_str())
                .and_then(|s| Url::parse(s).ok()),
            data.get("line").and_then(|v| v.as_u64()),
        ) else {
            return Ok(action);
        };

        match self.compute_action(&uri, line as usize) {
            Ok(Some((_title, edit))) => action.edit = Some(edit),
            Ok(None) => {}
            Err(e) => {
                self.client
                    .show_message(MessageType::ERROR, format!("ansible-vault-lsp: {e}"))
                    .await;
            }
        }
        Ok(action)
    }
}

#[tokio::main]
async fn main() {
    let stdin = tokio::io::stdin();
    let stdout = tokio::io::stdout();

    let (service, socket) = LspService::new(|client| Backend {
        client,
        documents: RwLock::new(HashMap::new()),
        init_options: RwLock::new(password::InitOptions::default()),
        supports_resolve: AtomicBool::new(false),
    });

    Server::new(stdin, stdout, socket).serve(service).await;
}
