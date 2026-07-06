mod actions;
mod password;
mod vault;

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::RwLock;

use tower_lsp::jsonrpc::Result;
use tower_lsp::lsp_types::*;
use tower_lsp::{Client, LanguageServer, LspService, Server};

struct Backend {
    client: Client,
    documents: RwLock<HashMap<Url, String>>,
    init_options: RwLock<password::InitOptions>,
}

impl Backend {
    fn document_dir(uri: &Url) -> Option<PathBuf> {
        uri.to_file_path().ok().and_then(|p| p.parent().map(|d| d.to_path_buf()))
    }

    fn resolve_passwords(&self, uri: &Url) -> password::Resolved {
        let opts = self.init_options.read().unwrap().clone();
        password::resolve(&opts, Self::document_dir(uri).as_deref())
    }

    fn full_line_edit(
        &self,
        uri: &Url,
        start_line: usize,
        end_line: usize,
        new_text: String,
        title: &str,
        total_lines: usize,
    ) -> CodeAction {
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

        CodeAction {
            title: title.to_string(),
            kind: Some(CodeActionKind::REFACTOR_REWRITE),
            edit: Some(WorkspaceEdit {
                changes: Some(changes),
                ..Default::default()
            }),
            ..Default::default()
        }
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

        Ok(InitializeResult {
            server_info: Some(ServerInfo {
                name: "ansible-vault-lsp".into(),
                version: Some(env!("CARGO_PKG_VERSION").into()),
            }),
            capabilities: ServerCapabilities {
                text_document_sync: Some(TextDocumentSyncCapability::Kind(TextDocumentSyncKind::FULL)),
                code_action_provider: Some(CodeActionProviderCapability::Simple(true)),
                hover_provider: Some(HoverProviderCapability::Simple(true)),
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

        let resolved = self.resolve_passwords(&uri);
        let value = if resolved.passwords.is_empty() {
            "**Ansible Vault**: no vault password found \
             (checked initialization_options, ANSIBLE_VAULT_PASSWORD_FILE, ansible.cfg)"
                .to_string()
        } else {
            match vault::decrypt_any(&block.vaulttext, &resolved.passwords) {
                Ok(plaintext) => {
                    // Use a longer fence if the plaintext itself contains one.
                    let fence = if plaintext.contains("```") { "`````" } else { "```" };
                    format!("**Ansible Vault** (decrypted)\n\n{fence}text\n{plaintext}\n{fence}")
                }
                Err(e) => format!("**Ansible Vault**: {e}"),
            }
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
        let text = match self.documents.read().unwrap().get(&uri) {
            Some(t) => t.clone(),
            None => return Ok(None),
        };
        let lines: Vec<&str> = text.lines().collect();
        let total = lines.len();
        let cursor = params.range.start.line as usize;

        let mut response: Vec<CodeActionOrCommand> = Vec::new();

        if let Some(block) = actions::find_vault_block(&lines, cursor) {
            let resolved = self.resolve_passwords(&uri);
            if resolved.passwords.is_empty() {
                self.client
                    .show_message(
                        MessageType::WARNING,
                        "ansible-vault-lsp: no vault password found (checked initialization_options, \
                         ANSIBLE_VAULT_PASSWORD_FILE, ansible.cfg)",
                    )
                    .await;
            } else {
                match vault::decrypt_any(&block.vaulttext, &resolved.passwords) {
                    Ok(plaintext) => {
                        let new_text = actions::render_decrypted(&block, &plaintext);
                        response.push(CodeActionOrCommand::CodeAction(self.full_line_edit(
                            &uri,
                            block.start_line,
                            block.end_line,
                            new_text,
                            "Decrypt with Ansible Vault",
                            total,
                        )));
                    }
                    Err(e) => {
                        self.client
                            .show_message(MessageType::ERROR, format!("ansible-vault-lsp: {e}"))
                            .await;
                    }
                }
            }
        } else if let Some(plain) = actions::find_plain_value(&lines, cursor) {
            let resolved = self.resolve_passwords(&uri);
            if let Some(pw) = resolved.passwords.first() {
                let opts = self.init_options.read().unwrap().clone();
                let vaulttext = vault::encrypt(&plain.value, pw, opts.encrypt_vault_id.as_deref());
                let new_text = actions::render_encrypted(&plain, &vaulttext);
                let line = plain.line;
                response.push(CodeActionOrCommand::CodeAction(self.full_line_edit(
                    &uri,
                    line,
                    line,
                    new_text,
                    "Encrypt with Ansible Vault",
                    total,
                )));
            }
        }

        if response.is_empty() {
            Ok(None)
        } else {
            Ok(Some(response))
        }
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
    });

    Server::new(stdin, stdout, socket).serve(service).await;
}
