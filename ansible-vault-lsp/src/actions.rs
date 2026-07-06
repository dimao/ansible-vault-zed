//! Cursor-based analysis of YAML documents: find the vault block or plain
//! scalar value under the cursor and build the replacement text.

use crate::vault;
use regex::Regex;
use std::sync::OnceLock;

/// An encrypted `!vault |` block found in the document.
#[derive(Debug)]
pub struct VaultBlock {
    /// 0-based first line (the one carrying the `!vault |` tag).
    pub start_line: usize,
    /// 0-based last line of the encrypted payload (inclusive).
    pub end_line: usize,
    /// Leading whitespace of the tag line.
    pub indent: String,
    /// Everything before `!vault` on the tag line, e.g. `db_password: ` or `- `.
    pub prefix: String,
    /// Reassembled vault text (header + hex, newline separated).
    pub vaulttext: String,
}

/// A plain `key: value` scalar that can be encrypted.
#[derive(Debug)]
pub struct PlainValue {
    /// 0-based line number.
    pub line: usize,
    pub indent: String,
    /// `key` part including the colon and one space, e.g. `db_password: `.
    pub prefix: String,
    /// The raw scalar value (quotes stripped).
    pub value: String,
}

fn tag_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^(\s*)(.*?)!vault\s*\|[+\-]?\d*\s*$").unwrap())
}

fn kv_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r#"^(\s*)((?:- )*[^\s#][^:]*:\s+)(.+?)\s*$"#).unwrap())
}

fn indent_of(line: &str) -> usize {
    line.len() - line.trim_start().len()
}

/// Find the `!vault |` block containing `cursor_line`, if any.
pub fn find_vault_block(lines: &[&str], cursor_line: usize) -> Option<VaultBlock> {
    if cursor_line >= lines.len() {
        return None;
    }

    // Scan upward (bounded) for the tag line.
    let mut tag_line = None;
    for l in (0..=cursor_line).rev() {
        if tag_re().is_match(lines[l]) {
            tag_line = Some(l);
            break;
        }
        // A non-blank line that is not part of a vault payload stops the scan.
        let t = lines[l].trim();
        if !t.is_empty() && !vault::is_vault_data(t) && !t.chars().all(|c| c.is_ascii_hexdigit()) {
            return None;
        }
    }
    let start = tag_line?;
    let caps = tag_re().captures(lines[start])?;
    let indent = caps[1].to_string();
    let prefix = caps[2].to_string();
    let tag_indent = indent.len();

    // Collect the payload: following lines indented deeper than the tag line.
    let mut payload: Vec<&str> = Vec::new();
    let mut end = start;
    for (i, line) in lines.iter().enumerate().skip(start + 1) {
        if line.trim().is_empty() {
            break;
        }
        if indent_of(line) <= tag_indent {
            break;
        }
        payload.push(line.trim());
        end = i;
    }

    if payload.is_empty() || !vault::is_vault_data(payload[0]) {
        return None;
    }
    if cursor_line > end {
        return None;
    }

    Some(VaultBlock {
        start_line: start,
        end_line: end,
        indent,
        prefix,
        vaulttext: payload.join("\n"),
    })
}

/// Find a plain `key: value` scalar on `cursor_line`, if any.
pub fn find_plain_value(lines: &[&str], cursor_line: usize) -> Option<PlainValue> {
    let line = lines.get(cursor_line)?;
    let caps = kv_re().captures(line)?;
    let value = caps[3].trim();
    // Not encryptable: tags, anchors, block scalars, flow collections, comments-only.
    if value.starts_with('!')
        || value.starts_with('&')
        || value.starts_with('*')
        || value.starts_with('|')
        || value.starts_with('>')
        || value.starts_with('#')
        || value.starts_with('{')
        || value.starts_with('[')
        || vault::is_vault_data(value)
    {
        return None;
    }
    Some(PlainValue {
        line: cursor_line,
        indent: caps[1].to_string(),
        prefix: caps[2].trim_end().to_string() + " ",
        value: unquote(value).to_string(),
    })
}

fn unquote(v: &str) -> &str {
    let b = v.as_bytes();
    if b.len() >= 2 && (b[0] == b'"' || b[0] == b'\'') && b[b.len() - 1] == b[0] {
        &v[1..v.len() - 1]
    } else {
        v
    }
}

/// Whether a plain scalar can be emitted unquoted in YAML.
fn needs_quoting(v: &str) -> bool {
    if v.is_empty() || v.trim() != v {
        return true;
    }
    let special_start = "!&*?|>%@`\"'#-:{}[],";
    if special_start.contains(v.chars().next().unwrap()) {
        return true;
    }
    v.contains(": ") || v.ends_with(':') || v.contains(" #")
}

fn quote_single(v: &str) -> String {
    format!("'{}'", v.replace('\'', "''"))
}

/// Build the replacement lines for decrypting `block` into plaintext.
/// Returns the full replacement text for lines start..=end (no trailing newline).
pub fn render_decrypted(block: &VaultBlock, plaintext: &str) -> String {
    let pt = plaintext.strip_suffix('\n').unwrap_or(plaintext);
    if pt.contains('\n') {
        let child_indent = format!("{}  ", block.indent);
        let keep = if plaintext.ends_with('\n') { "" } else { "-" };
        let mut out = format!("{}{}|{}", block.indent, block.prefix, keep);
        for l in pt.split('\n') {
            out.push('\n');
            if l.is_empty() {
                continue;
            }
            out.push_str(&child_indent);
            out.push_str(l);
        }
        out
    } else {
        let value = if needs_quoting(pt) { quote_single(pt) } else { pt.to_string() };
        format!("{}{}{}", block.indent, block.prefix, value)
    }
}

/// Build the replacement lines for encrypting `plain` into a vault block.
pub fn render_encrypted(plain: &PlainValue, vaulttext: &str) -> String {
    let child_indent = format!("{}  ", plain.indent);
    let mut out = format!("{}{}!vault |", plain.indent, plain.prefix);
    for l in vaulttext.lines() {
        out.push('\n');
        out.push_str(&child_indent);
        out.push_str(l);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const DOC: &str = "\
foo: bar
db_password: !vault |
  $ANSIBLE_VAULT;1.1;AES256
  61316235353966363430386636353265336434653066343937393337343933333433626165643032
  3866
other: value
";

    fn lines(s: &str) -> Vec<&str> {
        s.lines().collect()
    }

    #[test]
    fn finds_block_from_tag_line() {
        let l = lines(DOC);
        let b = find_vault_block(&l, 1).unwrap();
        assert_eq!(b.start_line, 1);
        assert_eq!(b.end_line, 4);
        assert_eq!(b.prefix, "db_password: ");
        assert!(b.vaulttext.starts_with("$ANSIBLE_VAULT;1.1;AES256\n"));
    }

    #[test]
    fn finds_block_from_payload_line() {
        let l = lines(DOC);
        let b = find_vault_block(&l, 3).unwrap();
        assert_eq!(b.start_line, 1);
        assert_eq!(b.end_line, 4);
    }

    #[test]
    fn no_block_on_plain_line() {
        let l = lines(DOC);
        assert!(find_vault_block(&l, 0).is_none());
        assert!(find_vault_block(&l, 5).is_none());
    }

    #[test]
    fn finds_plain_value() {
        let l = lines(DOC);
        let p = find_plain_value(&l, 0).unwrap();
        assert_eq!(p.prefix, "foo: ");
        assert_eq!(p.value, "bar");
        // vault tag line is not a plain value
        assert!(find_plain_value(&l, 1).is_none());
    }

    #[test]
    fn quoted_value_unwrapped() {
        let doc = "password: \"s3cr3t: with colon\"\n";
        let l = lines(doc);
        let p = find_plain_value(&l, 0).unwrap();
        assert_eq!(p.value, "s3cr3t: with colon");
    }

    #[test]
    fn render_roundtrip_layout() {
        let l = lines(DOC);
        let p = find_plain_value(&l, 0).unwrap();
        let rendered = render_encrypted(&p, "$ANSIBLE_VAULT;1.1;AES256\nabcdef");
        assert_eq!(rendered, "foo: !vault |\n  $ANSIBLE_VAULT;1.1;AES256\n  abcdef");

        let rl: Vec<&str> = rendered.lines().collect();
        let b = find_vault_block(&rl, 2).unwrap();
        let dec = render_decrypted(&b, "bar");
        assert_eq!(dec, "foo: bar");
    }

    #[test]
    fn decrypted_value_quoted_when_needed() {
        let l = lines(DOC);
        let b = find_vault_block(&l, 2).unwrap();
        assert_eq!(render_decrypted(&b, "a: b"), "db_password: 'a: b'");
        assert_eq!(
            render_decrypted(&b, "line1\nline2\n"),
            "db_password: |\n  line1\n  line2"
        );
    }

    #[test]
    fn list_item_vault() {
        let doc = "\
secrets:
  - !vault |
      $ANSIBLE_VAULT;1.1;AES256
      abcdef
";
        let l = lines(doc);
        let b = find_vault_block(&l, 2).unwrap();
        assert_eq!(b.prefix, "- ");
        assert_eq!(b.start_line, 1);
        assert_eq!(b.end_line, 3);
    }
}
