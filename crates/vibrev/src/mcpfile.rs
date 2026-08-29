//! Format-preserving edits to a client's config file.
//!
//! Every write here obeys three rules, in this order of importance:
//!
//! 1. **A parse failure aborts.** Never fall back to an empty document — that
//!    turns one syntax error into the loss of every server the user configured.
//! 2. **Nothing outside `vibrev-*` is touched.** Not other servers, not sibling
//!    sections (VS Code's `inputs`, Codex's `[model_providers]`), not formatting,
//!    and above all not comments. Hence `jsonc-parser`'s CST for JSON/JSONC and
//!    `toml_edit` for TOML; a `serde` round-trip through either would erase them.
//! 3. **Names are the identity.** An existing `vibrev-<engine>` is edited where it
//!    sits, so running `install` twice cannot produce a `vibrev-ida-2`.
//!
//! Even inside our own entry the update is surgical: only the keys of the
//! transport being written (`command`/`args`, or `url`/`headers`) and (where
//! the schema has one) `type` are set, so a user who added `env` or `disabled`
//! to `vibrev-ida` keeps it across an upgrade. The one exception is the keys
//! describing the *other* transport — see [`HTTP_TRANSPORT_KEYS`] and
//! [`STDIO_TRANSPORT_KEYS`].

use anyhow::{Context, Result, bail};
use camino::Utf8Path;
use jsonc_parser::ParseOptions;
use jsonc_parser::cst::{CstInputValue, CstNode, CstObject, CstRootNode};
use toml_edit::{Array, DocumentMut, Item, Table, Value};

use crate::client::{Client, Format, ServerSpec};

/// The keys that describe an entry's *HTTP* transport.
///
/// Stripped when we write stdio, set when we write HTTP. An entry we own must
/// describe exactly one transport: Codex uses `command` versus `url` as the
/// discriminator (no `type` field at all), so carrying both is a config error
/// there rather than a merely untidy one.
///
/// JSON clients spell the credential table `headers`. Codex spells it
/// `http_headers`. Both names are recognised on read (token rotate) and
/// stripped on a stdio write, so a leftover of either spelling cannot hide.
///
/// `headers` is also where the credential lives. Left behind in a project-scope
/// file it is a live secret inside the repository. Removing it is necessary but
/// *not* sufficient once the file has been committed — the only real fix is
/// `vibrev token rotate`. Callers say so; see `install::render`.
pub const HTTP_TRANSPORT_KEYS: &[&str] = &["url", "headers", "http_headers"];

/// The keys that describe an entry's *stdio* transport, stripped when we write HTTP.
pub const STDIO_TRANSPORT_KEYS: &[&str] = &["command", "args"];

/// The subset of [`HTTP_TRANSPORT_KEYS`] that can carry a credential.
pub const CREDENTIAL_KEYS: &[&str] = &["headers", "http_headers"];

/// What a single upsert or removal did. Drives both the dry-run wording and the
/// idempotency guarantee.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Op {
    Added,
    Updated,
    /// Already exactly right; the file will not be rewritten for this entry.
    Unchanged,
    Removed,
    /// Asked to remove something that was not there.
    Absent,
}

impl Op {
    pub fn as_str(self) -> &'static str {
        match self {
            Op::Added => "add",
            Op::Updated => "update",
            Op::Unchanged => "unchanged",
            Op::Removed => "remove",
            Op::Absent => "absent",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Op::Added => "新增",
            Op::Updated => "更新",
            Op::Unchanged => "无变化",
            Op::Removed => "移除",
            Op::Absent => "不存在",
        }
    }

    /// Whether the file content actually changes.
    pub fn writes(self) -> bool {
        matches!(self, Op::Added | Op::Updated | Op::Removed)
    }
}

/// An entry as it exists on disk, for comparison and for `vibrev list`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub name: String,
    pub command: Option<String>,
    pub args: Vec<String>,
    pub url: Option<String>,
}

/// A parsed client config, still carrying every byte of its original formatting.
pub enum Doc {
    /// Both JSON and JSONC: the CST is a superset, and using it for strict JSON
    /// costs nothing while preserving the user's key order and indentation.
    Jsonish(CstRootNode),
    Toml(Box<DocumentMut>),
}

/// Parse `text` (which may be the empty string for a file we are about to create).
///
/// The `path` is only for the error message, but it is the difference between
/// "parse failed" and something the user can open and fix.
pub fn parse(text: &str, format: Format, path: &Utf8Path) -> Result<Doc> {
    match format {
        Format::Json | Format::Jsonc => {
            // An empty or whitespace-only file has no root value to attach
            // properties to; `{}` is the same document with somewhere to write.
            let source = if text.trim().is_empty() { "{}" } else { text };
            let root = CstRootNode::parse(source, &ParseOptions::default())
                .with_context(|| format!("解析 {path} 失败（该文件不是合法的 JSON/JSONC）"))?;
            Ok(Doc::Jsonish(root))
        }
        Format::Toml => {
            let doc: DocumentMut = text
                .parse()
                .with_context(|| format!("解析 {path} 失败（该文件不是合法的 TOML）"))?;
            Ok(Doc::Toml(Box::new(doc)))
        }
    }
}

/// Read a file and parse it, treating "not there" as "empty".
///
/// Any other IO error is fatal: a permissions problem must not be mistaken for a
/// fresh install, or we would happily write a file the user cannot read back.
pub fn read(path: &Utf8Path, format: Format) -> Result<(String, Doc)> {
    let text = match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(e) => return Err(e).with_context(|| format!("读取 {path} 失败")),
    };
    let doc = parse(&text, format, path)?;
    Ok((text, doc))
}

impl Doc {
    pub fn render(&self) -> String {
        match self {
            Doc::Jsonish(root) => {
                let mut s = root.to_string();
                // Editors and every client here write a trailing newline; not
                // emitting one shows up as a spurious diff the first time the
                // client rewrites the file.
                if !s.ends_with('\n') {
                    s.push('\n');
                }
                s
            }
            Doc::Toml(doc) => doc.to_string(),
        }
    }

    /// Insert or update `spec` under the client's server key.
    pub fn upsert(&mut self, client: &Client, spec: &ServerSpec) -> Result<Op> {
        match self {
            Doc::Jsonish(root) => upsert_json(root, client, spec),
            Doc::Toml(doc) => upsert_toml(doc, client, spec),
        }
    }

    /// Drop `name` if present. Leaves the (now possibly empty) container in place:
    /// deleting `mcpServers` entirely would be a bigger edit than we were asked for.
    pub fn remove(&mut self, client: &Client, name: &str) -> Result<Op> {
        match self {
            Doc::Jsonish(root) => {
                let Some(servers) = json_servers(root, client)? else {
                    return Ok(Op::Absent);
                };
                match servers.get(name) {
                    Some(prop) => {
                        prop.remove();
                        Ok(Op::Removed)
                    }
                    None => Ok(Op::Absent),
                }
            }
            Doc::Toml(doc) => {
                let Some(parent) = doc.get_mut(client.key).and_then(Item::as_table_like_mut) else {
                    return Ok(Op::Absent);
                };
                Ok(if parent.remove(name).is_some() {
                    Op::Removed
                } else {
                    Op::Absent
                })
            }
        }
    }

    /// Whether `name`'s entry currently carries a credential-bearing key.
    ///
    /// Asked *before* [`Doc::upsert`] strips it, because the removal alone is not
    /// the whole remedy: in a version-controlled file the token is already in
    /// history by the time we see it, and the user needs to be told to rotate.
    pub fn carries_credentials(&self, client: &Client, name: &str) -> bool {
        match self {
            Doc::Jsonish(root) => json_servers(root, client)
                .ok()
                .flatten()
                .and_then(|servers| servers.get(name)?.object_value())
                .is_some_and(|entry| CREDENTIAL_KEYS.iter().any(|k| entry.get(k).is_some())),
            Doc::Toml(doc) => doc
                .get(client.key)
                .and_then(Item::as_table_like)
                .and_then(|parent| parent.get(name))
                .and_then(Item::as_table_like)
                .is_some_and(|tbl| CREDENTIAL_KEYS.iter().any(|k| tbl.get(k).is_some())),
        }
    }

    /// The literal credential values inside `name`'s entry, for masking.
    ///
    /// Returned so the preview can hide them by *exact value* rather than by
    /// pattern-matching diff text: header names are arbitrary (`X-Api-Key` as
    /// readily as `Authorization`), so anything that guessed from the key would
    /// both miss real secrets and mask innocent strings.
    pub fn credential_values(&self, client: &Client, name: &str) -> Vec<String> {
        let mut out = Vec::new();
        match self {
            Doc::Jsonish(root) => {
                let Some(entry) = json_servers(root, client)
                    .ok()
                    .flatten()
                    .and_then(|servers| servers.get(name)?.object_value())
                else {
                    return out;
                };
                for key in CREDENTIAL_KEYS {
                    let Some(map) = entry.get(key).and_then(|p| p.object_value()) else {
                        continue;
                    };
                    for prop in map.properties() {
                        if let Some(v) = prop
                            .value()
                            .and_then(|v| v.as_string_lit()?.decoded_value().ok())
                        {
                            out.push(v);
                        }
                    }
                }
            }
            Doc::Toml(doc) => {
                let Some(entry) = doc
                    .get(client.key)
                    .and_then(Item::as_table_like)
                    .and_then(|parent| parent.get(name))
                    .and_then(Item::as_table_like)
                else {
                    return out;
                };
                for key in CREDENTIAL_KEYS {
                    let Some(tbl) = entry.get(key).and_then(Item::as_table_like) else {
                        continue;
                    };
                    for (_, item) in tbl.iter() {
                        if let Some(v) = item.as_str() {
                            out.push(v.to_owned());
                        }
                    }
                }
            }
        }
        // An empty value is not a secret and masking it would rewrite every `""`
        // in the preview.
        out.retain(|v| !v.is_empty());
        out
    }

    /// Bearer credentials on vibrev-owned HTTP entries, in file order.
    ///
    /// Used by `token rotate` to decide what to rewrite. Stdio leftovers and
    /// anyone else's servers are ignored — we neither rotate those nor report
    /// them as "still on the old token".
    pub fn owned_http_bearers(&self, client: &Client) -> Vec<(String, String)> {
        self.ours(client)
            .into_iter()
            .filter_map(|entry| {
                let token = self.http_bearer(client, &entry.name)?;
                Some((entry.name, token))
            })
            .collect()
    }

    /// Replace `Authorization: Bearer <old>` with the new current token on every
    /// vibrev-owned HTTP entry that still carries one of `old`.
    ///
    /// Returns the entry names that actually changed. Callers that write the
    /// result into a version-controlled file are putting a live token where git
    /// will commit it; `token rotate` does so only for entries that already
    /// carried one of ours.
    pub fn rewrite_owned_http_bearers(
        &mut self,
        client: &Client,
        old: &[String],
        new: &str,
    ) -> Vec<String> {
        let names: Vec<String> = self.ours(client).into_iter().map(|e| e.name).collect();
        names
            .into_iter()
            .filter(|name| self.rewrite_http_bearer(client, name, old, new))
            .collect()
    }

    fn http_bearer(&self, client: &Client, name: &str) -> Option<String> {
        match self {
            Doc::Jsonish(root) => {
                let entry = json_servers(root, client)
                    .ok()
                    .flatten()
                    .and_then(|servers| servers.get(name)?.object_value())?;
                if !json_looks_http(&entry) {
                    return None;
                }
                json_headers_auth(&entry).and_then(|v| bearer_token(&v).map(str::to_owned))
            }
            Doc::Toml(doc) => {
                let entry = doc
                    .get(client.key)
                    .and_then(Item::as_table_like)
                    .and_then(|parent| parent.get(name))?;
                if !toml_looks_http(entry) {
                    return None;
                }
                toml_headers_auth(entry).and_then(|v| bearer_token(&v).map(str::to_owned))
            }
        }
    }

    fn rewrite_http_bearer(
        &mut self,
        client: &Client,
        name: &str,
        old: &[String],
        new: &str,
    ) -> bool {
        match self {
            Doc::Jsonish(root) => {
                let Some(entry) = json_servers(root, client)
                    .ok()
                    .flatten()
                    .and_then(|servers| servers.get(name)?.object_value())
                else {
                    return false;
                };
                if !json_looks_http(&entry) {
                    return false;
                }
                json_rewrite_auth(&entry, old, new)
            }
            Doc::Toml(doc) => {
                let Some(item) = doc
                    .get_mut(client.key)
                    .and_then(Item::as_table_like_mut)
                    .and_then(|parent| parent.get_mut(name))
                else {
                    return false;
                };
                if !toml_looks_http(item) {
                    return false;
                }
                toml_rewrite_auth(item, old, new)
            }
        }
    }

    /// Every `vibrev-*` entry currently in the file, in file order.
    pub fn ours(&self, client: &Client) -> Vec<Entry> {
        let all = match self {
            Doc::Jsonish(root) => json_servers(root, client)
                .ok()
                .flatten()
                .map(|servers| {
                    servers
                        .properties()
                        .into_iter()
                        .filter_map(|p| {
                            let name = p.name()?.decoded_value().ok()?;
                            let obj = p.object_value();
                            Some(Entry {
                                name,
                                command: obj.as_ref().and_then(|o| json_str(o, "command")),
                                args: obj
                                    .as_ref()
                                    .and_then(|o| json_strs(o, "args"))
                                    .unwrap_or_default(),
                                url: obj.as_ref().and_then(|o| json_str(o, "url")),
                            })
                        })
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default(),
            Doc::Toml(doc) => doc
                .get(client.key)
                .and_then(Item::as_table_like)
                .map(|parent| {
                    parent
                        .iter()
                        .map(|(name, item)| Entry {
                            name: name.to_owned(),
                            command: item
                                .as_table_like()
                                .and_then(|t| t.get("command"))
                                .and_then(Item::as_str)
                                .map(str::to_owned),
                            args: item
                                .as_table_like()
                                .and_then(|t| t.get("args"))
                                .and_then(toml_strs)
                                .unwrap_or_default(),
                            url: item
                                .as_table_like()
                                .and_then(|t| t.get("url"))
                                .and_then(Item::as_str)
                                .map(str::to_owned),
                        })
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default(),
        };
        all.into_iter()
            .filter(|e| crate::client::is_ours(&e.name))
            .collect()
    }
}

// -------------------------------------------------------------------- JSON ---

/// The servers object, or `None` when the key is absent.
///
/// Errors rather than replacing when the key exists but holds something other
/// than an object: that is a broken config, and overwriting it would destroy
/// whatever the user meant to put there.
fn json_servers(root: &CstRootNode, client: &Client) -> Result<Option<CstObject>> {
    let Some(obj) = root.object_value() else {
        // A non-object root (an array, a bare string) is not a client config.
        return match root.value() {
            Some(_) => bail!("顶层不是 JSON 对象，拒绝写入"),
            None => Ok(None),
        };
    };
    match obj.get(client.key) {
        None => Ok(None),
        Some(prop) => match prop.object_value() {
            Some(o) => Ok(Some(o)),
            None => bail!("{} 不是 JSON 对象，拒绝写入", client.key),
        },
    }
}

fn upsert_json(root: &CstRootNode, client: &Client, spec: &ServerSpec) -> Result<Op> {
    // Validate before creating anything, so a bad file is never half-edited.
    json_servers(root, client)?;
    let obj = root.object_value_or_set();
    let servers = obj.object_value_or_set(client.key);

    let entry = match servers.get(spec.name()) {
        None => {
            servers.append(spec.name(), json_entry_value(client, spec));
            return Ok(Op::Added);
        }
        Some(prop) => match prop.object_value() {
            Some(e) => e,
            // Present but not an object: nothing in there is salvageable as an
            // MCP entry, and it is ours by name, so replace it outright.
            None => {
                prop.set_value(json_entry_value(client, spec));
                return Ok(Op::Updated);
            }
        },
    };

    if json_matches(&entry, client, spec) {
        return Ok(Op::Unchanged);
    }
    json_apply(&entry, client, spec);
    Ok(Op::Updated)
}

fn json_matches(entry: &CstObject, client: &Client, spec: &ServerSpec) -> bool {
    match spec {
        ServerSpec::Stdio { command, args, .. } => {
            let type_ok = !client.emit_type || json_str(entry, "type").as_deref() == Some("stdio");
            let http_leftovers = HTTP_TRANSPORT_KEYS.iter().any(|k| entry.get(k).is_some());
            type_ok
                && !http_leftovers
                && json_str(entry, "command").as_deref() == Some(command.as_str())
                && json_strs(entry, "args").unwrap_or_default() == *args
        }
        ServerSpec::Http { url, token, .. } => {
            let type_ok = !client.emit_type || json_str(entry, "type").as_deref() == Some("http");
            let stdio_leftovers = STDIO_TRANSPORT_KEYS.iter().any(|k| entry.get(k).is_some());
            type_ok
                && !stdio_leftovers
                && json_str(entry, "url").as_deref() == Some(url.as_str())
                && json_token_matches(entry, token.as_deref())
        }
    }
}

fn json_token_matches(entry: &CstObject, token: Option<&str>) -> bool {
    match token {
        Some(want) => {
            json_headers_auth(entry).and_then(|v| bearer_token(&v).map(str::to_owned))
                == Some(want.to_owned())
        }
        None => CREDENTIAL_KEYS.iter().all(|k| entry.get(k).is_none()),
    }
}

fn json_apply(entry: &CstObject, client: &Client, spec: &ServerSpec) {
    match spec {
        ServerSpec::Stdio { command, args, .. } => {
            if client.emit_type {
                json_set(entry, "type", CstInputValue::String("stdio".to_owned()));
            }
            json_set(entry, "command", CstInputValue::String(command.clone()));
            json_set(entry, "args", json_args(args));
            json_remove_keys(entry, HTTP_TRANSPORT_KEYS);
        }
        ServerSpec::Http { url, token, .. } => {
            if client.emit_type {
                json_set(entry, "type", CstInputValue::String("http".to_owned()));
            }
            json_set(entry, "url", CstInputValue::String(url.clone()));
            match token {
                Some(token) => json_set(entry, "headers", json_bearer_headers(token)),
                None => json_remove_keys(entry, CREDENTIAL_KEYS),
            }
            json_remove_keys(entry, STDIO_TRANSPORT_KEYS);
        }
    }
}

fn json_remove_keys(entry: &CstObject, keys: &[&str]) {
    for key in keys {
        if let Some(prop) = entry.get(key) {
            prop.remove();
        }
    }
}

fn json_bearer_headers(token: &str) -> CstInputValue {
    CstInputValue::Object(vec![(
        "Authorization".to_owned(),
        CstInputValue::String(format!("Bearer {token}")),
    )])
}

fn json_entry_value(client: &Client, spec: &ServerSpec) -> CstInputValue {
    let mut fields = Vec::new();
    match spec {
        ServerSpec::Stdio { command, args, .. } => {
            if client.emit_type {
                fields.push(("type".to_owned(), CstInputValue::String("stdio".to_owned())));
            }
            fields.push(("command".to_owned(), CstInputValue::String(command.clone())));
            fields.push(("args".to_owned(), json_args(args)));
        }
        ServerSpec::Http { url, token, .. } => {
            if client.emit_type {
                fields.push(("type".to_owned(), CstInputValue::String("http".to_owned())));
            }
            fields.push(("url".to_owned(), CstInputValue::String(url.clone())));
            if let Some(token) = token {
                fields.push(("headers".to_owned(), json_bearer_headers(token)));
            }
        }
    }
    CstInputValue::Object(fields)
}

fn json_args(args: &[String]) -> CstInputValue {
    CstInputValue::Array(
        args.iter()
            .map(|a| CstInputValue::String(a.clone()))
            .collect(),
    )
}

fn json_set(obj: &CstObject, name: &str, value: CstInputValue) {
    match obj.get(name) {
        Some(prop) => prop.set_value(value),
        None => {
            obj.append(name, value);
        }
    }
}

fn json_looks_http(entry: &CstObject) -> bool {
    entry.get("url").is_some() || json_str(entry, "type").is_some_and(|t| is_http_type(&t))
}

fn is_http_type(t: &str) -> bool {
    t.eq_ignore_ascii_case("http")
        || t.eq_ignore_ascii_case("sse")
        || t.eq_ignore_ascii_case("streamable-http")
}

fn json_headers_auth(entry: &CstObject) -> Option<String> {
    let headers = entry.get("headers")?.object_value()?;
    json_str(&headers, "Authorization")
}

fn json_rewrite_auth(entry: &CstObject, old: &[String], new: &str) -> bool {
    let Some(headers) = entry.get("headers").and_then(|p| p.object_value()) else {
        return false;
    };
    let Some(prop) = headers.get("Authorization") else {
        return false;
    };
    let Some(value) = prop
        .value()
        .and_then(|v| v.as_string_lit()?.decoded_value().ok())
    else {
        return false;
    };
    let Some(token) = bearer_token(&value) else {
        return false;
    };
    if !old.iter().any(|o| o == token) {
        return false;
    }
    prop.set_value(CstInputValue::String(format!("Bearer {new}")));
    true
}

fn json_str(obj: &CstObject, name: &str) -> Option<String> {
    obj.get(name)?
        .value()?
        .as_string_lit()?
        .decoded_value()
        .ok()
}

fn json_strs(obj: &CstObject, name: &str) -> Option<Vec<String>> {
    let arr = obj.get(name)?.value()?.as_array()?;
    arr.elements()
        .iter()
        .map(|e| CstNode::as_string_lit(e)?.decoded_value().ok())
        .collect()
}

// -------------------------------------------------------------------- TOML ---

fn upsert_toml(doc: &mut DocumentMut, client: &Client, spec: &ServerSpec) -> Result<Op> {
    if doc
        .get(client.key)
        .is_some_and(|i| i.as_table_like().is_none())
    {
        bail!("{} 不是 TOML 表，拒绝写入", client.key);
    }
    if doc.get(client.key).is_none() {
        let mut t = Table::new();
        // Implicit: emit `[mcp_servers.vibrev-ida]` without a bare
        // `[mcp_servers]` header above it, which is how Codex writes it.
        t.set_implicit(true);
        doc.insert(client.key, Item::Table(t));
    }

    let parent = doc
        .get_mut(client.key)
        .and_then(Item::as_table_like_mut)
        .expect("just checked or created above");

    let existing = parent.get(spec.name());
    if let Some(item) = existing {
        let Some(tbl) = item.as_table_like() else {
            bail!("{}.{} 不是 TOML 表，拒绝写入", client.key, spec.name());
        };
        if toml_matches(tbl, spec) {
            return Ok(Op::Unchanged);
        }
        let tbl = parent
            .get_mut(spec.name())
            .and_then(Item::as_table_like_mut)
            .expect("checked immediately above");
        toml_apply(tbl, spec);
        return Ok(Op::Updated);
    }

    parent.insert(spec.name(), Item::Table(toml_entry(spec)));
    Ok(Op::Added)
}

fn toml_matches(tbl: &dyn toml_edit::TableLike, spec: &ServerSpec) -> bool {
    match spec {
        ServerSpec::Stdio { command, args, .. } => {
            let http_leftovers = HTTP_TRANSPORT_KEYS.iter().any(|k| tbl.get(k).is_some());
            !http_leftovers
                && tbl.get("command").and_then(Item::as_str) == Some(command.as_str())
                && tbl.get("args").and_then(toml_strs).unwrap_or_default() == *args
        }
        ServerSpec::Http { url, token, .. } => {
            let stdio_leftovers = STDIO_TRANSPORT_KEYS.iter().any(|k| tbl.get(k).is_some());
            !stdio_leftovers
                && tbl.get("url").and_then(Item::as_str) == Some(url.as_str())
                && toml_token_matches(tbl, token.as_deref())
        }
    }
}

fn toml_token_matches(tbl: &dyn toml_edit::TableLike, token: Option<&str>) -> bool {
    match token {
        Some(want) => {
            toml_headers_auth_from(tbl).and_then(|v| bearer_token(&v).map(str::to_owned))
                == Some(want.to_owned())
        }
        None => CREDENTIAL_KEYS.iter().all(|k| tbl.get(k).is_none()),
    }
}

fn toml_apply(tbl: &mut dyn toml_edit::TableLike, spec: &ServerSpec) {
    match spec {
        ServerSpec::Stdio { command, args, .. } => {
            tbl.insert("command", Item::Value(Value::from(command.clone())));
            tbl.insert("args", Item::Value(Value::Array(toml_args(args))));
            for key in HTTP_TRANSPORT_KEYS {
                tbl.remove(key);
            }
        }
        ServerSpec::Http { url, token, .. } => {
            tbl.insert("url", Item::Value(Value::from(url.clone())));
            match token {
                Some(token) => toml_set_bearer(tbl, token),
                None => {
                    for key in CREDENTIAL_KEYS {
                        tbl.remove(key);
                    }
                }
            }
            for key in STDIO_TRANSPORT_KEYS {
                tbl.remove(key);
            }
        }
    }
}

fn toml_set_bearer(tbl: &mut dyn toml_edit::TableLike, token: &str) {
    let value = Item::Value(Value::from(format!("Bearer {token}")));
    if let Some(headers) = tbl
        .get_mut("http_headers")
        .and_then(Item::as_table_like_mut)
    {
        headers.insert("Authorization", value);
        tbl.remove("headers");
        return;
    }
    if let Some(headers) = tbl.get_mut("headers").and_then(Item::as_table_like_mut) {
        headers.insert("Authorization", value);
        return;
    }
    let mut headers = Table::new();
    headers.insert(
        "Authorization",
        Item::Value(Value::from(format!("Bearer {token}"))),
    );
    tbl.insert("http_headers", Item::Table(headers));
    tbl.remove("headers");
}

fn toml_entry(spec: &ServerSpec) -> Table {
    let mut tbl = Table::new();
    toml_apply(&mut tbl, spec);
    tbl
}

fn toml_headers_auth_from(tbl: &dyn toml_edit::TableLike) -> Option<String> {
    for key in CREDENTIAL_KEYS {
        if let Some(value) = tbl
            .get(key)
            .and_then(Item::as_table_like)
            .and_then(|h| h.get("Authorization"))
            .and_then(Item::as_str)
        {
            return Some(value.to_owned());
        }
    }
    None
}

fn toml_looks_http(item: &Item) -> bool {
    let Some(tbl) = item.as_table_like() else {
        return false;
    };
    tbl.get("url").is_some()
        || tbl
            .get("type")
            .and_then(Item::as_str)
            .is_some_and(is_http_type)
}

fn toml_headers_auth(item: &Item) -> Option<String> {
    toml_headers_auth_from(item.as_table_like()?)
}

fn toml_rewrite_auth(item: &mut Item, old: &[String], new: &str) -> bool {
    let Some(tbl) = item.as_table_like_mut() else {
        return false;
    };
    let current = toml_headers_auth_from(tbl);
    let matches = current
        .as_deref()
        .and_then(bearer_token)
        .is_some_and(|token| old.iter().any(|o| o == token));
    if !matches {
        return false;
    }
    toml_set_bearer(tbl, new);
    true
}

/// RFC 9110: the scheme match is case-insensitive; the credential is not.
fn bearer_token(value: &str) -> Option<&str> {
    let (scheme, credential) = value.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("bearer") {
        return None;
    }
    let credential = credential.trim();
    (!credential.is_empty()).then_some(credential)
}

fn toml_args(args: &[String]) -> Array {
    args.iter().collect()
}

fn toml_strs(item: &Item) -> Option<Vec<String>> {
    item.as_array()?
        .iter()
        .map(|v| v.as_str().map(str::to_owned))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::by_id;

    fn spec(engine: &'static str, command: &str, args: &[&str]) -> ServerSpec {
        ServerSpec::Stdio {
            name: crate::client::server_name(engine),
            engine,
            command: command.to_owned(),
            args: args.iter().map(|s| (*s).to_owned()).collect(),
        }
    }

    fn http_spec(engine: &'static str, url: &str, token: Option<&str>) -> ServerSpec {
        ServerSpec::Http {
            name: crate::client::server_name(engine),
            engine,
            url: url.to_owned(),
            token: token.map(str::to_owned),
        }
    }

    fn edit(text: &str, client_id: &str, spec: &ServerSpec) -> (Op, String) {
        let client = by_id(client_id).unwrap();
        let mut doc = parse(text, client.format, Utf8Path::new("<test>")).unwrap();
        let op = doc.upsert(client, spec).unwrap();
        (op, doc.render())
    }

    #[test]
    fn vscode_comments_and_inputs_survive_a_write() {
        let before = r#"{
  // My own notes about this file.
  "inputs": [
    { "id": "token", "type": "promptString" } // secret, do not inline
  ],
  "servers": {
    /* block comment */
    "fetch": { "command": "uvx", "args": ["mcp-server-fetch"] }
  }
}
"#;
        let (op, after) = edit(
            before,
            "vscode",
            &spec("jadx", "/opt/rjadx", &["mcp", "--stdio"]),
        );
        assert_eq!(op, Op::Added);
        assert!(after.contains("// My own notes about this file."));
        assert!(after.contains("// secret, do not inline"));
        assert!(after.contains("/* block comment */"));
        assert!(after.contains("\"inputs\""));
        assert!(after.contains("mcp-server-fetch"));
        assert!(after.contains("\"vibrev-jadx\""));
        assert!(after.contains("\"type\": \"stdio\""));
    }

    #[test]
    fn running_twice_updates_in_place() {
        let s = spec("ida", "/opt/a/ida-headless-mcp", &[]);
        let (op1, once) = edit("{}", "cursor", &s);
        assert_eq!(op1, Op::Added);

        let (op2, twice) = edit(&once, "cursor", &s);
        assert_eq!(op2, Op::Unchanged, "an identical entry is not rewritten");
        assert_eq!(once, twice);

        let moved = spec("ida", "/opt/b/ida-headless-mcp", &[]);
        let (op3, third) = edit(&twice, "cursor", &moved);
        assert_eq!(op3, Op::Updated);
        assert_eq!(
            third.matches("vibrev-ida").count(),
            1,
            "never a second entry"
        );
        assert!(third.contains("/opt/b/ida-headless-mcp"));
        assert!(!third.contains("/opt/a/ida-headless-mcp"));
    }

    #[test]
    fn other_servers_and_sibling_keys_are_left_alone() {
        let before = r#"{
  "numStartups": 42,
  "mcpServers": {
    "sentry": { "type": "http", "url": "https://mcp.sentry.dev/mcp" }
  },
  "theme": "dark"
}
"#;
        let (_, after) = edit(before, "claude-code", &spec("jadx", "/opt/rjadx", &["mcp"]));
        assert!(after.contains("\"numStartups\": 42"));
        assert!(after.contains("https://mcp.sentry.dev/mcp"));
        assert!(after.contains("\"theme\": \"dark\""));
    }

    #[test]
    fn user_added_fields_on_our_own_entry_survive_an_update() {
        let before = r#"{
  "mcpServers": {
    "vibrev-jadx": {
      "type": "stdio",
      "command": "/old/rjadx",
      "args": ["mcp", "--stdio"],
      "env": { "RUST_LOG": "debug" }
    }
  }
}
"#;
        let (op, after) = edit(
            before,
            "claude-code",
            &spec("jadx", "/new/rjadx", &["mcp", "--stdio"]),
        );
        assert_eq!(op, Op::Updated);
        assert!(after.contains("\"RUST_LOG\": \"debug\""));
        assert!(after.contains("/new/rjadx"));
    }

    #[test]
    fn codex_toml_keeps_unrelated_sections() {
        let before = r#"model = "o3"

# A comment the user wrote.
[model_providers.openai]
name = "OpenAI"

[mcp_servers.other]
command = "npx"
args = ["-y", "other"]
"#;
        let (op, after) = edit(before, "codex", &spec("ida", "/opt/ida-headless-mcp", &[]));
        assert_eq!(op, Op::Added);
        assert!(after.contains(r#"model = "o3""#));
        assert!(after.contains("# A comment the user wrote."));
        assert!(after.contains("[model_providers.openai]"));
        assert!(after.contains("[mcp_servers.other]"));
        assert!(after.contains("[mcp_servers.vibrev-ida]"));
        // No `type` key: Codex infers stdio from `command`.
        assert!(!after.contains("type ="));
    }

    #[test]
    fn codex_creates_no_bare_parent_header() {
        let (_, after) = edit(
            "",
            "codex",
            &spec("jadx", "/opt/rjadx", &["mcp", "--stdio"]),
        );
        assert!(after.contains("[mcp_servers.vibrev-jadx]"));
        assert!(!after.contains("\n[mcp_servers]"));
        assert!(!after.starts_with("[mcp_servers]"));
        assert!(after.contains(r#"args = ["mcp", "--stdio"]"#));
    }

    #[test]
    fn toml_update_is_in_place_and_keeps_extra_keys() {
        let before = r#"[mcp_servers.vibrev-jadx]
command = "/old/rjadx"
args = ["mcp"]
startup_timeout_sec = 30
"#;
        let (op, after) = edit(
            before,
            "codex",
            &spec("jadx", "/new/rjadx", &["mcp", "--stdio"]),
        );
        assert_eq!(op, Op::Updated);
        assert!(after.contains("startup_timeout_sec = 30"));
        assert_eq!(after.matches("[mcp_servers.vibrev-jadx]").count(), 1);
    }

    /// The shape the HTTP setup docs show users for the HTTP option, token and
    /// all.
    fn http_entry_json() -> &'static str {
        r#"{
  "mcpServers": {
    "vibrev-ida": {
      "type": "http",
      "url": "http://127.0.0.1:8745/mcp",
      "headers": { "Authorization": "Bearer vbr_LEAKED" },
      "env": { "RUST_LOG": "debug" }
    }
  }
}
"#
    }

    #[test]
    fn rewriting_an_http_entry_drops_url_and_headers() {
        let (op, after) = edit(
            http_entry_json(),
            "claude-code",
            &spec("ida", "/opt/ida-headless-mcp", &["serve", "--stdio"]),
        );
        assert_eq!(op, Op::Updated);
        // The point of the whole exercise: no credential survives the rewrite.
        assert!(!after.contains("vbr_LEAKED"), "token left behind:\n{after}");
        assert!(!after.contains("Authorization"), "{after}");
        assert!(!after.contains("\"headers\""), "{after}");
        assert!(!after.contains("\"url\""), "{after}");
        assert!(!after.contains("8745"), "{after}");
        // …and the entry is now unambiguously one transport.
        assert!(after.contains("\"type\": \"stdio\""));
        assert!(after.contains("/opt/ida-headless-mcp"));
        // Keys orthogonal to transport are still none of our business.
        assert!(after.contains("\"RUST_LOG\": \"debug\""), "{after}");
    }

    #[test]
    fn writing_http_drops_command_and_args() {
        let before = r#"{
  "mcpServers": {
    "vibrev-ida": {
      "type": "stdio",
      "command": "/opt/ida-headless-mcp",
      "args": ["serve", "--mode", "stdio"],
      "env": { "RUST_LOG": "debug" }
    }
  }
}
"#;
        let (op, after) = edit(
            before,
            "claude-code",
            &http_spec("ida", "http://127.0.0.1:8765/mcp", Some("vbr_CURRENT")),
        );
        assert_eq!(op, Op::Updated);
        assert!(after.contains("\"type\": \"http\""), "{after}");
        assert!(after.contains("http://127.0.0.1:8765/mcp"), "{after}");
        assert!(after.contains("Bearer vbr_CURRENT"), "{after}");
        assert!(!after.contains("command"), "{after}");
        assert!(!after.contains("args"), "{after}");
        assert!(after.contains("\"RUST_LOG\": \"debug\""), "{after}");
    }

    #[test]
    fn project_http_writes_the_url_and_not_the_token() {
        let (op, after) = edit(
            "{}",
            "claude-code",
            &http_spec("ida", "http://127.0.0.1:8765/mcp", None),
        );
        assert_eq!(op, Op::Added);
        assert!(
            after.contains("\"url\": \"http://127.0.0.1:8765/mcp\""),
            "{after}"
        );
        assert!(!after.contains("Authorization"), "{after}");
        assert!(!after.contains("headers"), "{after}");
    }

    #[test]
    fn toml_http_uses_http_headers() {
        let (op, after) = edit(
            "",
            "codex",
            &http_spec("ida", "http://127.0.0.1:8765/mcp", Some("vbr_CURRENT")),
        );
        assert_eq!(op, Op::Added);
        assert!(
            after.contains("url = \"http://127.0.0.1:8765/mcp\""),
            "{after}"
        );
        assert!(
            after.contains("[mcp_servers.vibrev-ida.http_headers]"),
            "{after}"
        );
        assert!(
            after.contains("Authorization = \"Bearer vbr_CURRENT\""),
            "{after}"
        );
        assert!(!after.contains("command"), "{after}");
    }

    #[test]
    fn a_leftover_token_is_never_reported_as_unchanged() {
        // command and args already match, so only the credential makes this a
        // change. If `Unchanged` won here the token would be silently kept and
        // never even printed in the diff.
        let before = r#"{
  "mcpServers": {
    "vibrev-jadx": {
      "type": "stdio",
      "command": "/opt/rjadx",
      "args": ["mcp", "--stdio"],
      "headers": { "Authorization": "Bearer vbr_LEAKED" }
    }
  }
}
"#;
        let (op, after) = edit(
            before,
            "claude-code",
            &spec("jadx", "/opt/rjadx", &["mcp", "--stdio"]),
        );
        assert_eq!(op, Op::Updated, "a stale credential is a change");
        assert!(!after.contains("vbr_LEAKED"), "{after}");
    }

    #[test]
    fn toml_rewrite_drops_url_and_headers_too() {
        let before = r#"[mcp_servers.vibrev-ida]
url = "http://127.0.0.1:8745/mcp"
startup_timeout_sec = 30

[mcp_servers.vibrev-ida.headers]
Authorization = "Bearer vbr_LEAKED"
"#;
        let (op, after) = edit(before, "codex", &spec("ida", "/opt/ida-headless-mcp", &[]));
        assert_eq!(op, Op::Updated);
        assert!(!after.contains("vbr_LEAKED"), "{after}");
        assert!(!after.contains("Authorization"), "{after}");
        assert!(!after.contains("url ="), "{after}");
        assert!(after.contains("/opt/ida-headless-mcp"));
        assert!(after.contains("startup_timeout_sec = 30"), "{after}");
    }

    #[test]
    fn credentials_are_detected_before_they_are_stripped() {
        let c = by_id("claude-code").unwrap();
        let doc = parse(http_entry_json(), c.format, Utf8Path::new("<test>")).unwrap();
        assert!(doc.carries_credentials(c, "vibrev-ida"));
        // A plain stdio entry is not a false positive, and neither is a name we
        // do not have at all.
        assert!(!doc.carries_credentials(c, "vibrev-jadx"));

        let plain = parse(
            r#"{"mcpServers":{"vibrev-jadx":{"command":"/opt/rjadx","args":[]}}}"#,
            c.format,
            Utf8Path::new("<test>"),
        )
        .unwrap();
        assert!(!plain.carries_credentials(c, "vibrev-jadx"));

        let toml = by_id("codex").unwrap();
        let t = parse(
            "[mcp_servers.vibrev-ida.headers]\nAuthorization = \"Bearer x\"\n",
            toml.format,
            Utf8Path::new("<test>"),
        )
        .unwrap();
        assert!(t.carries_credentials(toml, "vibrev-ida"));
    }

    #[test]
    fn rotate_rewrites_only_our_http_bearer() {
        let c = by_id("claude-code").unwrap();
        let mut doc = parse(http_entry_json(), c.format, Utf8Path::new("<test>")).unwrap();
        let changed = doc.rewrite_owned_http_bearers(c, &["vbr_LEAKED".to_owned()], "vbr_NEW");
        assert_eq!(changed, ["vibrev-ida"]);
        let after = doc.render();
        assert!(after.contains("Bearer vbr_NEW"), "{after}");
        assert!(!after.contains("vbr_LEAKED"), "{after}");
        assert!(after.contains("http://127.0.0.1:8745/mcp"), "{after}");
    }

    #[test]
    fn rotate_does_not_touch_stdio_leftovers_or_someone_elses_server() {
        let c = by_id("claude-code").unwrap();
        let before = r#"{
  "mcpServers": {
    "sentry": {
      "type": "http",
      "url": "https://mcp.sentry.dev/mcp",
      "headers": { "Authorization": "Bearer vbr_LEAKED" }
    },
    "vibrev-jadx": {
      "type": "stdio",
      "command": "/opt/rjadx",
      "args": ["mcp", "--stdio"],
      "headers": { "Authorization": "Bearer vbr_LEAKED" }
    }
  }
}
"#;
        let mut doc = parse(before, c.format, Utf8Path::new("<test>")).unwrap();
        let changed = doc.rewrite_owned_http_bearers(c, &["vbr_LEAKED".to_owned()], "vbr_NEW");
        assert!(changed.is_empty(), "{changed:?}");
        let after = doc.render();
        assert!(after.contains("vbr_LEAKED"), "{after}");
        assert!(!after.contains("vbr_NEW"), "{after}");
    }

    #[test]
    fn rotate_rewrites_codex_toml_headers_too() {
        let c = by_id("codex").unwrap();
        let before = r#"[mcp_servers.other]
url = "https://example"
[mcp_servers.other.headers]
Authorization = "Bearer vbr_LEAKED"

[mcp_servers.vibrev-ida]
url = "http://127.0.0.1:8745/mcp"
[mcp_servers.vibrev-ida.headers]
Authorization = "Bearer vbr_LEAKED"
"#;
        let mut doc = parse(before, c.format, Utf8Path::new("<test>")).unwrap();
        let changed = doc.rewrite_owned_http_bearers(c, &["vbr_LEAKED".to_owned()], "vbr_NEW");
        assert_eq!(changed, ["vibrev-ida"]);
        let after = doc.render();
        assert!(after.contains("Bearer vbr_NEW"), "{after}");
        assert!(
            after.contains("Bearer vbr_LEAKED"),
            "foreign token kept:\n{after}"
        );
    }

    #[test]
    fn someone_elses_http_server_is_still_none_of_our_business() {
        // The strip is scoped to entries we own. A user's own remote server keeps
        // its url and its credential.
        let before = r#"{
  "mcpServers": {
    "sentry": {
      "type": "http",
      "url": "https://mcp.sentry.dev/mcp",
      "headers": { "Authorization": "Bearer their_token" }
    }
  }
}
"#;
        let (_, after) = edit(before, "claude-code", &spec("jadx", "/opt/rjadx", &["mcp"]));
        assert!(after.contains("their_token"), "{after}");
        assert!(after.contains("https://mcp.sentry.dev/mcp"));
    }

    #[test]
    fn a_syntax_error_is_an_error_not_an_empty_document() {
        let broken = r#"{ "mcpServers": { "a": { "command": "x" } "#;
        let Err(err) = parse(broken, Format::Json, Utf8Path::new("/tmp/x.json")) else {
            panic!("truncated JSON must not parse");
        };
        assert!(format!("{err:#}").contains("/tmp/x.json"));

        let broken_toml = "[mcp_servers.a\ncommand = \"x\"\n";
        assert!(parse(broken_toml, Format::Toml, Utf8Path::new("/tmp/x.toml")).is_err());
    }

    #[test]
    fn a_non_object_servers_key_is_refused_rather_than_replaced() {
        let client = by_id("cursor").unwrap();
        let mut doc = parse(
            r#"{ "mcpServers": "oops" }"#,
            Format::Json,
            Utf8Path::new("<test>"),
        )
        .unwrap();
        assert!(doc.upsert(client, &spec("ida", "/x", &[])).is_err());
        // And the document is untouched, so nothing was half-written.
        assert!(doc.render().contains(r#""oops""#));
    }

    #[test]
    fn removal_only_takes_our_own_entry() {
        let client = by_id("claude-code").unwrap();
        let before = r#"{
  "mcpServers": {
    "keepme": { "command": "npx" },
    "vibrev-ida": { "command": "/opt/ida-headless-mcp", "args": [] }
  }
}
"#;
        let mut doc = parse(before, client.format, Utf8Path::new("<test>")).unwrap();
        assert_eq!(doc.remove(client, "vibrev-ida").unwrap(), Op::Removed);
        assert_eq!(doc.remove(client, "vibrev-ida").unwrap(), Op::Absent);
        let after = doc.render();
        assert!(after.contains("keepme"));
        assert!(!after.contains("vibrev-ida"));
        // The container stays, even now that it holds only the user's server.
        assert!(after.contains("mcpServers"));
    }

    #[test]
    fn listing_reports_only_vibrev_entries() {
        let client = by_id("codex").unwrap();
        let doc = parse(
            r#"[mcp_servers.other]
command = "npx"
args = ["-y", "x"]

[mcp_servers.vibrev-jadx]
command = "/opt/rjadx"
args = ["mcp", "--stdio"]
"#,
            client.format,
            Utf8Path::new("<test>"),
        )
        .unwrap();
        let ours = doc.ours(client);
        assert_eq!(ours.len(), 1);
        assert_eq!(ours[0].name, "vibrev-jadx");
        assert_eq!(ours[0].command.as_deref(), Some("/opt/rjadx"));
        assert_eq!(ours[0].args, ["mcp", "--stdio"]);
    }

    #[test]
    fn an_empty_file_becomes_a_minimal_document() {
        let (op, after) = edit(
            "",
            "cursor",
            &spec("jadx", "/opt/rjadx", &["mcp", "--stdio"]),
        );
        assert_eq!(op, Op::Added);
        let v: serde_json::Value = serde_json::from_str(&after).expect("valid strict JSON");
        assert_eq!(v["mcpServers"]["vibrev-jadx"]["command"], "/opt/rjadx");
        // Cursor's schema has no `type`, so we do not invent one.
        assert!(v["mcpServers"]["vibrev-jadx"].get("type").is_none());
        assert!(after.ends_with('\n'));
    }
}
