//! The net under a tool answer that is too large to send.
//!
//! Paging bounds the answers a tool *plans* to give. This bounds the ones it
//! did not plan: one decompiled function that runs to ten megabytes, one search
//! whose pattern happened to match everything. Those arrive as a single value
//! with no `limit` on it, and the client they arrive at has a context window.
//!
//! # It is a net, not a floor
//!
//! The threshold has to sit *above* what the paged tools normally produce, and
//! this is not a detail — a third engine got it wrong in a way worth writing
//! down. `jadx-headless-mcp` reimplemented this design and set one tool's
//! default `max_bytes` to 65536 against a 50,000-character threshold, so an
//! ordinary "fetch this class's source" call tripped the net: the caller asked
//! for 64 KB of source and received a 1,600-character preview plus a URL. The
//! net had replaced the answer instead of catching an accident.
//!
//! [`OutputCache::spills`] exists for that: an engine can assert in its own
//! tests that a representative call does not trip the net.
//!
//! # Why the preview keeps its shape
//!
//! Over the threshold, the payload is trimmed *in place* — every object key
//! survives, long strings and long arrays are shortened — rather than replaced
//! by a `{truncated: true, …}` envelope. A caller can then see what the answer
//! looks like and how much of it there is, and decide whether to fetch the rest.
//! An envelope tells it only that something was withheld.
//!
//! Keeping the shape also means the advertised `outputSchema` stays true: a
//! preview still validates against it. The bookkeeping goes in `_meta`, which no
//! schema describes.

use std::collections::{HashMap, VecDeque};
use std::fs::DirBuilder;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use serde_json::{Value, json};
use tokio::io::AsyncWriteExt;
use tokio::sync::Mutex;

/// The `_meta` key the truncation bookkeeping travels under.
///
/// One name across the engines rather than one per engine. A client that knows
/// how to fetch a spilled output from `ida-headless-mcp` can do it for
/// `bn-headless-mcp` without being taught twice, and `_meta` keys are namespaced
/// by convention precisely so that a project can claim one.
pub const META_KEY: &str = "vibrev";

/// How large an answer may be, and what a preview of a larger one looks like.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    /// Serialized characters past which the net catches the answer.
    pub max_chars: usize,
    /// How many entries of a long array survive into the preview.
    pub preview_items: usize,
    /// How many characters of a long string survive into the preview.
    pub preview_string_chars: usize,
    /// How deep the trimming recurses before leaving a subtree alone.
    ///
    /// Below this depth the value is cloned whole: something has to stop the
    /// walk, and a deeply nested value that is *also* enormous is caught by the
    /// character count regardless — it just gets a coarser preview.
    pub preview_depth: usize,
    /// How long a spilled output stays fetchable.
    pub ttl: Duration,
    /// How many spilled outputs are kept before the oldest is dropped.
    pub max_entries: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_chars: 50_000,
            preview_items: 10,
            preview_string_chars: 1_000,
            preview_depth: 5,
            ttl: Duration::from_secs(30 * 60),
            max_entries: 128,
        }
    }
}

/// Where the full answer goes when the net catches one.
#[derive(Clone)]
pub enum Spill {
    /// Nowhere. The preview is all the caller gets.
    ///
    /// Honest for an engine with no second channel — and still much better than
    /// sending ten megabytes, because the preview says how much was held back.
    Nowhere,
    /// Kept in memory, fetched over this server's own HTTP face.
    Http {
        /// Used when a request carries nothing better — see [`external_base_url`].
        fallback_base_url: String,
    },
    /// Written to a private file, handed over as a `file://` URL.
    ///
    /// For stdio: there is no listener to fetch from, but the client is on this
    /// machine by construction — it started the process.
    ///
    /// The directory is removed when the cache is dropped, which means on a
    /// clean exit and not otherwise: a process killed with SIGKILL runs no
    /// destructors and leaves its spills behind. They are `0700`, so no other
    /// user can read them, but they are there until something else cleans up.
    File { directory: PathBuf },
}

/// The answer as it will go on the wire, and what was done to it.
#[derive(Debug)]
pub struct Prepared {
    pub value: Value,
    /// `None` when the answer fit and nothing was touched.
    pub truncation: Option<Truncation>,
}

impl Prepared {
    pub fn unchanged(value: Value) -> Self {
        Self {
            value,
            truncation: None,
        }
    }
}

/// What a caller needs to know to get the part that did not fit.
#[derive(Debug)]
pub struct Truncation {
    /// Goes in `_meta.vibrev`: `output_truncated`, `total_chars`, `output_id`,
    /// `download_url`, `download_hint`.
    pub metadata: Value,
    /// A sentence a human can act on, added as a second content block.
    pub hint: String,
}

#[derive(Debug, thiserror::Error)]
pub enum OutputError {
    #[error("failed to serialize tool output: {0}")]
    Serialize(#[from] serde_json::Error),
    #[error("failed to persist tool output: {0}")]
    Io(#[from] io::Error),
}

/// The net itself: trims what is too large, keeps the original fetchable.
#[derive(Clone)]
pub struct OutputCache {
    inner: Arc<CacheInner>,
    spill: Spill,
    limits: Limits,
}

struct CacheInner {
    state: Mutex<CacheState>,
    /// Removed on drop. Set only for [`Spill::File`], whose directory this
    /// process created and therefore owns.
    owned_directory: Option<PathBuf>,
    spills: AtomicU64,
}

impl Drop for CacheInner {
    fn drop(&mut self) {
        if let Some(directory) = &self.owned_directory {
            let _ = std::fs::remove_dir_all(directory);
        }
    }
}

#[derive(Default)]
struct CacheState {
    entries: HashMap<String, Cached>,
    order: VecDeque<String>,
}

struct Cached {
    /// Held in memory only for [`Spill::Http`]; the file variant has the file.
    value: Option<Value>,
    created_at: Instant,
    file_path: Option<PathBuf>,
}

impl OutputCache {
    /// Trim only. No second channel, so nothing is kept.
    pub fn truncating() -> Self {
        Self::with_spill(Spill::Nowhere, None)
    }

    /// Keep the full answer in memory, fetchable at `{base}/output/{id}.json`.
    pub fn http(fallback_base_url: impl Into<String>) -> Self {
        Self::with_spill(
            Spill::Http {
                fallback_base_url: fallback_base_url.into().trim_end_matches('/').to_string(),
            },
            None,
        )
    }

    /// Write full answers into a private directory of this process's own.
    ///
    /// `engine` only names the directory, so that an operator looking at
    /// `/tmp` can tell which process left one behind.
    pub fn spilling_to_files(engine: &str) -> Result<Self, OutputError> {
        let directory = std::env::temp_dir().join(format!(
            "{engine}-output-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4().simple()
        ));
        create_private_directory(&directory)?;
        Ok(Self::with_spill(
            Spill::File {
                directory: directory.clone(),
            },
            Some(directory),
        ))
    }

    fn with_spill(spill: Spill, owned_directory: Option<PathBuf>) -> Self {
        Self {
            inner: Arc::new(CacheInner {
                state: Mutex::new(CacheState::default()),
                owned_directory,
                spills: AtomicU64::new(0),
            }),
            spill,
            limits: Limits::default(),
        }
    }

    /// Override the thresholds. See the note on the net not being a floor.
    pub fn with_limits(mut self, limits: Limits) -> Self {
        self.limits = limits;
        self
    }

    pub fn limits(&self) -> Limits {
        self.limits
    }

    /// How many answers this cache has caught.
    ///
    /// For an engine to assert, in its own tests, that a representative call
    /// does *not* trip the net — which is the failure a third implementation of
    /// this design shipped with, and which nothing about the net itself reveals:
    /// a caller who receives a preview cannot tell "your answer was enormous"
    /// from "this tool's default page is larger than the threshold".
    pub fn spills(&self) -> u64 {
        self.inner.spills.load(Ordering::Relaxed)
    }

    /// Trim `value` if it is too large, and make the original fetchable.
    ///
    /// `request_base_url` lets one HTTP request's own host win over the
    /// configured fallback, so a server behind a reverse proxy hands out a URL
    /// that resolves from where the client is standing.
    pub async fn compact(
        &self,
        value: Value,
        request_base_url: Option<&str>,
    ) -> Result<Prepared, OutputError> {
        let serialized = serde_json::to_string(&value)?;
        let total_chars = serialized.chars().count();
        if total_chars <= self.limits.max_chars {
            return Ok(Prepared::unchanged(value));
        }

        self.inner.spills.fetch_add(1, Ordering::Relaxed);
        let id = uuid::Uuid::new_v4().simple().to_string();
        let preview = truncate_value(&value, 0, &self.limits);
        let (download_url, hint, file_path, cached_value) = match &self.spill {
            Spill::Nowhere => (
                Value::Null,
                format!("Output truncated at {} characters.", self.limits.max_chars),
                None,
                None,
            ),
            Spill::Http { fallback_base_url } => {
                let base_url = request_base_url.unwrap_or(fallback_base_url);
                let url = format!("{}/output/{id}.json", base_url.trim_end_matches('/'));
                let hint = format!("Output truncated. Run: curl -o .vibrev/{id}.json {url}");
                (Value::String(url), hint, None, Some(value))
            }
            Spill::File { directory } => {
                let file_path = directory.join(format!("{id}.json"));
                write_private_file(&file_path, serialized.as_bytes()).await?;
                let url = file_url(&file_path);
                let hint = format!(
                    "Output truncated. Full output saved to {}",
                    file_path.display()
                );
                (Value::String(url), hint, Some(file_path), None)
            }
        };

        // Nothing to remember when there is nothing to fetch: an entry with no
        // value and no file is a key that can only ever answer 404.
        if !matches!(self.spill, Spill::Nowhere) {
            let mut state = self.inner.state.lock().await;
            reap(&mut state, self.limits.ttl);
            state.entries.insert(
                id.clone(),
                Cached {
                    value: cached_value,
                    created_at: Instant::now(),
                    file_path,
                },
            );
            state.order.push_back(id.clone());
            while state.entries.len() > self.limits.max_entries {
                let Some(oldest) = state.order.pop_front() else {
                    break;
                };
                if let Some(entry) = state.entries.remove(&oldest) {
                    remove_file(&entry);
                }
            }
        }

        Ok(Prepared {
            value: preview,
            truncation: Some(Truncation {
                metadata: json!({
                    "output_truncated": true,
                    "total_chars": total_chars,
                    "output_id": id,
                    "download_url": download_url,
                    "download_hint": hint,
                }),
                hint,
            }),
        })
    }

    /// The full answer behind an `output_id`, while it is still held.
    pub async fn get(&self, id: &str) -> Option<Value> {
        let mut state = self.inner.state.lock().await;
        reap(&mut state, self.limits.ttl);
        state.entries.get(id).and_then(|entry| entry.value.clone())
    }
}

fn reap(state: &mut CacheState, ttl: Duration) {
    let now = Instant::now();
    let expired = state
        .entries
        .iter()
        .filter(|(_, entry)| now.duration_since(entry.created_at) >= ttl)
        .map(|(id, _)| id.clone())
        .collect::<Vec<_>>();
    for id in expired {
        if let Some(entry) = state.entries.remove(&id) {
            remove_file(&entry);
        }
    }
    state.order.retain(|id| state.entries.contains_key(id));
}

fn remove_file(entry: &Cached) {
    if let Some(path) = &entry.file_path {
        let _ = std::fs::remove_file(path);
    }
}

/// Shorten a value without changing what it looks like.
///
/// Objects keep every key — that is what lets a caller read the preview as a
/// description of the answer rather than as a fragment of it. Only the two
/// things that grow without bound, long strings and long arrays, are cut, and a
/// cut string says how much was cut.
pub fn truncate_value(value: &Value, depth: usize, limits: &Limits) -> Value {
    if depth > limits.preview_depth {
        return value.clone();
    }

    match value {
        Value::String(text) if text.chars().count() > limits.preview_string_chars => {
            let preview = text
                .chars()
                .take(limits.preview_string_chars)
                .collect::<String>();
            Value::String(format!(
                "{preview}... [{} chars total]",
                text.chars().count()
            ))
        }
        Value::Array(items) => Value::Array(
            items
                .iter()
                .take(limits.preview_items)
                .map(|item| truncate_value(item, depth + 1, limits))
                .collect(),
        ),
        Value::Object(fields) => Value::Object(
            fields
                .iter()
                .map(|(key, value)| (key.clone(), truncate_value(value, depth + 1, limits)))
                .collect(),
        ),
        // Spelled out rather than `_`: the remaining variants are scalars that
        // cannot exceed a bound, and naming them keeps the exhaustiveness check.
        Value::String(_) | Value::Null | Value::Bool(_) | Value::Number(_) => value.clone(),
    }
}

/// A server whose answers are held to a size.
///
/// The same shape as [`policy::Governed`](crate::policy::Governed), and for the
/// same reason: what a server *is* should not have to change so that its answers
/// can be bounded, and an engine that grows a new tool should get the net for
/// free rather than remembering to route through it.
///
/// # Where to put it
///
/// Around the MCP handler, and nowhere else. The derived CLI reads the same
/// `CallToolResult` the MCP face does — that is deliberate, it is what makes the
/// two front ends agree — but a CLI writes to a pipe, not to a context window,
/// so truncating there would be answering a question nobody asked. Wrapping the
/// handler catches exactly the calls that arrive over the protocol.
///
/// In a supervisor/worker engine, wrap the *worker*. The oversized answer never
/// crosses the pipe between them, and a supervisor that forwards verbatim keeps
/// doing so — it forwards an answer that was already bounded.
pub struct Capped<S> {
    inner: S,
    cache: OutputCache,
}

impl<S> Capped<S> {
    pub fn new(inner: S, cache: OutputCache) -> Self {
        Self { inner, cache }
    }

    pub fn cache(&self) -> &OutputCache {
        &self.cache
    }

    pub fn inner(&self) -> &S {
        &self.inner
    }
}

impl<S: rmcp::ServerHandler + Send + Sync> crate::decorate::Decorator for Capped<S> {
    type Inner = S;

    fn inner(&self) -> &S {
        &self.inner
    }

    async fn call_tool(
        &self,
        params: rmcp::model::CallToolRequestParams,
        ctx: rmcp::service::RequestContext<rmcp::RoleServer>,
    ) -> Result<rmcp::model::CallToolResponse, rmcp::ErrorData> {
        let base_url = request_base_url(&ctx);
        let response = self.inner.call_tool(params, ctx).await?;
        // Only a completed call has a payload to measure. An elicitation or a
        // task handle is a small control message, and rewriting one would be
        // rewriting something this net was not built to read.
        let rmcp::model::CallToolResponse::Complete(result) = response else {
            return Ok(response);
        };
        let prepared = self
            .cache
            .compact(payload_of(&result), base_url.as_deref())
            .await
            .map_err(|error| {
                rmcp::ErrorData::internal_error(
                    format!("failed to store large tool output: {error}"),
                    None,
                )
            })?;
        let Some(truncation) = prepared.truncation else {
            return Ok(result.into());
        };
        Ok(capped_result(result, prepared.value, truncation, self.cache.limits).into())
    }
}

crate::decorated_handler!(Capped<S>, generic S: rmcp::ServerHandler + Send + Sync);

/// The value a result carries, in the form the net can measure.
///
/// `structuredContent` when there is one. Otherwise the text — parsed as JSON if
/// it is JSON, and taken as a plain string if it is not. That last arm matters:
/// a tool that answers with ten megabytes of disassembly and no structured
/// payload would otherwise measure as `null` and sail straight through the net.
fn payload_of(result: &rmcp::model::CallToolResult) -> Value {
    if let Some(structured) = &result.structured_content {
        return structured.clone();
    }
    let Some(text) = result
        .content
        .first()
        .and_then(|content| content.as_text())
        .map(|text| text.text.as_str())
    else {
        return Value::Null;
    };
    serde_json::from_str(text).unwrap_or_else(|_| Value::String(text.to_string()))
}

/// Rebuild a result around the preview, keeping everything that made it legible.
///
/// The text block is shortened rather than replaced by the preview's JSON. A
/// decompiler's answer stays pseudocode and a hexdump stays a hexdump — the
/// first `max_chars` of exactly the bytes that would have been sent, which is
/// the most a bounded answer can be. Replacing it with serialized JSON would
/// hand a model an escaped string where it was reading code.
fn capped_result(
    result: rmcp::model::CallToolResult,
    preview: Value,
    truncation: Truncation,
    limits: Limits,
) -> rmcp::model::CallToolResult {
    let head = result
        .content
        .first()
        .and_then(|content| content.as_text())
        .map(|text| truncate_text(&text.text, limits.max_chars))
        .unwrap_or_else(|| serde_json::to_string(&preview).unwrap_or_else(|_| "{}".to_string()));

    let mut capped = result;
    capped.content = vec![
        rmcp::model::ContentBlock::text(head),
        rmcp::model::ContentBlock::text(truncation.hint),
    ];
    // A tool that published no structured content does not acquire one here:
    // its `outputSchema`, if it has one, described the absence.
    if capped.structured_content.is_some() {
        capped.structured_content = Some(preview);
    }
    let mut meta = capped.meta.take().unwrap_or_default();
    meta.0.insert(META_KEY.to_string(), truncation.metadata);
    capped.meta = Some(meta);
    capped
}

fn truncate_text(text: &str, max_chars: usize) -> String {
    let total = text.chars().count();
    if total <= max_chars {
        return text.to_string();
    }
    let head: String = text.chars().take(max_chars).collect();
    format!("{head}\n... [{total} chars total]")
}

/// The base URL this request arrived on, when it arrived over HTTP.
///
/// `None` on stdio, where there is no request to read and no listener for a URL
/// to point at — [`Spill::File`] is the answer there.
#[cfg(feature = "http")]
fn request_base_url(ctx: &rmcp::service::RequestContext<rmcp::RoleServer>) -> Option<String> {
    ctx.extensions
        .get::<http::request::Parts>()
        .and_then(external_base_url)
}

#[cfg(not(feature = "http"))]
fn request_base_url(_ctx: &rmcp::service::RequestContext<rmcp::RoleServer>) -> Option<String> {
    None
}

/// A `file://` URL for an absolute path.
///
/// Hand-rolled rather than `url::Url::from_file_path`, and the reason is the
/// dependency graph: that crate reaches this one function through IDN handling
/// and a Unicode normalization table — twenty-six crates, in a crate the
/// installer depends on and which speaks no protocol at all. What is actually
/// needed is RFC 3986 percent-encoding of a path, which is the ten lines below.
///
/// The unreserved set plus `/`, which is a separator here rather than data.
/// Everything else — spaces, `#`, `?`, and every non-ASCII byte — is escaped,
/// because a client parses this back out of a JSON string.
fn file_url(path: &Path) -> String {
    #[cfg(unix)]
    let bytes = {
        use std::os::unix::ffi::OsStrExt;
        path.as_os_str().as_bytes().to_vec()
    };
    // A Windows path is not bytes, and it starts with a drive letter rather than
    // a separator, so it needs the extra `/` that makes `file:///C:/…`.
    #[cfg(not(unix))]
    let bytes = {
        let text = path.to_string_lossy().replace('\\', "/");
        let text = if text.starts_with('/') {
            text
        } else {
            format!("/{text}")
        };
        text.into_bytes()
    };

    let mut url = String::from("file://");
    for byte in bytes {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' | b'/' => {
                url.push(byte as char)
            }
            other => url.push_str(&format!("%{other:02X}")),
        }
    }
    url
}

fn create_private_directory(path: &Path) -> io::Result<()> {
    let mut builder = DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(path)
}

async fn write_private_file(path: &Path, contents: &[u8]) -> io::Result<()> {
    let mut options = tokio::fs::OpenOptions::new();
    options.write(true).create_new(true);
    // Created 0600 rather than chmod'd afterwards: between `create` and a later
    // `set_permissions` the file is readable by anyone who can reach the
    // directory, and this one holds whatever a tool just read out of a binary.
    #[cfg(unix)]
    options.mode(0o600);
    let mut file = options.open(path).await?;
    file.write_all(contents).await?;
    file.flush().await
}

/// Where a client would have to reach this server, as far as the request says.
///
/// A `download_url` built from the address the listener bound to is unreachable
/// the moment anything sits in front of it — a container port map, an SSH
/// tunnel, an ingress. The headers below are what a proxy leaves behind, in
/// descending order of how deliberate they are: an explicit override first, then
/// RFC 7239 `Forwarded`, then the `X-Forwarded-*` family, then the request's own
/// `Host`.
///
/// Returns `None` for anything that is not an `http`/`https` URL with a host, so
/// a spoofed header cannot put an arbitrary scheme into the answer.
#[cfg(feature = "http")]
pub fn external_base_url(parts: &http::request::Parts) -> Option<String> {
    if let Some(base) = header_value(&parts.headers, "x-vibrev-external-base") {
        return normalize_http_base(base);
    }

    if let Some(forwarded) = header_value(&parts.headers, "forwarded") {
        let mut scheme = None;
        let mut host = None;
        for parameter in forwarded.split(',').next()?.split(';') {
            let Some((name, value)) = parameter.trim().split_once('=') else {
                continue;
            };
            let value = value.trim().trim_matches('"');
            match name.trim().to_ascii_lowercase().as_str() {
                "proto" => scheme = Some(value),
                "host" => host = Some(value),
                // `for=` and `by=` name the peers, not where to reach this
                // server, and an extension parameter is not ours to read.
                _ => {}
            }
        }
        if let Some(host) = host {
            return normalize_http_base(&format!("{}://{host}", scheme.unwrap_or("http")));
        }
    }

    let host = header_value(&parts.headers, "x-forwarded-host")
        .or_else(|| header_value(&parts.headers, "host"))
        .or_else(|| parts.uri.authority().map(|authority| authority.as_str()))?
        .split(',')
        .next()?
        .trim();
    let scheme = header_value(&parts.headers, "x-forwarded-proto")
        .and_then(|value| value.split(',').next())
        .map(str::trim)
        .or_else(|| parts.uri.scheme_str())
        .unwrap_or("http");
    let prefix = header_value(&parts.headers, "x-forwarded-prefix")
        .and_then(|value| value.split(',').next())
        .map(str::trim)
        .unwrap_or("")
        .trim_matches('/');
    let candidate = if prefix.is_empty() {
        format!("{scheme}://{host}")
    } else {
        format!("{scheme}://{host}/{prefix}")
    };
    normalize_http_base(&candidate)
}

#[cfg(feature = "http")]
fn header_value<'a>(headers: &'a http::HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name)?.to_str().ok()
}

/// A base URL a client can be handed, or `None`.
///
/// `http::Uri` rather than a URL crate: this runs only under the `http` feature,
/// where that type is already compiled, and what it has to decide is narrow —
/// is there an `http`/`https` scheme, is there a host, and what is the path with
/// the query and fragment dropped.
#[cfg(feature = "http")]
fn normalize_http_base(candidate: &str) -> Option<String> {
    let uri: http::Uri = candidate.parse().ok()?;
    if !matches!(uri.scheme_str(), Some("http") | Some("https")) {
        return None;
    }
    let scheme = uri.scheme_str()?;
    let authority = uri.authority()?.as_str();
    let path = uri.path().trim_end_matches('/');
    Some(format!("{scheme}://{authority}{path}"))
}

/// The `GET /output/{id}.json` route an engine mounts beside its `/mcp` one.
///
/// Behind whatever the listener requires: `Listener::serve` layers the credential
/// gate over the whole router, so this is not a second, unauthenticated way to
/// read a tool's answer. That was the failure this arrangement was built to make
/// impossible — see `transport`.
#[cfg(feature = "http")]
pub async fn serve_output(
    axum::extract::State(cache): axum::extract::State<OutputCache>,
    axum::extract::Path(path): axum::extract::Path<String>,
) -> Result<axum::Json<Value>, http::StatusCode> {
    let id = output_id(&path).ok_or(http::StatusCode::NOT_FOUND)?;
    cache
        .get(id)
        .await
        .map(axum::Json)
        .ok_or(http::StatusCode::NOT_FOUND)
}

/// The id in `{id}.json`, and only that.
///
/// A path segment is what a client sends, so it is refused unless it is exactly
/// one `.json` file name: no separators, nothing empty. The ids are UUIDs and
/// the lookup is a map, so nothing here reaches the filesystem — but a route
/// that accepts `../` shaped input is one refactor away from one that does.
#[cfg(feature = "http")]
fn output_id(path: &str) -> Option<&str> {
    path.trim_start_matches('/')
        .strip_suffix(".json")
        .filter(|id| !id.is_empty() && !id.contains('/'))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Read a `file://` URL back the way a client does.
    fn file_path_of(url: &str) -> PathBuf {
        let encoded = url.strip_prefix("file://").expect("a file URL");
        let mut bytes = Vec::new();
        let mut chars = encoded.chars();
        while let Some(ch) = chars.next() {
            if ch == '%' {
                let hex: String = chars.by_ref().take(2).collect();
                bytes.push(u8::from_str_radix(&hex, 16).expect("hex escape"));
            } else {
                bytes.push(ch as u8);
            }
        }
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStringExt;
            PathBuf::from(std::ffi::OsString::from_vec(bytes))
        }
        #[cfg(not(unix))]
        PathBuf::from(String::from_utf8(bytes).expect("utf-8 path"))
    }

    /// A path with a space and a non-ASCII character survives the round trip.
    ///
    /// Both are reachable: `TMPDIR` is whatever the user set it to.
    #[test]
    fn a_file_url_escapes_what_a_json_string_cannot_carry_plainly() {
        let url = file_url(Path::new("/tmp/vibrev out/输出 1.json"));

        assert_eq!(url, "file:///tmp/vibrev%20out/%E8%BE%93%E5%87%BA%201.json");
        assert_eq!(
            file_path_of(&url),
            PathBuf::from("/tmp/vibrev out/输出 1.json")
        );
    }

    fn over_threshold() -> Value {
        json!({"code": "x".repeat(Limits::default().max_chars + 1), "addr": "0x401000"})
    }

    #[tokio::test]
    async fn an_answer_that_fits_is_not_touched() {
        let cache = OutputCache::http("http://127.0.0.1:8765");
        let small = json!({"functions": ["main", "init"]});

        let prepared = cache.compact(small.clone(), None).await.expect("compact");

        assert_eq!(prepared.value, small);
        assert!(prepared.truncation.is_none());
        assert_eq!(cache.spills(), 0, "the net was not tripped");
    }

    #[tokio::test]
    async fn a_large_answer_is_kept_and_fetchable() {
        let cache = OutputCache::http("http://127.0.0.1:8765");
        let full = over_threshold();

        let prepared = cache.compact(full.clone(), None).await.expect("compact");
        let truncation = prepared.truncation.expect("truncation");
        let id = truncation.metadata["output_id"].as_str().expect("id");

        assert_eq!(cache.get(id).await, Some(full));
        assert_eq!(
            truncation.metadata["download_url"].as_str(),
            Some(format!("http://127.0.0.1:8765/output/{id}.json").as_str())
        );
        assert_eq!(cache.spills(), 1);
    }

    /// The preview describes the answer rather than replacing it.
    #[tokio::test]
    async fn every_key_survives_and_a_cut_string_says_how_much_was_cut() {
        let cache = OutputCache::truncating();
        let limits = Limits::default();

        let prepared = cache
            .compact(over_threshold(), None)
            .await
            .expect("compact");

        // The short field is untouched, so the preview still validates against
        // the schema the tool advertised.
        assert_eq!(prepared.value["addr"], json!("0x401000"));
        let code = prepared.value["code"].as_str().expect("string");
        assert!(code.starts_with(&"x".repeat(limits.preview_string_chars)));
        assert!(
            code.ends_with(&format!("... [{} chars total]", limits.max_chars + 1)),
            "{code}"
        );
    }

    #[tokio::test]
    async fn a_long_array_keeps_its_head_and_its_entries_keep_their_keys() {
        let limits = Limits::default();
        let functions: Vec<Value> = (0..5_000)
            .map(|i| json!({"name": format!("sub_{i:x}"), "addr": format!("{i:#x}")}))
            .collect();
        let cache = OutputCache::truncating();

        let prepared = cache
            .compact(json!({"functions": functions, "total": 5_000}), None)
            .await
            .expect("compact");

        let kept = prepared.value["functions"].as_array().expect("array");
        assert_eq!(kept.len(), limits.preview_items);
        assert_eq!(kept[0]["name"], json!("sub_0"));
        // The count beside the list is a scalar, so it is still the true one —
        // a caller can compare it against what it received.
        assert_eq!(prepared.value["total"], json!(5_000));
    }

    #[tokio::test]
    async fn a_spilled_answer_is_written_to_a_private_file() {
        let cache = OutputCache::spilling_to_files("test-engine").expect("cache");
        let full = over_threshold();

        let prepared = cache.compact(full.clone(), None).await.expect("compact");
        let truncation = prepared.truncation.expect("truncation");
        let path = file_path_of(truncation.metadata["download_url"].as_str().expect("url"));
        let saved: Value = serde_json::from_slice(&tokio::fs::read(&path).await.expect("read"))
            .expect("saved json");

        assert_eq!(saved, full);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = tokio::fs::metadata(&path)
                .await
                .expect("metadata")
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600, "spilled output is not world-readable");
        }
    }

    /// The whole point, in one measurement.
    #[tokio::test]
    async fn ten_megabytes_do_not_reach_the_wire() {
        let cache = OutputCache::spilling_to_files("test-engine").expect("cache");

        let prepared = cache
            .compact(
                json!({"addr": "0x401000", "code": "x".repeat(10 * 1024 * 1024)}),
                None,
            )
            .await
            .expect("compact");

        let wire = serde_json::to_vec(&prepared.value).expect("serialize");
        assert!(wire.len() < 2_000, "preview was {} bytes", wire.len());
        let path = file_path_of(
            prepared.truncation.expect("truncation").metadata["download_url"]
                .as_str()
                .expect("url"),
        );
        assert!(
            tokio::fs::metadata(path).await.expect("metadata").len() > 10_000_000,
            "the full answer was not kept"
        );
    }

    /// With nowhere to spill, there is nothing to remember.
    #[tokio::test]
    async fn a_truncating_cache_hands_out_no_url_and_holds_no_entry() {
        let cache = OutputCache::truncating();

        let prepared = cache
            .compact(over_threshold(), None)
            .await
            .expect("compact");
        let truncation = prepared.truncation.expect("truncation");

        assert_eq!(truncation.metadata["download_url"], Value::Null);
        let id = truncation.metadata["output_id"].as_str().expect("id");
        assert_eq!(cache.get(id).await, None);
    }

    /// A request's own host beats the configured fallback, so a server behind a
    /// proxy hands out a URL that resolves from where the client is standing.
    #[tokio::test]
    async fn a_request_host_overrides_the_fallback() {
        let cache = OutputCache::http("http://127.0.0.1:8765");

        let prepared = cache
            .compact(over_threshold(), Some("https://mcp.example.com/ida"))
            .await
            .expect("compact");

        let url = prepared.truncation.expect("truncation").metadata["download_url"]
            .as_str()
            .expect("url")
            .to_string();
        assert!(
            url.starts_with("https://mcp.example.com/ida/output/"),
            "{url}"
        );
    }

    #[tokio::test]
    async fn the_oldest_spill_is_dropped_once_the_cache_is_full() {
        let cache = OutputCache::http("http://127.0.0.1:8765").with_limits(Limits {
            max_entries: 2,
            ..Limits::default()
        });

        let mut ids = Vec::new();
        for _ in 0..3 {
            let prepared = cache
                .compact(over_threshold(), None)
                .await
                .expect("compact");
            let metadata = prepared.truncation.expect("truncation").metadata;
            ids.push(metadata["output_id"].as_str().expect("id").to_string());
        }

        assert_eq!(cache.get(&ids[0]).await, None, "the oldest was evicted");
        assert!(cache.get(&ids[2]).await.is_some(), "the newest is held");
    }

    /// A text answer with no structured payload is still measured.
    ///
    /// Reading the payload by parsing the text as JSON measures prose as `null`,
    /// which lets a tool answering with ten megabytes of disassembly through the
    /// net untouched.
    #[tokio::test]
    async fn an_answer_that_is_only_text_is_measured_as_text() {
        let cache = OutputCache::truncating();
        let listing = "mov rax, rbx\n".repeat(10_000);
        assert!(listing.chars().count() > cache.limits().max_chars);

        let result = rmcp::model::CallToolResult::success(vec![rmcp::model::ContentBlock::text(
            listing.clone(),
        )]);

        let prepared = cache
            .compact(payload_of(&result), None)
            .await
            .expect("compact");
        assert!(
            prepared.truncation.is_some(),
            "prose sailed through the net"
        );
    }

    /// A readable rendering is measured by what it describes, not by itself.
    ///
    /// Engines put pretty-printed JSON in `content` and the value in
    /// `structuredContent`, so the two differ by whitespace. Measuring the text
    /// would make an answer's size depend on how it was formatted for reading —
    /// and would put the *rendering* into the spill file instead of the value.
    #[tokio::test]
    async fn a_pretty_rendering_is_measured_by_its_structured_payload() {
        let value = json!({"addr": "0x401000", "code": "int main(void) {\n  return 0;\n}"});
        let pretty = serde_json::to_string_pretty(&value).expect("pretty");
        let mut result =
            rmcp::model::CallToolResult::success(vec![rmcp::model::ContentBlock::text(
                pretty.clone(),
            )]);
        result.structured_content = Some(value.clone());

        assert_eq!(payload_of(&result), value);

        let cache = OutputCache::truncating();
        let prepared = cache
            .compact(payload_of(&result), None)
            .await
            .expect("compact");
        assert!(prepared.truncation.is_none(), "a small answer was caught");
        assert_eq!(prepared.value, value);
    }

    /// The shortened text is the same bytes, not a different rendering.
    #[test]
    fn a_capped_text_block_keeps_the_form_the_tool_chose() {
        let limits = Limits::default();
        let pseudocode = "int main(void) {\n    return 0;\n}\n".repeat(5_000);
        // What `Rendered<T>` builds: the structured payload, plus `content`
        // carrying the text a reader actually wants.
        let mut result =
            rmcp::model::CallToolResult::structured(json!({"code": pseudocode.clone()}));
        result.content = vec![rmcp::model::ContentBlock::text(pseudocode.clone())];
        let truncation = Truncation {
            metadata: json!({"output_truncated": true}),
            hint: "Output truncated.".to_string(),
        };

        let capped = capped_result(result, json!({"code": "int main…"}), truncation, limits);

        let text = capped.content[0].as_text().expect("text").text.as_str();
        // Still C, not an escaped JSON string of C.
        assert!(text.starts_with("int main(void) {\n"), "{}", &text[..40]);
        assert!(text.ends_with(&format!("... [{} chars total]", pseudocode.chars().count())));
        assert_eq!(text.chars().count(), limits.max_chars + 1 + 24);
        assert_eq!(capped.content.len(), 2, "the hint is its own block");
        assert_eq!(
            capped.structured_content,
            Some(json!({"code": "int main…"}))
        );
        assert!(capped.meta.expect("meta").0.contains_key(META_KEY));
    }

    /// A tool that published no structured content does not acquire one.
    #[test]
    fn capping_does_not_invent_a_structured_payload() {
        let result = rmcp::model::CallToolResult::success(vec![rmcp::model::ContentBlock::text(
            "x".repeat(60_000),
        )]);
        let truncation = Truncation {
            metadata: json!({}),
            hint: "Output truncated.".to_string(),
        };

        let capped = capped_result(result, json!("x"), truncation, Limits::default());

        assert_eq!(capped.structured_content, None);
    }

    #[cfg(feature = "http")]
    #[test]
    fn a_proxy_is_believed_about_where_this_server_is_reachable() {
        let request = http::Request::builder()
            .uri("/mcp")
            .header("host", "127.0.0.1:8765")
            .header("x-forwarded-proto", "https")
            .header("x-forwarded-host", "mcp.example.com")
            .header("x-forwarded-prefix", "/ida/proxy/")
            .body(())
            .expect("request");
        let (parts, _) = request.into_parts();

        assert_eq!(
            external_base_url(&parts).as_deref(),
            Some("https://mcp.example.com/ida/proxy")
        );
    }

    /// A header cannot put an arbitrary scheme into a URL handed to a client.
    #[cfg(feature = "http")]
    #[test]
    fn a_base_url_that_is_not_http_is_refused() {
        for base in ["file:///etc", "javascript:alert(1)", "https://", "nonsense"] {
            let request = http::Request::builder()
                .uri("/mcp")
                .header("x-vibrev-external-base", base)
                .body(())
                .expect("request");
            let (parts, _) = request.into_parts();
            assert_eq!(external_base_url(&parts), None, "{base} was accepted");
        }
    }

    #[cfg(feature = "http")]
    #[test]
    fn the_output_route_accepts_only_a_single_json_file_name() {
        assert_eq!(output_id("abc.json"), Some("abc"));
        assert_eq!(output_id("/abc.json"), Some("abc"));
        assert_eq!(output_id("abc"), None);
        assert_eq!(output_id("nested/abc.json"), None);
        assert_eq!(output_id("../../etc/passwd.json"), None);
        assert_eq!(output_id(".json"), None);
    }

    /// The directory is this process's, and it does not outlive it.
    #[tokio::test]
    async fn a_spill_directory_is_removed_with_the_cache() {
        let cache = OutputCache::spilling_to_files("test-engine").expect("cache");
        let prepared = cache
            .compact(over_threshold(), None)
            .await
            .expect("compact");
        let path = file_path_of(
            prepared.truncation.expect("truncation").metadata["download_url"]
                .as_str()
                .expect("url"),
        );
        let directory = path.parent().expect("parent").to_path_buf();

        drop(cache);

        assert!(!directory.exists(), "{} survived", directory.display());
    }
}
