//! The HTTP listener an engine puts in front of the MCP server it already has.
//!
//! # What is here, and what is not
//!
//! The plan for this module was `Frontend::{Stdio, Http}` plus one
//! `serve(factory, frontend)`. The stdio half did not survive contact with the
//! engines: `ida-headless-mcp` runs idalib on the main thread and polls
//! `is_transport_closed` so it can close the worker pool on the way out, while
//! `bn-headless-mcp` awaits `service.waiting()`. Both are two lines long and
//! right for their engine, so a shared `Frontend::Stdio` would be a third shape
//! nobody uses. What *is* duplicated — and what a second engine would otherwise
//! have to reinvent, correctly, before it could listen on a port — is here:
//! bind, credential, `Host`, the startup banner, and graceful shutdown.
//!
//! # There is no way to serve unauthenticated
//!
//! [`Listener::serve`] takes the engine's [`Router`](axum::Router) and layers
//! the gate over *all* of it. An engine cannot mount a route that skips the
//! check, because it never gets to say which routes are covered. There is no
//! `--no-auth`, and not as a matter of documentation: the parameter does not
//! exist in this API, so the code that would honour it cannot be written.
//!
//! That is a deliberately narrow kind of strictness. The gate decides *who may
//! speak to this port*; it has no opinion about which tools are behind it. An
//! engine that advertises a tool over stdio advertises it here too — narrowing
//! the catalogue is [`crate::policy`]'s job and only ever happens because a user
//! asked. What this module insists on instead is that the operator be *told*:
//! see [`Exposure`].

mod access;
mod bearer;

pub use access::{AccessPolicy, enforce};
pub use bearer::{BearerRejection, validate as validate_bearer};

use std::fmt;
use std::io;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use clap::{Arg, ArgAction, ArgMatches};
use rmcp::transport::streamable_http_server::StreamableHttpServerConfig;
use rmcp::transport::streamable_http_server::session::local::LocalSessionManager;
use tokio_util::sync::CancellationToken;

use crate::token;

/// Where a listener binds when nobody said otherwise. Loopback, deliberately.
pub const DEFAULT_BIND: &str = "127.0.0.1:8765";

/// Legacy default retained for CLI/config compatibility. Origin is not checked.
pub const DEFAULT_ALLOW_ORIGIN: &str = "http://localhost,http://127.0.0.1";

/// SSE keep-alive, in seconds. `0` disables.
pub const DEFAULT_SSE_KEEP_ALIVE_SECS: u64 = 15;

/// Session inactivity timeout, in seconds.
///
/// rmcp defaults to 5 minutes, which is shorter than a single analysis pass on a
/// large binary in either engine; when it fires mid-call the session dies and
/// the client's `Mcp-Session-Id` stops working. `0` disables it, at the price of
/// leaking sessions when an HTTP connection drops silently — prefer a generous
/// positive value.
pub const DEFAULT_SESSION_KEEP_ALIVE_SECS: u64 = 1800;

/// Request-body cap, in MiB.
///
/// rmcp 3 introduced a 4 MiB default that is too small for bulk tools: a binary
/// patch travels as hex (2x the raw size) and a script tool sends whole source
/// files. rmcp grows a per-request buffer up to this cap *before* parsing, and
/// therefore before [`AccessPolicy`] sees the request, so the retention is
/// reachable by an unauthenticated caller even though the tool behind it is not.
/// 16 MiB covers a ~1.4 MiB patch with headroom while keeping that surface
/// bounded.
pub const DEFAULT_MAX_REQUEST_BODY_MIB: usize = 16;

const BYTES_PER_MIB: usize = 1024 * 1024;

pub const BIND_ARG: &str = "__vibrev_bind";
pub const TOKEN_FILE_ARG: &str = "__vibrev_token_file";
pub const ALLOW_ORIGIN_ARG: &str = "__vibrev_allow_origin";
pub const ALLOW_HOST_ARG: &str = "__vibrev_allow_host";
pub const SSE_KEEP_ALIVE_ARG: &str = "__vibrev_sse_keep_alive_secs";
pub const SESSION_KEEP_ALIVE_ARG: &str = "__vibrev_session_keep_alive_secs";
pub const STATELESS_ARG: &str = "__vibrev_stateless";
pub const JSON_RESPONSE_ARG: &str = "__vibrev_json_response";
pub const MAX_REQUEST_BODY_ARG: &str = "__vibrev_max_request_body_mib";

#[derive(Debug)]
pub enum TransportError {
    Token(token::TokenError),
    Bind { addr: SocketAddr, source: io::Error },
    LocalAddr(io::Error),
    Serve(io::Error),
}

impl fmt::Display for TransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TransportError::Token(error) => write!(f, "{error}"),
            TransportError::Bind { addr, source } => write!(f, "cannot bind {addr}: {source}"),
            TransportError::LocalAddr(source) => {
                write!(f, "cannot read the listener's address: {source}")
            }
            TransportError::Serve(source) => write!(f, "the HTTP listener failed: {source}"),
        }
    }
}

impl std::error::Error for TransportError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            TransportError::Token(error) => Some(error),
            TransportError::Bind { source, .. }
            | TransportError::LocalAddr(source)
            | TransportError::Serve(source) => Some(source),
        }
    }
}

impl From<token::TokenError> for TransportError {
    fn from(error: token::TokenError) -> Self {
        TransportError::Token(error)
    }
}

/// Everything the listener needs that a user can choose.
///
/// Note what is *not* a field: whether to require a credential. See the module
/// header.
#[derive(Debug, Clone)]
pub struct HttpOptions {
    pub bind: SocketAddr,
    /// `None` resolves to [`token::default_path`] at bind time.
    pub token_file: Option<PathBuf>,
    /// Legacy option retained for CLI/config compatibility. Origin is not checked.
    pub allow_origin: Vec<String>,
    /// `None` is "the bind-derived hosts only". `Some(["*"])` or `Some([""])`
    /// disables the check — the difference between "not configured" and
    /// "configured to allow everything" is one a listener has to keep.
    pub allow_host: Option<Vec<String>>,
    pub sse_keep_alive_secs: u64,
    pub session_keep_alive_secs: u64,
    pub stateless: bool,
    pub json_response: bool,
    pub max_request_body_mib: usize,
}

impl Default for HttpOptions {
    fn default() -> Self {
        Self {
            bind: DEFAULT_BIND.parse().expect("the default bind is a literal"),
            token_file: None,
            allow_origin: DEFAULT_ALLOW_ORIGIN.split(',').map(str::to_owned).collect(),
            allow_host: None,
            sse_keep_alive_secs: DEFAULT_SSE_KEEP_ALIVE_SECS,
            session_keep_alive_secs: DEFAULT_SESSION_KEEP_ALIVE_SECS,
            stateless: false,
            json_response: false,
            max_request_body_mib: DEFAULT_MAX_REQUEST_BODY_MIB,
        }
    }
}

impl HttpOptions {
    /// The flags, ready to hang on whichever subcommand opens the listener.
    ///
    /// Handed over as `Arg`s rather than a `#[derive(Args)]` struct for the same
    /// reason [`crate::policy::PolicyArgs`] is: an engine adds its own `.env()`
    /// on top, and the names, the help and the defaults stay identical across
    /// engines because there is one definition of them.
    ///
    /// Not `global(true)` — unlike the policy flags, these mean nothing outside
    /// the command that listens.
    pub fn args() -> Vec<Arg> {
        vec![
            Arg::new(BIND_ARG)
                .long("bind")
                .value_name("ADDR")
                .default_value(DEFAULT_BIND)
                .value_parser(clap::value_parser!(SocketAddr))
                .help("Listen address. Loopback by default; a non-loopback bind exposes this port to the local network"),
            Arg::new(TOKEN_FILE_ARG)
                .long("token-file")
                .value_name("PATH")
                .value_parser(clap::value_parser!(PathBuf))
                .help(
                    "Shared bearer token file. Defaults to $VIBREV_HOME/token, otherwise ~/.vibrev/token; \
                     created at mode 0600 on first use and reused thereafter. There is no switch that turns the token off",
                ),
            Arg::new(ALLOW_ORIGIN_ARG)
                .long("allow-origin")
                .value_name("ORIGIN")
                .value_delimiter(',')
                .action(ArgAction::Append)
                .default_value(DEFAULT_ALLOW_ORIGIN)
                .help("Legacy compatibility option; Origin headers are not validated"),
            Arg::new(ALLOW_HOST_ARG)
                .long("allow-host")
                .value_name("HOST")
                .value_delimiter(',')
                .action(ArgAction::Append)
                .help(
                    "Additional allowed Host headers (comma-separated). IP literals that --bind can reach are allowed automatically; \
                     put DNS names here. '*' or an empty string disables the Host check, and with it DNS-rebinding protection",
                ),
            Arg::new(SSE_KEEP_ALIVE_ARG)
                .long("sse-keep-alive-secs")
                .value_name("SECS")
                .default_value(DEFAULT_SSE_KEEP_ALIVE_SECS.to_string())
                .value_parser(clap::value_parser!(u64))
                .help("SSE keep-alive interval in seconds; 0 disables it"),
            Arg::new(SESSION_KEEP_ALIVE_ARG)
                .long("session-keep-alive-secs")
                .value_name("SECS")
                .default_value(DEFAULT_SESSION_KEEP_ALIVE_SECS.to_string())
                .value_parser(clap::value_parser!(u64))
                .help(
                    "HTTP session idle timeout in seconds. 0 disables it, but a silently dropped connection then leaves a zombie session; \
                     a generous positive value is safer",
                ),
            Arg::new(STATELESS_ARG)
                .long("stateless")
                .action(ArgAction::SetTrue)
                .help("Stateless mode (POST only, no sessions)"),
            Arg::new(JSON_RESPONSE_ARG)
                .long("json-response")
                .action(ArgAction::SetTrue)
                .help("Return application/json instead of SSE frames when dispatching without a session"),
            Arg::new(MAX_REQUEST_BODY_ARG)
                .long("max-request-body-mib")
                .value_name("MIB")
                .default_value(DEFAULT_MAX_REQUEST_BODY_MIB.to_string())
                .value_parser(clap::builder::RangedU64ValueParser::<usize>::new().range(1..=1024))
                .help(
                    "Request body cap in MiB. This buffer is allocated before auth, so an unauthenticated caller can fill it; \
                     raise it on purpose",
                ),
        ]
    }

    /// Read the flags back out.
    ///
    /// `try_get_*` throughout: a command tree that never registered these — a
    /// unit test building a bare `Command`, or an engine wiring the listener
    /// programmatically — reads as "everything default" rather than panicking.
    pub fn read(matches: &ArgMatches) -> Self {
        fn many(matches: &ArgMatches, id: &str) -> Option<Vec<String>> {
            matches
                .try_get_many::<String>(id)
                .ok()
                .flatten()
                .map(|values| values.cloned().collect())
        }

        let defaults = Self::default();
        Self {
            bind: matches
                .try_get_one::<SocketAddr>(BIND_ARG)
                .ok()
                .flatten()
                .copied()
                .unwrap_or(defaults.bind),
            token_file: matches
                .try_get_one::<PathBuf>(TOKEN_FILE_ARG)
                .ok()
                .flatten()
                .cloned(),
            allow_origin: many(matches, ALLOW_ORIGIN_ARG).unwrap_or(defaults.allow_origin),
            // `None` and `Some(vec![])` are different answers here, so this one
            // is not defaulted: see `HttpOptions::allow_host`.
            allow_host: many(matches, ALLOW_HOST_ARG),
            sse_keep_alive_secs: matches
                .try_get_one::<u64>(SSE_KEEP_ALIVE_ARG)
                .ok()
                .flatten()
                .copied()
                .unwrap_or(defaults.sse_keep_alive_secs),
            session_keep_alive_secs: matches
                .try_get_one::<u64>(SESSION_KEEP_ALIVE_ARG)
                .ok()
                .flatten()
                .copied()
                .unwrap_or(defaults.session_keep_alive_secs),
            stateless: flag(matches, STATELESS_ARG),
            json_response: flag(matches, JSON_RESPONSE_ARG),
            max_request_body_mib: matches
                .try_get_one::<usize>(MAX_REQUEST_BODY_ARG)
                .ok()
                .flatten()
                .copied()
                .unwrap_or(defaults.max_request_body_mib),
        }
    }
}

fn flag(matches: &ArgMatches, id: &str) -> bool {
    matches
        .try_get_one::<bool>(id)
        .ok()
        .flatten()
        .copied()
        .unwrap_or(false)
}

/// What a caller who holds the token can do to this host.
///
/// Every field here ends up on the operator's screen at startup, and that is the
/// point. This module refuses to let an engine serve without a credential, but
/// it deliberately does *not* decide which tools sit behind the port — an engine
/// that publishes a tool publishes it, and hiding one by default would only mean
/// an operator discovering it through "why does this not work". The obligation
/// that replaces the hiding is this struct: say plainly what the port reaches.
///
/// [`Exposure::reach`] has no default for that reason. A banner that says
/// nothing about what is behind the port is a banner whose reader has to go read
/// the source.
#[derive(Debug, Clone)]
pub struct Exposure {
    /// The engine's name, for the paste-able client-config block.
    pub engine: &'static str,
    /// Routes this listener answers, for the "listening on" line.
    pub routes: &'static [&'static str],
    /// What the tools behind this port can do to the host, in the operator's
    /// terms — not the tool names, what they *reach*. One sentence per entry;
    /// the banner wraps them, so an engine writing this never counts columns.
    pub reach: Vec<String>,
    /// `Some(why)` when some advertised tool runs caller-supplied code, with the
    /// engine's own explanation of which one and under what condition. `None`
    /// only when nothing behind this port does.
    pub arbitrary_code: Option<String>,
}

/// A bound port with a credential, ready for the engine's routes.
pub struct Listener {
    listener: tokio::net::TcpListener,
    addr: SocketAddr,
    access: AccessPolicy,
    cancel: CancellationToken,
    config: StreamableHttpServerConfig,
    token_path: PathBuf,
    loaded: token::Loaded,
}

impl Listener {
    /// Establish the credential, then bind.
    ///
    /// That order is load-bearing: a token file we cannot read or create is a
    /// fatal error, and doing it second would leave a bound port sitting there
    /// while the failure is being reported.
    pub async fn bind(opts: &HttpOptions) -> Result<Self, TransportError> {
        let token_path = match &opts.token_file {
            Some(path) => path.clone(),
            None => token::default_path()?,
        };
        let (auth, loaded) = token::Accepted::load(&token_path)?;

        let listener = tokio::net::TcpListener::bind(opts.bind)
            .await
            .map_err(|source| TransportError::Bind {
                addr: opts.bind,
                source,
            })?;
        let addr = listener.local_addr().map_err(TransportError::LocalAddr)?;

        let cancel = CancellationToken::new();
        Ok(Self {
            listener,
            addr,
            // The *resolved* address, not the requested one: `--bind :0` is a
            // real thing to do in a test, and a Host allowlist derived from port
            // zero would reject every request.
            access: AccessPolicy::new(addr, &opts.allow_origin, opts.allow_host.as_deref(), auth),
            config: streamable_config(opts, cancel.clone()),
            cancel,
            token_path,
            loaded,
        })
    }

    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    pub fn access(&self) -> &AccessPolicy {
        &self.access
    }

    /// Cancelling this stops the listener. It is also what an engine's own
    /// long-lived services should take, so one signal ends all of them.
    pub fn cancel(&self) -> &CancellationToken {
        &self.cancel
    }

    pub fn config(&self) -> &StreamableHttpServerConfig {
        &self.config
    }

    pub fn token_path(&self) -> &Path {
        &self.token_path
    }

    /// Lines the caller should print after the banner: that a token was just
    /// generated, and anything [`token::load_or_create`] warned about.
    ///
    /// Returned rather than printed because the engine owns its output stream —
    /// and because the wording is the engine's to localise.
    pub fn token_notes(&self) -> Vec<String> {
        let mut notes = Vec::new();
        if self.loaded.origin == token::Origin::Generated {
            notes.push(format!(
                "Generated a new shared token at {}.",
                self.token_path.display()
            ));
        }
        notes.extend(
            self.loaded
                .warnings
                .iter()
                .map(|warning| format!("WARNING: {warning}")),
        );
        notes
    }

    /// The security-posture banner to print on startup. See [`banner`].
    pub fn banner(&self, exposure: &Exposure, reveal_token: bool) -> String {
        banner(&self.access, exposure, reveal_token)
    }

    /// Serve `router` until a shutdown signal or [`Listener::cancel`].
    ///
    /// The gate goes on here, over the whole router, which is why this consumes
    /// the router rather than handing the policy out for the engine to apply:
    /// every route an engine mounts is covered, including the ones it adds next
    /// year.
    pub async fn serve(self, router: axum::Router) -> Result<(), TransportError> {
        let router = router.layer(axum::middleware::from_fn_with_state(
            self.access.clone(),
            enforce,
        ));

        let on_signal = self.cancel.clone();
        tokio::spawn(async move {
            shutdown_signal().await;
            on_signal.cancel();
        });

        let until = self.cancel.clone();
        axum::serve(self.listener, router)
            .with_graceful_shutdown(async move { until.cancelled().await })
            .await
            .map_err(TransportError::Serve)
    }
}

/// The security-posture banner a listener prints on startup.
///
/// Write it straight to stderr with `eprintln!`, not through `tracing`: an
/// inherited `RUST_LOG=error` must not be able to hide what a listener that just
/// came up will and will not let through.
///
/// `reveal_token` is the caller's answer to "is stderr a terminal". A person who
/// just typed the command needs the value to paste; a redirected stderr is a log
/// file, and a credential in CI output is the leak this avoids.
///
/// A free function over [`AccessPolicy`] rather than a method on [`Listener`]
/// because the banner is a pure function of the policy — and a test that needs a
/// bound socket to check a string is a test that fails one day because a port
/// was busy.
pub fn banner(access: &AccessPolicy, exposure: &Exposure, reveal_token: bool) -> String {
    const RULE: &str = "\
────────────────────────────────────────────────────────────────────────────";
    const INDENT: &str = "                  ";
    let addr = access.bind_addr();
    let endpoint = format!("http://{addr}");
    let token_file = access
        .auth()
        .source()
        .map(|path| path.display().to_string())
        .unwrap_or_else(|| "<not from a file>".to_string());
    let shown = if reveal_token {
        access.auth().primary().to_string()
    } else {
        format!("{}…", token::PREFIX)
    };

    let mut lines = vec![
        RULE.to_string(),
        " this listener requires a bearer token on every request".to_string(),
        format!(
            "   listening on : {endpoint} ({})",
            exposure.routes.join(", ")
        ),
        format!("   token file   : {token_file} (mode 0600)"),
        format!(
            "   accepted     : {} token(s); the first line is the current one",
            access.auth().count()
        ),
    ];
    // The engine writes sentences; the layout is decided once, here, so a
    // banner cannot run off the edge of a terminal because one engine's
    // sentence was longer than the author's editor was wide.
    const WIDTH: usize = 58;
    let mut exposed: Vec<String> = exposure
        .reach
        .iter()
        .flat_map(|sentence| wrap(sentence, WIDTH))
        .collect();
    if let Some(why) = &exposure.arbitrary_code {
        exposed.extend(wrap(
            &format!("and can execute arbitrary code — {why}"),
            WIDTH,
        ));
    }
    for (index, line) in exposed.iter().enumerate() {
        lines.push(match index {
            0 => format!("   exposure     : {line}"),
            _ => format!("{INDENT}{line}"),
        });
    }
    // Kept apart from the fixed prologue because these are about *reach* — who
    // can route a packet here — rather than about what the endpoint asks of a
    // caller once the packet arrives.
    if !addr.ip().is_loopback() {
        lines.push(format!(
            "   WARNING: --bind {addr} is not loopback; this port is reachable"
        ));
        lines.push("            from other hosts on the network.".to_string());
    }
    if access.host_check_disabled() {
        lines.push(
            "   WARNING: Host validation is disabled (--allow-host '*' or empty),".to_string(),
        );
        lines.push("            which removes the DNS-rebinding mitigation.".to_string());
    }
    lines.push(String::new());
    lines.push(" Client config (MCP Streamable HTTP):".to_string());
    lines.push(format!("   \"{}\": {{", exposure.engine));
    lines.push("     \"type\": \"http\",".to_string());
    lines.push(format!("     \"url\": \"{endpoint}/mcp\","));
    lines.push(format!(
        "     \"headers\": {{ \"Authorization\": \"Bearer {shown}\" }}"
    ));
    lines.push("   }".to_string());
    if !reveal_token {
        lines.push(
            " The token is elided because stderr is not a terminal. Read it with:".to_string(),
        );
        lines.push(format!("   head -n1 {token_file}"));
    }
    lines.push(String::new());
    lines.push(" stdio (the default, `serve`) needs none of this: the client spawns".to_string());
    lines.push(" it directly and there is no listener to reach.".to_string());
    lines.push(RULE.to_string());
    lines.join("\n")
}

/// Greedy word wrap, counting characters rather than bytes.
///
/// A word longer than `width` gets its own line rather than being cut: a URL or
/// a path is worse split than overhanging.
fn wrap(text: &str, width: usize) -> Vec<String> {
    let mut lines = Vec::new();
    let mut current = String::new();
    let mut taken = 0;
    for word in text.split_whitespace() {
        let len = word.chars().count();
        if taken > 0 && taken + 1 + len > width {
            lines.push(std::mem::take(&mut current));
            taken = 0;
        }
        if taken > 0 {
            current.push(' ');
            taken += 1;
        }
        current.push_str(word);
        taken += len;
    }
    if !current.is_empty() {
        lines.push(current);
    }
    lines
}

/// Resolve when the process is asked to stop.
///
/// `SIGTERM` as well as `SIGINT`: a container runtime or a service manager sends
/// the former, and an engine that only handles Ctrl-C gets killed outright there
/// — with whatever child processes it was holding.
pub async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};

        // A failure to install one handler must not cost us the others, so each
        // arm is only armed if its registration worked.
        let mut sigterm = signal(SignalKind::terminate()).ok();
        let mut sigint = signal(SignalKind::interrupt()).ok();
        let mut sigquit = signal(SignalKind::quit()).ok();
        tokio::select! {
            Some(()) = async { match &mut sigterm { Some(s) => s.recv().await, None => None } } => {}
            Some(()) = async { match &mut sigint { Some(s) => s.recv().await, None => None } } => {}
            Some(()) = async { match &mut sigquit { Some(s) => s.recv().await, None => None } } => {}
            _ = tokio::signal::ctrl_c() => {}
        }
    }

    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

/// rmcp's session store, with the inactivity timeout an engine actually wants.
pub fn session_manager(session_keep_alive_secs: u64) -> Arc<LocalSessionManager> {
    Arc::new(local_session_manager(session_keep_alive_secs))
}

/// The same, unwrapped, for an engine that layers its own `SessionManager` over
/// it — `ida-headless-mcp` closes a pooled worker when the client abandons its
/// SSE stream, which is a property of *its* process model rather than of MCP.
pub fn local_session_manager(session_keep_alive_secs: u64) -> LocalSessionManager {
    let mut manager = LocalSessionManager::default();
    manager.session_config.keep_alive = if session_keep_alive_secs == 0 {
        None
    } else {
        Some(Duration::from_secs(session_keep_alive_secs))
    };
    // Request-wise SSE priming must match the outer streamable config, which
    // also turns it off.
    manager.session_config.sse_retry = None;
    manager
}

pub fn streamable_config(
    opts: &HttpOptions,
    cancel: CancellationToken,
) -> StreamableHttpServerConfig {
    StreamableHttpServerConfig::default()
        .with_sse_keep_alive(if opts.sse_keep_alive_secs == 0 {
            None
        } else {
            Some(Duration::from_secs(opts.sse_keep_alive_secs))
        })
        .with_sse_retry(None)
        .with_legacy_session_mode(!opts.stateless)
        // Sessionless dispatch is not tied to --stateless: MCP 2026 requests
        // always take it, so --json-response applies there too instead of being
        // silently dropped without --stateless.
        .with_json_response(opts.json_response)
        .with_max_request_body_bytes(opts.max_request_body_mib.saturating_mul(BYTES_PER_MIB))
        .with_cancellation_token(cancel)
        // Host validation belongs to `AccessPolicy`, which knows the bind
        // address and can therefore answer with something actionable. Leaving
        // rmcp's copy on would mean two allowlists disagreeing.
        .with_allowed_hosts(Vec::<String>::new())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Command;

    fn parse(args: &[&str]) -> HttpOptions {
        let matches = Command::new("engine")
            .no_binary_name(true)
            .args(HttpOptions::args())
            .get_matches_from(args);
        HttpOptions::read(&matches)
    }

    fn policy_for(opts: &HttpOptions, tokens: &[&str]) -> AccessPolicy {
        let auth = token::Accepted::new(
            tokens.iter().map(|t| (*t).to_string()).collect(),
            Some(PathBuf::from("/home/tester/.vibrev/token")),
        )
        .expect("token set");
        AccessPolicy::new(
            opts.bind,
            &opts.allow_origin,
            opts.allow_host.as_deref(),
            auth,
        )
    }

    fn exposure() -> Exposure {
        Exposure {
            engine: "test-engine",
            routes: &["/mcp"],
            reach: vec!["read any file this host can read".to_string()],
            arbitrary_code: None,
        }
    }

    /// The defaults are part of the contract between engines: a user who learns
    /// one engine's listener must not have to re-learn the next one's.
    #[test]
    fn the_defaults_are_the_ones_documented() {
        let opts = parse(&[]);
        assert_eq!(opts.bind.to_string(), DEFAULT_BIND);
        assert_eq!(opts.allow_origin, ["http://localhost", "http://127.0.0.1"]);
        assert_eq!(opts.allow_host, None);
        assert_eq!(opts.sse_keep_alive_secs, 15);
        assert_eq!(opts.session_keep_alive_secs, 1800);
        assert_eq!(opts.max_request_body_mib, 16);
        assert!(!opts.stateless);
        assert!(!opts.json_response);
        assert_eq!(opts.token_file, None);
    }

    /// "not configured" and "configured to allow everything" are different
    /// answers, and the flag has to keep them apart: the first is the default
    /// posture, the second turns off the rebinding mitigation.
    #[test]
    fn an_absent_allow_host_is_not_an_empty_one() {
        assert_eq!(parse(&[]).allow_host, None);
        assert_eq!(
            parse(&["--allow-host", ""]).allow_host,
            Some(vec![String::new()])
        );
        assert_eq!(
            parse(&["--allow-host", "a.local,b.local"]).allow_host,
            Some(vec!["a.local".to_string(), "b.local".to_string()])
        );
    }

    #[test]
    fn every_flag_round_trips() {
        let opts = parse(&[
            "--bind",
            "0.0.0.0:9001",
            "--token-file",
            "/tmp/t",
            "--allow-origin",
            "http://a,http://b",
            "--sse-keep-alive-secs",
            "0",
            "--session-keep-alive-secs",
            "60",
            "--stateless",
            "--json-response",
            "--max-request-body-mib",
            "3",
        ]);
        assert_eq!(opts.bind.to_string(), "0.0.0.0:9001");
        assert_eq!(opts.token_file, Some(PathBuf::from("/tmp/t")));
        assert_eq!(opts.allow_origin, ["http://a", "http://b"]);
        assert_eq!(opts.sse_keep_alive_secs, 0);
        assert_eq!(opts.session_keep_alive_secs, 60);
        assert!(opts.stateless);
        assert!(opts.json_response);
        assert_eq!(opts.max_request_body_mib, 3);
    }

    /// A command tree that never registered these flags must still yield a
    /// working listener rather than panicking — the same rule `PolicyArgs::read`
    /// follows, and what lets an engine wire the listener programmatically.
    #[test]
    fn reading_a_command_without_the_flags_gives_the_defaults() {
        let matches = Command::new("bare")
            .no_binary_name(true)
            .get_matches_from(Vec::<&str>::new());
        let opts = HttpOptions::read(&matches);
        assert_eq!(opts.bind.to_string(), DEFAULT_BIND);
        assert_eq!(opts.max_request_body_mib, DEFAULT_MAX_REQUEST_BODY_MIB);
    }

    #[test]
    fn there_is_no_flag_that_turns_the_credential_off() {
        let rendered = Command::new("engine")
            .no_binary_name(true)
            .args(HttpOptions::args())
            .render_long_help()
            .to_string();
        for absent in ["--no-auth", "--insecure", "--anonymous", "--no-token"] {
            assert!(
                !rendered.contains(absent),
                "{absent} is offered: {rendered}"
            );
        }
        // Flattened before matching: whether clap wraps help text at all depends
        // on `clap/wrap_help`, which a *consumer* of this crate turns on — the
        // installer does — and cargo unifies features across a workspace build.
        // So the same assertion on the raw string passes under `-p vibrev-kit`
        // and fails under `--workspace`, at whatever width the terminal happens
        // to be.
        let flattened = rendered.split_whitespace().collect::<Vec<_>>().join(" ");
        assert!(
            flattened.contains("no switch that turns the token off"),
            "{rendered}"
        );
    }

    #[test]
    fn the_banner_states_the_requirement_and_where_the_file_is() {
        let opts = parse(&[]);
        let notice = banner(&policy_for(&opts, &["vbr_secret"]), &exposure(), false);
        assert!(notice.contains("requires a bearer token"));
        assert!(notice.contains("/home/tester/.vibrev/token"));
        assert!(notice.contains("http://127.0.0.1:8765/mcp"));
        // The paste-able snippet is the whole answer to "how do I configure a
        // client", since `vibrev install` writes stdio entries only.
        assert!(notice.contains("\"test-engine\": {"));
        assert!(notice.contains("\"Authorization\": \"Bearer "));
        // And it must say the default path is unaffected.
        assert!(notice.contains("stdio"));
        // The default posture must not claim more than it does.
        assert!(!notice.contains("WARNING:"));
        assert!(!notice.contains("execute arbitrary code"));
    }

    #[test]
    fn the_banner_hides_the_token_unless_stderr_is_a_terminal() {
        let opts = parse(&[]);
        let policy = policy_for(&opts, &["vbr_secret"]);
        let piped = banner(&policy, &exposure(), false);
        assert!(
            !piped.contains("vbr_secret"),
            "a redirected stderr is a log file"
        );
        assert!(piped.contains("elided because stderr is not a terminal"));

        let interactive = banner(&policy, &exposure(), true);
        assert!(
            interactive.contains("vbr_secret"),
            "a person needs it to paste"
        );
        assert!(!interactive.contains("elided"));
    }

    /// The trade this module makes: nothing is hidden from a caller who holds
    /// the token, so the operator is told what that buys them. An engine behind
    /// a listener that runs caller-supplied code says so on line one of the
    /// exposure block, every time it starts.
    #[test]
    fn code_execution_is_named_in_the_banner_rather_than_hidden_from_the_catalog() {
        let opts = parse(&[]);
        let mut exposure = exposure();
        exposure.arbitrary_code = Some("script.python runs caller-supplied Python".to_string());
        let notice = banner(&policy_for(&opts, &["vbr_a"]), &exposure, false);
        assert!(notice.contains("can execute arbitrary code"));
        // Word by word, not phrase by phrase: the banner wraps, so a phrase
        // assertion here would be an assertion about where the line broke.
        assert!(notice.contains("script.python"));
        assert!(notice.contains("caller-supplied"));
    }

    #[test]
    fn the_banner_flags_a_widened_listener() {
        let lan = parse(&["--bind", "0.0.0.0:8765"]);
        assert!(
            banner(&policy_for(&lan, &["vbr_a"]), &exposure(), false).contains("is not loopback")
        );

        let open = parse(&["--allow-host", "*"]);
        assert!(
            banner(&policy_for(&open, &["vbr_a"]), &exposure(), false)
                .contains("Host validation is disabled")
        );
    }

    /// The engine writes sentences and the banner lays them out, so no line
    /// runs off a terminal because one engine's sentence was long.
    #[test]
    fn every_banner_line_fits_in_eighty_columns() {
        let opts = parse(&["--bind", "0.0.0.0:8765"]);
        let mut exposure = exposure();
        exposure.reach = vec![
            "a caller holding the token can open any file on this host for analysis, \
             which is a sentence nobody wrapped by hand"
                .to_string(),
        ];
        exposure.arbitrary_code = Some(
            "script.python runs caller-supplied Python inside a worker; \
             --exclude-tools script.python removes it"
                .to_string(),
        );
        let notice = banner(&policy_for(&opts, &["vbr_a"]), &exposure, true);
        for line in notice.lines() {
            assert!(
                line.chars().count() <= 80,
                "{} columns: {line}",
                line.chars().count()
            );
        }
        // And wrapping must not lose the words that make it a warning.
        let flattened = notice.split_whitespace().collect::<Vec<_>>().join(" ");
        assert!(flattened.contains("--exclude-tools script.python removes it"));
        assert!(flattened.contains("a caller holding the token can open any file"));
    }

    #[test]
    fn a_word_longer_than_the_width_overhangs_rather_than_being_cut() {
        // Better an over-long line than a path a reader cannot paste.
        assert_eq!(
            wrap("a /very/long/path/that/exceeds b", 8),
            ["a", "/very/long/path/that/exceeds", "b"]
        );
        assert_eq!(wrap("one two three", 7), ["one two", "three"]);
        assert!(wrap("", 8).is_empty());
    }

    #[test]
    fn the_accepted_count_is_reported_so_a_half_done_rotation_is_visible() {
        let opts = parse(&[]);
        let notice = banner(
            &policy_for(&opts, &["vbr_new", "vbr_old"]),
            &exposure(),
            false,
        );
        assert!(notice.contains("2 token(s)"));
    }

    #[test]
    fn rmcp_host_validation_stays_off_so_there_is_only_one_allowlist() {
        let config = streamable_config(&parse(&[]), CancellationToken::new());
        assert!(config.allowed_hosts.is_empty());
    }

    #[test]
    fn json_response_applies_to_all_sessionless_dispatch() {
        // MCP 2026 requests are dispatched sessionless even with legacy sessions
        // enabled, so the flag must not depend on --stateless.
        let stateful = streamable_config(&parse(&["--json-response"]), CancellationToken::new());
        assert!(stateful.json_response);
        let stateless = streamable_config(
            &parse(&["--json-response", "--stateless"]),
            CancellationToken::new(),
        );
        assert!(stateless.json_response);
    }

    #[test]
    fn stateless_disables_legacy_sessions() {
        assert!(streamable_config(&parse(&[]), CancellationToken::new()).legacy_session_mode);
        assert!(
            !streamable_config(&parse(&["--stateless"]), CancellationToken::new())
                .legacy_session_mode
        );
    }

    #[test]
    fn the_body_cap_follows_the_operator_and_saturates() {
        let config = streamable_config(&parse(&[]), CancellationToken::new());
        assert_eq!(config.max_request_body_bytes, 16 * 1024 * 1024);
        // Large enough for the bulk tools rmcp's 4 MiB default rejects, small
        // enough that concurrent unauthenticated requests cannot each retain a
        // previous 64 MiB.
        assert!(config.max_request_body_bytes > 4 * 1024 * 1024);
        assert!(config.max_request_body_bytes < 64 * 1024 * 1024);

        let mut huge = parse(&[]);
        huge.max_request_body_mib = usize::MAX;
        assert_eq!(
            streamable_config(&huge, CancellationToken::new()).max_request_body_bytes,
            usize::MAX
        );
    }

    #[test]
    fn session_keep_alive_zero_disables_the_timeout() {
        assert!(local_session_manager(0).session_config.keep_alive.is_none());
        assert_eq!(
            local_session_manager(1800).session_config.keep_alive,
            Some(Duration::from_secs(1800)),
            "an explicit value must override rmcp's 300s default"
        );
        assert!(
            local_session_manager(1800)
                .session_config
                .sse_retry
                .is_none()
        );
    }
}
