//! The MCP client registry — the one place that knows where the four supported
//! clients keep their server lists and what shape an entry takes there.
//!
//! Every engine is a self-contained stdio MCP server, so an entry is always
//! `command` + `args` and never a URL, a token, or a header. That is what makes a
//! single [`ServerSpec`] renderable into all four dialects.
//!
//! The four differ in every axis that matters, which is why this is data and not a
//! trait: top-level key (`mcpServers` / `servers` / `mcp_servers`), file format
//! (JSON / JSONC / TOML), file location, and whether a first-party CLI exists to
//! delegate to.

use camino::{Utf8Path, Utf8PathBuf};

use crate::engine::Engine;

/// Which of a client's two configuration levels to write.
///
/// `Global` is "every project on this machine"; `Project` is a file inside the
/// current working directory, meant to be committed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Scope {
    Global,
    Project,
}

impl Scope {
    pub fn as_str(self) -> &'static str {
        match self {
            Scope::Global => "global",
            Scope::Project => "project",
        }
    }

    /// Whether files at this scope are routinely committed to version control.
    ///
    /// Every project-scope path is inside the repository — `.mcp.json`,
    /// `.cursor/mcp.json`, `.vscode/mcp.json` — and being shared with the team is
    /// the entire point of the scope. That makes it categorically the wrong place
    /// for a credential, and not only because someone might see it: deleting a
    /// secret from the working tree does not remove it from history, so the only
    /// real remedy after the fact is rotating the token, which nobody thinks to
    /// do. See [`crate::mcpfile::HTTP_TRANSPORT_KEYS`].
    pub fn version_controlled(self) -> bool {
        match self {
            Scope::Global => false,
            Scope::Project => true,
        }
    }

    pub const ALL: [Scope; 2] = [Scope::Global, Scope::Project];
}

impl std::str::FromStr for Scope {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "global" => Ok(Scope::Global),
            "project" => Ok(Scope::Project),
            other => Err(format!("未知的作用域 {other}（可用: global / project）")),
        }
    }
}

/// How the file has to be edited to come back out unharmed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    /// Strict JSON on disk. Still parsed with the CST so user key order and
    /// indentation survive a write.
    Json,
    /// JSON with comments. A `serde_json` round-trip would delete every one of
    /// them, so this is not negotiable.
    Jsonc,
    Toml,
}

/// A single `vibrev-<engine>` entry, before it is rendered into any dialect.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerSpec {
    /// `vibrev-<engine id>`. Also the idempotency key: an existing property with
    /// this name is updated in place, never duplicated.
    pub name: String,
    pub engine: &'static str,
    pub command: String,
    pub args: Vec<String>,
}

impl ServerSpec {
    pub fn new(engine: &'static Engine, command: &Utf8Path, args: &[String]) -> Self {
        Self {
            name: server_name(engine.id),
            engine: engine.id,
            command: command.to_string(),
            args: args.to_vec(),
        }
    }
}

/// One entry per engine rather than one multiplexed entry, so a user can disable
/// `vibrev-ida` in their client and keep `vibrev-jadx` — engine tool sets are large
/// and context budget is the scarce resource.
pub fn server_name(engine_id: &str) -> String {
    format!("vibrev-{engine_id}")
}

/// Entries `vibrev` considers its own. Anything else in the file is untouchable.
pub fn is_ours(name: &str) -> bool {
    name.strip_prefix("vibrev-")
        .is_some_and(|id| crate::engine::by_id(id).is_some())
}

/// Whether a client reads agent skills, and where from.
///
/// Only one of the four does. The variants carry the reason rather than leaving
/// it to a parallel table, because "skipped" without a cause reads as a bug: a
/// user who asked for skills and got nothing needs to know it is because Cursor
/// has no such concept, not because we failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SkillSupport {
    /// `.claude/skills/<name>/SKILL.md` — under `$HOME` for global scope, under
    /// the project directory for project scope.
    ClaudeStyle,
    /// No skill mechanism. The string names what the client has instead, so the
    /// skip line can say something the user can act on.
    Unsupported(&'static str),
}

impl SkillSupport {
    /// Where `scope`'s skills live, or `None` when this client has none.
    fn dir(self, scope: Scope, env: &Env) -> Option<Utf8PathBuf> {
        match self {
            Self::ClaudeStyle => Some(
                match scope {
                    Scope::Global => &env.home,
                    Scope::Project => &env.cwd,
                }
                .join(".claude")
                .join("skills"),
            ),
            Self::Unsupported(_) => None,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Client {
    /// What a user types after `--client`.
    pub id: &'static str,
    /// Display name for tables and prose.
    pub label: &'static str,
    /// The top-level table holding servers. Three keys for four clients.
    pub key: &'static str,
    pub format: Format,
    /// Whether this client reads agent skills. Orthogonal to the MCP entry: a
    /// client gets a `vibrev-<engine>` server either way.
    pub skills: SkillSupport,
    /// Whether the entry carries `"type": "stdio"`. Claude Code and VS Code both
    /// document it; Cursor's schema does not mention it and Codex infers the
    /// transport from the presence of `command` versus `url`.
    pub emit_type: bool,
    /// First-party CLI to delegate to, when it is on `PATH`.
    pub cli: Option<&'static str>,
}

pub const CLIENTS: &[Client] = &[
    Client {
        id: "claude-code",
        label: "Claude Code",
        key: "mcpServers",
        format: Format::Json,
        skills: SkillSupport::ClaudeStyle,
        emit_type: true,
        cli: Some("claude"),
    },
    Client {
        id: "cursor",
        label: "Cursor",
        key: "mcpServers",
        format: Format::Json,
        skills: SkillSupport::Unsupported("只有 .cursor/rules，不读 skill 目录"),
        emit_type: false,
        cli: None,
    },
    Client {
        id: "vscode",
        label: "VS Code",
        key: "servers",
        // `mcp.json` ships with explanatory comments and users add their own; the
        // file also carries an `inputs` array that must survive untouched.
        format: Format::Jsonc,
        skills: SkillSupport::Unsupported("只有 Copilot instructions，不读 skill 目录"),
        emit_type: true,
        cli: Some("code"),
    },
    Client {
        id: "codex",
        label: "Codex",
        key: "mcp_servers",
        format: Format::Toml,
        skills: SkillSupport::Unsupported("只有 AGENTS.md，不读 skill 目录"),
        // Codex has no `type` field at all — `command` versus `url` is the
        // discriminator, and an unknown key is a config error there.
        emit_type: false,
        cli: Some("codex"),
    },
];

pub fn by_id(id: &str) -> Option<&'static Client> {
    CLIENTS.iter().find(|c| c.id == id)
}

pub fn ids() -> Vec<&'static str> {
    CLIENTS.iter().map(|c| c.id).collect()
}

/// The directories a client's paths are resolved against.
///
/// Threaded explicitly rather than read from the process environment at each use
/// site: tests need a fake home, and `std::env::set_var` is `unsafe` in edition
/// 2024 for good reason.
#[derive(Debug, Clone)]
pub struct Env {
    pub home: Utf8PathBuf,
    /// Base for VS Code's `Code/User/` directory. This follows the *native GUI*
    /// convention, not the CLI one: `~/.config` on Linux, `~/Library/Application
    /// Support` on macOS, `%APPDATA%` on Windows.
    pub app_config: Utf8PathBuf,
    /// Project scope is relative to where the user ran the command.
    pub cwd: Utf8PathBuf,
}

impl Env {
    pub fn resolve() -> anyhow::Result<Self> {
        use anyhow::{Context, anyhow};
        use etcetera::BaseStrategy;

        let home = etcetera::home_dir()
            .ok()
            .and_then(|p| Utf8PathBuf::from_path_buf(p).ok())
            .context("无法定位用户主目录；请设置 HOME")?;

        let strategy =
            etcetera::base_strategy::choose_native_strategy().context("无法定位平台配置目录")?;
        // etcetera's Apple strategy maps `config_dir` to `~/Library/Preferences`,
        // but VS Code stores `User/mcp.json` under Application Support — so macOS
        // wants `data_dir`. Windows and Linux both want `config_dir`
        // (`%APPDATA%` and `$XDG_CONFIG_HOME` respectively).
        let raw = if cfg!(target_os = "macos") {
            strategy.data_dir()
        } else {
            strategy.config_dir()
        };
        let app_config = Utf8PathBuf::from_path_buf(raw)
            .map_err(|p| anyhow!("平台配置目录不是有效的 UTF-8 路径: {}", p.display()))?;

        let cwd = std::env::current_dir()
            .context("无法读取当前工作目录")
            .and_then(|p| {
                Utf8PathBuf::from_path_buf(p)
                    .map_err(|p| anyhow!("当前工作目录不是有效的 UTF-8 路径: {}", p.display()))
            })?;

        Ok(Self {
            home,
            app_config,
            cwd,
        })
    }
}

impl Client {
    /// Where this client keeps `scope`'s servers, or `None` when it has no such
    /// level at all (Codex is machine-global only).
    pub fn file(&self, scope: Scope, env: &Env) -> Option<Utf8PathBuf> {
        Some(match (self.id, scope) {
            ("claude-code", Scope::Global) => env.home.join(".claude.json"),
            ("claude-code", Scope::Project) => env.cwd.join(".mcp.json"),

            ("cursor", Scope::Global) => env.home.join(".cursor").join("mcp.json"),
            ("cursor", Scope::Project) => env.cwd.join(".cursor").join("mcp.json"),

            ("vscode", Scope::Global) => env.app_config.join("Code").join("User").join("mcp.json"),
            ("vscode", Scope::Project) => env.cwd.join(".vscode").join("mcp.json"),

            ("codex", Scope::Global) => env.home.join(".codex").join("config.toml"),
            // Codex reads only `~/.codex/config.toml`; there is no per-repo file
            // to write, and inventing one would be a file nothing ever reads.
            ("codex", Scope::Project) => return None,

            _ => return None,
        })
    }

    /// Where this client reads agent skills at `scope`, or `None` when it reads
    /// none at all. Mirrors [`Client::file`], which does the same for servers.
    pub fn skills_dir(&self, scope: Scope, env: &Env) -> Option<Utf8PathBuf> {
        self.skills.dir(scope, env)
    }

    /// Whether the user plausibly has this client, used to pick a default set for
    /// `--client`. Deliberately generous: a leftover config directory counts,
    /// because writing an entry for a client you uninstalled is harmless while
    /// silently skipping one you do have is not.
    pub fn detected(&self, env: &Env) -> bool {
        if self.cli.is_some_and(|bin| which::which(bin).is_ok()) {
            return true;
        }
        let marks: &[Utf8PathBuf] = &match self.id {
            "claude-code" => vec![env.home.join(".claude.json"), env.home.join(".claude")],
            "cursor" => vec![env.home.join(".cursor")],
            "vscode" => vec![env.app_config.join("Code").join("User")],
            "codex" => vec![env.home.join(".codex")],
            _ => vec![],
        };
        marks.iter().any(|p| p.exists())
    }

    /// The first-party CLI, if it is installed *and* usable for this scope.
    ///
    /// Only consulted under `--delegate`. Even then it is skipped where the CLI
    /// cannot express what we need — see the per-arm notes.
    pub fn delegate(&self, scope: Scope) -> Option<Utf8PathBuf> {
        let bin = self.cli?;
        match (self.id, scope) {
            // `code --add-mcp` only ever writes the user profile.
            ("vscode", Scope::Project) => return None,
            // `claude mcp add` mis-parses arguments that look like Windows switches
            // (anthropics/claude-code#4158: `/c` becomes `C:/`). Engine argv is
            // ours and currently safe, but the failure is silent corruption of the
            // command line, so Windows takes the direct-write path.
            ("claude-code", _) if cfg!(windows) => return None,
            _ => {}
        }
        which::which(bin)
            .ok()
            .and_then(|p| Utf8PathBuf::from_path_buf(p).ok())
    }

    /// Argv to add (or replace) `spec` via the first-party CLI.
    ///
    /// A `Vec<Vec<String>>` because Claude Code needs two: `add-json` exits 1 on an
    /// existing name rather than updating it, so an idempotent add is
    /// remove-then-add. The remove is expected to fail when nothing is there.
    pub fn add_argv(&self, spec: &ServerSpec, scope: Scope) -> Vec<Step> {
        match self.id {
            "claude-code" => {
                let s = claude_scope(scope);
                vec![
                    Step {
                        argv: vec![
                            "claude".into(),
                            "mcp".into(),
                            "remove".into(),
                            spec.name.clone(),
                            "--scope".into(),
                            s.into(),
                        ],
                        // Exits 1 when the server is not there, which is the
                        // common case on a first install.
                        tolerate_failure: true,
                    },
                    Step {
                        argv: vec![
                            "claude".into(),
                            "mcp".into(),
                            "add-json".into(),
                            spec.name.clone(),
                            self.entry_json(spec),
                            "--scope".into(),
                            s.into(),
                        ],
                        tolerate_failure: false,
                    },
                ]
            }
            "codex" => {
                // `codex mcp add` overwrites an existing entry in place, so one
                // step is enough. `--` keeps engine flags out of codex's own parser.
                let mut argv = vec![
                    "codex".into(),
                    "mcp".into(),
                    "add".into(),
                    spec.name.clone(),
                    "--".into(),
                    spec.command.clone(),
                ];
                argv.extend(spec.args.iter().cloned());
                vec![Step {
                    argv,
                    tolerate_failure: false,
                }]
            }
            "vscode" => vec![Step {
                argv: vec![
                    "code".into(),
                    "--add-mcp".into(),
                    self.entry_json_named(spec),
                ],
                tolerate_failure: false,
            }],
            _ => vec![],
        }
    }

    /// Argv to drop `name` via the first-party CLI, when one can do it.
    ///
    /// `code` has no removal flag, so VS Code always uninstalls by direct write.
    pub fn remove_argv(&self, name: &str, scope: Scope) -> Vec<Step> {
        match self.id {
            "claude-code" => vec![Step {
                argv: vec![
                    "claude".into(),
                    "mcp".into(),
                    "remove".into(),
                    name.to_owned(),
                    "--scope".into(),
                    claude_scope(scope).into(),
                ],
                tolerate_failure: false,
            }],
            "codex" => vec![Step {
                argv: vec![
                    "codex".into(),
                    "mcp".into(),
                    "remove".into(),
                    name.to_owned(),
                ],
                tolerate_failure: false,
            }],
            _ => vec![],
        }
    }

    /// The entry body as Claude Code's `add-json` wants it.
    fn entry_json(&self, spec: &ServerSpec) -> String {
        let mut o = serde_json::Map::new();
        if self.emit_type {
            o.insert("type".into(), "stdio".into());
        }
        o.insert("command".into(), spec.command.as_str().into());
        o.insert("args".into(), serde_json::json!(spec.args));
        serde_json::Value::Object(o).to_string()
    }

    /// `code --add-mcp` takes the name inside the JSON rather than as an argument.
    fn entry_json_named(&self, spec: &ServerSpec) -> String {
        let mut o = serde_json::Map::new();
        o.insert("name".into(), spec.name.as_str().into());
        if self.emit_type {
            o.insert("type".into(), "stdio".into());
        }
        o.insert("command".into(), spec.command.as_str().into());
        o.insert("args".into(), serde_json::json!(spec.args));
        serde_json::Value::Object(o).to_string()
    }
}

/// One process to run, plus whether a non-zero exit is fatal.
#[derive(Debug, Clone)]
pub struct Step {
    pub argv: Vec<String>,
    pub tolerate_failure: bool,
}

impl Step {
    /// Shell-ish rendering for the preview. Quoting is for human eyes only — the
    /// process is spawned from `argv` directly and never goes through a shell.
    pub fn display(&self) -> String {
        self.argv
            .iter()
            .map(|a| {
                if a.is_empty()
                    || a.chars()
                        .any(|c| c.is_whitespace() || "\"'`$&|;<>()*?![]{}#~".contains(c))
                {
                    format!("'{}'", a.replace('\'', r"'\''"))
                } else {
                    a.clone()
                }
            })
            .collect::<Vec<_>>()
            .join(" ")
    }
}

/// vibrev's `global`/`project` versus Claude Code's `local`/`user`/`project`.
/// `local` is deliberately never used: it hides servers in a per-directory section
/// of `~/.claude.json`, which is the opposite of what either of our scopes means.
fn claude_scope(scope: Scope) -> &'static str {
    match scope {
        Scope::Global => "user",
        Scope::Project => "project",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env() -> Env {
        Env {
            home: Utf8PathBuf::from("/home/u"),
            app_config: Utf8PathBuf::from("/home/u/.config"),
            cwd: Utf8PathBuf::from("/work/proj"),
        }
    }

    #[test]
    fn every_client_resolves_a_global_file() {
        for c in CLIENTS {
            assert!(c.file(Scope::Global, &env()).is_some(), "{}", c.id);
        }
    }

    #[test]
    fn codex_has_no_project_scope() {
        let c = by_id("codex").unwrap();
        assert!(c.file(Scope::Project, &env()).is_none());
        assert!(c.file(Scope::Global, &env()).is_some());
    }

    #[test]
    fn documented_paths() {
        let e = env();
        let f = |id: &str, s: Scope| by_id(id).unwrap().file(s, &e).map(|p| p.to_string());
        assert_eq!(
            f("claude-code", Scope::Global).as_deref(),
            Some("/home/u/.claude.json")
        );
        assert_eq!(
            f("claude-code", Scope::Project).as_deref(),
            Some("/work/proj/.mcp.json")
        );
        assert_eq!(
            f("cursor", Scope::Global).as_deref(),
            Some("/home/u/.cursor/mcp.json")
        );
        assert_eq!(
            f("vscode", Scope::Global).as_deref(),
            Some("/home/u/.config/Code/User/mcp.json")
        );
        assert_eq!(
            f("vscode", Scope::Project).as_deref(),
            Some("/work/proj/.vscode/mcp.json")
        );
        assert_eq!(
            f("codex", Scope::Global).as_deref(),
            Some("/home/u/.codex/config.toml")
        );
    }

    #[test]
    fn only_claude_code_reads_skills() {
        let e = env();
        assert_eq!(
            by_id("claude-code")
                .unwrap()
                .skills_dir(Scope::Global, &e)
                .map(|p| p.to_string())
                .as_deref(),
            Some("/home/u/.claude/skills")
        );
        assert_eq!(
            by_id("claude-code")
                .unwrap()
                .skills_dir(Scope::Project, &e)
                .map(|p| p.to_string())
                .as_deref(),
            Some("/work/proj/.claude/skills")
        );
        for id in ["cursor", "vscode", "codex"] {
            let c = by_id(id).unwrap();
            assert!(c.skills_dir(Scope::Global, &e).is_none(), "{id}");
            // A skip with no reason reads as a bug, so every unsupported client
            // has to be able to say what it has instead.
            assert!(
                matches!(c.skills, SkillSupport::Unsupported(why) if !why.is_empty()),
                "{id} must explain why it has no skills"
            );
        }
    }

    #[test]
    fn only_our_own_names_are_ours() {
        assert!(is_ours("vibrev-ida"));
        assert!(is_ours("vibrev-jadx"));
        // Not an engine, so not ours — a user is free to name a server this.
        assert!(!is_ours("vibrev-ghidra"));
        assert!(!is_ours("mcp-ida"));
        assert!(!is_ours("vibrev"));
    }

    #[test]
    fn claude_add_is_remove_then_add() {
        let c = by_id("claude-code").unwrap();
        let spec = ServerSpec {
            name: "vibrev-jadx".into(),
            engine: "jadx",
            command: "/opt/rjadx".into(),
            args: vec!["mcp".into(), "--stdio".into()],
        };
        let steps = c.add_argv(&spec, Scope::Global);
        assert_eq!(steps.len(), 2);
        assert!(
            steps[0].tolerate_failure,
            "the pre-remove must not be fatal"
        );
        assert_eq!(steps[0].argv[2], "remove");
        assert_eq!(steps[1].argv[2], "add-json");
        // `--scope user`, never `local`.
        assert_eq!(steps[1].argv.last().unwrap(), "user");
    }

    #[test]
    fn codex_argv_puts_engine_flags_after_a_double_dash() {
        let c = by_id("codex").unwrap();
        let spec = ServerSpec {
            name: "vibrev-jadx".into(),
            engine: "jadx",
            command: "/opt/rjadx".into(),
            args: vec!["mcp".into(), "--stdio".into()],
        };
        let steps = c.add_argv(&spec, Scope::Global);
        assert_eq!(
            steps[0].argv,
            [
                "codex",
                "mcp",
                "add",
                "vibrev-jadx",
                "--",
                "/opt/rjadx",
                "mcp",
                "--stdio"
            ]
        );
    }

    #[test]
    fn vscode_project_scope_is_never_delegated() {
        let c = by_id("vscode").unwrap();
        assert!(c.delegate(Scope::Project).is_none());
    }

    #[test]
    fn type_stdio_only_where_the_schema_documents_it() {
        let spec = ServerSpec {
            name: "vibrev-ida".into(),
            engine: "ida",
            command: "/opt/ida-headless-mcp".into(),
            args: vec![],
        };
        assert!(
            by_id("claude-code")
                .unwrap()
                .entry_json(&spec)
                .contains("stdio")
        );
        assert!(!by_id("cursor").unwrap().entry_json(&spec).contains("stdio"));
        assert!(!by_id("codex").unwrap().entry_json(&spec).contains("stdio"));
    }

    #[test]
    fn preview_quotes_json_but_not_plain_paths() {
        let s = Step {
            argv: vec!["claude".into(), "/opt/x".into(), r#"{"a":1}"#.into()],
            tolerate_failure: false,
        };
        assert_eq!(s.display(), r#"claude /opt/x '{"a":1}'"#);
    }
}
