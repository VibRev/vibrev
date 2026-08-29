//! The MCP client registry — the one place that knows where each supported
//! client keeps its server list and what shape an entry takes there.
//!
//! An entry is either stdio (`command` + `args`, the client spawns the binary) or
//! HTTP (`url` + optional bearer, the operator starts the listener). [`ServerSpec`]
//! is that choice, rendered into the client's dialect.
//!
//! Clients differ in every axis that matters, which is why this is data and not a
//! trait: top-level key (`mcpServers` / `servers` / `mcp_servers` /
//! `context_servers`), file format (JSON / JSONC / TOML), file location, and
//! whether a first-party CLI exists to delegate to. Paths live on [`Client`]
//! too — a match on `id` is how a fourth client used to sneak in a fifth path.

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
///
/// Two shapes because they are two transports: folding them into one struct
/// with optional fields would let `command` sit next to `url`, which Codex
/// treats as a config error rather than a merely untidy one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServerSpec {
    /// The client spawns `command` with `args`.
    Stdio {
        /// `vibrev-<engine id>`. Also the idempotency key.
        name: String,
        engine: &'static str,
        command: String,
        args: Vec<String>,
    },
    /// The client connects to a listener the operator started.
    Http {
        name: String,
        engine: &'static str,
        url: String,
        /// Absent when this run was told not to copy the bearer — by default
        /// that is every version-controlled file. The URL still goes in so the
        /// client knows where to connect.
        token: Option<String>,
    },
}

impl ServerSpec {
    pub fn stdio(engine: &'static Engine, command: &Utf8Path, args: &[String]) -> Self {
        Self::Stdio {
            name: server_name(engine.id),
            engine: engine.id,
            command: command.to_string(),
            args: args.to_vec(),
        }
    }

    pub fn http(engine: &'static Engine, url: &str, token: Option<String>) -> Self {
        Self::Http {
            name: server_name(engine.id),
            engine: engine.id,
            url: url.to_owned(),
            token,
        }
    }

    /// Uninstall only needs the name; the transport of a missing entry is nothing.
    pub fn named(engine: &'static Engine) -> Self {
        Self::Stdio {
            name: server_name(engine.id),
            engine: engine.id,
            command: String::new(),
            args: Vec::new(),
        }
    }

    pub fn name(&self) -> &str {
        match self {
            Self::Stdio { name, .. } | Self::Http { name, .. } => name,
        }
    }

    pub fn engine(&self) -> &'static str {
        match self {
            Self::Stdio { engine, .. } | Self::Http { engine, .. } => engine,
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

/// A config file (or detection mark) resolved against [`Env`].
#[derive(Debug, Clone, Copy)]
enum ConfigPath {
    /// `$HOME/<segments>`
    Home(&'static [&'static str]),
    /// Platform app-config dir: `~/Library/Application Support` on macOS,
    /// `%APPDATA%` on Windows, `$XDG_CONFIG_HOME` (else `~/.config`) on Linux.
    App(&'static [&'static str]),
    /// `$CWD/<segments>`
    Project(&'static [&'static str]),
}

impl ConfigPath {
    fn resolve(self, env: &Env) -> Utf8PathBuf {
        let (base, segs) = match self {
            Self::Home(segs) => (&env.home, segs),
            Self::App(segs) => (&env.app_config, segs),
            Self::Project(segs) => (&env.cwd, segs),
        };
        segs.iter().fold(base.to_owned(), |p, s| p.join(s))
    }
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
    /// Extra names `by_id` accepts. Canonical `id` stays what tables print.
    pub aliases: &'static [&'static str],
    /// Display name for tables and prose.
    pub label: &'static str,
    /// The top-level table holding servers.
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
    global: ConfigPath,
    project: Option<ConfigPath>,
    /// Existence of any of these means the client is probably installed.
    marks: &'static [ConfigPath],
}

const MCP_SERVERS: &str = "mcpServers";
const NO_SKILLS: SkillSupport = SkillSupport::Unsupported("不读 Claude Code skill 目录");

#[cfg(target_os = "linux")]
const ZED_GLOBAL: ConfigPath = ConfigPath::Home(&[".config", "zed", "settings.json"]);
#[cfg(not(target_os = "linux"))]
const ZED_GLOBAL: ConfigPath = ConfigPath::App(&["Zed", "settings.json"]);
#[cfg(target_os = "linux")]
const ZED_MARK: ConfigPath = ConfigPath::Home(&[".config", "zed"]);
#[cfg(not(target_os = "linux"))]
const ZED_MARK: ConfigPath = ConfigPath::App(&["Zed"]);

pub const CLIENTS: &[Client] = &[
    Client {
        id: "claude-code",
        aliases: &[],
        label: "Claude Code",
        key: MCP_SERVERS,
        format: Format::Json,
        skills: SkillSupport::ClaudeStyle,
        emit_type: true,
        cli: Some("claude"),
        global: ConfigPath::Home(&[".claude.json"]),
        project: Some(ConfigPath::Project(&[".mcp.json"])),
        marks: &[
            ConfigPath::Home(&[".claude.json"]),
            ConfigPath::Home(&[".claude"]),
        ],
    },
    Client {
        id: "cursor",
        aliases: &[],
        label: "Cursor",
        key: MCP_SERVERS,
        format: Format::Json,
        skills: SkillSupport::Unsupported("只有 .cursor/rules，不读 skill 目录"),
        emit_type: false,
        cli: None,
        global: ConfigPath::Home(&[".cursor", "mcp.json"]),
        project: Some(ConfigPath::Project(&[".cursor", "mcp.json"])),
        marks: &[ConfigPath::Home(&[".cursor"])],
    },
    Client {
        id: "vscode",
        aliases: &["vs-code"],
        label: "VS Code",
        key: "servers",
        // `mcp.json` ships with explanatory comments and users add their own; the
        // file also carries an `inputs` array that must survive untouched.
        format: Format::Jsonc,
        skills: SkillSupport::Unsupported("只有 Copilot instructions，不读 skill 目录"),
        emit_type: true,
        cli: Some("code"),
        global: ConfigPath::App(&["Code", "User", "mcp.json"]),
        project: Some(ConfigPath::Project(&[".vscode", "mcp.json"])),
        marks: &[ConfigPath::App(&["Code", "User"])],
    },
    Client {
        id: "vscode-insiders",
        aliases: &["vs-code-insiders"],
        label: "VS Code Insiders",
        key: "servers",
        format: Format::Jsonc,
        skills: SkillSupport::Unsupported("只有 Copilot instructions，不读 skill 目录"),
        emit_type: true,
        cli: Some("code-insiders"),
        global: ConfigPath::App(&["Code - Insiders", "User", "mcp.json"]),
        project: Some(ConfigPath::Project(&[".vscode", "mcp.json"])),
        marks: &[ConfigPath::App(&["Code - Insiders", "User"])],
    },
    Client {
        id: "codex",
        aliases: &[],
        label: "Codex",
        key: "mcp_servers",
        format: Format::Toml,
        skills: SkillSupport::Unsupported("只有 AGENTS.md，不读 skill 目录"),
        // Codex has no `type` field at all — `command` versus `url` is the
        // discriminator, and an unknown key is a config error there.
        emit_type: false,
        cli: Some("codex"),
        global: ConfigPath::Home(&[".codex", "config.toml"]),
        project: Some(ConfigPath::Project(&[".codex", "config.toml"])),
        marks: &[ConfigPath::Home(&[".codex"])],
    },
    Client {
        id: "claude-desktop",
        aliases: &["claude-app"],
        label: "Claude Desktop",
        key: MCP_SERVERS,
        format: Format::Json,
        skills: SkillSupport::Unsupported("桌面应用不读 skill 目录"),
        emit_type: true,
        cli: None,
        global: ConfigPath::App(&["Claude", "claude_desktop_config.json"]),
        project: None,
        marks: &[ConfigPath::App(&["Claude"])],
    },
    Client {
        id: "windsurf",
        aliases: &[],
        label: "Windsurf",
        key: MCP_SERVERS,
        format: Format::Json,
        skills: NO_SKILLS,
        emit_type: false,
        cli: None,
        global: ConfigPath::Home(&[".codeium", "windsurf", "mcp_config.json"]),
        project: Some(ConfigPath::Project(&[".windsurf", "mcp.json"])),
        marks: &[ConfigPath::Home(&[".codeium", "windsurf"])],
    },
    Client {
        id: "zed",
        aliases: &[],
        label: "Zed",
        key: "context_servers",
        format: Format::Jsonc,
        skills: NO_SKILLS,
        emit_type: false,
        cli: None,
        global: ZED_GLOBAL,
        project: Some(ConfigPath::Project(&[".zed", "settings.json"])),
        marks: &[ZED_MARK],
    },
    Client {
        id: "cline",
        aliases: &[],
        label: "Cline",
        key: MCP_SERVERS,
        format: Format::Json,
        skills: NO_SKILLS,
        emit_type: false,
        cli: None,
        global: ConfigPath::App(&[
            "Code",
            "User",
            "globalStorage",
            "saoudrizwan.claude-dev",
            "settings",
            "cline_mcp_settings.json",
        ]),
        project: None,
        marks: &[ConfigPath::App(&[
            "Code",
            "User",
            "globalStorage",
            "saoudrizwan.claude-dev",
        ])],
    },
    Client {
        id: "roo",
        aliases: &["roocode", "roo-code"],
        label: "Roo Code",
        key: MCP_SERVERS,
        format: Format::Json,
        skills: NO_SKILLS,
        emit_type: false,
        cli: None,
        global: ConfigPath::App(&[
            "Code",
            "User",
            "globalStorage",
            "rooveterinaryinc.roo-cline",
            "settings",
            "mcp_settings.json",
        ]),
        project: None,
        marks: &[ConfigPath::App(&[
            "Code",
            "User",
            "globalStorage",
            "rooveterinaryinc.roo-cline",
        ])],
    },
    Client {
        id: "kilo",
        aliases: &["kilocode", "kilo-code"],
        label: "Kilo Code",
        key: MCP_SERVERS,
        format: Format::Json,
        skills: NO_SKILLS,
        emit_type: false,
        cli: None,
        global: ConfigPath::App(&[
            "Code",
            "User",
            "globalStorage",
            "kilocode.kilo-code",
            "settings",
            "mcp_settings.json",
        ]),
        project: None,
        marks: &[ConfigPath::App(&[
            "Code",
            "User",
            "globalStorage",
            "kilocode.kilo-code",
        ])],
    },
    Client {
        id: "lmstudio",
        aliases: &["lm-studio"],
        label: "LM Studio",
        key: MCP_SERVERS,
        format: Format::Json,
        skills: NO_SKILLS,
        emit_type: false,
        cli: None,
        global: ConfigPath::Home(&[".lmstudio", "mcp.json"]),
        project: None,
        marks: &[ConfigPath::Home(&[".lmstudio"])],
    },
    Client {
        id: "gemini",
        aliases: &["gemini-cli"],
        label: "Gemini CLI",
        key: MCP_SERVERS,
        format: Format::Jsonc,
        skills: NO_SKILLS,
        emit_type: false,
        cli: None,
        global: ConfigPath::Home(&[".gemini", "settings.json"]),
        project: None,
        marks: &[ConfigPath::Home(&[".gemini"])],
    },
    Client {
        id: "qwen",
        aliases: &["qwen-coder"],
        label: "Qwen Coder",
        key: MCP_SERVERS,
        format: Format::Jsonc,
        skills: NO_SKILLS,
        emit_type: false,
        cli: None,
        global: ConfigPath::Home(&[".qwen", "settings.json"]),
        project: None,
        marks: &[ConfigPath::Home(&[".qwen"])],
    },
    Client {
        id: "copilot",
        aliases: &["copilot-cli"],
        label: "Copilot CLI",
        key: MCP_SERVERS,
        format: Format::Json,
        skills: NO_SKILLS,
        emit_type: false,
        cli: None,
        global: ConfigPath::Home(&[".copilot", "mcp-config.json"]),
        project: None,
        marks: &[ConfigPath::Home(&[".copilot"])],
    },
    Client {
        id: "amazonq",
        aliases: &["amazon-q"],
        label: "Amazon Q",
        key: MCP_SERVERS,
        format: Format::Json,
        skills: NO_SKILLS,
        emit_type: false,
        cli: None,
        global: ConfigPath::Home(&[".aws", "amazonq", "mcp_config.json"]),
        project: None,
        marks: &[ConfigPath::Home(&[".aws", "amazonq"])],
    },
    Client {
        id: "warp",
        aliases: &[],
        label: "Warp",
        key: MCP_SERVERS,
        format: Format::Json,
        skills: NO_SKILLS,
        emit_type: false,
        cli: None,
        global: ConfigPath::Home(&[".warp", "mcp_config.json"]),
        project: None,
        marks: &[ConfigPath::Home(&[".warp"])],
    },
    Client {
        id: "kiro",
        aliases: &[],
        label: "Kiro",
        key: MCP_SERVERS,
        format: Format::Json,
        skills: NO_SKILLS,
        emit_type: false,
        cli: None,
        global: ConfigPath::Home(&[".kiro", "mcp_config.json"]),
        project: None,
        marks: &[ConfigPath::Home(&[".kiro"])],
    },
    Client {
        id: "trae",
        aliases: &[],
        label: "Trae",
        key: MCP_SERVERS,
        format: Format::Json,
        skills: NO_SKILLS,
        emit_type: false,
        cli: None,
        global: ConfigPath::Home(&[".trae", "mcp_config.json"]),
        project: None,
        marks: &[ConfigPath::Home(&[".trae"])],
    },
    Client {
        id: "crush",
        aliases: &[],
        label: "Crush",
        key: MCP_SERVERS,
        format: Format::Json,
        skills: NO_SKILLS,
        emit_type: false,
        cli: None,
        global: ConfigPath::Home(&["crush.json"]),
        project: None,
        marks: &[ConfigPath::Home(&["crush.json"])],
    },
];

pub fn by_id(id: &str) -> Option<&'static Client> {
    CLIENTS
        .iter()
        .find(|c| c.id == id || c.aliases.iter().copied().any(|a| a == id))
}

pub fn ids() -> Vec<&'static str> {
    CLIENTS.iter().map(|c| c.id).collect()
}

/// Canonical ids plus aliases, for clap.
pub fn names() -> Vec<&'static str> {
    CLIENTS
        .iter()
        .flat_map(|c| std::iter::once(c.id).chain(c.aliases.iter().copied()))
        .collect()
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
    /// level at all.
    pub fn file(&self, scope: Scope, env: &Env) -> Option<Utf8PathBuf> {
        match scope {
            Scope::Global => Some(self.global.resolve(env)),
            Scope::Project => self.project.map(|p| p.resolve(env)),
        }
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
        self.marks.iter().any(|p| p.resolve(env).exists())
    }

    /// The first-party CLI, if it is installed *and* usable for this scope.
    ///
    /// Only consulted under `--delegate`. Even then it is skipped where the CLI
    /// cannot express what we need — see the per-arm notes.
    pub fn delegate(&self, scope: Scope) -> Option<Utf8PathBuf> {
        let bin = self.cli?;
        match (self.id, scope) {
            // `code --add-mcp` only ever writes the user profile.
            ("vscode" | "vscode-insiders", Scope::Project) => return None,
            // `codex mcp add` writes `~/.codex/config.toml`. Project scope is
            // `.codex/config.toml` in the repo, which only the direct writer hits.
            ("codex", Scope::Project) => return None,
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
                            spec.name().to_owned(),
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
                            spec.name().to_owned(),
                            self.entry_json(spec),
                            "--scope".into(),
                            s.into(),
                        ],
                        tolerate_failure: false,
                    },
                ]
            }
            "codex" => {
                // HTTP: `codex mcp add --url` cannot set a static bearer
                // (`http_headers` is config-file only), so the installer never
                // delegates an HTTP spec — see `install::build`. Stdio still
                // uses `--` so engine flags stay out of codex's own parser.
                let ServerSpec::Stdio {
                    name,
                    command,
                    args,
                    ..
                } = spec
                else {
                    return vec![];
                };
                let mut argv = vec![
                    "codex".into(),
                    "mcp".into(),
                    "add".into(),
                    name.clone(),
                    "--".into(),
                    command.clone(),
                ];
                argv.extend(args.iter().cloned());
                vec![Step {
                    argv,
                    tolerate_failure: false,
                }]
            }
            "vscode" | "vscode-insiders" => vec![Step {
                argv: vec![
                    self.cli.unwrap_or("code").into(),
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
        serde_json::Value::Object(self.entry_fields(spec, None)).to_string()
    }

    /// `code --add-mcp` takes the name inside the JSON rather than as an argument.
    fn entry_json_named(&self, spec: &ServerSpec) -> String {
        serde_json::Value::Object(self.entry_fields(spec, Some(spec.name()))).to_string()
    }

    fn entry_fields(
        &self,
        spec: &ServerSpec,
        name: Option<&str>,
    ) -> serde_json::Map<String, serde_json::Value> {
        let mut o = serde_json::Map::new();
        if let Some(name) = name {
            o.insert("name".into(), name.into());
        }
        match spec {
            ServerSpec::Stdio { command, args, .. } => {
                if self.emit_type {
                    o.insert("type".into(), "stdio".into());
                }
                o.insert("command".into(), command.as_str().into());
                o.insert("args".into(), serde_json::json!(args));
            }
            ServerSpec::Http { url, token, .. } => {
                if self.emit_type {
                    o.insert("type".into(), "http".into());
                }
                o.insert("url".into(), url.as_str().into());
                if let Some(token) = token {
                    o.insert(
                        "headers".into(),
                        serde_json::json!({ "Authorization": format!("Bearer {token}") }),
                    );
                }
            }
        }
        o
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
    fn every_client_resolves_a_project_file_or_says_it_has_none() {
        for c in CLIENTS {
            let got = c.file(Scope::Project, &env());
            match c.project {
                Some(_) => assert!(got.is_some(), "{}", c.id),
                None => assert!(got.is_none(), "{}", c.id),
            }
        }
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
        assert_eq!(
            f("codex", Scope::Project).as_deref(),
            Some("/work/proj/.codex/config.toml")
        );
        assert_eq!(
            f("windsurf", Scope::Global).as_deref(),
            Some("/home/u/.codeium/windsurf/mcp_config.json")
        );
        assert_eq!(
            f("windsurf", Scope::Project).as_deref(),
            Some("/work/proj/.windsurf/mcp.json")
        );
        assert_eq!(
            f("claude-desktop", Scope::Global).as_deref(),
            Some("/home/u/.config/Claude/claude_desktop_config.json")
        );
        assert_eq!(f("claude-desktop", Scope::Project), None);
        assert_eq!(
            f("vscode-insiders", Scope::Global).as_deref(),
            Some("/home/u/.config/Code - Insiders/User/mcp.json")
        );
        assert_eq!(
            f("cline", Scope::Global).as_deref(),
            Some(
                "/home/u/.config/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json"
            )
        );
        assert_eq!(
            f("zed", Scope::Project).as_deref(),
            Some("/work/proj/.zed/settings.json")
        );
    }

    #[test]
    fn aliases_resolve_to_the_canonical_client() {
        assert_eq!(by_id("roocode").unwrap().id, "roo");
        assert_eq!(by_id("amazon-q").unwrap().id, "amazonq");
        assert_eq!(by_id("vs-code-insiders").unwrap().id, "vscode-insiders");
        assert!(by_id("not-a-client").is_none());
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
        for c in CLIENTS.iter().filter(|c| c.id != "claude-code") {
            assert!(c.skills_dir(Scope::Global, &e).is_none(), "{}", c.id);
            // A skip with no reason reads as a bug, so every unsupported client
            // has to be able to say what it has instead.
            assert!(
                matches!(c.skills, SkillSupport::Unsupported(why) if !why.is_empty()),
                "{} must explain why it has no skills",
                c.id
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
        let spec = ServerSpec::Stdio {
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
        let spec = ServerSpec::Stdio {
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
        assert!(
            by_id("vscode-insiders")
                .unwrap()
                .delegate(Scope::Project)
                .is_none()
        );
    }

    #[test]
    fn codex_project_scope_is_never_delegated() {
        // `codex mcp add` writes ~/.codex/config.toml, not the repo file.
        let c = by_id("codex").unwrap();
        assert!(c.delegate(Scope::Project).is_none());
    }

    #[test]
    fn type_stdio_only_where_the_schema_documents_it() {
        let spec = ServerSpec::Stdio {
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
