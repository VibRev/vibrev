//! `vibrev install` / `uninstall` / `list` — registering engines with MCP clients.
//!
//! What gets written is a plain stdio entry pointing straight at the engine
//! binary, one per engine:
//!
//! ```jsonc
//! "vibrev-jadx": { "command": "~/.vibrev/engines/rjadx", "args": ["mcp", "--stdio"] }
//! ```
//!
//! `vibrev` is not in that command line, and there is no daemon, URL or token —
//! the client spawns the engine itself, and one entry per engine is what lets a
//! user turn `vibrev-ida` off in their client without losing `vibrev-jadx`.
//!
//! Because we only ever *write* stdio, we also *remove* the other transport's
//! keys from an entry we own (`mcpfile::HTTP_TRANSPORT_KEYS`). That is a security
//! rule before it is a tidiness one: `headers` is where the bearer token lives,
//! and project scope writes files that get committed. Deleting a token that has
//! already been committed does not un-leak it, so the removal is reported and
//! rotation is demanded rather than assumed — see [`credential_warning`].
//!
//! Two write paths. Both are supported and both are tested, but they are not
//! equals — the direct write is the default:
//!
//! * **direct write** through a format-preserving parser. The default, because it
//!   is the only path that can promise a user's file comes back the way they left
//!   it;
//! * **delegate** to the client's own CLI, behind `--delegate`. It tracks upstream
//!   schema changes for free, which is real but speculative value; the cost is
//!   measured — `codex mcp add` (0.147.0) reserializes the `[mcp_servers]` region
//!   and deletes every comment attached to it. A preserving writer exists for
//!   exactly one reason, and delegating discards it, so the user has to ask.
//!
//! Which one is running is never left implicit, because the two can preview
//! different things: we cannot know what `claude mcp add-json` will do to a file,
//! so delegation previews **the commands to be run** while a direct write previews
//! **the diff**. Blending them into one fake "diff" would be a lie.

use std::io::IsTerminal;

use anyhow::{Context, Result, bail};
use camino::{Utf8Path, Utf8PathBuf};
use owo_colors::{OwoColorize, Stream};
use serde_json::{Value, json};

use crate::atomic::{self, Backup};
use crate::client::{self, Client, Env, Scope, ServerSpec, Step};
use crate::config::{Config, Paths};
use crate::discover::{self, Located, Outcome};
use crate::engine::{self, Engine};
use crate::mcpfile::{self, Op};
use crate::skill::{self, Skill, State};

/// `install` and `uninstall` differ only in which way the entries move.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Install,
    Uninstall,
}

impl Kind {
    fn as_str(self) -> &'static str {
        match self {
            Kind::Install => "install",
            Kind::Uninstall => "uninstall",
        }
    }
}

pub struct Options {
    pub kind: Kind,
    pub engines: Vec<String>,
    pub all: bool,
    pub clients: Vec<String>,
    pub scope: Scope,
    pub dry_run: bool,
    pub yes: bool,
    /// Hand the file to the client's own CLI instead of writing it here.
    /// Off by default: it costs the format-preservation guarantee, and losing a
    /// user's comments is a measured harm where staying on the upstream schema is
    /// a hoped-for benefit.
    pub delegate: bool,
    /// Whether this run touches the MCP entry, the skill directories, or both.
    pub skills: SkillMode,
}

/// Which of the two halves of an install a run is doing.
///
/// They are separate because they are separately useful: an engine upgrade
/// changes the skill content without changing the `command` line, and a user who
/// does not want 2 MB of reference material in their home should be able to say
/// so without giving up the server entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SkillMode {
    /// The default for `install` / `uninstall`: server entry and skills together.
    With,
    /// `--no-skills`.
    Without,
    /// `vibrev skill install` / `vibrev skill uninstall`.
    Only,
}

impl SkillMode {
    fn servers(self) -> bool {
        match self {
            Self::With | Self::Without => true,
            Self::Only => false,
        }
    }

    fn skills(self) -> bool {
        match self {
            Self::With | Self::Only => true,
            Self::Without => false,
        }
    }

    /// What to call this run in the preview heading and the JSON `command`.
    fn verb(self, kind: Kind) -> &'static str {
        match (self, kind) {
            (Self::Only, Kind::Install) => "skill install",
            (Self::Only, Kind::Uninstall) => "skill uninstall",
            (_, Kind::Install) => "install",
            (_, Kind::Uninstall) => "uninstall",
        }
    }
}

/// How one file will be changed.
#[derive(Debug)]
enum Method {
    Delegate {
        /// Resolved binary, so the spawn does not re-search `PATH`.
        bin: Utf8PathBuf,
        label: &'static str,
    },
    Direct,
}

#[derive(Debug)]
struct Change {
    spec: Option<ServerSpec>,
    server: String,
    engine: &'static str,
    op: Op,
    /// The entry we are about to write held an `Authorization` header, which the
    /// upsert strips (`mcpfile::HTTP_TRANSPORT_KEYS`). Recorded because the strip
    /// is not the whole story: in a version-controlled file the token is already
    /// in history and has to be rotated, not just deleted.
    stripped_credentials: bool,
    /// The literal secret values found in this entry, masked out of the preview.
    secrets: Vec<String>,
    /// Only for the delegate path.
    steps: Vec<Step>,
}

#[derive(Debug)]
struct Action {
    client: &'static Client,
    scope: Scope,
    file: Utf8PathBuf,
    method: Method,
    changes: Vec<Change>,
    before: String,
    /// The exact bytes a direct write would produce. Empty for delegation, where
    /// the resulting file is the client CLI's business.
    after: String,
}

impl Action {
    fn writes(&self) -> bool {
        self.changes.iter().any(|c| c.op.writes())
    }
}

#[derive(Debug)]
struct Skip {
    client: &'static Client,
    scope: Scope,
    reason: String,
}

/// One skill directory's worth of change.
///
/// Kept beside [`Action`] rather than inside it: an `Action` is one file edited
/// through a format-preserving parser and previewed as a diff, while this is a
/// whole directory replaced wholesale and previewed as a summary. Folding the
/// two into one type buys nothing and costs a branch at every use.
#[derive(Debug)]
struct SkillAction {
    client: &'static Client,
    scope: Scope,
    /// The client's skills root, e.g. `~/.claude/skills`.
    dir: Utf8PathBuf,
    engine: &'static str,
    skill: Skill,
    op: SkillOp,
    /// How to obtain the content. `None` for removals, which read the disk and
    /// never need the engine — an engine that has been deleted must still be
    /// uninstallable.
    source: Option<Source>,
}

impl SkillAction {
    fn target(&self) -> Utf8PathBuf {
        self.dir.join(&self.skill.name)
    }
}

/// Where an install pulls skill content from.
#[derive(Debug, Clone)]
struct Source {
    engine: &'static Engine,
    located: Located,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum SkillOp {
    Added,
    /// The engine was upgraded and now carries different content.
    Updated {
        from: String,
    },
    Unchanged,
    Removed,
    /// A directory under this name exists with no ownership marker. Never
    /// written, never removed — see [`crate::skill`].
    Foreign,
    /// Ours, but installed on behalf of a different engine.
    OtherEngine {
        engine: String,
    },
}

impl SkillOp {
    fn writes(&self) -> bool {
        match self {
            Self::Added | Self::Updated { .. } | Self::Removed => true,
            Self::Unchanged | Self::Foreign | Self::OtherEngine { .. } => false,
        }
    }

    fn label(&self) -> &'static str {
        match self {
            Self::Added => "新增",
            Self::Updated { .. } => "更新",
            Self::Unchanged => "无变化",
            Self::Removed => "移除",
            Self::Foreign | Self::OtherEngine { .. } => "跳过",
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            Self::Added => "added",
            Self::Updated { .. } => "updated",
            Self::Unchanged => "unchanged",
            Self::Removed => "removed",
            Self::Foreign => "foreign",
            Self::OtherEngine { .. } => "other-engine",
        }
    }

    /// The half-line appended after the skill name, where there is something the
    /// user has to understand before the run finishes.
    fn note(&self) -> Option<String> {
        match self {
            // The way out has to be part of the message. Refusing without saying
            // how to proceed leaves a user who genuinely wants our copy — because
            // they moved here from ida-pro-mcp's plugin, say — with no next step
            // and no idea that deleting the directory is the sanctioned one.
            Self::Foreign => Some(format!(
                "该目录没有 {} 标记，不是 vibrev 装的；不会覆盖，也不会删除。\
                 确认可以丢弃后，手动删掉该目录再重跑本命令",
                skill::MARKER
            )),
            Self::OtherEngine { engine } => Some(format!(
                "这份是 {engine} 引擎装的，本次不动它；要换成本引擎的版本，先 vibrev skill uninstall {engine}"
            )),
            Self::Updated { from } => Some(format!("引擎已升级（原指纹 {from}）")),
            Self::Added | Self::Unchanged | Self::Removed => None,
        }
    }
}

#[derive(Debug)]
struct Plan {
    kind: Kind,
    scope: Scope,
    mode: SkillMode,
    actions: Vec<Action>,
    skill_actions: Vec<SkillAction>,
    skips: Vec<Skip>,
}

impl Plan {
    fn is_empty(&self) -> bool {
        self.actions.is_empty() && self.skill_actions.is_empty()
    }

    fn writes(&self) -> bool {
        self.actions.iter().any(Action::writes) || self.skill_actions.iter().any(|s| s.op.writes())
    }
}

// ------------------------------------------------------------------- entry ---

/// Never returns: every path ends in [`crate::ui::fail`] or `exit(0)`.
pub fn run(opts: Options, cfg: &Config, paths: &Paths, json: bool) -> ! {
    match execute(&opts, cfg, paths, json) {
        Ok(()) => std::process::exit(0),
        Err(e) => {
            // The engine-missing case carries its install guidance as the error
            // chain's tail; keep it, that is the actionable part.
            let detail: Vec<String> = e
                .chain()
                .skip(1)
                .map(|c| c.to_string())
                .flat_map(|s| s.lines().map(str::to_owned).collect::<Vec<_>>())
                .collect();
            crate::ui::fail(json, opts.kind.as_str(), &e.to_string(), &detail)
        }
    }
}

fn execute(opts: &Options, cfg: &Config, paths: &Paths, json: bool) -> Result<()> {
    let env = Env::resolve()?;
    let resolved = resolve_engines(opts, cfg, paths)?;
    let clients = resolve_clients(opts, &env)?;
    let plan = build(opts, &clients, &resolved, &env, paths)?;

    if plan.is_empty() {
        if json {
            println!("{}", crate::pretty(&plan.to_json(opts.dry_run)));
            return Ok(());
        }
        for s in &plan.skips {
            println!(
                "跳过 {} ({})：{}",
                s.client.label,
                s.scope.as_str(),
                s.reason
            );
        }
        bail!(match opts.skills {
            SkillMode::Only => "没有可安装的技能目录",
            SkillMode::With | SkillMode::Without => "没有可写入的客户端配置",
        });
    }

    if json {
        // A machine reading `--json` gets the plan; `--dry-run` says whether it
        // was carried out. There is no prompt to fall back on here, so the same
        // rule as a pipe applies: writing needs `--yes` spelled out.
        if !opts.dry_run {
            if !opts.yes {
                bail!("--json 模式下不会交互确认；确认后加 --yes，或用 --dry-run 预览");
            }
            apply(&plan, paths)?;
        }
        println!("{}", crate::pretty(&plan.to_json(opts.dry_run)));
        return Ok(());
    }

    // The preview prints in every mode, including `--yes`: it is the record of
    // what happened, not just a confirmation prompt.
    print!("{}", render(&plan, paths, &env, crate::ui::color_enabled()));

    if opts.dry_run {
        println!("--dry-run：未写入任何文件。");
        return Ok(());
    }
    if !plan.writes() {
        println!("所有条目均已是最新，无需写入。");
        return Ok(());
    }
    if !opts.yes && !confirm()? {
        println!("已取消。");
        return Ok(());
    }

    let outcomes = apply(&plan, paths)?;
    println!();
    for action in plan.skill_actions.iter().filter(|a| a.op.writes()) {
        println!(
            "✓ {} {}  {} {}",
            action.client.label,
            paths.abbreviate(&action.target()),
            action.op.label(),
            action.skill.name
        );
    }
    for (action, backup) in plan.actions.iter().zip(&outcomes) {
        let changed: Vec<String> = action
            .changes
            .iter()
            .filter(|c| c.op.writes())
            .map(|c| format!("{} {}", c.op.label(), c.server))
            .collect();
        if changed.is_empty() {
            continue;
        }
        println!(
            "✓ {} {}  {}",
            action.client.label,
            paths.abbreviate(&action.file),
            changed.join("，")
        );
        if let Backup::Created(p) = backup {
            println!("  已备份原文件到 {}", paths.abbreviate(p));
            // The backup is a verbatim copy, so it still holds whatever we just
            // removed. Saying where it went is not enough — the user has to know
            // it is still a live copy of the secret.
            if action.changes.iter().any(|c| c.stripped_credentials) {
                println!("  ⚠ 该备份里仍是原始内容，凭据原样保留（权限 0600）");
                if action.scope.version_controlled() {
                    println!("    已刻意放在仓库之外，避免 git add 时被一起提交");
                }
            }
        }
    }
    Ok(())
}

// -------------------------------------------------------------- resolution ---

/// One engine, resolved as far as this run needs it.
#[derive(Debug)]
struct Resolved {
    engine: &'static Engine,
    spec: ServerSpec,
    /// Where the binary is. `None` on uninstall, which works from names alone.
    located: Option<Located>,
}

/// Turn engine ids into concrete `command` + `args`, refusing anything we cannot
/// point a client at.
fn resolve_engines(opts: &Options, cfg: &Config, paths: &Paths) -> Result<Vec<Resolved>> {
    // Uninstall works from names alone: the binary may well be gone already, and
    // requiring it to be present in order to *remove* the entry would be absurd.
    // The same holds for skills, which is why removal reads its list off the disk
    // markers instead of asking the engine.
    if opts.kind == Kind::Uninstall {
        let engines: Vec<&'static Engine> = if opts.all || opts.engines.is_empty() {
            engine::ENGINES.iter().collect()
        } else {
            opts.engines
                .iter()
                .map(|id| lookup(id))
                .collect::<Result<_>>()?
        };
        return Ok(engines
            .into_iter()
            .map(|e| Resolved {
                engine: e,
                spec: ServerSpec {
                    name: client::server_name(e.id),
                    engine: e.id,
                    command: String::new(),
                    args: Vec::new(),
                },
                located: None,
            })
            .collect());
    }

    let wanted: Vec<&'static Engine> = if opts.all {
        engine::ENGINES.iter().collect()
    } else {
        opts.engines
            .iter()
            .map(|id| lookup(id))
            .collect::<Result<_>>()?
    };

    let mut resolved = Vec::new();
    for eng in wanted {
        match discover::locate(eng, cfg, paths) {
            Outcome::Found(l) => resolved.push(Resolved {
                engine: eng,
                spec: ServerSpec::new(eng, &l.path, &l.mcp_args),
                located: Some(l),
            }),
            // `--all` means "everything you can find", so a missing engine is
            // simply not part of the answer.
            Outcome::Missing if opts.all => continue,
            Outcome::Missing => {
                return Err(anyhow::Error::msg(eng.install.join("\n")).context(format!(
                    "未找到 {} 引擎的二进制 {}，拒绝为它写入客户端配置",
                    eng.id, eng.bin
                )));
            }
            Outcome::ConfigBroken { path, reason } if opts.all => {
                // Silently skipping a path the user wrote down would hide their
                // typo; naming it and carrying on with the rest is the compromise.
                eprintln!(
                    "警告：{} 的 config.toml 路径 {path} {reason}，已跳过",
                    eng.id
                );
                continue;
            }
            Outcome::ConfigBroken { path, reason } => {
                bail!("{} 的 config.toml 路径 {path} {reason}", eng.id)
            }
        }
    }

    if resolved.is_empty() {
        bail!(
            "没有发现任何可注册的引擎；先运行 vibrev doctor 查看查找位置与安装指引（可用: {}）",
            engine::ids().join(" / ")
        );
    }
    Ok(resolved)
}

fn lookup(id: &str) -> Result<&'static Engine> {
    engine::by_id(id)
        .ok_or_else(|| anyhow::anyhow!("未知的引擎 {id}（可用: {}）", engine::ids().join(" / ")))
}

fn resolve_clients(opts: &Options, env: &Env) -> Result<Vec<&'static Client>> {
    if opts.clients.is_empty() {
        let found: Vec<&'static Client> =
            client::CLIENTS.iter().filter(|c| c.detected(env)).collect();
        if found.is_empty() {
            bail!(
                "没有检测到任何 MCP 客户端；用 --client 明确指定（可用: {}）",
                client::ids().join(" / ")
            );
        }
        return Ok(found);
    }
    opts.clients
        .iter()
        .map(|id| {
            client::by_id(id).ok_or_else(|| {
                anyhow::anyhow!("未知的客户端 {id}（可用: {}）", client::ids().join(" / "))
            })
        })
        .collect()
}

// -------------------------------------------------------------------- plan ---

fn build(
    opts: &Options,
    clients: &[&'static Client],
    resolved: &[Resolved],
    env: &Env,
    paths: &Paths,
) -> Result<Plan> {
    let mut actions = Vec::new();
    let mut skill_actions = Vec::new();
    let mut skips = Vec::new();

    if opts.skills.skills() {
        for &c in clients {
            build_skills(opts, c, resolved, env, &mut skill_actions, &mut skips);
        }
    }

    if !opts.skills.servers() {
        return Ok(Plan {
            kind: opts.kind,
            scope: opts.scope,
            mode: opts.skills,
            actions,
            skill_actions,
            skips,
        });
    }

    let specs: Vec<ServerSpec> = resolved.iter().map(|r| r.spec.clone()).collect();
    for &c in clients {
        let Some(file) = c.file(opts.scope, env) else {
            skips.push(Skip {
                client: c,
                scope: opts.scope,
                reason: format!("{} 没有项目级作用域，只会读取全局配置", c.label),
            });
            continue;
        };

        // Uninstall must not create a file that was never there.
        if opts.kind == Kind::Uninstall && !file.exists() {
            skips.push(Skip {
                client: c,
                scope: opts.scope,
                reason: format!("{} 不存在", paths.abbreviate(&file)),
            });
            continue;
        }

        let delegate = if opts.delegate {
            c.delegate(opts.scope)
        } else {
            None
        };
        // Removal by CLI is not universal: `code` has no counterpart to
        // `--add-mcp`, so VS Code always uninstalls by direct write.
        let delegate = match (opts.kind, delegate) {
            (Kind::Uninstall, Some(_)) if c.remove_argv("x", opts.scope).is_empty() => None,
            (_, d) => d,
        };

        let (before, mut doc) = mcpfile::read(&file, c.format)?;
        let mut changes = Vec::new();
        for spec in &specs {
            // Sampled before the upsert, which is what removes them.
            let stripped_credentials =
                opts.kind == Kind::Install && doc.carries_credentials(c, &spec.name);
            let secrets = if stripped_credentials {
                doc.credential_values(c, &spec.name)
            } else {
                Vec::new()
            };
            let op = match opts.kind {
                Kind::Install => doc
                    .upsert(c, spec)
                    .with_context(|| format!("{file}: 无法写入 {}", spec.name))?,
                Kind::Uninstall => doc
                    .remove(c, &spec.name)
                    .with_context(|| format!("{file}: 无法移除 {}", spec.name))?,
            };
            let steps = match (&delegate, op.writes(), opts.kind) {
                (Some(_), true, Kind::Install) => c.add_argv(spec, opts.scope),
                (Some(_), true, Kind::Uninstall) => c.remove_argv(&spec.name, opts.scope),
                _ => Vec::new(),
            };
            changes.push(Change {
                spec: (opts.kind == Kind::Install).then(|| spec.clone()),
                server: spec.name.clone(),
                engine: spec.engine,
                op,
                stripped_credentials,
                secrets,
                steps,
            });
        }

        // Uninstall of engines that were never registered: nothing to say beyond
        // "absent", and an empty action would just be noise in the preview.
        if changes.iter().all(|c| c.op == Op::Absent) {
            skips.push(Skip {
                client: c,
                scope: opts.scope,
                reason: format!("{} 里没有 vibrev 条目", paths.abbreviate(&file)),
            });
            continue;
        }

        let (method, after) = match delegate {
            Some(bin) => (
                Method::Delegate {
                    bin,
                    label: c.cli.unwrap_or("?"),
                },
                String::new(),
            ),
            // Rendered once, here: the bytes previewed as a diff are byte-for-byte
            // the bytes `apply` writes, with no second parse in between.
            None => (Method::Direct, doc.render()),
        };

        actions.push(Action {
            client: c,
            scope: opts.scope,
            file,
            method,
            changes,
            before,
            after,
        });
    }

    Ok(Plan {
        kind: opts.kind,
        scope: opts.scope,
        mode: opts.skills,
        actions,
        skill_actions,
        skips,
    })
}

/// Work out what happens to `client`'s skill directories.
///
/// Install and uninstall discover their work from opposite ends. Installing asks
/// each engine what it carries; removing reads the ownership markers off the
/// disk, because the engine may be long gone and a skill you cannot uninstall
/// once the binary is deleted is a skill that lives in someone's home forever.
fn build_skills(
    opts: &Options,
    client: &'static Client,
    resolved: &[Resolved],
    env: &Env,
    out: &mut Vec<SkillAction>,
    skips: &mut Vec<Skip>,
) {
    let Some(dir) = client.skills_dir(opts.scope, env) else {
        let client::SkillSupport::Unsupported(why) = client.skills else {
            // `skills_dir` only returns None for Unsupported, so this is
            // unreachable; saying so beats an `unwrap` that lies about it.
            unreachable!("a client with a skills directory always resolves one")
        };
        skips.push(Skip {
            client,
            scope: opts.scope,
            reason: format!("{why}（skill）"),
        });
        return;
    };

    match opts.kind {
        Kind::Install => {
            for r in resolved {
                let Some(located) = &r.located else {
                    continue;
                };
                for s in skill::offered(r.engine, located) {
                    let target = dir.join(&s.name);
                    let op = match State::read(&target, r.engine.id, &s) {
                        State::Absent => SkillOp::Added,
                        State::Current => SkillOp::Unchanged,
                        State::Stale { from } => SkillOp::Updated { from },
                        State::Foreign => SkillOp::Foreign,
                        State::OtherEngine { engine } => SkillOp::OtherEngine { engine },
                    };
                    out.push(SkillAction {
                        client,
                        scope: opts.scope,
                        dir: dir.clone(),
                        engine: r.engine.id,
                        skill: s,
                        op,
                        source: Some(Source {
                            engine: r.engine,
                            located: located.clone(),
                        }),
                    });
                }
            }
        }
        Kind::Uninstall => {
            let wanted: Vec<&'static str> = resolved.iter().map(|r| r.engine.id).collect();
            for (marker, target) in installed_under(&dir) {
                if !wanted.contains(&marker.engine.as_str()) {
                    continue;
                }
                out.push(SkillAction {
                    client,
                    scope: opts.scope,
                    dir: dir.clone(),
                    // Leaked from the marker rather than from the registry: the
                    // borrow has to be 'static and the id came from us.
                    engine: engine::by_id(&marker.engine).map_or("?", |e| e.id),
                    skill: Skill {
                        name: target.file_name().unwrap_or(&marker.name).to_owned(),
                        description: String::new(),
                        files: marker.files,
                        bytes: 0,
                        fingerprint: marker.fingerprint,
                    },
                    op: SkillOp::Removed,
                    source: None,
                });
            }
        }
    }
}

/// Every skill directory under `dir` that carries our ownership marker.
///
/// Directories without one are not returned at all: they are not ours to list,
/// let alone to remove.
fn installed_under(dir: &Utf8Path) -> Vec<(skill::Marker, Utf8PathBuf)> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut found: Vec<(skill::Marker, Utf8PathBuf)> = entries
        .filter_map(Result::ok)
        .filter_map(|e| Utf8PathBuf::from_path_buf(e.path()).ok())
        .filter(|p| p.is_dir())
        .filter_map(|p| skill::Marker::read(&p).map(|m| (m, p)))
        .collect();
    found.sort_by(|a, b| a.1.cmp(&b.1));
    found
}

// ------------------------------------------------------------------ render ---

fn render(plan: &Plan, paths: &Paths, env: &Env, color: bool) -> String {
    let bold = |s: &str| {
        if color {
            format!("{}", s.if_supports_color(Stream::Stdout, |t| t.bold()))
        } else {
            s.to_owned()
        }
    };

    let verb = plan.mode.verb(plan.kind);
    let mut out = format!(
        "{}\n\n",
        bold(&format!(
            "计划变更（{verb}，作用域 {}）",
            plan.scope.as_str()
        ))
    );
    if plan.scope == Scope::Project {
        out.push_str(&format!("项目目录: {}\n\n", env.cwd));
    }

    for a in &plan.actions {
        let tag = match &a.method {
            Method::Delegate { label, .. } => format!("委派 {label} CLI"),
            Method::Direct => "直接写入".to_owned(),
        };
        out.push_str(&format!(
            "  {}  {}  [{tag}]\n",
            bold(a.client.label),
            paths.abbreviate(&a.file)
        ));
        for c in &a.changes {
            out.push_str(&format!("    {}  {}\n", c.op.label(), c.server));
        }

        match &a.method {
            // Delegation previews commands, not a diff: the resulting file is the
            // client CLI's to decide and guessing at it would be fiction.
            Method::Delegate { .. } => {
                let steps: Vec<&Step> = a.changes.iter().flat_map(|c| &c.steps).collect();
                if steps.is_empty() {
                    out.push_str("    （无需执行任何命令）\n");
                } else {
                    out.push_str("    将执行的命令:\n");
                    for s in steps {
                        let note = if s.tolerate_failure {
                            "    # 条目不存在时会失败，可忽略"
                        } else {
                            ""
                        };
                        out.push_str(&format!("      $ {}{note}\n", s.display()));
                    }
                }
            }
            Method::Direct => {
                let d = crate::diff::unified(&a.before, &a.after, &paths.abbreviate(&a.file));
                if d.is_empty() {
                    out.push_str("    （文件内容无变化）\n");
                } else {
                    let secrets: Vec<&str> = a
                        .changes
                        .iter()
                        .flat_map(|c| c.secrets.iter().map(String::as_str))
                        .collect();
                    let (d, masked) = mask_secrets(&d, &secrets);
                    out.push_str("    将产生的改动:\n");
                    for line in d.lines() {
                        out.push_str(&format!("      {}\n", paint(line, color)));
                    }
                    if masked {
                        out.push_str(&format!(
                            "    （{MASK} 是显示时遮蔽的凭据值，不是被改写的内容；\
                             除这些位置外，预览与将写入的字节逐字相同）\n"
                        ));
                    }
                }
            }
        }
        out.push('\n');
    }

    out.push_str(&render_skills(plan, paths, &bold));

    // Last thing before the confirmation prompt, because it is the one item here
    // that stays actionable after the write succeeds.
    out.push_str(&credential_warning(plan, paths, &bold));

    if !plan.skips.is_empty() {
        out.push_str(&format!("{}\n", bold("已跳过")));
        for s in &plan.skips {
            out.push_str(&format!(
                "  {} ({})：{}\n",
                s.client.label,
                s.scope.as_str(),
                s.reason
            ));
        }
        out.push('\n');
    }
    out
}

/// The skill half of the preview, grouped by directory.
///
/// A summary rather than a diff: the unit of change is a whole directory, and
/// showing 105 `+` lines would bury the one thing worth reading — how much is
/// about to be written into the user's home, and whether anything is being
/// refused.
fn render_skills(plan: &Plan, paths: &Paths, bold: &dyn Fn(&str) -> String) -> String {
    if plan.skill_actions.is_empty() {
        return String::new();
    }

    let mut out = String::new();
    let mut current: Option<&Utf8Path> = None;
    for action in &plan.skill_actions {
        if current != Some(action.dir.as_path()) {
            out.push_str(&format!(
                "  {}  {}  [技能目录]\n",
                bold(action.client.label),
                paths.abbreviate(&action.dir)
            ));
            current = Some(action.dir.as_path());
        }

        let size = if action.skill.bytes > 0 {
            format!(
                " ({} 文件, {})",
                action.skill.files,
                human_bytes(action.skill.bytes)
            )
        } else {
            format!(" ({} 文件)", action.skill.files)
        };
        out.push_str(&format!(
            "    {}  {}{size}  {} 引擎提供\n",
            action.op.label(),
            action.skill.name,
            action.engine
        ));
        if let Some(note) = action.op.note() {
            out.push_str(&format!("      {note}\n"));
        }
    }
    out.push('\n');
    out
}

fn human_bytes(bytes: usize) -> String {
    const UNITS: [&str; 4] = ["B", "KB", "MB", "GB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit + 1 < UNITS.len() {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

/// Stands in for a credential value in the preview.
///
/// Chosen to be obviously not a value: it has to read as "hidden here", never as
/// "this is what will be written".
const MASK: &str = "‹凭据已遮蔽›";

/// Replace each secret's *quoted* occurrence in `text`, returning whether any
/// substitution happened.
///
/// The preview exists so a user can check the structural change before agreeing
/// to it, and the one thing they never need to read back is the secret's value —
/// while `--dry-run` in CI would otherwise copy it straight into a build log.
/// So the guarantee weakens from "the previewed bytes are the written bytes" to
/// "…except at the marked positions", which is still checkable.
///
/// Matching includes the surrounding quotes so a pathologically short value
/// cannot shred the rest of the diff: both JSON and TOML render these as quoted
/// strings, and `"1"` is far rarer than a bare `1`.
fn mask_secrets(text: &str, secrets: &[&str]) -> (String, bool) {
    let mut out = text.to_owned();
    let mut masked = false;
    for s in secrets {
        let quoted = format!("\"{s}\"");
        if out.contains(&quoted) {
            out = out.replace(&quoted, &format!("\"{MASK}\""));
            masked = true;
        }
    }
    (out, masked)
}

/// The note printed when an entry we are rewriting held an `Authorization`
/// header.
///
/// Deleting the token is the easy half. The half that matters is that a
/// project-scope file is normally committed, so by the time we see the token it
/// is in the repository's history — where deleting it from the working tree does
/// nothing. Saying "removed" and stopping there would leave the user believing a
/// leaked credential had been dealt with.
fn credential_warning(plan: &Plan, paths: &Paths, bold: &dyn Fn(&str) -> String) -> String {
    let hits: Vec<(&Action, &Change)> = plan
        .actions
        .iter()
        .flat_map(|a| a.changes.iter().map(move |c| (a, c)))
        .filter(|(_, c)| c.stripped_credentials)
        .collect();
    if hits.is_empty() {
        return String::new();
    }

    let mut out = format!("{}\n", bold("⚠ 凭据"));
    for (a, c) in &hits {
        // Only the direct path actually removes it: under --delegate the file is
        // written by the client's own CLI, and we neither control nor can
        // predict what it keeps. Claiming a removal we did not perform would be
        // the worst possible thing to be wrong about here.
        let what = match a.method {
            Method::Direct => "条目里的 Authorization header 将被移除",
            Method::Delegate { .. } => {
                "条目里有 Authorization header；委派路径由客户端 CLI 写入，vibrev 不会移除它，请手动删除"
            }
        };
        out.push_str(&format!(
            "  {} 的 {} —— {what}\n",
            paths.abbreviate(&a.file),
            c.server
        ));
    }

    if plan.scope.version_controlled() {
        out.push_str("\n  该作用域的文件会提交进 git。从工作区删掉不等于没泄漏：\n");
        out.push_str("  只要提交过一次，凭据就留在提交历史里，也大概率已经推到远端。\n");
        out.push_str("\n  建议按顺序做完这三步：\n");
        out.push_str(&format!(
            "    1. 确认是否已经提交过：git log --oneline -- {}\n",
            hits.first()
                .map_or(".", |(a, _)| a.file.file_name().unwrap_or("."))
        ));
        out.push_str("    2. 运行 vibrev token rotate 作废并重签已泄漏的 token。\n");
        out.push_str("       删除工作区里的字符串不会让它失效；提交历史里的那份仍然有效。\n");
        out.push_str("    3. 备份副本里仍有原值（见下方备份路径），确认无需回滚后删掉它\n");
    }
    out.push('\n');
    out
}

fn paint(line: &str, color: bool) -> String {
    if !color {
        return line.to_owned();
    }
    // `---`/`+++` are headers, not content; colouring them as changes would
    // suggest the whole file was replaced.
    if line.starts_with("+++") || line.starts_with("---") || line.starts_with("@@") {
        return line.to_owned();
    }
    match line.chars().next() {
        Some('+') => format!("{}", line.if_supports_color(Stream::Stdout, |t| t.green())),
        Some('-') => format!("{}", line.if_supports_color(Stream::Stdout, |t| t.red())),
        _ => line.to_owned(),
    }
}

/// A y/N prompt, only where one can be answered.
///
/// Non-interactive callers must never block here, so a pipe is an error telling
/// the user which flag they wanted rather than a hang or a silent write.
fn confirm() -> Result<bool> {
    if !std::io::stdin().is_terminal() {
        bail!("非交互式环境下不会自动写入；确认后加 --yes，或先用 --dry-run 预览");
    }
    eprint!("继续? [y/N] ");
    use std::io::Write;
    let _ = std::io::stderr().flush();

    let mut answer = String::new();
    std::io::stdin()
        .read_line(&mut answer)
        .context("读取确认输入失败")?;
    Ok(matches!(
        answer.trim().to_ascii_lowercase().as_str(),
        "y" | "yes"
    ))
}

// ------------------------------------------------------------------- apply ---

fn apply(plan: &Plan, paths: &Paths) -> Result<Vec<Backup>> {
    // Skills first. They are the reversible half — a skill directory can be
    // re-exported from the binary at any time, while a client config is the
    // user's own file. If the run is going to fail, failing before touching the
    // irreplaceable thing is the better order.
    for action in &plan.skill_actions {
        if action.op.writes() {
            apply_skill(action, paths)?;
        }
    }

    let mut backups = Vec::new();
    for a in &plan.actions {
        if !a.writes() {
            backups.push(Backup::NotNeeded);
            continue;
        }
        // Held across backup *and* write, so a concurrent `vibrev` cannot slip a
        // write in between and end up recorded in neither `.bak` nor the file.
        let _lock = atomic::lock(&a.file, paths)?;
        // The backup must not land inside a repository: it is a verbatim copy of
        // the file we may just have stripped a credential out of.
        let backup = atomic::backup(&a.file, a.scope.version_controlled(), paths)?;

        match &a.method {
            Method::Direct => atomic::write(&a.file, &a.after)?,
            Method::Delegate { bin, .. } => {
                for step in a.changes.iter().flat_map(|c| &c.steps) {
                    run_step(bin, step)?;
                }
            }
        }
        backups.push(backup);
    }
    Ok(backups)
}

/// Install or remove one skill directory.
///
/// The replacement is staged and then renamed, never written in place: a client
/// that reads the directory while an unpack is halfway through would see a skill
/// with half its files, and there is no way for it to tell that apart from a
/// skill that genuinely has half those files.
///
/// The staging directory is a **sibling of the target**, not `/tmp`. `rename`
/// does not cross filesystems, and `~` on a separate mount is ordinary.
fn apply_skill(action: &SkillAction, paths: &Paths) -> Result<()> {
    let target = action.target();
    // The lock covers the whole swap, so a concurrent `vibrev` cannot rename its
    // own staging directory into place between our two renames.
    let _lock = atomic::lock(&target, paths)?;

    if action.op == SkillOp::Removed {
        // Re-checked under the lock: the plan was built before it was held, and
        // deleting a tree in someone's home on stale evidence is not something
        // to be casual about.
        match skill::Marker::read(&target) {
            Some(m) if m.engine == action.engine => {}
            _ => bail!(
                "{target} 已不再带有 {} 引擎的 {} 标记，拒绝删除",
                action.engine,
                skill::MARKER
            ),
        }
        return std::fs::remove_dir_all(&target).with_context(|| format!("删除 {target} 失败"));
    }

    let Some(source) = &action.source else {
        bail!("{} 缺少导出来源，无法安装", action.skill.name)
    };

    std::fs::create_dir_all(&action.dir).with_context(|| format!("创建 {} 失败", action.dir))?;
    let staging = tempfile::Builder::new()
        .prefix(".vibrev-skill-")
        .tempdir_in(action.dir.as_std_path())
        .with_context(|| format!("在 {} 下创建暂存目录失败", action.dir))?;
    let staging_path = Utf8PathBuf::from_path_buf(staging.path().to_path_buf())
        .map_err(|p| anyhow::anyhow!("暂存目录不是有效的 UTF-8 路径: {}", p.display()))?;

    let exported = skill::export(source.engine, &source.located, &action.skill, &staging_path)?;
    skill::write_marker(&exported, action.engine, &action.skill)?;

    // POSIX has no atomic directory exchange, so this is the two-step: move the
    // old one aside, move the new one in, and put the old one back if the second
    // rename fails. The window where neither is at `target` is one syscall wide.
    let aside = staging_path.join(".previous");
    let displaced = target.exists();
    if displaced {
        std::fs::rename(&target, &aside).with_context(|| format!("移开原有的 {target} 失败"))?;
    }

    if let Err(e) = std::fs::rename(&exported, &target) {
        if displaced {
            // Best effort, and the only thing left to try: if this also fails
            // the error below still names both paths, so the old copy is
            // findable rather than lost.
            let _ = std::fs::rename(&aside, &target);
        }
        return Err(e).with_context(|| format!("将 {exported} 移动到 {target} 失败"));
    }

    // `staging` drops here and takes `.previous` with it.
    Ok(())
}

fn run_step(bin: &Utf8PathBuf, step: &Step) -> Result<()> {
    // Spawned from argv directly — no shell, so nothing in an engine path is ever
    // word-split or glob-expanded.
    let out = std::process::Command::new(bin.as_std_path())
        .args(&step.argv[1..])
        .output()
        .with_context(|| format!("执行 {} 失败", step.display()))?;

    if out.status.success() || step.tolerate_failure {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&out.stderr);
    let stdout = String::from_utf8_lossy(&out.stdout);
    let detail: Vec<&str> = [stderr.trim(), stdout.trim()]
        .into_iter()
        .filter(|s| !s.is_empty())
        .collect();
    bail!(
        "{} 失败（退出码 {}）{}{}",
        step.display(),
        out.status.code().unwrap_or(-1),
        if detail.is_empty() { "" } else { ": " },
        detail.join(" / ")
    )
}

// -------------------------------------------------------------------- json ---

impl Plan {
    fn to_json(&self, dry_run: bool) -> Value {
        json!({
            "ok": true,
            "command": self.mode.verb(self.kind),
            "scope": self.scope.as_str(),
            "dryRun": dry_run,
            "skills": self.skill_actions.iter().map(|a| {
                let mut o = serde_json::Map::new();
                o.insert("client".into(), a.client.id.into());
                o.insert("scope".into(), a.scope.as_str().into());
                o.insert("engine".into(), a.engine.into());
                o.insert("skill".into(), a.skill.name.as_str().into());
                o.insert("dir".into(), a.target().as_str().into());
                o.insert("op".into(), a.op.as_str().into());
                o.insert("files".into(), a.skill.files.into());
                if a.skill.bytes > 0 {
                    o.insert("bytes".into(), a.skill.bytes.into());
                }
                if !a.skill.fingerprint.is_empty() {
                    o.insert("fingerprint".into(), a.skill.fingerprint.as_str().into());
                }
                // Only where something was refused: a machine driving this needs
                // to notice that a directory was left alone on purpose.
                if let Some(note) = a.op.note() {
                    o.insert("note".into(), note.into());
                }
                Value::Object(o)
            }).collect::<Vec<_>>(),
            "actions": self.actions.iter().map(|a| json!({
                "client": a.client.id,
                "scope": a.scope.as_str(),
                "file": a.file.as_str(),
                "method": match a.method {
                    Method::Delegate { .. } => "delegate",
                    Method::Direct => "direct",
                },
                "changes": a.changes.iter().map(|c| {
                    let mut o = serde_json::Map::new();
                    o.insert("server".into(), c.server.as_str().into());
                    o.insert("engine".into(), c.engine.into());
                    o.insert("op".into(), c.op.as_str().into());
                    // Only emitted when true: a machine reading this needs to
                    // notice a leaked credential, and a field that is `false` on
                    // every normal run is one nobody looks at.
                    if c.stripped_credentials {
                        o.insert("strippedCredentials".into(), true.into());
                        o.insert("rotateRequired".into(), a.scope.version_controlled().into());
                    }
                    if let Some(spec) = &c.spec {
                        o.insert("command".into(), spec.command.as_str().into());
                        o.insert("args".into(), json!(spec.args));
                    }
                    if !c.steps.is_empty() {
                        o.insert("commands".into(), json!(
                            c.steps.iter().map(|s| json!(s.argv)).collect::<Vec<_>>()
                        ));
                    }
                    Value::Object(o)
                }).collect::<Vec<_>>(),
            })).collect::<Vec<_>>(),
            "skipped": self.skips.iter().map(|s| json!({
                "client": s.client.id,
                "scope": s.scope.as_str(),
                "reason": s.reason,
            })).collect::<Vec<_>>(),
        })
    }
}

// -------------------------------------------------------------------- list ---

/// `vibrev list` — every `vibrev-*` entry, in every client, in both scopes.
///
/// Reads only. A file that fails to parse is reported as such rather than
/// aborting: unlike a write, one broken config does not endanger the others.
pub fn list(paths: &Paths, json: bool) -> ! {
    let env = match Env::resolve() {
        Ok(e) => e,
        Err(e) => crate::ui::fail(json, "config", &format!("{e:#}"), &[]),
    };

    struct Row {
        client: &'static Client,
        scope: Scope,
        file: Utf8PathBuf,
        entries: Vec<mcpfile::Entry>,
        error: Option<String>,
    }

    let mut rows = Vec::new();
    for c in client::CLIENTS {
        for scope in Scope::ALL {
            let Some(file) = c.file(scope, &env) else {
                continue;
            };
            if !file.exists() {
                continue;
            }
            let (entries, error) = match mcpfile::read(&file, c.format) {
                Ok((_, doc)) => (doc.ours(c), None),
                Err(e) => (Vec::new(), Some(format!("{e:#}"))),
            };
            if entries.is_empty() && error.is_none() {
                continue;
            }
            rows.push(Row {
                client: c,
                scope,
                file,
                entries,
                error,
            });
        }
    }

    if json {
        let doc = json!({
            "ok": true,
            "servers": rows.iter().flat_map(|r| {
                r.entries.iter().map(|e| json!({
                    "server": e.name,
                    "client": r.client.id,
                    "scope": r.scope.as_str(),
                    "file": r.file.as_str(),
                    "command": e.command,
                    "args": e.args,
                })).collect::<Vec<_>>()
            }).collect::<Vec<_>>(),
            "errors": rows.iter().filter_map(|r| r.error.as_ref().map(|e| json!({
                "client": r.client.id,
                "scope": r.scope.as_str(),
                "file": r.file.as_str(),
                "error": e,
            }))).collect::<Vec<_>>(),
        });
        println!("{}", crate::pretty(&doc));
        std::process::exit(0)
    }

    if rows.is_empty() {
        println!("还没有把任何引擎注册到 MCP 客户端。运行 vibrev install --all 试试。");
        std::process::exit(0)
    }

    use comfy_table::{Cell, ContentArrangement, Table, presets::NOTHING};
    let mut table = Table::new();
    table
        .load_preset(NOTHING)
        .set_content_arrangement(ContentArrangement::Disabled);
    table.set_header(vec!["SERVER", "客户端", "作用域", "命令", "文件"]);
    for r in &rows {
        for e in &r.entries {
            let mut cmd = e
                .command
                .clone()
                .unwrap_or_else(|| "(无 command)".to_owned());
            if !e.args.is_empty() {
                cmd.push(' ');
                cmd.push_str(&e.args.join(" "));
            }
            table.add_row(vec![
                Cell::new(&e.name),
                Cell::new(r.client.label),
                Cell::new(r.scope.as_str()),
                Cell::new(cmd),
                Cell::new(paths.abbreviate(&r.file)),
            ]);
        }
    }
    for column in table.column_iter_mut() {
        column.set_padding((0, 2));
    }
    println!(
        "{}",
        table
            .to_string()
            .lines()
            .map(str::trim_end)
            .collect::<Vec<_>>()
            .join("\n")
    );

    for r in rows.iter().filter(|r| r.error.is_some()) {
        eprintln!(
            "警告：无法解析 {}：{}",
            paths.abbreviate(&r.file),
            r.error.as_deref().unwrap_or_default()
        );
    }
    std::process::exit(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::scratch;
    use camino::Utf8Path;

    /// A fake home with the four client files staged as `(relative path, content)`.
    fn fixture(tag: &str, files: &[(&str, &str)]) -> (Env, Paths, Utf8PathBuf) {
        let root = scratch(tag);
        let home = root.join("home");
        let cwd = root.join("proj");
        std::fs::create_dir_all(&home).unwrap();
        std::fs::create_dir_all(&cwd).unwrap();
        for (rel, body) in files {
            let p = home.join(rel);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(&p, body).unwrap();
        }
        let env = Env {
            home: home.clone(),
            app_config: home.join(".config"),
            cwd,
        };
        let paths = Paths {
            root: root.join("vibrev"),
            home: Some(home),
        };
        (env, paths, root)
    }

    /// A resolved engine to feed `build`, with no binary behind it.
    ///
    /// `located: None` means the skill half finds nothing to export, which is
    /// what the server-side tests want; the skill tests below supply a stub.
    fn spec(engine: &'static str, command: &str, args: &[&str]) -> Resolved {
        Resolved {
            engine: engine::by_id(engine).expect("test engines come from the registry"),
            spec: ServerSpec {
                name: client::server_name(engine),
                engine,
                command: command.to_owned(),
                args: args.iter().map(|s| (*s).to_owned()).collect(),
            },
            located: None,
        }
    }

    fn opts(kind: Kind, scope: Scope) -> Options {
        Options {
            kind,
            engines: vec![],
            all: true,
            clients: vec![],
            scope,
            dry_run: false,
            yes: true,
            delegate: false,
            // These tests are about the MCP entry; the skill half has its own.
            skills: SkillMode::Without,
        }
    }

    #[test]
    fn direct_write_produces_the_previewed_bytes() {
        let (env, paths, _root) = fixture(
            "install-direct",
            &[(".cursor/mcp.json", "{\n  \"mcpServers\": {}\n}\n")],
        );
        let cursor = client::by_id("cursor").unwrap();
        let specs = vec![spec("jadx", "/opt/rjadx", &["mcp", "--stdio"])];
        let plan = build(
            &opts(Kind::Install, Scope::Global),
            &[cursor],
            &specs,
            &env,
            &paths,
        )
        .unwrap();

        assert_eq!(plan.actions.len(), 1);
        let previewed = plan.actions[0].after.clone();
        assert_eq!(plan.actions[0].changes[0].op, Op::Added);

        apply(&plan, &paths).unwrap();
        let on_disk = std::fs::read_to_string(env.home.join(".cursor/mcp.json")).unwrap();
        assert_eq!(on_disk, previewed, "preview and write must not diverge");
        assert!(on_disk.contains("vibrev-jadx"));
    }

    #[test]
    fn a_second_run_is_an_update_not_a_duplicate() {
        let (env, paths, _root) = fixture("install-idempotent", &[]);
        let cursor = client::by_id("cursor").unwrap();
        let o = opts(Kind::Install, Scope::Global);

        let first = build(
            &o,
            &[cursor],
            &[spec("ida", "/opt/a/ida-headless-mcp", &[])],
            &env,
            &paths,
        )
        .unwrap();
        assert_eq!(first.actions[0].changes[0].op, Op::Added);
        apply(&first, &paths).unwrap();

        // Same input again: nothing to do at all.
        let second = build(
            &o,
            &[cursor],
            &[spec("ida", "/opt/a/ida-headless-mcp", &[])],
            &env,
            &paths,
        )
        .unwrap();
        assert_eq!(second.actions[0].changes[0].op, Op::Unchanged);
        assert!(!second.actions[0].writes());

        // Engine moved: the existing entry is edited where it is.
        let third = build(
            &o,
            &[cursor],
            &[spec("ida", "/opt/b/ida-headless-mcp", &[])],
            &env,
            &paths,
        )
        .unwrap();
        assert_eq!(third.actions[0].changes[0].op, Op::Updated);
        apply(&third, &paths).unwrap();

        let body = std::fs::read_to_string(env.home.join(".cursor/mcp.json")).unwrap();
        assert_eq!(body.matches("vibrev-ida").count(), 1);
        assert!(body.contains("/opt/b/ida-headless-mcp"));
    }

    #[test]
    fn the_first_write_takes_a_backup_and_later_ones_keep_it() {
        let original = "{\n  \"mcpServers\": {}\n}\n";
        let (env, paths, _root) = fixture("install-backup", &[(".cursor/mcp.json", original)]);
        let cursor = client::by_id("cursor").unwrap();
        let o = opts(Kind::Install, Scope::Global);
        let file = env.home.join(".cursor/mcp.json");

        let p1 = build(&o, &[cursor], &[spec("jadx", "/opt/a", &[])], &env, &paths).unwrap();
        assert_eq!(
            apply(&p1, &paths).unwrap()[0],
            Backup::Created(Utf8PathBuf::from(format!("{file}.bak")))
        );

        let p2 = build(&o, &[cursor], &[spec("jadx", "/opt/b", &[])], &env, &paths).unwrap();
        assert!(matches!(apply(&p2, &paths).unwrap()[0], Backup::Kept(_)));

        assert_eq!(
            std::fs::read_to_string(format!("{file}.bak")).unwrap(),
            original,
            ".bak must still be the file as it was before vibrev ever ran"
        );
    }

    #[test]
    fn a_broken_config_aborts_the_whole_plan() {
        let (env, paths, _root) = fixture(
            "install-broken",
            &[(".cursor/mcp.json", "{ \"mcpServers\": { \"a\": ")],
        );
        let cursor = client::by_id("cursor").unwrap();
        let err = build(
            &opts(Kind::Install, Scope::Global),
            &[cursor],
            &[spec("jadx", "/opt/rjadx", &[])],
            &env,
            &paths,
        )
        .unwrap_err();
        assert!(format!("{err:#}").contains("解析"));
        // Untouched: no rebuild, no truncation, no `.bak` covering for it.
        assert_eq!(
            std::fs::read_to_string(env.home.join(".cursor/mcp.json")).unwrap(),
            "{ \"mcpServers\": { \"a\": "
        );
        assert!(!env.home.join(".cursor/mcp.json.bak").exists());
    }

    #[test]
    fn codex_is_skipped_for_project_scope() {
        let (env, paths, _root) = fixture("install-codex-project", &[]);
        let codex = client::by_id("codex").unwrap();
        let plan = build(
            &opts(Kind::Install, Scope::Project),
            &[codex],
            &[spec("jadx", "/opt/rjadx", &[])],
            &env,
            &paths,
        )
        .unwrap();
        assert!(plan.actions.is_empty());
        assert_eq!(plan.skips.len(), 1);
        assert!(plan.skips[0].reason.contains("没有项目级作用域"));
    }

    #[test]
    fn uninstall_leaves_other_servers_alone() {
        let (env, paths, _root) = fixture(
            "uninstall-keeps",
            &[(
                ".cursor/mcp.json",
                r#"{
  "mcpServers": {
    "keepme": { "command": "npx", "args": ["-y", "x"] },
    "vibrev-jadx": { "command": "/opt/rjadx", "args": ["mcp"] }
  }
}
"#,
            )],
        );
        let cursor = client::by_id("cursor").unwrap();
        let plan = build(
            &opts(Kind::Uninstall, Scope::Global),
            &[cursor],
            &[spec("jadx", "", &[])],
            &env,
            &paths,
        )
        .unwrap();
        assert_eq!(plan.actions[0].changes[0].op, Op::Removed);
        apply(&plan, &paths).unwrap();

        let body = std::fs::read_to_string(env.home.join(".cursor/mcp.json")).unwrap();
        assert!(body.contains("keepme"));
        assert!(!body.contains("vibrev-jadx"));
    }

    #[test]
    fn uninstall_does_not_create_files() {
        let (env, paths, _root) = fixture("uninstall-absent", &[]);
        let cursor = client::by_id("cursor").unwrap();
        let plan = build(
            &opts(Kind::Uninstall, Scope::Global),
            &[cursor],
            &[spec("jadx", "", &[])],
            &env,
            &paths,
        )
        .unwrap();
        assert!(plan.actions.is_empty());
        assert!(!env.home.join(".cursor/mcp.json").exists());
    }

    #[test]
    fn the_preview_distinguishes_commands_from_a_diff() {
        let (env, paths, root) = fixture("install-preview", &[]);
        // A stub `claude` on PATH is what makes the delegate branch reachable in
        // a test; see the integration tests for the full round trip.
        let bin = root.join("bin");
        std::fs::create_dir_all(&bin).unwrap();

        let cursor = client::by_id("cursor").unwrap();
        let plan = build(
            &opts(Kind::Install, Scope::Global),
            &[cursor],
            &[spec("jadx", "/opt/rjadx", &["mcp", "--stdio"])],
            &env,
            &paths,
        )
        .unwrap();
        let text = render(&plan, &paths, &env, false);
        assert!(text.contains("[直接写入]"));
        assert!(text.contains("将产生的改动:"));
        assert!(text.contains("+"));
        assert!(!text.contains("将执行的命令:"));
    }

    #[test]
    fn engines_that_are_not_installed_are_refused_with_guidance() {
        let root = scratch("install-missing-engine");
        let paths = Paths {
            root: root.clone(),
            home: Some(root.clone()),
        };
        let mut o = opts(Kind::Install, Scope::Global);
        o.all = false;
        o.engines = vec!["bn".into()];

        let err = resolve_engines(&o, &Config::default(), &paths).unwrap_err();
        assert!(err.to_string().contains("bn-headless-mcp"));
        // The registry's install guidance rides along as the error's cause.
        let chain: String = err.chain().skip(1).map(|c| c.to_string()).collect();
        assert!(chain.contains("Binary Ninja"));
    }

    #[test]
    fn uninstall_needs_no_engine_binary() {
        let root = scratch("uninstall-no-binary");
        let paths = Paths {
            root: root.clone(),
            home: Some(root.clone()),
        };
        let mut o = opts(Kind::Uninstall, Scope::Global);
        o.all = false;
        o.engines = vec!["bn".into()];

        let specs = resolve_engines(&o, &Config::default(), &paths).unwrap();
        assert_eq!(specs.len(), 1);
        assert_eq!(specs[0].spec.name, "vibrev-bn");
        assert!(
            specs[0].located.is_none(),
            "uninstall must not need to find the binary"
        );
    }

    #[test]
    fn project_scope_writes_next_to_the_project() {
        let (env, paths, _root) = fixture("install-project", &[]);
        let vscode = client::by_id("vscode").unwrap();
        let plan = build(
            &opts(Kind::Install, Scope::Project),
            &[vscode],
            &[spec("jadx", "/opt/rjadx", &["mcp", "--stdio"])],
            &env,
            &paths,
        )
        .unwrap();
        assert_eq!(plan.actions[0].file, env.cwd.join(".vscode/mcp.json"));
        apply(&plan, &paths).unwrap();

        let body = std::fs::read_to_string(env.cwd.join(".vscode/mcp.json")).unwrap();
        // VS Code's key, not Claude's.
        assert!(body.contains("\"servers\""));
        assert!(!body.contains("mcpServers"));
    }

    // ------------------------------------------------------------- skills ---

    /// A fake engine that answers `skills list` and `skills export`.
    ///
    /// `fingerprint` is baked into the script, so "the engine was upgraded" is
    /// modelled by writing a second stub over the first — which is what an
    /// upgrade is from this side of the process boundary.
    #[cfg(unix)]
    fn stub_engine(at: &Utf8Path, fingerprint: &str) {
        use std::os::unix::fs::PermissionsExt;
        let script = format!(
            r#"#!/bin/sh
[ "$1" = "skills" ] || exit 2
case "$2" in
  list)
    printf '%s' '{{"ok":true,"skills":[{{"name":"toyskill","description":"d","files":2,"bytes":24,"fingerprint":"{fingerprint}"}}]}}'
    ;;
  export)
    # argv is: skills export --dir <dir> --skill <name>
    mkdir -p "$4/$6/docs" || exit 1
    printf 'skill {fingerprint}\n' > "$4/$6/SKILL.md"
    printf 'body\n' > "$4/$6/docs/a.md"
    ;;
  *) exit 2 ;;
esac
"#
        );
        if let Some(parent) = at.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(at, script).unwrap();
        std::fs::set_permissions(at, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    #[cfg(unix)]
    fn resolved_stub(bin: &Utf8Path) -> Resolved {
        let eng = engine::by_id("ida").expect("ida is registered");
        Resolved {
            engine: eng,
            spec: ServerSpec::new(eng, bin, &[]),
            located: Some(Located {
                path: bin.to_owned(),
                origin: crate::discover::Origin::Path,
                mcp_args: Vec::new(),
            }),
        }
    }

    #[cfg(unix)]
    fn skill_opts(kind: Kind) -> Options {
        Options {
            skills: SkillMode::Only,
            ..opts(kind, Scope::Global)
        }
    }

    #[cfg(unix)]
    #[test]
    fn a_skill_is_exported_into_the_client_directory() {
        let (env, paths, root) = fixture("skill-install", &[]);
        let bin = root.join("bin/ida-headless-mcp");
        stub_engine(&bin, "v1");
        let claude = client::by_id("claude-code").unwrap();

        let plan = build(
            &skill_opts(Kind::Install),
            &[claude],
            &[resolved_stub(&bin)],
            &env,
            &paths,
        )
        .unwrap();
        assert_eq!(plan.skill_actions.len(), 1);
        assert_eq!(plan.skill_actions[0].op, SkillOp::Added);
        // Skill-only runs leave the MCP entry alone entirely.
        assert!(plan.actions.is_empty());

        apply(&plan, &paths).unwrap();
        let dir = env.home.join(".claude/skills/toyskill");
        assert_eq!(
            std::fs::read_to_string(dir.join("SKILL.md")).unwrap(),
            "skill v1\n"
        );
        assert!(dir.join("docs/a.md").exists());

        let marker = skill::Marker::read(&dir).expect("a marker was written");
        assert_eq!(marker.engine, "ida");
        assert_eq!(marker.fingerprint, "v1");
    }

    #[cfg(unix)]
    #[test]
    fn a_second_run_writes_nothing_and_an_upgrade_replaces_the_content() {
        let (env, paths, root) = fixture("skill-idempotent", &[]);
        let bin = root.join("bin/ida-headless-mcp");
        stub_engine(&bin, "v1");
        let claude = client::by_id("claude-code").unwrap();
        let o = skill_opts(Kind::Install);

        let first = build(&o, &[claude], &[resolved_stub(&bin)], &env, &paths).unwrap();
        apply(&first, &paths).unwrap();

        let second = build(&o, &[claude], &[resolved_stub(&bin)], &env, &paths).unwrap();
        assert_eq!(second.skill_actions[0].op, SkillOp::Unchanged);
        assert!(!second.writes(), "an up-to-date skill is not rewritten");

        // Engine upgraded: same skill name, new content.
        stub_engine(&bin, "v2");
        let third = build(&o, &[claude], &[resolved_stub(&bin)], &env, &paths).unwrap();
        assert_eq!(
            third.skill_actions[0].op,
            SkillOp::Updated {
                from: "v1".to_owned()
            }
        );
        apply(&third, &paths).unwrap();

        let dir = env.home.join(".claude/skills/toyskill");
        assert_eq!(
            std::fs::read_to_string(dir.join("SKILL.md")).unwrap(),
            "skill v2\n"
        );
        // The staging directory is gone, and the displaced copy with it. Scoped
        // to our own prefix rather than "the directory is otherwise empty": the
        // claim is that the swap cleans up after itself, and an unrelated entry
        // appearing beside it would not make that claim false.
        let leftovers: Vec<String> = std::fs::read_dir(env.home.join(".claude/skills"))
            .unwrap()
            .filter_map(Result::ok)
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.starts_with(".vibrev-skill-"))
            .collect();
        assert!(leftovers.is_empty(), "staging left behind: {leftovers:?}");
    }

    #[cfg(unix)]
    #[test]
    fn a_directory_we_did_not_write_is_never_touched() {
        // Not "skill-foreign": `skill::tests::a_directory_without_our_marker_is_foreign`
        // has that one, and a shared tag means a shared — and wiped — directory.
        let (env, paths, root) = fixture("skill-install-foreign", &[]);
        let bin = root.join("bin/ida-headless-mcp");
        stub_engine(&bin, "v1");
        let claude = client::by_id("claude-code").unwrap();

        // Someone else's skill under the name our engine also uses.
        let dir = env.home.join(".claude/skills/toyskill");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("SKILL.md"), "hand written, do not clobber").unwrap();

        let plan = build(
            &skill_opts(Kind::Install),
            &[claude],
            &[resolved_stub(&bin)],
            &env,
            &paths,
        )
        .unwrap();
        assert_eq!(plan.skill_actions[0].op, SkillOp::Foreign);
        assert!(!plan.writes());
        apply(&plan, &paths).unwrap();

        assert_eq!(
            std::fs::read_to_string(dir.join("SKILL.md")).unwrap(),
            "hand written, do not clobber"
        );
        // And an uninstall does not reach it either: removal works off markers,
        // and this directory has none.
        let removal = build(
            &skill_opts(Kind::Uninstall),
            &[claude],
            &[resolved_stub(&bin)],
            &env,
            &paths,
        )
        .unwrap();
        assert!(removal.skill_actions.is_empty());
        assert!(dir.exists());
    }

    #[cfg(unix)]
    #[test]
    fn uninstall_removes_our_skill_and_leaves_other_engines_alone() {
        let (env, paths, root) = fixture("skill-uninstall", &[]);
        let bin = root.join("bin/ida-headless-mcp");
        stub_engine(&bin, "v1");
        let claude = client::by_id("claude-code").unwrap();

        apply(
            &build(
                &skill_opts(Kind::Install),
                &[claude],
                &[resolved_stub(&bin)],
                &env,
                &paths,
            )
            .unwrap(),
            &paths,
        )
        .unwrap();

        // A skill another engine owns, in the same directory.
        let theirs = env.home.join(".claude/skills/bnskill");
        std::fs::create_dir_all(&theirs).unwrap();
        skill::write_marker(
            &theirs,
            "bn",
            &Skill {
                name: "bnskill".to_owned(),
                description: String::new(),
                files: 1,
                bytes: 1,
                fingerprint: "x".to_owned(),
            },
        )
        .unwrap();

        let mut o = skill_opts(Kind::Uninstall);
        o.all = false;
        o.engines = vec!["ida".to_owned()];
        let plan = build(
            &o,
            &[claude],
            &resolve_engines(&o, &Config::default(), &paths).unwrap(),
            &env,
            &paths,
        )
        .unwrap();
        assert_eq!(plan.skill_actions.len(), 1);
        assert_eq!(plan.skill_actions[0].skill.name, "toyskill");
        apply(&plan, &paths).unwrap();

        assert!(!env.home.join(".claude/skills/toyskill").exists());
        assert!(theirs.exists(), "bn's skill is not ida's to remove");
    }

    #[cfg(unix)]
    #[test]
    fn staging_happens_beside_the_target_so_rename_never_crosses_a_filesystem() {
        let (env, paths, root) = fixture("skill-staging", &[]);
        let bin = root.join("bin/ida-headless-mcp");
        stub_engine(&bin, "v1");
        let claude = client::by_id("claude-code").unwrap();
        let plan = build(
            &skill_opts(Kind::Install),
            &[claude],
            &[resolved_stub(&bin)],
            &env,
            &paths,
        )
        .unwrap();

        // The invariant `apply_skill` depends on: staging is a child of the very
        // directory the target lives in, never `/tmp`.
        let action = &plan.skill_actions[0];
        assert_eq!(action.dir, env.home.join(".claude/skills"));
        assert_eq!(action.target(), action.dir.join("toyskill"));
    }

    #[cfg(unix)]
    #[test]
    fn clients_without_a_skill_mechanism_say_why() {
        let (env, paths, root) = fixture("skill-unsupported", &[]);
        let bin = root.join("bin/ida-headless-mcp");
        stub_engine(&bin, "v1");
        let cursor = client::by_id("cursor").unwrap();

        let plan = build(
            &skill_opts(Kind::Install),
            &[cursor],
            &[resolved_stub(&bin)],
            &env,
            &paths,
        )
        .unwrap();
        assert!(plan.skill_actions.is_empty());
        assert_eq!(plan.skips.len(), 1);
        assert!(plan.skips[0].reason.contains(".cursor/rules"));
    }

    #[cfg(unix)]
    #[test]
    fn no_skills_leaves_the_skill_half_out_entirely() {
        let (env, paths, root) = fixture("skill-optout", &[]);
        let bin = root.join("bin/ida-headless-mcp");
        stub_engine(&bin, "v1");
        let claude = client::by_id("claude-code").unwrap();

        let mut o = opts(Kind::Install, Scope::Global);
        o.skills = SkillMode::Without;
        let plan = build(&o, &[claude], &[resolved_stub(&bin)], &env, &paths).unwrap();
        assert!(plan.skill_actions.is_empty());
        assert!(!plan.actions.is_empty(), "the MCP entry is still written");
    }

    #[cfg(unix)]
    #[test]
    fn an_engine_that_does_not_understand_skills_is_not_an_error() {
        let (env, paths, root) = fixture("skill-oldengine", &[]);
        let bin = root.join("bin/ida-headless-mcp");
        // A binary predating the subcommand: clap exits 2 with a usage message.
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::create_dir_all(bin.parent().unwrap()).unwrap();
            std::fs::write(&bin, "#!/bin/sh\necho 'unknown subcommand' >&2\nexit 2\n").unwrap();
            std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let claude = client::by_id("claude-code").unwrap();

        let mut o = opts(Kind::Install, Scope::Global);
        o.skills = SkillMode::With;
        let plan = build(&o, &[claude], &[resolved_stub(&bin)], &env, &paths).unwrap();
        // One stale engine must not take `vibrev install --all` down with it.
        assert!(plan.skill_actions.is_empty());
        assert!(!plan.actions.is_empty());
    }

    #[test]
    fn nothing_is_written_when_the_plan_is_only_a_dry_run() {
        let (env, paths, _root) = fixture("install-dryrun", &[]);
        let cursor = client::by_id("cursor").unwrap();
        let plan = build(
            &opts(Kind::Install, Scope::Global),
            &[cursor],
            &[spec("jadx", "/opt/rjadx", &[])],
            &env,
            &paths,
        )
        .unwrap();
        // `build` is pure; only `apply` touches the disk.
        assert!(!env.home.join(".cursor/mcp.json").exists());
        let _ = render(&plan, &paths, &env, false);
        assert!(!env.home.join(".cursor/mcp.json").exists());
        let _ = Utf8Path::new("");
    }
}
