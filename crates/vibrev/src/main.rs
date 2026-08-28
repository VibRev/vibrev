//! `vibrev` — the installer and dispatcher.
//!
//! Each engine is a complete MCP server carrying its own supervisor and CLI, and
//! this binary is **not on any request path**. It links no engine code; it only
//! answers two questions:
//!
//! * where are the engine binaries (`doctor`, `engine list`)
//! * hand this process over to one of them (`vibrev <engine> <args…>`)
//! * write those binaries into an MCP client's config (`install` / `uninstall`)
//!
//! `install` writes an HTTP entry for engines whose `serve` defaults to a
//! listener (IDA, BN) — the operator starts the process — and a stdio spawn for
//! engines that have no listener (jadx).

mod atomic;
mod client;
mod config;
mod diff;
mod discover;
mod dispatch;
mod engine;
mod install;
mod mcpfile;
mod probe;
mod report;
mod skill;
#[cfg(test)]
mod testutil;
mod token;
mod ui;

use std::ffi::OsString;
use std::time::Duration;

use clap::builder::PossibleValuesParser;
use clap::{Args, CommandFactory, FromArgMatches, Parser, Subcommand};
use owo_colors::{OwoColorize, Stream};
use serde_json::json;

use crate::client::Scope;
use crate::config::Paths;
use crate::discover::Outcome;
use crate::install::{Kind, Options, SkillMode};
use crate::report::{EngineReport, Status};
use crate::ui::fail;

#[derive(Debug, Parser)]
#[command(
    name = "vibrev",
    version,
    about = "VibRev —— 逆向工程 MCP 工具链的安装与派发入口",
    long_about = "VibRev —— 逆向工程 MCP 工具链的安装与派发入口。\n\n\
                  每个引擎都是独立完整的 MCP server，自带 supervisor 与 CLI；\n\
                  vibrev 不链接任何引擎，也不在任何请求路径上，只负责发现与派发。",
    subcommand_required = true,
    arg_required_else_help = true,
    disable_help_subcommand = true
)]
struct Cli {
    /// 结构化输出：成功走 stdout JSON，失败走 stdout {"ok":false,…} 且退出码 1
    #[arg(long, global = true)]
    json: bool,

    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Debug, Subcommand)]
enum Cmd {
    /// 检测引擎与环境
    Doctor(DoctorArgs),

    /// 引擎管理
    Engine {
        #[command(subcommand)]
        cmd: EngineCmd,
    },

    /// 把引擎注册到 MCP 客户端
    Install(InstallArgs),

    /// 从 MCP 客户端注销引擎（不指定引擎则移除全部 vibrev-* 条目）
    Uninstall(InstallArgs),

    /// 列出已配置的 vibrev server 与它们所在的客户端
    List,

    /// 引擎自带的 agent skill（只有 Claude Code 读技能目录）
    Skill {
        #[command(subcommand)]
        cmd: SkillCmd,
    },

    /// HTTP bearer token
    Token {
        #[command(subcommand)]
        cmd: TokenCmd,
    },

    /// `vibrev <engine> <args…>`：原样透传给引擎自己的 CLI
    #[command(external_subcommand)]
    Dispatch(Vec<OsString>),
}

#[derive(Debug, Subcommand)]
enum SkillCmd {
    /// 列出各引擎提供的 skill 与本机安装状态
    List,
    /// 只安装 skill，不改动 MCP 条目
    Install(InstallArgs),
    /// 只移除 vibrev 装的 skill，不改动 MCP 条目
    Uninstall(InstallArgs),
}

#[derive(Debug, Subcommand)]
enum TokenCmd {
    /// 生成新 token 并回写已安装的 HTTP 客户端配置
    Rotate(RotateTokenArgs),
}

#[derive(Debug, Args)]
struct RotateTokenArgs {
    /// 立即失效旧 token。会先列出将因此 401 的配置
    #[arg(long)]
    expire_old: bool,

    /// 确认失效旧 token。没有它时 --expire-old 列出将断开的配置后拒绝
    #[arg(long, short = 'y')]
    yes: bool,
}

#[derive(Debug, Args)]
struct InstallArgs {
    /// 引擎 id，可指定多个
    #[arg(value_name = "ENGINE", value_parser = PossibleValuesParser::new(engine::ids()))]
    engines: Vec<String>,

    /// 处理全部已发现的引擎
    #[arg(long)]
    all: bool,

    /// 目标客户端，可重复指定；默认为全部已检测到的客户端
    #[arg(long = "client", value_name = "NAME", value_parser = PossibleValuesParser::new(client::ids()))]
    clients: Vec<String>,

    /// 写入哪一级配置：global 是本机全部项目，project 是当前目录下的文件
    #[arg(long, default_value = "global", value_parser = PossibleValuesParser::new(["global", "project"]))]
    scope: String,

    /// 只预览，不写入任何文件
    #[arg(long)]
    dry_run: bool,

    /// 跳过确认。预览照常打印
    #[arg(long, short = 'y')]
    yes: bool,

    /// 改由客户端自带的 CLI 写入（claude / codex / code），而不是 vibrev 直接改文件。
    /// 代价：文件交给对方处理，格式与注释可能不被保留 —— 实测 codex mcp add 会抹掉
    /// ~/.codex/config.toml 里 [mcp_servers] 段的全部注释。默认不开启
    #[arg(long)]
    delegate: bool,

    /// 不安装引擎自带的 skill，只写 MCP 条目。
    /// 对 vibrev skill install / uninstall 无意义，那两条命令本来就只动 skill
    #[arg(long)]
    no_skills: bool,
}

impl InstallArgs {
    fn into_options(self, kind: Kind, mode: SkillMode, json: bool) -> Options {
        let scope: Scope = self
            .scope
            .parse()
            .unwrap_or_else(|e: String| fail(json, "usage", &e, &[]));
        if self.no_skills && mode == SkillMode::Only {
            fail(
                json,
                "usage",
                "vibrev skill 只处理 skill，--no-skills 会让它无事可做",
                &[],
            )
        }
        Options {
            kind,
            engines: self.engines,
            all: self.all,
            clients: self.clients,
            scope,
            dry_run: self.dry_run,
            yes: self.yes,
            delegate: self.delegate,
            skills: if self.no_skills {
                SkillMode::Without
            } else {
                mode
            },
        }
    }
}

#[derive(Debug, Subcommand)]
enum EngineCmd {
    /// 列出已发现的引擎与版本
    List(ProbeArgs),
}

#[derive(Debug, Args)]
struct DoctorArgs {
    #[command(flatten)]
    probe: ProbeArgs,
}

#[derive(Debug, Args)]
struct ProbeArgs {
    /// 单个引擎 MCP initialize 握手的超时（秒）
    #[arg(
        long,
        value_name = "SECS",
        default_value = "2",
        env = "VIBREV_PROBE_TIMEOUT"
    )]
    timeout: f64,

    /// 跳过握手，只报告二进制位置（不产生版本号）
    #[arg(long)]
    no_probe: bool,
}

fn main() {
    // Build from the derived tree, then bolt on help text generated from the
    // engine registry so a new engine never means editing a doc string.
    let matches = Cli::command().after_help(after_help()).get_matches();
    let cli = match Cli::from_arg_matches(&matches) {
        Ok(c) => c,
        Err(e) => e.exit(),
    };
    let json = cli.json;

    let paths = match Paths::resolve() {
        Ok(p) => p,
        Err(e) => fail(json, "config", &e.to_string(), &[]),
    };
    let cfg = match config::load(&paths) {
        Ok(c) => c,
        Err(e) => fail(json, "config", &format!("{e:#}"), &[]),
    };

    match cli.cmd {
        // Dispatch stays outside any async runtime: `exec` replaces the process
        // image, and there is nothing to gain from having a reactor alive for it.
        Cmd::Dispatch(argv) => run_dispatch(&argv, &cfg, &paths, json),
        Cmd::Doctor(args) => run_doctor(args.probe, &cfg, &paths, json),
        Cmd::Engine {
            cmd: EngineCmd::List(args),
        } => run_list(args, &cfg, &paths, json),
        Cmd::Install(args) => {
            require_engine_selection(&args, "install", json);
            install::run(
                args.into_options(Kind::Install, SkillMode::With, json),
                &cfg,
                &paths,
                json,
            )
        }
        Cmd::Uninstall(args) => install::run(
            args.into_options(Kind::Uninstall, SkillMode::With, json),
            &cfg,
            &paths,
            json,
        ),
        Cmd::List => install::list(&paths, json),
        Cmd::Skill { cmd } => match cmd {
            SkillCmd::List => skill::list(&cfg, &paths, json),
            SkillCmd::Install(args) => {
                require_engine_selection(&args, "skill install", json);
                install::run(
                    args.into_options(Kind::Install, SkillMode::Only, json),
                    &cfg,
                    &paths,
                    json,
                )
            }
            SkillCmd::Uninstall(args) => install::run(
                args.into_options(Kind::Uninstall, SkillMode::Only, json),
                &cfg,
                &paths,
                json,
            ),
        },
        Cmd::Token {
            cmd: TokenCmd::Rotate(args),
        } => token::run(
            token::RotateOpts {
                expire_old: args.expire_old,
                yes: args.yes,
            },
            &paths,
            json,
        ),
    }
}

/// No engine and no `--all` is almost always a user reaching for an interactive
/// wizard that does not exist yet; say so instead of guessing at what they meant.
///
/// Only installs need this. Uninstall without an engine has an obvious reading —
/// everything we put there — and that is what it does.
fn require_engine_selection(args: &InstallArgs, verb: &str, json: bool) {
    if !args.engines.is_empty() || args.all {
        return;
    }
    fail(
        json,
        "usage",
        &format!("{verb} 需要指定引擎"),
        &[
            format!(
                "  vibrev {verb} <engine>...   # {}",
                engine::ids().join(" / ")
            ),
            format!("  vibrev {verb} --all         # 全部已发现的引擎"),
            String::new(),
            "先运行 vibrev doctor 看看哪些引擎已经就位。".to_owned(),
        ],
    )
}

fn after_help() -> String {
    let mut s = String::from("用法概览:\n");
    s.push_str("  vibrev doctor              检测引擎与环境\n");
    s.push_str("  vibrev engine list         列出已发现的引擎\n");
    s.push_str("  vibrev install <engine>    把引擎写进 MCP 客户端配置\n");
    s.push_str("  vibrev list                列出已配置的 vibrev server\n");
    s.push_str("  vibrev skill list          列出引擎自带的 skill 与安装状态\n");
    s.push_str("  vibrev token rotate        轮换 HTTP token 并回写客户端配置\n");
    s.push_str("  vibrev <engine> <args>     派发到对应引擎的 CLI（参数原样透传）\n\n");

    s.push_str("引擎:\n");
    let width = engine::ENGINES
        .iter()
        .map(|e| e.id.len())
        .max()
        .unwrap_or(4);
    for e in engine::ENGINES {
        s.push_str(&format!(
            "  {:<width$}  {:<18} {}\n",
            e.id,
            e.about,
            e.bin,
            width = width
        ));
    }

    s.push_str("\n客户端 (install / uninstall 的 --client):\n");
    let cw = client::CLIENTS
        .iter()
        .map(|c| c.id.len())
        .max()
        .unwrap_or(6);
    for c in client::CLIENTS {
        s.push_str(&format!("  {:<cw$}  {}\n", c.id, c.label, cw = cw));
    }

    s.push_str("\n示例:\n");
    s.push_str("  vibrev doctor\n");
    s.push_str("  vibrev engine list --json\n");
    s.push_str("  vibrev install --all --dry-run                 # 先看看会改什么\n");
    s.push_str("  vibrev install jadx --client cursor --yes\n");
    s.push_str("  vibrev install --all --scope project --yes     # 写进当前仓库\n");
    s.push_str("  vibrev install ida --no-skills                 # 只写 MCP 条目，不装 skill\n");
    s.push_str("  vibrev skill install ida --yes                 # 引擎升级后单独刷新 skill\n");
    s.push_str("  vibrev uninstall ida\n");
    s.push_str("  vibrev token rotate --expire-old --yes  # 泄漏时立即失效旧 token\n");
    s.push_str(
        "  vibrev ida decompile main --limit 20   # → ida-headless-mcp decompile main --limit 20\n",
    );
    s.push_str(
        "  vibrev jadx --help                     # --help 也透传，看到的是引擎自己的帮助\n",
    );
    s
}

// ---------------------------------------------------------------- dispatch ---

fn run_dispatch(argv: &[OsString], cfg: &config::Config, paths: &Paths, json: bool) -> ! {
    let (head, rest) = argv
        .split_first()
        .expect("clap never yields an empty external subcommand");
    let id = head.to_string_lossy();

    let Some(eng) = engine::by_id(&id) else {
        fail(
            json,
            "unknown-subcommand",
            &format!("未知的子命令或引擎: {id}"),
            &[
                format!("可用引擎: {}", engine::ids().join(" / ")),
                "其余命令见 vibrev --help".to_owned(),
            ],
        )
    };

    match discover::locate(eng, cfg, paths) {
        Outcome::Found(located) => {
            // Returns only on failure; on success this process *is* the engine.
            let e = dispatch::exec(&located, rest);
            fail(
                json,
                "exec",
                &format!("无法执行 {}: {e}", located.path),
                &[],
            )
        }
        Outcome::ConfigBroken { path, reason } => fail(
            json,
            "config",
            &format!(
                "{} 里 [engines.{id}] 指向的 {path} {reason}",
                paths.config_file()
            ),
            &["改掉配置里的 path，或删掉该条让 vibrev 回到自动发现。".to_owned()],
        ),
        Outcome::Missing => fail(
            json,
            "engine-not-found",
            &format!("未找到 {} 引擎的二进制 {}", eng.id, eng.bin),
            &install_detail(eng, paths),
        ),
    }
}

/// The install guidance, framed by where we looked. Being explicit about the four
/// levels turns "not found" into something the user can act on directly.
fn install_detail(eng: &'static engine::Engine, paths: &Paths) -> Vec<String> {
    let mut v = vec![
        String::new(),
        "查找顺序（均未命中）:".to_owned(),
        format!(
            "  1. {} 的 [engines.{}] path",
            paths.abbreviate(&paths.config_file()),
            eng.id
        ),
        format!(
            "  2. {}",
            paths.abbreviate(&paths.engines_dir().join(eng.bin))
        ),
        format!("  3. PATH 中的 {}", eng.bin),
        String::new(),
    ];
    v.extend(eng.install.iter().map(|s| (*s).to_owned()));
    v
}

// ------------------------------------------------------------------ doctor ---

fn run_doctor(args: ProbeArgs, cfg: &config::Config, paths: &Paths, json: bool) -> ! {
    let reports = collect(&args, cfg, paths);

    if json {
        let doc = json!({
            "ok": true,
            "vibrev": env!("CARGO_PKG_VERSION"),
            "home": paths.root.as_str(),
            "config": paths.config_file().as_str(),
            "enginesDir": paths.engines_dir().as_str(),
            "engines": reports.iter().map(|r| r.to_json(true)).collect::<Vec<_>>(),
        });
        println!("{}", pretty(&doc));
        std::process::exit(0)
    }

    let color = ui::color_enabled();
    let refs: Vec<&EngineReport> = reports.iter().collect();

    println!("{}", heading("引擎", color));
    println!("{}", indent(&report::table(&refs, paths, color)));

    print_skill_section(&reports, color);

    println!();
    println!("{}", heading("环境", color));
    let exists = |p: &camino::Utf8Path| if p.exists() { "" } else { " (不存在)" };
    let cfg_file = paths.config_file();
    let eng_dir = paths.engines_dir();
    println!("  vibrev      {}", env!("CARGO_PKG_VERSION"));
    println!(
        "  配置        {}{}",
        paths.abbreviate(&cfg_file),
        exists(&cfg_file)
    );
    println!(
        "  引擎目录    {}{}",
        paths.abbreviate(&eng_dir),
        exists(&eng_dir)
    );
    println!(
        "  握手        {}",
        if args.no_probe {
            "已跳过 (--no-probe)".to_owned()
        } else {
            format!("MCP initialize，超时 {} 秒", args.timeout)
        }
    );

    // Unknown keys in config.toml would otherwise do nothing at all, silently.
    let unknown: Vec<&str> = cfg
        .engines
        .keys()
        .map(String::as_str)
        .filter(|k| engine::by_id(k).is_none())
        .collect();
    if !unknown.is_empty() {
        println!();
        println!(
            "  注意：config.toml 里有无法识别的引擎 [{}]，已忽略（可用: {}）",
            unknown.join(", "),
            engine::ids().join(" / ")
        );
    }

    for r in &reports {
        match r.status() {
            Status::Missing => {
                println!();
                println!("{}", heading(&format!("{} 未安装", r.engine.id), color));
                for line in r.engine.install {
                    println!("{}", indent(line));
                }
            }
            Status::ConfigError => {
                let (path, reason) = r
                    .config_error
                    .as_ref()
                    .expect("ConfigError carries a cause");
                println!();
                println!("{}", heading(&format!("{} 配置有问题", r.engine.id), color));
                println!(
                    "{}",
                    indent(&format!(
                        "[engines.{}] path = \"{path}\" —— {reason}",
                        r.engine.id
                    ))
                );
            }
            _ => {}
        }
    }

    // doctor reports; it does not judge. A machine that needs a verdict should
    // read `vibrev engine list --json`.
    std::process::exit(0)
}

/// The skills the found engines carry, and whether they are on disk.
///
/// Silent when no engine ships any, which is the state for two of the three
/// today — a permanently empty section trains people to skip the whole report.
///
/// A status summary, not an inventory: `vibrev skill list` prints the paths.
fn print_skill_section(reports: &[EngineReport], color: bool) {
    let Ok(env) = client::Env::resolve() else {
        return;
    };

    let mut lines = Vec::new();
    for report in reports {
        let Some(located) = &report.located else {
            continue;
        };
        for offered in skill::offered(report.engine, located) {
            // Only Claude Code reads skills, so there is exactly one place per
            // scope worth reporting; naming the others would be noise.
            let installed: Vec<String> = client::CLIENTS
                .iter()
                .flat_map(|c| client::Scope::ALL.map(move |s| (c, s)))
                .filter_map(|(c, scope)| {
                    let dir = c.skills_dir(scope, &env)?.join(&offered.name);
                    match skill::State::read(&dir, report.engine.id, &offered) {
                        skill::State::Absent => None,
                        state => Some(format!("{} {}: {}", c.id, scope.as_str(), state.as_str())),
                    }
                })
                .collect();
            lines.push(format!(
                "{}  {}  {} 文件  {}",
                report.engine.id,
                offered.name,
                offered.files,
                if installed.is_empty() {
                    "未安装".to_owned()
                } else {
                    installed.join("，")
                }
            ));
        }
    }

    if lines.is_empty() {
        return;
    }
    println!();
    println!("{}", heading("技能", color));
    for line in lines {
        println!("{}", indent(&line));
    }
    println!("{}", indent("（只有 Claude Code 读技能目录）"));
}

// ------------------------------------------------------------- engine list ---

fn run_list(args: ProbeArgs, cfg: &config::Config, paths: &Paths, json: bool) -> ! {
    let reports = collect(&args, cfg, paths);
    let found: Vec<&EngineReport> = reports.iter().filter(|r| r.found()).collect();

    if json {
        let doc = json!({
            "ok": true,
            "engines": found.iter().map(|r| r.to_json(false)).collect::<Vec<_>>(),
        });
        println!("{}", pretty(&doc));
        std::process::exit(0)
    }

    if found.is_empty() {
        println!("没有发现任何引擎。运行 vibrev doctor 查看查找位置与安装指引。");
        std::process::exit(0)
    }
    println!("{}", report::table(&found, paths, ui::color_enabled()));
    std::process::exit(0)
}

// ------------------------------------------------------------------ shared ---

/// Discover all three engines, then probe the ones we found — concurrently, so a
/// wedged engine costs the timeout once rather than once per engine.
fn collect(args: &ProbeArgs, cfg: &config::Config, paths: &Paths) -> Vec<EngineReport> {
    let mut reports: Vec<EngineReport> = discover::locate_all(cfg, paths)
        .into_iter()
        .map(|(e, outcome)| EngineReport::new(e, outcome))
        .collect();

    if args.no_probe {
        return reports;
    }

    let budget = Duration::from_secs_f64(args.timeout.max(0.0));
    let rt = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        // Without a runtime we cannot handshake at all; degrade to "found, not
        // probed" rather than throwing away the discovery results too.
        Err(_) => return reports,
    };

    rt.block_on(async {
        let mut tasks = Vec::new();
        for (idx, r) in reports.iter().enumerate() {
            if let Some(located) = r.located.clone() {
                tasks.push((
                    idx,
                    tokio::spawn(async move { probe::probe(&located, budget).await }),
                ));
            }
        }
        for (idx, task) in tasks {
            let outcome = match task.await {
                Ok(p) => p,
                Err(e) => probe::Probe::Failed(format!("探测任务异常终止：{e}")),
            };
            reports[idx].probe = Some(outcome);
        }
    });

    reports
}

fn pretty(v: &serde_json::Value) -> String {
    serde_json::to_string_pretty(v).unwrap_or_else(|_| v.to_string())
}

fn heading(text: &str, color: bool) -> String {
    if color {
        format!("{}", text.if_supports_color(Stream::Stdout, |t| t.bold()))
    } else {
        text.to_owned()
    }
}

fn indent(block: &str) -> String {
    block
        .lines()
        .map(|l| {
            if l.is_empty() {
                String::new()
            } else {
                format!("  {l}")
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}
