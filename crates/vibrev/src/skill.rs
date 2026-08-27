//! Agent skills — asking an engine what knowledge it ships, and putting it
//! where a client will read it.
//!
//! An engine is a complete MCP server, and some of them also carry a body of
//! reference material a model needs in order to use the tool surface well:
//! `ida-headless-mcp` ships 105 files of IDAPython documentation compiled into
//! the binary. `vibrev` links no engine code, so it does not — and must not —
//! hold a copy. It asks:
//!
//! ```text
//! <engine> skills list --json      → what do you have
//! <engine> skills export --dir …   → write it here
//! ```
//!
//! Two consequences shape everything below.
//!
//! **An engine that does not answer is not an error.** A binary predating the
//! `skills` subcommand exits non-zero with a clap usage message. Treating that as
//! a failure would mean one stale engine breaks `vibrev install --all`, so every
//! way of not answering degrades to "ships no skills".
//!
//! **A directory we did not write is untouchable.** `~/.claude/skills/idapython`
//! is a name a user could have chosen themselves, and ida-pro-mcp's plugin
//! installs one under exactly that name. Removing a directory tree in someone's
//! home is not undoable, so the rule is evidence-based: no [`MARKER`], no touch.

use std::process::Command;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use camino::{Utf8Path, Utf8PathBuf};
use serde::{Deserialize, Serialize};

use crate::discover::Located;
use crate::engine::Engine;

/// Written into every skill directory `vibrev` installs.
///
/// This file *is* the ownership proof. Its absence means the directory came from
/// somewhere else and neither an update nor a removal may proceed.
pub const MARKER: &str = ".vibrev-skill.json";

/// One skill as an engine describes it.
///
/// The engine's type, literally: `vibrev_skills::Skill` is what
/// `skills list --json` serializes and what this parses.
pub use vibrev_skills::Skill;

/// The marker file's contents.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct Marker {
    /// Engine id, so `vibrev uninstall ida` does not remove `bn`'s skill.
    pub engine: String,
    pub name: String,
    pub fingerprint: String,
    pub files: usize,
    /// Which version wrote it. Never read by the code — it is here for the
    /// person who finds this file in their home directory and wonders what put
    /// it there.
    pub installed_by: String,
}

impl Marker {
    fn new(engine: &str, skill: &Skill) -> Self {
        Self {
            engine: engine.to_owned(),
            name: skill.name.clone(),
            fingerprint: skill.fingerprint.clone(),
            files: skill.files,
            installed_by: format!("vibrev {}", env!("CARGO_PKG_VERSION")),
        }
    }

    /// Read the marker out of an installed skill directory.
    ///
    /// `Ok(None)` covers both "no such directory" and "a directory that is not
    /// ours", because the caller treats them the same way: hands off.
    pub fn read(dir: &Utf8Path) -> Option<Self> {
        let raw = std::fs::read_to_string(dir.join(MARKER)).ok()?;
        serde_json::from_str(&raw).ok()
    }
}

/// What an engine ships, or an empty list if it ships nothing.
///
/// Never fails on the engine's behalf — see the module note. The `Result` is for
/// the caller's own errors, not the probe's.
pub fn offered(engine: &'static Engine, located: &Located) -> Vec<Skill> {
    if engine.skills_args.is_empty() {
        return Vec::new();
    }
    let mut cmd = Command::new(located.path.as_std_path());
    cmd.args(engine.skills_args).arg("--json");

    let Some(output) = output_within(cmd, LIST_TIMEOUT) else {
        return Vec::new();
    };
    if !output.status.success() {
        return Vec::new();
    }
    serde_json::from_slice::<vibrev_skills::Listing>(&output.stdout)
        .map(|listing| listing.skills)
        .unwrap_or_default()
}

/// `skills list` answers out of data compiled into the binary, so this is not a
/// work budget — it is the point at which we conclude the process is not going
/// to answer at all.
const LIST_TIMEOUT: Duration = Duration::from_secs(5);

/// Unpacking a couple of megabytes onto disk, with room for a slow filesystem.
const EXPORT_TIMEOUT: Duration = Duration::from_secs(60);

/// Spawn, retrying while the kernel says the binary is still being written.
///
/// `ETXTBSY` means someone holds the file open for writing, and on Linux that
/// includes a *sibling thread's* fork: between `fork` and `exec` the child holds
/// every fd the parent had, so one thread writing an engine binary makes another
/// thread's `exec` of it fail for as long as that window lasts. It is transient
/// by construction, and it is not the engine's answer to anything.
///
/// Retrying matters because of what [`offered`] does with a `None`: it reports
/// that this engine ships no skills. Without this loop a transient `ETXTBSY`
/// reads exactly like an engine too old to know the `skills` subcommand, and
/// `vibrev install` quietly installs nothing. It was measured here first —
/// six occurrences in fifteen runs of this crate's own tests, which write a stub
/// engine and immediately run it — but nothing about it is confined to tests:
/// installing right after building an engine is the same race.
fn spawn_past_a_busy_binary(cmd: &mut Command) -> Option<std::process::Child> {
    const ATTEMPTS: usize = 10;
    const PAUSE: Duration = Duration::from_millis(20);

    for attempt in 0..ATTEMPTS {
        match cmd.spawn() {
            Ok(child) => return Some(child),
            Err(error) if error.kind() == std::io::ErrorKind::ExecutableFileBusy => {
                if attempt + 1 < ATTEMPTS {
                    std::thread::sleep(PAUSE);
                }
            }
            Err(_) => return None,
        }
    }
    None
}

/// Run `cmd` to completion, killing it if it outlives `budget`.
///
/// `Command::output()` waits forever, which is the wrong contract for a binary
/// we merely found on disk: `vibrev install --all --yes` in a CI script would
/// hang on one wedged engine with no one there to interrupt it. The MCP probe
/// already treats an engine as something that might not answer
/// (`VIBREV_PROBE_TIMEOUT`); this is the same rule without a tokio runtime to
/// borrow.
///
/// Polling `try_wait` assumes the child does not fill its pipe buffer and block
/// on the write — a process blocked that way never exits, and we would kill it
/// rather than read it. Both commands here emit well under a pipe's worth: a
/// one-line JSON list, and a handful of progress lines.
fn output_within(mut cmd: Command, budget: Duration) -> Option<std::process::Output> {
    use std::process::Stdio;

    cmd.stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = spawn_past_a_busy_binary(&mut cmd)?;

    let deadline = Instant::now() + budget;
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) if Instant::now() >= deadline => {
                let _ = child.kill();
                // Reap it, so the killed child does not linger as a zombie for
                // the rest of this process's life.
                let _ = child.wait();
                return None;
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(10)),
            Err(_) => return None,
        }
    }
    child.wait_with_output().ok()
}

/// Ask the engine to write `skill` into `into`, which must already exist.
///
/// The engine creates `into/<skill name>/`; this returns that path.
pub fn export(
    engine: &'static Engine,
    located: &Located,
    skill: &Skill,
    into: &Utf8Path,
) -> Result<Utf8PathBuf> {
    let mut args: Vec<&str> = engine.skills_args.to_vec();
    // The registry spells `skills list`; the sibling verb is `export`.
    let last = args
        .last_mut()
        .context("an engine that offers skills has a non-empty skills_args")?;
    *last = "export";

    let mut cmd = Command::new(located.path.as_std_path());
    cmd.args(&args)
        .arg("--dir")
        .arg(into.as_str())
        .arg("--skill")
        .arg(&skill.name);
    let output = output_within(cmd, EXPORT_TIMEOUT).with_context(|| {
        format!(
            "执行 {} skills export 失败或超过 {} 秒未完成",
            located.path,
            EXPORT_TIMEOUT.as_secs()
        )
    })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!(
            "{} skills export {} 失败（退出码 {}）{}",
            located.path,
            skill.name,
            output.status.code().unwrap_or(-1),
            if stderr.trim().is_empty() {
                String::new()
            } else {
                format!(": {}", stderr.trim())
            }
        );
    }

    let root = into.join(&skill.name);
    if !root.is_dir() {
        bail!("{} 报告导出成功，但 {root} 不存在", located.path);
    }
    Ok(root)
}

/// Write the ownership marker into a freshly exported directory.
pub fn write_marker(dir: &Utf8Path, engine: &str, skill: &Skill) -> Result<()> {
    let marker = Marker::new(engine, skill);
    let body = serde_json::to_string_pretty(&marker).context("序列化 skill 标记失败")?;
    std::fs::write(dir.join(MARKER), format!("{body}\n"))
        .with_context(|| format!("写入 {}/{MARKER} 失败", dir))
}

/// How an installed skill directory compares to what the engine offers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum State {
    /// Nothing there.
    Absent,
    /// Ours, and the same fingerprint.
    Current,
    /// Ours, but a different fingerprint — the engine was upgraded.
    Stale { from: String },
    /// Something is there and it is not ours. Never written, never removed.
    Foreign,
    /// Ours, but installed by a different engine under the same skill name.
    /// Also untouchable by this engine's install or uninstall.
    OtherEngine { engine: String },
}

impl State {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Absent => "absent",
            Self::Current => "current",
            Self::Stale { .. } => "stale",
            Self::Foreign => "foreign",
            Self::OtherEngine { .. } => "other-engine",
        }
    }

    /// Classify `dir` against what `engine` offers as `skill`.
    pub fn read(dir: &Utf8Path, engine: &str, skill: &Skill) -> Self {
        if !dir.exists() {
            return Self::Absent;
        }
        let Some(marker) = Marker::read(dir) else {
            return Self::Foreign;
        };
        if marker.engine != engine {
            return Self::OtherEngine {
                engine: marker.engine,
            };
        }
        if marker.fingerprint == skill.fingerprint {
            Self::Current
        } else {
            Self::Stale {
                from: marker.fingerprint,
            }
        }
    }
}

// -------------------------------------------------------------------- list ---

/// `vibrev skill list` — what the engines offer, and what is on disk.
///
/// Reads only, and reports rather than judges: a skill directory that belongs to
/// someone else shows up as `foreign` instead of being hidden, because the whole
/// reason a user runs this is to find out why their skill is not the one they
/// expected.
pub fn list(cfg: &crate::config::Config, paths: &crate::config::Paths, json: bool) -> ! {
    let env = match crate::client::Env::resolve() {
        Ok(e) => e,
        Err(e) => crate::ui::fail(json, "config", &format!("{e:#}"), &[]),
    };

    struct Row {
        engine: &'static str,
        skill: Skill,
        client: &'static str,
        scope: crate::client::Scope,
        dir: Utf8PathBuf,
        state: State,
    }

    let mut offers: Vec<(&'static Engine, Skill)> = Vec::new();
    for (engine, outcome) in crate::discover::locate_all(cfg, paths) {
        let crate::discover::Outcome::Found(located) = outcome else {
            continue;
        };
        offers.extend(offered(engine, &located).into_iter().map(|s| (engine, s)));
    }

    let mut rows = Vec::new();
    for (engine, skill) in &offers {
        for client in crate::client::CLIENTS {
            for scope in crate::client::Scope::ALL {
                let Some(dir) = client.skills_dir(scope, &env) else {
                    continue;
                };
                let target = dir.join(&skill.name);
                let state = State::read(&target, engine.id, skill);
                // Only say something about a place where something exists.
                if state == State::Absent {
                    continue;
                }
                rows.push(Row {
                    engine: engine.id,
                    skill: skill.clone(),
                    client: client.id,
                    scope,
                    dir: target,
                    state,
                });
            }
        }
    }

    if json {
        let doc = serde_json::json!({
            "ok": true,
            "offered": offers.iter().map(|(e, s)| serde_json::json!({
                "engine": e.id,
                "skill": s.name,
                "description": s.description,
                "files": s.files,
                "bytes": s.bytes,
                "fingerprint": s.fingerprint,
            })).collect::<Vec<_>>(),
            "installed": rows.iter().map(|r| serde_json::json!({
                "engine": r.engine,
                "skill": r.skill.name,
                "client": r.client,
                "scope": r.scope.as_str(),
                "dir": r.dir.as_str(),
                "state": r.state.as_str(),
            })).collect::<Vec<_>>(),
        });
        println!("{}", crate::pretty(&doc));
        std::process::exit(0)
    }

    if offers.is_empty() {
        println!("没有发现任何提供 skill 的引擎。运行 vibrev doctor 查看引擎状态。");
    } else {
        println!("引擎提供:");
        for (engine, skill) in &offers {
            println!(
                "  {}  {}  {} 文件  {}",
                engine.id, skill.name, skill.files, skill.fingerprint
            );
        }
    }

    if rows.is_empty() {
        println!();
        println!("本机还没有安装任何 skill。运行 vibrev skill install --all 试试。");
        std::process::exit(0)
    }

    println!();
    println!("本机安装:");
    for r in &rows {
        println!(
            "  {}  {} ({})  {}  {}",
            r.skill.name,
            r.client,
            r.scope.as_str(),
            r.state.as_str(),
            paths.abbreviate(&r.dir)
        );
    }
    std::process::exit(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::scratch;

    fn skill(name: &str, fingerprint: &str) -> Skill {
        Skill {
            name: name.to_owned(),
            description: "a skill".to_owned(),
            files: 3,
            bytes: 99,
            fingerprint: fingerprint.to_owned(),
        }
    }

    #[test]
    fn an_empty_directory_is_absent() {
        let root = scratch("skill-absent");
        assert_eq!(
            State::read(&root.join("nope"), "ida", &skill("x", "aa")),
            State::Absent
        );
    }

    #[test]
    fn a_directory_without_our_marker_is_foreign() {
        let root = scratch("skill-foreign");
        let dir = root.join("idapython");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("SKILL.md"), "someone else's").unwrap();
        assert_eq!(
            State::read(&dir, "ida", &skill("idapython", "aa")),
            State::Foreign
        );
    }

    #[test]
    fn a_marker_we_cannot_parse_is_foreign_rather_than_ours() {
        let root = scratch("skill-badmarker");
        let dir = root.join("idapython");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(MARKER), "{ not json").unwrap();
        // Erring the other way would let a corrupt file authorise a delete.
        assert_eq!(
            State::read(&dir, "ida", &skill("idapython", "aa")),
            State::Foreign
        );
    }

    #[test]
    fn a_matching_fingerprint_is_current_and_a_different_one_is_stale() {
        let root = scratch("skill-fingerprint");
        let dir = root.join("idapython");
        std::fs::create_dir_all(&dir).unwrap();
        write_marker(&dir, "ida", &skill("idapython", "aa")).unwrap();

        assert_eq!(
            State::read(&dir, "ida", &skill("idapython", "aa")),
            State::Current
        );
        assert_eq!(
            State::read(&dir, "ida", &skill("idapython", "bb")),
            State::Stale {
                from: "aa".to_owned()
            }
        );
    }

    #[test]
    fn one_engine_does_not_own_anothers_directory() {
        let root = scratch("skill-otherengine");
        let dir = root.join("shared");
        std::fs::create_dir_all(&dir).unwrap();
        write_marker(&dir, "bn", &skill("shared", "aa")).unwrap();
        assert_eq!(
            State::read(&dir, "ida", &skill("shared", "aa")),
            State::OtherEngine {
                engine: "bn".to_owned()
            }
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_wedged_engine_is_killed_rather_than_waited_on_forever() {
        let root = scratch("skill-timeout");
        let bin = root.join("hang");
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::write(&bin, "#!/bin/sh\nsleep 30\n").unwrap();
            std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
        }

        let started = Instant::now();
        let out = output_within(Command::new(bin.as_std_path()), Duration::from_millis(200));
        assert!(out.is_none(), "a child that never exits yields nothing");
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "the budget was not enforced: waited {:?}",
            started.elapsed()
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_prompt_engine_is_not_cut_off() {
        let root = scratch("skill-notimeout");
        let bin = root.join("quick");
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::write(&bin, "#!/bin/sh\nprintf 'hi'\n").unwrap();
            std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
        }

        let out = output_within(Command::new(bin.as_std_path()), Duration::from_secs(5))
            .expect("a fast child is waited for, not killed");
        assert!(out.status.success());
        assert_eq!(out.stdout, b"hi");
    }

    #[test]
    fn the_marker_round_trips() {
        let root = scratch("skill-marker-roundtrip");
        std::fs::create_dir_all(&root).unwrap();
        write_marker(&root, "ida", &skill("idapython", "deadbeef")).unwrap();
        let read = Marker::read(&root).expect("the marker we just wrote");
        assert_eq!(read.engine, "ida");
        assert_eq!(read.fingerprint, "deadbeef");
        assert_eq!(read.files, 3);
        assert!(read.installed_by.starts_with("vibrev "));
    }
}
