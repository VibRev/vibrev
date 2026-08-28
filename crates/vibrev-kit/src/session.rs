//! The subject an engine's tools operate on.
//!
//! Every VibRev engine is stateful in the same way and for the same reason:
//! `decompile` does not carry a binary, it reads *the open one*. IDA calls that
//! the open database, JADX will call it the loaded APK/DEX, Binary Ninja the
//! current `BinaryView`. Three engines, one shape — and, left to each engine,
//! three flag names, three help strings, three "you forgot to say which"
//! messages, and three subtly different readiness waits.
//!
//! What is shared is *not* the lifecycle. Compare the two ways IDA already
//! names this thing:
//!
//! * `--idb <path>` — the CLI process **creates** the session, owns it, and
//!   tears it down when the one call is done. The value is an *input*.
//! * `database=<session_id>` — the caller **borrows** a session some supervisor
//!   created. The value is a *handle* into someone else's table.
//!
//! Those are different lifetimes and this module deliberately does not pretend
//! otherwise. What they have in common is the only thing a derived CLI needs:
//! both are *the one value a tool call cannot get from its own schema*. So what
//! is modelled here is the **slot**, and whether an engine reads it as a path or
//! as a handle is the engine's business. IDA opens a path; nothing here would
//! have to change for an engine that attaches to a running session instead.
//!
//! The slot has a schema-side name too ([`SessionSpec::selector`]): the property
//! some MCP faces make explicit — `database`, injected into every routed tool by
//! `ida-headless-mcp`'s supervisor. The derived CLI removes it, because a
//! one-shot process has exactly one session and asking the user to name it would
//! be asking for something only the server knows. Removing it *by derivation* is
//! the point: the day that injection moves, a `--database` flag would otherwise
//! appear next to `--idb` with nothing to say which one wins.

use std::fmt;
use std::future::Future;
use std::time::{Duration, Instant};

use clap::{Arg, ArgAction, ArgMatches};

/// Arg id for the session flag. Underscore-prefixed so it cannot collide with a
/// schema property name, which is what every derived `Arg` is keyed on.
pub const SESSION_ARG: &str = "__vibrev_session";
/// Arg id for the readiness opt-out.
pub const NO_WAIT_ARG: &str = "__vibrev_no_wait";

/// How an engine declares the thing its tools are *about*.
///
/// Declared once per engine, next to the command tree, and consumed by
/// [`EngineCli::with_session`](crate::cli::EngineCli::with_session).
#[derive(Debug, Clone, Copy)]
pub struct SessionSpec {
    /// The MCP schema property that names a session explicitly, on the faces
    /// that require one (`"database"` for IDA's supervisor). The derived CLI
    /// registers no flag for it and therefore never sends it.
    ///
    /// `None` for an engine whose sessions are never named in a schema.
    pub selector: Option<&'static str>,
    /// Long flag, without dashes: `"idb"` becomes `--idb`.
    pub flag: &'static str,
    /// Value placeholder in `--help`.
    pub value_name: &'static str,
    pub help: &'static str,
    /// What to tell the user when the flag is absent.
    ///
    /// Declared here rather than typed at the call site so the message cannot
    /// diverge from the flag it is about — the same reason `title` moved onto
    /// the tool attribute.
    pub missing: &'static str,
    /// Readiness gate. `None` means this engine's sessions are usable the
    /// moment they open.
    pub ready: Option<ReadySpec>,
}

/// When "open" does not yet mean "answers correctly".
///
/// IDA's `open_idb` returns before auto-analysis settles, and a tool read in
/// that window answers with a well-formed, smaller, *wrong* number. The MCP face
/// covers this by making such tools publish `analysis_coverage` — the answer
/// describes its own incompleteness. That is a *reporting* contract and it is
/// not what this is.
///
/// This is a *scheduling* one: a one-shot CLI has no "check back later", so it
/// waits instead of labelling. The two are complements, and neither subsumes the
/// other — `analysis_coverage` cannot prevent the wrong answer and only exists
/// on the tools that owe it, while waiting cannot label anything and cannot help
/// when analysis never converges at all. Which is exactly why the wait has a
/// ceiling, an opt-out, and a *visible* outcome when it gives up.
///
/// # Known limit: this models readiness as a property of the session
///
/// The wait runs once, after opening, on the assumption that a session which has
/// settled stays settled. That is right for IDA, and `Option` already covers the
/// engine whose open is synchronous — Binary Ninja's
/// `load_with_options(update_analysis_and_wait = true)` does not return until it
/// has converged, so it declares `ready: None` and waits for nothing.
///
/// It is *not* the whole story for that engine: under CPU starvation its
/// non-determinism returns, so it settles again before each read. Readiness there
/// is a per-read property, not a per-session one, and nothing here expresses
/// that. Necessary but not sufficient, which is worth knowing before the next
/// engine assumes opening buys it permanently.
#[derive(Debug, Clone, Copy)]
pub struct ReadySpec {
    /// Long flag, without dashes, that skips the wait.
    pub skip_flag: &'static str,
    pub skip_help: &'static str,
    /// Ceiling on the whole wait.
    pub timeout: Duration,
    /// Interval between probes.
    pub poll: Duration,
    /// Printed when the ceiling is reached. Say what the results may now be.
    pub timed_out: &'static str,
    /// Printed when the engine cannot tell whether it is ready.
    pub unknown: &'static str,
}

/// What the command line said about the session.
#[derive(Debug, Clone)]
pub struct SessionArgs {
    /// The value of the session flag, verbatim.
    pub target: String,
    /// Whether to run the readiness wait. Always `false` for an engine that
    /// declared no [`ReadySpec`].
    pub wait_for_ready: bool,
}

/// The session flag was not given.
///
/// Carries [`SessionSpec::missing`] so the caller prints the declared prose
/// rather than inventing its own.
#[derive(Debug, Clone)]
pub struct MissingSession {
    pub flag: &'static str,
    pub message: &'static str,
}

impl fmt::Display for MissingSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "need --{} — {}", self.flag, self.message)
    }
}

impl std::error::Error for MissingSession {}

impl SessionSpec {
    /// The globals to hang off the tool subtree.
    ///
    /// Global rather than per-leaf so `<engine> tool --idb X decompile 0x1000`
    /// and `<engine> tool decompile --idb X 0x1000` both work; clap refuses
    /// "global and required" together, which is why the requirement is enforced
    /// by [`read`](Self::read) instead.
    pub fn args(&self) -> Vec<Arg> {
        let mut args = vec![
            Arg::new(SESSION_ARG)
                .long(self.flag)
                .global(true)
                .value_name(self.value_name)
                .help(self.help),
        ];
        if let Some(ready) = &self.ready {
            args.push(
                Arg::new(NO_WAIT_ARG)
                    .long(ready.skip_flag)
                    .global(true)
                    .action(ArgAction::SetTrue)
                    .help(ready.skip_help),
            );
        }
        args
    }

    /// Long flag names this spec occupies, for the collision check.
    pub(crate) fn flags(&self) -> Vec<&'static str> {
        let mut names = vec![self.flag];
        if let Some(ready) = &self.ready {
            names.push(ready.skip_flag);
        }
        names
    }

    /// Read the session out of parsed matches.
    pub fn read(&self, m: &ArgMatches) -> Result<SessionArgs, MissingSession> {
        let target = m
            .try_get_one::<String>(SESSION_ARG)
            .ok()
            .flatten()
            .cloned()
            .ok_or(MissingSession {
                flag: self.flag,
                message: self.missing,
            })?;
        let skipped = m.try_get_one::<bool>(NO_WAIT_ARG).ok().flatten() == Some(&true);
        Ok(SessionArgs {
            target,
            wait_for_ready: self.ready.is_some() && !skipped,
        })
    }

    /// Read the session for one tool, honouring
    /// [`CliHints::needs_session`](crate::CliHints::needs_session).
    ///
    /// `Ok(None)` is "this tool asked for no session", which is a different
    /// thing from "the user forgot to name one" and must not be reported as it:
    /// `<engine> tool tool_help decompile` has no database to open, and refusing
    /// it would be the CLI inventing a requirement the tool does not have. The
    /// rule lives here rather than in each engine's `main`, since every stateful
    /// engine has a handful of catalog-shaped tools in the same position.
    pub fn read_for(
        &self,
        def: &crate::ToolDef,
        m: &ArgMatches,
    ) -> Result<Option<SessionArgs>, MissingSession> {
        if !def.cli.needs_session {
            return Ok(None);
        }
        self.read(m).map(Some)
    }
}

/// How the readiness wait ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Readiness {
    /// The engine reported ready before the ceiling.
    Ready,
    /// The wait was not run — no [`ReadySpec`], or the opt-out flag.
    Skipped,
    /// The ceiling was reached with the engine still not ready.
    TimedOut,
    /// The engine could not say. Carries its reason.
    Unknown(String),
}

impl Readiness {
    /// The line to put on stderr, if this outcome means the answer that follows
    /// may be incomplete.
    ///
    /// Neither non-ready outcome may pass *silently*: a probe error confined to
    /// `warn!`, or a deadline expiring with nothing printed, is a degradation
    /// the caller never learns about. An answer that may be incomplete has to
    /// say so itself.
    pub fn warning(&self, spec: &ReadySpec) -> Option<String> {
        match self {
            Self::Ready | Self::Skipped => None,
            Self::TimedOut => Some(spec.timed_out.to_owned()),
            Self::Unknown(reason) => Some(format!("{}（{reason}）", spec.unknown)),
        }
    }

    pub fn is_ready(&self) -> bool {
        matches!(self, Self::Ready)
    }
}

/// Poll `probe` until it says ready, the ceiling passes, or it fails.
///
/// `probe` is the engine's own readiness question and nothing here interprets
/// it: IDA polls `auto_is_ok` — `auto_state` reads `AU_NONE` throughout and is
/// useless for this — while another engine would ask something else entirely.
/// What is shared, and what would otherwise be written three times, is the loop:
/// the interval, the ceiling, and the fact that giving up has to be *said*.
pub async fn wait_until_ready<F, Fut>(spec: &ReadySpec, mut probe: F) -> Readiness
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<bool, String>>,
{
    let deadline = Instant::now() + spec.timeout;
    loop {
        match probe().await {
            Ok(true) => return Readiness::Ready,
            Ok(false) => {}
            Err(reason) => return Readiness::Unknown(reason),
        }
        if Instant::now() + spec.poll >= deadline {
            return Readiness::TimedOut;
        }
        tokio::time::sleep(spec.poll).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    const READY: ReadySpec = ReadySpec {
        skip_flag: "no-wait-analysis",
        skip_help: "skip",
        timeout: Duration::from_millis(60),
        poll: Duration::from_millis(5),
        timed_out: "等待分析收敛超时，结果可能不完整",
        unknown: "无法确认分析是否收敛",
    };

    const SPEC: SessionSpec = SessionSpec {
        selector: Some("database"),
        flag: "idb",
        value_name: "PATH",
        help: "the database to open",
        missing: "IDA 的工具都读当前打开的数据库",
        ready: Some(READY),
    };

    fn matches(argv: &[&str]) -> ArgMatches {
        let mut cmd = clap::Command::new("eng").subcommand(clap::Command::new("tool"));
        for arg in SPEC.args() {
            cmd = cmd.arg(arg);
        }
        cmd.get_matches_from(argv)
    }

    #[test]
    fn a_missing_session_reports_the_declared_prose_not_an_invented_one() {
        let m = matches(&["eng", "tool"]);
        let error = SPEC.read(&m).expect_err("no --idb was given");
        assert_eq!(error.flag, "idb");
        assert!(error.to_string().contains("--idb"), "{error}");
        assert!(error.to_string().contains(SPEC.missing), "{error}");
    }

    #[test]
    fn the_session_flag_is_global_so_it_reads_from_either_side_of_the_tool() {
        for argv in [
            ["eng", "--idb", "/tmp/cat", "tool"],
            ["eng", "tool", "--idb", "/tmp/cat"],
        ] {
            let m = matches(&argv);
            let args = SPEC.read(&m).expect("the flag was given");
            assert_eq!(args.target, "/tmp/cat");
            assert!(args.wait_for_ready, "waiting is the default");
        }
    }

    #[test]
    fn the_opt_out_flag_turns_the_wait_off() {
        let m = matches(&["eng", "tool", "--idb", "/tmp/cat", "--no-wait-analysis"]);
        assert!(!SPEC.read(&m).expect("the flag was given").wait_for_ready);
    }

    /// An engine with no readiness concept gets no flag and never waits, rather
    /// than getting a flag that does nothing.
    #[test]
    fn an_engine_without_a_readiness_gate_has_no_readiness_flag() {
        const PLAIN: SessionSpec = SessionSpec {
            ready: None,
            ..SPEC
        };
        let longs: Vec<String> = PLAIN
            .args()
            .iter()
            .filter_map(|a| a.get_long().map(str::to_owned))
            .collect();
        assert_eq!(longs, ["idb"]);

        let mut cmd = clap::Command::new("eng");
        for arg in PLAIN.args() {
            cmd = cmd.arg(arg);
        }
        let m = cmd.get_matches_from(["eng", "--idb", "/tmp/cat"]);
        assert!(!PLAIN.read(&m).expect("the flag was given").wait_for_ready);
    }

    fn def(needs_session: bool) -> crate::ToolDef {
        let schema: serde_json::Map<String, serde_json::Value> =
            serde_json::from_value(serde_json::json!({"type": "object", "properties": {}}))
                .expect("an object schema is an object");
        crate::ToolDef {
            tool: rmcp::model::Tool::new("tool_help", "docs for one tool", schema),
            cli: crate::CliHints {
                positional: &[],
                int_args: &[],
                enabled: true,
                needs_session,
            },
            ext: None,
        }
    }

    /// "This tool asked for no session" and "the user forgot to name one" are
    /// different answers, and printing the second for the first would invent a
    /// requirement `tool_help` does not have.
    #[test]
    fn a_tool_that_needs_no_session_is_not_asked_for_one() {
        let m = matches(&["eng", "tool"]);
        assert!(
            SPEC.read_for(&def(false), &m)
                .expect("no session is not an error")
                .is_none()
        );
        assert!(SPEC.read_for(&def(true), &m).is_err());
    }

    #[tokio::test]
    async fn a_wait_that_converges_reports_ready_and_says_nothing() {
        let calls = Cell::new(0u32);
        let outcome = wait_until_ready(&READY, || {
            calls.set(calls.get() + 1);
            let n = calls.get();
            async move { Ok(n >= 3) }
        })
        .await;
        assert_eq!(outcome, Readiness::Ready);
        assert_eq!(outcome.warning(&READY), None);
    }

    /// The half the hand-written loop got wrong: the ceiling expiring used to
    /// fall through to the call with no output at all.
    #[tokio::test]
    async fn a_wait_that_never_converges_says_so() {
        let outcome = wait_until_ready(&READY, || async { Ok(false) }).await;
        assert_eq!(outcome, Readiness::TimedOut);
        assert_eq!(outcome.warning(&READY).as_deref(), Some(READY.timed_out));
    }

    /// …and so does the other half: a probe that fails is "I could not tell",
    /// which is not the same as "ready" and must not read like it.
    #[tokio::test]
    async fn a_probe_that_fails_is_reported_with_its_reason() {
        let outcome = wait_until_ready(&READY, || async { Err("worker gone".to_owned()) }).await;
        assert_eq!(outcome, Readiness::Unknown("worker gone".to_owned()));
        let warning = outcome
            .warning(&READY)
            .expect("an unknown state is reported");
        assert!(warning.contains("worker gone"), "{warning}");
        assert!(warning.contains(READY.unknown), "{warning}");
    }
}
