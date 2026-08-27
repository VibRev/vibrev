//! `vibrev <engine> <args…>` — hand the process over to the engine's own CLI.
//!
//! `vibrev` sits on no request path, and that has to be literally true for
//! dispatch too. On Unix we `execvp` into the engine: no fork, no supervisor
//! process left behind, so signals, job control, exit codes, and terminal
//! ownership are the engine's without anything having to forward them.
//!
//! Arguments are never parsed. `vibrev ida decompile main --limit 20` becomes
//! `ida-headless-mcp decompile main --limit 20`, byte for byte — if `vibrev` tried
//! to understand `--limit` it would have to be upgraded every time an engine grew
//! a flag.

use std::ffi::OsString;

use crate::discover::Located;

/// Replace this process with the engine. Only returns if the exec itself failed.
#[cfg(unix)]
pub fn exec(located: &Located, args: &[OsString]) -> std::io::Error {
    use std::os::unix::process::CommandExt;

    std::process::Command::new(located.path.as_std_path())
        .args(args)
        .exec()
}

/// No `exec` off Unix, so spawn and mirror the child's exit status. Signal
/// handling is inevitably approximate here; that is a platform limitation, not a
/// design choice.
#[cfg(not(unix))]
pub fn exec(located: &Located, args: &[OsString]) -> std::io::Error {
    let status = match std::process::Command::new(located.path.as_std_path())
        .args(args)
        .status()
    {
        Ok(s) => s,
        Err(e) => return e,
    };
    std::process::exit(status.code().unwrap_or(1))
}
