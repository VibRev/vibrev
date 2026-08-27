//! Terminal conventions.
//!
//! Two rules, both non-negotiable:
//!
//! * Nothing writes an escape sequence into a pipe. `std::io::IsTerminal` has been
//!   stable since 1.70, and `supports-color` (via owo-colors) layers `NO_COLOR` /
//!   `CLICOLOR_FORCE` / `TERM=dumb` on top of it.
//! * Error semantics: human mode gets `Error: <msg>` on stderr and exit 1;
//!   `--json` gets `{"ok":false,…}` on **stdout** and exit 1, so a caller can parse
//!   one stream and never have to guess.

use owo_colors::{OwoColorize, Stream};

/// Whether colour should be emitted for stdout.
///
/// Rather than re-deriving `NO_COLOR` / `CLICOLOR_FORCE` / TTY rules — and drifting
/// from owo-colors when one of them changes — ask owo-colors by rendering a probe
/// string and seeing whether it came back decorated. `supports_color` caches its
/// answer, so this is a lookup after the first call.
pub fn color_enabled() -> bool {
    format!("{}", "x".if_supports_color(Stream::Stdout, |t| t.green())) != "x"
}

/// Emits the failure in whichever mode the caller is in, then exits 1.
/// Never returns.
pub fn fail(json: bool, kind: &str, msg: &str, detail: &[String]) -> ! {
    if json {
        let mut body = serde_json::Map::new();
        body.insert("ok".into(), serde_json::Value::Bool(false));
        body.insert("error".into(), kind.into());
        body.insert("message".into(), msg.into());
        if !detail.is_empty() {
            body.insert("detail".into(), detail.into());
        }
        println!("{}", serde_json::Value::Object(body));
    } else {
        eprintln!("Error: {msg}");
        for line in detail {
            eprintln!("{line}");
        }
    }
    std::process::exit(1)
}
