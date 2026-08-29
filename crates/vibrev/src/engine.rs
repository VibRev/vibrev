//! The engine registry — the one place that knows the three engines exist.
//!
//! `vibrev` links no engine code and sits on no request path, so all it needs per
//! engine is: what the binary is called, how to make it speak stdio MCP (for the
//! identity probe), whether `install` should point a client at a listener instead
//! of spawning the binary, and what to tell a user who does not have it.
//!
//! The install guidance is deliberately conservative. Neither IDA nor BN can
//! honestly be offered as a binary download today, so nothing here prints a
//! command `vibrev` cannot actually deliver.

/// A statically known engine. There are exactly three; a fourth would be a new
/// entry here and nowhere else.
#[derive(Debug, Clone, Copy)]
pub struct Engine {
    /// The name a user types: `vibrev <id> ...`.
    pub id: &'static str,
    /// The executable to look for.
    pub bin: &'static str,
    /// One line for `--help`.
    pub about: &'static str,
    /// Argv that makes the engine serve MCP on stdio, used by the identity probe.
    /// Overridable per engine via `mcp_args` in `config.toml` — an engine may well
    /// rename its subcommand before we notice.
    pub mcp_args: &'static [&'static str],
    /// Client-facing listener, if this engine's `serve` defaults to HTTP.
    ///
    /// `None` means `install` cannot write HTTP and stays on a stdio spawn.
    /// `Some` is the URL `--mode http` (the default) writes; `--mode stdio`
    /// still uses `mcp_args`. The identity probe always uses `mcp_args`.
    pub http: Option<&'static str>,
    /// Argv that makes the engine describe the agent skills it carries, minus the
    /// trailing `--json`. Empty means it ships none and the probe is skipped
    /// entirely — an engine that grows a skill later changes this one line.
    pub skills_args: &'static [&'static str],
    /// What to print when the binary is missing. Every line must be something the
    /// user can actually act on.
    pub install: &'static [&'static str],
}

pub const ENGINES: &[Engine] = &[
    Engine {
        id: "ida",
        bin: "ida-headless-mcp",
        about: "IDA Pro",
        // The transport has to be named: this engine's `serve` defaults to
        // HTTP, so a bare invocation would bind a port and never read the pipe
        // — the probe below and every config written from these args speak
        // stdio. `serve` is the multi-database supervisor, which does not
        // initialize idalib until a database is opened, so it stays the
        // cheapest thing to hand a handshake probe.
        mcp_args: &["serve", "--mode", "stdio"],
        http: Some(DEFAULT_HTTP_MCP_URL),
        // `skills list` answers out of data compiled into the binary: no
        // database, no license, no IDA installation.
        skills_args: &["skills", "list"],
        install: &[
            "IDA 引擎目前只能从源码构建。",
            "分发一个链接了 IDA SDK 的二进制在许可上是否允许尚未核查，",
            "因此这里不承诺、也不提供 release 下载。",
            "",
            "前置条件：",
            "  - IDA Pro 9.2 / 9.3 / 9.4 之一（三个版本各自构建，manifest 不通用）",
            "  - 对应版本的 idalib（随 IDA 安装目录提供）",
            "",
            "构建（release 产物约 27.5 MB，因为静态链接了 idalib）：",
            "  git clone https://github.com/fuqiuluo/ida-headless-mcp",
            "  cd ida-headless-mcp",
            "  cargo build --release",
            "  install -D target/release/ida-headless-mcp ~/.vibrev/engines/ida-headless-mcp",
            "",
            "或把产物放进 PATH，或在 ~/.vibrev/config.toml 里写明路径：",
            "  [engines.ida]",
            "  path = \"/path/to/ida-headless-mcp\"",
        ],
    },
    Engine {
        id: "bn",
        bin: "bn-headless-mcp",
        about: "Binary Ninja",
        // Same default, same fix. `serve` speaks HTTP unless told otherwise,
        // and a bare invocation is a bare `serve` — which would leave the
        // identity probe waiting on a pipe nobody reads. `install` writes the
        // HTTP URL separately (`http` below). Nothing distinguishes the two
        // engines on this field any more; ida above carries the long version.
        mcp_args: &["serve", "--mode", "stdio"],
        http: Some(DEFAULT_HTTP_MCP_URL),
        // No skill vendored yet. The channel is engine-agnostic, so this becomes
        // `&["skills", "list"]` the day `bn-headless-mcp` grows a `skills/`.
        skills_args: &[],
        install: &[
            "BN 引擎必须在你自己的机器上、按你自己的 Binary Ninja 版本从源码构建：",
            "binaryninjacore-sys 用 bindgen 解析本机头文件，二进制无法跨机器分发。",
            "所以 vibrev 没有、也不会有 `vibrev engine install bn` 这条捷径。",
            "",
            "前置条件：",
            "  - 本机安装 Binary Ninja，且 license 为 Commercial 或 Ultimate（headless 需要）",
            "  - clang（bindgen 依赖）",
            "  - 记下 $BINARYNINJADIR/api_REVISION.txt 里的 commit，构建时要 pin 它",
            "",
            "从 workspace 的 bn-headless-mcp 仓库源码构建：",
            "  cd bn-headless-mcp",
            "  # Cargo.toml 里 binaryninja / binaryninjacore-sys 的 rev",
            "  # 必须等于 $BINARYNINJADIR/api_REVISION.txt",
            "  BINARYNINJADIR=/path/to/binaryninja cargo build --release",
            "  install -D target/release/bn-headless-mcp ~/.vibrev/engines/bn-headless-mcp",
            "",
            "或把产物放进 PATH，或在 ~/.vibrev/config.toml 里写明路径：",
            "  [engines.bn]",
            "  path = \"/path/to/bn-headless-mcp\"",
        ],
    },
    Engine {
        id: "jadx",
        bin: "rjadx",
        about: "Android APK / DEX",
        // `rjadx mcp` refuses to start without an explicit transport
        // (CliError::McpTransportRequired), so `--stdio` is not optional here.
        mcp_args: &["mcp", "--stdio"],
        // `rjadx mcp` has no HTTP listener; the client still spawns it.
        http: None,
        // No skill vendored yet; see the note on `bn`.
        skills_args: &[],
        install: &[
            "jadx 引擎是纯 Rust，没有本机 SDK 依赖，构建最简单：",
            "",
            "  cargo install --git https://github.com/… rjadx-cli",
            "",
            "或从源码构建：",
            "  git clone <jadx-rs>",
            "  cd jadx-rs",
            "  cargo build --release -p rjadx-cli",
            "  install -D target/release/rjadx ~/.vibrev/engines/rjadx",
            "",
            "（jadx-rs 尚未推送到公共 remote，上面的 URL 需替换为实际仓库地址。）",
        ],
    },
];

/// The listener URL `install` writes for engines whose `serve` defaults to HTTP.
///
/// Same bind as `vibrev_kit::transport::DEFAULT_BIND` plus the `/mcp` path the
/// engines actually serve. Named here so the installer does not take the `http`
/// feature just to read a string. Both IDA and BN bind this by default; the
/// operator runs one of them, or rebinds.
pub const DEFAULT_HTTP_MCP_URL: &str = "http://127.0.0.1:8765/mcp";

/// Look an engine up by the id a user typed.
pub fn by_id(id: &str) -> Option<&'static Engine> {
    ENGINES.iter().find(|e| e.id == id)
}

/// Every engine id, for error messages and help text.
pub fn ids() -> Vec<&'static str> {
    ENGINES.iter().map(|e| e.id).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bn_install_guidance_describes_the_existing_repo() {
        let bn = by_id("bn").expect("bn is a registered engine");
        let text = bn.install.join("\n");
        assert!(
            !text.contains("尚未建立"),
            "doctor/install guidance is stale:\n{text}"
        );
        assert!(text.contains("bn-headless-mcp"), "{text}");
        assert!(text.contains("api_REVISION.txt"), "{text}");
        assert!(
            text.contains("Commercial") && text.contains("Ultimate"),
            "{text}"
        );
        assert!(
            text.contains("vibrev engine install bn"),
            "must still say the shortcut does not exist:\n{text}"
        );
    }

    #[test]
    fn http_engines_share_the_default_listener_and_jadx_does_not() {
        assert_eq!(by_id("ida").unwrap().http, Some(DEFAULT_HTTP_MCP_URL));
        assert_eq!(by_id("bn").unwrap().http, Some(DEFAULT_HTTP_MCP_URL));
        assert_eq!(by_id("jadx").unwrap().http, None);
    }

    #[test]
    fn no_engine_claims_its_repo_does_not_exist() {
        for engine in ENGINES {
            let text = engine.install.join("\n");
            assert!(
                !text.contains("尚未建立"),
                "{} still says the repo is missing:\n{text}",
                engine.id
            );
        }
    }
}
