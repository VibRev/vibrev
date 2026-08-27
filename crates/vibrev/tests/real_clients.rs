//! The delegate path against the **real** client CLIs.
//!
//! `--delegate` is opt-in, and elsewhere it is exercised by four tests against
//! stub scripts we wrote ourselves. Stubs cannot fail the way this path actually
//! fails: upstream renames a subcommand or a flag, our argv stops being accepted,
//! CI stays green and the user gets the error. Tracking upstream for free is the
//! one thing delegation is *for*, so it needs a test that can actually notice.
//!
//! Every test here is `#[ignore]`d — the real CLIs are third-party software that a
//! CI runner will usually not have, and the ones that are installed vary per
//! machine. Run them deliberately:
//!
//! ```text
//! cargo test -p vibrev --test real_clients -- --ignored --nocapture
//! cargo test -- --ignored --nocapture delegation_against_real_clients
//! ```
//!
//! `--nocapture` is worth typing: a CLI that is not installed makes its test
//! **skip and say so** rather than fail, and that sentence is the whole report for
//! that client. Whoever runs this tests whatever they happen to have.
//!
//! What is asserted is the upstream *contract*, not upstream's output:
//!
//! * the argv we construct is still accepted (exit 0, no "unknown subcommand");
//! * the entry it writes still parses back into `vibrev list` as the same
//!   `command` + `args` we asked for;
//! * running twice still leaves exactly one entry, i.e. idempotency still holds —
//!   for Claude Code that also pins `mcp remove` + `mcp add-json --scope user`,
//!   since `add-json` alone exits 1 on a name that exists;
//! * unrelated entries and unrelated config survive.
//!
//! One assertion runs the other way round, and says so when it fires: the Codex
//! test asserts that `codex mcp add` **loses** the comments attached to
//! `[mcp_servers]`. That is the measurement the opt-in default rests on, so if it
//! ever stops being true this suite is the thing that should notice — as a failure
//! that reads "upstream may have been fixed", not as a silent drift.
//!
//! Isolation is absolute and is the reason this file does not simply reuse
//! `install.rs`'s sandbox: these tests run software that edits the developer's own
//! MCP configuration. Every child process gets `HOME`, `CODEX_HOME` and
//! `XDG_CONFIG_HOME` inside `target/`, and `PATH` is the only thing inherited from
//! the outside — because that is how the real CLI gets found at all.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const VIBREV: &str = env!("CARGO_BIN_EXE_vibrev");

/// What the sandbox engine binary is registered as, in every client.
const SERVER: &str = "vibrev-jadx";

// ------------------------------------------------------------- CLI lookup ---

/// Resolve `bin` against the PATH *this test process* inherited.
///
/// Not `which::which`, which would be the same thing with a dependency: the point
/// is to look at the outside world once, here, and then hand the child a `PATH`
/// that can still find it while everything else points into `target/`.
fn on_path(bin: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|dir| dir.join(bin))
        .find(|p| is_executable(p))
}

#[cfg(unix)]
fn is_executable(p: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(p).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
}

#[cfg(not(unix))]
fn is_executable(p: &Path) -> bool {
    p.is_file()
}

/// A missing client CLI is not a failure: nobody has all four, and a test suite
/// that demands them is a test suite nobody runs.
fn skip(bin: &str, how_to_get_it: &str) {
    println!("跳过：PATH 上没有 `{bin}`，本机无法验证这个客户端（安装方式：{how_to_get_it}）");
}

/// Best-effort version string, so a failure a month from now says which build it
/// was measured against.
fn version_of(cli: &Path, args: &[&str]) -> String {
    Command::new(cli)
        .args(args)
        .env("NO_COLOR", "1")
        .output()
        .ok()
        .map(|o| {
            let text = String::from_utf8_lossy(&o.stdout).into_owned();
            text.lines().next().unwrap_or_default().trim().to_owned()
        })
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "(未知版本)".to_owned())
}

// ---------------------------------------------------------------- sandbox ---

/// A disposable `$HOME` that the real client CLIs are pointed at.
struct Sandbox {
    home: PathBuf,
    proj: PathBuf,
    tmp: PathBuf,
    /// The engine binary the entries will point at.
    engine: PathBuf,
}

/// Scratch space next to the test binary, i.e. inside `target/`. Not
/// `std::env::temp_dir()`: `/tmp` is a small tmpfs on the dev machines, and these
/// directories get whole `~/.claude` trees written into them.
fn sandbox(tag: &str) -> Sandbox {
    let base = PathBuf::from(VIBREV)
        .parent()
        .expect("the test binary lives in a directory")
        .join("vibrev-real-clients")
        .join(tag);
    let _ = std::fs::remove_dir_all(&base);

    let home = base.join("home");
    let proj = base.join("proj");
    let tmp = base.join("tmp");
    let engines = home.join(".vibrev").join("engines");
    for d in [&home, &proj, &tmp, &engines] {
        std::fs::create_dir_all(d).expect("scratch dirs are creatable");
    }

    // `install` refuses to register an engine it cannot find, so there has to be
    // something runnable at the path the entry will name.
    let engine = engines.join("rjadx");
    std::fs::write(&engine, "#!/bin/sh\nexit 0\n").expect("engine stub is writable");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&engine, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    Sandbox {
        home,
        proj,
        tmp,
        engine,
    }
}

impl Sandbox {
    /// Run `vibrev` with every path a client could possibly resolve pointed inside
    /// the sandbox.
    ///
    /// `env_clear` first, so that no variable from the developer's shell —
    /// `CLAUDE_CONFIG_DIR` is the dangerous one — can send a real client CLI back
    /// at the real configuration. `PATH` is then put back verbatim, because it is
    /// what makes the real CLI (and, for Codex, the `node` that runs it) findable.
    fn vibrev(&self, args: &[&str]) -> Output {
        let mut cmd = Command::new(VIBREV);
        cmd.args(args)
            .current_dir(&self.proj)
            .env_clear()
            .env("HOME", &self.home)
            .env("VIBREV_HOME", self.home.join(".vibrev"))
            .env("XDG_CONFIG_HOME", self.home.join(".config"))
            // Codex resolves its config directory from `CODEX_HOME` before falling
            // back to `$HOME/.codex`; pinning both is one less thing to be wrong.
            .env("CODEX_HOME", self.home.join(".codex"))
            .env("TMPDIR", &self.tmp)
            .env("NO_COLOR", "1")
            .env("LANG", "C.UTF-8");
        if let Some(path) = std::env::var_os("PATH") {
            cmd.env("PATH", path);
        }
        cmd.output().expect("vibrev is runnable")
    }

    fn read(&self, rel: &str) -> String {
        std::fs::read_to_string(self.home.join(rel))
            .unwrap_or_else(|e| panic!("reading {rel}: {e}"))
    }

    fn write(&self, rel: &str, body: &str) {
        let p = self.home.join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, body).unwrap();
    }

    fn engine_path(&self) -> String {
        self.engine.display().to_string()
    }

    /// `vibrev list --json`, i.e. our own reader looking at what the client CLI
    /// wrote. This is the half of the contract that the stubs can never test:
    /// upstream is free to write the entry in a shape we cannot read.
    fn listed(&self, client: &str) -> Vec<serde_json::Value> {
        let out = self.vibrev(&["--json", "list"]);
        assert!(out.status.success(), "vibrev list failed: {}", stderr(&out));
        let v: serde_json::Value = serde_json::from_str(&stdout(&out))
            .unwrap_or_else(|e| panic!("vibrev list --json 不是 JSON: {e}\n{}", stdout(&out)));
        assert!(
            v["errors"].as_array().is_none_or(|a| a.is_empty()),
            "vibrev 读不回客户端 CLI 写出的文件（上游可能换了写法）: {}",
            v["errors"]
        );
        v["servers"]
            .as_array()
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .filter(|s| s["client"] == client)
            .collect()
    }

    /// The argv `vibrev` would hand to the client CLI, straight out of the plan.
    /// Pinning it here is what makes an upstream change legible: the preview says
    /// what we sent, the run says whether it was accepted.
    fn planned_argv(&self, args: &[&str]) -> Vec<Vec<String>> {
        let mut full = vec!["--json"];
        full.extend_from_slice(args);
        full.extend_from_slice(&["--delegate", "--dry-run"]);
        let out = self.vibrev(&full);
        assert!(out.status.success(), "{}", stderr(&out));
        let v: serde_json::Value = serde_json::from_str(&stdout(&out)).unwrap();
        assert_eq!(
            v["actions"][0]["method"],
            "delegate",
            "预期走委派路径，实际计划是: {}",
            stdout(&out)
        );
        v["actions"][0]["changes"][0]["commands"]
            .as_array()
            .map(|cs| {
                cs.iter()
                    .map(|c| {
                        c.as_array()
                            .expect("每条命令都是 argv 数组")
                            .iter()
                            .map(|a| a.as_str().unwrap_or_default().to_owned())
                            .collect()
                    })
                    .collect()
            })
            .unwrap_or_default()
    }
}

fn stdout(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

fn stderr(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

/// The one entry we own, as `vibrev list` sees it — or a failure naming what the
/// client CLI actually left behind.
fn only_entry(entries: Vec<serde_json::Value>) -> serde_json::Value {
    let mut ours: Vec<serde_json::Value> = entries
        .iter()
        .filter(|e| e["server"] == SERVER)
        .cloned()
        .collect();
    assert_eq!(
        ours.len(),
        1,
        "应当恰好有一条 {SERVER}（幂等性），实际: {entries:?}"
    );
    ours.remove(0)
}

// ------------------------------------------------------------------ codex ---

/// Codex: `codex mcp add <name> -- <command> <args…>` and `codex mcp remove`.
#[test]
#[ignore = "需要真实的 codex CLI；见文件头，用 -- --ignored --nocapture 运行"]
fn delegation_against_real_clients_codex() {
    let Some(cli) = on_path("codex") else {
        return skip("codex", "npm i -g @openai/codex");
    };
    println!(
        "codex: {} ({})",
        cli.display(),
        version_of(&cli, &["--version"])
    );

    let sb = sandbox("codex");
    // A file shaped like a real one: an unrelated setting, an unrelated server,
    // and comments in both regions.
    sb.write(
        ".codex/config.toml",
        r#"model = "o3"
approval_policy = "on-request"

# 这个 server 是我自己加的
[mcp_servers.other]
command = "npx"
# 别删这行
args = ["-y", "some-other-server"]
"#,
    );

    // What we are about to send. If upstream renames the subcommand, this is the
    // line to compare the error against.
    let argv = sb.planned_argv(&["install", "jadx", "--client", "codex"]);
    assert_eq!(
        argv,
        [[
            "codex".to_owned(),
            "mcp".into(),
            "add".into(),
            SERVER.into(),
            "--".into(),
            sb.engine_path(),
            "mcp".into(),
            "--stdio".into(),
        ]],
        "委派 argv 变了；先确认这是有意的改动"
    );

    let out = sb.vibrev(&[
        "install",
        "jadx",
        "--client",
        "codex",
        "--delegate",
        "--yes",
    ]);
    assert!(
        out.status.success(),
        "真实的 `codex mcp add` 拒绝了我们构造的 argv —— 上游契约可能变了。\nargv: {argv:?}\nstderr: {}\nstdout: {}",
        stderr(&out),
        stdout(&out)
    );
    assert!(
        stdout(&out).contains("[委派 codex CLI]"),
        "{}",
        stdout(&out)
    );

    // Round trip 1: through a TOML parse, so a shape change shows up as a type
    // error rather than as a substring that happens to still be there.
    let raw = sb.read(".codex/config.toml");
    let doc: toml::Value = toml::from_str(&raw).expect("codex 写出的仍是合法 TOML");
    let entry = doc
        .get("mcp_servers")
        .and_then(|m| m.get(SERVER))
        .unwrap_or_else(|| panic!("codex 没写出 [mcp_servers.{SERVER}]:\n{raw}"));
    assert_eq!(entry["command"].as_str(), Some(sb.engine_path().as_str()));
    assert_eq!(
        entry["args"].as_array().map(|a| a.len()),
        Some(2),
        "args 丢了或多了: {entry:?}"
    );
    assert_eq!(entry["args"][0].as_str(), Some("mcp"));
    assert_eq!(entry["args"][1].as_str(), Some("--stdio"));

    // Round trip 2: our own reader. The client CLI writing something we cannot
    // read back is the failure mode that only a real CLI can produce.
    let listed = only_entry(sb.listed("codex"));
    assert_eq!(listed["command"], sb.engine_path());
    assert_eq!(listed["args"][0], "mcp");
    assert_eq!(listed["args"][1], "--stdio");

    // The user's own server is not collateral damage.
    assert_eq!(doc["mcp_servers"]["other"]["command"].as_str(), Some("npx"));
    assert_eq!(doc["model"].as_str(), Some("o3"), "无关配置被改写了");
    assert_eq!(doc["approval_policy"].as_str(), Some("on-request"));

    // Idempotency: `codex mcp add` overwrites in place, so a second run is still
    // one entry — and a third, as a dry run, reports nothing to do.
    let again = sb.vibrev(&[
        "install",
        "jadx",
        "--client",
        "codex",
        "--delegate",
        "--yes",
    ]);
    assert!(again.status.success(), "{}", stderr(&again));
    let body = sb.read(".codex/config.toml");
    assert_eq!(
        body.matches(&format!("[mcp_servers.{SERVER}]")).count(),
        1,
        "重复条目：`codex mcp add` 不再原地覆盖了\n{body}"
    );
    let _ = only_entry(sb.listed("codex"));

    let dry = sb.vibrev(&[
        "--json",
        "install",
        "jadx",
        "--client",
        "codex",
        "--dry-run",
    ]);
    let v: serde_json::Value = serde_json::from_str(&stdout(&dry)).unwrap();
    assert_eq!(
        v["actions"][0]["changes"][0]["op"],
        "unchanged",
        "委派写出的条目和我们直接写出的不是同一个东西：{}",
        stdout(&dry)
    );

    // The measurement the opt-in default rests on, asserted so that it cannot rot
    // quietly.
    assert!(
        !body.contains("# 别删这行"),
        "真实的 `codex mcp add` 现在**保留**了 [mcp_servers] 区域的注释。\n\
         这不是这个测试坏了，而是上游可能修好了：把委派降级为 opt-in 的\n\
         唯一实测理由就是这里的注释丢失（当时测的是 codex-cli 0.147.0）。\n\
         请重新测量上游行为，更新 tests/install.rs 里的 codex stub，\n\
         并重新考虑 --delegate 是否还需要用户显式要求。\n实际文件:\n{body}"
    );
    assert!(
        !body.contains("# 这个 server 是我自己加的"),
        "同上：[mcp_servers] 区域上方的注释这次活下来了，请重新测量上游。\n{body}"
    );
    // A comment outside the region was never in danger, and stays a control.
    assert!(
        body.contains("approval_policy"),
        "区域之外的配置不该被动过\n{body}"
    );

    // And the way back out.
    let rm = sb.vibrev(&[
        "uninstall",
        "jadx",
        "--client",
        "codex",
        "--delegate",
        "--yes",
    ]);
    assert!(
        rm.status.success(),
        "真实的 `codex mcp remove` 拒绝了我们的 argv：{}",
        stderr(&rm)
    );
    let after = sb.read(".codex/config.toml");
    assert!(!after.contains(SERVER), "条目没被删掉:\n{after}");
    assert!(after.contains("[mcp_servers.other]"), "删多了:\n{after}");
}

// ------------------------------------------------------------ claude code ---

/// Claude Code: `claude mcp remove` then `claude mcp add-json … --scope user`.
///
/// The two-step is the interesting part. `add-json` exits 1 on a name that already
/// exists, so our idempotency depends on the remove running first and on its
/// failure being tolerated when there is nothing to remove. Running install twice
/// is what pins all of that.
#[test]
#[ignore = "需要真实的 claude CLI；见文件头，用 -- --ignored --nocapture 运行"]
fn delegation_against_real_clients_claude_code() {
    let Some(cli) = on_path("claude") else {
        return skip("claude", "https://claude.com/product/claude-code");
    };
    println!(
        "claude: {} ({})",
        cli.display(),
        version_of(&cli, &["--version"])
    );

    let sb = sandbox("claude-code");
    sb.write(
        ".claude.json",
        r#"{
  "numStartups": 17,
  "mcpServers": {
    "keepme": { "type": "stdio", "command": "npx", "args": ["-y", "keepme"] }
  }
}
"#,
    );

    let argv = sb.planned_argv(&["install", "jadx", "--client", "claude-code"]);
    assert_eq!(argv.len(), 2, "add 应当是 remove + add-json 两步: {argv:?}");
    assert_eq!(argv[0][..3], ["claude", "mcp", "remove"]);
    assert_eq!(argv[1][..3], ["claude", "mcp", "add-json"]);
    assert_eq!(
        argv[1].last().map(String::as_str),
        Some("user"),
        "--scope user"
    );

    let out = sb.vibrev(&[
        "install",
        "jadx",
        "--client",
        "claude-code",
        "--delegate",
        "--yes",
    ]);
    assert!(
        out.status.success(),
        "真实的 `claude mcp` 拒绝了我们构造的 argv —— 上游契约可能变了。\nargv: {argv:?}\nstderr: {}\nstdout: {}",
        stderr(&out),
        stdout(&out)
    );
    assert!(
        stdout(&out).contains("[委派 claude CLI]"),
        "{}",
        stdout(&out)
    );

    let doc: serde_json::Value =
        serde_json::from_str(&sb.read(".claude.json")).expect("claude 写出的仍是合法 JSON");
    let entry = &doc["mcpServers"][SERVER];
    assert_eq!(entry["type"], "stdio", "type 字段丢了: {entry}");
    assert_eq!(entry["command"], sb.engine_path());
    assert_eq!(entry["args"][0], "mcp");
    assert_eq!(entry["args"][1], "--stdio");

    let listed = only_entry(sb.listed("claude-code"));
    assert_eq!(listed["command"], sb.engine_path());
    assert_eq!(listed["args"][1], "--stdio");

    // Everything else in the file is the user's.
    assert_eq!(doc["numStartups"], 17, "无关字段被改写了");
    assert_eq!(doc["mcpServers"]["keepme"]["command"], "npx");

    // The whole point of remove-then-add: a second install must not trip over
    // `add-json`'s "already exists" (exit 1), and must not duplicate.
    let again = sb.vibrev(&[
        "install",
        "jadx",
        "--client",
        "claude-code",
        "--delegate",
        "--yes",
    ]);
    assert!(
        again.status.success(),
        "第二次委派安装失败：`claude mcp remove` + `add-json` 的组合不再幂等。\nstderr: {}",
        stderr(&again)
    );
    let listed = only_entry(sb.listed("claude-code"));
    assert_eq!(listed["args"][1], "--stdio");
    let doc: serde_json::Value = serde_json::from_str(&sb.read(".claude.json")).unwrap();
    assert_eq!(
        doc["mcpServers"]["keepme"]["command"], "npx",
        "第二次跑丢了别人的条目"
    );

    let dry = sb.vibrev(&[
        "--json",
        "install",
        "jadx",
        "--client",
        "claude-code",
        "--dry-run",
    ]);
    let v: serde_json::Value = serde_json::from_str(&stdout(&dry)).unwrap();
    assert_eq!(
        v["actions"][0]["changes"][0]["op"],
        "unchanged",
        "委派写出的条目和我们直接写出的不是同一个东西：{}",
        stdout(&dry)
    );

    let rm = sb.vibrev(&[
        "uninstall",
        "jadx",
        "--client",
        "claude-code",
        "--delegate",
        "--yes",
    ]);
    assert!(
        rm.status.success(),
        "真实的 `claude mcp remove` 拒绝了我们的 argv：{}",
        stderr(&rm)
    );
    let doc: serde_json::Value = serde_json::from_str(&sb.read(".claude.json")).unwrap();
    assert!(
        doc["mcpServers"].get(SERVER).is_none(),
        "条目没被删掉: {doc}"
    );
    assert_eq!(doc["mcpServers"]["keepme"]["command"], "npx", "删多了");
}

// ---------------------------------------------------------------- vs code ---

/// VS Code: `code --add-mcp '{"name": …}'`, user profile only.
///
/// Not verified on the machine this was written on — no `code` there, which is
/// exactly the case the skip exists for. The assertions are therefore only what
/// the documented flag promises: the entry lands in the user profile under
/// `servers`, we can read it back, and a second call does not duplicate it.
#[test]
#[ignore = "需要真实的 code CLI；见文件头，用 -- --ignored --nocapture 运行"]
fn delegation_against_real_clients_vscode() {
    let Some(cli) = on_path("code") else {
        return skip(
            "code",
            "VS Code -> Shell Command: Install 'code' command in PATH",
        );
    };
    println!(
        "code: {} ({})",
        cli.display(),
        version_of(&cli, &["--version"])
    );

    let sb = sandbox("vscode");

    let argv = sb.planned_argv(&["install", "jadx", "--client", "vscode"]);
    assert_eq!(argv.len(), 1, "{argv:?}");
    assert_eq!(argv[0][..2], ["code", "--add-mcp"]);
    let payload: serde_json::Value =
        serde_json::from_str(&argv[0][2]).expect("--add-mcp 的参数是一段 JSON");
    assert_eq!(payload["name"], SERVER, "名字在 JSON 里，不是位置参数");
    assert_eq!(payload["type"], "stdio");

    let out = sb.vibrev(&[
        "install",
        "jadx",
        "--client",
        "vscode",
        "--delegate",
        "--yes",
    ]);
    assert!(
        out.status.success(),
        "真实的 `code --add-mcp` 拒绝了我们构造的 argv —— 上游契约可能变了。\nargv: {argv:?}\nstderr: {}",
        stderr(&out)
    );

    let listed = only_entry(sb.listed("vscode"));
    assert_eq!(listed["command"], sb.engine_path());
    assert_eq!(listed["args"][1], "--stdio");
    assert_eq!(listed["scope"], "global", "--add-mcp 只写用户配置");

    let again = sb.vibrev(&[
        "install",
        "jadx",
        "--client",
        "vscode",
        "--delegate",
        "--yes",
    ]);
    assert!(again.status.success(), "{}", stderr(&again));
    let _ = only_entry(sb.listed("vscode"));
}
