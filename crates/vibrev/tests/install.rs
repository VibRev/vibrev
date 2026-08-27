//! End-to-end tests for `vibrev install` / `uninstall` / `list`.
//!
//! These drive the real binary against a throwaway `$HOME`, because the parts most
//! worth testing only exist at that level: `PATH` lookup of a client CLI, the
//! non-TTY confirmation rule, exit codes, and the exact bytes that land on disk.
//!
//! Both write paths are covered, deliberately — delegation is opt-in but still
//! supported, so a regression in either is a real bug:
//!
//! * **direct write** is the default and is pinned by golden files in
//!   `tests/golden/`. That it stays the default even with a client CLI sitting on
//!   `PATH` is itself a test;
//! * **delegation** needs `--delegate`, and runs against stub `claude` / `codex` /
//!   `code` scripts placed at the front of `PATH`, which record their argv and then
//!   perform the edit.
//!
//! Nothing here touches the developer's own client configuration: every child
//! process gets a `$HOME` inside `target/`.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const VIBREV: &str = env!("CARGO_BIN_EXE_vibrev");

/// A disposable home directory, engine binaries and `PATH`.
struct Sandbox {
    root: PathBuf,
    home: PathBuf,
    proj: PathBuf,
    /// Prepended to `PATH`; holds the client CLI stubs when a test wants them.
    bin: PathBuf,
    /// Where the stubs append their argv.
    log: PathBuf,
}

/// Scratch space next to the test binary — i.e. inside `target/`. Not
/// `std::env::temp_dir()`: `/tmp` is a small tmpfs on the dev machines.
fn sandbox(tag: &str) -> Sandbox {
    let base = PathBuf::from(VIBREV)
        .parent()
        .unwrap()
        .join("vibrev-it")
        .join(tag);
    let _ = std::fs::remove_dir_all(&base);

    let home = base.join("home");
    let proj = base.join("proj");
    let bin = base.join("bin");
    for d in [&home, &proj, &bin] {
        std::fs::create_dir_all(d).unwrap();
    }
    // Engines must look runnable or `install` refuses to register them, which is
    // itself a tested behaviour (see `missing_engine_is_refused_with_guidance`).
    let engines = home.join(".vibrev").join("engines");
    std::fs::create_dir_all(&engines).unwrap();
    for name in ["rjadx", "ida-headless-mcp"] {
        write_exec(&engines.join(name), "#!/bin/sh\nexit 0\n");
    }

    Sandbox {
        log: base.join("cli.log"),
        root: base,
        home,
        proj,
        bin,
    }
}

fn write_exec(path: &Path, body: &str) {
    std::fs::write(path, body).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
}

impl Sandbox {
    fn vibrev(&self, args: &[&str]) -> Output {
        Command::new(VIBREV)
            .args(args)
            .current_dir(&self.proj)
            .env_clear()
            .env("HOME", &self.home)
            .env("VIBREV_HOME", self.home.join(".vibrev"))
            // Pinned so the developer's own XDG settings cannot move VS Code's
            // file out from under the test.
            .env("XDG_CONFIG_HOME", self.home.join(".config"))
            // Stub directory first; `/usr/bin:/bin` only so the stubs' own
            // interpreters resolve. The real `claude` and `codex` live in neither.
            .env("PATH", format!("{}:/usr/bin:/bin", self.bin.display()))
            .env("NO_COLOR", "1")
            .env("VIBREV_FAKE_LOG", &self.log)
            .output()
            .expect("vibrev is runnable")
    }

    fn write(&self, rel: &str, body: &str) {
        let p = self.home.join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, body).unwrap();
    }

    fn read(&self, rel: &str) -> String {
        std::fs::read_to_string(self.home.join(rel))
            .unwrap_or_else(|e| panic!("reading {rel}: {e}"))
    }

    fn exists(&self, rel: &str) -> bool {
        self.home.join(rel).exists()
    }

    /// Same, but for the project-scope files — the ones that live in the repo and
    /// therefore get committed.
    fn write_proj(&self, rel: &str, body: &str) {
        let p = self.proj.join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, body).unwrap();
    }

    fn read_proj(&self, rel: &str) -> String {
        std::fs::read_to_string(self.proj.join(rel))
            .unwrap_or_else(|e| panic!("reading project {rel}: {e}"))
    }

    /// Absolute paths differ per machine and per test; fold them back to a token
    /// so a golden file can be compared byte for byte.
    fn normalize(&self, s: &str) -> String {
        s.replace(&self.root.display().to_string(), "<SANDBOX>")
    }

    fn cli_log(&self) -> String {
        std::fs::read_to_string(&self.log).unwrap_or_default()
    }

    /// Install stub `claude`, `codex` and `code` at the front of `PATH`.
    ///
    /// They mimic the upstream behaviour that actually shapes our code, verified
    /// against the real CLIs: `claude mcp add-json` **fails** on a name that
    /// already exists (so an idempotent add has to remove first), `claude mcp
    /// remove` **fails** when the name is absent (so that removal must be
    /// tolerated), and `codex mcp add` overwrites in place.
    fn install_stubs(&self) {
        let record = r#"printf '%s\n' "$*" >> "$VIBREV_FAKE_LOG""#;

        write_exec(
            &self.bin.join("claude"),
            &format!(
                r#"#!/bin/sh
{record}
# $1=mcp $2=remove|add-json $3=name
if [ "$2" = "remove" ]; then
  python3 - "$HOME/.claude.json" "$3" <<'PY' || exit 1
import json, os, sys
p, name = sys.argv[1], sys.argv[2]
d = json.load(open(p)) if os.path.exists(p) else {{}}
if name not in d.get("mcpServers", {{}}):
    sys.exit(1)
del d["mcpServers"][name]
json.dump(d, open(p, "w"), indent=2)
PY
  exit 0
fi
if [ "$2" = "add-json" ]; then
  python3 - "$HOME/.claude.json" "$3" "$4" <<'PY'
import json, os, sys
p, name, body = sys.argv[1], sys.argv[2], sys.argv[3]
d = json.load(open(p)) if os.path.exists(p) else {{}}
servers = d.setdefault("mcpServers", {{}})
if name in servers:
    print("MCP server %s already exists" % name)
    sys.exit(1)
servers[name] = json.loads(body)
json.dump(d, open(p, "w"), indent=2)
PY
  exit $?
fi
exit 2
"#
            ),
        );

        write_exec(
            &self.bin.join("codex"),
            &format!(
                r#"#!/bin/sh
{record}
# $1=mcp $2=add|remove $3=name, then `--` and the command line
sub="$2"; name="$3"; shift 3
[ "$1" = "--" ] && shift
python3 - "$HOME/.codex/config.toml" "$sub" "$name" "$@" <<'PY'
import os, sys
p, sub, name, argv = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4:]
os.makedirs(os.path.dirname(p), exist_ok=True)
text = open(p).read() if os.path.exists(p) else ""
head = "[mcp_servers.%s]" % name
# The lossy part, and the whole reason delegation is opt-in: the real `codex
# mcp add` reserializes the mcp_servers region from a plain TOML parse,
# so every comment attached to it disappears — the header's own leading comment
# included. Comments above the region survive. Measured against codex-cli
# 0.147.0; simplified here to "from the first mcp_servers header to the end".
lines = text.splitlines()
cut = next((i for i, l in enumerate(lines) if l.startswith("[mcp_servers")), len(lines))
while cut > 0 and lines[cut - 1].lstrip().startswith('#'):
    cut -= 1
lines = lines[:cut] + [l for l in lines[cut:] if not l.lstrip().startswith('#')]
blocks, cur = [], []
for line in lines:
    if line.startswith("[") and cur:
        blocks.append(cur); cur = []
    cur.append(line)
if cur: blocks.append(cur)
blocks = [b for b in blocks if not b[0].startswith(head)]
if sub == "add":
    args = ", ".join('"%s"' % a for a in argv[1:])
    blocks.append([head, 'command = "%s"' % argv[0], "args = [%s]" % args, ""])
open(p, "w").write("\n".join("\n".join(b) for b in blocks))
PY
"#
            ),
        );

        // `code --add-mcp` only ever writes the user profile, which is why VS Code
        // project scope is never delegated.
        write_exec(
            &self.bin.join("code"),
            &format!(
                r#"#!/bin/sh
{record}
python3 - "$HOME/.config/Code/User/mcp.json" "$2" <<'PY'
import json, os, sys
p, body = sys.argv[1], sys.argv[2]
os.makedirs(os.path.dirname(p), exist_ok=True)
d = json.load(open(p)) if os.path.exists(p) else {{}}
e = json.loads(body)
d.setdefault("servers", {{}})[e.pop("name")] = e
json.dump(d, open(p, "w"), indent=2)
PY
"#
            ),
        );
    }
}

fn stdout(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

fn stderr(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

/// Compare against `tests/golden/<name>`, or rewrite it when `UPDATE_GOLDEN=1`.
fn assert_golden(name: &str, actual: &str) {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("golden")
        .join(name);
    if std::env::var_os("UPDATE_GOLDEN").is_some() {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, actual).unwrap();
        return;
    }
    let expected = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("{}: {e}\n以 UPDATE_GOLDEN=1 重新生成", path.display()));
    assert_eq!(
        actual,
        expected,
        "\n{} 不匹配。确认改动符合预期后用 UPDATE_GOLDEN=1 cargo test 更新。\n",
        path.display()
    );
}

// ------------------------------------------------------- direct write path ---

/// The bytes the direct-write path produces, for all four dialects at once.
///
/// This is the test that would catch a `serde_json` round-trip sneaking back in:
/// the VS Code fixture is full of comments and the Codex fixture is full of
/// unrelated TOML sections, and both are reproduced verbatim except for our entry.
#[test]
fn direct_write_matches_golden_for_every_client() {
    let sb = sandbox("golden-direct");

    sb.write(
        ".config/Code/User/mcp.json",
        r#"{
  // MCP servers for this profile. Edited by hand — keep the comments!
  "inputs": [
    {
      "id": "gh-token",
      "type": "promptString",
      "description": "GitHub PAT", // never inline the secret
      "password": true
    }
  ],
  "servers": {
    /* Fetches web pages. */
    "fetch": {
      "command": "uvx",
      "args": ["mcp-server-fetch"]
    }
  }
}
"#,
    );
    sb.write(
        ".codex/config.toml",
        r#"model = "o3"
approval_policy = "on-request"

# The user's own provider block.
[model_providers.openai]
name = "OpenAI"
base_url = "https://api.openai.com/v1"

[mcp_servers.other]
command = "npx"
args = ["-y", "some-other-server"]
"#,
    );
    sb.write(
        ".cursor/mcp.json",
        r#"{
  "mcpServers": {
    "postgres": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-postgres"]
    }
  }
}
"#,
    );
    sb.write(
        ".claude.json",
        r#"{
  "numStartups": 17,
  "theme": "dark",
  "mcpServers": {
    "sentry": {
      "type": "http",
      "url": "https://mcp.sentry.dev/mcp"
    }
  },
  "projects": {
    "/work/somewhere": {
      "allowedTools": []
    }
  }
}
"#,
    );

    let out = sb.vibrev(&[
        "install",
        "--all",
        "--client",
        "claude-code",
        "--client",
        "cursor",
        "--client",
        "vscode",
        "--client",
        "codex",
        "--yes",
    ]);
    assert!(out.status.success(), "{}", stderr(&out));

    assert_golden(
        "vscode.mcp.json",
        &sb.normalize(&sb.read(".config/Code/User/mcp.json")),
    );
    assert_golden(
        "codex.config.toml",
        &sb.normalize(&sb.read(".codex/config.toml")),
    );
    assert_golden(
        "cursor.mcp.json",
        &sb.normalize(&sb.read(".cursor/mcp.json")),
    );
    assert_golden(
        "claude.claude.json",
        &sb.normalize(&sb.read(".claude.json")),
    );

    // Not a golden file, because these are the properties that matter and they
    // should fail with a clear message rather than as a diff.
    let vscode = sb.read(".config/Code/User/mcp.json");
    assert!(vscode.contains("keep the comments!"), "line comment lost");
    assert!(
        vscode.contains("// never inline the secret"),
        "trailing comment lost"
    );
    assert!(
        vscode.contains("/* Fetches web pages. */"),
        "block comment lost"
    );
    assert!(vscode.contains("\"gh-token\""), "inputs section lost");

    let codex = sb.read(".codex/config.toml");
    assert!(
        codex.contains("# The user's own provider block."),
        "TOML comment lost"
    );
    assert!(
        codex.contains("[model_providers.openai]"),
        "unrelated section lost"
    );
    assert!(codex.contains("[mcp_servers.other]"), "other server lost");

    assert!(sb.read(".claude.json").contains("\"numStartups\": 17"));
    assert!(sb.read(".cursor/mcp.json").contains("server-postgres"));

    // Both engines landed in each client, under that client's own top-level key.
    // VS Code is excluded here on purpose: its file is JSONC and `serde_json`
    // cannot read it — which is exactly why it is not written with `serde_json`
    // either.
    for (file, key) in [
        (".cursor/mcp.json", "mcpServers"),
        (".claude.json", "mcpServers"),
    ] {
        let v: serde_json::Value = serde_json::from_str(&sb.read(file)).unwrap();
        assert!(v[key]["vibrev-ida"]["command"].is_string(), "{file}");
        assert_eq!(v[key]["vibrev-jadx"]["args"][0], "mcp", "{file}");
    }
    assert!(vscode.contains("\"vibrev-ida\""));
    assert!(vscode.contains("\"vibrev-jadx\""));
    assert!(vscode.contains("\"type\": \"stdio\""));
}

// ---------------------------------------------------------- delegate path ---

/// A client CLI on `PATH` does not change the default.
///
/// One file with comments, run twice — once as it ships, once with `--delegate`.
/// The difference is the decision: the default keeps the user's comments and the
/// delegated path loses the ones attached to `[mcp_servers]`, which is what the
/// real `codex mcp add` does.
#[test]
fn the_default_is_a_direct_write_even_with_a_client_cli_on_path() {
    const COMMENTED: &str = r#"model = "o3"

# 这个 server 是我自己加的
[mcp_servers.other]
command = "npx"
# 别删这行
args = ["-y", "some-other-server"]
"#;

    let sb = sandbox("default-direct");
    sb.install_stubs();
    sb.write(".codex/config.toml", COMMENTED);

    let out = sb.vibrev(&["install", "jadx", "--client", "codex", "--yes"]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(stdout(&out).contains("[直接写入]"), "{}", stdout(&out));
    assert!(stdout(&out).contains("将产生的改动:"), "{}", stdout(&out));
    assert_eq!(sb.cli_log(), "", "no client CLI may run without --delegate");

    let direct = sb.read(".codex/config.toml");
    assert!(direct.contains("[mcp_servers.vibrev-jadx]"), "{direct}");
    assert!(direct.contains("# 这个 server 是我自己加的"), "{direct}");
    assert!(direct.contains("# 别删这行"), "{direct}");

    // The other half of the decision: asking for delegation really does hand the
    // file over, and really does cost the comments.
    let dlg = sandbox("default-direct-delegated");
    dlg.install_stubs();
    dlg.write(".codex/config.toml", COMMENTED);

    let out = dlg.vibrev(&[
        "install",
        "jadx",
        "--client",
        "codex",
        "--delegate",
        "--yes",
    ]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(
        stdout(&out).contains("[委派 codex CLI]"),
        "{}",
        stdout(&out)
    );
    assert!(!dlg.cli_log().is_empty(), "the client CLI should have run");

    let delegated = dlg.read(".codex/config.toml");
    assert!(
        delegated.contains("[mcp_servers.vibrev-jadx]"),
        "{delegated}"
    );
    assert!(
        !delegated.contains("# 别删这行"),
        "the stub models `codex mcp add`, which drops mcp_servers comments; if \
         this ever starts passing, re-measure upstream:\n{delegated}"
    );
}

#[test]
fn delegation_runs_the_client_cli_and_tolerates_its_expected_failures() {
    let sb = sandbox("delegate");
    sb.install_stubs();

    let out = sb.vibrev(&[
        "install",
        "jadx",
        "--client",
        "claude-code",
        "--client",
        "codex",
        "--client",
        "vscode",
        "--delegate",
        "--yes",
    ]);
    assert!(out.status.success(), "{}", stderr(&out));

    let text = stdout(&out);
    assert!(text.contains("[委派 claude CLI]"), "{text}");
    assert!(text.contains("[委派 codex CLI]"), "{text}");
    assert!(text.contains("[委派 code CLI]"), "{text}");
    // Delegation previews commands; it must never claim to know the diff.
    assert!(text.contains("将执行的命令:"), "{text}");
    assert!(!text.contains("将产生的改动:"), "{text}");

    let log = sb.cli_log();
    // Claude needs remove-then-add, and the remove fails on a first install —
    // which must not abort the run.
    assert!(log.contains("mcp remove vibrev-jadx --scope user"), "{log}");
    assert!(log.contains("mcp add-json vibrev-jadx"), "{log}");
    assert!(log.contains("mcp add vibrev-jadx --"), "{log}");
    assert!(log.contains("--add-mcp"), "{log}");

    // The stubs really wrote the files, so the argv we build is usable.
    let claude: serde_json::Value = serde_json::from_str(&sb.read(".claude.json")).unwrap();
    assert_eq!(claude["mcpServers"]["vibrev-jadx"]["type"], "stdio");
    assert_eq!(claude["mcpServers"]["vibrev-jadx"]["args"][1], "--stdio");

    assert!(
        sb.read(".codex/config.toml")
            .contains("[mcp_servers.vibrev-jadx]")
    );

    let vscode: serde_json::Value =
        serde_json::from_str(&sb.read(".config/Code/User/mcp.json")).unwrap();
    assert_eq!(vscode["servers"]["vibrev-jadx"]["type"], "stdio");
    // `name` belongs to `--add-mcp`'s argument, not to the entry.
    assert!(vscode["servers"]["vibrev-jadx"].get("name").is_none());
}

#[test]
fn delegation_is_skipped_where_the_cli_cannot_do_the_job() {
    let sb = sandbox("delegate-scope");
    sb.install_stubs();

    // `code --add-mcp` writes the user profile only, so project scope is a direct
    // write even when `--delegate` is asked for and `code` is right there on PATH.
    let out = sb.vibrev(&[
        "install",
        "jadx",
        "--client",
        "vscode",
        "--scope",
        "project",
        "--delegate",
        "--yes",
    ]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(stdout(&out).contains("[直接写入]"), "{}", stdout(&out));
    assert_eq!(sb.cli_log(), "", "no CLI should have run");

    let body = std::fs::read_to_string(sb.proj.join(".vscode/mcp.json")).unwrap();
    assert!(body.contains("\"servers\""));
    assert!(body.contains("vibrev-jadx"));
    // And the user profile was not touched.
    assert!(!sb.exists(".config/Code/User/mcp.json"));
}

#[test]
fn a_failing_client_cli_fails_the_command() {
    let sb = sandbox("delegate-failure");
    sb.install_stubs();
    // Replace the stub with one that always fails, as a broken/renamed upstream
    // subcommand would.
    write_exec(
        &sb.bin.join("codex"),
        "#!/bin/sh\necho 'unknown subcommand' >&2\nexit 3\n",
    );

    let out = sb.vibrev(&[
        "install",
        "jadx",
        "--client",
        "codex",
        "--delegate",
        "--yes",
    ]);
    assert!(!out.status.success());
    let err = stderr(&out);
    assert!(err.starts_with("Error: "), "{err}");
    assert!(err.contains("退出码 3"), "{err}");
    assert!(err.contains("unknown subcommand"), "{err}");
}

// ------------------------------------------------------------ idempotency ---

#[test]
fn installing_twice_updates_in_place_and_never_duplicates() {
    let sb = sandbox("idempotent");

    let first = sb.vibrev(&["install", "jadx", "--client", "cursor", "--yes"]);
    assert!(first.status.success(), "{}", stderr(&first));
    assert!(
        stdout(&first).contains("新增  vibrev-jadx"),
        "{}",
        stdout(&first)
    );

    // Second run, same engine path: nothing to do at all.
    let second = sb.vibrev(&["install", "jadx", "--client", "cursor", "--yes"]);
    assert!(second.status.success(), "{}", stderr(&second));
    let text = stdout(&second);
    assert!(text.contains("无变化  vibrev-jadx"), "{text}");
    assert!(text.contains("所有条目均已是最新"), "{text}");
    assert!(
        !text.contains("新增"),
        "a re-run must not report an add: {text}"
    );

    // Move the engine; the entry is edited where it sits.
    let cfg = sb.home.join(".vibrev").join("config.toml");
    let moved = sb.home.join("elsewhere").join("rjadx");
    std::fs::create_dir_all(moved.parent().unwrap()).unwrap();
    write_exec(&moved, "#!/bin/sh\nexit 0\n");
    std::fs::write(
        &cfg,
        format!("[engines.jadx]\npath = \"{}\"\n", moved.display()),
    )
    .unwrap();

    let third = sb.vibrev(&["install", "jadx", "--client", "cursor", "--yes"]);
    assert!(third.status.success(), "{}", stderr(&third));
    assert!(
        stdout(&third).contains("更新  vibrev-jadx"),
        "{}",
        stdout(&third)
    );

    let body = sb.read(".cursor/mcp.json");
    assert_eq!(
        body.matches("vibrev-jadx").count(),
        1,
        "duplicated entry:\n{body}"
    );
    assert!(!body.contains("vibrev-jadx-2"));
    assert!(body.contains(&moved.display().to_string()));
}

#[test]
fn dry_run_says_add_the_first_time_and_update_the_second() {
    let sb = sandbox("dryrun-wording");

    let preview = sb.vibrev(&["install", "jadx", "--client", "cursor", "--dry-run"]);
    assert!(preview.status.success(), "{}", stderr(&preview));
    assert!(stdout(&preview).contains("新增  vibrev-jadx"));
    assert!(stdout(&preview).contains("--dry-run：未写入任何文件"));
    assert!(
        !sb.exists(".cursor/mcp.json"),
        "--dry-run must not create files"
    );

    sb.vibrev(&["install", "jadx", "--client", "cursor", "--yes"]);

    // Same engine, new path → the preview says "update", not "add".
    let moved = sb.home.join("elsewhere").join("rjadx");
    std::fs::create_dir_all(moved.parent().unwrap()).unwrap();
    write_exec(&moved, "#!/bin/sh\nexit 0\n");
    std::fs::write(
        sb.home.join(".vibrev").join("config.toml"),
        format!("[engines.jadx]\npath = \"{}\"\n", moved.display()),
    )
    .unwrap();

    let again = sb.vibrev(&["install", "jadx", "--client", "cursor", "--dry-run"]);
    let text = stdout(&again);
    assert!(text.contains("更新  vibrev-jadx"), "{text}");
    assert!(text.contains("将产生的改动:"), "{text}");
    // The diff is a real diff of the real file.
    assert!(text.contains("--- ~/.cursor/mcp.json"), "{text}");
    assert!(text.contains('+'), "{text}");
    // Still not written.
    assert!(!sb.read(".cursor/mcp.json").contains("elsewhere"));
}

#[test]
fn dry_run_json_reports_the_plan_without_writing() {
    let sb = sandbox("dryrun-json");
    let out = sb.vibrev(&[
        "--json",
        "install",
        "jadx",
        "--client",
        "cursor",
        "--dry-run",
    ]);
    assert!(out.status.success(), "{}", stderr(&out));

    let v: serde_json::Value = serde_json::from_str(&stdout(&out)).unwrap();
    assert_eq!(v["ok"], true);
    assert_eq!(v["dryRun"], true);
    assert_eq!(v["command"], "install");
    assert_eq!(v["actions"][0]["client"], "cursor");
    assert_eq!(v["actions"][0]["method"], "direct");
    assert_eq!(v["actions"][0]["changes"][0]["op"], "add");
    assert_eq!(v["actions"][0]["changes"][0]["server"], "vibrev-jadx");
    assert!(!sb.exists(".cursor/mcp.json"));
}

// -------------------------------------------------- refusals and backups ----

/// The single most important failure mode: a config we cannot parse must abort,
/// never be "repaired" into an empty document.
#[test]
fn a_broken_config_aborts_instead_of_being_rebuilt() {
    let sb = sandbox("broken-config");
    let broken = "{\n  \"mcpServers\": {\n    \"a\": { \"command\": \"x\" }\n";
    sb.write(".cursor/mcp.json", broken);

    let out = sb.vibrev(&["install", "jadx", "--client", "cursor", "--yes"]);
    assert!(
        !out.status.success(),
        "a broken config must not be written over"
    );

    let err = stderr(&out);
    assert!(err.starts_with("Error: "), "{err}");
    assert!(err.contains("解析"), "{err}");
    assert!(err.contains(".cursor/mcp.json"), "{err}");

    assert_eq!(sb.read(".cursor/mcp.json"), broken, "the file was modified");
    assert!(
        !sb.exists(".cursor/mcp.json.bak"),
        "no .bak should exist yet"
    );
}

#[test]
fn broken_toml_aborts_too_and_reports_json_errors_on_stdout() {
    let sb = sandbox("broken-toml");
    let broken = "[mcp_servers.a\ncommand = \"x\"\n";
    sb.write(".codex/config.toml", broken);

    let out = sb.vibrev(&["--json", "install", "jadx", "--client", "codex", "--yes"]);
    assert!(!out.status.success());

    // `--json` failures are a document on stdout, so a caller parses one stream
    // and never has to guess which.
    let v: serde_json::Value = serde_json::from_str(&stdout(&out)).unwrap();
    assert_eq!(v["ok"], false);
    assert!(v["message"].as_str().unwrap().contains("解析"));
    assert_eq!(sb.read(".codex/config.toml"), broken);
}

#[test]
fn a_backup_is_taken_once_and_never_clobbered() {
    let sb = sandbox("backup");
    let original = "{\n  \"mcpServers\": {}\n}\n";
    sb.write(".cursor/mcp.json", original);

    let first = sb.vibrev(&["install", "jadx", "--client", "cursor", "--yes"]);
    assert!(first.status.success(), "{}", stderr(&first));
    assert!(
        stdout(&first).contains("已备份原文件到"),
        "{}",
        stdout(&first)
    );
    assert_eq!(sb.read(".cursor/mcp.json.bak"), original);

    // A later install must not overwrite the pre-vibrev snapshot.
    let moved = sb.home.join("elsewhere").join("rjadx");
    std::fs::create_dir_all(moved.parent().unwrap()).unwrap();
    write_exec(&moved, "#!/bin/sh\nexit 0\n");
    std::fs::write(
        sb.home.join(".vibrev").join("config.toml"),
        format!("[engines.jadx]\npath = \"{}\"\n", moved.display()),
    )
    .unwrap();

    let second = sb.vibrev(&["install", "jadx", "--client", "cursor", "--yes"]);
    assert!(second.status.success(), "{}", stderr(&second));
    assert_eq!(
        sb.read(".cursor/mcp.json.bak"),
        original,
        ".bak must still be the file as it was before vibrev ever ran"
    );
    assert!(sb.read(".cursor/mcp.json").contains("vibrev-jadx"));
}

#[test]
fn a_missing_engine_is_refused_with_its_install_guidance() {
    let sb = sandbox("missing-engine");

    let out = sb.vibrev(&["install", "bn", "--client", "cursor", "--yes"]);
    assert!(!out.status.success());
    let err = stderr(&out);
    assert!(err.contains("bn-headless-mcp"), "{err}");
    assert!(
        err.contains("Binary Ninja"),
        "guidance from the registry: {err}"
    );
    assert!(
        !err.contains("尚未建立"),
        "BN repo exists; guidance is stale:\n{err}"
    );
    assert!(!sb.exists(".cursor/mcp.json"), "nothing may be written");
}

#[test]
fn all_skips_engines_that_are_not_installed() {
    let sb = sandbox("all-skips");
    // Only ida and jadx exist in the sandbox; bn does not.
    let out = sb.vibrev(&[
        "--json",
        "install",
        "--all",
        "--client",
        "cursor",
        "--dry-run",
    ]);
    assert!(out.status.success(), "{}", stderr(&out));

    let v: serde_json::Value = serde_json::from_str(&stdout(&out)).unwrap();
    let engines: Vec<&str> = v["actions"][0]["changes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["engine"].as_str().unwrap())
        .collect();
    assert_eq!(engines, ["ida", "jadx"], "bn is not installed here");
}

// ------------------------------------------------------------ scope rules ---

#[test]
fn codex_has_no_project_scope_and_says_so() {
    let sb = sandbox("codex-project");
    let out = sb.vibrev(&[
        "install", "jadx", "--client", "codex", "--scope", "project", "--yes",
    ]);
    assert!(
        !out.status.success(),
        "nothing to do is an error, not a silent no-op"
    );
    let text = format!("{}{}", stdout(&out), stderr(&out));
    assert!(text.contains("没有项目级作用域"), "{text}");
    assert!(!sb.proj.join(".codex").exists());
}

// ------------------------------------------------------- credentials in git ---
//
// Project scope writes files that live in the repository and are normally
// committed. A Bearer token in one of them reaches the remote, and stays in the
// history after it is deleted — so the behaviour when vibrev meets one has to be
// pinned, not left to whatever the merge happens to do.
//
// vibrev cannot currently *write* a token: every entry it emits is stdio, and
// `ServerSpec` has no field for one. The reachable form of the leak is therefore
// an entry that already carries one — hand-written, left by another tool, or
// copied from a documented HTTP snippet — which vibrev then rewrites.

/// The documented snippet for the HTTP option, already in place.
const LEAKY_MCP_JSON: &str = r#"{
  "mcpServers": {
    "vibrev-jadx": {
      "type": "http",
      "url": "http://127.0.0.1:8745/mcp",
      "headers": { "Authorization": "Bearer vbr_LEAKED" }
    }
  }
}
"#;

#[test]
fn a_token_in_a_committed_file_is_removed_and_rotation_is_demanded() {
    let sb = sandbox("project-token");
    sb.write_proj(".mcp.json", LEAKY_MCP_JSON);

    let out = sb.vibrev(&[
        "install",
        "jadx",
        "--client",
        "claude-code",
        "--scope",
        "project",
        "--yes",
    ]);
    assert!(out.status.success(), "{}", stderr(&out));

    let after = sb.read_proj(".mcp.json");
    assert!(
        !after.contains("vbr_LEAKED"),
        "token survived the rewrite:\n{after}"
    );
    assert!(!after.contains("Authorization"), "{after}");
    assert!(!after.contains("8745"), "stale url survived:\n{after}");
    assert!(after.contains("\"type\": \"stdio\""), "{after}");

    // Removing it is only half the remedy, so the other half has to be said out
    // loud: the file is in git, and deleting a committed secret is not enough.
    let text = stdout(&out);
    assert!(text.contains("凭据"), "no credential warning:\n{text}");
    assert!(
        text.contains("git log"),
        "no way to check whether it was committed:\n{text}"
    );
    assert!(text.contains("作废并重签"), "no revocation advice:\n{text}");
    assert!(
        text.contains("vibrev token rotate"),
        "rotation is the remedy:\n{text}"
    );

    // And nothing anywhere in the project may still hold the secret — the whole
    // directory is what gets committed, not just the file we edited.
    let leaked = leaky_files(&sb.proj);
    assert!(
        leaked.is_empty(),
        "secret still in the project dir: {leaked:?}"
    );
}

/// Every file under `dir` still containing the test token.
fn leaky_files(dir: &Path) -> Vec<PathBuf> {
    let mut hits = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        for e in std::fs::read_dir(&d).into_iter().flatten().flatten() {
            let p = e.path();
            if p.is_dir() {
                stack.push(p);
            } else if std::fs::read(&p)
                .map(|b| String::from_utf8_lossy(&b).contains("vbr_LEAKED"))
                .unwrap_or(false)
            {
                hits.push(p);
            }
        }
    }
    hits
}

#[test]
fn the_backup_of_a_committed_file_is_kept_out_of_the_repository() {
    // The backup is a verbatim copy, so it holds the credential we just removed.
    // A sibling `.mcp.json.bak` is untracked and unignored: `git add .` commits
    // the very secret the strip was for.
    let sb = sandbox("project-token-backup");
    sb.write_proj(".mcp.json", LEAKY_MCP_JSON);

    let out = sb.vibrev(&[
        "install",
        "jadx",
        "--client",
        "claude-code",
        "--scope",
        "project",
        "--yes",
    ]);
    assert!(out.status.success(), "{}", stderr(&out));

    assert!(
        !sb.proj.join(".mcp.json.bak").exists(),
        "backup landed in the repo"
    );
    assert!(
        leaky_files(&sb.proj).is_empty(),
        "{:?}",
        leaky_files(&sb.proj)
    );

    // The backup still has to exist somewhere: it is the user's undo, and
    // deleting the leak by deleting the safety net would be a bad trade.
    let kept = leaky_files(&sb.home);
    assert_eq!(kept.len(), 1, "expected exactly one backup copy: {kept:?}");
    assert!(
        kept[0].starts_with(sb.home.join(".vibrev").join("backups")),
        "backup went to {:?}",
        kept[0]
    );
    assert!(stdout(&out).contains("已备份原文件到"), "{}", stdout(&out));

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&kept[0]).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "a backup holding a credential must not be world-readable"
        );
    }
}

#[test]
fn a_global_backup_still_sits_next_to_the_file() {
    // Only version-controlled scopes move. `~/.claude.json.bak` is where a user
    // looks for their undo, and nothing there is going to be committed.
    let sb = sandbox("global-token-backup");
    sb.write(".claude.json", LEAKY_MCP_JSON);

    let out = sb.vibrev(&["install", "jadx", "--client", "claude-code", "--yes"]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(
        sb.exists(".claude.json.bak"),
        "backup should stay beside the file"
    );
    assert!(sb.read(".claude.json.bak").contains("vbr_LEAKED"));
}

#[test]
fn the_same_token_in_a_global_file_is_removed_without_demanding_rotation() {
    // `~/.claude.json` is not in anyone's repository, so the deletion really is
    // the whole fix. Telling the user to rotate here would be crying wolf.
    let sb = sandbox("global-token");
    sb.write(".claude.json", LEAKY_MCP_JSON);

    let out = sb.vibrev(&["install", "jadx", "--client", "claude-code", "--yes"]);
    assert!(out.status.success(), "{}", stderr(&out));

    let after = sb.read(".claude.json");
    assert!(!after.contains("vbr_LEAKED"), "{after}");

    let text = stdout(&out);
    assert!(
        text.contains("凭据"),
        "the removal is still worth reporting:\n{text}"
    );
    assert!(
        !text.contains("vibrev token rotate"),
        "no rotation needed here:\n{text}"
    );
}

#[test]
fn dry_run_reports_the_credential_without_touching_the_file() {
    let sb = sandbox("project-token-dry");
    sb.write_proj(".mcp.json", LEAKY_MCP_JSON);

    let out = sb.vibrev(&[
        "install",
        "jadx",
        "--client",
        "claude-code",
        "--scope",
        "project",
        "--dry-run",
    ]);
    assert!(out.status.success(), "{}", stderr(&out));

    let text = stdout(&out);
    assert!(text.contains("凭据"), "{text}");
    // The value itself must not reach stdout: `--dry-run` in CI would copy it
    // into the build log, which is a fresh distribution channel for the secret.
    assert!(
        !text.contains("vbr_LEAKED"),
        "the preview printed the credential:\n{text}"
    );
    // Masked, not silently dropped — the user still has to see that a `headers`
    // key is going away, and that what they cannot read is hidden, not rewritten.
    assert!(text.contains("‹凭据已遮蔽›"), "no mask marker:\n{text}");
    assert!(
        text.contains("headers"),
        "the structural change is still shown:\n{text}"
    );
    assert!(
        text.contains("逐字相同"),
        "the weakened guarantee is not stated:\n{text}"
    );

    // A preview that edited the file would be the worst of both worlds.
    assert_eq!(sb.read_proj(".mcp.json"), LEAKY_MCP_JSON);
    assert!(
        !sb.proj.join(".mcp.json.bak").exists(),
        "dry-run must not back up"
    );
}

#[test]
fn json_mode_flags_the_credential_and_whether_rotation_is_needed() {
    let sb = sandbox("project-token-json");
    sb.write_proj(".mcp.json", LEAKY_MCP_JSON);

    let out = sb.vibrev(&[
        "--json",
        "install",
        "jadx",
        "--client",
        "claude-code",
        "--scope",
        "project",
        "--yes",
    ]);
    assert!(out.status.success(), "{}", stderr(&out));

    let doc: serde_json::Value = serde_json::from_str(&stdout(&out)).unwrap();
    let change = &doc["actions"][0]["changes"][0];
    assert_eq!(change["strippedCredentials"], true, "{doc:#}");
    assert_eq!(change["rotateRequired"], true, "{doc:#}");
    assert!(!sb.read_proj(".mcp.json").contains("vbr_LEAKED"));

    // The ordinary case must stay quiet, or the field is noise nobody reads.
    let sb2 = sandbox("no-token-json");
    let out2 = sb2.vibrev(&[
        "--json",
        "install",
        "jadx",
        "--client",
        "claude-code",
        "--yes",
    ]);
    let doc2: serde_json::Value = serde_json::from_str(&stdout(&out2)).unwrap();
    assert!(
        doc2["actions"][0]["changes"][0]["strippedCredentials"].is_null(),
        "{doc2:#}"
    );
}

#[test]
fn delegation_does_not_claim_a_removal_it_cannot_perform() {
    // Under --delegate the file is written by the client's own CLI. We do not
    // control what it keeps, so the honest report is "there is a token here and
    // vibrev is not the one removing it" — never a removal we did not do.
    let sb = sandbox("delegate-token");
    sb.install_stubs();
    sb.write(".claude.json", LEAKY_MCP_JSON);

    let out = sb.vibrev(&[
        "install",
        "jadx",
        "--client",
        "claude-code",
        "--delegate",
        "--yes",
    ]);
    assert!(out.status.success(), "{}", stderr(&out));

    let text = stdout(&out);
    assert!(text.contains("凭据"), "{text}");
    assert!(
        text.contains("vibrev 不会移除"),
        "must not claim a removal:\n{text}"
    );
}

#[test]
fn project_scope_writes_beside_the_project_not_the_home() {
    let sb = sandbox("project-scope");
    let out = sb.vibrev(&[
        "install",
        "jadx",
        "--client",
        "cursor",
        "--client",
        "claude-code",
        "--scope",
        "project",
        "--yes",
    ]);
    assert!(out.status.success(), "{}", stderr(&out));

    assert!(sb.proj.join(".cursor/mcp.json").exists());
    assert!(sb.proj.join(".mcp.json").exists());
    assert!(!sb.exists(".cursor/mcp.json"));
    assert!(!sb.exists(".claude.json"));
}

// ------------------------------------------------- confirmation semantics ---

/// A pipe cannot answer a prompt, so the command must refuse rather than hang.
#[test]
fn a_non_tty_without_yes_refuses_instead_of_blocking() {
    let sb = sandbox("non-tty");
    let out = sb.vibrev(&["install", "jadx", "--client", "cursor"]);
    assert!(!out.status.success());
    assert!(stderr(&out).contains("--yes"), "{}", stderr(&out));
    assert!(!sb.exists(".cursor/mcp.json"), "nothing may be written");
    // The preview still printed: the user should see what they were about to do.
    assert!(stdout(&out).contains("将产生的改动:"));
}

/// `--json` has no prompt to fall back on either, so the same rule applies.
#[test]
fn json_mode_also_needs_yes_before_it_writes() {
    let sb = sandbox("json-needs-yes");
    let out = sb.vibrev(&["--json", "install", "jadx", "--client", "cursor"]);
    assert!(!out.status.success());

    let v: serde_json::Value = serde_json::from_str(&stdout(&out)).unwrap();
    assert_eq!(v["ok"], false);
    assert!(v["message"].as_str().unwrap().contains("--yes"));
    assert!(!sb.exists(".cursor/mcp.json"));

    // With `--yes` it goes through and reports `dryRun: false`.
    let ok = sb.vibrev(&["--json", "install", "jadx", "--client", "cursor", "--yes"]);
    assert!(ok.status.success(), "{}", stderr(&ok));
    let v: serde_json::Value = serde_json::from_str(&stdout(&ok)).unwrap();
    assert_eq!(v["dryRun"], false);
    assert_eq!(v["actions"][0]["changes"][0]["op"], "add");
    assert!(sb.read(".cursor/mcp.json").contains("vibrev-jadx"));
}

#[test]
fn piped_output_carries_no_colour_escapes() {
    let sb = sandbox("no-color");
    let out = sb.vibrev(&["install", "jadx", "--client", "cursor", "--dry-run"]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(
        !stdout(&out).contains('\u{1b}'),
        "escape sequence in a pipe"
    );
}

// ------------------------------------------------------ uninstall and list ---

#[test]
fn uninstall_removes_only_our_entries() {
    let sb = sandbox("uninstall");
    sb.write(
        ".cursor/mcp.json",
        r#"{
  "mcpServers": {
    "keepme": { "command": "npx", "args": ["-y", "keepme"] }
  }
}
"#,
    );
    let install = sb.vibrev(&["install", "--all", "--client", "cursor", "--yes"]);
    assert!(install.status.success(), "{}", stderr(&install));
    assert!(sb.read(".cursor/mcp.json").contains("vibrev-ida"));

    let out = sb.vibrev(&["uninstall", "--client", "cursor", "--yes"]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(
        stdout(&out).contains("移除  vibrev-ida"),
        "{}",
        stdout(&out)
    );

    let body = sb.read(".cursor/mcp.json");
    assert!(body.contains("keepme"), "{body}");
    assert!(!body.contains("vibrev-"), "{body}");
    assert!(body.contains("mcpServers"), "the container stays: {body}");
}

#[test]
fn uninstall_never_creates_a_file_that_was_not_there() {
    let sb = sandbox("uninstall-absent");
    let out = sb.vibrev(&["uninstall", "--client", "cursor", "--yes"]);
    assert!(!out.status.success(), "there was nothing to do");
    assert!(!sb.exists(".cursor/mcp.json"));
}

#[test]
fn uninstall_works_after_the_engine_binary_is_gone() {
    let sb = sandbox("uninstall-no-binary");
    let install = sb.vibrev(&["install", "jadx", "--client", "cursor", "--yes"]);
    assert!(install.status.success(), "{}", stderr(&install));

    std::fs::remove_file(sb.home.join(".vibrev/engines/rjadx")).unwrap();

    let out = sb.vibrev(&["uninstall", "jadx", "--client", "cursor", "--yes"]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(!sb.read(".cursor/mcp.json").contains("vibrev-jadx"));
}

#[test]
fn list_reports_what_is_configured_and_where() {
    let sb = sandbox("list");
    sb.write(
        ".cursor/mcp.json",
        "{\n  \"mcpServers\": {\n    \"keepme\": { \"command\": \"npx\" }\n  }\n}\n",
    );
    sb.vibrev(&[
        "install", "--all", "--client", "cursor", "--client", "codex", "--yes",
    ]);
    sb.vibrev(&[
        "install", "jadx", "--client", "vscode", "--scope", "project", "--yes",
    ]);

    let human = sb.vibrev(&["list"]);
    assert!(human.status.success(), "{}", stderr(&human));
    let text = stdout(&human);
    assert!(text.contains("vibrev-ida"), "{text}");
    assert!(text.contains("vibrev-jadx"), "{text}");
    assert!(text.contains("Cursor"), "{text}");
    assert!(text.contains("Codex"), "{text}");
    assert!(text.contains("project"), "{text}");
    assert!(!text.contains("keepme"), "only vibrev entries: {text}");

    let json = sb.vibrev(&["--json", "list"]);
    let v: serde_json::Value = serde_json::from_str(&stdout(&json)).unwrap();
    let servers = v["servers"].as_array().unwrap();
    assert!(
        servers
            .iter()
            .all(|s| s["server"].as_str().unwrap().starts_with("vibrev-"))
    );
    assert!(
        servers
            .iter()
            .any(|s| s["client"] == "codex" && s["scope"] == "global")
    );
    assert!(
        servers
            .iter()
            .any(|s| s["client"] == "vscode" && s["scope"] == "project")
    );
    assert!(servers.iter().any(|s| s["args"][0] == "mcp"));
}

#[test]
fn list_on_a_fresh_machine_says_so() {
    let sb = sandbox("list-empty");
    let out = sb.vibrev(&["list"]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(
        stdout(&out).contains("还没有把任何引擎注册"),
        "{}",
        stdout(&out)
    );
}

// -------------------------------------------------------------- usage ------

#[test]
fn install_without_an_engine_explains_rather_than_guessing() {
    let sb = sandbox("usage");
    let out = sb.vibrev(&["install"]);
    assert!(!out.status.success());
    let err = stderr(&out);
    assert!(err.contains("install 需要指定引擎"), "{err}");
    assert!(err.contains("--all"), "{err}");
    // No half-built wizard: nothing was written and nothing was asked.
    assert!(!sb.exists(".cursor/mcp.json"));
}

#[test]
fn an_unknown_client_is_rejected_by_the_parser() {
    let sb = sandbox("usage-client");
    let out = sb.vibrev(&["install", "jadx", "--client", "zed"]);
    assert!(!out.status.success());
    assert!(stderr(&out).contains("zed"), "{}", stderr(&out));
}
