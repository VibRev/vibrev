# vibrev

English | [简体中文](README.zh-CN.md)

The shared runtime behind the VibRev reverse-engineering MCP engines, and the installer that wires them into your MCP clients.

This repository has two jobs that look unrelated and are not:

- **Four library crates** that the engines depend on by path, so that three separately-developed MCP servers present one surface.
- **One binary, `vibrev`**, that finds those engines on your machine and writes them into Claude Code / Cursor / VS Code / Codex.

They belong together because the interesting bugs live between them: a token file written by the installer and read by an engine, a `skills list --json` document printed by an engine and parsed by the installer. Neither program can see the other's source. Anything two VibRev programs must agree on lives here, as one type.

[![License: Apache 2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

## Crates

| Crate | Kind | What it is |
|---|---|---|
| [`vibrev`](crates/vibrev) | bin | Installer and dispatcher. Discovers engine binaries, writes MCP client config, execs into engine CLIs. Links no engine code. |
| [`vibrev-kit`](crates/vibrev-kit) | lib | Shared engine runtime: CLI construction, schema normalization, tool policy, pagination, output caps, background tasks, HTTP transport. |
| [`vibrev-tool-macros`](crates/vibrev-tool-macros) | proc-macro | `#[vibrev_tool]` / `#[vibrev_tool_router]` — one definition drives both the MCP tool surface and the clap command tree. |
| [`vibrev-skills`](crates/vibrev-skills) | lib | Agent skills compiled into an engine binary: archive format, packer, and the two CLI verbs both sides agree on. |
| [`toy-engine`](crates/toy-engine) | bin | The reference engine. A second consumer of the shared crates that lives *inside* this repository. |

## The `vibrev` binary

```bash
vibrev doctor                      # what is installed, where, and what version
vibrev install --all               # project-scope HTTP (and skills) for every engine found
vibrev install ida --mode stdio    # client spawns the binary instead of connecting to a listener
vibrev install ida --scope global --client claude-code
vibrev list                        # which clients currently hold a vibrev entry
vibrev uninstall                   # no engine named = remove every vibrev-* entry
vibrev skill list                  # skills each engine offers, and their local state
vibrev token rotate                # new HTTP bearer token, rewrite installed HTTP configs
vibrev ida decompile main --limit 20   # anything unrecognised is passed to the engine
```

`--json` is global: human mode prints `Error: <msg>` to stderr and exits 1; `--json` prints `{"ok":false,…}` to stdout and exits 1, so a caller parses exactly one stream.

`doctor` always exits 0. It reports; it does not judge.

### Engines

| id | binary | domain |
|---|---|---|
| `ida` | `ida-headless-mcp` | IDA Pro |
| `bn` | `bn-headless-mcp` | Binary Ninja |
| `jadx` | `rjadx` | Android APK / DEX |

Discovery is four levels, first hit wins, and level 1 does not fall through:

1. `[engines.<id>] path` in `~/.vibrev/config.toml`
2. `~/.vibrev/engines/<bin>`
3. `PATH`
4. nothing found — print install guidance for that engine

The root is `~/.vibrev`, overridable with `VIBREV_HOME`. The installer and the engines resolve it through the same code, so setting it moves both.

### Clients

| id | client | file (global) | file (project) | format |
|---|---|---|---|---|
| `claude-code` | Claude Code | `~/.claude.json` | `./.mcp.json` | JSON |
| `cursor` | Cursor | `~/.cursor/mcp.json` | `./.cursor/mcp.json` | JSON |
| `vscode` | VS Code | `<config>/Code/User/mcp.json` | `./.vscode/mcp.json` | JSONC |
| `vscode-insiders` | VS Code Insiders | `<config>/Code - Insiders/User/mcp.json` | `./.vscode/mcp.json` | JSONC |
| `codex` | Codex | `~/.codex/config.toml` | `./.codex/config.toml` | TOML |
| `claude-desktop` | Claude Desktop | `<config>/Claude/claude_desktop_config.json` | — | JSON |
| `windsurf` | Windsurf | `~/.codeium/windsurf/mcp_config.json` | `./.windsurf/mcp.json` | JSON |
| `zed` | Zed | `<config>/Zed/settings.json` | `./.zed/settings.json` | JSONC |
| `cline` | Cline | VS Code `globalStorage` | — | JSON |
| `roo` | Roo Code | VS Code `globalStorage` | — | JSON |
| `kilo` | Kilo Code | VS Code `globalStorage` | — | JSON |
| `lmstudio` | LM Studio | `~/.lmstudio/mcp.json` | — | JSON |
| `gemini` | Gemini CLI | `~/.gemini/settings.json` | — | JSONC |
| `qwen` | Qwen Coder | `~/.qwen/settings.json` | — | JSONC |
| `copilot` | Copilot CLI | `~/.copilot/mcp-config.json` | — | JSON |
| `amazonq` | Amazon Q | `~/.aws/amazonq/mcp_config.json` | — | JSON |
| `warp` | Warp | `~/.warp/mcp_config.json` | — | JSON |
| `kiro` | Kiro | `~/.kiro/mcp_config.json` | — | JSON |
| `trae` | Trae | `~/.trae/mcp_config.json` | — | JSON |
| `crush` | Crush | `~/crush.json` | — | JSON |

`--client` also accepts aliases (`roocode`, `amazon-q`, `vs-code-insiders`, …). Clients without a project file are skipped under `--scope project`. `install` without `--client` still only writes clients that look installed.

Edits are **format-preserving**: a `serde_json` round-trip would delete every comment in VS Code's `mcp.json`, so the JSONC and TOML paths go through `jsonc-parser` and `toml_edit` instead. Writes are atomic (temp file + rename) under an advisory lock, with a one-time `.bak` at mode 0600.

`install` defaults to **project** scope and **`--mode http`**. IDA and BN get a URL the operator's own process is expected to answer; `--mode stdio` writes a spawn instead. The bearer is copied from `~/.vibrev/token` into **global** HTTP entries by default (project-scope files are committed). `--with-token` writes it at project scope too; `--no-token` leaves it out of every file. The listener cannot be run unauthenticated, so a client entry with no `Authorization` header will 401:

```jsonc
"vibrev-ida": {
  "type": "http",
  "url": "http://127.0.0.1:8765/mcp",
  "headers": { "Authorization": "Bearer vbr_…" }
}
```

jadx has no listener, so it stays a stdio spawn:

```jsonc
"vibrev-jadx": { "command": "~/.vibrev/engines/rjadx", "args": ["mcp", "--stdio"] }
```

Start the HTTP engines yourself (`ida-headless-mcp` / `bn-headless-mcp`); they bind `127.0.0.1:8765` unless told otherwise.

A few flags are worth knowing:

- `--delegate` hands the write to the client's own CLI (`claude` / `codex` / `code`) instead of editing the file. It is **off by default** because it is lossy: `codex mcp add` reserializes `~/.codex/config.toml` and wipes the comments in its `[mcp_servers]` section.
- `--no-skills` writes MCP entries only. Skills go to `~/.claude/skills`; only Claude Code reads them, and a directory without the `.vibrev-skill.json` marker is never overwritten or deleted.
- `--mode http|stdio` chooses the transport. HTTP is the default; engines with no listener (jadx) stay stdio either way.
- `--with-token` / `--no-token` override the default of "bearer in global files, not in project files". They conflict with each other, and with `--mode stdio`.
- `--scope global` writes the machine-wide files. Default is project.

## `vibrev-kit`

The rule for what belongs here is *anything two VibRev programs have to agree on* — not merely "shared between engines". That is why `token` lives here: the installer is not an engine, but it opens the same file.

| Module | Job |
|---|---|
| `cli` | JSON Schema → `clap::Command`, and `ArgMatches` → tool arguments. A whitelist classifier: a construct it cannot map is reported, never silently dropped. |
| `contract` | The cross-engine tool-surface contract as something that *runs*. Scans a catalog, reports every departure. Mechanism here; per-engine lists passed in. |
| `decorate` | The only mirror of rmcp's full `ServerHandler` surface. Every `Decorator` method already forwards, so a decorator cannot silently drop a capability it never heard of. |
| `output` | The net under an answer too large to send: preview trimming plus a spill to a private file, bookkeeping under `_meta.vibrev`. |
| `page` | One definition of pagination arithmetic — offsets that actually advance, limits that clamp. |
| `policy` | Which tools an engine offers when the user asked for fewer. Everything on by default; flags only subtract. Read-only is derived from `readOnlyHint`, not from a hand-kept list. |
| `render` | Tool results → readable text. Bookkeeping is detected structurally, not by a list of field names. |
| `schema` | The JSON Schema vocabulary every face speaks. Reading half and rewriting half, written against each other. Normalization happens when the `Tool` is built, not when it is served. |
| `session` | The one value a tool call cannot get from its own schema: which session or database to work on. Models the slot, not the lifecycle. |
| `tasks` | Background work and the MCP Tasks face. Registry and protocol adapter only; *which* calls go to the background is the engine's decision. |
| `token` | The shared HTTP bearer token file `~/.vibrev/token`. Every line is accepted, which is what makes an interrupted rotation safe. Created `O_EXCL` at mode 0600 — never create-then-chmod. |
| `transport` | **`http` feature only.** The HTTP listener an engine puts in front of its MCP server. |

At the crate root: `ToolOutcome`, `Rendered<T>` (keeps `structuredContent` *and* puts readable text in `content`), `ToolDef`, `Advertised`, `engine_identity!`, and `parse_int` / `parse_unsigned` (accepting `184`, `0xb8`, `0b1011`).

### The `http` feature

Off by default. A stdio-only engine — and the installer, which speaks no protocol at all — should not compile axum just to reach `schema` and `policy`.

```toml
vibrev-kit = { version = "0.0.1", features = ["http"] }
```

`Listener::serve` takes the engine's `axum::Router` and layers the bearer gate over *all* of it. The engine never gets to say which routes are exempt, and `AccessPolicy.auth` is not an `Option`. **There is no way to serve unauthenticated.** Credential failures get 401 with `WWW-Authenticate`.

## `vibrev-tool-macros`

`#[vibrev_tool_router]` rewrites every `#[vibrev_tool]` in the block into `#[rmcp::tool]`, delegates to `#[rmcp::tool_router]`, and emits the CLI builder alongside — in one compilation unit, so the MCP surface and the CLI cannot drift.

```rust
#[vibrev_tool_router(group_about(binary = "Inspect mapped functions"))]
impl Toy {
    /// Liveness probe; returns the engine identity.
    #[vibrev_tool(verb = "ping", title = "Engine heartbeat",
                  annotations(read_only = true, idempotent = true))]
    pub async fn ping(&self) -> Result<Rendered<Pong>, ErrorData> { … }

    #[vibrev_tool(verb = "decompile", title = "Decompile function",
                  annotations(read_only = true, idempotent = true),
                  cli(positional = "func"))]
    pub async fn decompile(&self, Parameters(a): Parameters<DecompileArgs>)
        -> Result<Rendered<Decompiled>, ErrorData> { … }
}
```

`title` and `annotations(read_only = …)` are **required** — each is a compile error if missing. That is what lets `policy` derive read-only mode instead of keeping a deny list.

Generated on the impl block: `vibrev_tool_defs()`, `vibrev_cli(bin)`, `vibrev_call(name, args)`, `try_vibrev_call(…)`. The CLI path reaches the same function bodies through the same conversion the MCP router uses.

## `vibrev-skills`

An engine compiles its reference documentation into its own binary and exports it on demand. Three lines:

```text
build.rs        vibrev_skills::pack::pack(&root)?   -> OUT_DIR
src/skills.rs   vibrev_skills::embedded!()          -> Embedded
main.rs         args.run(&SKILLS, name, version)    -> `skills list` / `skills export`
```

The crate splits along a feature so a build script does not pay for a runtime:

```toml
[dependencies]       vibrev-skills = { path = "…" }                          # reader + the two verbs
[build-dependencies] vibrev-skills = { path = "…", default-features = false } # packer only, just flate2
```

Without that line a build script would link an MCP server library to read some Markdown — `vibrev-kit` pulls in rmcp, tokio and schemars. It is the same line `vibrev-kit` draws around axum.

The packer walks one directory with names sorted, so the archive is byte-identical across machines. Every field the installer reads is `#[serde(default)]`: an engine older than the installer answering `{}` reports "no skills" rather than "malformed", and `vibrev install --all` keeps going.

## Build and test

Edition 2024, MSRV **1.95**, resolver 3. Nothing here links a disassembler SDK, so a plain checkout builds.

```bash
cargo test --workspace --all-features
```

**`--all-features` is not optional.** `vibrev-kit`'s `http` feature is off by default, so without it the `transport` tests do not compile at all — while `cargo test -p vibrev-kit` still prints a green line. `toy-engine` has to run inside the workspace too: its contract scan runs against a real macro-derived catalog rather than a hand-built fixture.

Periodic, not a merge gate — these drive the real client CLIs against your real config files:

```bash
cargo test -p vibrev --test real_clients -- --ignored --nocapture
```

Golden files live in `crates/vibrev/tests/golden/` and refresh with `UPDATE_GOLDEN=1 cargo test`.

## Relationship to the engines

`vibrev` the binary links no engine code and sits on no request path. On Unix, dispatch is a real `execvp`: no fork, no supervisor left behind, so signals, job control, exit codes and terminal ownership are the engine's without anything having to forward them.

The *library* crates are a different story. An engine depends on `vibrev-kit` and `vibrev-tool-macros` — and, if it ships skills, on `vibrev-skills` — and they end up compiled into its request path. So a change here can break a program that is not in this repository, and nothing in this build would find out about it.

`contract` is what offsets that. It turns the cross-engine tool-surface agreement into a scan an engine runs over its own catalog in its own test suite, so a kit change that reshapes a schema, a title or a tool ordering fails there rather than in someone's client. Each engine passes its own lists in; kit holds the mechanism and never holds an engine's tool names. The scan touches no disassembler and needs no license — it builds its catalog from `#[vibrev_tool]` attributes alone.

Two files are contracts between programs that cannot see each other's source, which is why they are types in shared crates rather than prose in a comment:

- `~/.vibrev/token` — `vibrev token rotate` writes it, every engine listener reads it. One implementation: `vibrev_kit::token`.
- `<engine> skills list --json` — the engine prints it, `vibrev install` parses it. One type: `vibrev_skills::Listing`.

## License

Apache License 2.0 — see [LICENSE](LICENSE).
