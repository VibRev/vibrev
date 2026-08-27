//! The reference engine for the VibRev shared crates.
//!
//! It proves one tool definition drives both the MCP surface and the CLI, and it
//! gives those crates a second consumer that lives inside this repository — the
//! engines that ship are in repositories of their own.
//!
//! Five tools, defined once. `toy mcp` serves them over stdio MCP; `toy tool
//! <tool>` reaches the same function bodies through a clap tree built from the
//! same `Tool` structs. `mcp` is the sample *management* command, and it and the
//! tools stay out of each other's namespace. The tools deliberately cover the
//! awkward cases:
//!
//! * `ping`               — no parameters
//! * `decompile`          — positional argument, optional flag, boolean pair, enum
//! * `binary.functions`   — `group.verb` nesting, array parameter
//! * `annotation.rename`  — integer accepting `0x`, and a non-read-only annotation
//! * `report.build`       — a nested object, i.e. the case the CLI *cannot* map

use rmcp::{
    ErrorData, RoleServer, ServerHandler, ServiceExt,
    handler::server::wrapper::Parameters,
    model::{
        ListResourcesResult, PaginatedRequestParams, ReadResourceRequestParams,
        ReadResourceResponse, ReadResourceResult, Resource, ResourceContents, ServerCapabilities,
        ServerInfo,
    },
    service::RequestContext,
    tool_handler,
    transport::stdio,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use vibrev_kit::Rendered;
// `#[vibrev_tool]` needs no import: the router macro consumes it before name
// resolution. It stays exported so that using it *outside* a router still yields a
// pointed error rather than a bare "cannot find attribute".
use vibrev_tool_macros::vibrev_tool_router;

#[derive(Clone, Default)]
pub struct Toy;

#[derive(Debug, Clone, Copy, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum Dialect {
    C,
    Rust,
    Objc,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct DecompileArgs {
    /// 函数名或地址
    pub func: String,
    /// 最多返回多少行
    #[schemars(range(min = 1, max = 10000))]
    pub limit: Option<i64>,
    /// 是否包含函数体
    pub with_body: Option<bool>,
    /// 伪代码方言
    pub dialect: Option<Dialect>,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct Decompiled {
    pub c_code: String,
    /// `limit` 是否真的砍掉了内容。
    ///
    /// 没有这个字段，一段刚好 `limit` 行的伪代码和一段被砍成 `limit` 行的
    /// 伪代码是同一个回包 —— 调用方读到的是一个完整的函数，而不是一半。
    pub truncated: bool,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct FunctionsArgs {
    /// 名称过滤，可给多个
    pub filter: Option<Vec<String>>,
    /// 从第几条开始
    #[schemars(range(min = 0))]
    pub offset: Option<i64>,
    /// 分页上限
    #[schemars(range(min = 1, max = 1000))]
    pub limit: Option<i64>,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct FunctionInfo {
    pub name: String,
    pub addr: String,
    pub size: u32,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct FunctionPage {
    pub functions: Vec<FunctionInfo>,
    /// 匹配 `filter` 的总数，不是本页条数。
    pub total: usize,
    /// 下一页从第几条开始；没有下一页时是 null。
    pub next_offset: Option<usize>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct RenameArgs {
    /// 目标地址，接受 184 / 0xb8 / 0b1011
    pub addr: i64,
    /// 新名字
    pub new_name: String,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct Renamed {
    pub addr: String,
    pub new_name: String,
    pub ok: bool,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ReportSection {
    pub heading: String,
    pub body: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ReportArgs {
    /// 报告标题
    pub title: String,
    /// 嵌套结构 —— CLI 无法映射，走 --json-input
    pub section: ReportSection,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct Report {
    pub content: String,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct Pong {
    pub engine: String,
    pub ok: bool,
}

#[vibrev_tool_router(group_about(binary = "Inspect mapped functions"))]
impl Toy {
    /// Liveness probe; returns the engine identity.
    // The contract scan rejects a title that is the tool name with different
    // capitalisation — "Ping" here would spend a field the client shows in a
    // picker and say nothing the name did not.
    #[vibrev_tool(
        verb = "ping",
        title = "Engine heartbeat",
        annotations(read_only = true, idempotent = true)
    )]
    pub async fn ping(&self) -> Result<Rendered<Pong>, ErrorData> {
        Ok(Rendered(Pong {
            engine: "toy".into(),
            ok: true,
        }))
    }

    /// Decompile a function; returns pseudocode.
    #[vibrev_tool(
        verb = "decompile",
        title = "Decompile function",
        annotations(read_only = true, idempotent = true),
        cli(positional = "func")
    )]
    pub async fn decompile(
        &self,
        Parameters(a): Parameters<DecompileArgs>,
    ) -> Result<Rendered<Decompiled>, ErrorData> {
        let dialect = match a.dialect {
            Some(Dialect::Rust) => "rust",
            Some(Dialect::Objc) => "objc",
            Some(Dialect::C) | None => "c",
        };
        let mut code = format!("// {dialect}\nint {}(void)", a.func);
        if a.with_body.unwrap_or(true) {
            code.push_str(" {\n    return 0;\n}");
        } else {
            code.push(';');
        }
        // `limit` counts lines here, so there is no second page to fetch — the
        // caller either gets the whole function or is told they did not.
        let limit = vibrev_kit::page::capped(a.limit, 10_000, 10_000);
        let lines: Vec<&str> = code.lines().take(limit).collect();
        let truncated = lines.len() < code.lines().count();
        Ok(Rendered(Decompiled {
            c_code: lines.join("\n"),
            truncated,
        }))
    }

    /// List functions in the current binary.
    #[vibrev_tool(
        group = "binary",
        verb = "functions",
        title = "List functions",
        annotations(read_only = true, idempotent = true)
    )]
    pub async fn list_functions(
        &self,
        Parameters(a): Parameters<FunctionsArgs>,
    ) -> Result<Rendered<FunctionPage>, ErrorData> {
        let all = [
            ("main", "0x1000", 120u32),
            ("init", "0x1040", 64),
            ("fini", "0x1080", 32),
        ];
        // The whole of the wire-integer convention, in one line: both fields are
        // declared `i64` because a `uint32` in a published input schema is
        // rejected by strict consumers, and `bounds` is the way back — the
        // negative `offset` is refused rather than becoming 18446744073709551615,
        // and the absurd `limit` is clamped rather than refused.
        let (offset, limit) = vibrev_kit::page::bounds(a.offset, a.limit, 1000, 1000)
            .map_err(|e| ErrorData::invalid_params(e.to_string(), None))?;
        let wanted = a.filter.unwrap_or_default();
        let matched: Vec<FunctionInfo> = all
            .iter()
            .filter(|(n, _, _)| wanted.is_empty() || wanted.iter().any(|w| n.contains(w.as_str())))
            .map(|(n, addr, size)| FunctionInfo {
                name: (*n).into(),
                addr: (*addr).into(),
                size: *size,
            })
            .collect();
        // Paged after filtering, and `total` counts what matched. Reporting
        // `all.len()` here — which this did — tells a caller who filtered for
        // "main" that there are three of them.
        let page = vibrev_kit::page::Page::of(matched, offset, limit);
        Ok(Rendered(FunctionPage {
            functions: page.items,
            total: page.total,
            next_offset: page.next_offset,
        }))
    }

    /// Rename a function. Not read-only.
    #[vibrev_tool(
        group = "annotation",
        verb = "rename",
        title = "Rename function",
        annotations(read_only = false, destructive = false, idempotent = true),
        cli(int_args = "addr")
    )]
    pub async fn rename(
        &self,
        Parameters(a): Parameters<RenameArgs>,
    ) -> Result<Rendered<Renamed>, ErrorData> {
        Ok(Rendered(Renamed {
            addr: format!("{:#x}", a.addr),
            new_name: a.new_name,
            ok: true,
        }))
    }

    /// Build a report from a nested section object.
    #[vibrev_tool(
        group = "report",
        verb = "build",
        title = "Build report",
        annotations(read_only = true)
    )]
    pub async fn build_report(
        &self,
        Parameters(a): Parameters<ReportArgs>,
    ) -> Result<Rendered<Report>, ErrorData> {
        Ok(Rendered(Report {
            content: format!(
                "# {}\n\n## {}\n{}",
                a.title, a.section.heading, a.section.body
            ),
        }))
    }
}

/// The one resource this engine serves.
///
/// It exists so that this engine has a *second* capability besides tools. A
/// decorator that forwards `call_tool` and forgets the rest still looks correct
/// against a tools-only server; against this one, `resources/read` answers
/// `-32601` and a test says so. That is not a hypothetical case being
/// anticipated — see [`vibrev_kit::decorate`] for the release it describes.
const MANIFEST_URI: &str = "toy://manifest";

#[tool_handler(router = Self::tool_router())]
impl ServerHandler for Toy {
    fn get_info(&self) -> ServerInfo {
        // Reports the real crate name and version — no upstream impersonation, and
        // not rmcp's identity either.
        ServerInfo::new(
            ServerCapabilities::builder()
                .enable_tools()
                .enable_resources()
                .build(),
        )
        .with_server_info(vibrev_kit::engine_identity!())
        .with_instructions("Reference engine: one tool definition drives both MCP and the CLI")
    }

    async fn list_resources(
        &self,
        _params: Option<PaginatedRequestParams>,
        _ctx: RequestContext<RoleServer>,
    ) -> Result<ListResourcesResult, ErrorData> {
        Ok(ListResourcesResult::with_all_items(vec![
            Resource::new(MANIFEST_URI, "toy_manifest")
                .with_description("The tools this engine defines")
                .with_mime_type("application/json"),
        ]))
    }

    async fn read_resource(
        &self,
        params: ReadResourceRequestParams,
        _ctx: RequestContext<RoleServer>,
    ) -> Result<ReadResourceResponse, ErrorData> {
        if params.uri != MANIFEST_URI {
            return Err(ErrorData::invalid_params(
                format!("no such resource: {}", params.uri),
                None,
            ));
        }
        let defs = Toy::vibrev_tool_defs();
        let names: Vec<&str> = defs.iter().map(|def| def.name()).collect();
        let manifest = serde_json::json!({ "tools": names });
        Ok(ReadResourceResult::new(vec![ResourceContents::text(
            manifest.to_string(),
            MANIFEST_URI,
        )])
        .into())
    }
}

/// The root-level commands this engine handles itself.
///
/// Handed to both `with_management` (collision check, before grafting) and
/// [`assert_management_matches_command`](vibrev_kit::cli::assert_management_matches_command)
/// (closed loop, after). The two inputs have to be the same list or the drift
/// check is checking a different declaration than the collision check used.
const MANAGEMENT_COMMANDS: &[&str] = &["mcp", "skills"];

/// The skills compiled into this binary by `build.rs`.
///
/// `skills/toy-reference` is two files of real documentation, and it is here
/// for the same reason `toy://manifest` is: a shared piece proven against one
/// engine is a shared piece proven against that engine's habits. `vibrev`
/// installs skills from engines it merely found on disk, so the path from a
/// repository directory to a JSON document an installer parses has to be
/// exercised somewhere the installer's own tests can reach.
static SKILLS: vibrev_skills::Embedded = vibrev_skills::embedded!();

fn cli_command() -> clap::Command {
    let cmd = Toy::vibrev_cli("toy")
        .with_management(MANAGEMENT_COMMANDS)
        .command()
        .about("VibRev reference engine")
        .subcommand(clap::Command::new("mcp").about("以 stdio 运行 MCP server"))
        // Built with clap's builder API rather than named in a derived enum:
        // this engine has no `#[derive(Subcommand)]` tree to name it in. Both
        // spellings reach the same derived type in `vibrev-skills`.
        .subcommand(vibrev_skills::command());
    vibrev_kit::cli::assert_management_matches_command(&cmd, MANAGEMENT_COMMANDS);
    cmd
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let toy = Toy;

    // Management commands go on the root that `vibrev_cli` returns; the derived
    // tools live under `tool`, so the two cannot collide. `with_management` is how
    // the kit learns what those root commands are called — the list has to match the
    // `.subcommand(..)` calls below, and it is checked against every tool name before
    // the tree is handed back.
    let matches = cli_command().get_matches();

    if let Some(("mcp", _)) = matches.subcommand() {
        // The output net wraps the MCP face and only the MCP face. The `tool`
        // subcommand below runs the same tools and is deliberately not wrapped:
        // a CLI writes to a pipe, and truncating there would answer a question
        // nobody asked.
        let service = vibrev_kit::output::Capped::new(
            toy,
            vibrev_kit::output::OutputCache::spilling_to_files("toy-engine")?,
        )
        .serve(stdio())
        .await?;
        service.waiting().await?;
        return Ok(());
    }

    // Answerable with no MCP session and no server at all — an installer runs
    // this against a binary it has only just found.
    if let Some(("skills", sub)) = matches.subcommand() {
        return vibrev_skills::from_matches(sub)?.run(
            &SKILLS,
            "toy-engine",
            env!("CARGO_PKG_VERSION"),
        );
    }

    let defs = Toy::vibrev_tool_defs();
    let Some((name, leaf)) = vibrev_kit::cli::resolve(&matches) else {
        // `subcommand_required` rules out "nothing"; reaching here means a
        // management command was declared above and then never handled.
        anyhow::bail!("未处理的管理命令");
    };
    let Some(def) = defs.iter().find(|d| d.name() == name) else {
        anyhow::bail!("unknown tool: {name}");
    };

    // --json-input carries the parameters the CLI cannot express structurally.
    let args = match leaf.try_get_one::<String>("__json_input").ok().flatten() {
        Some(path) => {
            let raw = if path == "-" {
                std::io::read_to_string(std::io::stdin())?
            } else {
                std::fs::read_to_string(path)?
            };
            serde_json::from_str(&raw)?
        }
        None => match vibrev_kit::cli::to_arguments(def, leaf) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("Error: {e}");
                std::process::exit(1);
            }
        },
    };

    match toy.vibrev_call(&name, args).await {
        Ok(outcome) => {
            let text = if leaf.get_flag("__json") {
                outcome.json_text()
            } else {
                // Exactly the bytes MCP puts in `content[0]` — the outcome was
                // built by the same `IntoCallToolResult` the router uses, so this
                // is the same string rather than a matching one.
                outcome.text.clone()
            };
            if outcome.is_error {
                // The tool ran and reported failure. `isError: true` on the MCP
                // side, exit code + stderr on this one.
                eprintln!("{text}");
                std::process::exit(1);
            }
            println!("{text}");
            Ok(())
        }
        Err(e) => {
            eprintln!("Error: {}", e.message);
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vibrev_kit::contract::Audit;

    /// The contract scan, run against a real macro-derived catalog.
    ///
    /// This engine writes no normalization of its own — it is five tools and an
    /// `#[vibrev_tool_router]` — so a clean report here says the normalizing
    /// happens inside the macro expansion.
    ///
    /// The `checked` counts are the fuse: the failure a contract test cannot
    /// afford is "0 findings over 0 tools", and `assert_clean` on an empty
    /// catalog would pass.
    #[test]
    fn the_shared_contract_holds() {
        // `run_repeated` also rebuilds the catalog, which is what pins the
        // macro's list order — clients render `tools/list` in the order they
        // receive it.
        let report = Audit::new("toy").run_repeated(Toy::vibrev_tool_defs);

        assert_eq!(report.checked().tools, 5);
        assert_eq!(
            report.checked().output_schemas,
            5,
            "every tool publishes one"
        );
        report.assert_clean();
    }

    #[test]
    fn group_about_from_the_router_attr_shows_in_help() {
        let cmd = cli_command();
        let mut tools = cmd
            .find_subcommand(vibrev_kit::cli::TOOL_COMMAND)
            .expect("tool")
            .clone();
        let help = tools.render_help().to_string();
        assert!(
            help.contains("Inspect mapped functions"),
            "macro group_about must appear in `tool --help`: {help}"
        );
        assert_eq!(
            tools
                .find_subcommand("binary")
                .expect("binary")
                .get_about()
                .map(ToString::to_string)
                .as_deref(),
            Some("Inspect mapped functions")
        );
        assert!(
            tools
                .find_subcommand("annotation")
                .expect("annotation")
                .get_about()
                .is_none(),
            "a group without group_about must stay empty"
        );
        assert!(
            tools
                .find_subcommand("report")
                .expect("report")
                .get_about()
                .is_none(),
            "a group without group_about must stay empty"
        );
    }
}
