//! Throwaway survey harness: feed real MCP `tools/list` schemas to the
//! schema->clap mapper and report what clap actually ends up with.
//!
//! Not a test, not part of the shipped surface: it exists so the mappability
//! numbers in the survey come from running `vibrev_kit::cli`, not from reading it.
//!
//! Usage: `cargo run -p vibrev-kit --example ida_schema_survey -- tools.json`
//!
//! Input is the `result.tools` array of an MCP `tools/list` response (or a whole
//! JSON-RPC response envelope).

use std::collections::BTreeMap;

use clap::ArgAction;
use serde_json::{Map, Value};
use vibrev_kit::{
    CliHints, ToolDef,
    cli::{self, EngineCli},
};

fn main() {
    let path = std::env::args().nth(1).expect("usage: ... <tools.json>");
    let raw: Value = serde_json::from_slice(&std::fs::read(&path).expect("read tools.json"))
        .expect("parse tools.json");
    let tools = raw
        .get("result")
        .and_then(|r| r.get("tools"))
        .or_else(|| raw.get("tools"))
        .unwrap_or(&raw)
        .as_array()
        .expect("a tools array")
        .clone();

    let defs: Vec<ToolDef> = tools
        .iter()
        .map(|t| {
            let name = t["name"].as_str().expect("tool name").to_owned();
            let desc = t
                .get("description")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_owned();
            let schema: Map<String, Value> = t["inputSchema"]
                .as_object()
                .expect("an object inputSchema")
                .clone();
            let mut tool = rmcp::model::Tool::new(name, desc, schema);
            if let Some(title) = t.get("title").and_then(Value::as_str) {
                tool.title = Some(title.to_owned());
            }
            ToolDef {
                tool,
                // No hints: this measures the *default* mapping, which is what an
                // implementer gets before hand-tuning 78 tools.
                cli: CliHints {
                    positional: &[],
                    int_args: &[],
                    enabled: true,
                    needs_session: true,
                },
                ext: None,
            }
        })
        .collect();

    println!("== input: {} tools from {path}\n", defs.len());

    // The engine's real management commands (src/main.rs). Declaring them is the
    // only way to learn whether any of the 78 tool names would have been
    // refused.
    let management = ["mcp", "serve", "serve-http", "probe", "worker"];
    let cmd = EngineCli::new("ida", defs.clone())
        .with_management(&management)
        .command();
    println!("build() did not panic: no tool-name collision against {management:?}\n");

    // Would the *default* RESERVED list have refused anything? Answered by probing
    // each name rather than by building, because build() panics on the first hit.
    let refused: Vec<&str> = defs
        .iter()
        .map(ToolDef::name)
        .filter(|n| cli::RESERVED.contains(&n.split('.').next().unwrap_or(n)))
        .collect();
    println!("names RESERVED (the undeclared fallback) would refuse: {refused:?}\n");

    let tool_root = cmd
        .find_subcommand(cli::TOOL_COMMAND)
        .expect("the tool subtree exists");

    let mut n_hatch = 0usize;
    let mut n_flag = 0usize;
    let mut n_positional = 0usize;
    let mut n_possible = 0usize;
    let mut n_append = 0usize;
    let mut n_bool_pair = 0usize;
    let mut n_plain = 0usize;
    let mut widest: Vec<(usize, String)> = Vec::new();
    let mut per_tool: BTreeMap<String, Vec<String>> = BTreeMap::new();

    for sub in tool_root.get_subcommands() {
        let name = sub.get_name().to_owned();
        if name == "help" {
            continue;
        }
        let mut lines = Vec::new();
        let mut visible = 0usize;
        for a in sub.get_arguments() {
            let id = a.get_id().as_str().to_owned();
            if id == "__json" {
                continue;
            }
            if id == "__json_input" {
                n_hatch += 1;
                lines.push("  --json-input <FILE>   [ESCAPE HATCH]".into());
                continue;
            }
            if a.is_hide_set() {
                lines.push(format!(
                    "  --{:<24} (hidden half of a boolean pair)",
                    a.get_long().unwrap_or("?")
                ));
                continue;
            }
            visible += 1;
            let long = a.get_long().map(|l| format!("--{l}"));
            let is_pos = a.is_positional();
            if is_pos {
                n_positional += 1;
            } else if long.is_some() {
                n_flag += 1;
            }
            let pv: Vec<String> = a
                .get_possible_values()
                .iter()
                .map(|p| p.get_name().to_owned())
                .collect();
            if !pv.is_empty() {
                n_possible += 1;
            }
            let appends = matches!(a.get_action(), ArgAction::Append);
            let sets_true = matches!(a.get_action(), ArgAction::SetTrue);
            if appends {
                n_append += 1;
            }
            if sets_true {
                n_bool_pair += 1;
            }
            if !appends && !sets_true && pv.is_empty() {
                n_plain += 1;
            }
            lines.push(format!(
                "  {:<26} required={:<5} action={:<8} num_args={:?} values={:?}",
                long.unwrap_or_else(|| format!("<{}>", a.get_id())),
                a.is_required_set(),
                if sets_true {
                    "SetTrue"
                } else if appends {
                    "Append"
                } else {
                    "Set"
                },
                a.get_num_args(),
                pv,
            ));
        }
        widest.push((visible, name.clone()));
        per_tool.insert(name, lines);
    }

    println!("== totals across the whole derived tree ==");
    println!("subcommands under `ida tool`: {}", per_tool.len());
    println!("tools that grew --json-input : {n_hatch}");
    println!("positional args              : {n_positional}");
    println!("--flags                      : {n_flag}");
    println!("  of which SetTrue (bool)    : {n_bool_pair}");
    println!("  of which Append (array)    : {n_append}");
    println!("  of which value-validated   : {n_possible}   <- PossibleValuesParser");
    println!("  of which plain free-form   : {n_plain}");
    println!();

    widest.sort_by(|a, b| b.0.cmp(&a.0));
    println!("== widest subcommands (visible args) ==");
    for (n, name) in widest.iter().take(8) {
        println!("  {n:3}  {name}");
    }
    println!();

    // Prove the hatch text is or is not present.
    let with_after: Vec<&str> = tool_root
        .get_subcommands()
        .filter(|c| c.get_after_help().is_some())
        .map(|c| c.get_name())
        .collect();
    println!("subcommands carrying the `--json-input` after_help note: {with_after:?}\n");

    // The part that reading the code cannot settle: what JSON actually reaches the
    // tool for the shapes the mapper has no branch for.
    println!("== round-trip: parsed command line -> tool arguments ==");
    let probes: &[(&str, &[&str])] = &[
        (
            "decompile",
            &["ida", "tool", "decompile", "--address", "0x140001000"],
        ),
        (
            "disasm",
            &[
                "ida",
                "tool",
                "disasm",
                "--address",
                "0x1000",
                "--count",
                "0x20",
            ],
        ),
        (
            "open_idb",
            &[
                "ida",
                "tool",
                "open_idb",
                "--path",
                "/tmp/cat",
                "--auto-analyse",
                "--timeout-secs",
                "300",
            ],
        ),
        (
            "analyze_function",
            &[
                "ida",
                "tool",
                "analyze_function",
                "--address",
                "0x1000",
                "--no-include-pseudocode",
            ],
        ),
        (
            "open_dsc",
            &[
                "ida",
                "tool",
                "open_dsc",
                "--path",
                "/c",
                "--arch",
                "arm64e",
                "--module",
                "/usr/lib/libobjc.A.dylib",
                "--frameworks",
                "/a",
                "/b",
            ],
        ),
        (
            "comment_append",
            &[
                "ida",
                "tool",
                "comment_append",
                "--address",
                "0x1000",
                "--comment",
                "hi",
                "--scope",
                "nonsense-not-a-scope",
            ],
        ),
        (
            "survey_binary",
            &[
                "ida",
                "tool",
                "survey_binary",
                "--detail",
                "not-a-detail-level",
                "--max-functions",
                "99999999",
            ],
        ),
        (
            "sdk_mutation",
            &[
                "ida",
                "tool",
                "sdk_mutation",
                "--action",
                "make_code",
                "--function-addresses",
                "0x1000",
                "0x2000",
            ],
        ),
        (
            "find_paths",
            &[
                "ida",
                "tool",
                "find_paths",
                "--start",
                "0x1000",
                "--end",
                "0x2000",
                "--max-paths",
                "9999",
            ],
        ),
    ];
    for (tool, argv) in probes {
        let def = defs
            .iter()
            .find(|d| d.name() == *tool)
            .expect("probe names a real tool");
        let fresh = EngineCli::new("ida", defs.clone())
            .with_management(&management)
            .command();
        match fresh.try_get_matches_from(argv.iter().copied()) {
            Ok(m) => {
                let (resolved, leaf) = cli::resolve(&m).expect("a tool path");
                let args = cli::to_arguments(def, leaf);
                println!("  $ {}", argv.join(" "));
                println!(
                    "    -> {resolved} {}",
                    match args {
                        Ok(v) => serde_json::to_string(&v).expect("serializable"),
                        Err(e) => format!("ERROR: {e}"),
                    }
                );
            }
            Err(e) => {
                println!("  $ {}", argv.join(" "));
                println!(
                    "    -> REJECTED BY CLAP: {}",
                    e.to_string().lines().next().unwrap_or("")
                );
            }
        }
    }
    println!();

    // A missing required argument must still be an error; with no hatch present the
    // mapper uses .required(true).
    println!("== required enforcement ==");
    for argv in [
        vec!["ida", "tool", "decompile"],
        vec!["ida", "tool", "open_dsc", "--path", "/c"],
    ] {
        let fresh = EngineCli::new("ida", defs.clone())
            .with_management(&management)
            .command();
        let r = fresh.try_get_matches_from(argv.iter().copied());
        println!(
            "  $ {} -> {}",
            argv.join(" "),
            match r {
                Ok(_) => "ACCEPTED (!)".to_owned(),
                Err(e) => e.to_string().lines().next().unwrap_or("").to_owned(),
            }
        );
    }
    println!();

    // Positionals: the hint names parameters, but the *order* clap sees is the
    // order `properties` iterates, which is the order the schema arrived in.
    println!("== positional hints ==");
    for (tool, hint) in [
        ("find_paths", &["start", "end"][..]),
        ("decompile", &["address"][..]),
        ("open_idb", &["path"][..]),
    ] {
        let hinted: Vec<ToolDef> = defs
            .iter()
            .cloned()
            .map(|mut d| {
                if d.name() == tool {
                    d.cli.positional = match tool {
                        "find_paths" => &["start", "end"],
                        "decompile" => &["address"],
                        _ => &["path"],
                    };
                }
                d
            })
            .collect();
        let mut fresh = EngineCli::new("ida", hinted.clone())
            .with_management(&management)
            .command();
        let order: Vec<String> = fresh
            .find_subcommand(cli::TOOL_COMMAND)
            .and_then(|t| t.find_subcommand(tool))
            .map(|c| {
                c.get_positionals()
                    .map(|a| a.get_id().as_str().to_owned())
                    .collect()
            })
            .unwrap_or_default();
        let usage = fresh
            .find_subcommand_mut(cli::TOOL_COMMAND)
            .and_then(|t| t.find_subcommand_mut(tool))
            .map(|c| c.render_usage().to_string())
            .unwrap_or_default();
        println!("  hint {hint:?} on {tool}: clap positional order = {order:?}");
        println!("    {}", usage.lines().last().unwrap_or("").trim());
        // And what a caller who follows the hint order actually sends.
        let argv: Vec<&str> = match tool {
            "find_paths" => vec!["ida", "tool", "find_paths", "0xSTART", "0xEND"],
            "decompile" => vec!["ida", "tool", "decompile", "0x140001000"],
            _ => vec!["ida", "tool", "open_idb", "/tmp/cat"],
        };
        let fresh2 = EngineCli::new("ida", hinted.clone())
            .with_management(&management)
            .command();
        if let Ok(m) = fresh2.try_get_matches_from(argv.iter().copied()) {
            let def = hinted.iter().find(|d| d.name() == tool).expect("tool");
            let (_, leaf) = cli::resolve(&m).expect("path");
            println!(
                "    $ {} -> {}",
                argv.join(" "),
                serde_json::to_string(&cli::to_arguments(def, leaf).expect("ok"))
                    .expect("serializable")
            );
        }
    }
    println!();

    // Is `--help` still usable at 25 flags? Rendered, not estimated.
    println!("== rendered --help size ==");
    for probe in ["sdk_mutation", "analyze_function", "decompile", "open_idb"] {
        let mut fresh = EngineCli::new("ida", defs.clone())
            .with_management(&management)
            .command();
        let help = fresh
            .find_subcommand_mut(cli::TOOL_COMMAND)
            .and_then(|t| t.find_subcommand_mut(probe))
            .map(|c| c.render_long_help().to_string())
            .unwrap_or_default();
        let lines = help.lines().count();
        let undocumented = tools
            .iter()
            .find(|t| t["name"] == probe)
            .and_then(|t| t["inputSchema"].get("properties"))
            .and_then(Value::as_object)
            .map(|p| {
                p.values()
                    .filter(|v| v.get("description").is_none())
                    .count()
            })
            .unwrap_or(0);
        println!(
            "  {probe:<18} {lines:>4} lines, {:>5} bytes, {undocumented} params with no description",
            help.len()
        );
    }
    println!();
    {
        let mut fresh = EngineCli::new("ida", defs.clone())
            .with_management(&management)
            .command();
        if let Some(h) = fresh
            .find_subcommand_mut(cli::TOOL_COMMAND)
            .and_then(|t| t.find_subcommand_mut("sdk_mutation"))
            .map(|c| c.render_long_help().to_string())
        {
            println!("---- ida tool sdk_mutation --help ----\n{h}\n----\n");
        }
    }

    println!("== per-tool argument tables ==");
    for (name, lines) in &per_tool {
        println!("{name}");
        for l in lines {
            println!("{l}");
        }
    }
}
